"""provenance-layer — a tamper-evident, hash-chained ledger for AI decisions.

Every material decision an AI system takes (a grade, a triage, an approval)
is recorded as an append-only, hash-chained event. The chain makes silent
rewriting impossible; the Merkle checkpoint makes the whole history
anchorable to any public chain or transparency log as a single digest —
the ledger stays private, only the proof travels.

Design properties:
  * Append-only JSONL storage — human-readable, greppable, auditable.
  * Each record binds: its payload hash, the previous record hash, and its
    own canonical hash. Change one byte of history and verification fails
    at exactly that record.
  * Checkpoints emit a compact anchor receipt (Merkle root + chain head).
    Anchor it on a national chain, a consortium chain, or print it in a
    newspaper — sovereignty preserved: no decision data leaves the ledger.
  * Inclusion proofs show ONE decision is inside an anchored checkpoint
    without revealing any other decision.

Standard library only. Runs air-gapped.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

GENESIS = "0" * 64


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(obj) -> bytes:
    """Deterministic JSON encoding — the only encoding that is hashed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def payload_hash(payload) -> str:
    """Hash of the decision payload (the payload itself need not be stored)."""
    return _sha256_hex(_canonical(payload))


class Ledger:
    """An append-only, hash-chained decision ledger backed by a JSONL file."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    # ---------------------------------------------------------------- write

    def append(self, actor: str, event: str, payload) -> dict:
        """Record a decision. Returns the sealed record."""
        records = self.read_all()
        prev_hash = records[-1]["record_hash"] if records else GENESIS
        record = {
            "seq": len(records) + 1,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actor": actor,
            "event": event,
            "payload_hash": payload_hash(payload),
            "prev_hash": prev_hash,
        }
        record["record_hash"] = _sha256_hex(_canonical(record))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        return record

    # ----------------------------------------------------------------- read

    def read_all(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    # --------------------------------------------------------------- verify

    def verify(self) -> tuple[bool, str]:
        """Re-derive every hash in the chain. Any silent edit fails loudly."""
        prev = GENESIS
        for rec in self.read_all():
            claimed = rec.get("record_hash", "")
            body = {k: v for k, v in rec.items() if k != "record_hash"}
            if rec.get("prev_hash") != prev:
                return False, f"chain break at seq {rec.get('seq')}: prev_hash mismatch"
            if _sha256_hex(_canonical(body)) != claimed:
                return False, f"tamper detected at seq {rec.get('seq')}: record_hash mismatch"
            prev = claimed
        return True, "ledger verified: every record intact, chain unbroken"

    # ----------------------------------------------------------- checkpoint

    def checkpoint(self) -> dict:
        """Compact anchor receipt: publish this digest anywhere public.

        The receipt commits to the entire history (Merkle root over every
        record hash + the chain head). The ledger itself never leaves home.
        """
        from merkle import merkle_root

        records = self.read_all()
        leaves = [r["record_hash"] for r in records]
        return {
            "anchor": "provenance-layer/v1",
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "records": len(records),
            "chain_head": leaves[-1] if leaves else GENESIS,
            "merkle_root": merkle_root(leaves),
        }
