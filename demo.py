"""Ninety-second trust-boundary demo for the provenance-layer PoC.

Run: python demo.py
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile

from ledger import Ledger, record_digest
from merkle import inclusion_proof, verify_inclusion

_DEMO_DIR = tempfile.TemporaryDirectory(prefix="provenance-demo-")
ROOT = _DEMO_DIR.name
LEDGER_PATH = os.path.join(ROOT, "demo-ledger.jsonl")
CHECKPOINT_PATH = os.path.join(ROOT, "demo-checkpoint.json")


def banner(text: str) -> None:
    print()
    print("=" * 76)
    print(text)
    print("=" * 76)


def write_records(records: list[dict]) -> None:
    with open(LEDGER_PATH, "w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def rewrite_hash_chain(records: list[dict], start_index: int) -> None:
    """Model an attacker who can rewrite bytes but does not hold the HMAC key."""

    for index in range(start_index, len(records)):
        records[index]["prev_hash"] = (
            records[index - 1]["record_hash"] if index else "0" * 64
        )
        body = {
            key: value
            for key, value in records[index].items()
            if key not in {"record_hash", "writer_mac"}
        }
        records[index]["record_hash"] = record_digest(body)


def _run_demo() -> None:
    for path in (LEDGER_PATH, CHECKPOINT_PATH):
        if os.path.exists(path):
            os.remove(path)

    # Ephemeral demo key: never printed or persisted.
    writer_key = secrets.token_bytes(32)
    ledger = Ledger(LEDGER_PATH, writer_key=writer_key)

    banner("1. AI proposes; the accountable human decides; authenticated records seal")
    cases = [
        ("case-0001", "R1", "R1", "approved"),
        ("case-0002", "R2", "R2", "approved"),
        ("case-0003", "R3A", "R3A", "approved"),
        ("case-0004", "R1", "R2", "overridden"),
        ("case-0005", "R0", "R0", "approved"),
        ("case-0006", "R3S", "REFER", "escalated"),
        ("case-0007", "R1", "R1", "approved"),
        ("case-0008", "R2", "R2", "approved"),
    ]
    for case_id, ai_grade, human_grade, outcome in cases:
        decision = {
            "case": case_id,
            "ai_proposed": ai_grade,
            "human_decision": human_grade,
            "outcome": outcome,
            "policy": "shadow-mode-v1: human is the decision of record",
        }
        record = ledger.append(
            actor="grader.L3",
            event=f"screening-grade:{outcome}",
            payload=decision,
        )
        print(
            f"  seq {record['seq']}: {case_id} AI={ai_grade:5s} "
            f"human={human_grade:5s} ({outcome}) {record['record_hash'][:16]}..."
        )

    ok, message = ledger.verify(require_auth=True)
    print(f"\n  verify: {message}")
    assert ok

    banner("2. Naive edit: change one old commitment without updating its hash")
    original = ledger.read_all()
    edited = [dict(record) for record in original]
    edited[3]["payload_commitment"] = "0" * 64
    write_records(edited)
    ok, message = ledger.verify(require_auth=True)
    print(f"  verify after edit: {message}")
    assert not ok

    banner("3. Stronger edit: recompute every public hash in the rewritten tail")
    rewritten = [dict(record) for record in original]
    rewritten[3]["payload_commitment"] = "f" * 64
    rewrite_hash_chain(rewritten, 3)
    write_records(rewritten)

    public_reader = Ledger(LEDGER_PATH)
    chain_ok, chain_message = public_reader.verify()
    auth_ok, auth_message = ledger.verify(require_auth=True)
    print(f"  public hash-chain check: {chain_message}")
    print(f"  authenticated-writer check: {auth_message}")
    assert chain_ok, "a fully recomputed plain hash chain is internally consistent"
    assert not auth_ok, "the attacker cannot recompute HMACs without the writer key"

    write_records(original)
    ok, message = ledger.verify(require_auth=True)
    print(f"  restored original: {message}")
    assert ok

    banner("4. Retained checkpoint: one receipt commits to the current history")
    receipt = ledger.checkpoint(require_auth=True)
    with open(CHECKPOINT_PATH, "w", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(receipt, indent=2))
    checkpoint_ok, checkpoint_message = ledger.verify_checkpoint(receipt, require_auth=True)
    print(f"\n  verify retained checkpoint: {checkpoint_message}")
    assert checkpoint_ok
    print("  anchor_status is UNPUBLISHED: this repository does not submit it anywhere.")

    banner("5. Tail truncation is visible only against the retained checkpoint")
    truncated = original[:-1]
    write_records(truncated)
    local_ok, local_message = Ledger(LEDGER_PATH).verify()
    witness_ok, witness_message = Ledger(LEDGER_PATH).verify_checkpoint(receipt)
    print(f"  local chain check: {local_message}")
    print(f"  retained-checkpoint check: {witness_message}")
    assert local_ok, "a truncated prefix remains internally consistent"
    assert not witness_ok, "the retained checkpoint detects truncation"
    write_records(original)

    banner("6. Inclusion proof: prove one record is in the checkpointed set")
    records = ledger.read_all()
    leaves = [record["record_hash"] for record in records]
    index = 5
    proof = inclusion_proof(leaves, index)
    included = verify_inclusion(leaves[index], proof, receipt["merkle_root"])
    print(f"  record seq {index + 1} is in the retained checkpoint: {included}")
    print(f"  proof path: {len(proof['path'])} sibling hashes")
    print("  no other raw decision payload is disclosed by this proof")
    assert included

    banner("Boundary: integrity is not truth; anchorable is not anchored; PoC is not production")


def main() -> None:
    try:
        _run_demo()
    finally:
        _DEMO_DIR.cleanup()


if __name__ == "__main__":
    main()
