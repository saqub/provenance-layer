"""60-second demonstration: AI decisions -> human gate -> sealed ledger ->
tamper attempt caught -> checkpoint -> inclusion proof.

The scenario mirrors a clinical-style AI-assisted screening workflow:
an AI model proposes a grade, an accountable human approves or overrides,
and the DECISION OF RECORD is sealed into the ledger. This is the pattern
behind the Provenance Layer proposition: the gate produces the record;
the chain makes the record permanent.

Run:  python demo.py
"""

from __future__ import annotations

import json
import os

from ledger import Ledger, payload_hash
from merkle import inclusion_proof, verify_inclusion

LEDGER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo-ledger.jsonl")


def banner(text: str) -> None:
    print()
    print("=" * 72)
    print(text)
    print("=" * 72)


def main() -> None:
    # fresh run every time
    if os.path.exists(LEDGER_PATH):
        os.remove(LEDGER_PATH)
    ledger = Ledger(LEDGER_PATH)

    banner("1. AI proposes; the accountable human decides; the ledger seals it")
    cases = [
        ("case-0001", "R1", "R1", "approved"),
        ("case-0002", "R2", "R2", "approved"),
        ("case-0003", "R3A", "R3A", "approved"),
        ("case-0004", "R1", "R2", "overridden"),   # human raises the AI grade
        ("case-0005", "R0", "R0", "approved"),
        ("case-0006", "R3S", "REFER", "escalated"),  # human refuses to auto-grade
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
        rec = ledger.append(
            actor="grader.L3",
            event=f"screening-grade:{outcome}",
            payload=decision,
        )
        print(f"  seq {rec['seq']}: {case_id}  AI={ai_grade:5s} human={human_grade:5s} "
              f"({outcome})  sealed {rec['record_hash'][:16]}…")

    ok, msg = ledger.verify()
    print(f"\n  verify: {msg}")
    assert ok

    banner("2. A tamper attempt — someone edits history")
    with open(LEDGER_PATH, encoding="utf-8") as f:
        lines = f.readlines()
    original_line = lines[3]
    doctored = json.loads(original_line)
    # the attacker flips a past override back to 'approved' — quietly
    doctored_payload = {"case": "case-0004", "ai_proposed": "R1",
                        "human_decision": "R1", "outcome": "approved",
                        "policy": "shadow-mode-v1: human is the decision of record"}
    doctored["payload_hash"] = payload_hash(doctored_payload)
    lines[3] = json.dumps(doctored, sort_keys=True, ensure_ascii=False) + "\n"
    with open(LEDGER_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)

    ok, msg = ledger.verify()
    print(f"  verify after edit: {msg}")
    assert not ok, "tampering must be detected"

    # restore the true history
    lines[3] = original_line
    with open(LEDGER_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)
    ok, msg = ledger.verify()
    print(f"  verify after restore: {msg}")
    assert ok

    banner("3. Checkpoint — one digest commits to the whole history")
    receipt = ledger.checkpoint()
    print(json.dumps(receipt, indent=2))
    print("\n  Publish that receipt anywhere public — a national chain, a")
    print("  consortium chain, a transparency log. The ledger never leaves home.")

    banner("4. Inclusion proof — prove one decision without revealing the rest")
    records = ledger.read_all()
    leaves = [r["record_hash"] for r in records]
    idx = 5  # case-0006, the escalation
    proof = inclusion_proof(leaves, idx)
    good = verify_inclusion(leaves[idx], proof, receipt["merkle_root"])
    print(f"  decision seq {idx + 1} (case-0006, escalated) is in the anchored set: {good}")
    print(f"  proof size: {len(proof)} hashes — no other decision disclosed")
    assert good

    banner("provenance-layer: the gate produces the record; the chain makes it permanent")


if __name__ == "__main__":
    main()
