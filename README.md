# provenance-layer

**A reference implementation for hash-chained AI decision receipts, authenticated checkpoints, and selective inclusion proofs.**

This repository is deliberately small enough to audit in one sitting. It
models an AI-assisted decision in which a model proposes, an accountable human
decides, and the system records a commitment to the decision payload.

> **Boundary:** this is a non-production proof of concept. It does not make a
> local file immutable, submit anything to a blockchain, authenticate the human
> named in an `actor` string, establish trusted time, or prove that a decision
> was correct. Modification or full-chain rewriting is detectable with an
> uncompromised writer key or a retained checkpoint. Tail truncation requires
> a checkpoint or equivalent state retained outside the attacker's control.

## Run it in 90 seconds

Python 3.10+ is the only requirement.

```bash
git clone https://github.com/saqub/provenance-layer.git
cd provenance-layer
python demo.py
python -W error -m unittest -v
```

The demo shows six things:

1. a strict, versioned JSONL ledger with salted payload commitments;
2. a naive historical edit being detected by the hash chain;
3. a stronger attacker recomputing the whole public chain;
4. HMAC-authenticated records detecting that stronger rewrite;
5. a retained checkpoint detecting otherwise invisible tail truncation; and
6. an index- and tree-size-aware Merkle inclusion proof.

The test suite contains 39 unit and adversarial tests and uses only the Python
standard library.

## The three distinctions that matter

| Term | What this PoC means |
|---|---|
| **Tamper-evident, not immutable** | A self-consistent hash chain can be rewritten by someone who controls the file. A writer HMAC or independently retained checkpoint makes that rewrite detectable. |
| **Anchoring-ready, not anchored** | The code emits a canonical checkpoint receipt with `anchor_status: UNPUBLISHED`. Publishing its digest to a transparency log, consortium system, or public chain is a separate integration. |
| **Integrity, not truth** | A commitment can prove that bytes have not changed relative to a trusted witness. It cannot prove that an event was accurate, authorised, fair, or lawful. |

## What is implemented

- strict `provenance-layer/record/v2` schema, sequential numbering, one
  `ledger_id`, UTC timestamps, and previous-record links;
- deterministic JSON profile that rejects floats, non-string keys, NaN,
  infinity, duplicate keys on read, and non-NFC strings;
- per-record 128-bit public salts for payload commitments;
- domain-separated SHA-256 record, Merkle-node, and receipt digests;
- optional HMAC-SHA256 writer authentication with non-secret key identifiers;
- cooperative cross-process file locking, append mode, flush, and `fsync`;
- fail-closed append and checkpoint creation when the current ledger is invalid;
- canonical checkpoint receipts that bind ledger identity, record count, chain
  head, Merkle root, and explicit publication state;
- checkpoint verification against a separately retained receipt; and
- inclusion proofs that validate leaf index, tree size, sibling direction, and
  path shape.

## What is intentionally not solved

- an external timestamp, transparency-log submission, or blockchain adapter;
- asymmetric signatures, individual actor identity, non-repudiation, PKI,
  HSM/KMS custody, or key rotation;
- a trusted clock or independently attested execution environment;
- malicious processes that bypass the cooperative lock;
- multi-writer ordering, crash recovery beyond one flushed append, high
  throughput, pruning, replication, or distributed consensus;
- confidentiality: actor, event type, time, and volume remain visible, and even
  salted commitments can leak information when the payload space is tiny;
- proof that an AI output or human decision was substantively correct; or
- compliance with any law, standard, procurement framework, or assurance
  programme.

Read [THREAT_MODEL.md](THREAT_MODEL.md) before adapting the code, and
[PROTOCOL.md](PROTOCOL.md) before implementing a compatible verifier.

## Minimal library example

```python
import os
from ledger import Ledger

writer_key = bytes.fromhex(os.environ["PROVENANCE_WRITER_KEY"])
ledger = Ledger("decisions.jsonl", writer_key=writer_key)

record = ledger.append(
    actor="reviewer-7",
    event="human-approved",
    payload={
        "case": "synthetic-001",
        "model": "example-model-v1",
        "policy": "approval-policy-v3",
        "decision": "REFER",
    },
)

ok, detail = ledger.verify(require_auth=True)
receipt = ledger.checkpoint(require_auth=True)
```

Generate a local test key without putting it in source control:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

HMAC proves that the same shared secret authenticated the record. It is not an
individual digital signature and does not provide non-repudiation.

## Why logging and assurance are relevant

- [Article 12 of the EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj?locale=en)
  requires automatic event logging and traceability for high-risk AI systems;
  it does **not** prescribe blockchain or use the phrase "tamper-evident".
- Under the EU's amended 2026 timeline, [Annex III high-risk rules apply from
  2 December 2027 and product-integrated high-risk rules from 2 August
  2028](https://digital-strategy.ec.europa.eu/en/policies/enforcement-ai-act).
- G42's February 2026 [Assurance Compute
  Framework](https://www.g42.ai/resources/news/g42-announces-assurance-compute-framework-secure-advanced-us-ai-infrastructure-across-pax-silica-ecosystem)
  says it intends to use cryptographic mechanisms for compute-utilisation and
  token-level verification. This independent PoC operates at the application
  decision/action layer; it is not a substitute for that compute-layer design.

This repository is independent and is not affiliated with, commissioned by,
or endorsed by G42, the European Union, or any organisation cited above.

## Files

```text
ledger.py          strict records, HMAC authentication, checkpoints
merkle.py          Merkle roots and index/size-aware inclusion proofs
demo.py            synthetic decision workflow and attack demonstrations
test_ledger.py     39 unit and adversarial tests
PROTOCOL.md        record, receipt, and proof formats
THREAT_MODEL.md    claims, attacker model, and explicit exclusions
SECURITY.md        vulnerability reporting and support boundary
```

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

Built by [Saqub Hussain](https://github.com/saqub), founder of X7 Systems Ltd
(UK company 16884921). The code is a conversation starter: the valuable next
step is testing the pattern against one bounded, non-sensitive workflow with an
agreed threat model.
