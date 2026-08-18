# Changelog

## 0.3.0 - 2026-08-19

- Reframed the project as an anchoring-ready, non-production reference.
- Added strict record and checkpoint schemas, ledger identity, and sequence checks.
- Added salted payload commitments and domain-separated digests.
- Added optional HMAC-authenticated records and receipts.
- Added fail-closed checkpoints and retained-checkpoint verification.
- Added index- and tree-size-aware Merkle proofs with strict path validation.
- Added cooperative file locking, append mode, flush, and `fsync`.
- Expanded the demo to expose full-chain rewrite and tail-truncation boundaries.
- Expanded the suite from 10 happy-path tests to 33 unit/adversarial tests.
- Added protocol, threat-model, security, packaging, licence, and CI records.
- Corrected the EU AI Act statement and removed immutability/blockchain overclaims.

## 0.1.0 - 2026-08-18

- Initial hash-chain, Merkle checkpoint, inclusion proof, demo, and tests.
