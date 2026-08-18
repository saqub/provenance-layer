# Changelog

## 0.3.1 - 2026-08-19

- Fixed an authentication-downgrade path by binding each ledger to the
  authentication mode and writer key identifier established by record 1.
- Made keyless append and checkpoint creation refuse authenticated histories.
- Made public verification reject manually mixed authentication modes.
- Enforced string types for hexadecimal record and checkpoint fields.
- Converted invalid canonical record and receipt data into structured failures.
- Corrected the tail-truncation boundary and security-reporting route.
- Rejected boolean Merkle indices and tree sizes and moved demo files to an
  ephemeral temporary directory.
- Expanded the suite to 39 unit and adversarial tests.

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
- Added protocol, threat-model, security, packaging, and licence records.
- Corrected the EU AI Act statement and removed immutability/blockchain overclaims.

## 0.1.0 - 2026-08-18

- Initial hash-chain, Merkle checkpoint, inclusion proof, demo, and tests.
