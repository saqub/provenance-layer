# Protocol notes - v0.3.0 PoC

This document makes the byte-level commitments in the Python implementation
reviewable. It is a PoC profile, not a proposed standard.

## Canonical JSON profile

Before hashing, values are encoded with Python `json.dumps` using:

```text
sort_keys=True
separators=(",", ":")
ensure_ascii=False
allow_nan=False
UTF-8 bytes
```

Accepted values are null, booleans, integers, NFC-normalised strings, arrays,
and objects whose keys are NFC-normalised strings. Floats and all other Python
types are rejected. Duplicate JSON keys are rejected when a JSONL record is
read.

This intentionally narrow profile is deterministic inside the reference
implementation. It is not a complete RFC 8785 implementation. A second-language
implementation must pass shared test vectors before interoperability is claimed.

## Domain-separated digests

`||` means byte concatenation. Hex fields are decoded to raw bytes when shown
with `hex_decode`.

```text
payload_commitment = SHA-256(
  "provenance-layer/payload/v1\0" ||
  hex_decode(payload_salt) ||
  canonical_json(payload)
)

record_hash = SHA-256(
  "provenance-layer/record/v2\0" ||
  canonical_json(record_body)
)

writer_mac = HMAC-SHA-256(
  writer_key,
  "provenance-layer/hmac/v1\0" || hex_decode(record_hash)
)

merkle_parent = SHA-256(
  "provenance-layer/merkle-node/v2\0" ||
  hex_decode(left) || hex_decode(right)
)

receipt_hash = SHA-256(
  "provenance-layer/checkpoint/v2\0" ||
  canonical_json(receipt_body)
)
```

The receipt HMAC uses the same HMAC construction over `receipt_hash`.

## Record body

The body committed by `record_hash` contains exactly:

```json
{
  "actor": "reviewer-7",
  "event": "human-approved",
  "ledger_id": "UUID",
  "payload_commitment": "64 lowercase hex",
  "payload_salt": "32 lowercase hex",
  "prev_hash": "64 lowercase hex",
  "schema": "provenance-layer/record/v2",
  "seq": 1,
  "ts": "timezone-aware ISO 8601",
  "writer_key_id": "16 lowercase hex or null"
}
```

`record_hash` and optional `writer_mac` are then added. Unknown fields, missing
fields, mixed ledger identities, invalid sequence numbers, and invalid digests
fail verification.

`actor` is a label. This PoC does not bind it to a person or credential.

## Merkle construction

Record hashes are leaves. Adjacent leaves are combined with the domain-separated
node hash above. At an odd-width level, the final unpaired node is promoted
unchanged. Empty trees use 64 zeroes; a one-leaf tree's root is that leaf.

An inclusion proof carries:

```json
{
  "schema": "provenance-layer/inclusion-proof/v2",
  "leaf_index": 5,
  "tree_size": 8,
  "path": [
    {"hash": "64 lowercase hex", "side": "right"}
  ]
}
```

The verifier checks index, tree size, expected sibling side at every level,
path length, and final root. The checkpoint separately binds `record_count`, so
the proof must be evaluated with the checkpoint it is meant to satisfy.

## Checkpoint receipt

The receipt body contains exactly:

```json
{
  "anchor_status": "UNPUBLISHED",
  "chain_head": "64 lowercase hex",
  "created_at": "timezone-aware ISO 8601",
  "ledger_id": "UUID or null",
  "merkle_root": "64 lowercase hex",
  "record_count": 8,
  "schema": "provenance-layer/checkpoint/v2",
  "writer_key_id": "16 lowercase hex or null"
}
```

`receipt_hash` and optional `receipt_mac` are added. The word `UNPUBLISHED` is
load-bearing: creating this JSON is not an external anchor. A later adapter
would need to define the external system, submitted digest, transaction or log
identifier, trusted time source, finality rule, failure handling, and verifier.

## Verification levels

1. **Structure and hash chain:** internally consistent bytes only.
2. **Writer HMAC:** detects rewrites by an attacker who lacks the shared key;
   it does not identify an individual or provide non-repudiation.
3. **Retained checkpoint:** detects tail truncation and full-chain replacement
   relative to a receipt kept outside the attacker's control.
4. **External witness:** not implemented here. This is the point where trusted
   time and independently observable history could be introduced.
