# provenance-layer

**A tamper-evident, blockchain-anchorable ledger for AI decisions — in 300 lines of standard-library Python.**

Generative AI has collapsed the cost of fabrication — of content, of records, of provenance itself. The counter-asset is *proof*. This repository is a working proof-of-concept of the smallest useful unit of verifiable AI: every material decision an AI system takes (a grade, a triage, an approval) is sealed into an append-only, hash-chained ledger; the whole history is committed to a single digest that can be anchored to **any** public chain or transparency log; and any single decision can be proven present **without revealing any other decision**.

> The gate produces the record. The chain makes the record permanent.

## Why this matters now

- **Regulation has arrived.** EU AI Act **Article 12** — tamper-evident event logging across the lifetime of high-risk AI systems — has been in force since 2 August 2026.
- **The category is proven.** Hardware-attested AI audit (EQTY Lab / Intel / NVIDIA), blockchain-anchored model governance (IBM / Casper Labs), and a decade of national-scale ledger-anchored health-record auditing in Estonia (Guardtime KSI) all demonstrate the pattern.
- **The sovereignty property.** The ledger never leaves home. Only a checkpoint digest travels — publishable on a national chain, a consortium chain, or a newspaper's front page. Proof without data exfiltration, which is the property that matters to any government client.

## 60-second demo

```
python demo.py
```

Runs a clinical-style AI-assisted screening scenario (AI proposes a grade; an accountable human approves, overrides or escalates; the *decision of record* is sealed), then:

1. **Verifies** the full chain — every record re-hashed, every link checked.
2. **Attempts a tamper** — a past human override is quietly flipped back to "approved". Verification fails at exactly that record: `tamper detected at seq 4`.
3. **Checkpoints** — one compact anchor receipt (Merkle root + chain head) commits to the entire history.
4. **Proves inclusion** — decision №6 is shown to be inside the anchored set with a 3-hash proof, disclosing nothing else.

```
python test_ledger.py   # 10 tests, stdlib unittest
```

## What it is / what it is not

| It is | It is not |
|---|---|
| A working demonstration of tamper-evident AI decision logging with chain-agnostic anchoring | A product, a custody system, or a token |
| Standard-library Python, zero dependencies, runs **air-gapped** | Tied to any chain, cloud, or vendor |
| The pattern behind a human-gated AI operations estate (the gate emits the event; the ledger seals it) | A claim that scale problems (throughput, key management, HSMs, TEE attestation) are solved here |

## Design notes

- **Records** bind `payload_hash` + `prev_hash` + their own canonical hash. Storage is human-readable JSONL — auditable with `grep`, no tooling required.
- **Payload privacy by construction**: the ledger can store only the *hash* of a decision payload; the payload itself may live in a governed store, or nowhere.
- **Anchoring is a policy choice, not an architecture choice**: the checkpoint receipt is a plain JSON digest. Anchor hourly to a consortium chain, daily to a public one, or continuously to a transparency log — the ledger code does not change.
- **Extension path**: TEE-attested writers (the EQTY pattern), C2PA-style content credentials for model outputs, X-Road-style cross-agency verification (the Estonia pattern).

## Provenance of this idea

Built by [Saqub Hussain](https://github.com/saqub) — X7 Systems Ltd (UK) — extending the append-only audit patterns of X7's operating AI estate (human-gated agent pipelines, evidence-review systems with atomic audit trails, grounded advisors where numbers come from the database, not the model). GISEC Dubai 2022 speaker, *"Training for the Future: Crypto Cyber Security."*

*This is a proof of concept written to be read in one sitting. The interesting conversation is what it becomes at national scale.*
