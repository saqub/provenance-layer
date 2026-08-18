# Threat model

## Intended use

This repository is an educational reference and technical discussion artefact
for one bounded, synthetic or non-sensitive workflow. It helps reviewers reason
about event commitments, writer authentication, checkpoints, and external
witnessing before choosing production infrastructure.

It is not a medical, education, employment, identity, payment, custody,
compliance, or production decision system.

## Assets

- the order and exact committed bytes of event records;
- a verifier's ability to detect changes relative to a trusted key or receipt;
- minimisation of raw payload disclosure; and
- an explicit boundary between local evidence and external witnessing.

## Attacker capabilities considered

| Capability | Result in this PoC |
|---|---|
| Edits one record but not later hashes | Hash-chain verification fails at the edited record. |
| Rewrites a record and recomputes the whole later chain | Public hash-chain verification can pass. Writer-HMAC verification fails if the key was not compromised. |
| Deletes the final record(s) | The remaining prefix can pass local verification. Comparison with a separately retained checkpoint fails. |
| Replaces the whole ledger and local checkpoint | Detectable only if the verifier has an authentic key or a checkpoint outside that attacker's control. |
| Guesses a low-entropy payload | A random public salt stops bulk precomputation but not targeted guessing. Do not treat commitments as encryption. |
| Uses a fake `actor` label | Accepted. Actor identity is not authenticated by this version. |
| Writes while another cooperating process writes | The advisory lock serialises users of this implementation. A process that ignores the lock is out of scope. |

## Explicitly out of scope

- compromise, theft, misuse, rotation, revocation, or recovery of the writer key;
- malicious operating-system, administrator, hypervisor, firmware, HSM, or TEE;
- trusted identity, trusted time, non-repudiation, or proof of human approval;
- distributed ordering, consensus, replication, availability, denial of service,
  rollback protection, and disaster recovery;
- side-channel leakage and traffic analysis;
- confidentiality of metadata or payload commitments;
- correctness, fairness, safety, legality, or quality of the underlying AI or
  human decision; and
- legal or standards compliance.

## Why the HMAC is present

The original teaching sketch used only public hashes. Anyone able to rewrite
the file could therefore rewrite the full chain. V0.3 adds HMAC-SHA256 to make
that limitation executable: the demo shows the recomputed chain passing a
public hash check and failing authenticated verification.

HMAC is intentionally not described as a digital signature. Every holder of
the shared key can create the same code. A production design would normally
evaluate asymmetric signatures, workload identity, protected key custody,
rotation, revocation, and independently attested execution.

## External anchor boundary

The checkpoint says `anchor_status: UNPUBLISHED`. Until a checkpoint digest is
independently witnessed, a keyless third party cannot distinguish original
history from a fully regenerated history. A production discovery should compare
at least:

- an append-only transparency log;
- a national or consortium trust service;
- an existing enterprise timestamping/notarisation service; and
- a public-chain timestamp where jurisdiction, cost, privacy, and finality make
  it appropriate.

The raw decision payload need not leave the governed environment. A digest,
proof, and metadata still leave when exported and may themselves be sensitive
or personal data; classification and privacy review remain necessary.
