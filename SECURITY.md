# Security policy

## Supported status

This repository is a non-production proof of concept. Only the latest tagged
0.x release receives corrections. No release is supported for production,
regulated, safety-critical, personal-data, or custody use.

## Reporting a vulnerability

Please use GitHub's **Security > Report a vulnerability** flow for this
repository. Do not publish an exploit, key, personal data, or sensitive system
detail in a public issue.

Include:

- affected commit or tag;
- the violated claim or threat-model assumption;
- a minimal reproduction using synthetic data; and
- expected impact.

The most useful reports distinguish a defect from an explicit limitation in
[THREAT_MODEL.md](THREAT_MODEL.md). Explicit limitations may still motivate a
design improvement, but they are not production-security promises.
