# Security policy

## Supported status

This repository is a non-production proof of concept. Only the latest tagged
0.x release receives corrections. No release is supported for production,
regulated, safety-critical, personal-data, or custody use.

## Reporting a vulnerability

Use GitHub's **Security > Report a vulnerability** flow, which is enabled for
this repository. Alternatively, send a minimal confidential summary to
[admin@x7system.com](mailto:admin@x7system.com) and request a secure exchange.
Do not email an exploit, key, personal data, credentials, or sensitive system
detail, and do not publish them in a public issue.

Include:

- affected commit or tag;
- the violated claim or threat-model assumption;
- a minimal reproduction using synthetic data; and
- expected impact.

The most useful reports distinguish a defect from an explicit limitation in
[THREAT_MODEL.md](THREAT_MODEL.md). Explicit limitations may still motivate a
design improvement, but they are not production-security promises.
