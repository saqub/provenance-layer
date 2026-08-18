# Contributing

This PoC is deliberately small. Changes should make the security boundary more
obvious, not add surface area without a testable claim.

Before opening a pull request:

```bash
python -W error -m unittest -v
python demo.py
python -m build
```

Requirements:

- use synthetic data only;
- add an adversarial test for every security-relevant fix;
- update `PROTOCOL.md` when committed bytes or proof semantics change;
- update `THREAT_MODEL.md` when a trust assumption changes;
- never describe a generated receipt as externally anchored unless the code
  submits it to a named witness and verifies the resulting evidence; and
- do not claim legal, standards, or product compliance.
