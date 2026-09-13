# Contributing

Issues and pull requests are welcome. Please describe the repository shape that a new rule covers, keep the rule explainable, and add a regression test.

Before opening a pull request, run:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m oss_security_audit . --fail-on high
```

Do not include real credentials, private keys, personal data, or proprietary source in issues, tests, or fixtures. Build test values from harmless fragments when a detector needs to be exercised.
