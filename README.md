# OSS Security Audit

`oss-security-audit` is a small, local-first baseline scanner for source repositories. It catches common publication mistakes before code is pushed: credential-like values, sensitive files, GitHub Actions workflows without an explicit permission policy, containers that run without a declared user, and missing ignore rules.

The tool reads files on the machine where it runs. It does not upload source code, call an API, or print detected credential values. Findings contain only a rule, path, line number, and a redacted explanation.

## Quick start

Requires Python 3.10 or newer.

```bash
python -m venv .venv
. .venv/bin/activate       # Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e .
oss-security-audit /path/to/repository
```

Use JSON in CI or other automation:

```bash
oss-security-audit . --json --fail-on high
```

The default exit policy fails for `HIGH` and `CRITICAL` findings. Pass `--fail-on none` for an advisory-only run. Use `--exclude vendor --exclude fixtures` to skip directory names that are intentionally checked elsewhere.

## Checks

| Rule | Severity | What it flags |
| --- | --- | --- |
| `SECRET001` | high | Recognisable provider tokens, private-key headers, and credential-like assignments |
| `SECRET002` | high | `.env`, key material, and common credential filenames in the working tree |
| `GHA001` | medium | A workflow without an explicit `permissions:` policy |
| `DOCKER001` | low | A Dockerfile that has no declared `USER` |
| `GIT001` | low | No `.gitignore` at the repository root |
| `GIT002` | low | Missing `.env`, `*.pem`, or `*.key` ignore patterns |

This is a baseline check, not a complete security review. It does not inspect Git history, understand every encoding, or replace dedicated secret scanners, dependency auditing, SAST, or human review.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m oss_security_audit . --json
```

Contributions that add a rule should include a focused test and keep output free of secret values. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

A ready-to-copy GitHub Actions workflow is included at [docs/ci-template.yml](docs/ci-template.yml). Copy it to `.github/workflows/ci.yml` in a fork to run the tests and baseline scan on every push and pull request.

## License

MIT. See [LICENSE](LICENSE).
