"""Small, explainable checks used by the repository scanner.

The scanner deliberately reports locations and rule names, never the value that
looked like a credential. It is intended as a fast baseline check and not as a
replacement for a full SAST or secret-history review.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, Severity


SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GitHub fine-grained token"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "provider API key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key"),
)

GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)"
    r"\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]"
)

PLACEHOLDER_MARKERS = (
    "example",
    "replace-me",
    "replace_me",
    "your-",
    "your_",
    "<your",
    "${",
    "redacted",
    "dummy",
    "changeme",
)


def _is_placeholder(value: str) -> bool:
    candidate = value.strip().lower()
    return not candidate or any(marker in candidate for marker in PLACEHOLDER_MARKERS)


def scan_text_for_secrets(text: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(line) and ("SECRET001", line_number) not in seen:
                findings.append(
                    Finding(
                        "SECRET001",
                        Severity.HIGH,
                        rel_path,
                        f"Potential {label} detected; value redacted.",
                        line_number,
                    )
                )
                seen.add(("SECRET001", line_number))

        match = GENERIC_ASSIGNMENT.search(line)
        if match and not _is_placeholder(match.group(1)) and ("SECRET001", line_number) not in seen:
            findings.append(
                Finding(
                    "SECRET001",
                    Severity.HIGH,
                    rel_path,
                    "Credential-like assignment detected; value redacted.",
                    line_number,
                )
            )
            seen.add(("SECRET001", line_number))

    return findings


def sensitive_path_finding(rel_path: str) -> Finding | None:
    path = Path(rel_path)
    name = path.name.lower()
    suffix = path.suffix.lower()

    is_env = name == ".env" or (name.startswith(".env.") and name not in {".env.example", ".env.template"})
    is_key_material = suffix in {".pem", ".key", ".p12", ".pfx", ".keystore"} or name in {
        "id_rsa",
        "id_ed25519",
        "credentials.json",
        "service-account.json",
    }
    if is_env or is_key_material:
        return Finding(
            "SECRET002",
            Severity.HIGH,
            rel_path,
            "Sensitive-looking file is present in the working tree; verify it is safe to publish.",
        )
    return None


def workflow_findings(text: str, rel_path: str) -> list[Finding]:
    if re.search(r"(?m)^\s*permissions\s*:", text):
        return []
    return [
        Finding(
            "GHA001",
            Severity.MEDIUM,
            rel_path,
            "GitHub Actions workflow does not declare an explicit permissions policy.",
        )
    ]


def dockerfile_findings(text: str, rel_path: str) -> list[Finding]:
    if not re.search(r"(?im)^\s*from\s+", text):
        return []
    if re.search(r"(?im)^\s*user\s+\S+", text):
        return []
    return [
        Finding(
            "DOCKER001",
            Severity.LOW,
            rel_path,
            "Container image does not declare a non-root USER; review whether one is appropriate.",
        )
    ]


def gitignore_findings(root: Path) -> list[Finding]:
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return [
            Finding(
                "GIT001",
                Severity.LOW,
                ".gitignore",
                "Repository has no .gitignore; add rules for local credentials and build output.",
            )
        ]

    try:
        lines = {line.strip().lower() for line in gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()}
    except OSError:
        return []

    findings: list[Finding] = []
    for pattern in (".env", "*.pem", "*.key"):
        if pattern not in lines:
            findings.append(
                Finding(
                    "GIT002",
                    Severity.LOW,
                    ".gitignore",
                    f"Recommended sensitive-file pattern {pattern!r} is missing.",
                )
            )
    return findings
