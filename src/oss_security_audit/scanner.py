from __future__ import annotations

from pathlib import Path

from .models import Finding, ScanSummary
from .rules import (
    dockerfile_findings,
    gitignore_findings,
    scan_text_for_secrets,
    sensitive_path_finding,
    workflow_findings,
)

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}
MAX_FILE_BYTES = 1_048_576


def _iter_files(root: Path, excluded_dirs: set[str]):
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            relative = path.relative_to(root)
            if any(part in excluded_dirs for part in relative.parts):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path, relative.as_posix()


def _read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def scan_repository(path: str | Path, excludes: tuple[str, ...] = ()) -> ScanSummary:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"scan path is not a directory: {path}")

    excluded_dirs = DEFAULT_EXCLUDED_DIRS | {item.strip("/\\") for item in excludes if item.strip("/\\")}
    findings: list[Finding] = []
    files_scanned = 0

    for file_path, relative_path in _iter_files(root, excluded_dirs):
        files_scanned += 1
        sensitive = sensitive_path_finding(relative_path)
        if sensitive:
            findings.append(sensitive)

        text = _read_text(file_path)
        if text is None:
            continue
        findings.extend(scan_text_for_secrets(text, relative_path))

        lower_path = relative_path.lower()
        if lower_path.startswith(".github/workflows/") and file_path.suffix.lower() in {".yml", ".yaml"}:
            findings.extend(workflow_findings(text, relative_path))
        if file_path.name.lower().startswith("dockerfile"):
            findings.extend(dockerfile_findings(text, relative_path))

    findings.extend(gitignore_findings(root))
    findings.sort(key=lambda item: (-int(item.severity), item.path, item.line or 0, item.rule_id))
    return ScanSummary(files_scanned=files_scanned, findings=tuple(findings))
