from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Severity ordering used for output and CI exit decisions."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    """One redacted, location-aware security finding."""

    rule_id: str
    severity: Severity
    path: str
    message: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        return data


@dataclass(frozen=True)
class ScanSummary:
    files_scanned: int
    findings: tuple[Finding, ...]
