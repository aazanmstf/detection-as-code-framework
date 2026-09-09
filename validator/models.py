"""
Data models used across the validation engine.

These are intentionally simple dataclasses rather than a heavyweight
schema library, to keep the codebase easy to read for a portfolio /
interview setting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


ALLOWED_STATUSES = {"experimental", "test", "stable", "deprecated"}

ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}

ALLOWED_SPLUNK_QUERY_TYPES = {"search", "tstats", "transaction"}

REQUIRED_METADATA_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
]


@dataclass
class ValidationIssue:
    """A single validation error or warning tied to a rule file."""

    file: str
    check: str
    message: str
    severity: str = "error"  # "error" or "warning"

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.file} ({self.check}): {self.message}"


@dataclass
class QualityScore:
    """Breakdown of the 100-point detection quality score."""

    metadata_complete: int = 0
    valid_uuid: int = 0
    valid_detection_logic: int = 0
    mitre_mapping: int = 0
    false_positives: int = 0
    splunk_metadata: int = 0
    description_quality: int = 0

    @property
    def total(self) -> int:
        return (
            self.metadata_complete
            + self.valid_uuid
            + self.valid_detection_logic
            + self.mitre_mapping
            + self.false_positives
            + self.splunk_metadata
            + self.description_quality
        )

    def as_dict(self) -> Dict[str, int]:
        return {
            "metadata_complete": self.metadata_complete,
            "valid_uuid": self.valid_uuid,
            "valid_detection_logic": self.valid_detection_logic,
            "mitre_mapping": self.mitre_mapping,
            "false_positives": self.false_positives,
            "splunk_metadata": self.splunk_metadata,
            "description_quality": self.description_quality,
            "total": self.total,
        }


@dataclass
class RuleResult:
    """The full validation result for a single detection rule file."""

    path: str
    rule_id: str = ""
    title: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    issues: List[ValidationIssue] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    score: QualityScore = field(default_factory=QualityScore)

    @property
    def passed(self) -> bool:
        return not any(i.severity == "error" for i in self.issues)

    def add_error(self, check: str, message: str) -> None:
        self.issues.append(ValidationIssue(self.path, check, message, "error"))

    def add_warning(self, check: str, message: str) -> None:
        self.issues.append(ValidationIssue(self.path, check, message, "warning"))


@dataclass
class RepositoryResult:
    """Aggregated validation result across the whole repository."""

    rules: List[RuleResult] = field(default_factory=list)
    duplicate_id_issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def all_issues(self) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = list(self.duplicate_id_issues)
        for rule in self.rules:
            issues.extend(rule.issues)
        return issues

    @property
    def passed(self) -> bool:
        if self.duplicate_id_issues:
            return False
        return all(rule.passed for rule in self.rules)

    @property
    def average_score(self) -> float:
        if not self.rules:
            return 0.0
        return sum(r.score.total for r in self.rules) / len(self.rules)
