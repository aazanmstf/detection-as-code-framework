"""
Bridges an uploaded Sigma rule to the existing `validator` package without
modifying any validator code. Mirrors exactly what scripts/validate.py and
dashboard/backend.py already do: import validate_single_file /
validate_repository and call them.

Uploaded content is written to a private temp file (never into the real
detections/ tree, never at a path derived from user input) purely because
validate_single_file's signature takes a Path - the underlying checks
never execute the file, they only parse it as YAML.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import List, Optional

WEBAPP_ROOT = Path(__file__).resolve().parent
REPO_ROOT = WEBAPP_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))

from validator.rule_validator import validate_repository, validate_single_file  # noqa: E402

from webapp.explain import explain  # noqa: E402


def _issue_to_dict(issue) -> dict:
    exp = explain(issue.check)
    return {
        "check": issue.check,
        "severity": issue.severity,
        "message": issue.message,
        "plain_english": exp["plain_english"],
        "fix": exp["fix"],
    }


def validate_uploaded_rule(file_bytes: bytes, original_filename: str) -> dict:
    """
    Validate a single uploaded rule's bytes using the existing validator
    and return a plain dict shaped for storage/rendering. Also cross-checks
    the uploaded rule's id against every id already used by the production
    rules in detections/, since a single-file validation run can't see the
    rest of the repository.
    """
    with tempfile.TemporaryDirectory(prefix="dac_upload_") as tmp_dir:
        tmp_path = Path(tmp_dir) / "uploaded_rule.yml"
        tmp_path.write_bytes(file_bytes)

        result = validate_single_file(tmp_path, Path(tmp_dir))

    issues = [_issue_to_dict(i) for i in result.issues]

    duplicate_warning: Optional[str] = None
    if result.rule_id:
        duplicate_warning = _check_duplicate_against_production(result.rule_id, original_filename)
        if duplicate_warning:
            issues.append(
                {
                    "check": "duplicate_id",
                    "severity": "error",
                    "message": duplicate_warning,
                    **explain("duplicate_id"),
                }
            )

    passed = result.passed and not duplicate_warning

    return {
        "result": "PASS" if passed else "FAIL",
        "score": result.score.total,
        "title": result.title,
        "rule_id": result.rule_id,
        "attack_techniques": result.attack_techniques,
        "issues": issues,
        "duplicate_warning": duplicate_warning,
    }


def _check_duplicate_against_production(rule_id: str, original_filename: str) -> Optional[str]:
    """Check whether an uploaded rule's id collides with a rule already
    committed to detections/. Read-only: does not touch production files."""
    detections_dir = REPO_ROOT / "detections"
    if not detections_dir.exists():
        return None

    repo_result = validate_repository(detections_dir)
    for rule in repo_result.rules:
        if rule.rule_id == rule_id:
            return (
                f"This id is already used by an existing production rule "
                f"({rule.path}). Generate a new UUID for '{original_filename}'."
            )
    return None


def build_report_text(run) -> str:
    """Render a validation run (webapp.models.RunView) as a plain-text
    downloadable report."""
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("Detection as Code - Validation Report")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"File:      {run.original_filename}")
    lines.append(f"Submitted: {run.submitted_at}")
    lines.append(f"Rule ID:   {run.rule_id or '(none / invalid)'}")
    lines.append(f"Title:     {run.rule_title or '(none)'}")
    lines.append(f"Result:    {run.result}")
    lines.append(f"Score:     {run.score}/100")
    lines.append("")

    if run.attack_techniques:
        lines.append("MITRE ATT&CK techniques: " + ", ".join(run.attack_techniques))
    else:
        lines.append("MITRE ATT&CK techniques: none mapped")
    lines.append("")

    lines.append("-" * 60)
    lines.append("Issues")
    lines.append("-" * 60)
    if not run.issues:
        lines.append("None - this rule passed every check.")
    else:
        for i, issue in enumerate(run.issues, start=1):
            lines.append(f"\n{i}. [{issue['severity'].upper()}] {issue['check']}")
            lines.append(f"   Validator message: {issue['message']}")
            lines.append(f"   What this means:   {issue['plain_english']}")
            lines.append(f"   Suggested fix:     {issue['fix']}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("This report reflects static Sigma rule validation only. "
                  "It does not execute against a live SIEM.")
    return "\n".join(lines)
