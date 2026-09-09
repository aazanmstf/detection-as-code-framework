#!/usr/bin/env python3
"""
CLI entry point for the Detection as Code Validation Framework.

Usage:
    python scripts/validate.py
    python scripts/validate.py --path detections
    python scripts/validate.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

# Allow running as `python scripts/validate.py` from the repo root without
# installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validator import coverage as coverage_mod
from validator.rule_validator import validate_repository

CHECK_ORDER = ["required_field", "status", "level", "logsource", "uuid", "detection_logic", "attack_mapping", "splunk_metadata"]

CHECK_LABELS = {
    "required_field": "Metadata",
    "status": "Metadata",
    "level": "Metadata",
    "logsource": "Metadata",
    "uuid": "UUID",
    "detection_logic": "Detection Logic",
    "attack_mapping": "ATT&CK",
    "splunk_metadata": "Splunk",
    "duplicate_id": "UUID",
    "yaml_parse": "Metadata",
    "yaml_read": "Metadata",
}

DISPLAY_CATEGORY_ORDER = ["Metadata", "UUID", "Detection Logic", "ATT&CK", "Splunk"]


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="validate.py",
        description="Validate Sigma detection rules for metadata, logic, "
        "MITRE ATT&CK mapping, and Splunk compatibility.",
    )
    parser.add_argument(
        "--path",
        default="detections",
        help="Directory to recursively scan for detection rules (default: detections)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output instead of human-readable text",
    )
    return parser.parse_args(argv)


def category_status(repo_result, category: str) -> str:
    """Return PASS/FAIL for a display category (e.g. 'Metadata') based on
    whether any error-level issue from a matching check exists."""
    for issue in repo_result.all_issues:
        if issue.severity != "error":
            continue
        if CHECK_LABELS.get(issue.check) == category:
            return "FAIL"
    return "PASS"


def render_text_report(repo_result) -> str:
    lines: List[str] = []
    width = 60
    lines.append("=" * width)
    lines.append("Detection as Code Validation Framework")
    lines.append("=" * width)
    lines.append("")
    lines.append(f"Rules discovered: {len(repo_result.rules)}")
    lines.append("")
    lines.append("Validation:")
    for category in DISPLAY_CATEGORY_ORDER:
        status = category_status(repo_result, category)
        dots = "." * (16 - len(category))
        lines.append(f"  {category} {dots} {status}")

    if repo_result.duplicate_id_issues:
        lines.append("")
        lines.append("Duplicate IDs:")
        for issue in repo_result.duplicate_id_issues:
            lines.append(f"  ERROR: {issue.message}")

    lines.append("")
    lines.append("-" * width)
    lines.append("Errors and Warnings")
    lines.append("-" * width)
    any_issue = False
    for rule in repo_result.rules:
        if not rule.issues:
            continue
        any_issue = True
        lines.append(f"\n{rule.path}")
        for issue in rule.issues:
            lines.append(f"  {issue}")
    if not any_issue:
        lines.append("  None")

    lines.append("")
    lines.append("-" * width)
    lines.append("Quality")
    lines.append("-" * width)
    for rule in repo_result.rules:
        lines.append(f"  {rule.path}")
        lines.append(f"    Quality Score: {rule.score.total}/100")
    lines.append(f"\n  Average Rule Score: {repo_result.average_score:.0f}/100")

    report = coverage_mod.build_coverage_report(repo_result)
    lines.append("")
    lines.append("-" * width)
    lines.append("MITRE ATT&CK Coverage (repository-level)")
    lines.append("-" * width)
    lines.append(f"  Rules: {report.total_rules}")
    lines.append(f"  Unique Techniques: {report.unique_techniques}")
    lines.append(f"  Unmapped Rules: {len(report.unmapped_rules)}")
    if report.technique_rows():
        lines.append("")
        for row in report.technique_rows():
            technique = row["technique"].ljust(12)
            name = (row["name"] + " ").ljust(33)
            count = row["count"]
            noun = "rule" if count == "1" else "rules"
            lines.append(f"  {technique}{name}{count} {noun}")

    lines.append("")
    lines.append("=" * width)
    lines.append("RESULT")
    lines.append("=" * width)
    lines.append("PASS" if repo_result.passed else "FAIL")

    return "\n".join(lines)


def build_json_report(repo_result) -> dict:
    report = coverage_mod.build_coverage_report(repo_result)
    return {
        "rules_discovered": len(repo_result.rules),
        "result": "PASS" if repo_result.passed else "FAIL",
        "average_score": round(repo_result.average_score, 2),
        "duplicate_ids": [issue.message for issue in repo_result.duplicate_id_issues],
        "rules": [
            {
                "path": rule.path,
                "id": rule.rule_id,
                "title": rule.title,
                "passed": rule.passed,
                "score": rule.score.as_dict(),
                "attack_techniques": rule.attack_techniques,
                "issues": [
                    {
                        "check": issue.check,
                        "severity": issue.severity,
                        "message": issue.message,
                    }
                    for issue in rule.issues
                ],
            }
            for rule in repo_result.rules
        ],
        "attack_coverage": {
            "total_rules": report.total_rules,
            "unique_techniques": report.unique_techniques,
            "unmapped_rules": report.unmapped_rules,
            "techniques": report.technique_rows(),
        },
    }


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    base_path = Path(args.path)

    repo_result = validate_repository(base_path)

    if args.json:
        print(json.dumps(build_json_report(repo_result), indent=2))
    else:
        print(render_text_report(repo_result))

    return 0 if repo_result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
