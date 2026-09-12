"""
Validates MITRE ATT&CK tags on a Sigma rule and extracts technique IDs for
repository-level coverage reporting.

Recognized formats:
    attack.T1059
    attack.T1059.001

This module intentionally does NOT validate technique IDs against the live
ATT&CK dataset (that would require bundling or downloading the full ATT&CK
STIX corpus). It validates *formatting* only, and coverage reporting is
explicitly labeled as repository-level, not enterprise ATT&CK coverage.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from validator.models import RuleResult

ATTACK_TAG_PATTERN = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def is_valid_attack_tag(tag: str) -> bool:
    return bool(ATTACK_TAG_PATTERN.match(tag.strip()))


def extract_technique_id(tag: str) -> str:
    """Given a tag like 'attack.t1059.001', return normalized 'T1059.001'."""
    match = ATTACK_TAG_PATTERN.match(tag.strip())
    if not match:
        return ""
    return match.group(1).upper()


def run(rule: Dict[str, Any], result: RuleResult) -> None:
    tags = rule.get("tags")
    if tags is None:
        return  # missing 'tags' already reported by metadata_validator

    if not isinstance(tags, list):
        result.add_error("attack_mapping", "tags must be a list")
        return

    attack_tags = [t for t in tags if isinstance(t, str) and t.lower().startswith("attack.t")]

    if not attack_tags:
        result.add_warning(
            "attack_mapping",
            "No MITRE ATT&CK technique tags found (expected 'attack.tXXXX')",
        )
        return

    techniques: List[str] = []
    for tag in attack_tags:
        if not is_valid_attack_tag(tag):
            result.add_error(
                "attack_mapping",
                f"Invalid ATT&CK tag format: '{tag}' "
                "(expected 'attack.tXXXX' or 'attack.tXXXX.XXX')",
            )
            continue
        techniques.append(extract_technique_id(tag))

    result.attack_techniques = sorted(set(techniques))
