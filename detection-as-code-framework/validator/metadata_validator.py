"""
Validates required Sigma metadata fields: presence of required fields,
allowed status values, allowed severity levels, and a minimally useful
logsource block.
"""

from __future__ import annotations

from typing import Any, Dict

from validator.models import (
    ALLOWED_LEVELS,
    ALLOWED_STATUSES,
    REQUIRED_METADATA_FIELDS,
    RuleResult,
)

LOGSOURCE_USEFUL_KEYS = {"category", "product", "service"}


def validate_required_fields(rule: Dict[str, Any], result: RuleResult) -> None:
    """Ensure every required top-level field is present and non-empty."""
    for field_name in REQUIRED_METADATA_FIELDS:
        if field_name not in rule:
            result.add_error(
                "required_field",
                f"Missing required field: {field_name}",
            )
            continue

        value = rule[field_name]
        if value is None:
            result.add_error(
                "required_field",
                f"Required field '{field_name}' is empty",
            )
        elif isinstance(value, (str, list, dict)) and len(value) == 0:
            result.add_error(
                "required_field",
                f"Required field '{field_name}' is empty",
            )


def validate_status(rule: Dict[str, Any], result: RuleResult) -> None:
    """Ensure status is one of the allowed Sigma lifecycle values."""
    status = rule.get("status")
    if status is None:
        return  # already reported by validate_required_fields
    if status not in ALLOWED_STATUSES:
        allowed = ", ".join(sorted(ALLOWED_STATUSES))
        result.add_error(
            "status",
            f"Invalid status '{status}'. Allowed values: {allowed}",
        )


def validate_level(rule: Dict[str, Any], result: RuleResult) -> None:
    """Ensure level (severity) is one of the allowed values."""
    level = rule.get("level")
    if level is None:
        return  # already reported by validate_required_fields
    if level not in ALLOWED_LEVELS:
        allowed = ", ".join(sorted(ALLOWED_LEVELS))
        result.add_error(
            "level",
            f"Invalid level '{level}'. Allowed values: {allowed}",
        )


def validate_logsource(rule: Dict[str, Any], result: RuleResult) -> None:
    """Ensure logsource is present and contains at least one useful key."""
    logsource = rule.get("logsource")
    if logsource is None:
        return  # already reported by validate_required_fields

    if not isinstance(logsource, dict):
        result.add_error(
            "logsource",
            "logsource must be a mapping (e.g. category/product/service)",
        )
        return

    present_keys = LOGSOURCE_USEFUL_KEYS.intersection(logsource.keys())
    if not present_keys:
        result.add_error(
            "logsource",
            "logsource does not contain any of the useful keys: "
            + ", ".join(sorted(LOGSOURCE_USEFUL_KEYS)),
        )
        return

    # Catch logsources where the useful keys exist but are empty strings.
    for key in present_keys:
        if not str(logsource.get(key, "")).strip():
            result.add_error(
                "logsource",
                f"logsource field '{key}' is present but empty",
            )


def validate_description_quality(rule: Dict[str, Any], result: RuleResult) -> bool:
    """
    Lightweight heuristic check used both for warnings and for the quality
    score: a description should be reasonably descriptive, not a one-word
    placeholder.

    Returns True if the description meets the quality bar.
    """
    description = rule.get("description")
    if not isinstance(description, str):
        return False

    cleaned = description.strip()
    if len(cleaned) < 30:
        result.add_warning(
            "description_quality",
            "Description is very short; consider adding more context "
            "about the detection's purpose and behavior.",
        )
        return False
    return True


def run(rule: Dict[str, Any], result: RuleResult) -> None:
    """Run all metadata validation checks against a parsed rule."""
    validate_required_fields(rule, result)
    validate_status(rule, result)
    validate_level(rule, result)
    validate_logsource(rule, result)
    validate_description_quality(rule, result)
