"""
Validates the `detection` block of a Sigma rule: presence of selections,
presence and non-emptiness of the condition, and that the condition only
references selections that actually exist.

This is a lightweight condition checker, NOT a full Sigma condition
grammar implementation. It supports the common patterns used in this
repository's rules:

    selection
    selection_a and selection_b
    selection_a or selection_b
    selection_a and not selection_b
    1 of selection*
    all of selection*

Anything more exotic is out of scope and is documented as a limitation.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from validator.models import RuleResult

# Tokens that are part of Sigma condition grammar rather than selection
# names. These are stripped out before we check "does this identifier
# refer to a real selection".
CONDITION_KEYWORDS = {"and", "or", "not", "of", "1", "all"}

# Matches "1 of selection*" / "all of filter*" style aggregate references.
_WILDCARD_OF_PATTERN = re.compile(
    r"\b(?:\d+|all)\s+of\s+([A-Za-z0-9_\*]+)", re.IGNORECASE
)

# Matches bare identifiers (selection/filter names), letters/digits/underscore.
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _extract_selection_dict(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Return all keys in the detection block except 'condition'."""
    return {k: v for k, v in detection.items() if k != "condition"}


def _referenced_identifiers(condition: str) -> List[str]:
    """
    Extract identifier-like tokens from a condition string, excluding
    Sigma grammar keywords (and/or/not/of/1/all) and wildcard suffixes.
    """
    identifiers = []
    for match in _IDENTIFIER_PATTERN.finditer(condition):
        token = match.group(0)
        if token.lower() in CONDITION_KEYWORDS:
            continue
        identifiers.append(token)
    return identifiers


def _matches_wildcard(name: str, pattern: str) -> bool:
    """Match a selection name against a simple 'prefix*' wildcard pattern."""
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def validate_detection_block(rule: Dict[str, Any], result: RuleResult) -> None:
    detection = rule.get("detection")

    if detection is None:
        result.add_error("detection_logic", "Missing required field: detection")
        return

    if not isinstance(detection, dict):
        result.add_error("detection_logic", "detection must be a mapping")
        return

    condition = detection.get("condition")
    if condition is None:
        result.add_error("detection_logic", "Missing required field: condition")
        return

    if not isinstance(condition, str) or not condition.strip():
        result.add_error("detection_logic", "condition must be a non-empty string")
        return

    selections = _extract_selection_dict(detection)
    if not selections:
        result.add_error(
            "detection_logic",
            "detection block defines a condition but no selections",
        )
        return

    for name, body in selections.items():
        if body is None or (isinstance(body, (list, dict, str)) and len(body) == 0):
            result.add_error(
                "detection_logic",
                f"Selection '{name}' is empty",
            )

    _validate_condition_references(condition, selections, result)


def _validate_condition_references(
    condition: str, selections: Dict[str, Any], result: RuleResult
) -> None:
    """
    Ensure every non-wildcard identifier referenced in the condition maps
    to a real selection, and every wildcard pattern ('selection*') matches
    at least one real selection.
    """
    selection_names = set(selections.keys())

    # Handle "N of pattern*" / "all of pattern*" wildcard references first,
    # then remove them from the string so their pattern text (which contains
    # a '*' and isn't a plain identifier) doesn't get mis-parsed below.
    remaining_condition = condition
    for wildcard_match in _WILDCARD_OF_PATTERN.finditer(condition):
        pattern = wildcard_match.group(1)
        if pattern.endswith("*"):
            if not any(_matches_wildcard(n, pattern) for n in selection_names):
                result.add_error(
                    "detection_logic",
                    f"Condition references wildcard pattern '{pattern}' "
                    "that matches no selections",
                )
        else:
            # "1 of selection_name" without a wildcard - treat as a direct reference.
            if pattern not in selection_names:
                result.add_error(
                    "detection_logic",
                    f"Condition references unknown selection: '{pattern}'",
                )
        remaining_condition = remaining_condition.replace(wildcard_match.group(0), "")

    for identifier in _referenced_identifiers(remaining_condition):
        if identifier.endswith("*"):
            # Bare wildcard identifier not covered by the "N of" pattern above.
            if not any(_matches_wildcard(n, identifier) for n in selection_names):
                result.add_error(
                    "detection_logic",
                    f"Condition references wildcard pattern '{identifier}' "
                    "that matches no selections",
                )
            continue
        if identifier not in selection_names:
            result.add_error(
                "detection_logic",
                f"Condition references unknown selection: '{identifier}'",
            )


def run(rule: Dict[str, Any], result: RuleResult) -> None:
    validate_detection_block(rule, result)
