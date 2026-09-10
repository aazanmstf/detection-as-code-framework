"""
Translates the existing validator's technical ValidationIssue objects into
plain-English explanations and concrete fix suggestions for the web UI.

This module does NOT change validator behavior or messages - it only
*interprets* the `check` field that validator/*.py already attaches to
every issue (see validator/models.py: ValidationIssue.check). If the
validator adds a new check name this module doesn't recognize yet, we
fall back to showing the validator's own message with a generic fix tip
rather than failing.
"""

from __future__ import annotations

from typing import Dict, TypedDict


class Explanation(TypedDict):
    plain_english: str
    fix: str


# Keyed by ValidationIssue.check (see validator/metadata_validator.py,
# detection_validator.py, attack_validator.py, splunk_validator.py,
# rule_validator.py for the exact check names in use).
EXPLANATIONS: Dict[str, Explanation] = {
    "yaml_parse": {
        "plain_english": "The file isn't valid YAML, so it can't be read as a rule at all.",
        "fix": "Check for missing colons, bad indentation, or unclosed quotes/brackets. "
        "Paste the file into a YAML validator to find the exact line.",
    },
    "yaml_read": {
        "plain_english": "The file couldn't be read from disk.",
        "fix": "Re-upload the file; if this keeps happening, try re-saving it with UTF-8 encoding.",
    },
    "required_field": {
        "plain_english": "A field Sigma requires for every rule is missing or empty.",
        "fix": "Add the missing field. Every rule needs: title, id, status, description, "
        "author, date, logsource, detection, falsepositives, level, and tags.",
    },
    "status": {
        "plain_english": "The 'status' field has a value Sigma doesn't recognize.",
        "fix": "Set status to one of: experimental, test, stable, or deprecated.",
    },
    "level": {
        "plain_english": "The 'level' (severity) field has a value that isn't allowed.",
        "fix": "Set level to one of: informational, low, medium, high, or critical.",
    },
    "logsource": {
        "plain_english": "The rule doesn't say clearly what kind of logs it applies to.",
        "fix": "Add at least one of category, product, or service under logsource "
        "(e.g. category: process_creation, product: windows).",
    },
    "description_quality": {
        "plain_english": "The description is too short to explain what the rule detects.",
        "fix": "Expand the description to a sentence or two covering what behavior "
        "the rule looks for and why it matters.",
    },
    "uuid": {
        "plain_english": "The rule's 'id' field isn't a valid UUID.",
        "fix": "Generate a proper UUID, e.g. in Python: "
        "import uuid; print(uuid.uuid4()) - and use that as the id.",
    },
    "duplicate_id": {
        "plain_english": "Another rule already uses this exact id.",
        "fix": "Generate a new, unique UUID for this rule so it doesn't collide with an existing one.",
    },
    "detection_logic": {
        "plain_english": "The detection logic itself has a structural problem - "
        "most often the condition references a selection that doesn't exist.",
        "fix": "Make sure every name used in 'condition' matches a selection defined "
        "in the detection block exactly (check spelling and underscores).",
    },
    "attack_mapping": {
        "plain_english": "One of the MITRE ATT&CK tags is formatted incorrectly.",
        "fix": "ATT&CK tags must look like attack.t1059 or attack.t1059.001 "
        "(lowercase 'attack.', a 't', then 4 digits, optionally a sub-technique).",
    },
    "splunk_metadata": {
        "plain_english": "The optional Splunk compatibility metadata (x_splunk) is present "
        "but not structured correctly.",
        "fix": "x_splunk needs a data_model (string), a query_type of search/tstats/"
        "transaction, and if present, fields must be a list of non-empty strings.",
    },
}

DEFAULT_EXPLANATION: Explanation = {
    "plain_english": "The validator flagged an issue with this rule.",
    "fix": "Review the message above and compare against a passing rule in detections/ for reference.",
}


def explain(check: str) -> Explanation:
    return EXPLANATIONS.get(check, DEFAULT_EXPLANATION)
