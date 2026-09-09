"""
Validates optional Splunk compatibility metadata (`x_splunk`) attached to
a Sigma rule.

IMPORTANT: This performs *static metadata validation only*. It does not
parse or execute real SPL, and it does not connect to a Splunk instance.
See README.md "Splunk Compatibility" section for the full explanation of
this distinction.
"""

from __future__ import annotations

from typing import Any, Dict

from validator.models import ALLOWED_SPLUNK_QUERY_TYPES, RuleResult


def run(rule: Dict[str, Any], result: RuleResult) -> None:
    x_splunk = rule.get("x_splunk")

    if x_splunk is None:
        return  # Splunk metadata is optional; nothing to validate.

    if not isinstance(x_splunk, dict):
        result.add_error("splunk_metadata", "x_splunk must be a mapping")
        return

    data_model = x_splunk.get("data_model")
    if not data_model or not isinstance(data_model, str):
        result.add_error(
            "splunk_metadata",
            "x_splunk.data_model is required and must be a non-empty string",
        )

    query_type = x_splunk.get("query_type")
    if not query_type or not isinstance(query_type, str):
        result.add_error(
            "splunk_metadata",
            "x_splunk.query_type is required and must be a non-empty string",
        )
    elif query_type not in ALLOWED_SPLUNK_QUERY_TYPES:
        allowed = ", ".join(sorted(ALLOWED_SPLUNK_QUERY_TYPES))
        result.add_error(
            "splunk_metadata",
            f"x_splunk.query_type '{query_type}' is not allowed. "
            f"Allowed values: {allowed}",
        )

    fields = x_splunk.get("fields")
    if fields is not None:
        if not isinstance(fields, list):
            result.add_error("splunk_metadata", "x_splunk.fields must be a list")
        else:
            for field_name in fields:
                if not isinstance(field_name, str) or not field_name.strip():
                    result.add_error(
                        "splunk_metadata",
                        "x_splunk.fields contains an empty or non-string field name",
                    )
                    break
