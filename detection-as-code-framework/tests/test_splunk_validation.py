"""Tests for validator.splunk_validator."""

from pathlib import Path

from validator import splunk_validator
from validator.models import RuleResult
from validator.rule_validator import validate_single_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_missing_x_splunk_is_not_an_error():
    result = RuleResult(path="test.yml")
    splunk_validator.run({}, result)
    assert result.issues == []


def test_valid_x_splunk_metadata_passes():
    result = RuleResult(path="test.yml")
    rule = {
        "x_splunk": {
            "data_model": "Endpoint",
            "query_type": "tstats",
            "fields": ["Processes.process", "Processes.parent_process"],
        }
    }
    splunk_validator.run(rule, result)
    assert result.issues == []


def test_x_splunk_must_be_a_mapping():
    result = RuleResult(path="test.yml")
    rule = {"x_splunk": ["not", "a", "mapping"]}
    splunk_validator.run(rule, result)
    assert any(i.check == "splunk_metadata" for i in result.issues)


def test_missing_data_model_fails():
    result = RuleResult(path="test.yml")
    rule = {"x_splunk": {"query_type": "search"}}
    splunk_validator.run(rule, result)
    assert any("data_model" in i.message for i in result.issues)


def test_missing_query_type_fails():
    result = RuleResult(path="test.yml")
    rule = {"x_splunk": {"data_model": "Endpoint"}}
    splunk_validator.run(rule, result)
    assert any("query_type" in i.message for i in result.issues)


def test_disallowed_query_type_fails():
    result = RuleResult(path="test.yml")
    rule = {"x_splunk": {"data_model": "Endpoint", "query_type": "delete_everything"}}
    splunk_validator.run(rule, result)
    assert any(
        i.check == "splunk_metadata" and "not allowed" in i.message for i in result.issues
    )


def test_allowed_query_types_all_pass():
    for query_type in ("search", "tstats", "transaction"):
        result = RuleResult(path="test.yml")
        rule = {"x_splunk": {"data_model": "Endpoint", "query_type": query_type}}
        splunk_validator.run(rule, result)
        assert result.issues == [], f"query_type={query_type} unexpectedly failed"


def test_fields_must_be_a_list():
    result = RuleResult(path="test.yml")
    rule = {
        "x_splunk": {
            "data_model": "Endpoint",
            "query_type": "search",
            "fields": "Processes.process",
        }
    }
    splunk_validator.run(rule, result)
    assert any("fields must be a list" in i.message for i in result.issues)


def test_empty_field_name_fails():
    result = RuleResult(path="test.yml")
    rule = {
        "x_splunk": {
            "data_model": "Endpoint",
            "query_type": "search",
            "fields": ["Processes.process", ""],
        }
    }
    splunk_validator.run(rule, result)
    assert any("empty" in i.message.lower() for i in result.issues)


def test_production_rules_with_splunk_metadata_are_valid():
    repo_root = Path(__file__).parent.parent
    detections_dir = repo_root / "detections"
    rules_with_splunk = []
    for rule_file in sorted(detections_dir.rglob("*.yml")):
        result = validate_single_file(rule_file, repo_root)
        if result.raw.get("x_splunk") is not None:
            rules_with_splunk.append(result)
            splunk_errors = [i for i in result.issues if i.check == "splunk_metadata"]
            assert splunk_errors == [], f"{rule_file}: {splunk_errors}"

    # At least 2 production rules should include optional Splunk metadata.
    assert len(rules_with_splunk) >= 2
