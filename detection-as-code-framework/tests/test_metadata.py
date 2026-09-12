"""Tests for validator.metadata_validator and YAML parsing behavior."""

from pathlib import Path

import pytest

from validator.models import RuleResult
from validator.rule_validator import load_rule, validate_single_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_valid_yaml_parses_successfully():
    result = RuleResult(path="valid_rule.yml")
    rule = load_rule(FIXTURES / "valid_rule.yml", result)
    assert rule is not None
    assert result.issues == []


def test_invalid_yaml_syntax_is_reported(tmp_path):
    broken_file = tmp_path / "broken.yml"
    broken_file.write_text("title: [unclosed list\ndetection: {", encoding="utf-8")

    result = RuleResult(path="broken.yml")
    rule = load_rule(broken_file, result)

    assert rule is None
    assert any(issue.check == "yaml_parse" for issue in result.issues)


def test_empty_yaml_file_is_reported(tmp_path):
    empty_file = tmp_path / "empty.yml"
    empty_file.write_text("", encoding="utf-8")

    result = RuleResult(path="empty.yml")
    rule = load_rule(empty_file, result)

    assert rule is None
    assert any(issue.check == "yaml_parse" for issue in result.issues)


def test_non_mapping_yaml_root_is_rejected(tmp_path):
    list_file = tmp_path / "list_root.yml"
    list_file.write_text("- one\n- two\n", encoding="utf-8")

    result = RuleResult(path="list_root.yml")
    rule = load_rule(list_file, result)

    assert rule is None
    assert any(issue.check == "yaml_parse" for issue in result.issues)


def test_missing_required_fields_are_reported():
    result = validate_single_file(FIXTURES / "invalid_rule.yml", FIXTURES)
    error_messages = [i.message for i in result.issues if i.severity == "error"]

    assert any("Missing required field: author" in m for m in error_messages)
    assert any("Missing required field: date" in m for m in error_messages)


def test_invalid_status_is_rejected():
    result = validate_single_file(FIXTURES / "invalid_rule.yml", FIXTURES)
    assert any(i.check == "status" for i in result.issues)


def test_invalid_level_is_rejected():
    result = validate_single_file(FIXTURES / "invalid_rule.yml", FIXTURES)
    assert any(i.check == "level" for i in result.issues)


def test_valid_status_and_level_pass():
    result = validate_single_file(FIXTURES / "valid_rule.yml", FIXTURES)
    assert not any(i.check == "status" for i in result.issues)
    assert not any(i.check == "level" for i in result.issues)


def test_logsource_missing_useful_keys_is_rejected():
    result = RuleResult(path="test.yml")
    rule = {
        "title": "t",
        "id": "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d",
        "status": "stable",
        "description": "x" * 40,
        "author": "a",
        "date": "2024-01-01",
        "logsource": {"unrelated_key": "value"},
        "detection": {"selection": {"Image": "x"}, "condition": "selection"},
        "falsepositives": ["none"],
        "level": "low",
        "tags": ["attack.t1059"],
    }

    from validator import metadata_validator

    metadata_validator.validate_logsource(rule, result)
    assert any(i.check == "logsource" for i in result.issues)


def test_production_rules_pass_metadata_validation():
    """Every production rule under detections/ must have clean metadata."""
    repo_root = Path(__file__).parent.parent
    detections_dir = repo_root / "detections"
    rule_files = sorted(detections_dir.rglob("*.yml"))
    assert len(rule_files) >= 5

    for rule_file in rule_files:
        result = validate_single_file(rule_file, repo_root)
        metadata_errors = [
            i
            for i in result.issues
            if i.severity == "error"
            and i.check in {"required_field", "status", "level", "logsource"}
        ]
        assert metadata_errors == [], f"{rule_file}: {metadata_errors}"
