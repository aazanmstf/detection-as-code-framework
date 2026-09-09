"""Tests for validator.detection_validator (condition parsing and checks)."""

from pathlib import Path

from validator.models import RuleResult
from validator.rule_validator import validate_single_file
from validator import detection_validator

FIXTURES = Path(__file__).parent / "fixtures"


def _run(detection: dict) -> RuleResult:
    result = RuleResult(path="test.yml")
    rule = {"detection": detection}
    detection_validator.run(rule, result)
    return result


def test_simple_valid_condition_passes():
    result = _run(
        {
            "selection": {"Image|endswith": "powershell.exe"},
            "condition": "selection",
        }
    )
    assert not any(i.severity == "error" for i in result.issues)


def test_and_condition_passes():
    result = _run(
        {
            "selection": {"Image|endswith": "powershell.exe"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and filter",
        }
    )
    assert not any(i.severity == "error" for i in result.issues)


def test_and_not_condition_passes():
    result = _run(
        {
            "selection": {"Image|endswith": "powershell.exe"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        }
    )
    assert not any(i.severity == "error" for i in result.issues)


def test_or_condition_passes():
    result = _run(
        {
            "selection_a": {"Image|endswith": "cmd.exe"},
            "selection_b": {"Image|endswith": "powershell.exe"},
            "condition": "selection_a or selection_b",
        }
    )
    assert not any(i.severity == "error" for i in result.issues)


def test_wildcard_of_condition_passes():
    result = _run(
        {
            "selection_a": {"Image|endswith": "cmd.exe"},
            "selection_b": {"Image|endswith": "powershell.exe"},
            "condition": "1 of selection*",
        }
    )
    assert not any(i.severity == "error" for i in result.issues)


def test_all_of_wildcard_condition_passes():
    result = _run(
        {
            "filter_a": {"User": "SYSTEM"},
            "filter_b": {"Workstation": "DC01"},
            "condition": "all of filter*",
        }
    )
    assert not any(i.severity == "error" for i in result.issues)


def test_condition_referencing_unknown_selection_fails():
    result = _run(
        {
            "selection": {"Image|endswith": "powershell.exe"},
            "condition": "nonexistent_selection",
        }
    )
    assert any(i.check == "detection_logic" for i in result.issues)


def test_wildcard_condition_matching_nothing_fails():
    result = _run(
        {
            "selection": {"Image|endswith": "powershell.exe"},
            "condition": "1 of filter*",
        }
    )
    assert any(i.check == "detection_logic" for i in result.issues)


def test_missing_detection_block_fails():
    result = RuleResult(path="test.yml")
    detection_validator.run({}, result)
    assert any("Missing required field: detection" in i.message for i in result.issues)


def test_missing_condition_fails():
    result = _run({"selection": {"Image": "x"}})
    assert any("Missing required field: condition" in i.message for i in result.issues)


def test_empty_condition_fails():
    result = _run({"selection": {"Image": "x"}, "condition": "   "})
    assert any(i.check == "detection_logic" for i in result.issues)


def test_no_selections_defined_fails():
    result = _run({"condition": "selection"})
    assert any("no selections" in i.message for i in result.issues)


def test_empty_selection_fails():
    result = _run({"selection": {}, "condition": "selection"})
    assert any("is empty" in i.message for i in result.issues)


def test_invalid_rule_fixture_has_unknown_selection_reference():
    result = validate_single_file(FIXTURES / "invalid_rule.yml", FIXTURES)
    assert any(
        i.check == "detection_logic" and "unknown selection" in i.message.lower()
        for i in result.issues
    )


def test_production_rules_pass_detection_logic():
    repo_root = Path(__file__).parent.parent
    detections_dir = repo_root / "detections"
    for rule_file in sorted(detections_dir.rglob("*.yml")):
        result = validate_single_file(rule_file, repo_root)
        logic_errors = [i for i in result.issues if i.check == "detection_logic"]
        assert logic_errors == [], f"{rule_file}: {logic_errors}"
