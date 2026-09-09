"""Tests for validator.attack_validator and validator.coverage."""

from pathlib import Path

from validator import attack_validator, coverage
from validator.models import RuleResult
from validator.rule_validator import validate_repository, validate_single_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_valid_attack_tag_recognized():
    assert attack_validator.is_valid_attack_tag("attack.t1059")
    assert attack_validator.is_valid_attack_tag("attack.t1059.001")
    assert attack_validator.is_valid_attack_tag("attack.T1110")


def test_invalid_attack_tag_rejected():
    assert not attack_validator.is_valid_attack_tag("attack.notatechnique")
    assert not attack_validator.is_valid_attack_tag("t1059")
    assert not attack_validator.is_valid_attack_tag("attack.t10")
    assert not attack_validator.is_valid_attack_tag("attack.t1059.1")


def test_extract_technique_id_normalizes_case():
    assert attack_validator.extract_technique_id("attack.t1059.001") == "T1059.001"
    assert attack_validator.extract_technique_id("attack.T1110") == "T1110"


def test_extract_technique_id_returns_empty_for_invalid_tag():
    assert attack_validator.extract_technique_id("not.a.tag") == ""


def test_valid_tags_populate_attack_techniques():
    result = RuleResult(path="test.yml")
    rule = {"tags": ["attack.t1059.001", "attack.execution"]}
    attack_validator.run(rule, result)
    assert result.attack_techniques == ["T1059.001"]
    assert not any(i.severity == "error" for i in result.issues)


def test_invalid_tag_format_produces_error():
    result = RuleResult(path="test.yml")
    rule = {"tags": ["attack.notatechnique"]}
    attack_validator.run(rule, result)
    assert any(i.check == "attack_mapping" for i in result.issues)


def test_no_attack_tags_produces_warning_not_error():
    result = RuleResult(path="test.yml")
    rule = {"tags": ["some.other.tag"]}
    attack_validator.run(rule, result)
    assert not any(i.severity == "error" for i in result.issues)
    assert any(i.severity == "warning" for i in result.issues)


def test_tags_must_be_a_list():
    result = RuleResult(path="test.yml")
    rule = {"tags": "attack.t1059"}
    attack_validator.run(rule, result)
    assert any(i.check == "attack_mapping" and i.severity == "error" for i in result.issues)


def test_invalid_rule_fixture_has_invalid_attack_tag():
    result = validate_single_file(FIXTURES / "invalid_rule.yml", FIXTURES)
    assert any(i.check == "attack_mapping" for i in result.issues)


def test_coverage_report_counts_techniques_and_unmapped_rules():
    repo_root = Path(__file__).parent.parent
    repo_result = validate_repository(repo_root / "detections")
    report = coverage.build_coverage_report(repo_result)

    assert report.total_rules == len(repo_result.rules)
    assert report.unique_techniques > 0
    assert report.unmapped_rules == []
    # T1059.001 is used by two production rules (suspicious_powershell,
    # encoded_powershell).
    assert report.technique_counts.get("T1059.001") == 2


def test_coverage_report_technique_rows_are_sorted():
    repo_root = Path(__file__).parent.parent
    repo_result = validate_repository(repo_root / "detections")
    report = coverage.build_coverage_report(repo_result)
    rows = report.technique_rows()
    techniques = [row["technique"] for row in rows]
    assert techniques == sorted(techniques)
