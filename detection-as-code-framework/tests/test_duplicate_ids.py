"""Tests for UUID validation and duplicate ID detection."""

from pathlib import Path

from validator.models import RuleResult
from validator.rule_validator import (
    find_duplicate_ids,
    validate_repository,
    validate_single_file,
    validate_uuid,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_valid_uuid_passes():
    result = RuleResult(path="test.yml")
    rule = {"id": "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"}
    validate_uuid(rule, result)
    assert result.issues == []
    assert result.rule_id == "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"


def test_invalid_uuid_fails():
    result = RuleResult(path="test.yml")
    rule = {"id": "not-a-valid-uuid"}
    validate_uuid(rule, result)
    assert any(i.check == "uuid" for i in result.issues)


def test_invalid_rule_fixture_has_invalid_uuid():
    result = validate_single_file(FIXTURES / "invalid_rule.yml", FIXTURES)
    assert any(i.check == "uuid" for i in result.issues)


def test_duplicate_ids_detected_across_repository(tmp_path):
    # Copy the valid and duplicate fixtures into an isolated temp repo so
    # this test doesn't depend on the real detections/ directory.
    import shutil

    repo = tmp_path / "detections"
    repo.mkdir()
    shutil.copy(FIXTURES / "valid_rule.yml", repo / "valid_rule.yml")
    shutil.copy(FIXTURES / "duplicate_rule.yml", repo / "duplicate_rule.yml")

    repo_result = validate_repository(repo)

    assert len(repo_result.duplicate_id_issues) == 1
    issue = repo_result.duplicate_id_issues[0]
    assert "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d" in issue.message
    assert not repo_result.passed


def test_no_duplicates_in_production_detections():
    repo_root = Path(__file__).parent.parent
    repo_result = validate_repository(repo_root / "detections")
    assert repo_result.duplicate_id_issues == []


def test_find_duplicate_ids_helper_with_no_duplicates():
    r1 = RuleResult(path="a.yml", rule_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    r2 = RuleResult(path="b.yml", rule_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    issues = find_duplicate_ids([r1, r2])
    assert issues == []
