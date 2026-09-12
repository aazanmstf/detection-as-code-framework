"""
Top-level orchestration for rule validation:

* discovers *.yml / *.yaml files under a directory
* parses YAML safely
* validates UUID format for the `id` field
* detects duplicate IDs across the repository
* delegates to metadata_validator, detection_validator, attack_validator,
  and splunk_validator for the rest of the checks
* computes the per-rule quality score
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from validator import attack_validator, detection_validator, metadata_validator, splunk_validator
from validator.models import RepositoryResult, RuleResult, ValidationIssue


def discover_rule_files(base_path: Path) -> List[Path]:
    """Recursively find all .yml/.yaml files under base_path, sorted for
    deterministic output."""
    if not base_path.exists():
        return []
    files = list(base_path.rglob("*.yml")) + list(base_path.rglob("*.yaml"))
    return sorted(files)


def load_rule(path: Path, result: RuleResult) -> Dict[str, Any] | None:
    """Parse a YAML file. Returns the parsed dict, or None if parsing failed
    (an error is recorded on the result in that case)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        result.add_error("yaml_read", f"Could not read file: {exc}")
        return None

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        result.add_error("yaml_parse", f"YAML parsing failed: {exc}")
        return None

    if data is None:
        result.add_error("yaml_parse", "Rule file is empty")
        return None

    if not isinstance(data, dict):
        result.add_error("yaml_parse", "YAML root must be a mapping/object")
        return None

    return data


def validate_uuid(rule: Dict[str, Any], result: RuleResult) -> None:
    """Ensure the `id` field is present and is a syntactically valid UUID."""
    rule_id = rule.get("id")
    if rule_id is None:
        return  # missing-field already reported by metadata_validator

    if not isinstance(rule_id, str):
        result.add_error("uuid", "id must be a string")
        return

    try:
        uuid.UUID(rule_id)
    except (ValueError, AttributeError, TypeError):
        result.add_error("uuid", f"id '{rule_id}' is not a valid UUID")
        return

    result.rule_id = rule_id


def compute_quality_score(rule: Dict[str, Any], result: RuleResult) -> None:
    """
    Compute the 100-point detection quality score based on validation
    outcomes. See docs/validation-guide.md for the full breakdown.
    """
    score = result.score

    error_checks = {issue.check for issue in result.issues if issue.severity == "error"}

    # Metadata complete: +20 if no required_field/status/level/logsource errors.
    metadata_checks = {"required_field", "status", "level", "logsource"}
    if not (metadata_checks & error_checks):
        score.metadata_complete = 20

    # Valid UUID: +10
    if "uuid" not in error_checks and result.rule_id:
        score.valid_uuid = 10

    # Valid detection logic: +20
    if "detection_logic" not in error_checks:
        score.valid_detection_logic = 20

    # MITRE mapping: +15 if at least one valid ATT&CK technique tag exists.
    if result.attack_techniques and "attack_mapping" not in error_checks:
        score.mitre_mapping = 15

    # False positives documented: +15 if non-trivial falsepositives content.
    fps = rule.get("falsepositives")
    if fps and not (isinstance(fps, list) and fps in ([], ["Unknown"], ["unknown"])):
        score.false_positives = 15

    # Splunk metadata: +10 if x_splunk present and valid.
    if rule.get("x_splunk") is not None and "splunk_metadata" not in error_checks:
        score.splunk_metadata = 10

    # Description quality: +10 if description passed the quality heuristic.
    description = rule.get("description", "")
    if isinstance(description, str) and len(description.strip()) >= 30:
        score.description_quality = 10


def validate_single_file(path: Path, repo_root: Path) -> RuleResult:
    """Run the full validation pipeline against a single rule file."""
    try:
        rel_path = str(path.relative_to(repo_root))
    except ValueError:
        rel_path = str(path)

    result = RuleResult(path=rel_path)

    rule = load_rule(path, result)
    if rule is None:
        return result

    result.raw = rule
    result.title = str(rule.get("title", ""))

    metadata_validator.run(rule, result)
    validate_uuid(rule, result)
    detection_validator.run(rule, result)
    attack_validator.run(rule, result)
    splunk_validator.run(rule, result)

    compute_quality_score(rule, result)
    return result


def find_duplicate_ids(rules: List[RuleResult]) -> List[ValidationIssue]:
    """Detect rule IDs that are reused across more than one file."""
    id_to_files: Dict[str, List[str]] = {}
    for rule in rules:
        if not rule.rule_id:
            continue
        id_to_files.setdefault(rule.rule_id, []).append(rule.path)

    issues: List[ValidationIssue] = []
    for rule_id, files in id_to_files.items():
        if len(files) > 1:
            file_list = ", ".join(sorted(files))
            issues.append(
                ValidationIssue(
                    file=file_list,
                    check="duplicate_id",
                    message=f"Duplicate detection ID '{rule_id}' found in: {file_list}",
                    severity="error",
                )
            )
    return issues


def validate_repository(base_path: Path) -> RepositoryResult:
    """Validate every rule file discovered under base_path and detect
    duplicate IDs across the whole set."""
    repo_root = base_path if base_path.is_dir() else base_path.parent
    files = discover_rule_files(base_path)

    rule_results = [validate_single_file(f, repo_root) for f in files]
    duplicate_issues = find_duplicate_ids(rule_results)

    return RepositoryResult(rules=rule_results, duplicate_id_issues=duplicate_issues)
