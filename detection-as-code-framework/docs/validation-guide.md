# Validation Guide

This document describes every validation check performed by the
framework, in the order they run.

## Summary Table

| Check     | Purpose                | Failure Example    |
| --------- | ---------------------- | ------------------ |
| YAML      | Prevent parsing errors | Invalid YAML syntax, empty file, or non-mapping root |
| Metadata  | Rule quality / completeness | Missing `author`, invalid `status`, invalid `level`, empty `logsource` |
| UUID      | Unique rule identity    | `id` is not a valid UUID, or is reused by another rule |
| Detection Logic | Logic correctness | `condition` references a selection that doesn't exist |
| ATT&CK    | Threat mapping          | `attack.notarealtechnique` tag format |
| Splunk    | Compatibility metadata  | `x_splunk.query_type: delete_everything` |

## 1. YAML Validation

The rule file must parse as valid YAML, must not be empty, and its root
element must be a mapping (object), not a list or scalar. This runs
first because every later check depends on having a parsed dictionary to
inspect.

## 2. Required Metadata Fields

Every rule must define: `title`, `id`, `status`, `description`, `author`,
`date`, `logsource`, `detection`, `falsepositives`, `level`, and `tags`.
A field that is present but empty (`falsepositives: []`, `title: ""`) is
treated the same as a missing field.

## 3. Status Validation

`status` must be one of: `experimental`, `test`, `stable`, `deprecated`.

## 4. Severity (`level`) Validation

`level` must be one of: `informational`, `low`, `medium`, `high`,
`critical`.

## 5. Logsource Validation

`logsource` must be a mapping and must contain at least one of
`category`, `product`, or `service` with non-empty content. This catches
rules with a technically-present-but-useless logsource block.

## 6. Detection Logic Validation

* `detection` must exist and be a mapping.
* `condition` must exist and be a non-empty string.
* At least one selection (any key other than `condition`) must be
  defined, and no selection may be empty.
* Every identifier the condition references must resolve to a real
  selection. Supported condition patterns:
  * `selection`
  * `selection_a and selection_b`
  * `selection_a or selection_b`
  * `selection_a and not selection_b`
  * `1 of selection*`
  * `all of filter*`

This is a lightweight, regex-based checker, not a full implementation of
the Sigma condition grammar. It is intentionally scoped to catch the most
common authoring mistake in a Detection as Code workflow: a typo'd or
renamed selection that the condition no longer references correctly.

## 7. Rule ID / UUID Validation

`id` must be a syntactically valid UUID (validated with Python's
`uuid.UUID()`). Separately, the framework checks that no two rules in the
repository share the same `id` — this is a repository-wide check, run
once after every individual rule has been parsed.

## 8. MITRE ATT&CK Validation

Tags of the form `attack.tXXXX` or `attack.tXXXX.XXX` (case-insensitive)
are recognized as ATT&CK technique references. Malformed tags (e.g.
`attack.notatechnique`) produce an error. A rule with no ATT&CK tags at
all produces a warning, not an error, since some detections (e.g. pure
policy violations) may not map cleanly to a technique.

Extracted techniques feed into the repository-level coverage report
(rule count per technique, unique technique count, and unmapped rules).
This is explicitly **repository-level** coverage — it says nothing about
enterprise-wide ATT&CK coverage across an organization's full detection
stack.

## 9. Splunk Compatibility Validation

`x_splunk` is optional. When present:

* `data_model` must be a non-empty string.
* `query_type` must be one of `search`, `tstats`, `transaction`.
* `fields`, if present, must be a list of non-empty strings.

This validates **metadata structure only**. It does not parse or execute
SPL, and does not connect to a Splunk instance.

## 10. Quality Scoring

Each rule receives a score out of 100, computed from validation results:

| Component                | Points | Awarded When |
| ------------------------- | ------ | ------------ |
| Metadata complete          | 20     | No metadata (required-field/status/level/logsource) errors |
| Valid UUID                 | 10     | `id` is a syntactically valid UUID |
| Valid detection logic      | 20     | No `detection_logic` errors |
| MITRE mapping               | 15     | At least one valid ATT&CK technique tag |
| False positives documented | 15     | `falsepositives` is present and not an empty/placeholder value |
| Splunk metadata             | 10     | `x_splunk` present and passes validation (0 if absent) |
| Description quality         | 10     | Description is at least 30 characters |

The score is a coarse, explainable heuristic intended to surface rules
that are technically valid but low-effort (e.g. a one-line description,
no ATT&CK mapping) — not a substitute for human review.

## Errors vs. Warnings

Most checks produce **errors**, which fail validation (exit code 1).
A small number of checks (missing ATT&CK tags, very short descriptions)
produce **warnings**, which are surfaced in the report but do not fail
the build. This mirrors how many real CI quality gates distinguish
"must fix" from "should improve."
