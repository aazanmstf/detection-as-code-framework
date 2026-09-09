# Detection as Code Validation & Testing Framework

![CI](https://github.com/YOUR-USERNAME/detection-as-code-framework/actions/workflows/detection-validation.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A Python framework that validates Sigma detection rules before they are
merged into a Git repository: metadata completeness, detection logic
soundness, duplicate rule IDs, MITRE ATT&CK tag formatting and coverage,
and optional Splunk compatibility metadata — all enforced automatically
in GitHub Actions.

## Overview

Security teams increasingly manage detection rules the same way software
teams manage code: in Git, reviewed via pull request, and validated by
CI before merge. This is often called **Detection as Code (DaC)**.

This project is a portfolio-scale implementation of that workflow. It
takes a folder of Sigma YAML rules and runs them through a validation
pipeline that catches the kinds of mistakes that would otherwise surface
weeks later in production: a typo'd condition reference, a duplicate
rule ID, a missing false-positive explanation, or a malformed ATT&CK tag.

## Why Detection as Code?

Detection rules are logic, and logic drifts and breaks like any other
code. Without validation, common failure modes include:

* A rule's `condition` references a selection that was renamed, silently
  making the detection inert.
* Two engineers independently create rules with the same UUID, breaking
  downstream tooling that keys off rule ID.
* A rule ships with no MITRE ATT&CK mapping, no false-positive guidance,
  or a one-word description — technically "done," practically useless
  to whoever inherits it.

Treating detections as code — version-controlled, peer-reviewed, and
validated by CI — catches these problems before they reach production,
the same way a linter or test suite catches software bugs before deploy.

## Architecture

```
Developer
   |
   v
Sigma Rule (YAML)
   |
   v
Validation Engine  --->  Metadata / Detection Logic / MITRE / Splunk checks
   |
   v
Quality Score (0-100 per rule)
   |
   v
MITRE ATT&CK Coverage Report
   |
   v
pytest (52 tests)
   |
   v
GitHub Actions
   |
   v
Merge (or blocked on failure)
```

See [`docs/architecture.md`](docs/architecture.md) for a full breakdown
of each component and a Mermaid diagram.

## Features

- Recursive discovery of Sigma rules under `detections/`
- YAML structural validation (parse errors, empty files, non-mapping roots)
- Required-field, `status`, `level`, and `logsource` validation
- UUID format validation and repository-wide duplicate ID detection
- Lightweight detection-logic / condition-reference checker (catches
  conditions that reference nonexistent selections)
- MITRE ATT&CK tag format validation and repository-level coverage report
- Static Splunk metadata (`x_splunk`) compatibility validation
- Explainable 100-point per-rule quality score
- Human-readable and `--json` CLI output
- 52 pytest tests covering both valid and intentionally broken fixtures
- GitHub Actions workflow that blocks merge on any failure
- Local web dashboard (stdlib-only, no new dependencies) showing rules,
  quality scores, ATT&CK coverage, and a one-click **Run Validation** button

## Repository Structure

```
detection-as-code-framework/
├── README.md
├── LICENSE
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── .github/workflows/detection-validation.yml
├── detections/
│   ├── windows/
│   │   ├── suspicious_powershell.yml
│   │   ├── encoded_powershell.yml
│   │   └── suspicious_process.yml
│   ├── authentication/
│   │   └── brute_force_login.yml
│   └── defense_evasion/
│       └── security_tool_tampering.yml
├── validator/
│   ├── __init__.py
│   ├── models.py
│   ├── rule_validator.py
│   ├── metadata_validator.py
│   ├── detection_validator.py
│   ├── attack_validator.py
│   ├── splunk_validator.py
│   └── coverage.py
├── scripts/
│   └── validate.py
├── dashboard/
│   ├── backend.py
│   └── static/
│       ├── index.html
│       ├── style.css
│       └── app.js
├── tests/
│   ├── test_metadata.py
│   ├── test_detection_logic.py
│   ├── test_duplicate_ids.py
│   ├── test_attack_mapping.py
│   ├── test_splunk_validation.py
│   └── fixtures/
│       ├── valid_rule.yml
│       ├── invalid_rule.yml
│       └── duplicate_rule.yml
└── docs/
    ├── architecture.md
    └── validation-guide.md
```

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/YOUR-USERNAME/detection-as-code-framework.git
cd detection-as-code-framework
pip install -r requirements.txt
```

## Usage

Validate the whole repository:

```bash
python scripts/validate.py
```

Validate a specific directory:

```bash
python scripts/validate.py --path detections
```

Machine-readable output (for CI or tooling):

```bash
python scripts/validate.py --json
```

The CLI exits with code `0` when every rule passes and code `1` when any
rule fails or a duplicate ID is found.

## Example Output

```
============================================================
Detection as Code Validation Framework
============================================================

Rules discovered: 5

Validation:
  Metadata ........ PASS
  UUID ............ PASS
  Detection Logic . PASS
  ATT&CK .......... PASS
  Splunk .......... PASS

------------------------------------------------------------
Errors and Warnings
------------------------------------------------------------
  None

------------------------------------------------------------
Quality
------------------------------------------------------------
  authentication/brute_force_login.yml
    Quality Score: 100/100
  defense_evasion/security_tool_tampering.yml
    Quality Score: 90/100
  windows/encoded_powershell.yml
    Quality Score: 100/100
  windows/suspicious_powershell.yml
    Quality Score: 100/100
  windows/suspicious_process.yml
    Quality Score: 90/100

  Average Rule Score: 96/100

------------------------------------------------------------
MITRE ATT&CK Coverage (repository-level)
------------------------------------------------------------
  Rules: 5
  Unique Techniques: 5
  Unmapped Rules: 0

  T1027       Obfuscated Files or Information  1 rule
  T1059.001   PowerShell                       2 rules
  T1110       Brute Force                      1 rule
  T1204.002   Malicious File                   1 rule
  T1562.001   Disable or Modify Tools          1 rule

============================================================
RESULT
============================================================
PASS
```

If a rule's condition references a nonexistent selection, the same run
instead reports:

```
Validation:
  Detection Logic . FAIL

------------------------------------------------------------
Errors and Warnings
------------------------------------------------------------

windows/suspicious_process.yml
  [ERROR] windows/suspicious_process.yml (detection_logic): Condition references unknown selection: 'nonexistent_filter'
...
RESULT
FAIL
```
and exits with code `1`.

## Validation Checks

| Check     | Purpose                | Failure Example    |
| --------- | ---------------------- | ------------------ |
| YAML      | Prevent parsing errors | Invalid YAML       |
| Metadata  | Rule quality            | Missing `author`   |
| UUID      | Unique rule identity    | Duplicate ID       |
| Detection Logic | Logic correctness | Unknown selection reference |
| ATT&CK    | Threat mapping           | Invalid technique tag format |
| Splunk    | Compatibility metadata   | Invalid `query_type` |

Full detail on every check is in
[`docs/validation-guide.md`](docs/validation-guide.md).

## MITRE ATT&CK Coverage

The validator extracts `attack.tXXXX` / `attack.tXXXX.XXX` tags from
every rule and builds a **repository-level** coverage summary: total
rules, unique techniques, per-technique rule counts, and rules with no
ATT&CK mapping at all. This tells you what this repository covers — it
is not a claim of full enterprise ATT&CK coverage, and technique IDs are
validated for format only, not cross-checked against the live ATT&CK
dataset.

## Splunk Compatibility

**This project performs static Splunk metadata/compatibility validation
rather than executing queries against Splunk.** Rules may optionally
include an `x_splunk` block describing how the detection would map to a
Splunk data model and query type:

```yaml
x_splunk:
  data_model: Endpoint
  query_type: tstats
  fields:
    - Processes.process
    - Processes.parent_process
```

The validator checks that this metadata is well-formed (a real data
model string, an allowed `query_type`, and non-empty field names). It
does **not** parse or execute SPL, and does not require or connect to a
Splunk instance.

## Testing

```bash
pytest
# or, with more detail:
pytest -v
```

52 tests cover: valid and invalid YAML, missing/invalid metadata,
invalid/duplicate UUIDs, invalid status/level values, missing or
malformed detection logic (including every supported condition pattern
and the unknown-selection-reference case), valid and invalid ATT&CK
tags, valid and invalid Splunk metadata, quality scoring, and
repository-level ATT&CK coverage. Tests run against both the real
`detections/` rules (which must always pass) and the intentionally
broken fixtures in `tests/fixtures/` (which must always fail the checks
they're designed to exercise).

> Generated and statically reviewed; the test suite above was executed
> locally during development (`pytest`: 52 passed) and the CLI was
> confirmed to exit `0` on the clean repository and `1` when a
> production rule was deliberately broken. Please re-run `pytest`
> locally to verify in your own environment.

## Web Dashboard

A small local dashboard is included for visually reviewing rule status
without reading CLI output. It is purely additive: `dashboard/backend.py`
only *imports and calls* the existing `validator` package
(`validate_repository`, `build_coverage_report`) the same way
`scripts/validate.py` does — no validator code was changed to build it,
and no new dependencies are required (it uses only Python's standard
library `http.server`).

```
dashboard/
├── backend.py       # local HTTP server + API, reuses validator/ as-is
└── static/
    ├── index.html   # dashboard layout
    ├── style.css    # dark, minimal styling
    └── app.js        # fetches /api/validate and renders the UI
```

It shows:

- The 5 detection rules, each with PASS/FAIL status, quality score, and
  mapped ATT&CK techniques
- A repository-level MITRE ATT&CK coverage table
- An overall PASS/FAIL badge
- A **Run Validation** button that re-runs the real validator on demand
  and refreshes the page's data — no page reload needed

### Running the dashboard

From the repository root:

```bash
python dashboard/backend.py
```

This starts a local server at `http://127.0.0.1:8765` and opens it in
your default browser automatically. If it doesn't open on its own,
navigate to that URL manually. Press `Ctrl+C` in the terminal to stop
the server.

The dashboard talks to a single JSON endpoint, `GET/POST /api/validate`,
which runs `validate_repository()` fresh on every call — so clicking
**Run Validation** after editing a rule file shows the real, current
result, not cached data.

### Opening it in VS Code

1. Open the `detection-as-code-framework` folder in VS Code
   (**File → Open Folder...**, select the repo root — the one containing
   `README.md`, `validator/`, and `dashboard/`).
2. Make sure your Python interpreter is selected: open the Command
   Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) → **Python: Select
   Interpreter** → choose the Python 3.11+ environment where you ran
   `pip install -r requirements.txt`.
3. Open a terminal inside VS Code: **Terminal → New Terminal** (or
   `` Ctrl+` ``). This opens a shell already rooted at the repo folder.
4. In that terminal, run:
   ```bash
   python dashboard/backend.py
   ```
5. VS Code will show the server's console output
   (`Detection as Code dashboard running at http://127.0.0.1:8765`) in
   the integrated terminal, and your browser will open the dashboard
   automatically. If VS Code shows a "port forwarding" popup, you can
   dismiss it — this is a local-only server and doesn't need it.
6. To stop it, click into the integrated terminal and press `Ctrl+C`.

You can also run it via VS Code's **Run → Run Without Debugging**
(`Ctrl+F5`) with `dashboard/backend.py` open and focused as the active
file — VS Code will run it the same way as the terminal command above.

Editing a rule in `detections/` while the dashboard is running and then
clicking **Run Validation** is the fastest way to see how a change
affects PASS/FAIL status, score, and ATT&CK coverage without leaving the
browser.

## CI/CD

`.github/workflows/detection-validation.yml` runs on every push and pull
request against `main`:

1. Checkout the repository
2. Set up Python 3.11
3. Install dependencies from `requirements.txt`
4. Run `pytest`
5. Run `python scripts/validate.py --path detections`
6. Fail the workflow if either step fails

No secrets, cloud credentials, or external services are required.

## Example Detection

```yaml
title: Suspicious PowerShell Execution With Download Cradle
id: 7c3f1a2e-4b6d-4e2a-9f1c-2d5e8a9b1c33
status: stable
description: >
  Detects PowerShell processes launched with command-line arguments commonly
  associated with download cradles or execution bypass techniques, such as
  hidden windows, disabled execution policy, and non-interactive flags
  combined with a web-download cmdlet.
author: Detection Engineering Portfolio
date: 2024-11-02
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith: '\powershell.exe'
  selection_flags:
    CommandLine|contains|all:
      - '-WindowStyle Hidden'
      - '-ExecutionPolicy Bypass'
  selection_download:
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'Net.WebClient'
  condition: selection_process and selection_flags and selection_download
falsepositives:
  - Legitimate administrative scripts that intentionally suppress the
    PowerShell window and bypass execution policy for automated deployment
    tools (e.g., SCCM, Intune remediation scripts).
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

## Quality Scoring

Each rule is scored out of 100 points based on validation outcomes:
metadata completeness (20), valid UUID (10), valid detection logic (20),
MITRE mapping (15), documented false positives (15), Splunk metadata
(10), and description quality (10). See
[`docs/validation-guide.md`](docs/validation-guide.md) for exactly how
each component is computed.

## Limitations

This is a **portfolio-scale framework**, and it's built to be honest
about what it is not:

- **Not a complete Sigma specification implementation.** The condition
  parser supports common patterns (`and`/`or`/`not`, `1 of x*`,
  `all of x*`) but not the full Sigma grammar (nested groups, complex
  aggregations, etc.).
- **Not a production SIEM** and does not ingest, index, or search log
  data.
- **Not a replacement for Splunk.** Splunk validation is static metadata
  checking, not SPL execution.
- **Not a complete ATT&CK validation engine.** Tag format is validated;
  technique IDs are not cross-checked against the live ATT&CK dataset,
  and coverage is repository-level, not enterprise-level.
- **Not a detection deployment platform.** It validates rules; it does
  not deploy, tune, or manage their lifecycle in a live SIEM.

## Future Improvements

1. Full pySigma integration for spec-complete condition parsing
2. Splunk SPL compilation (not just metadata validation)
3. Microsoft Sentinel KQL output
4. CrowdStrike query support
5. Detection deployment automation
6. Automated pull-request review comments
7. Historical detection quality tracking over time
8. False-positive rate metrics fed back from production
9. ATT&CK Navigator layer export
10. Detection coverage dashboard

## Interview Explanation

### How I Explain This Project

"I built a Detection as Code framework that treats Sigma detection rules
like software: version-controlled in Git, and validated automatically
before they can be merged. The problem it solves is that detection rules
quietly break in ways that are easy to miss in manual review — a
condition that references a selection someone renamed, two rules that
accidentally share the same UUID, or a rule that ships with no
false-positive guidance or ATT&CK mapping. My validator recursively
scans a `detections/` folder, parses each Sigma YAML file, and runs it
through a pipeline: required metadata fields, allowed status and
severity values, a lightweight condition-logic checker that verifies
every selection referenced in the condition actually exists, UUID format
and repository-wide duplicate detection, MITRE ATT&CK tag format
validation, and optional Splunk metadata validation. Each rule gets a
0–100 quality score based on those results, and the whole repository
gets a MITRE ATT&CK coverage summary — how many rules map to which
techniques, and which rules have no mapping at all. Everything is
enforced by a GitHub Actions workflow that runs my pytest suite and the
validator itself on every push and pull request, so a broken rule fails
CI instead of reaching production. I was intentional about scope: the
Splunk piece validates metadata structure, not live SPL execution,
and I say that explicitly in the README, because I'd rather be honest
about what a portfolio project does than overclaim SIEM integration I
didn't build."

### Interview Questions & Answers

**1. What is Detection as Code?**
Managing detection rules the same way software is managed: stored in
version control, reviewed via pull request, and validated automatically
by CI/CD before merge — rather than being edited directly in a SIEM's
UI with no history or review.

**2. Why use Sigma?**
Sigma is a vendor-agnostic, YAML-based format for describing detection
logic. It decouples the detection's intent from any single SIEM's query
syntax, which makes rules portable, easy to diff in Git, and readable by
humans during review.

**3. Why validate detection rules?**
Because detection logic drifts and breaks like any other code — a typo,
a renamed field, a copy-paste error — but unlike application code, a
broken detection often fails silently (it just never fires) rather than
throwing a visible error. Automated validation catches structural and
logical mistakes before a rule reaches production.

**4. How does your validator work?**
It recursively discovers YAML files under `detections/`, parses each
with `yaml.safe_load`, and runs a series of independent checks —
metadata completeness, status/level values, detection logic and
condition references, UUID format, ATT&CK tag format, and optional
Splunk metadata — aggregating the results into a per-rule quality score
and a repository-wide pass/fail.

**5. How do you detect duplicate IDs?**
After every rule in the repository has been parsed and its `id`
validated as a well-formed UUID, I build a map of UUID to the list of
files that use it. Any UUID used by more than one file is reported as a
duplicate-ID error, since Sigma rule IDs are meant to be globally unique
identifiers.

**6. How do you validate detection logic?**
I check that the `detection` block has at least one non-empty selection
and a non-empty `condition`, then extract identifier-like tokens from
the condition string (excluding grammar keywords like `and`/`or`/`not`)
and confirm each one matches a real selection name — including
wildcard patterns like `1 of selection*`. It's a lightweight,
regex-based checker, not a full Sigma grammar parser, and I'm upfront
about that limitation.

**7. Why map detections to MITRE ATT&CK?**
ATT&CK gives detection engineering a shared vocabulary for describing
adversary behavior, which makes it possible to reason about coverage
("do we have detections for credential access techniques?") and to
communicate detection intent to other teams without relying on
vendor-specific terminology.

**8. How does your ATT&CK coverage report work?**
The validator extracts every valid `attack.tXXXX` tag from every rule,
tallies how many rules map to each technique, and reports total rules,
unique techniques covered, and rules with no ATT&CK mapping at all. I
call this repository-level coverage explicitly, since it only reflects
what's in this repo, not an organization's full detection stack.

**9. How does Splunk fit into the project?**
Rules can optionally carry an `x_splunk` metadata block describing how
the detection would translate into a Splunk data model and query type.
My validator checks that this metadata is structurally sound — a real
data model, an allowed query type, valid field names — as a way of
documenting SIEM-mapping intent without requiring an actual Splunk
instance.

**10. Does your project actually connect to Splunk?**
No, and I'm explicit about that in the README. It performs static
metadata validation only; it does not parse or execute SPL and does not
require a Splunk license, server, or API key. Building a real SPL
compiler is listed as a future improvement.

**11. How would you deploy this in a production SOC?**
As a required GitHub Actions check on pull requests targeting the
detections repository, so a rule can't be merged unless it passes
validation. In a real environment I'd extend the pipeline to also push
passing rules to the SIEM (via its API) as a deployment step, and add
PR-comment reporting so reviewers see the validation summary inline.

**12. What would you improve next?**
Full pySigma integration for spec-complete condition and backend query
generation, real SPL/KQL compilation instead of metadata-only Splunk
checks, and historical quality tracking so a team can see whether
detection quality is trending up or down over time, not just at a
single point-in-time check.
