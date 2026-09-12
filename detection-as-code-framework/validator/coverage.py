"""
Builds a repository-level MITRE ATT&CK coverage summary from a set of
validated rules.

This is explicitly a *repository-level* coverage report: it summarizes
which techniques are covered by rules in THIS repository, not enterprise
ATT&CK coverage across an organization's full detection stack.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List

from validator.models import RepositoryResult

# Small, illustrative technique-name lookup for readable reporting.
# Not exhaustive - only covers techniques used in this repository's rules.
TECHNIQUE_NAMES: Dict[str, str] = {
    "T1059.001": "PowerShell",
    "T1027": "Obfuscated Files or Information",
    "T1204.002": "Malicious File",
    "T1110": "Brute Force",
    "T1562.001": "Disable or Modify Tools",
}


@dataclass
class CoverageReport:
    total_rules: int = 0
    unique_techniques: int = 0
    technique_counts: Counter = field(default_factory=Counter)
    unmapped_rules: List[str] = field(default_factory=list)

    def technique_rows(self) -> List[Dict[str, str]]:
        rows = []
        for technique, count in sorted(self.technique_counts.items()):
            rows.append(
                {
                    "technique": technique,
                    "name": TECHNIQUE_NAMES.get(technique, "Unknown / Uncatalogued"),
                    "count": str(count),
                }
            )
        return rows


def build_coverage_report(repo_result: RepositoryResult) -> CoverageReport:
    report = CoverageReport()
    report.total_rules = len(repo_result.rules)

    for rule in repo_result.rules:
        if rule.attack_techniques:
            report.technique_counts.update(rule.attack_techniques)
        else:
            report.unmapped_rules.append(rule.path)

    report.unique_techniques = len(report.technique_counts)
    return report
