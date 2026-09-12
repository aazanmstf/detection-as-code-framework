"""
Detection as Code (DaC) Validation & Testing Framework
--------------------------------------------------------

A lightweight Python package for statically validating Sigma detection
rules stored in a Git repository: metadata completeness, detection logic
soundness, duplicate rule IDs, MITRE ATT&CK tag formatting/coverage, and
optional Splunk compatibility metadata.

This package performs *static* validation only. It does not execute
queries against a live SIEM and does not implement the full Sigma
specification. See docs/architecture.md and README.md for scope and
limitations.
"""

__version__ = "1.0.0"
