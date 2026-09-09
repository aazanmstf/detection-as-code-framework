"""
Local dashboard backend for the Detection as Code Validation Framework.

This module is purely additive. It IMPORTS and CALLS the existing
validator package (validator.rule_validator, validator.coverage) exactly
as scripts/validate.py does - it does not modify, subclass, or monkeypatch
any validator code. It exposes a tiny local HTTP API (stdlib only, no new
dependencies) plus static file serving for the dashboard UI in
dashboard/static/.

Run with:
    python dashboard/backend.py

Then open http://127.0.0.1:8765 in a browser.
"""

from __future__ import annotations

import json
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Timer
from urllib.parse import urlparse

# Make the repo root importable so `from validator...` works regardless of
# the working directory this script is launched from (e.g. VS Code's
# "Run Python File" uses the file's own directory as cwd by default).
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from validator import coverage as coverage_mod  # noqa: E402
from validator.rule_validator import validate_repository  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
DETECTIONS_DIR = REPO_ROOT / "detections"

HOST = "127.0.0.1"
PORT = 8765

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}


def build_report() -> dict:
    """
    Run the existing, unmodified validator against detections/ and shape
    the result for the dashboard UI. This calls the same public functions
    scripts/validate.py already uses (validate_repository,
    build_coverage_report) - the validation logic itself lives in one
    place only: the validator/ package.
    """
    repo_result = validate_repository(DETECTIONS_DIR)
    coverage_report = coverage_mod.build_coverage_report(repo_result)

    rules = []
    for rule in repo_result.rules:
        rules.append(
            {
                "path": rule.path,
                "id": rule.rule_id,
                "title": rule.title or rule.path,
                "passed": rule.passed,
                "score": rule.score.total,
                "attack_techniques": rule.attack_techniques,
                "issues": [
                    {"check": i.check, "severity": i.severity, "message": i.message}
                    for i in rule.issues
                ],
            }
        )

    return {
        "result": "PASS" if repo_result.passed else "FAIL",
        "rules_discovered": len(repo_result.rules),
        "average_score": round(repo_result.average_score, 1),
        "duplicate_ids": [i.message for i in repo_result.duplicate_id_issues],
        "rules": rules,
        "coverage": {
            "total_rules": coverage_report.total_rules,
            "unique_techniques": coverage_report.unique_techniques,
            "unmapped_rules": coverage_report.unmapped_rules,
            "techniques": coverage_report.technique_rows(),
        },
    }


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "DaCDashboard/1.0"

    def log_message(self, fmt: str, *args) -> None:  # quieter console output
        sys.stderr.write(f"[dashboard] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(404, "Not found")
            return
        content_type = CONTENT_TYPES.get(path.suffix, "application/octet-stream")
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_validate(self) -> None:
        try:
            self._send_json(build_report())
        except Exception as exc:  # surface errors in the UI instead of a blank page
            self._send_json({"error": str(exc)}, status=500)

    def do_GET(self) -> None:  # noqa: N802 (stdlib method name)
        route = urlparse(self.path).path

        if route in ("/", "/index.html"):
            self._send_file(STATIC_DIR / "index.html")
            return

        if route == "/api/validate":
            self._handle_validate()
            return

        # Static assets (style.css, app.js, ...), guarded against path escape.
        candidate = (STATIC_DIR / route.lstrip("/")).resolve()
        if candidate.is_relative_to(STATIC_DIR.resolve()):
            self._send_file(candidate)
            return

        self.send_error(404, "Not found")

    def do_POST(self) -> None:  # noqa: N802 (stdlib method name)
        if urlparse(self.path).path == "/api/validate":
            self._handle_validate()
            return
        self.send_error(404, "Not found")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    url = f"http://{HOST}:{PORT}"
    print(f"Detection as Code dashboard running at {url}")
    print("Press Ctrl+C to stop.")
    Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        server.shutdown()


if __name__ == "__main__":
    main()
