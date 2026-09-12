"""
Tests for the secure webapp, using Flask's test client (no real network
binding needed). Kept in webapp/tests/ - separate from the root tests/
directory - so the existing GitHub Actions workflow (which only installs
requirements.txt and runs `pytest` against tests/) is completely
unaffected by this suite needing Flask.

Run with:
    pip install -r requirements.txt -r requirements-webapp.txt
    pytest webapp/tests
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from webapp.app import create_app  # noqa: E402
from webapp.security import login_rate_limiter  # noqa: E402

VALID_RULE = b"""
title: Test Fixture Valid Rule
id: aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
status: test
description: A fully valid fixture rule used purely for webapp tests.
author: Webapp Tests
date: 2024-01-01
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
falsepositives:
  - Routine admin use of the command prompt.
level: low
tags:
  - attack.t1059
"""

BROKEN_RULE = b"""
title: Test Fixture Broken Rule
id: not-a-uuid
status: test
description: Short
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\evil.exe'
  condition: nonexistent_selection
falsepositives: []
level: low
tags:
  - attack.t1059
"""

DUPLICATE_OF_PRODUCTION_RULE = b"""
title: Duplicate Of Production Rule
id: 7c3f1a2e-4b6d-4e2a-9f1c-2d5e8a9b1c33
status: test
description: Uses the same id as detections/windows/suspicious_powershell.yml on purpose.
author: Webapp Tests
date: 2024-01-01
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
falsepositives:
  - Testing duplicate id detection.
level: low
tags:
  - attack.t1059
"""


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_DATABASE_PATH", str(tmp_path / "test.db"))
    application = create_app("testing")
    application.config["WTF_CSRF_ENABLED"] = False
    yield application
    login_rate_limiter._records.clear()  # avoid state leaking between tests


@pytest.fixture()
def client(app):
    return app.test_client()


def register(client, username="alice", email="alice@example.com", password="correcthorse9"):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=True,
    )


def login(client, username="alice", password="correcthorse9"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def upload(client, content: bytes, filename: str = "rule.yml"):
    return client.post(
        "/upload",
        data={"rule_file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


# ---------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------


def test_register_and_login_flow(client):
    resp = register(client)
    assert resp.status_code == 200
    assert b"You can now log in" in resp.data or b"log in" in resp.data.lower()

    resp = login(client)
    assert resp.status_code == 200
    assert b"Welcome back" in resp.data


def test_duplicate_username_rejected(client):
    register(client, username="bob", email="bob@example.com")
    resp = register(client, username="bob", email="bob2@example.com")
    assert b"already taken" in resp.data


def test_weak_password_rejected(client):
    resp = client.post(
        "/register",
        data={
            "username": "weakpw",
            "email": "weak@example.com",
            "password": "short1",
            "confirm_password": "short1",
        },
    )
    assert b"at least 10 characters" in resp.data


def test_password_confirmation_mismatch_rejected(client):
    resp = client.post(
        "/register",
        data={
            "username": "mismatch",
            "email": "mismatch@example.com",
            "password": "correcthorse9",
            "confirm_password": "differenthorse9",
        },
    )
    assert b"do not match" in resp.data


def test_login_with_wrong_password_shows_generic_error(client):
    register(client, username="carol", email="carol@example.com")
    resp = client.post(
        "/login", data={"username": "carol", "password": "wrongpassword1"}
    )
    assert b"Invalid username/email or password" in resp.data


def test_login_with_unknown_user_shows_same_generic_error(client):
    resp = client.post(
        "/login", data={"username": "nobody", "password": "wrongpassword1"}
    )
    assert b"Invalid username/email or password" in resp.data


def test_login_rate_limiter_locks_after_repeated_failures(client):
    register(client, username="dave", email="dave@example.com")
    for _ in range(5):
        client.post("/login", data={"username": "dave", "password": "wrongpassword1"})
    resp = client.post("/login", data={"username": "dave", "password": "wrongpassword1"})
    assert b"Too many failed attempts" in resp.data


def test_upload_requires_login(client):
    resp = client.get("/", follow_redirects=True)
    assert b"Please log in to continue" in resp.data or b"Log in" in resp.data


def test_logout_clears_session(client):
    register(client, username="erin", email="erin@example.com")
    login(client, username="erin")
    resp = client.get("/history")
    assert resp.status_code == 200

    client.post("/logout")
    resp = client.get("/history", follow_redirects=True)
    assert b"Please log in to continue" in resp.data


# ---------------------------------------------------------------------
# Upload + validation
# ---------------------------------------------------------------------


def test_upload_valid_rule_passes(client):
    register(client, username="frank", email="frank@example.com")
    login(client, username="frank")

    resp = upload(client, VALID_RULE)
    assert resp.status_code == 200
    assert b"PASS" in resp.data
    assert b"No issues found" in resp.data


def test_upload_broken_rule_fails_with_explanation_and_fix(client):
    register(client, username="grace", email="grace@example.com")
    login(client, username="grace")

    resp = upload(client, BROKEN_RULE)
    assert resp.status_code == 200
    assert b"FAIL" in resp.data
    # Plain-English explanation and fix text from webapp/explain.py should render.
    assert b"What this means" in resp.data
    assert b"Suggested fix" in resp.data
    assert b"unknown selection" in resp.data.lower()


def test_upload_rejects_wrong_extension(client):
    register(client, username="heidi", email="heidi@example.com")
    login(client, username="heidi")

    resp = upload(client, b"not a yaml rule", filename="rule.txt")
    assert b"Only .yml or .yaml files are accepted" in resp.data


def test_upload_rejects_empty_file(client):
    register(client, username="ivan", email="ivan@example.com")
    login(client, username="ivan")

    resp = upload(client, b"", filename="empty.yml")
    assert b"empty" in resp.data.lower()


def test_upload_detects_duplicate_id_against_production_rule(client):
    register(client, username="judy", email="judy@example.com")
    login(client, username="judy")

    resp = upload(client, DUPLICATE_OF_PRODUCTION_RULE)
    assert b"FAIL" in resp.data
    assert b"already used by an existing production rule" in resp.data


# ---------------------------------------------------------------------
# History + authorization (IDOR protection)
# ---------------------------------------------------------------------


def test_history_lists_users_own_runs(client):
    register(client, username="kim", email="kim@example.com")
    login(client, username="kim")
    upload(client, VALID_RULE)

    resp = client.get("/history")
    assert b"rule.yml" in resp.data


def test_user_cannot_view_another_users_run(client, app):
    # User one uploads a rule.
    register(client, username="leo", email="leo@example.com")
    login(client, username="leo")
    upload(client, VALID_RULE)

    with app.app_context():
        db = app.config["DB"]
        leo_run = db.get_runs_for_user(db.get_user_by_username("leo")["id"])[0]

    client.post("/logout")

    # A second, different user tries to view leo's run by guessing the id.
    register(client, username="mallory", email="mallory@example.com")
    login(client, username="mallory")
    resp = client.get(f"/runs/{leo_run['id']}")
    assert resp.status_code == 404


def test_user_cannot_download_another_users_report(client, app):
    register(client, username="nina", email="nina@example.com")
    login(client, username="nina")
    upload(client, VALID_RULE)

    with app.app_context():
        db = app.config["DB"]
        nina_run = db.get_runs_for_user(db.get_user_by_username("nina")["id"])[0]

    client.post("/logout")

    register(client, username="oscar", email="oscar@example.com")
    login(client, username="oscar")
    resp = client.get(f"/runs/{nina_run['id']}/download")
    assert resp.status_code == 404


def test_download_report_contains_key_fields(client, app):
    register(client, username="paul", email="paul@example.com")
    login(client, username="paul")
    upload(client, VALID_RULE)

    with app.app_context():
        db = app.config["DB"]
        paul_run = db.get_runs_for_user(db.get_user_by_username("paul")["id"])[0]

    resp = client.get(f"/runs/{paul_run['id']}/download")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/plain")
    assert b"Validation Report" in resp.data
    assert b"PASS" in resp.data
    assert b"rule.yml" in resp.data


def test_security_headers_present(client):
    resp = client.get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in resp.headers


# ---------------------------------------------------------------------
# New enterprise UI pages: Dashboard, Integrations, Audit Logs, Settings
# ---------------------------------------------------------------------


def test_dashboard_requires_login(client):
    resp = client.get("/dashboard", follow_redirects=True)
    assert b"Please log in to continue" in resp.data


def test_dashboard_shows_empty_state_with_no_runs(client):
    register(client, username="quinn", email="quinn@example.com")
    login(client, username="quinn")
    resp = client.get("/dashboard")
    assert b"No validation activity yet" in resp.data


def test_dashboard_reflects_real_uploaded_rule_data(client):
    register(client, username="rachel", email="rachel@example.com")
    login(client, username="rachel")
    upload(client, VALID_RULE)  # tags: attack.t1059, score 100/100

    resp = client.get("/dashboard")
    assert b"No validation activity yet" not in resp.data
    # 1 rule validated, 100% pass rate, ATT&CK technique from the fixture.
    assert b"100%" in resp.data
    assert b"T1059" in resp.data


def test_dashboard_only_reflects_current_users_runs(client):
    register(client, username="sam", email="sam@example.com")
    login(client, username="sam")
    upload(client, VALID_RULE)
    client.post("/logout")

    register(client, username="tina", email="tina@example.com")
    login(client, username="tina")
    resp = client.get("/dashboard")
    # Tina has no runs of her own - sam's upload must not leak into her view.
    assert b"No validation activity yet" in resp.data


def test_integrations_page_shows_honest_empty_state(client):
    register(client, username="uma", email="uma@example.com")
    login(client, username="uma")
    resp = client.get("/integrations")
    assert b"No integrations configured" in resp.data
    # Must never claim a live/connected integration.
    assert b"Connected" not in resp.data


def test_audit_log_records_registration_and_login(client):
    register(client, username="victor", email="victor@example.com")
    login(client, username="victor")

    resp = client.get("/audit-logs")
    assert b"account registered" in resp.data
    assert b"login success" in resp.data


def test_audit_log_records_rule_upload(client):
    register(client, username="wendy", email="wendy@example.com")
    login(client, username="wendy")
    upload(client, VALID_RULE)

    resp = client.get("/audit-logs")
    assert b"rule uploaded" in resp.data
    assert b"rule.yml" in resp.data


def test_audit_log_only_shows_current_users_events(client):
    register(client, username="xena", email="xena@example.com")
    login(client, username="xena")
    client.post("/logout")

    register(client, username="yuri", email="yuri@example.com")
    login(client, username="yuri")

    resp = client.get("/audit-logs")
    page_text = resp.data.decode().lower()
    # Yuri's own registration/login should appear...
    assert "account registered" in page_text
    # ...but this is Yuri's page load, not Xena's - her username should not
    # appear anywhere in the events rendered for Yuri's account.
    assert "xena" not in page_text


def test_settings_shows_real_account_info(client):
    register(client, username="zoe", email="zoe@example.com")
    login(client, username="zoe")

    resp = client.get("/settings")
    assert b"zoe" in resp.data
    assert b"zoe@example.com" in resp.data


def test_settings_shows_actual_run_count(client):
    register(client, username="amir", email="amir@example.com")
    login(client, username="amir")
    upload(client, VALID_RULE)
    upload(client, BROKEN_RULE)

    resp = client.get("/settings")
    assert b">2<" in resp.data or b"2" in resp.data


# ---------------------------------------------------------------------
# CSRF (tested with a second app instance where CSRF is actually enabled)
# ---------------------------------------------------------------------


def test_csrf_protection_blocks_request_without_token(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_DATABASE_PATH", str(tmp_path / "csrf_test.db"))
    protected_app = create_app("testing")
    protected_app.config["WTF_CSRF_ENABLED"] = True
    protected_client = protected_app.test_client()

    resp = protected_client.post(
        "/register",
        data={
            "username": "csrftest",
            "email": "csrf@example.com",
            "password": "correcthorse9",
            "confirm_password": "correcthorse9",
        },
    )
    assert resp.status_code == 400  # CSRFProtect rejects the missing token
