"""
Core application routes: upload a Sigma rule, see instant PASS/FAIL
results with plain-English explanations, browse validation history, and
download a report - all scoped strictly to the logged-in user.

Authorization: every route that touches a specific validation_run row
re-checks `run.user_id == g.user["id"]` before returning anything, so one
user can never view or download another user's data even by guessing an
id in the URL (insecure direct object reference protection).
"""

from __future__ import annotations

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from webapp.auth import login_required
from webapp.models import RunView
from webapp.security import MAX_UPLOAD_BYTES, has_allowed_extension
from webapp.validation_service import build_report_text, validate_uploaded_rule

bp = Blueprint("validation", __name__)


@bp.route("/", methods=["GET"])
@login_required
def upload():
    return render_template("upload.html", result=None)


@bp.route("/upload", methods=["POST"])
@login_required
def submit_upload():
    uploaded_file = request.files.get("rule_file")

    if uploaded_file is None or uploaded_file.filename == "":
        flash("Choose a .yml or .yaml Sigma rule file to upload.", "error")
        return render_template("upload.html", result=None)

    if not has_allowed_extension(uploaded_file.filename):
        flash("Only .yml or .yaml files are accepted.", "error")
        return render_template("upload.html", result=None)

    file_bytes = uploaded_file.read()
    if len(file_bytes) == 0:
        flash("The uploaded file is empty.", "error")
        return render_template("upload.html", result=None)
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        flash(f"File is too large (max {MAX_UPLOAD_BYTES // 1024} KB).", "error")
        return render_template("upload.html", result=None)

    outcome = validate_uploaded_rule(file_bytes, uploaded_file.filename)

    db = current_app.config["DB"]
    run_id = db.create_validation_run(
        user_id=g.user["id"],
        original_filename=uploaded_file.filename,
        result=outcome["result"],
        score=outcome["score"],
        rule_title=outcome["title"],
        rule_id=outcome["rule_id"],
        attack_techniques=outcome["attack_techniques"],
        issues=outcome["issues"],
        duplicate_warning=outcome["duplicate_warning"],
    )
    db.create_audit_event(
        event_type="rule_uploaded",
        username=g.user["username"],
        user_id=g.user["id"],
        detail=f"Uploaded '{uploaded_file.filename}' -> {outcome['result']} ({outcome['score']}/100)",
        ip_address=request.remote_addr,
    )

    return redirect(url_for("validation.view_run", run_id=run_id))


def _get_owned_run_or_404(run_id: int) -> RunView:
    db = current_app.config["DB"]
    row = db.get_run_by_id(run_id)
    if row is None:
        abort(404)
    run = RunView.from_row(row)
    if run.user_id != g.user["id"]:
        # Same response as "not found" - don't confirm the id exists at all.
        abort(404)
    return run


@bp.route("/runs/<int:run_id>", methods=["GET"])
@login_required
def view_run(run_id: int):
    run = _get_owned_run_or_404(run_id)
    return render_template("upload.html", result=run)


@bp.route("/history", methods=["GET"])
@login_required
def history():
    db = current_app.config["DB"]
    rows = db.get_runs_for_user(g.user["id"])
    runs = [RunView.from_row(row) for row in rows]
    return render_template("history.html", runs=runs)


@bp.route("/runs/<int:run_id>/download", methods=["GET"])
@login_required
def download_report(run_id: int):
    run = _get_owned_run_or_404(run_id)
    report_text = build_report_text(run)
    filename = f"validation-report-run-{run.id}.txt"
    return Response(
        report_text,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------
# Dashboard, Integrations, Audit Logs, Settings
#
# These pages only ever render data that's actually stored for the
# logged-in user (their own validation_runs and audit_log rows) - no
# simulated stats, alerts, or "live" activity are ever generated.
# ---------------------------------------------------------------------


def _summarize_runs(runs: list[RunView]) -> dict:
    total = len(runs)
    passed = sum(1 for r in runs if r.result == "PASS")
    failed = total - passed
    avg_score = round(sum(r.score for r in runs) / total, 1) if total else 0.0
    pass_rate = round((passed / total) * 100) if total else 0

    technique_counts: dict[str, int] = {}
    for run in runs:
        for technique in run.attack_techniques:
            technique_counts[technique] = technique_counts.get(technique, 0) + 1

    max_count = max(technique_counts.values()) if technique_counts else 0
    coverage = [
        {
            "technique": technique,
            "count": count,
            "percent": round((count / max_count) * 100) if max_count else 0,
        }
        for technique, count in sorted(technique_counts.items())
    ]

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "avg_score": avg_score,
        "pass_rate": pass_rate,
        "unique_techniques": len(technique_counts),
        "coverage": coverage,
    }


@bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    db = current_app.config["DB"]
    rows = db.get_runs_for_user(g.user["id"], limit=500)
    runs = [RunView.from_row(row) for row in rows]
    summary = _summarize_runs(runs)
    recent_runs = runs[:6]
    return render_template("dashboard.html", summary=summary, recent_runs=recent_runs)


@bp.route("/integrations", methods=["GET"])
@login_required
def integrations():
    return render_template("integrations.html")


@bp.route("/audit-logs", methods=["GET"])
@login_required
def audit_logs():
    db = current_app.config["DB"]
    rows = db.get_audit_events_for_user(g.user["id"])
    return render_template("audit_logs.html", events=rows)


@bp.route("/settings", methods=["GET"])
@login_required
def settings():
    db = current_app.config["DB"]
    run_count = db.count_runs_for_user(g.user["id"])
    return render_template("settings.html", run_count=run_count)
