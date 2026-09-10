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
