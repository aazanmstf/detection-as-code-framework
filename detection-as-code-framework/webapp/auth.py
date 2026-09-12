"""
Authentication routes: register, login, logout.

Security properties:
  - Passwords are hashed with werkzeug's scrypt-based hasher, never stored
    or logged in plaintext.
  - Login failures return an identical, generic error whether the username
    or the password was wrong, so the endpoint doesn't reveal which
    accounts exist (username enumeration resistance).
  - Login attempts are throttled per (username, IP) via security.login_rate_limiter.
  - CSRF protection is applied automatically to every POST by Flask-WTF's
    CSRFProtect, initialized once in app.py.
  - Session cookies are HttpOnly/SameSite=Lax always, and Secure whenever
    SESSION_COOKIE_SECURE is enabled (see config.py) - i.e. always in
    production, since that config forces HTTPS-only cookies.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from webapp.security import (
    hash_password,
    login_rate_limiter,
    validate_email,
    validate_password_policy,
    validate_username,
    verify_password,
)

bp = Blueprint("auth", __name__)


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.get("user"):
        return redirect(url_for("validation.upload"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""

        errors = []
        errors += validate_username(username)
        errors += validate_email(email)
        errors += validate_password_policy(password, username=username, email=email)
        if password != confirm:
            errors.append("Passwords do not match.")

        db = current_app.config["DB"]
        if not errors and db.get_user_by_username(username):
            errors.append("That username is already taken.")
        if not errors and db.get_user_by_email(email):
            errors.append("An account with that email already exists.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email)

        new_user_id = db.create_user(username=username, email=email, password_hash=hash_password(password))
        db.create_audit_event(
            event_type="account_registered",
            username=username,
            user_id=new_user_id,
            detail="New account created.",
            ip_address=request.remote_addr,
        )
        flash("Account created. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", username="", email="")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.get("user"):
        return redirect(url_for("validation.upload"))

    if request.method == "POST":
        identifier = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        ip_address = request.remote_addr or "unknown"

        locked, seconds_remaining = login_rate_limiter.is_locked(identifier, ip_address)
        if locked:
            minutes = max(1, seconds_remaining // 60)
            flash(
                f"Too many failed attempts. Try again in about {minutes} minute(s).",
                "error",
            )
            return render_template("login.html", username=identifier)

        db = current_app.config["DB"]
        user = db.get_user_by_username(identifier) or db.get_user_by_email(identifier)

        generic_error = "Invalid username/email or password."
        if user is None or not verify_password(user["password_hash"], password):
            login_rate_limiter.record_failure(identifier, ip_address)
            db.create_audit_event(
                event_type="login_failed",
                username=identifier,
                user_id=(user["id"] if user else None),
                detail="Invalid credentials.",
                ip_address=ip_address,
            )
            flash(generic_error, "error")
            return render_template("login.html", username=identifier)

        login_rate_limiter.record_success(identifier, ip_address)

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]

        db.create_audit_event(
            event_type="login_success",
            username=user["username"],
            user_id=user["id"],
            detail="Successful login.",
            ip_address=ip_address,
        )

        flash(f"Welcome back, {user['username']}.", "success")
        next_url = request.args.get("next")
        return redirect(next_url or url_for("validation.upload"))

    return render_template("login.html", username="")


@bp.route("/logout", methods=["POST"])
def logout():
    if g.get("user"):
        current_app.config["DB"].create_audit_event(
            event_type="logout",
            username=g.user["username"],
            user_id=g.user["id"],
            detail="User logged out.",
            ip_address=request.remote_addr,
        )
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
