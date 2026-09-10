"""
Flask application factory.

Wires together config, the database, CSRF protection, per-request user
loading, security response headers, and the two blueprints (auth,
validation). Kept as a factory (create_app) rather than a module-level
`app = Flask(...)` so tests can build isolated app instances with their
own temp database.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, g, session
from flask_wtf import CSRFProtect

from webapp.config import get_config
from webapp.models import Database

csrf = CSRFProtect()


def create_app(env: str | None = None) -> Flask:
    app = Flask(__name__)
    config_cls = get_config(env)
    app.config.from_object(config_cls)

    db_path = app.config["DATABASE_PATH"]
    if not db_path:
        # TestingConfig with no explicit TEST_DATABASE_PATH set - use a
        # throwaway temp file so schema persists across the short-lived
        # connections the Database class opens per operation.
        import tempfile

        db_path = str(Path(tempfile.mkdtemp(prefix="dac_webapp_test_")) / "test.db")
    app.config["DB"] = Database(db_path)

    csrf.init_app(app)

    register_request_hooks(app)
    register_blueprints(app)
    register_error_handlers(app)

    return app


def register_request_hooks(app: Flask) -> None:
    @app.before_request
    def load_logged_in_user():
        user_id = session.get("user_id")
        g.user = None
        if user_id is not None:
            db = app.config["DB"]
            row = db.get_user_by_id(user_id)
            if row is not None:
                g.user = row
            else:
                # Session refers to a user that no longer exists - clear it.
                session.clear()

    @app.after_request
    def set_security_headers(response):
        # A minimal, dependency-free set of hardening headers appropriate
        # for a server-rendered app with no third-party embeds.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response

    @app.context_processor
    def inject_user():
        return {"current_user": g.get("user")}

    @app.context_processor
    def inject_csrf_helper():
        from markupsafe import Markup
        from flask_wtf.csrf import generate_csrf

        def csrf_field():
            token = generate_csrf()
            return Markup(f'<input type="hidden" name="csrf_token" value="{token}">')

        return {"csrf_field": csrf_field}


def register_blueprints(app: Flask) -> None:
    from webapp.auth import bp as auth_bp
    from webapp.validation_routes import bp as validation_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(validation_bp)


def register_error_handlers(app: Flask) -> None:
    from flask import render_template

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="Forbidden."), 403

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", code=413, message="Uploaded file is too large."), 413

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("error.html", code=500, message="Something went wrong."), 500


if __name__ == "__main__":
    application = create_app()
    application.run(host="127.0.0.1", port=5000, debug=application.config.get("DEBUG", False))
