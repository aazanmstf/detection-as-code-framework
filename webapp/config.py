"""
Configuration for the webapp, loaded from environment variables (and an
optional local .env file for development). Nothing sensitive is hardcoded.

See .env.example for the full list of supported variables.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

WEBAPP_ROOT = Path(__file__).resolve().parent
REPO_ROOT = WEBAPP_ROOT.parent
INSTANCE_DIR = WEBAPP_ROOT / "instance"

# Load a local .env file if present (development convenience only - in
# real production, environment variables should be set by the process
# manager / platform, not read from a file shipped in the repo).
load_dotenv(WEBAPP_ROOT / ".env")


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class BaseConfig:
    ENV = os.environ.get("FLASK_ENV", "development")

    # SECRET_KEY signs the session cookie. In development we generate a
    # random ephemeral key if none is set (sessions won't survive a
    # restart, which is fine for local use). In production, a real,
    # persistent secret MUST be provided via environment variable -
    # enforced in ProductionConfig below.
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH", str(INSTANCE_DIR / "webapp.db")
    )

    DETECTIONS_DIR = REPO_ROOT / "detections"

    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_BYTES", 100 * 1024))

    # Session / cookie hardening.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME_SECONDS", 60 * 60 * 8))

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # tokens tied to the session, not a wall-clock window


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # requires the app to be served over HTTPS

    def __init__(self):
        if not os.environ.get("SECRET_KEY"):
            raise RuntimeError(
                "SECRET_KEY environment variable must be set in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )


class TestingConfig(BaseConfig):
    TESTING = True
    WTF_CSRF_ENABLED = False  # simplifies posting from the test client
    # A real (temp) file rather than ":memory:" so the schema persists
    # across the multiple short-lived connections opened per request.
    DATABASE_PATH = os.environ.get("TEST_DATABASE_PATH", "")


def get_config(name: str | None = None):
    name = name or os.environ.get("FLASK_ENV", "development")
    mapping = {
        "development": DevelopmentConfig,
        "production": ProductionConfig,
        "testing": TestingConfig,
    }
    config_cls = mapping.get(name, DevelopmentConfig)
    if name == "production":
        ProductionConfig()  # triggers the SECRET_KEY check
    return config_cls
