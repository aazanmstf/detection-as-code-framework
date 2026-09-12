"""
Security utilities for the webapp.

Centralizes the security-sensitive primitives (password hashing, password
policy, login throttling, safe filename handling) in one small, reviewable
module rather than scattering them across routes.
"""

from __future__ import annotations

import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Tuple

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename as werkzeug_secure_filename

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
# werkzeug's default (scrypt) is a modern, salted, memory-hard KDF - this
# avoids ever storing or comparing plaintext passwords.


def hash_password(plain_password: str) -> str:
    return generate_password_hash(plain_password)


def verify_password(password_hash: str, plain_password: str) -> bool:
    try:
        return check_password_hash(password_hash, plain_password)
    except ValueError:
        # Malformed hash in the DB - treat as a failed check, never raise
        # into a route where it could leak implementation detail.
        return False


# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------

MIN_PASSWORD_LENGTH = 10

# A short list of extremely common passwords. Not a substitute for a real
# breached-password API (e.g. HaveIBeenPwned k-anonymity lookup), which is
# listed as a future improvement, but catches the most obvious weak choices.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678",
    "qwerty123", "letmein", "welcome1", "iloveyou", "admin123",
    "changeme", "detection123",
}


def validate_password_policy(password: str, username: str = "", email: str = "") -> List[str]:
    """Return a list of human-readable problems with the password, or an
    empty list if it satisfies the policy."""
    problems: List[str] = []

    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")

    if not re.search(r"[A-Za-z]", password):
        problems.append("Password must contain at least one letter.")

    if not re.search(r"[0-9]", password):
        problems.append("Password must contain at least one number.")

    if password.lower() in COMMON_PASSWORDS:
        problems.append("This password is too common. Choose something more unique.")

    if username and password.lower() == username.lower():
        problems.append("Password cannot be the same as your username.")

    return problems


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_username(username: str) -> List[str]:
    problems = []
    if not USERNAME_PATTERN.match(username or ""):
        problems.append(
            "Username must be 3-32 characters and contain only letters, "
            "numbers, dots, dashes, or underscores."
        )
    return problems


def validate_email(email: str) -> List[str]:
    problems = []
    if not EMAIL_PATTERN.match(email or ""):
        problems.append("Enter a valid email address.")
    return problems


# ---------------------------------------------------------------------------
# Login attempt throttling
# ---------------------------------------------------------------------------
# A minimal in-memory limiter to blunt naive password-guessing against the
# login endpoint. This is intentionally simple:
#
#   - It is per-process, in-memory state. In a multi-worker or multi-instance
#     production deployment (gunicorn with >1 worker, multiple containers)
#     each process/instance has its OWN counters, so this does not provide a
#     hard global guarantee.
#   - For real production use, replace this with a shared store (Redis) and/or
#     a battle-tested library such as Flask-Limiter backed by Redis. That is
#     called out explicitly in docs/webapp-security.md and the README.
#
# It still provides real, meaningful protection for a single-process
# deployment and demonstrates the *pattern* correctly.


@dataclass
class _AttemptRecord:
    failures: List[float] = field(default_factory=list)
    locked_until: float = 0.0


class LoginRateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 900, lockout_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._records: Dict[str, _AttemptRecord] = defaultdict(_AttemptRecord)
        self._lock = Lock()

    def _key(self, identifier: str, ip_address: str) -> str:
        return f"{identifier.lower()}::{ip_address}"

    def is_locked(self, identifier: str, ip_address: str) -> Tuple[bool, int]:
        """Returns (locked, seconds_remaining)."""
        key = self._key(identifier, ip_address)
        with self._lock:
            record = self._records[key]
            now = time.time()
            if record.locked_until > now:
                return True, int(record.locked_until - now)
            return False, 0

    def record_failure(self, identifier: str, ip_address: str) -> None:
        key = self._key(identifier, ip_address)
        with self._lock:
            record = self._records[key]
            now = time.time()
            record.failures = [t for t in record.failures if now - t < self.window_seconds]
            record.failures.append(now)
            if len(record.failures) >= self.max_attempts:
                record.locked_until = now + self.lockout_seconds
                record.failures = []

    def record_success(self, identifier: str, ip_address: str) -> None:
        key = self._key(identifier, ip_address)
        with self._lock:
            if key in self._records:
                del self._records[key]


login_rate_limiter = LoginRateLimiter()


# ---------------------------------------------------------------------------
# Safe file handling for uploads
# ---------------------------------------------------------------------------

ALLOWED_UPLOAD_EXTENSIONS = {".yml", ".yaml"}
MAX_UPLOAD_BYTES = 100 * 1024  # 100 KB is generous for a single Sigma rule


def has_allowed_extension(filename: str) -> bool:
    filename = filename or ""
    lowered = filename.lower()
    return any(lowered.endswith(ext) for ext in ALLOWED_UPLOAD_EXTENSIONS)


def safe_storage_name(original_filename: str) -> str:
    """
    Build a filename safe to use on disk: sanitize the original name with
    werkzeug's secure_filename (strips path separators, unicode tricks,
    etc.) and prefix it with a random UUID so that (a) two users' uploads
    can never collide and (b) the original filename is never trusted to
    construct a path on its own.
    """
    cleaned = werkzeug_secure_filename(original_filename) or "rule.yml"
    return f"{uuid.uuid4().hex}_{cleaned}"
