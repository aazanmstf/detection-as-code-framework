"""
Database access layer for the webapp.

Uses Python's built-in sqlite3 module directly (no ORM dependency) with
parameterized queries EVERYWHERE user-controlled data is involved - never
raw string formatting into SQL - to prevent SQL injection.

SQLite is appropriate for a portfolio-scale single-instance deployment.
docs/webapp-security.md and DEPLOYMENT.md call out migrating to
PostgreSQL as the recommended step for a real multi-instance production
deployment.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    original_filename TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    result TEXT NOT NULL,
    score INTEGER NOT NULL,
    rule_title TEXT,
    rule_id TEXT,
    attack_techniques_json TEXT NOT NULL,
    issues_json TEXT NOT NULL,
    duplicate_warning TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX IF NOT EXISTS idx_validation_runs_user_id
    ON validation_runs (user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id
    ON audit_log (user_id);
"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    """Thin wrapper that opens a fresh sqlite3 connection per operation.

    Short-lived connections avoid cross-request/thread sharing issues with
    sqlite3 and keep the concurrency model simple and easy to reason about
    for a portfolio-scale app.
    """

    def __init__(self, database_path: str):
        self.database_path = database_path
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # -- Users --------------------------------------------------------

    def create_user(self, username: str, email: str, password_hash: str) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) "
                "VALUES (?, ?, ?, ?)",
                (username, email, password_hash, _utcnow_iso()),
            )
            return cursor.lastrowid

    def get_user_by_username(self, username: str) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()

    def get_user_by_email(self, email: str) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)
            ).fetchone()

    def get_user_by_id(self, user_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()

    # -- Validation runs ------------------------------------------------

    def create_validation_run(
        self,
        user_id: int,
        original_filename: str,
        result: str,
        score: int,
        rule_title: str,
        rule_id: str,
        attack_techniques: List[str],
        issues: List[dict],
        duplicate_warning: Optional[str],
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO validation_runs (
                    user_id, original_filename, submitted_at, result, score,
                    rule_title, rule_id, attack_techniques_json, issues_json,
                    duplicate_warning
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    original_filename,
                    _utcnow_iso(),
                    result,
                    score,
                    rule_title,
                    rule_id,
                    json.dumps(attack_techniques),
                    json.dumps(issues),
                    duplicate_warning,
                ),
            )
            return cursor.lastrowid

    def get_runs_for_user(self, user_id: int, limit: int = 100) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM validation_runs WHERE user_id = ? "
                "ORDER BY submitted_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()

    def get_run_by_id(self, run_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM validation_runs WHERE id = ?", (run_id,)
            ).fetchone()

    def count_runs_for_user(self, user_id: int) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM validation_runs WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            return row["n"] if row else 0

    # -- Audit log --------------------------------------------------------
    # A real, append-only security event trail: authentication events and
    # rule uploads. Used to back the "Audit Logs" page with genuine data
    # (never simulated/fake entries).

    def create_audit_event(
        self,
        event_type: str,
        username: str,
        user_id: Optional[int] = None,
        detail: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log (user_id, username, event_type, detail, ip_address, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, username, event_type, detail, ip_address, _utcnow_iso()),
            )
            return cursor.lastrowid

    def get_audit_events_for_user(self, user_id: int, limit: int = 200) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM audit_log WHERE user_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()


@dataclass
class RunView:
    """Convenience wrapper that decodes the JSON columns of a run row for
    templates, so Jinja templates never need to call json.loads directly."""

    id: int
    user_id: int
    original_filename: str
    submitted_at: str
    result: str
    score: int
    rule_title: str
    rule_id: str
    attack_techniques: List[str]
    issues: List[dict]
    duplicate_warning: Optional[str]

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "RunView":
        return cls(
            id=row["id"],
            user_id=row["user_id"],
            original_filename=row["original_filename"],
            submitted_at=row["submitted_at"],
            result=row["result"],
            score=row["score"],
            rule_title=row["rule_title"] or "",
            rule_id=row["rule_id"] or "",
            attack_techniques=json.loads(row["attack_techniques_json"]),
            issues=json.loads(row["issues_json"]),
            duplicate_warning=row["duplicate_warning"],
        )
