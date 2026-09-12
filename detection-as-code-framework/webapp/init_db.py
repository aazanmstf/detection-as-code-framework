#!/usr/bin/env python3
"""
Standalone database initialization script.

Useful for provisioning the SQLite file before first run, e.g. in a
deployment setup step. The Database class already initializes the schema
automatically on first use, so this script is a convenience, not a
requirement.

Usage:
    python webapp/init_db.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webapp.config import get_config
from webapp.models import Database


def main() -> None:
    config_cls = get_config()
    db_path = config_cls.DATABASE_PATH
    db = Database(db_path)
    print(f"Database initialized at: {db_path}")
    _ = db  # schema created as a side effect of construction


if __name__ == "__main__":
    main()
