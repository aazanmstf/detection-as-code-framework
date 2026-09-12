"""
WSGI entry point for later production deployment.

This file is NOT used to deploy anything now - it exists so that when
you are ready to deploy, a production WSGI server can find the app
object without needing Flask's development server (`app.run(...)`,
which is not designed for production use).

Example (not executed here):
    gunicorn --workers 3 --bind 0.0.0.0:8000 webapp.wsgi:app

See DEPLOYMENT.md for the full later-deployment checklist.
"""

from __future__ import annotations

import os

from webapp.app import create_app

app = create_app(os.environ.get("FLASK_ENV", "production"))
