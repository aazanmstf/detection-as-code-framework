# Deployment Guide (Not Yet Deployed)

This document describes how `webapp/` would be deployed later. **Nothing
in this repository deploys anything automatically** - there is no
Dockerfile being built, no CI step that pushes anywhere, and no cloud
resources are created by any file here. This is a checklist for when
you're ready to do that yourself.

## Local Development (what you can do right now)

```bash
pip install -r requirements.txt -r requirements-webapp.txt
cp webapp/.env.example webapp/.env
# edit webapp/.env if you want to override any defaults - optional for local dev
python webapp/app.py
```

Open `http://127.0.0.1:5000`. The SQLite database is created
automatically at `webapp/instance/webapp.db` on first run.

Run the webapp's own test suite:

```bash
pytest webapp/tests
```

(This is separate from `pytest` at the repo root, which only runs the
original 52 validator tests and is what CI uses - see
`.github/workflows/detection-validation.yml`, which is unchanged.)

## Before Deploying Publicly: Checklist

1. **Generate a real `SECRET_KEY`** and set it as an environment
   variable on the host/platform (not in a committed file):
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. **Set `FLASK_ENV=production`.** This activates `ProductionConfig`,
   which forces `SESSION_COOKIE_SECURE=True` and refuses to start
   without a `SECRET_KEY`.
3. **Serve over HTTPS.** `SESSION_COOKIE_SECURE=True` means the session
   cookie is never sent over plain HTTP - put a reverse proxy (nginx,
   Caddy, or your platform's load balancer) in front that terminates
   TLS, or use a platform that provides HTTPS automatically (Render,
   Railway, Fly.io, etc.).
4. **Run behind a real WSGI server**, not Flask's dev server:
   ```bash
   gunicorn --workers 3 --bind 0.0.0.0:8000 webapp.wsgi:app
   ```
   `webapp/wsgi.py` already exposes the right `app` object for this.
5. **Move off SQLite for multi-instance deployments.** SQLite is fine
   for a single process/instance. If you scale to multiple
   workers/instances behind a load balancer, migrate `webapp/models.py`
   to PostgreSQL (e.g. via `psycopg2` + connection pooling) so every
   instance sees the same data - the parameterized-query pattern
   already used throughout `models.py` carries over directly.
6. **Move the login rate limiter to Redis** if running more than one
   worker/instance (see `docs/webapp-security.md` section 2). Consider
   Flask-Limiter with a Redis storage backend as a drop-in replacement
   for `webapp/security.py`'s `LoginRateLimiter`.
7. **Set a real upload size limit at the reverse proxy too** (e.g.
   nginx's `client_max_body_size`), not just in Flask, so oversized
   uploads are rejected before they reach the app process.
8. **Add persistent volume/backup for the SQLite file** (or the
   PostgreSQL database, once migrated) so user accounts and validation
   history survive a redeploy.
9. **Turn on dependency scanning** (e.g. `pip-audit` or GitHub's
   Dependabot) for `requirements.txt` and `requirements-webapp.txt`.
10. **Add email verification and password reset** before treating this
    as a real account system for the public - see
    `docs/webapp-security.md`'s "Out of Scope" section.
11. **Point real monitoring/logging at it** - at minimum, ship the
    gunicorn/application logs somewhere durable, and consider adding
    structured logging of authentication events.

## Example Production Launch Command (for reference only)

```bash
export FLASK_ENV=production
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SESSION_COOKIE_SECURE=true
export DATABASE_PATH=/var/lib/dac-webapp/webapp.db

pip install -r requirements.txt -r requirements-webapp.txt
python webapp/init_db.py
gunicorn --workers 3 --bind 0.0.0.0:8000 webapp.wsgi:app
```

This command is documentation, not automation - it is not run by
anything in this repository.

## What Stays Unchanged

- `validator/` - the core validation engine (unmodified)
- `detections/` - the 5 production Sigma rules (unmodified)
- `tests/` - the original 52 pytest tests (unmodified)
- `.github/workflows/detection-validation.yml` - CI (unmodified,
  installs only `requirements.txt` and runs `pytest` + the CLI)
- `dashboard/` - the original local, no-login dashboard (still works
  standalone via `python dashboard/backend.py`, untouched)

`webapp/` is purely additive.
