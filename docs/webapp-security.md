# Webapp Security Design

This document explains the security decisions behind `webapp/`, so a
reviewer (or an interviewer) can see exactly what's protected and why,
and what's explicitly out of scope for a portfolio-scale build.

## Threat Model

`webapp/` is a multi-user, internet-facing application (once deployed):
anyone can register an account, so the main risks are:

1. Account takeover (weak passwords, credential stuffing/brute force)
2. One user reading or tampering with another user's data
3. Malicious file upload (the one place untrusted external content enters the system)
4. Cross-site request forgery against logged-in users
5. Session hijacking / cookie theft
6. SQL injection
7. Leaking secrets (keys, password hashes) through misconfiguration

Each is addressed below, file-by-file.

## 1. Authentication & Password Storage

- Passwords are hashed with Werkzeug's `generate_password_hash`, which
  uses **scrypt** by default (memory-hard, salted). Plaintext passwords
  are never stored, logged, or included in error messages.
  See `webapp/security.py`.
- Password policy (`validate_password_policy`): minimum 10 characters,
  requires a letter and a number, rejects a short list of extremely
  common passwords, and rejects using the username as the password.
- Login errors are intentionally generic ("Invalid username/email or
  password") whether the account doesn't exist or the password was
  wrong - this prevents username enumeration. See `webapp/auth.py`.

## 2. Brute-Force / Credential-Stuffing Protection

`webapp/security.py`'s `LoginRateLimiter` locks out an
`(identifier, IP)` pair for 15 minutes after 5 failed attempts within a
15-minute window, and clears on success.

**Known limitation:** this is in-memory, per-process state. If the app
is later deployed with multiple gunicorn workers or multiple instances,
each process has its own counters, so the limiter is not a hard global
guarantee. For a real production deployment, replace this with a
shared store (Redis) - e.g. Flask-Limiter with a Redis backend - so
limits are enforced across every worker/instance. This is called out
again in `DEPLOYMENT.md`.

## 3. Session Security

- `SECRET_KEY` (which signs session cookies) is read from the
  `SECRET_KEY` environment variable. It is **never** hardcoded. In
  development, if unset, a random key is generated at process start
  (sessions just won't survive a restart - acceptable for local use).
  In production (`ProductionConfig`), the app **refuses to start** if
  `SECRET_KEY` isn't set. See `webapp/config.py`.
- Cookies are `HttpOnly` (JavaScript can't read them, mitigating XSS
  cookie theft) and `SameSite=Lax` (mitigates CSRF via cross-site
  navigation) always.
- `SESSION_COOKIE_SECURE` is forced `True` in production, meaning
  cookies are only ever sent over HTTPS. This requires the app to
  actually be served over HTTPS in production (see `DEPLOYMENT.md`) -
  otherwise the cookie will never be sent and login will appear broken,
  which is an intentional fail-closed behavior.
- Sessions expire after `SESSION_LIFETIME_SECONDS` (default 8 hours).

## 4. CSRF Protection

Every state-changing request (register, login, logout, upload) is a
`POST`. `Flask-WTF`'s `CSRFProtect` is initialized once in
`webapp/app.py` and protects **all** `POST`/`PUT`/`PATCH`/`DELETE`
requests app-wide by default - there's no per-route opt-in to forget.
Every form includes a hidden CSRF token via the `csrf_field()` template
helper. Verified by `webapp/tests/test_webapp.py::test_csrf_protection_blocks_request_without_token`,
which confirms a request missing the token is rejected with `400`.

## 5. Authorization / Insecure Direct Object Reference (IDOR) Protection

`validation_runs` rows are only ever returned after re-checking
`run.user_id == g.user["id"]` in `_get_owned_run_or_404()`
(`webapp/validation_routes.py`). A user who guesses another user's
run ID gets an identical `404` (not a `403`), so the response doesn't
even confirm the ID exists. This is exercised by
`test_user_cannot_view_another_users_run` and
`test_user_cannot_download_another_users_report`.

## 6. File Upload Handling

Untrusted external input enters the system in exactly one place: the
rule upload form. It's handled defensively:

- **Extension allow-list**: only `.yml`/`.yaml` accepted
  (`has_allowed_extension`).
- **Size limit**: `MAX_CONTENT_LENGTH` (Flask-enforced) and a second
  explicit check (`MAX_UPLOAD_BYTES`, default 100 KB) reject oversized
  uploads before they're processed.
- **No path trust**: the uploaded content is written to a
  `tempfile.TemporaryDirectory()` with a fixed, hardcoded filename
  (`uploaded_rule.yml`) - the user's original filename is *never* used
  to build a filesystem path, eliminating path traversal risk. The
  original filename is only ever used as a display string (and is
  HTML-escaped by Jinja2's autoescaping when rendered).
- **No code execution**: the uploaded content is only ever parsed with
  `yaml.safe_load` (inside the unmodified `validator` package) - never
  `eval`'d, never used to construct a shell command, never passed to
  `yaml.load` (which, unlike `safe_load`, can be tricked into
  instantiating arbitrary Python objects).
- **The temp file is deleted** as soon as validation finishes (the
  `with tempfile.TemporaryDirectory()` block exits) - nothing from an
  upload persists on disk. Only the *validation result* (JSON-encoded
  findings) is stored in the database, not the original file content.

## 7. SQL Injection Prevention

`webapp/models.py` uses Python's built-in `sqlite3` module directly. Every
query that includes any variable data uses `?` placeholders with values
passed as a separate tuple - never string formatting/concatenation into
SQL. There is no code path in the entire webapp that builds a SQL string
with `f"..."` or `.format()`/`%` using request data.

## 8. XSS Prevention

All templates are Jinja2 (`webapp/templates/`), which HTML-escapes
variables by default. No template uses the `| safe` filter or
`Markup()` on user-supplied data (the one place `Markup()` is used,
`csrf_field()` in `webapp/app.py`, only wraps a server-generated CSRF
token, never user input). A `Content-Security-Policy` header
(`default-src 'self'`, no inline scripts) is set on every response as
defense in depth, so even a missed escape wouldn't execute injected
`<script>` tags.

## 9. Security Response Headers

Set on every response in `webapp/app.py`'s `after_request` hook:

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Stops the browser from MIME-sniffing responses into an executable type |
| `X-Frame-Options` | `DENY` | Prevents the app from being framed (clickjacking) |
| `Referrer-Policy` | `same-origin` | Avoids leaking full URLs to third parties |
| `Content-Security-Policy` | `default-src 'self'; ...` | Restricts scripts/styles/images to same-origin |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Only sent when `SESSION_COOKIE_SECURE` is on (i.e. HTTPS is expected) - tells browsers to always use HTTPS for this host |

## 10. Configuration & Secrets Hygiene

- All secrets (`SECRET_KEY`) and environment-specific settings (DB path,
  upload limits, cookie security flag) come from environment variables,
  loaded via `python-dotenv` from an optional local `webapp/.env` file
  for development convenience only. See `webapp/.env.example`.
- `webapp/.env` and `webapp/instance/` (where the SQLite file lives) are
  in `.gitignore` - neither secrets nor user data are ever committed.
- `ProductionConfig` fails fast (raises `RuntimeError`) if `SECRET_KEY`
  is missing, rather than silently falling back to something insecure.

## What's Explicitly Out of Scope (Portfolio-Scale Honesty)

Matching the same honesty principle as the core validator's README
limitations section:

- **No email verification or password reset flow.** A real production
  app would verify email ownership and support secure password reset
  (e.g. time-limited signed tokens emailed to the user). Listed as a
  future improvement.
- **No distributed rate limiting.** See section 2 above - the current
  limiter is single-process only.
- **No multi-factor authentication.**
- **No dependency vulnerability scanning automation** (e.g. `pip-audit`
  in CI) - worth adding before a real public launch.
- **SQLite, not a managed database.** Fine for a single-instance
  deployment; `DEPLOYMENT.md` recommends PostgreSQL for a real
  multi-instance production setup.
- **No structured audit logging** of security-relevant events (failed
  logins, permission denials) beyond what Flask's own request log
  captures.

This app has not been deployed and is not currently exposed to the
public internet - see `DEPLOYMENT.md` for what would need to happen
before that changes.
