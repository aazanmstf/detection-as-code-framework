"""
Secure, multi-user web application for the Detection as Code Validation
Framework: account registration/login, Sigma rule upload, instant
validation with plain-English explanations, downloadable reports, and
per-user validation history.

This package only ever *imports* the existing top-level `validator`
package - it never modifies it. See docs/webapp-security.md for the
security design and DEPLOYMENT.md for how to deploy this later.
"""

__version__ = "1.0.0"
