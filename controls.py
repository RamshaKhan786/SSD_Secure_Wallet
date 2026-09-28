"""
controls.py — Security control implementations for the Mini Secure Fintech Wallet.

Each function/constant here implements ONE named control from the assignment's
Security Design Table. db.py and app.py call into this module instead of
re-implementing policy decisions inline, so every control has a single,
auditable, independently-testable home — and the report can point directly
at a function name for "where was the control implemented?".

Control index
-------------
C1  Password hashing              hash_password / verify_password
C2  Parameterized queries         a pattern followed throughout db.py (every
                                   query uses ? placeholders, never string
                                   interpolation) — not a standalone function,
                                   noted here for completeness. The one
                                   deliberate exception is the vulnerable-mode
                                   demo path in db.get_user_by_credentials_unsafe.
C3  Object-level authorization    is_owner
C4  Server-side input validation  validate_registration / validate_transfer_amount
C5  CSRF protection                new_csrf_token / csrf_token_valid
C6  Account lockout                is_account_locked / next_failed_login_state
C7  Tamper-evident audit log       audit_row_hash / verify_audit_chain
C8  Session hardening              SESSION_SECURITY_CONFIG / rotate_session
C9  Security response headers      SECURITY_HEADERS
C10 Role separation (admin-only)   is_admin
"""
import hashlib
import re
import secrets
import time
from decimal import Decimal, InvalidOperation

from werkzeug.security import generate_password_hash, check_password_hash

# ---- policy constants -------------------------------------------------
MAX_TRANSFER = Decimal("100000")     # C4: per-transaction limit (Rs.)
MAX_FAILED_LOGINS = 5                # C6: attempts allowed before lockout
LOCK_SECONDS = 300                   # C6: lockout duration
USERNAME_PATTERN = re.compile(r"[a-z0-9_]{3,20}")
MIN_PASSWORD_LEN = 8


# ---------------------------------------------------------------- C1: password hashing
def hash_password(password):
    """Salted, slow hash (werkzeug/scrypt). Plaintext passwords are never stored."""
    return generate_password_hash(password)


def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)


# ---------------------------------------------------------------- C3: object-level authorization
def is_owner(session_uid, requested_uid):
    """A user may only act on their OWN wallet — never trust a client-supplied id."""
    return session_uid == requested_uid


# ---------------------------------------------------------------- C10: role separation
def is_admin(user):
    """Privileged operations (the audit log) require an explicit admin role."""
    return user is not None and user["role"] == "admin"


# ---------------------------------------------------------------- C4: server-side input validation
def validate_registration(username, password):
    """Returns (ok, error_message_or_None). Client-side checks are UX only; this is the real gate."""
    if not USERNAME_PATTERN.fullmatch(username):
        return False, "Username: 3-20 chars [a-z0-9_]."
    if len(password) < MIN_PASSWORD_LEN:
        return False, f"Password must be at least {MIN_PASSWORD_LEN} characters."
    return True, None


def validate_transfer_amount(amount_str):
    """Returns (ok, amount_in_paisa_or_error_message)."""
    try:
        d = Decimal(str(amount_str).strip())
        if not d.is_finite() or d <= 0 or d > MAX_TRANSFER or d != d.quantize(Decimal("0.01")):
            raise ValueError
    except (InvalidOperation, ValueError, AttributeError):
        return False, f"Amount must be a positive number (max 2 decimals, up to Rs. {MAX_TRANSFER:,})."
    return True, int(d * 100)


# ---------------------------------------------------------------- C5: CSRF protection
def new_csrf_token():
    return secrets.token_hex(16)


def csrf_token_valid(sent_token, expected_token):
    return secrets.compare_digest(sent_token or "", expected_token or "")


# ---------------------------------------------------------------- C6: account lockout
def is_account_locked(user):
    return user["locked_until"] > time.time()


def next_failed_login_state(user):
    """
    Pure policy calculation: given one more bad password, what should
    (failed_attempts, locked_until) become? db.py persists the result.
    """
    n_fail = user["failed_attempts"] + 1
    if n_fail >= MAX_FAILED_LOGINS:
        return 0, time.time() + LOCK_SECONDS
    return n_fail, 0


# ---------------------------------------------------------------- C7: tamper-evident audit log
GENESIS_HASH = "0" * 64


def audit_row_hash(prev_hash, ts, uid, action, detail):
    """Each row's hash covers the previous row's hash, forming a tamper-evident chain."""
    return hashlib.sha256(f"{prev_hash}|{ts}|{uid}|{action}|{detail}".encode()).hexdigest()


def verify_audit_chain(rows):
    """
    rows: audit_log rows ordered OLDEST -> NEWEST.
    Returns None if the chain is intact, else the id of the first tampered row.
    """
    prev = GENESIS_HASH
    for r in rows:
        expected = audit_row_hash(prev, r["ts"], r["user_id"], r["action"], r["detail"])
        if r["prev_hash"] != prev or r["hash"] != expected:
            return r["id"]
        prev = r["hash"]
    return None


# ---------------------------------------------------------------- C8: session hardening
SESSION_SECURITY_CONFIG = {
    "SESSION_COOKIE_HTTPONLY": True,     # JS cannot read the session cookie
    "SESSION_COOKIE_SAMESITE": "Lax",    # cookie not sent on cross-site POSTs
    "PERMANENT_SESSION_LIFETIME": 1000,  # idle session timeout, in seconds
}


def rotate_session(session, user_id):
    """
    Anti session-fixation: wipe any pre-login session data and issue a fresh
    session + CSRF token bound to the newly authenticated user.
    """
    session.clear()
    session.permanent = True
    session["uid"] = user_id
    session["csrf"] = new_csrf_token()


# ---------------------------------------------------------------- C9: security response headers
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'"
    ),
    "Cache-Control": "no-store",
}