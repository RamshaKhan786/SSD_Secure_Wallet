"""
Security-control policy for the Mini Secure Fintech Wallet.

The assignment asks us to identify weaknesses and then choose controls that
reduce the corresponding risks.  This file keeps the security decisions in
one place; db.py is responsible for persisting the results.

Control map
-----------
C1  Password hashing
C2  Parameterized SQL (implemented throughout db.py)
C3  Authentication / login protection
C4  Object-level authorization
C5  Role separation (customer vs admin)
C6  Server-side input validation
C7  CSRF protection
C8  Account lockout
C9  Tamper-evident audit trail
C10 Session hardening
C11 Security response headers
C12 Step-up authentication for high-value transfers
C13 Beneficiary validation and ownership
"""

import hashlib
import hmac
import re
import secrets
import time
from decimal import Decimal, InvalidOperation

from werkzeug.security import generate_password_hash, check_password_hash

# ---- policy constants -------------------------------------------------
MAX_TRANSFER = Decimal("100000")          # Rs. 100,000 per transaction
MAX_FAILED_LOGINS = 5                     # lock after 5 failed attempts
LOCK_SECONDS = 300                        # 5 minute lock
USERNAME_PATTERN = re.compile(r"[a-z0-9_]{3,20}")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
MAX_FULL_NAME_LEN = 60
STEP_UP_THRESHOLD = Decimal("10000")      # Rs. 10,000 and above
STEP_UP_CODE_TTL = 120                    # seconds
STEP_UP_MAX_ATTEMPTS = 3
SESSION_IDLE_TIMEOUT = 600                # 10 minutes


# ---------------------------------------------------------------- C1: password hashing

def hash_password(password):
    """Create a salted, slow password hash. Plaintext passwords are never stored in secure mode."""
    return generate_password_hash(password)


def verify_password(stored_hash, password):
    """Verify a supplied password against a previously stored hash."""
    return check_password_hash(stored_hash, password)


# ---------------------------------------------------------------- C4: object-level authorization

def is_owner(session_uid, requested_uid):
    """A user may only access wallet objects belonging to their own account."""
    return session_uid == requested_uid


# ---------------------------------------------------------------- C5: role separation

def is_admin(user):
    """Return True only for an explicitly stored admin role."""
    return user is not None and user["role"] == "admin"


# ---------------------------------------------------------------- C6: server-side validation

def validate_registration(username, password, full_name):
    """Return (ok, error_message_or_None). This is the real validation gate."""
    username = (username or "").strip()
    full_name = (full_name or "").strip()

    if not USERNAME_PATTERN.fullmatch(username):
        return False, "Username must be 3-20 characters using lowercase letters, numbers, or _."
    if not full_name or len(full_name) > MAX_FULL_NAME_LEN:
        return False, f"Full name is required and must be at most {MAX_FULL_NAME_LEN} characters."
    if len(password or "") < MIN_PASSWORD_LEN:
        return False, f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if len(password or "") > MAX_PASSWORD_LEN:
        return False, f"Password must not exceed {MAX_PASSWORD_LEN} characters."
    return True, None


def validate_transfer_recipient(username):
    """Validate a recipient identifier before it is used by the transfer logic."""
    username = (username or "").strip()
    if not USERNAME_PATTERN.fullmatch(username):
        return False, "Recipient username is invalid."
    return True, None


def validate_beneficiary_username(username):
    """Validate the identifier used when adding a beneficiary."""
    username = (username or "").strip()
    if not USERNAME_PATTERN.fullmatch(username):
        return False, "Beneficiary username must be 3-20 characters using lowercase letters, numbers, or _."
    return True, None


def validate_beneficiary_id(value):
    """Validate a beneficiary record id supplied by the client."""
    try:
        beneficiary_id = int(value)
    except (TypeError, ValueError):
        return False, None
    return beneficiary_id > 0, beneficiary_id if beneficiary_id > 0 else None


def validate_transfer_amount(amount_str):
    """Return (ok, amount_in_paisa_or_error_message)."""
    try:
        d = Decimal(str(amount_str).strip())
        if (
            not d.is_finite()
            or d <= 0
            or d > MAX_TRANSFER
            or d != d.quantize(Decimal("0.01"))
        ):
            raise ValueError
    except (InvalidOperation, ValueError, AttributeError):
        return False, (
            "Amount must be positive, use at most 2 decimal places, "
            f"and be no more than Rs. {MAX_TRANSFER:,.0f}."
        )
    return True, int(d * 100)


# ---------------------------------------------------------------- C7: CSRF protection

def new_csrf_token():
    return secrets.token_hex(32)


def csrf_token_valid(sent_token, expected_token):
    return secrets.compare_digest(sent_token or "", expected_token or "")


# ---------------------------------------------------------------- C8: account lockout

def is_account_locked(user):
    return user["locked_until"] > time.time()


def next_failed_login_state(user):
    """Calculate the next lockout state; db.py persists the result."""
    n_fail = user["failed_attempts"] + 1
    if n_fail >= MAX_FAILED_LOGINS:
        return 0, time.time() + LOCK_SECONDS
    return n_fail, 0


# ---------------------------------------------------------------- C9: tamper-evident audit log
GENESIS_HASH = "0" * 64


def audit_row_hash(prev_hash, ts, uid, action, detail):
    """Hash the current event together with the previous event's hash."""
    payload = f"{prev_hash}|{ts}|{uid}|{action}|{detail}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def verify_audit_chain(rows):
    """Return None when intact, otherwise return the first tampered row id."""
    prev = GENESIS_HASH
    for row in rows:
        expected = audit_row_hash(
            prev, row["ts"], row["user_id"], row["action"], row["detail"]
        )
        if row["prev_hash"] != prev or row["hash"] != expected:
            return row["id"]
        prev = row["hash"]
    return None


# ---------------------------------------------------------------- C10: session hardening
SESSION_SECURITY_CONFIG = {
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax",
    "PERMANENT_SESSION_LIFETIME": SESSION_IDLE_TIMEOUT,
    "SESSION_REFRESH_EACH_REQUEST": True,
}


def rotate_session(session, user_id):
    """Clear pre-login session data and bind a fresh session to the user."""
    session.clear()
    session.permanent = True
    session["uid"] = user_id
    session["csrf"] = new_csrf_token()


# ---------------------------------------------------------------- C11: security response headers
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "Cache-Control": "no-store",
}


# ---------------------------------------------------------------- C12: step-up authentication

def needs_step_up(amount_paisa):
    return amount_paisa >= int(STEP_UP_THRESHOLD * 100)


def generate_step_up_code():
    """Generate a six-digit demo verification code."""
    return f"{secrets.randbelow(1_000_000):06d}"


def new_step_up_challenge_id():
    """Random identifier stored in the session instead of the verification code itself."""
    return secrets.token_urlsafe(24)


def step_up_code_digest(code, secret_key):
    """Create a server-keyed digest so the raw code need not be stored in the session/database."""
    return hmac.new(
        str(secret_key).encode("utf-8"),
        str(code or "").encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def step_up_code_valid(entered_code, expected_digest, expires_at, secret_key):
    """Validate expiry and compare the keyed digest in constant time."""
    if time.time() > expires_at:
        return False
    actual = step_up_code_digest(entered_code, secret_key)
    return secrets.compare_digest(actual, expected_digest or "")
