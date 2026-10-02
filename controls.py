"""
Security-control policy for the Mini Secure Fintech Wallet.

The assignment asks us to identify weaknesses and then choose controls that
reduce the corresponding risks.  This file keeps the security decisions in
one place; db.py is responsible for persisting the results.

Control map
-----------
C1  Password hashing
C2  Parameterized SQL (implemented throughout db.py)
C3  Authentication / login protection (implemented in app.py login())
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
C14 CNIC encryption and masking
C15 Rate limiting
"""

import hashlib
import hmac
import re
import secrets
import time
from decimal import Decimal, InvalidOperation
from cryptography.fernet import Fernet, InvalidToken
import base64
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
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CNIC_PATTERN = re.compile(r"^\d{5}-\d{7}-\d{1}$")
PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$")


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


# ---------------------------------------------------------------- C6: server-side input validation

def validate_registration(username, password, full_name, email, cnic):
    if not USERNAME_PATTERN.fullmatch(username):
        return False, "Username: 3-20 chars [a-z0-9_]."
    if not full_name or len(full_name) > MAX_FULL_NAME_LEN:
        return False, f"Full name is required and must be at most {MAX_FULL_NAME_LEN} characters."
    if not PASSWORD_PATTERN.fullmatch(password):
        return False, "Password must be 8+ chars with upper, lower, digit, and special char."
    if not EMAIL_PATTERN.fullmatch(email):
        return False, "Enter a valid email address."
    if not CNIC_PATTERN.fullmatch(cnic):
        return False, "CNIC must be in the format 12345-1234567-1."
    return True, None


def validate_transfer_recipient(username):
    """Validate a recipient identifier before it is used by the transfer logic."""
    username = (username or "").strip()
    if not USERNAME_PATTERN.fullmatch(username):
        return False, "Recipient username is invalid."
    return True, None


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


# ---------------------------------------------------------------- C13: beneficiary validation and ownership
# Ownership itself is enforced in db.py (queries filter by user_id).

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


# ---------------------------------------------------------------- C14: CNIC encryption and masking

def _fernet_key_from_secret(secret_key):
    """Derive a valid 32-byte urlsafe-base64 Fernet key from the app's SECRET_KEY,
    so we don't need to manage a second separate secret."""
    digest = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_cnic(cnic, secret_key):
    f = Fernet(_fernet_key_from_secret(secret_key))
    return f.encrypt(cnic.encode()).decode()


def decrypt_cnic(encrypted_cnic, secret_key):
    f = Fernet(_fernet_key_from_secret(secret_key))
    try:
        return f.decrypt(encrypted_cnic.encode()).decode()
    except InvalidToken:
        return None


def mask_cnic(cnic):
    """12345-1234567-1 -> ***********67-1 (only the last 4 characters shown)."""
    if not cnic or len(cnic) < 4:
        return "****"
    return "*" * (len(cnic) - 4) + cnic[-4:]


# ---------------------------------------------------------------- C15: rate limiting
# Fixed-window counters stored in the rate_limits table (see db.hit_rate_limit).
# Each request increments bucket "<name>:<identifier>" for the current window;
# once max_hits is reached, further requests get HTTP 429 until the window ends.

# bucket_name: (max_hits, window_seconds)
RATE_LIMITS = {
    "login_ip":         (20, 300),   # 20 login tries / 5 min / IP
    "login_account":    (10, 300),   # 10 login tries / 5 min / username
    "register_ip":      (5, 3600),   # 5 signups / hour / IP
    "transfer_user":    (5, 60),     # 5 transfer attempts / min / user
    "beneficiary_user": (10, 60),    # 10 beneficiary writes / min / user
    "stepup_user":      (6, 300),    # 6 step-up confirmations / 5 min / user
}


def rate_limit_policy(bucket_name):
    """Return (max_hits, window_seconds) for a bucket, or (None, None) if unknown."""
    return RATE_LIMITS.get(bucket_name, (None, None))


def bucket_key(name, identifier):
    """Compose a stable bucket key: 'login_ip:1.2.3.4'."""
    return f"{name}:{identifier}"