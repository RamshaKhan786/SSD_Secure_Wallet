"""
db.py — All database access for the Mini Secure Fintech Wallet.

Every sqlite3 query lives in this file. app.py never writes raw SQL — it
only calls the functions defined here. Policy DECISIONS (password hashing
algorithm, lockout thresholds, validation rules, audit hash chain, CSRF,
headers, authorization) live in controls.py; this file only PERSISTS their
results. See controls.py's docstring for the full control index (C1-C10).
"""
import sqlite3
from datetime import datetime, timezone
from decimal import Decimal
from flask import g, current_app

import controls

SIGNUP_CREDIT = 1000_00  # demo starting balance, in paisa (not a security control)


# ---------------------------------------------------------------- connection
def get_db():
    """One SQLite connection per request, cached on Flask's `g`."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB"], isolation_level=None)  # manual txns
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db(app):
    """Create tables and seed demo users. Called once at startup, outside a request."""
    db = sqlite3.connect(app.config["DB"], isolation_level=None)
    db.executescript("""
   CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    full_name TEXT, email TEXT UNIQUE NOT NULL, cnic TEXT UNIQUE NOT NULL,
    balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0 OR %s),
    role TEXT NOT NULL DEFAULT 'customer',
    failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER,
        amount INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY, ts TEXT, user_id INTEGER, action TEXT, detail TEXT,
        prev_hash TEXT, hash TEXT);
    
    CREATE TABLE IF NOT EXISTS beneficiaries(
        id INTEGER PRIMARY KEY,
        owner_id INTEGER NOT NULL,
        beneficiary_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(owner_id, beneficiary_id),
        FOREIGN KEY(owner_id) REFERENCES users(id),
        FOREIGN KEY(beneficiary_id) REFERENCES users(id)
    );
""" % ("0" if app.config["SECURE"] else "1"))
    if not db.execute("SELECT 1 FROM users").fetchone():
        secure = app.config["SECURE"]
        for u, p, n, b, r in [("ali", "Ali@12345", "Ali Khan", 50000_00, "customer"),
                               ("sara", "Sara@12345", "Sara Ahmed", 10000_00, "customer"),
                               ("admin", "Admin@12345", "Auditor", 0, "admin")]:
            pw = controls.hash_password(p) if secure else p  # C1
            db.execute("INSERT INTO users(username,password,full_name,balance,role) VALUES(?,?,?,?,?)",
                       (u, pw, n, b, r))
    db.close()


# ---------------------------------------------------------------- passwords
def store_password(pw):
    # C1: applied only when secure mode is on; VULN mode stores plaintext for the demo.
    return controls.hash_password(pw) if current_app.config["SECURE"] else pw


# ---------------------------------------------------------------- audit log (C7)
def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def audit(db, uid, action, detail=""):
    """Append-only log; each row's hash covers the previous row (C7) => tampering is detectable."""
    if not current_app.config["SECURE"]:
        return  # VULN: nothing is recorded
    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else controls.GENESIS_HASH
    ts = now()
    h = controls.audit_row_hash(prev, ts, uid, action, detail)
    db.execute("INSERT INTO audit_log(ts,user_id,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)",
               (ts, uid, action, detail, prev, h))


def verify_audit(db):
    """Returns None if the audit chain is intact, else the id of the first bad row."""
    rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    return controls.verify_audit_chain(rows)


def get_audit_rows(db, limit=100):
    return db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


# ---------------------------------------------------------------- users
def get_user_by_id(db, uid):
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def get_user_by_username(db, username):
    return db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def get_user_by_credentials_unsafe(db, username, password):
    # VULN: string-built SQL (injectable) + plaintext password comparison.
    # Only reachable when app.config["SECURE"] is False (vulnerable demo mode).
    # This is the deliberate exception to control C2 (parameterized queries).
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query).fetchone()


def create_user(db, username, password, full_name, email, cnic):
    """Raises sqlite3.IntegrityError if the username, email, or CNIC is already taken."""
    db.execute(
        "INSERT INTO users(username,password,full_name,email,cnic,balance) VALUES(?,?,?,?,?,?)",
        (username, store_password(password), full_name, email, cnic, SIGNUP_CREDIT)
    )
    audit(db, None, "REGISTER", username)


def mark_login_success(db, uid):
    db.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (uid,))


def mark_login_failure(db, user):
    """C6: persists the lockout state that controls.next_failed_login_state() decided."""
    attempt_number = user["failed_attempts"] + 1
    failed_attempts, locked_until = controls.next_failed_login_state(user)
    db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
               (failed_attempts, locked_until, user["id"]))
    audit(db, user["id"], "LOGIN_FAILED", f"attempt {attempt_number}")


def get_other_demo_user(db, me):
    """Any other customer account, used only to target the Security Lab demo attacks."""
    row = db.execute(
        "SELECT * FROM users WHERE role='customer' AND id != ? ORDER BY id LIMIT 1", (me["id"],)
    ).fetchone()
    return row or me


# ---------------------------------------------------------------- transfers
def do_transfer(db, sender, to_username, amount_str, step_up_verified=False):
    """Returns (ok, message).

    step_up_verified must be True only when the caller has already checked a
    valid step-up code (see /api/transfer/confirm in app.py). It defaults to
    False so any other caller is safe automatically.
    """
    if not current_app.config["SECURE"]:
        # VULN: no validation, no atomicity, no ownership/overdraft checks
        amt = int(Decimal(amount_str) * 100)
        rcv = db.execute("SELECT id FROM users WHERE username=?", (to_username,)).fetchone()
        db.execute("UPDATE users SET balance=balance-? WHERE id=?", (amt, sender["id"]))
        if rcv:
            db.execute("UPDATE users SET balance=balance+? WHERE id=?", (amt, rcv["id"]))
        db.execute("INSERT INTO transactions(sender_id,receiver_id,amount,status,created_at) VALUES(?,?,?,?,?)",
                   (sender["id"], rcv["id"] if rcv else None, amt, "SUCCESS", now()))
        return True, "Transfer complete."

    # C5: server-side input validation
    ok, amt_or_msg = controls.validate_transfer_amount(amount_str)
    if not ok:
        return False, amt_or_msg
    amt = amt_or_msg

    # Recipient must be a different, registered customer
    rcv = db.execute("SELECT id FROM users WHERE username=? AND role='customer'", (to_username,)).fetchone()
    if not rcv or rcv["id"] == sender["id"]:
        return False, "Invalid recipient."

    # C11: high-value transfers can only proceed after a verified step-up code.
    # Enforced here, at the point where money moves, so no route can bypass it.
    if controls.needs_step_up(amt) and not step_up_verified:
        audit(db, sender["id"], "STEP_UP_BYPASS_BLOCKED", f"to={rcv['id']} amt={amt}")
        return False, "High-value transfers require step-up verification."

    # C12: all-or-nothing transfer; the write lock prevents double-spend races
    db.execute("BEGIN IMMEDIATE")
    try:
        cur = db.execute("UPDATE users SET balance=balance-? WHERE id=? AND balance>=?",
                         (amt, sender["id"], amt))          # balance re-checked inside the txn
        if cur.rowcount == 0:
            db.execute("INSERT INTO transactions(sender_id,receiver_id,amount,status,created_at) VALUES(?,?,?,?,?)",
                       (sender["id"], rcv["id"], amt, "FAILED", now()))
            audit(db, sender["id"], "TRANSFER_FAILED", f"to={rcv['id']} amt={amt} insufficient funds")
            db.execute("COMMIT")
            return False, "Insufficient funds."
        db.execute("UPDATE users SET balance=balance+? WHERE id=?", (amt, rcv["id"]))
        db.execute("INSERT INTO transactions(sender_id,receiver_id,amount,status,created_at) VALUES(?,?,?,?,?)",
                   (sender["id"], rcv["id"], amt, "SUCCESS", now()))
        audit(db, sender["id"], "TRANSFER", f"to={rcv['id']} amt={amt}")
        db.execute("COMMIT")
        return True, "Transfer complete."
    except Exception:
        db.execute("ROLLBACK")
        raise


def get_history(db, uid):
    return db.execute("""SELECT t.*, s.username AS sname, r.username AS rname FROM transactions t
        LEFT JOIN users s ON s.id=t.sender_id LEFT JOIN users r ON r.id=t.receiver_id
        WHERE t.sender_id=? OR t.receiver_id=? ORDER BY t.id DESC""", (uid, uid)).fetchall()


# ---------------------------------------------------------------- beneficiaries

def add_beneficiary(db, owner_id, beneficiary_username):
    """
    Add a registered customer as a beneficiary for the logged-in user.
    Returns (True, message) on success or (False, message) on failure.
    """
    beneficiary = db.execute(
        "SELECT id, username, full_name, role FROM users WHERE username=?",
        (beneficiary_username,)
    ).fetchone()

    if not beneficiary:
        return False, "Beneficiary does not exist."

    if beneficiary["id"] == owner_id:
        return False, "You cannot add yourself as a beneficiary."

    if beneficiary["role"] != "customer":
        return False, "This account cannot be added as a beneficiary."

    existing = db.execute(
        "SELECT id FROM beneficiaries WHERE owner_id=? AND beneficiary_id=?",
        (owner_id, beneficiary["id"])
    ).fetchone()

    if existing:
        return False, "This beneficiary has already been added."

    db.execute(
        """
        INSERT INTO beneficiaries(owner_id, beneficiary_id, created_at)
        VALUES(?,?,?)
        """,
        (owner_id, beneficiary["id"], now())
    )

    audit(
        db,
        owner_id,
        "BENEFICIARY_ADDED",
        f"beneficiary={beneficiary['username']}"
    )

    return True, f"{beneficiary['username']} added as beneficiary."


def get_beneficiaries(db, owner_id):
    """Return only beneficiaries belonging to the logged-in user."""
    return db.execute(
        """
        SELECT
            b.id,
            u.id AS user_id,
            u.username,
            u.full_name,
            b.created_at
        FROM beneficiaries b
        JOIN users u ON u.id = b.beneficiary_id
        WHERE b.owner_id=?
        ORDER BY b.id DESC
        """,
        (owner_id,)
    ).fetchall()


def remove_beneficiary(db, owner_id, beneficiary_id):
    """Remove a beneficiary only if it belongs to the logged-in user."""
    cur = db.execute(
        """
        DELETE FROM beneficiaries
        WHERE owner_id=? AND beneficiary_id=?
        """,
        (owner_id, beneficiary_id)
    )

    if cur.rowcount == 0:
        return False, "Beneficiary not found."

    audit(
        db,
        owner_id,
        "BENEFICIARY_REMOVED",
        f"beneficiary_id={beneficiary_id}"
    )

    return True, "Beneficiary removed."
