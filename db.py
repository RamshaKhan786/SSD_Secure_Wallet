"""
Database layer for the Mini Secure Fintech Wallet.

All SQLite access is kept here.  app.py decides which route/action to run,
controls.py decides security policy, and this module persists the resulting
state.
"""

import sqlite3
from datetime import datetime, timezone
from decimal import Decimal

from flask import current_app, g

import controls

SIGNUP_CREDIT = 1000_00  # Rs. 1,000.00, stored in paisa


def get_db():
    """Return one SQLite connection for the current Flask request."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB"], isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 3000")
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Create the application tables and seed demo users in an empty database."""
    db = sqlite3.connect(app.config["DB"], isolation_level=None)
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 3000")

    balance_check = "balance >= 0" if app.config["SECURE"] else "balance >= 0 OR 1"
    db.executescript(
        f"""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            cnic TEXT UNIQUE NOT NULL,
            balance INTEGER NOT NULL DEFAULT 0 CHECK({balance_check}),
            role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','admin')),
            failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts >= 0),
            locked_until REAL NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER,
            amount INTEGER NOT NULL CHECK(amount > 0),
            status TEXT NOT NULL CHECK(status IN ('SUCCESS','FAILED')),
            created_at TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            user_id INTEGER,
            action TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS step_up_challenges(
            challenge_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            recipient_username TEXT NOT NULL,
            amount_paisa INTEGER NOT NULL CHECK(amount_paisa > 0),
            code_digest TEXT NOT NULL,
            expires_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS beneficiaries(
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            beneficiary_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, beneficiary_user_id),
            CHECK(user_id != beneficiary_user_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(beneficiary_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_transactions_sender ON transactions(sender_id);
        CREATE INDEX IF NOT EXISTS idx_transactions_receiver ON transactions(receiver_id);
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_step_up_user ON step_up_challenges(user_id);
        CREATE INDEX IF NOT EXISTS idx_beneficiaries_user ON beneficiaries(user_id);
        CREATE INDEX IF NOT EXISTS idx_beneficiaries_target ON beneficiaries(beneficiary_user_id);
        """
    )

    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        secure = app.config["SECURE"]
        demo_users = [
            ("ali", "Ali@12345", "Ali Khan", "ali@gmail.com", "12345-1234567-1", 50000_00, "customer"),
            ("sara", "Sara@12345", "Sara Ahmed", "sara@gmail.com", "12345-7654321-2", 10000_00, "customer"),
            ("admin", "Admin@12345", "Auditor", "admin@gmail.com", "12345-0000000-9", 0, "admin")
        ]
    for username, password, full_name, email, cnic, balance, role in demo_users:
        stored_password = controls.hash_password(password) if secure else password
        stored_cnic = controls.encrypt_cnic(cnic, app.config["SECRET_KEY"]) if secure else cnic
        db.execute(
            "INSERT INTO users(username,password,full_name,email,cnic,balance,role) VALUES(?,?,?,?,?,?,?)",
            (username, stored_password, full_name, email, stored_cnic, balance, role),
    )
    db.close()


# ---------------------------------------------------------------- passwords

def store_password(password):
    """Use hashing in secure mode; plaintext is deliberately retained only for the lab's vulnerable mode."""
    return controls.hash_password(password) if current_app.config["SECURE"] else password


# ---------------------------------------------------------------- timestamps / audit log

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def audit(db, uid, action, detail=""):
    """Append one tamper-evident event to the audit chain in secure mode."""
    if not current_app.config["SECURE"]:
        return

    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else controls.GENESIS_HASH
    ts = now()
    h = controls.audit_row_hash(prev, ts, uid, action, detail)
    db.execute(
        "INSERT INTO audit_log(ts,user_id,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)",
        (ts, uid, action, detail, prev, h),
    )


def verify_audit(db):
    rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    return controls.verify_audit_chain(rows)


def get_audit_rows(db, limit=100):
    return db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()


# ---------------------------------------------------------------- users

def get_user_by_id(db, uid):
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def get_user_by_username(db, username):
    return db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def get_user_by_credentials_unsafe(db, username, password):
    """VULNERABLE DEMO ONLY: intentionally injectable login query."""
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query).fetchone()


def create_user(db, username, password, full_name, email, cnic):
    stored_cnic = controls.encrypt_cnic(cnic, current_app.config["SECRET_KEY"]) \
        if current_app.config["SECURE"] else cnic
    db.execute(
        "INSERT INTO users(username,password,full_name,email,cnic,balance) VALUES(?,?,?,?,?,?)",
        (username, store_password(password), full_name, email, stored_cnic, SIGNUP_CREDIT),
    )
    audit(db, None, "REGISTER", username)


def mark_login_success(db, uid):
    db.execute(
        "UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (uid,)
    )


def mark_login_failure(db, user):
    attempt_number = user["failed_attempts"] + 1
    failed_attempts, locked_until = controls.next_failed_login_state(user)
    db.execute(
        "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
        (failed_attempts, locked_until, user["id"]),
    )
    audit(db, user["id"], "LOGIN_FAILED", f"attempt {attempt_number}")


def get_other_demo_user(db, me):
    """Select another customer solely for the Security Lab's demonstration requests."""
    row = db.execute(
        "SELECT id, username, full_name, role FROM users "
        "WHERE role='customer' AND id != ? ORDER BY id LIMIT 1",
        (me["id"],),
    ).fetchone()
    return row or me


def get_customer_by_username(db, username):
    return db.execute(
        "SELECT id, username, full_name, role FROM users "
        "WHERE username=? AND role='customer'",
        (username,),
    ).fetchone()


# ---------------------------------------------------------------- beneficiaries

def get_beneficiaries(db, user_id):
    """Return all beneficiaries owned by the authenticated user."""
    return db.execute(
        """
        SELECT b.id, b.beneficiary_user_id, u.username, u.full_name, b.created_at
        FROM beneficiaries b
        JOIN users u ON u.id = b.beneficiary_user_id
        WHERE b.user_id=? AND u.role='customer'
        ORDER BY b.id DESC
        """,
        (user_id,),
    ).fetchall()


def add_beneficiary(db, user_id, beneficiary_username):
    """Add a registered customer as a beneficiary for the current user."""
    beneficiary = get_customer_by_username(db, beneficiary_username)
    if not beneficiary:
        return False, "Beneficiary not found."
    if beneficiary["id"] == user_id:
        return False, "You cannot add yourself as a beneficiary."

    try:
        db.execute(
            "INSERT INTO beneficiaries(user_id, beneficiary_user_id, created_at) VALUES(?,?,?)",
            (user_id, beneficiary["id"], now()),
        )
    except sqlite3.IntegrityError:
        return False, "Beneficiary already exists."

    audit(db, user_id, "BENEFICIARY_ADDED", f"beneficiary={beneficiary['id']}")
    return True, "Beneficiary added."


def remove_beneficiary(db, user_id, beneficiary_id):
    """Remove only a beneficiary record owned by the current user."""
    row = db.execute(
        "SELECT id, beneficiary_user_id FROM beneficiaries WHERE id=? AND user_id=?",
        (beneficiary_id, user_id),
    ).fetchone()
    if not row:
        return False, "Beneficiary not found."

    db.execute(
        "DELETE FROM beneficiaries WHERE id=? AND user_id=?",
        (beneficiary_id, user_id),
    )
    audit(db, user_id, "BENEFICIARY_REMOVED", f"beneficiary={row['beneficiary_user_id']}")
    return True, "Beneficiary removed."


# ---------------------------------------------------------------- transfers

def do_transfer(db, sender, to_username, amount_str, step_up_verified=False):
    """Perform a secure atomic transfer, or the intentionally weak demo transfer in vulnerable mode."""
    if not current_app.config["SECURE"]:
        # VULN: no positive-amount check, no overdraft prevention, no step-up,
        # and no atomic transaction. This path exists only for before/after tests.
        amt = int(Decimal(amount_str) * 100)
        rcv = db.execute(
            "SELECT id FROM users WHERE username=?", (to_username,)
        ).fetchone()
        db.execute(
            "UPDATE users SET balance=balance-? WHERE id=?", (amt, sender["id"])
        )
        if rcv:
            db.execute(
                "UPDATE users SET balance=balance+? WHERE id=?", (amt, rcv["id"])
            )
        db.execute(
            "INSERT INTO transactions(sender_id,receiver_id,amount,status,created_at) VALUES(?,?,?,?,?)",
            (sender["id"], rcv["id"] if rcv else None, abs(amt), "SUCCESS", now()),
        )
        return True, "Transfer complete."

    ok, amt_or_msg = controls.validate_transfer_amount(amount_str)
    if not ok:
        return False, amt_or_msg
    amt = amt_or_msg

    recipient_ok, recipient_msg = controls.validate_transfer_recipient(to_username)
    if not recipient_ok:
        return False, recipient_msg

    rcv = get_customer_by_username(db, to_username)
    if not rcv or rcv["id"] == sender["id"]:
        return False, "Invalid recipient."

    if controls.needs_step_up(amt) and not step_up_verified:
        audit(
            db,
            sender["id"],
            "STEP_UP_BYPASS_BLOCKED",
            f"to={rcv['id']} amt={amt}",
        )
        return False, "High-value transfers require step-up verification."

    db.execute("BEGIN IMMEDIATE")
    try:
        # Re-check the balance under the write lock, preventing overdrafts and
        # double-spend races between concurrent requests.
        cur = db.execute(
            "UPDATE users SET balance=balance-? WHERE id=? AND balance>=?",
            (amt, sender["id"], amt),
        )
        if cur.rowcount == 0:
            db.execute(
                "INSERT INTO transactions(sender_id,receiver_id,amount,status,created_at) VALUES(?,?,?,?,?)",
                (sender["id"], rcv["id"], amt, "FAILED", now()),
            )
            audit(
                db,
                sender["id"],
                "TRANSFER_FAILED",
                f"to={rcv['id']} amt={amt} insufficient funds",
            )
            db.execute("COMMIT")
            return False, "Insufficient funds."

        db.execute(
            "UPDATE users SET balance=balance+? WHERE id=?",
            (amt, rcv["id"]),
        )
        db.execute(
            "INSERT INTO transactions(sender_id,receiver_id,amount,status,created_at) VALUES(?,?,?,?,?)",
            (sender["id"], rcv["id"], amt, "SUCCESS", now()),
        )
        audit(db, sender["id"], "TRANSFER", f"to={rcv['id']} amt={amt}")
        db.execute("COMMIT")
        return True, "Transfer complete."
    except Exception:
        db.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------- step-up challenge storage

def delete_user_step_up_challenges(db, user_id):
    db.execute("DELETE FROM step_up_challenges WHERE user_id=?", (user_id,))


def create_step_up_challenge(
    db, challenge_id, user_id, recipient_username, amount_paisa, code_digest, expires_at
):
    delete_user_step_up_challenges(db, user_id)
    db.execute(
        "INSERT INTO step_up_challenges(" \
        "challenge_id,user_id,recipient_username,amount_paisa,code_digest,expires_at,attempts,created_at) " \
        "VALUES(?,?,?,?,?,?,0,?)",
        (
            challenge_id,
            user_id,
            recipient_username,
            amount_paisa,
            code_digest,
            expires_at,
            now(),
        ),
    )


def get_step_up_challenge(db, challenge_id, user_id):
    return db.execute(
        "SELECT * FROM step_up_challenges WHERE challenge_id=? AND user_id=?",
        (challenge_id, user_id),
    ).fetchone()


def increment_step_up_attempts(db, challenge_id):
    db.execute(
        "UPDATE step_up_challenges SET attempts=attempts+1 WHERE challenge_id=?",
        (challenge_id,),
    )
    return db.execute(
        "SELECT attempts FROM step_up_challenges WHERE challenge_id=?",
        (challenge_id,),
    ).fetchone()["attempts"]


def delete_step_up_challenge(db, challenge_id):
    db.execute(
        "DELETE FROM step_up_challenges WHERE challenge_id=?", (challenge_id,)
    )


# ---------------------------------------------------------------- history

def get_history(db, uid):
    return db.execute(
        """
        SELECT t.*, s.username AS sname, r.username AS rname
        FROM transactions t
        JOIN users s ON s.id=t.sender_id
        LEFT JOIN users r ON r.id=t.receiver_id
        WHERE t.sender_id=? OR t.receiver_id=?
        ORDER BY t.id DESC
        """,
        (uid, uid),
    ).fetchall()
