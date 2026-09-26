"""
Mini Secure Fintech Wallet  (Flask + SQLite)

GUI/backend separation:
  - This file (app.py) holds ONLY core functionality: database access,
    authentication, transfer/business logic, audit logging, and routing.
  - All presentation lives in templates/ (Jinja2 HTML) and static/ (CSS/JS).

Two modes, switched by env var WALLET_MODE (or app.config["SECURE"]):
  secure      (default) - all security controls ON
  vulnerable            - controls OFF, used ONLY for the before/after demo.
                          Every intentionally weak spot is marked  # VULN.

Run:  pip install -r requirements.txt && python app.py
"""
import os, re, sqlite3, hashlib, secrets, time
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from functools import wraps
from flask import (Flask, request, session, redirect, render_template,
                    g, jsonify, flash, abort)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    DB=os.environ.get("WALLET_DB", "wallet.db"),
    SECURE=os.environ.get("WALLET_MODE", "secure") != "vulnerable",
    SECRET_KEY=os.environ.get("WALLET_SECRET") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,          # C8: JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",         # C5: cookie not sent on cross-site POSTs
    SESSION_COOKIE_SECURE=bool(os.environ.get("WALLET_HTTPS")),  # set when behind TLS
    PERMANENT_SESSION_LIFETIME=1000,        # C8: session timeout
)
MAX_TRANSFER = Decimal("100000")   # per-transaction limit (Rs.)
MAX_FAILED, LOCK_SECONDS = 5, 300  # C6: lockout policy
SIGNUP_CREDIT = 1000_00            # demo credit in paisa


@app.context_processor
def inject_globals():
    # Makes {{ secure }} available in every template without passing it explicitly.
    return {"secure": app.config["SECURE"]}


# ---------------------------------------------------------------- database -------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB"], isolation_level=None)  # manual txns
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def store_password(pw):
    # C1: salted, slow hash.  VULN: plaintext in vulnerable mode.
    return generate_password_hash(pw) if app.config["SECURE"] else pw


def init_db():
    db = sqlite3.connect(app.config["DB"], isolation_level=None)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
        full_name TEXT, balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0 OR %s),
        role TEXT NOT NULL DEFAULT 'customer',
        failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER,
        amount INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY, ts TEXT, user_id INTEGER, action TEXT, detail TEXT,
        prev_hash TEXT, hash TEXT);
    """ % ("0" if app.config["SECURE"] else "1"))
    if not db.execute("SELECT 1 FROM users").fetchone():
        for u, p, n, b, r in [("ali", "Ali@12345", "Ali Khan", 50000_00, "customer"),
                               ("sara", "Sara@12345", "Sara Ahmed", 10000_00, "customer"),
                               ("admin", "Admin@12345", "Auditor", 0, "admin")]:
            db.execute("INSERT INTO users(username,password,full_name,balance,role) VALUES(?,?,?,?,?)",
                       (u, store_password(p), n, b, r))
    db.close()


# ---------------------------------------------------------------- audit log (C7) ---------------------------------------
def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def audit(db, uid, action, detail=""):
    """Append-only log; each row's hash covers the previous row => tampering is detectable."""
    if not app.config["SECURE"]:
        return  # VULN: nothing is recorded
    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else "0" * 64
    ts = now()
    h = hashlib.sha256(f"{prev}|{ts}|{uid}|{action}|{detail}".encode()).hexdigest()
    db.execute("INSERT INTO audit_log(ts,user_id,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)",
               (ts, uid, action, detail, prev, h))


def verify_audit(db):
    """Returns None if chain intact, else the id of the first bad row."""
    prev = "0" * 64
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        exp = hashlib.sha256(f"{prev}|{r['ts']}|{r['user_id']}|{r['action']}|{r['detail']}".encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != exp:
            return r["id"]
        prev = r["hash"]
    return None


# ---------------------------------------------------------------- helpers / guards
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            return redirect("/login")
        return f(*a, **k)
    return w


def current_user():
    return get_db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()


def other_demo_user(me):
    """Any other customer account, used only to target the Security Lab demo attacks."""
    row = get_db().execute(
        "SELECT * FROM users WHERE role='customer' AND id != ? ORDER BY id LIMIT 1", (me["id"],)
    ).fetchone()
    return row or me


@app.before_request
def csrf_protect():
    # C5: every state-changing request from a logged-in user needs the per-session token
    if app.config["SECURE"] and request.method == "POST" and "uid" in session:
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(sent, session.get("csrf", "")):
            audit(get_db(), session["uid"], "CSRF_REJECTED", request.path)
            abort(400, "Invalid CSRF token")


@app.after_request
def headers(r):
    if app.config["SECURE"]:   # C9: reduce browser-side exposure
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["X-Frame-Options"] = "DENY"
        r.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; frame-ancestors 'none'"
        )
        r.headers["Cache-Control"] = "no-store"
    return r


@app.errorhandler(500)
def err500(_):  # C9: no stack traces / internals leaked to the user
    return "Something went wrong.", 500


# ---------------------------------------------------------------- transfer logic
def do_transfer(db, sender, to_username, amount_str):
    """Returns (ok, message)."""
    if not app.config["SECURE"]:
        # VULN: no validation, no atomicity, no ownership/overdraft checks
        amt = int(Decimal(amount_str) * 100)
        rcv = db.execute("SELECT id FROM users WHERE username=?", (to_username,)).fetchone()
        db.execute("UPDATE users SET balance=balance-? WHERE id=?", (amt, sender["id"]))
        if rcv:
            db.execute("UPDATE users SET balance=balance+? WHERE id=?", (amt, rcv["id"]))
        db.execute("INSERT INTO transactions(sender_id,receiver_id,amount,status,created_at) VALUES(?,?,?,?,?)",
                   (sender["id"], rcv["id"] if rcv else None, amt, "SUCCESS", now()))
        return True, "Transfer complete."

    # C4: strict input validation (server-side)
    try:
        d = Decimal(amount_str.strip())
        if not d.is_finite() or d <= 0 or d > MAX_TRANSFER or d != d.quantize(Decimal("0.01")):
            raise ValueError
    except (InvalidOperation, ValueError, AttributeError):
        return False, f"Amount must be a positive number (max 2 decimals, up to Rs. {MAX_TRANSFER:,})."
    amt = int(d * 100)
    rcv = db.execute("SELECT id FROM users WHERE username=? AND role='customer'", (to_username,)).fetchone()
    if not rcv or rcv["id"] == sender["id"]:
        return False, "Invalid recipient."

    # C4: atomic transfer - all-or-nothing, write lock prevents double-spend races
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


def history(db, uid):
    return db.execute("""SELECT t.*, s.username AS sname, r.username AS rname FROM transactions t
        LEFT JOIN users s ON s.id=t.sender_id LEFT JOIN users r ON r.id=t.receiver_id
        WHERE t.sender_id=? OR t.receiver_id=? ORDER BY t.id DESC""", (uid, uid)).fetchall()


# ---------------------------------------------------------------- page routes
@app.route("/")
def index():
    return redirect("/dashboard" if "uid" in session else "/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p, n = (request.form.get(k, "").strip() for k in ("username", "password", "full_name"))
        if app.config["SECURE"] and (not re.fullmatch(r"[a-z0-9_]{3,20}", u) or len(p) < 8):
            flash("Username: 3-20 chars [a-z0-9_]. Password: min 8 characters.")
        else:
            try:
                db = get_db()
                db.execute("INSERT INTO users(username,password,full_name,balance) VALUES(?,?,?,?)",
                           (u, store_password(p), n[:60], SIGNUP_CREDIT))
                audit(db, None, "REGISTER", u)
                flash("Account created. Please log in.")
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("Username unavailable.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("username", ""), request.form.get("password", "")
        db, user = get_db(), None
        if not app.config["SECURE"]:
            # VULN: string-built SQL (injectable) + plaintext password comparison
            user = db.execute(f"SELECT * FROM users WHERE username='{u}' AND password='{p}'").fetchone()
        else:
            row = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()  # C2: parameterised
            if row and row["locked_until"] > time.time():                              # C6: lockout
                audit(db, row["id"], "LOGIN_BLOCKED_LOCKED", "")
            elif row and check_password_hash(row["password"], p):
                db.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (row["id"],))
                user = row
            elif row:
                n_fail = row["failed_attempts"] + 1
                lock = time.time() + LOCK_SECONDS if n_fail >= MAX_FAILED else 0
                db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                           (0 if lock else n_fail, lock, row["id"]))
                audit(db, row["id"], "LOGIN_FAILED", f"attempt {n_fail}")
        if user:
            session.clear()                       # C8: new session on login (anti-fixation)
            session.permanent = True
            session["uid"], session["csrf"] = user["id"], secrets.token_hex(16)
            audit(db, user["id"], "LOGIN_OK", "")
            return redirect("/dashboard")
        flash("Invalid credentials or account temporarily locked.")  # C3: generic message
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    me = current_user()
    other = other_demo_user(me)
    return render_template(
        "dashboard.html",
        user=me,
        other_user=other,
        csrf=session["csrf"],
        is_admin=(me["role"] == "admin"),
    )


@app.route("/api/transfer", methods=["POST"])
@login_required
def api_transfer():
    d = request.get_json(silent=True) or {}
    ok, msg = do_transfer(get_db(), current_user(), str(d.get("to", "")), str(d.get("amount", "")))
    return jsonify(ok=ok, message=msg), (200 if ok else 400)


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    ok, msg = do_transfer(get_db(), current_user(), request.form.get("to", ""), request.form.get("amount", ""))
    flash(msg)
    return redirect("/dashboard")


@app.route("/logout", methods=["POST"])
def logout():
    if "uid" in session:
        audit(get_db(), session["uid"], "LOGOUT", "")
    session.clear()
    return redirect("/login")


# ---- JSON API (used to demonstrate broken access control) -------------------
def authorize_owner(uid):
    # C3: object-level authorisation - you may only read YOUR OWN wallet
    if app.config["SECURE"] and uid != session["uid"]:
        audit(get_db(), session["uid"], "ACCESS_DENIED", f"tried wallet {uid}")
        abort(403)


@app.route("/api/wallet/<int:uid>/balance")
@login_required
def api_balance(uid):
    authorize_owner(uid)   # VULN when removed/disabled: any user can read any balance
    r = get_db().execute("SELECT username,balance FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify(username=r["username"], balance=r["balance"]) if r else abort(404)


@app.route("/api/wallet/<int:uid>/transactions")
@login_required
def api_txs(uid):
    authorize_owner(uid)
    return jsonify([dict(t) for t in history(get_db(), uid)])


# ---- privileged operation: audit log (admin only) ---------------------------
@app.route("/admin/audit")
@login_required
def admin_audit():
    db = get_db()
    if app.config["SECURE"] and current_user()["role"] != "admin":   # C10: role separation
        audit(db, session["uid"], "ACCESS_DENIED", "/admin/audit")
        abort(403)
    bad = verify_audit(db)
    rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("admin_audit.html", bad=bad, rows=rows)


if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=int(os.environ.get("WALLET_PORT", "5001")))   # never debug=True: exposes an interactive shell
