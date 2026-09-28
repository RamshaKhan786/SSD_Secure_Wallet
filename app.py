"""
Mini Secure Fintech Wallet  (Flask + SQLite)

File split:
  - app.py       -> ONLY routing/HTTP: URL handlers, session wiring, and
                     wiring controls into the request lifecycle (before/after
                     request hooks). No raw SQL, no control policy logic.
  - db.py        -> ALL database access (connections, queries, transfer
                     persistence, audit log storage).
  - controls.py  -> ALL security control policy/algorithms (C1-C10). See its
                     docstring for the full control index.
  - templates/, static/ -> presentation (Jinja2 HTML, CSS, JS).

Two modes, switched by env var WALLET_MODE (or app.config["SECURE"]):
  secure      (default) - all security controls ON
  vulnerable            - controls OFF, used ONLY for the before/after demo.
                          Every intentionally weak spot is marked  # VULN.

Run:  pip install -r requirements.txt && python app.py
"""
import os
import sqlite3
import secrets
from functools import wraps
from flask import Flask, request, session, redirect, render_template, jsonify, flash, abort

import db as wallet_db
import controls

app = Flask(__name__)
app.config.update(
    DB=os.environ.get("WALLET_DB", "wallet.db"),
    SECURE=os.environ.get("WALLET_MODE", "secure") != "vulnerable",
    SECRET_KEY=os.environ.get("WALLET_SECRET") or secrets.token_hex(32),
    SESSION_COOKIE_SECURE=bool(os.environ.get("WALLET_HTTPS")),  # set when behind TLS
    **controls.SESSION_SECURITY_CONFIG,  # C8: httponly/samesite/lifetime cookie policy
)

app.teardown_appcontext(wallet_db.close_db)


@app.context_processor
def inject_globals():
    # Makes {{ secure }} available in every template without passing it explicitly.
    return {"secure": app.config["SECURE"]}


# ---------------------------------------------------------------- helpers / guards
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            return redirect("/login")
        return f(*a, **k)
    return w


def current_user():
    return wallet_db.get_user_by_id(wallet_db.get_db(), session["uid"])


def authorize_owner(uid):
    # C3: object-level authorisation - you may only read YOUR OWN wallet
    if app.config["SECURE"] and not controls.is_owner(session["uid"], uid):
        wallet_db.audit(wallet_db.get_db(), session["uid"], "ACCESS_DENIED", f"tried wallet {uid}")
        abort(403)


@app.before_request
def csrf_protect():
    # C5: every state-changing request from a logged-in user needs the per-session token
    if app.config["SECURE"] and request.method == "POST" and "uid" in session:
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not controls.csrf_token_valid(sent, session.get("csrf", "")):
            wallet_db.audit(wallet_db.get_db(), session["uid"], "CSRF_REJECTED", request.path)
            abort(400, "Invalid CSRF token")


@app.after_request
def apply_security_headers(r):
    if app.config["SECURE"]:  # C9: reduce browser-side exposure
        for name, value in controls.SECURITY_HEADERS.items():
            r.headers[name] = value
    return r


@app.errorhandler(500)
def err500(_):  # C9: no stack traces / internals leaked to the user
    return "Something went wrong.", 500


# ---------------------------------------------------------------- page routes
@app.route("/")
def index():
    return redirect("/dashboard" if "uid" in session else "/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p, n = (request.form.get(k, "").strip() for k in ("username", "password", "full_name"))
        ok, err = controls.validate_registration(u, p) if app.config["SECURE"] else (True, None)  # C4
        if not ok:
            flash(err)
        else:
            try:
                wallet_db.create_user(wallet_db.get_db(), u, p, n[:60])
                flash("Account created. Please log in.")
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("Username unavailable.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("username", ""), request.form.get("password", "")
        conn = wallet_db.get_db()
        user = None
        if not app.config["SECURE"]:
            # VULN: injectable query + plaintext comparison, both live in db.py
            user = wallet_db.get_user_by_credentials_unsafe(conn, u, p)
        else:
            row = wallet_db.get_user_by_username(conn, u)                         # C2: parameterised
            if row and controls.is_account_locked(row):                          # C6
                wallet_db.audit(conn, row["id"], "LOGIN_BLOCKED_LOCKED", "")
            elif row and controls.verify_password(row["password"], p):           # C1
                wallet_db.mark_login_success(conn, row["id"])
                user = row
            elif row:
                wallet_db.mark_login_failure(conn, row)                          # C6
        if user:
            controls.rotate_session(session, user["id"])                        # C8
            wallet_db.audit(conn, user["id"], "LOGIN_OK", "")
            return redirect("/dashboard")
        flash("Invalid credentials or account temporarily locked.")  # C3-style generic message
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    me = current_user()
    other = wallet_db.get_other_demo_user(wallet_db.get_db(), me)
    return render_template(
        "dashboard.html",
        user=me,
        other_user=other,
        csrf=session["csrf"],
        is_admin=controls.is_admin(me),  # C10
    )


@app.route("/api/transfer", methods=["POST"])
@login_required
def api_transfer():
    d = request.get_json(silent=True) or {}
    ok, msg = wallet_db.do_transfer(wallet_db.get_db(), current_user(), str(d.get("to", "")), str(d.get("amount", "")))
    return jsonify(ok=ok, message=msg), (200 if ok else 400)


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    ok, msg = wallet_db.do_transfer(wallet_db.get_db(), current_user(), request.form.get("to", ""), request.form.get("amount", ""))
    flash(msg)
    return redirect("/dashboard")


@app.route("/logout", methods=["POST"])
def logout():
    if "uid" in session:
        wallet_db.audit(wallet_db.get_db(), session["uid"], "LOGOUT", "")
    session.clear()
    return redirect("/login")


# ---- JSON API (used to demonstrate broken access control) -------------------
@app.route("/api/wallet/<int:uid>/balance")
@login_required
def api_balance(uid):
    authorize_owner(uid)   # VULN when removed/disabled: any user can read any balance
    r = wallet_db.get_user_by_id(wallet_db.get_db(), uid)
    return jsonify(username=r["username"], balance=r["balance"]) if r else abort(404)


@app.route("/api/wallet/<int:uid>/transactions")
@login_required
def api_txs(uid):
    authorize_owner(uid)
    return jsonify([dict(t) for t in wallet_db.get_history(wallet_db.get_db(), uid)])


# ---- privileged operation: audit log (admin only) ---------------------------
@app.route("/admin/audit")
@login_required
def admin_audit():
    conn = wallet_db.get_db()
    if app.config["SECURE"] and not controls.is_admin(current_user()):   # C10: role separation
        wallet_db.audit(conn, session["uid"], "ACCESS_DENIED", "/admin/audit")
        abort(403)
    bad = wallet_db.verify_audit(conn)
    rows = wallet_db.get_audit_rows(conn)
    return render_template("admin_audit.html", bad=bad, rows=rows)


if __name__ == "__main__":
    wallet_db.init_db(app)
    app.run(debug=False, port=int(os.environ.get("WALLET_PORT", "5001")))   # never debug=True: exposes an interactive shell