"""
Mini Secure Fintech Wallet (Flask + SQLite)

Application structure
---------------------
app.py       Routes, HTTP handling, sessions, request lifecycle.
db.py        All database access and transaction persistence.
controls.py  Security policies and security-control algorithms.
templates/   Jinja2 HTML presentation.
static/      Browser-side JavaScript and CSS.

two demonstration modes
-----------------------
secure      Default. Security controls are enabled.
vulnerable  Deliberately weak mode for the assignment's before/after testing.
             Run it only on a local test machine.
"""

import math
import os
import secrets
import sqlite3
import time
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)

import controls
import db as wallet_db


# ---------------------------------------------------------------- configuration
WALLET_MODE = os.environ.get("WALLET_MODE", "secure").strip().lower()
SECURE_MODE = WALLET_MODE != "vulnerable"
DEFAULT_DB = "wallet_secure.db" if SECURE_MODE else "wallet_vulnerable.db"


def env_flag(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


app = Flask(__name__)
app.config.update(
    DB=os.environ.get("WALLET_DB", DEFAULT_DB),
    SECURE=SECURE_MODE,
    SECRET_KEY=os.environ.get("WALLET_SECRET") or secrets.token_hex(32),
    SESSION_COOKIE_SECURE=env_flag("WALLET_HTTPS"),
    MAX_CONTENT_LENGTH=16 * 1024,
    STEPUP_DEMO=not env_flag("WALLET_NO_STEPUP_DEMO"),
    **controls.SESSION_SECURITY_CONFIG,
)

wallet_db.init_db(app)
app.teardown_appcontext(wallet_db.close_db)


@app.context_processor
def inject_globals():
    return {"secure": app.config["SECURE"]}


# ---------------------------------------------------------------- helpers / guards

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect("/login")
        user = wallet_db.get_user_by_id(wallet_db.get_db(), session["uid"])
        if user is None:
            session.clear()
            return redirect("/login")
        return f(*args, **kwargs)

    return wrapper


def current_user():
    user = wallet_db.get_user_by_id(wallet_db.get_db(), session["uid"])
    if user is None:
        session.clear()
        abort(401)
    return user


def authorize_owner(uid):
    if app.config["SECURE"] and not controls.is_owner(session["uid"], uid):
        wallet_db.audit(
            wallet_db.get_db(),
            session["uid"],
            "ACCESS_DENIED",
            f"tried wallet {uid}",
        )
        abort(403)


# ---------------------------------------------------------------- C15: rate limiting helpers
def client_ip():
    # Behind a reverse proxy, wrap the app with werkzeug's ProxyFix.
    # Never read X-Forwarded-For directly: clients can forge it.
    return request.remote_addr or "unknown"


def check_rate_limit(bucket_name, identifier):
    """Return None if allowed, or the seconds to wait if the limit is hit."""
    if not app.config["SECURE"]:
        return None  # vulnerable mode stays unthrottled for before/after tests
    max_hits, window = controls.rate_limit_policy(bucket_name)
    if max_hits is None:
        return None
    key = controls.bucket_key(bucket_name, identifier)
    conn = wallet_db.get_db()
    allowed, _remaining, retry_after = wallet_db.hit_rate_limit(conn, key, window, max_hits)
    if allowed:
        return None
    wallet_db.audit(conn, session.get("uid"), "RATE_LIMITED", key)
    return retry_after


def rate_limit_json(bucket_name, identifier):
    """For JSON routes: return a 429 response if limited, else None."""
    wait = check_rate_limit(bucket_name, identifier)
    if wait is None:
        return None
    seconds = max(1, math.ceil(wait))
    resp = jsonify(ok=False, message=f"Too many requests. Try again in {seconds} seconds.")
    resp.status_code = 429
    resp.headers["Retry-After"] = str(seconds)
    return resp


# ---------------------------------------------------------------- request lifecycle security
@app.before_request
def csrf_protect():
    """Require the per-session token on every authenticated POST request."""
    if app.config["SECURE"] and request.method in {"POST", "PUT", "PATCH", "DELETE"} and "uid" in session:
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not controls.csrf_token_valid(sent, session.get("csrf", "")):
            wallet_db.audit(
                wallet_db.get_db(),
                session["uid"],
                "CSRF_REJECTED",
                request.path,
            )
            abort(400, "Invalid CSRF token")


@app.after_request
def apply_security_headers(response):
    if app.config["SECURE"]:
        for name, value in controls.SECURITY_HEADERS.items():
            response.headers[name] = value
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(400)
def err400(error):
    return str(error.description or "Bad request."), 400


@app.errorhandler(401)
def err401(_error):
    return "Authentication required.", 401


@app.errorhandler(403)
def err403(_error):
    return "Forbidden.", 403


@app.errorhandler(404)
def err404(_error):
    return "Not found.", 404


@app.errorhandler(413)
def err413(_error):
    return "Request too large.", 413


@app.errorhandler(500)
def err500(_error):
    return "Something went wrong.", 500


# ---------------------------------------------------------------- page routes
@app.route("/")
def index():
    return redirect("/dashboard" if "uid" in session else "/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        wait = check_rate_limit("register_ip", client_ip())
        if wait is not None:
            flash(f"Too many sign-ups from this address. Try again in {max(1, math.ceil(wait))} seconds.")
            return render_template("register.html"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        cnic = request.form.get("cnic", "").strip()

        if app.config["SECURE"]:
            ok, error = controls.validate_registration(username, password, full_name, email, cnic)
        else:
            ok, error = True, None

        if not ok:
            flash(error)
        else:
            try:
                wallet_db.create_user(
                    wallet_db.get_db(),
                    username,
                    password,
                    full_name[: controls.MAX_FULL_NAME_LEN],
                    email,
                    cnic,
                )
                flash("Account created. Please log in.")
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("Username, email, or CNIC already in use.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # C15: throttle before any password work. The account bucket also counts
        # unknown usernames, so it does not reveal which usernames exist.
        wait = check_rate_limit("login_ip", client_ip())
        if wait is None:
            wait = check_rate_limit("login_account", username.strip().lower()[:64])
        if wait is not None:
            flash(f"Too many login attempts. Try again in {max(1, math.ceil(wait))} seconds.")
            return render_template("login.html"), 429

        conn = wallet_db.get_db()
        user = None
        message = "Invalid username or password."

        if not app.config["SECURE"]:
            # VULN: injectable SQL and plaintext comparison for the before-test.
            user = wallet_db.get_user_by_credentials_unsafe(conn, username, password)
        else:
            row = wallet_db.get_user_by_username(conn, username)
            if row and controls.is_account_locked(row):
                wallet_db.audit(conn, row["id"], "LOGIN_BLOCKED_LOCKED", "")
                remaining = max(1, int((row["locked_until"] - time.time()) // 60) + 1)
                message = (f"Your account is blocked due to too many failed "
                           f"login attempts. Try again in about {remaining} minute(s).")
            elif row and controls.verify_password(row["password"], password):
                wallet_db.mark_login_success(conn, row["id"])
                user = row
            elif row:
                # mark_login_failure returns True when this failure triggered the lock.
                if wallet_db.mark_login_failure(conn, row):
                    message = (f"Account is blocked now after "
                               f"{controls.MAX_FAILED_LOGINS} failed attempts. "
                               f"Try again in {controls.LOCK_SECONDS // 60} minutes.")

        if user:
            controls.rotate_session(session, user["id"])
            wallet_db.audit(conn, user["id"], "LOGIN_OK", "")
            return redirect("/dashboard")

        flash(message)

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    me = current_user()
    other = wallet_db.get_other_demo_user(wallet_db.get_db(), me)

    decrypted_cnic = controls.decrypt_cnic(me["cnic"], app.config["SECRET_KEY"]) if app.config["SECURE"] else me["cnic"]
    masked_cnic = controls.mask_cnic(decrypted_cnic) if decrypted_cnic else "****"

    return render_template(
        "dashboard.html",
        user=me,
        other_user=other,
        csrf=session["csrf"],
        session_timeout=controls.SESSION_IDLE_TIMEOUT,
        is_admin=controls.is_admin(me),
        masked_cnic=masked_cnic,
    )


# ---------------------------------------------------------------- beneficiary API
@app.route("/api/beneficiaries", methods=["GET"])
@login_required
def api_beneficiaries():
    rows = wallet_db.get_beneficiaries(wallet_db.get_db(), session["uid"])
    return jsonify([dict(row) for row in rows])


@app.route("/api/beneficiaries", methods=["POST"])
@login_required
def api_add_beneficiary():
    limited = rate_limit_json("beneficiary_user", session["uid"])
    if limited:
        return limited

    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    conn = wallet_db.get_db()

    if app.config["SECURE"]:
        ok, message = controls.validate_beneficiary_username(username)
        if not ok:
            return jsonify(ok=False, message=message), 400

    ok, message = wallet_db.add_beneficiary(conn, session["uid"], username)
    if ok:
        return jsonify(ok=True, message=message), 201
    return jsonify(ok=False, message=message), 400


@app.route("/api/beneficiaries/<int:beneficiary_id>", methods=["DELETE"])
@login_required
def api_remove_beneficiary(beneficiary_id):
    limited = rate_limit_json("beneficiary_user", session["uid"])
    if limited:
        return limited

    valid, parsed_id = controls.validate_beneficiary_id(beneficiary_id)
    if not valid:
        return jsonify(ok=False, message="Invalid beneficiary id."), 400

    conn = wallet_db.get_db()
    ok, message = wallet_db.remove_beneficiary(conn, session["uid"], parsed_id)
    if ok:
        return jsonify(ok=True, message=message), 200

    if app.config["SECURE"]:
        wallet_db.audit(
            conn,
            session["uid"],
            "BENEFICIARY_REMOVE_DENIED",
            f"beneficiary_record={parsed_id}",
        )
    return jsonify(ok=False, message=message), 404


# ---------------------------------------------------------------- transfer API
@app.route("/api/transfer", methods=["POST"])
@login_required
def api_transfer():
    limited = rate_limit_json("transfer_user", session["uid"])
    if limited:
        return limited

    payload = request.get_json(silent=True) or {}
    to = str(payload.get("to", "")).strip()
    amount_str = str(payload.get("amount", "")).strip()
    conn = wallet_db.get_db()

    if app.config["SECURE"]:
        ok, amount_or_msg = controls.validate_transfer_amount(amount_str)
        if not ok:
            return jsonify(ok=False, message=amount_or_msg), 400

        recipient_ok, recipient_msg = controls.validate_transfer_recipient(to)
        if not recipient_ok:
            return jsonify(ok=False, message=recipient_msg), 400

        recipient = wallet_db.get_customer_by_username(conn, to)
        if not recipient or recipient["id"] == session["uid"]:
            return jsonify(ok=False, message="Invalid recipient."), 400

        # Early rejection: do not issue a step-up code for a transfer that can
        # never succeed. do_transfer() still re-checks the balance atomically.
        if current_user()["balance"] < amount_or_msg:
            return jsonify(ok=False, message="Insufficient funds."), 400

        if controls.needs_step_up(amount_or_msg):
            code = controls.generate_step_up_code()
            challenge_id = controls.new_step_up_challenge_id()
            expires_at = time.time() + controls.STEP_UP_CODE_TTL
            digest = controls.step_up_code_digest(code, app.config["SECRET_KEY"])
            wallet_db.create_step_up_challenge(
                conn,
                challenge_id,
                session["uid"],
                to,
                amount_or_msg,
                digest,
                expires_at,
            )
            session["stepup_id"] = challenge_id
            wallet_db.audit(
                conn,
                session["uid"],
                "STEP_UP_REQUIRED",
                f"to={recipient['id']} amount={amount_or_msg}",
            )

            response = {
                "ok": True,
                "step_up_required": True,
                "message": (
                    f"Transfers of Rs. {controls.STEP_UP_THRESHOLD:,.0f}+ "
                    "need a verification code."
                ),
            }
            # Classroom-only substitute for an SMS/authenticator channel.
            # The raw code is NOT stored in the Flask client session.
            if app.config["STEPUP_DEMO"]:
                response["demo_code"] = code
            return jsonify(**response), 200

    ok, message = wallet_db.do_transfer(
        conn,
        current_user(),
        to,
        amount_str,
    )
    return jsonify(ok=ok, message=message), (200 if ok else 400)


@app.route("/api/transfer/confirm", methods=["POST"])
@login_required
def api_transfer_confirm():
    limited = rate_limit_json("stepup_user", session["uid"])
    if limited:
        return limited

    payload = request.get_json(silent=True) or {}
    entered_code = str(payload.get("code", ""))
    conn = wallet_db.get_db()
    challenge_id = session.get("stepup_id")

    if not challenge_id:
        return jsonify(ok=False, message="No pending transfer to confirm."), 400

    challenge = wallet_db.get_step_up_challenge(conn, challenge_id, session["uid"])
    if not challenge:
        session.pop("stepup_id", None)
        return jsonify(ok=False, message="No pending transfer to confirm."), 400

    if not controls.step_up_code_valid(
        entered_code,
        challenge["code_digest"],
        challenge["expires_at"],
        app.config["SECRET_KEY"],
    ):
        if time.time() > challenge["expires_at"]:
            wallet_db.delete_step_up_challenge(conn, challenge_id)
            session.pop("stepup_id", None)
            wallet_db.audit(conn, session["uid"], "STEP_UP_FAILED", "expired code")
            return jsonify(ok=False, message="Incorrect or expired code."), 400

        attempts = wallet_db.increment_step_up_attempts(conn, challenge_id)
        if attempts >= controls.STEP_UP_MAX_ATTEMPTS:
            wallet_db.delete_step_up_challenge(conn, challenge_id)
            session.pop("stepup_id", None)
            wallet_db.audit(
                conn,
                session["uid"],
                "STEP_UP_FAILED",
                "max attempts exceeded, transfer voided",
            )
            return jsonify(
                ok=False,
                message="Too many incorrect codes. Transfer cancelled. Please try again.",
            ), 400

        wallet_db.audit(
            conn,
            session["uid"],
            "STEP_UP_FAILED",
            f"attempt {attempts}",
        )
        return jsonify(ok=False, message="Incorrect or expired code."), 400

    # Code is valid. Consume the server-side challenge before executing the
    # transfer so it cannot be reused.
    pending_to = challenge["recipient_username"]
    pending_amount = challenge["amount_paisa"]
    wallet_db.delete_step_up_challenge(conn, challenge_id)
    session.pop("stepup_id", None)

    ok, message = wallet_db.do_transfer(
        conn,
        current_user(),
        pending_to,
        f"{pending_amount / 100:.2f}",
        step_up_verified=True,
    )
    wallet_db.audit(
        conn,
        session["uid"],
        "STEP_UP_OK" if ok else "STEP_UP_VERIFIED_TRANSFER_FAILED",
        f"to={pending_to} amount={pending_amount}",
    )
    return jsonify(ok=ok, message=message), (200 if ok else 400)


# ---------------------------------------------------------------- legacy form route kept for the before/after bypass demonstration
@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    wait = check_rate_limit("transfer_user", session["uid"])
    if wait is not None:
        flash(f"Too many transfers. Try again in {max(1, math.ceil(wait))} seconds.")
        return redirect("/dashboard")

    ok, message = wallet_db.do_transfer(
        wallet_db.get_db(),
        current_user(),
        request.form.get("to", "").strip(),
        request.form.get("amount", "").strip(),
    )
    flash(message)
    return redirect("/dashboard")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    uid = session["uid"]
    wallet_db.audit(wallet_db.get_db(), uid, "LOGOUT", "")
    session.clear()
    return redirect("/login")


# ---------------------------------------------------------------- JSON APIs for balance / history
@app.route("/api/wallet/<int:uid>/balance")
@login_required
def api_balance(uid):
    authorize_owner(uid)
    row = wallet_db.get_user_by_id(wallet_db.get_db(), uid)
    return jsonify(username=row["username"], balance=row["balance"]) if row else abort(404)


@app.route("/api/wallet/<int:uid>/transactions")
@login_required
def api_txs(uid):
    authorize_owner(uid)
    return jsonify([dict(row) for row in wallet_db.get_history(wallet_db.get_db(), uid)])


# ---------------------------------------------------------------- privileged operation
@app.route("/admin/audit")
@login_required
def admin_audit():
    conn = wallet_db.get_db()
    if app.config["SECURE"] and not controls.is_admin(current_user()):
        wallet_db.audit(conn, session["uid"], "ACCESS_DENIED", "/admin/audit")
        abort(403)
    bad = wallet_db.verify_audit(conn)
    rows = wallet_db.get_audit_rows(conn)
    return render_template("admin_audit.html", bad=bad, rows=rows)


if __name__ == "__main__":
    # Secure mode is the default. Vulnerable mode is intentionally enabled
    # only when WALLET_MODE=vulnerable is supplied for the assignment lab.
    app.run(debug=False, port=int(os.environ.get("WALLET_PORT", "5001")))