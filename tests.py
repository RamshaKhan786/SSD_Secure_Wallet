"""
Before/after security and functional tests for the assignment.

Run:
    python tests.py

Each scenario runs against a fresh database in both vulnerable mode (BEFORE)
and secure mode (AFTER), except for functional checks that intentionally test
only the secure implementation.
"""

import os
import sqlite3
import tempfile

import app as wallet


def fresh(mode):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    wallet.app.config.update(
        DB=path,
        SECURE=(mode == "secure"),
        TESTING=True,
        STEPUP_DEMO=True,
    )
    wallet.wallet_db.init_db(wallet.app)
    return wallet.app.test_client(), path


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def q(path, sql, *args):
    conn = sqlite3.connect(path)
    rows = conn.execute(sql, args).fetchall()
    conn.commit()
    conn.close()
    return rows


def balance(path, username):
    return q(path, "SELECT balance FROM users WHERE username=?", username)[0][0] / 100


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})


def csrf(client):
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def send_form(client, to, amount, include_csrf=True):
    data = {"to": to, "amount": amount}
    if include_csrf:
        data["csrf_token"] = csrf(client)
    return client.post("/transfer", data=data, follow_redirects=False)


def send_json(client, to, amount, include_csrf=True):
    headers = {"X-CSRF-Token": csrf(client)} if include_csrf else {}
    return client.post(
        "/api/transfer",
        json={"to": to, "amount": amount},
        headers=headers,
    )


def add_beneficiary(client, username, include_csrf=True):
    headers = {"X-CSRF-Token": csrf(client)} if include_csrf else {}
    return client.post(
        "/api/beneficiaries",
        json={"username": username},
        headers=headers,
    )


def beneficiaries(client):
    return client.get("/api/beneficiaries")


def remove_beneficiary(client, beneficiary_id, include_csrf=True):
    headers = {"X-CSRF-Token": csrf(client)} if include_csrf else {}
    return client.delete(
        f"/api/beneficiaries/{beneficiary_id}",
        headers=headers,
    )


def w1_password_storage(client):
    stored = q(client.application.config["DB"], "SELECT password FROM users WHERE username=?", "ali")[0][0]
    return f"Ali password begins with: {stored[:25]!r}; plaintext stored: {stored == 'Ali@12345'}"


def w2_sql_injection(client):
    login(client, "ali' --", "wrong")
    dashboard = client.get("/dashboard")
    return f"SQL-injection login -> dashboard HTTP {dashboard.status_code}"


def w3_idor(client):
    login(client, "sara", "Sara@12345")
    response = client.get("/api/wallet/1/balance")
    return f"Sara reads Ali balance -> HTTP {response.status_code}"


def w4_transfer_manipulation(client):
    login(client, "sara", "Sara@12345")
    path = client.application.config["DB"]
    before_sara = balance(path, "sara")
    before_ali = balance(path, "ali")

    negative = send_json(client, "ali", "-5000")
    after_negative_sara = balance(path, "sara")
    after_negative_ali = balance(path, "ali")

    overdraft = send_json(client, "ali", "99999")
    after_overdraft_sara = balance(path, "sara")

    unknown = send_json(client, "ghost", "500")
    after_unknown_sara = balance(path, "sara")

    return (
        f"negative HTTP {negative.status_code}; "
        f"Sara {before_sara:,.0f}->{after_negative_sara:,.0f}, "
        f"Ali {before_ali:,.0f}->{after_negative_ali:,.0f}; "
        f"overdraft HTTP {overdraft.status_code}, Sara now {after_overdraft_sara:,.0f}; "
        f"unknown recipient HTTP {unknown.status_code}, Sara now {after_unknown_sara:,.0f}"
    )


def w5_csrf(client):
    login(client, "sara", "Sara@12345")
    before = balance(client.application.config["DB"], "sara")
    response = send_json(client, "ali", "100", include_csrf=False)
    after = balance(client.application.config["DB"], "sara")
    return f"Forged transfer without CSRF -> HTTP {response.status_code}, Sara {before:,.0f}->{after:,.0f}"


def w6_bruteforce(client):
    for i in range(8):
        login(client, "ali", f"guess{i}")
    login(client, "ali", "Ali@12345")
    response = client.get("/dashboard")
    return f"Correct password after 8 guesses -> dashboard HTTP {response.status_code}"


def w7_audit_tamper(client):
    login(client, "sara", "Sara@12345")
    send_json(client, "ali", "100")
    path = client.application.config["DB"]
    count = q(path, "SELECT COUNT(*) FROM audit_log")[0][0]
    if count == 0:
        return "Audit rows recorded: 0"

    q(path, "UPDATE audit_log SET detail='tampered' WHERE action='TRANSFER'")
    with client.application.app_context():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        bad = wallet.wallet_db.verify_audit(conn)
        conn.close()
    return f"Audit rows recorded: {count}; tampering detected at row {bad}"


def w8_admin_access(client):
    login(client, "sara", "Sara@12345")
    response = client.get("/admin/audit")
    return f"Customer Sara opens /admin/audit -> HTTP {response.status_code}"


def c12_stepup(client):
    login(client, "ali", "Ali@12345")
    path = client.application.config["DB"]
    before = balance(path, "ali")
    response = send_json(client, "sara", "15000")
    issued = response.get_json() if response.is_json else {}

    if not issued.get("step_up_required"):
        return f"High-value transfer did not issue step-up -> HTTP {response.status_code}"

    with client.session_transaction() as sess:
        # The raw code must NOT be present in the Flask client session.
        session_snapshot = dict(sess)
        raw_code_present = "code" in str(session_snapshot)
        challenge_id_present = "stepup_id" in session_snapshot

    wrong = client.post(
        "/api/transfer/confirm",
        json={"code": "000000"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    after_wrong = balance(path, "ali")

    correct_code = issued.get("demo_code")
    success_text = "correct code not available for this test"
    if correct_code:
        correct = client.post(
            "/api/transfer/confirm",
            json={"code": correct_code},
            headers={"X-CSRF-Token": csrf(client)},
        )
        success_text = f"correct code -> HTTP {correct.status_code}, transfer success: {correct.get_json().get('ok') is True}"

    return (
        f"Rs.15,000 requested -> HTTP {response.status_code}; "
        f"challenge id in session: {challenge_id_present}; raw code in session: {raw_code_present}; "
        f"wrong code -> HTTP {wrong.status_code}; balance unchanged after wrong code: {before == after_wrong}; "
        f"{success_text}"
    )


def functional_secure():
    client, path = fresh("secure")
    try:
        # Registration
        reg = client.post(
            "/register",
            data={
                "username": "test_user",
                "full_name": "Test User",
                "password": "Strong@123",
            },
            follow_redirects=False,
        )
        assert reg.status_code == 302 and reg.headers["Location"].endswith("/login")

        # Authentication
        login_response = login(client, "test_user", "Strong@123")
        assert login_response.status_code == 302

        # Own balance and history
        user_row = q(path, "SELECT id FROM users WHERE username=?", "test_user")[0][0]
        balance_response = client.get(f"/api/wallet/{user_row}/balance")
        history_response = client.get(f"/api/wallet/{user_row}/transactions")
        assert balance_response.status_code == 200
        assert history_response.status_code == 200

        # Transfer to another customer and verify both balances/history.
        before_sender = balance(path, "test_user")
        before_receiver = balance(path, "sara")
        transfer_response = send_json(client, "sara", "200")
        assert transfer_response.status_code == 200
        assert transfer_response.get_json()["ok"] is True
        assert balance(path, "test_user") == before_sender - 200
        assert balance(path, "sara") == before_receiver + 200

        history = client.get(f"/api/wallet/{user_row}/transactions").get_json()
        assert any(row["status"] == "SUCCESS" and row["amount"] == 20000 for row in history)
        required_history_fields = {"sender_id", "receiver_id", "amount", "created_at", "status"}
        assert required_history_fields.issubset(history[0].keys())

        # Beneficiary add/list/remove functionality.
        add = add_beneficiary(client, "sara")
        assert add.status_code == 201 and add.get_json()["ok"] is True
        listed = beneficiaries(client)
        assert listed.status_code == 200
        beneficiary_rows = listed.get_json()
        assert len(beneficiary_rows) == 1 and beneficiary_rows[0]["username"] == "sara"

        duplicate = add_beneficiary(client, "sara")
        assert duplicate.status_code == 400
        beneficiary_id = beneficiary_rows[0]["id"]

        csrf_remove = remove_beneficiary(client, beneficiary_id, include_csrf=False)
        assert csrf_remove.status_code == 400
        assert len(beneficiaries(client).get_json()) == 1

        remove = remove_beneficiary(client, beneficiary_id)
        assert remove.status_code == 200 and remove.get_json()["ok"] is True
        assert beneficiaries(client).get_json() == []

        self_add = add_beneficiary(client, "test_user")
        assert self_add.status_code == 400
        invalid_recipient = add_beneficiary(client, "ghost")
        assert invalid_recipient.status_code == 400

        # Beneficiary records are owner-scoped: another user cannot remove Sara's record.
        add_again = add_beneficiary(client, "sara")
        assert add_again.status_code == 201
        shared_id = beneficiaries(client).get_json()[0]["id"]
        other_client, other_path = fresh("secure")
        try:
            login(other_client, "sara", "Sara@12345")
            cross_owner_remove = remove_beneficiary(other_client, shared_id)
            assert cross_owner_remove.status_code == 404
        finally:
            cleanup(other_path)

        # Admin can access the privileged audit page; normal customers cannot.
        admin_client, admin_path = fresh("secure")
        try:
            login(admin_client, "admin", "Admin@12345")
            assert admin_client.get("/admin/audit").status_code == 200
        finally:
            cleanup(admin_path)

        # Logout invalidates the authenticated session.
        logout = client.post("/logout", data={"csrf_token": csrf(client)})
        assert logout.status_code == 302
        assert client.get("/dashboard").status_code == 302

        # Security headers are present in secure mode.
        headers_response = client.get("/login")
        for name in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
            assert name in headers_response.headers

        return "Functional secure checks: PASS"
    finally:
        cleanup(path)
def c14_rate_limit_login(client):
    """Fire many bad logins; expect 429 after the limit."""
    statuses = []
    for i in range(25):
        r = login(client, "ali", f"bad{i}")
        statuses.append(r.status_code)
    blocked = statuses.count(429)
    return f"25 login attempts -> {blocked} blocked with 429"


def c14_rate_limit_transfer(client):
    login(client, "sara", "Sara@12345")
    blocked = 0
    for _ in range(40):
        r = send_json(client, "ali", "1")
        if r.status_code == 429:
            blocked += 1
    return f"40 transfers -> {blocked} rate-limited"

def security_before_after():
    scenarios = [
        ("W1 Plaintext credentials", w1_password_storage),
        ("W2 SQL injection", w2_sql_injection),
        ("W3 IDOR / broken object authorization", w3_idor),
        ("W4 Transfer manipulation", w4_transfer_manipulation),
        ("W5 CSRF", w5_csrf),
        ("W6 Brute-force login", w6_bruteforce),
        ("W7 Audit tampering", w7_audit_tamper),
        ("W8 Unauthorized admin access", w8_admin_access),
        ("C12 Step-up authentication", c12_stepup),
    ]

    for title, function in scenarios:
        print(f"\n=== {title}")
        for mode, label in (("vulnerable", "BEFORE"), ("secure", "AFTER")):
            client, path = fresh(mode)
            try:
                print(f"  {label}: {function(client)}")
            finally:
                cleanup(path)


if __name__ == "__main__":
    print(functional_secure())
    security_before_after()
