"""
Before/after security tests.  Run:  python tests.py
Each test runs against a fresh database in VULNERABLE mode (before) and SECURE mode (after).
"""
import os, sqlite3, tempfile
import app as w

def fresh(mode):
    w.app.config.update(DB=tempfile.mktemp(suffix=".db"), SECURE=(mode == "secure"), TESTING=True)
    w.init_db()
    return w.app.test_client()

def q(sql, *a):
    c = sqlite3.connect(w.app.config["DB"]); r = c.execute(sql, a).fetchall(); c.commit(); c.close(); return r

def bal(u): return q("SELECT balance FROM users WHERE username=?", u)[0][0] / 100

def login(c, u, p): return c.post("/login", data={"username": u, "password": p})

def token(c):
    with c.session_transaction() as s: return s.get("csrf", "")

def send(c, to, amt, csrf=True):
    d = {"to": to, "amount": amt}
    if csrf: d["csrf_token"] = token(c)
    return c.post("/transfer", data=d)

def t1(c):  # W1 credentials at rest
    return f"ali's stored password = {q('SELECT password FROM users WHERE username=?', 'ali')[0][0][:40]!r}"

def t2(c):  # W2 SQL injection login
    login(c, "ali' --", "wrong")
    return f"login as ali with password 'wrong' -> /dashboard HTTP {c.get('/dashboard').status_code}"

def t3(c):  # W3 broken object-level authorisation
    login(c, "sara", "Sara@12345")
    r = c.get("/api/wallet/1/balance")
    return f"sara reads ali's balance -> HTTP {r.status_code} {r.get_data(as_text=True).strip()[:60] if r.status_code == 200 else ''}"

def t4(c):  # W4a negative amount / W4b overdraft / W4c unknown recipient
    login(c, "sara", "Sara@12345")
    a0, s0 = bal("ali"), bal("sara")
    send(c, "ali", "-5000")
    out = [f"sara sends Rs.-5000 to ali: ali {a0:,.0f}->{bal('ali'):,.0f}, sara {s0:,.0f}->{bal('sara'):,.0f}"]
    s1 = bal("sara"); send(c, "ali", "99999")
    out.append(f"sara (has {s1:,.0f}) sends Rs.99,999: sara now {bal('sara'):,.0f}")
    s2 = bal("sara"); send(c, "ghost", "500")
    out.append(f"sara sends Rs.500 to non-existent user: sara {s2:,.0f}->{bal('sara'):,.0f}")
    return "\n      ".join(out)

def t5(c):  # W5 CSRF (forged POST with no token)
    login(c, "sara", "Sara@12345"); s0 = bal("sara")
    r = send(c, "ali", "100", csrf=False)
    return f"forged transfer without CSRF token -> HTTP {r.status_code}, sara {s0:,.0f}->{bal('sara'):,.0f}"

def t6(c):  # W6 brute force
    for i in range(8): login(c, "ali", f"guess{i}")
    login(c, "ali", "Ali@12345")   # correct password after 8 wrong guesses
    return f"correct password after 8 guesses -> /dashboard HTTP {c.get('/dashboard').status_code}"

def t7(c):  # W7 audit trail + tamper detection
    login(c, "sara", "Sara@12345"); send(c, "ali", "100")
    n = q("SELECT COUNT(*) FROM audit_log")[0][0]
    if n == 0: return "audit rows recorded: 0 (nothing to review or verify)"
    q("UPDATE audit_log SET detail='to=1 amt=1' WHERE action='TRANSFER'")   # attacker edits DB
    with w.app.app_context():
        db = sqlite3.connect(w.app.config["DB"]); db.row_factory = sqlite3.Row
        bad = w.verify_audit(db); db.close()
    return f"audit rows recorded: {n}; after editing a row, verify_audit -> tampered row id {bad}"

def t8(c):  # W8 privileged endpoint reachable by normal customer
    login(c, "sara", "Sara@12345")
    return f"customer sara opens /admin/audit -> HTTP {c.get('/admin/audit').status_code}"

TESTS = [("W1 Plaintext credentials", t1), ("W2 SQL injection at login", t2),
         ("W3 Access to another user's wallet (IDOR)", t3), ("W4 Transfer manipulation", t4),
         ("W5 CSRF forged transfer", t5), ("W6 Brute-force login", t6),
         ("W7 Missing / tamperable audit trail", t7), ("W8 Customer reaches admin function", t8)]

if __name__ == "__main__":
    for name, fn in TESTS:
        print(f"\n=== {name}")
        for mode, label in (("vulnerable", "BEFORE"), ("secure", "AFTER ")):
            print(f"  {label}: {fn(fresh(mode))}")
