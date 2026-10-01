# Mini Secure Fintech Wallet

This implementation is aligned with Assignment 1: Mini Secure Fintech Wallet.
The application supports account creation, login, balance viewing, beneficiary
management (add/list/remove), fund transfer, transaction history, logout, and a
before/after Security Lab.

## Project structure

```text
app.py                 Flask routes and request/session handling
db.py                  SQLite database and transfer persistence
controls.py            Security policy and control algorithms
tests.py               Functional + before/after security tests
requirements.txt       Python dependencies
templates/
  base.html
  login.html
  register.html
  dashboard.html
  admin_audit.html
static/
  css/style.css
  js/login.js
  js/register.js
  js/dashboard.js
```

## Run

```text
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5001/`.

Secure mode is the default. The default database is `wallet_secure.db`.
The intentionally vulnerable lab uses a separate `wallet_vulnerable.db` so
switching modes does not accidentally reuse plaintext demo credentials.

## Vulnerable mode for the assignment demo

On Windows CMD:

```text
set WALLET_MODE=vulnerable
python app.py
```

On PowerShell:

```text
$env:WALLET_MODE="vulnerable"
python app.py
```

The vulnerable mode is for local classroom testing only.

## Demo users

- `ali` / `Ali@12345`
- `sara` / `Sara@12345`
- `admin` / `Admin@12345`

The secure database stores password hashes rather than these plaintext values.

## Before/after testing

Run:

```text
python tests.py
```

The test program checks the assignment's main functional requirements and then
runs the same selected attack scenarios in vulnerable mode (BEFORE) and secure
mode (AFTER).

## Main security decisions

| ID | Weakness | Control | Implementation |
|---|---|---|---|
| W1 | Credentials exposed at rest | Password hashing | `controls.py` + `db.py` |
| W2 | SQL injection | Parameterized SQL | All normal DB queries in `db.py` |
| W3 | One user accessing another user's wallet | Object-level authorization | `authorize_owner()` in `app.py` |
| W4 | Manipulated/invalid money transfers | Server validation + atomic transaction | `controls.py` + `db.py` |
| W5 | Forged state-changing requests | CSRF token | `app.py` + session |
| W6 | Repeated password guessing | Account lockout | `controls.py` + `db.py` |
| W7 | Important actions changed without detection | Hash-chained audit log | `controls.py` + `db.py` |
| W8 | Customer reaching admin-only functions | Role separation | `controls.is_admin()` + admin route |
| C12 | High-value transfer bypass | Step-up authentication | `app.py` + `db.py` + `controls.py` |
| C13 | Beneficiary records could be added/removed without ownership checks | Server-side beneficiary validation + owner-scoped queries + CSRF | `app.py` + `db.py` + `controls.py` + `dashboard.js` |

The design also applies secure defaults, least privilege, separation of
responsibilities, defense in depth, logging/accountability, and reduction of
unnecessary exposure where they are relevant to this wallet.

## Step-up demo limitation

The assignment has no SMS/e-mail/authenticator provider. By default the secure
app therefore returns a clearly labelled `demo_code` in the high-value transfer
response so the classroom demonstration remains usable. The raw code is not
stored in the Flask client session; only a random challenge ID is stored there,
and the server stores a keyed digest. Set `WALLET_NO_STEPUP_DEMO=1` to stop the
API from returning the demo code and use a real second-channel delivery
mechanism in a future implementation.

## Beneficiary management

Each logged-in customer can add another registered customer as a beneficiary,
view saved beneficiaries, select one to populate the transfer recipient field,
and remove a beneficiary. Beneficiary records are stored in their own table with
a unique `(user_id, beneficiary_user_id)` pair. Secure-mode changes are protected
by server-side username validation, CSRF protection, ownership-scoped lookup/delete
queries, foreign keys, and audit logging.

API endpoints:
- `GET /api/beneficiaries` - list the current user's beneficiaries.
- `POST /api/beneficiaries` - add a registered customer using `{ "username": "sara" }`.
- `DELETE /api/beneficiaries/<id>` - remove only a beneficiary record owned by the current user.

Removing a beneficiary does not delete the customer account and does not delete transaction history.
