# Mini Secure Fintech Wallet

Flask + SQLite. Files: `app.py` (application), `tests.py` (before/after tests), `requirements.txt`.

## Run
```bash
pip install -r requirements.txt
python app.py                      # SECURE mode  -> http://127.0.0.1:5000
WALLET_MODE=vulnerable python app.py   # controls OFF (demo only; delete wallet.db when switching modes)
python tests.py                    # automated before/after results for W1-W8
```

## Demo accounts
| user | password | role |
|---|---|---|
| ali | Ali@12345 | customer (Rs. 50,000) |
| sara | Sara@12345 | customer (Rs. 10,000) |
| admin | Admin@12345 | admin (can view audit log) |

New users can register (get Rs. 1,000 demo credit).

## Manual demo ideas (vulnerable vs secure)
- Login with username `ali' --` and any password.
- While logged in as sara open `/api/wallet/1/balance` (Ali's balance).
- Transfer `-5000` to ali, or an amount larger than your balance.
- Open `/admin/audit` as sara.
