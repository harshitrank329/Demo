# Simple FastAPI auth demo

This minimal project provides registration and login pages using FastAPI, SQLite, session cookies and `passlib` for password hashing.

Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run

```bash
uvicorn main:app --reload
```

Open http://127.0.0.1:8000/register to create a user, then log in.

Notes
- The app uses `SessionMiddleware` with a simple secret; change `secret_key` in `main.py` to a strong random value for production.
- The database file `users.db` is created automatically on first run.
