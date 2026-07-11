from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import sqlite3
from passlib.hash import bcrypt
import os

DB_PATH = "users.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB_PATH):
        conn = get_db()
        conn.execute(
            """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
        )
        conn.commit()
        conn.close()


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="change_me_to_a_random_secret")
templates = Jinja2Templates(directory="templates")
init_db()


@app.get("/")
def root():
    return RedirectResponse("/dashboard")


@app.get("/register")
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "message": ""})


@app.post("/register")
def register_post(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    try:
        password_hash = bcrypt.hash(password)
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return templates.TemplateResponse("register.html", {"request": request, "message": "Username already exists"})
    conn.close()
    return RedirectResponse("/login", status_code=303)


@app.get("/login")
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "message": ""})


@app.post("/login")
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row or not bcrypt.verify(password, row["password_hash"]):
        return templates.TemplateResponse("login.html", {"request": request, "message": "Invalid credentials"})
    request.session['user'] = username
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/dashboard")
def dashboard(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")
