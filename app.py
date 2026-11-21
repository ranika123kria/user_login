"""Tiny, deliberately vulnerable demo app for Proofgate. DO NOT DEPLOY.

Run:  pip install flask==2.2.4 flask-cors==3.0.8 requests==2.25.0
      python app.py
"""
import sqlite3
import subprocess

import requests
from flask import Flask, abort, redirect, request, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "dev"
CORS(app, origins="*", supports_credentials=True)  # open CORS

# Hardcoded Supabase service_role key (fake token, for the demo only)
SUPABASE_SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW9wcm9qZWN0cmVmIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.FAKEsignatureFORdemoONLYnotREAL0000000000000"

DB = "demo.db"


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    con.commit()
    con.close()


def form(action, fields):
    inputs = "".join(f'<input name="{f}" placeholder="{f}"> ' for f in fields)
    return f'<form method="post" action="{action}">{inputs}<button>Go</button></form>'


@app.route("/")
def index():
    return (
        form("/register", ["username", "password"])
        + form("/login", ["username", "password"])
        + form("/notes", ["title", "body"])
    )


@app.route("/register", methods=["POST"])
def register():
    con = db()
    con.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (request.form["username"], generate_password_hash(request.form["password"])),
    )
    con.commit()
    return redirect("/")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    # String-built SQL: SQL injection
    row = db().execute(
        "SELECT * FROM users WHERE username = '%s'" % username
    ).fetchone()
    if row and check_password_hash(row["password_hash"], request.form["password"]):
        session["user_id"] = row["id"]
        return redirect("/")
    return "Invalid credentials", 401


@app.route("/notes", methods=["POST"])
def create_note():
    if "user_id" not in session:
        abort(401)
    con = db()
    cur = con.execute(
        "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
        (session["user_id"], request.form["title"], request.form["body"]),
    )
    con.commit()
    return {"id": cur.lastrowid}


@app.route("/note/<int:note_id>")
def view_note(note_id):
    if "user_id" not in session:
        abort(401)
    # No ownership check: any logged-in user can read any note (IDOR)
    note = db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None:
        abort(404)
    return {"id": note["id"], "owner": note["user_id"],
            "title": note["title"], "body": note["body"]}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Command injection via shell=True
    return subprocess.check_output("ping -c 1 " + host, shell=True, text=True)


@app.route("/fetch")
def fetch():
    # TLS verification disabled, user-controlled URL
    return requests.get(request.args["url"], verify=False, timeout=5).text


if __name__ == "__main__":
    init_db()
    app.run(debug=True)  # debug mode on
