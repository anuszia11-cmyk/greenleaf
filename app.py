import os
import sqlite3
from functools import wraps
from pathlib import Path

import bcrypt
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["DATABASE"] = os.environ.get("DATABASE", str(BASE_DIR / "greenleaf.db"))


# ---------- database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- auth helpers ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        national_id = request.form["national_id"].strip()
        db = get_db()
        borrower = db.execute(
            "SELECT id FROM borrowers WHERE national_id = ?", (national_id,)
        ).fetchone()
        if borrower is None:
            flash("No borrower record found for that national ID.")
        else:
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, borrower_id) VALUES (?, ?, ?)",
                    (username, pw_hash, borrower["id"]),
                )
                db.commit()
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username taken or this borrower already has an account.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["borrower_id"] = user["borrower_id"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    # Show only the logged-in borrower's own record (listing everyone leaked names too).
    borrowers = get_db().execute(
        "SELECT id, name FROM borrowers WHERE id = ?", (session.get("borrower_id"),)
    ).fetchall()
    return render_template("dashboard.html", borrowers=borrowers)


@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403


@app.route("/borrower/<int:borrower_id>")
@login_required
def borrower_detail(borrower_id):
    # IDOR fix (Task 3): the id in the URL comes from the user and can be changed.
    # session["borrower_id"] was set by the server at login and is signed with
    # SECRET_KEY, so it can be trusted. Only the owner may view the record.
    if session.get("borrower_id") != borrower_id:
        app.logger.warning(
            "IDOR blocked: user=%s (borrower %s) tried to open borrower %s",
            session.get("username"), session.get("borrower_id"), borrower_id,
        )
        abort(403)

    borrower = get_db().execute(
        "SELECT * FROM borrowers WHERE id = ?", (borrower_id,)
    ).fetchone()
    if borrower is None:
        abort(404)
    return render_template("borrower.html", borrower=borrower)


if __name__ == "__main__":
    app.run(debug=False)