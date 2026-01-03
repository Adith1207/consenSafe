from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "securerail_secret_key"   # change in production
DB_NAME = "database.db"


# =====================================================
# DATABASE HELPERS
# =====================================================

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# =====================================================
# PASSWORD POLICY (STRONG PASSWORD)
# =====================================================

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


# =====================================================
# ROUTES
# =====================================================

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# ---------------- REGISTER -----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]

        if not is_strong_password(password):
            return "Password must be strong (8+ chars, upper, lower, number, special char)"

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, hashed_password, role)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            return "Username or Email already exists"

    return render_template("register.html")


# ---------------- LOGIN -----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        return "Invalid email or password"

    return render_template("login.html")


# ---------------- DASHBOARD -----------------

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"]
    )


# ---------------- CHANGE PASSWORD -----------------

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "email" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]

        if not is_strong_password(new_password):
            return "New password is not strong enough"

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (session["email"],)
        ).fetchone()

        if user and check_password_hash(user["password"], old_password):
            conn.execute(
                "UPDATE users SET password = ? WHERE email = ?",
                (generate_password_hash(new_password), session["email"])
            )
            conn.commit()
            conn.close()
            return "Password updated successfully"

        conn.close()
        return "Old password incorrect"

    return "Change Password Page (UI to be implemented)"


# ---------------- FORGOT PASSWORD (OTP READY) -----------------

@app.route("/forgot-password")
def forgot_password():
    return "Forgot Password flow (OTP via Email to be implemented)"


# ---------------- LOGOUT -----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =====================================================
# APP START
# =====================================================

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
