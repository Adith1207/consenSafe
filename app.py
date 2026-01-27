from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import re
import random
import time
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "consensafe_secret_key"
ALLOWED_ROLES = ("user", "app", "admin")
DB_NAME = "database.db"

# =====================================================
# OTP STORE (IN-MEMORY FOR LAB)
# =====================================================
# format: { email: { "otp": "123456", "expires": timestamp } }
otp_store = {}


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
# STRONG PASSWORD POLICY (NIST-ALIGNED)
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


# =====================================================
# REGISTER
# =====================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]
        if role not in ALLOWED_ROLES:
            return "Invalid role selection"

        if not is_strong_password(password):
            return "Password must be strong (8+ chars, upper, lower, number, special)"

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


# =====================================================
# LOGIN (EMAIL-BASED)
# =====================================================

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
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        return "Invalid email or password"

    return render_template("login.html")


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session["role"]

    if role == "user":
        return render_template("dashboard_user.html", username=session["username"])

    elif role == "app":
        return render_template("dashboard_app.html", username=session["username"])

    elif role == "admin":
        return render_template("dashboard_admin.html", username=session["username"])

    else:
        return "Unauthorized role", 403


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =====================================================
# CHANGE PASSWORD (LOGGED-IN USER)
# =====================================================

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

    return render_template("reset_password.html")


# =====================================================
# FORGOT PASSWORD → OTP GENERATION
# =====================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        conn.close()

        if not user:
            return "Email not registered"

        otp = str(random.randint(100000, 999999))
        otp_store[email] = {
            "otp": otp,
            "expires": time.time() + 300  # 5 minutes
        }

        # LAB MODE: Print OTP in terminal
        print(f"[OTP for {email}] : {otp}")

        session["reset_email"] = email
        return redirect(url_for("verify_otp"))

    return render_template("forgot_password.html")


# =====================================================
# OTP VERIFICATION
# =====================================================

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "reset_email" not in session:
        return redirect(url_for("login"))

    email = session["reset_email"]

    if request.method == "POST":
        entered_otp = request.form["otp"]
        record = otp_store.get(email)

        if not record:
            return "OTP invalid or expired"

        if time.time() > record["expires"]:
            otp_store.pop(email)
            return "OTP expired"

        if entered_otp != record["otp"]:
            return "Incorrect OTP"

        otp_store.pop(email)
        session["otp_verified"] = True
        return redirect(url_for("reset_password"))

    return render_template("verify_otp.html")


# =====================================================
# RESET PASSWORD (AFTER OTP)
# =====================================================

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if not session.get("otp_verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form["password"]

        if not is_strong_password(new_password):
            return "Password is not strong enough"

        conn = get_db()
        conn.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (generate_password_hash(new_password), session["reset_email"])
        )
        conn.commit()
        conn.close()

        session.pop("otp_verified")
        session.pop("reset_email")

        return redirect(url_for("login"))

    return render_template("reset_password.html")


# =====================================================
# APP START
# =====================================================

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
