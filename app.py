from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import re
import random
import time
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# =====================================================
# APP CONFIG
# =====================================================

app = Flask(__name__)
app.secret_key = "consensafe_secret_key"
app.permanent_session_lifetime = timedelta(minutes=10)

DB_NAME = "database.db"
ALLOWED_ROLES = ("user", "app", "admin")

# =====================================================
# OTP STORE (IN-MEMORY)
# =====================================================

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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email_enc TEXT NOT NULL,
            phone_enc TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS consents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            app_id INTEGER NOT NULL,
            allowed_fields TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expiry DATETIME NOT NULL,
            status TEXT CHECK(status IN ('approved','revoked')) NOT NULL,
            consent_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (app_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

# =====================================================
# SESSION TIMEOUT (SECURITY HARDENING)
# =====================================================

@app.before_request
def enforce_session_timeout():
    if "user_id" in session:
        now = time.time()
        last = session.get("last_activity")

        if last and now - last > 600:
            session.clear()
            return redirect(url_for("login"))

        session["last_activity"] = now

# =====================================================
# PASSWORD POLICY (NIST-ALIGNED)
# =====================================================

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# =====================================================
# AUTHORIZATION: CONSENT CHECK
# =====================================================

def has_consent(user_id, app_id, field):
    conn = get_db()
    consent = conn.execute("""
        SELECT * FROM consents
        WHERE user_id=? AND app_id=?
        AND status='approved'
        AND expiry > datetime('now')
    """, (user_id, app_id)).fetchone()

    if consent:
        conn.execute(
            "INSERT INTO audit_logs (actor_id, action) VALUES (?, ?)",
            (app_id, f"Accessed {field} of user {user_id}")
        )
        conn.commit()
        conn.close()
        return field in consent["allowed_fields"].split(",")

    conn.execute(
        "INSERT INTO audit_logs (actor_id, action) VALUES (?, ?)",
        (app_id, f"Unauthorized access attempt for {field} of user {user_id}")
    )
    conn.commit()
    conn.close()
    return False

# =====================================================
# ROUTES
# =====================================================

@app.route("/")
def home():
    return redirect(url_for("dashboard")) if "user_id" in session else redirect(url_for("login"))

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
            return "Invalid role"

        if role == "admin":
            return "Admin accounts are created by system only"

        if not is_strong_password(password):
            return "Weak password"

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
                (username, email, generate_password_hash(password), role)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return "User already exists"

    return render_template("register.html")

# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session.permanent = False 
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            session["last_activity"] = time.time()
            return redirect(url_for("dashboard"))

        return "Invalid credentials"

    return render_template("login.html")

# =====================================================
# DASHBOARD (ROLE-BASED)
# =====================================================

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session["role"]

    if role == "user":
        return render_template("dashboard_user.html", username=session["username"])
    if role == "app":
        return render_template("dashboard_app.html", username=session["username"])
    if role == "admin":
        return render_template("dashboard_admin.html", username=session["username"])

    return "Unauthorized", 403

# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =====================================================
# CHANGE PASSWORD
# =====================================================

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        old = request.form["old_password"]
        new = request.form["new_password"]

        if not is_strong_password(new):
            return "Weak password"

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE id=?",
            (session["user_id"],)
        ).fetchone()

        if user and check_password_hash(user["password"], old):
            conn.execute(
                "UPDATE users SET password=? WHERE id=?",
                (generate_password_hash(new), session["user_id"])
            )
            conn.commit()
            conn.close()
            return redirect(url_for("dashboard"))

        conn.close()
        return "Old password incorrect"

    return render_template("change_password.html")

# =====================================================
# FORGOT PASSWORD (OTP)
# =====================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        if not user:
            return "Email not registered"

        otp = str(random.randint(100000, 999999))
        otp_store[email] = {"otp": otp, "expires": time.time() + 300}
        print(f"[OTP for {email}] : {otp}")

        session["reset_email"] = email
        return redirect(url_for("verify_otp"))

    return render_template("forgot_password.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "reset_email" not in session:
        return redirect(url_for("login"))

    email = session["reset_email"]

    if request.method == "POST":
        record = otp_store.get(email)

        if not record or time.time() > record["expires"]:
            return "OTP expired"

        if request.form["otp"] != record["otp"]:
            return "Incorrect OTP"

        otp_store.pop(email)
        session["otp_verified"] = True
        return redirect(url_for("reset_password"))

    return render_template("verify_otp.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if not session.get("otp_verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form["password"]

        if not is_strong_password(password):
            return "Weak password"

        conn = get_db()
        conn.execute(
            "UPDATE users SET password=? WHERE email=?",
            (generate_password_hash(password), session["reset_email"])
        )
        conn.commit()
        conn.close()

        session.clear()
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# =====================================================
# STEP 3: CONSENT WORKFLOW
# =====================================================

@app.route("/request-access", methods=["GET", "POST"])
def request_access():
    if session.get("role") != "app":
        return "Unauthorized", 403

    if request.method == "POST":
        user_id = request.form["user_id"]
        fields = ",".join(request.form.getlist("fields"))
        purpose = request.form["purpose"]
        expiry = request.form["expiry"]

        conn = get_db()
        conn.execute("""
            INSERT INTO consents
            (user_id, app_id, allowed_fields, purpose, expiry, status, consent_hash, signature)
            VALUES (?, ?, ?, ?, ?, 'approved', 'hash_placeholder', 'sig_placeholder')
        """, (user_id, session["user_id"], fields, purpose, expiry))
        conn.commit()
        conn.close()

        return redirect(url_for("dashboard"))

    conn = get_db()
    users = conn.execute("SELECT id, username FROM users WHERE role='user'").fetchall()
    conn.close()

    return render_template("request_access.html", users=users)

@app.route("/my-consents")
def my_consents():
    if session.get("role") != "user":
        return "Unauthorized", 403

    conn = get_db()
    consents = conn.execute("""
        SELECT consents.*, users.username AS app_name
        FROM consents
        JOIN users ON consents.app_id = users.id
        WHERE consents.user_id = ?
    """, (session["user_id"],)).fetchall()
    conn.close()

    return render_template("my_consents.html", consents=consents)

@app.route("/revoke-consent/<int:consent_id>")
def revoke_consent(consent_id):
    if session.get("role") != "user":
        return "Unauthorized", 403

    conn = get_db()
    conn.execute(
        "UPDATE consents SET status='revoked' WHERE id=? AND user_id=?",
        (consent_id, session["user_id"])
    )
    conn.commit()
    conn.close()

    return redirect(url_for("my_consents"))

# =====================================================
# START APP
# =====================================================

if __name__ == "__main__":
    init_db()
    app.run(debug=True)