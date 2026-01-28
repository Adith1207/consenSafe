from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import re
import random
import time
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# ===== SIGNATURE & HASH IMPORTS (PATCH 3) =====
import hmac
import hashlib

# ===== CRYPTO IMPORTS (PATCH) =====
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# =====================================================
# APP CONFIG
# =====================================================

app = Flask(__name__)
app.secret_key = "consensafe_secret_key"
app.permanent_session_lifetime = timedelta(minutes=10)

DB_NAME = "database.db"
ALLOWED_ROLES = ("user", "app", "admin")

# ===== AES KEY (LAB MODE) =====
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes = AES-256

# ===== SIGNATURE KEY (LAB MODE) =====
SIGN_KEY = b"consensafe_hmac_signing_key"

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
            address_enc TEXT NOT NULL,
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
# AES ENCRYPTION / DECRYPTION (PATCH)
# =====================================================

def encrypt_data(plaintext: str) -> str:
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()


def decrypt_data(encoded_ciphertext: str) -> str:
    raw = base64.b64decode(encoded_ciphertext)
    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()

# =====================================================
# CONSENT HASHING & DIGITAL SIGNATURE (PATCH 3)
# =====================================================

def compute_consent_hash(data: str) -> str:
    """
    Computes SHA-256 hash of consent data
    """
    return hashlib.sha256(data.encode()).hexdigest()


def sign_consent(consent_hash: str) -> str:
    """
    Creates HMAC-SHA256 signature of consent hash
    """
    return hmac.new(
        SIGN_KEY,
        consent_hash.encode(),
        hashlib.sha256
    ).hexdigest()

def verify_consent_integrity(consent):
    """
    Verifies consent hash and digital signature
    """
    data = f"{consent['user_id']}|{consent['app_id']}|" \
           f"{consent['allowed_fields']}|" \
           f"{consent['purpose']}|" \
           f"{consent['expiry']}"

    recomputed_hash = compute_consent_hash(data)

    if recomputed_hash != consent["consent_hash"]:
        return False

    expected_sig = sign_consent(recomputed_hash)
    return hmac.compare_digest(expected_sig, consent["signature"])

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

            # 1️⃣ Insert user (auth data)
            cursor = conn.execute(
                "INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
                (username, email, generate_password_hash(password), role)
            )

            # 2️⃣ Get user_id of newly created user
            user_id = cursor.lastrowid

            # 3️⃣ Encrypt sensitive PII
            email_enc = encrypt_data(email)
            phone_enc = encrypt_data("9999999999")  # placeholder phone for lab
            address_enc = encrypt_data("Chennai, India") # lab placeholder

            # 4️⃣ Store encrypted data
            conn.execute(
                "INSERT INTO user_data (user_id, email_enc, phone_enc,address_enc) VALUES (?, ?, ?,?)",
                (user_id, email_enc, phone_enc,address_enc)
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
        # 1️⃣ Build canonical consent data string
        consent_data = f"{user_id}|{session['user_id']}|{fields}|{purpose}|{expiry}"


        # 2️⃣ Hash the consent
        consent_hash = compute_consent_hash(consent_data)


        # 3️⃣ Digitally sign the hash
        signature = sign_consent(consent_hash)


        conn.execute("""
        INSERT INTO consents
        (user_id, app_id, allowed_fields, purpose, expiry, status, consent_hash, signature)
        VALUES (?, ?, ?, ?, ?, 'approved', ?, ?)
        """, (user_id, session["user_id"], fields, purpose, expiry, consent_hash, signature))

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

@app.route("/access-data/<int:user_id>/<field>")
def access_data(user_id, field):
    if session.get("role") != "app":
        return "Unauthorized", 403

    if field not in ("email", "phone", "address"):
        return "Invalid field", 400

    conn = get_db()

    consent = conn.execute("""
        SELECT * FROM consents
        WHERE user_id=? AND app_id=?
        AND status='approved'
        AND expiry > datetime('now')
    """, (user_id, session["user_id"])).fetchone()

    if not consent:
        conn.close()
        return "No valid consent", 403

    # 🔐 Verify hash & signature
    if not verify_consent_integrity(consent):
        conn.close()
        return "Consent integrity violation", 403

    if field not in consent["allowed_fields"].split(","):
        conn.close()
        return "Field not allowed", 403

    user_data = conn.execute("""
        SELECT email_enc, phone_enc, address_enc
        FROM user_data WHERE user_id=?
    """, (user_id,)).fetchone()

    if not user_data:
        conn.close()
        return "No data found", 404

    # 🔓 Decrypt only permitted field
    if field == "email":
        value = decrypt_data(user_data["email_enc"])
    elif field == "phone":
        value = decrypt_data(user_data["phone_enc"])
    else:
        value = decrypt_data(user_data["address_enc"])

    # 🧾 Audit log
    conn.execute(
        "INSERT INTO audit_logs (actor_id, action) VALUES (?, ?)",
        (session["user_id"], f"Accessed {field} of user {user_id}")
    )

    conn.commit()
    conn.close()

    return {field: value}

@app.route("/granted-access")
def granted_access():
    if session.get("role") != "app":
        return "Unauthorized", 403

    conn = get_db()
    consents = conn.execute("""
        SELECT consents.*, users.username AS user_name
        FROM consents
        JOIN users ON consents.user_id = users.id
        WHERE consents.app_id = ?
    """, (session["user_id"],)).fetchall()
    conn.close()

    return render_template("granted_access.html", consents=consents)

@app.route("/audit-logs")
def audit_logs():
    role = session.get("role")

    if role not in ("app", "admin"):
        return "Unauthorized", 403

    conn = get_db()

    if role == "app":
        logs = conn.execute("""
            SELECT action, timestamp
            FROM audit_logs
            WHERE actor_id = ?
            ORDER BY timestamp DESC
        """, (session["user_id"],)).fetchall()
    else:
        logs = conn.execute("""
            SELECT users.username, audit_logs.action, audit_logs.timestamp
            FROM audit_logs
            JOIN users ON audit_logs.actor_id = users.id
            ORDER BY timestamp DESC
        """).fetchall()

    conn.close()
    return render_template("audit_logs.html", logs=logs, role=role)

# =====================================================
# START APP
# =====================================================

if __name__ == "__main__":
    init_db()
    app.run(debug=True)