# ConsentSafe – Secure Consent-Based Data Access System

**Course:** 23CSE313 – Foundations of Cyber Security  
**Lab Evaluation:** 1  
**Institution:** Amrita Vishwa Vidyapeetham  
**Department:** Computer Science and Engineering

---

## 1. Project Overview

ConsentSafe is a secure, consent-driven web application designed to demonstrate the practical implementation of core cybersecurity concepts including authentication, authorization, encryption, hashing, digital signatures, encoding, and audit logging.

The system simulates a real-world data-sharing scenario where third-party applications can access a user’s sensitive data **only after explicit user approval**, ensuring confidentiality, integrity, and accountability.

---

## 2. Application Scenario

The application models a **consent-based data sharing platform** involving three roles:

- **User** – Owns personal data and grants or revokes consent
- **App** – Requests access to user data for a specific purpose
- **Admin** – Read-only auditor for monitoring and compliance

Sensitive user data includes:

- Email
- Phone number
- Address

---

## 3. User Roles and Responsibilities

### 3.1 User

- Register and log in securely
- View consent requests from apps
- Approve or revoke consents
- Change password
- Reset password using OTP
- View active consents

### 3.2 App

- Request access to user data
- View granted consents
- Access only approved data fields
- View its own audit logs

### 3.3 Admin (Read-Only)

- View all users
- View all consent records
- View complete audit logs
- No permission to access user data
- No permission to approve or revoke consents

---

## 4. Authentication Mechanism

### 4.1 Single-Factor Authentication

- Email and password-based login
- Passwords are never stored in plaintext

### 4.2 Multi-Factor Authentication (MFA)

- OTP-based password reset mechanism
- OTP is:
  - Randomly generated
  - Time-bound (valid for 5 minutes)
  - Single-use

This aligns with the NIST SP 800-63 authentication principles.

---

## 5. Password Security (Hashing with Salt)

- Passwords are stored using **PBKDF2 with SHA-256**
- Each password is salted automatically
- Implemented using Werkzeug’s secure hashing utilities

This protects against:

- Database breaches
- Rainbow table attacks
- Offline brute-force attacks

---

## 6. Encryption and Decryption

Sensitive user data is encrypted before storage:

| Data Field | Protection  |
| ---------- | ----------- |
| Email      | AES-256-CBC |
| Phone      | AES-256-CBC |
| Address    | AES-256-CBC |

- A random Initialization Vector (IV) is used
- Encrypted data is Base64 encoded for safe storage

Even database administrators cannot read plaintext data.

---

## 7. Authorization and Access Control

### 7.1 Consent-Based Access Control Model

Instead of a static Access Control List (ACL), the system uses **dynamic consent-based authorization**.

Each consent record defines:

- User ID
- App ID
- Allowed fields
- Purpose
- Expiry
- Status (`pending`, `approved`, `revoked`)

### 7.2 Consent Lifecycle:

App → Requests Access (pending)
User → Approves/Revokes Consent
System → Allows Data Access

Access is allowed **only when consent is approved and valid**.

---

## 8. Digital Signature and Integrity Protection

To ensure consent integrity:

- A SHA-256 hash is computed for consent data
- The hash is digitally signed using HMAC-SHA256

Before any data access:

- Consent hash is recomputed
- Signature is verified
- Any mismatch results in access denial

This ensures:

- Integrity
- Authenticity
- Non-repudiation

---

## 9. Secure Data Access Enforcement

When an app requests data access, the system verifies:

1. Consent exists
2. Consent status is `approved`
3. Consent has not expired
4. Requested field is allowed
5. Consent hash and signature are valid

Only the permitted field is decrypted and returned.

---

## 10. Encoding

- Encrypted binary data is encoded using **Base64**
- Ensures compatibility with database storage and HTTP transmission

---

## 11. Audit Logging

All sensitive operations are logged in the audit logs table:

Logged events include:

- Consent approval
- Consent revocation
- Data access attempts
- Unauthorized access attempts

Each log contains:

- Actor ID (user/app/admin)
- Action description
- Timestamp

Audit logs ensure traceability and accountability.

---

## 12. Database Schema

### Tables Used

- `users` – Stores authentication credentials and roles
- `user_data` – Stores encrypted personal data
- `consents` – Stores consent records and access permissions
- `audit_logs` – Stores security-related events

---

## 13. Admin Account Setup

Admin accounts are created manually to avoid privilege escalation.

Steps:

1. Generate password hash using:
   ```python
   generate_password_hash("Admin@123")
   ```

## 14.Security Principles Demonstrated

- Confidentiality

- Integrity

- Authentication

- Authorization

- Least Privilege

- Defense in Depth

- Accountability

- Non-repudiation

## 16.How to Run the Application:

```bash
    python3 app.py
```
