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
