# System Architecture – TrustLease

---

## 1. Introduction

TrustLease is designed using a **secure layered client–server architecture** that enforces security controls at every stage of data access.  
The architecture ensures strong separation between user interaction, security enforcement, cryptographic operations, and data storage.

This design supports **time-bound delegated access**, where permissions are granted temporarily, verified continuously, and revoked automatically when expired.

---

## 2. Architectural Overview

The system is divided into three main layers:

1. **Client Layer** – User interaction
2. **Application Layer** – Security enforcement and business logic
3. **Data Storage Layer** – Secure persistence of data and metadata

All security decisions are enforced on the server side.
<h2>Architectural Structure</h2>

<div style="border:1px solid #333; padding:12px; width:70%; margin-bottom:16px;">
  <b>Client Layer</b><br/>
  Web Interface (Browser)
</div>

<div style="margin-left:32px; margin-bottom:16px;">
  ⬇️ HTTPS
</div>

<div style="border:1px solid #333; padding:12px; width:70%; margin-bottom:16px;">
  <b>Application Layer (Backend Server)</b>
  <ul>
    <li>Authentication Module</li>
    <li>Authorization Module</li>
    <li>Lease Management Module</li>
    <li>Cryptography Engine</li>
    <li>Audit & Logging Module</li>
  </ul>
</div>

<div style="margin-left:32px; margin-bottom:16px;">
  ⬇️ Secure DB Access
</div>

<div style="border:1px solid #333; padding:12px; width:70%;">
  <b>Data Storage Layer</b><br/>
  Database (Users, Encrypted Data, Leases, Logs)
</div>



---

## 3. Client Layer

### Responsibilities
- Provides user interface for login, data upload, and access requests
- Sends requests securely to the backend using HTTPS
- Displays system responses and access status

### Security Considerations
- No sensitive data is stored on the client
- No cryptographic keys are exposed
- Client is treated as untrusted
- All authorization decisions occur on the backend

---

## 4. Application Layer

The application layer is the **core of the system** and enforces all security policies.

---

### 4.1 Authentication Module

**Responsibilities:**
- User registration
- Secure password verification using hashing with salt
- Multi-Factor Authentication using OTP

**Security Objective:**  
Ensure that only authenticated users can enter the system.

---

### 4.2 Authorization Module

**Responsibilities:**
- Identify user roles (Owner, Delegate, Admin)
- Enforce the Access Control Matrix
- Validate permissions before every request
- Block unauthorized access attempts

**Security Objective:**  
Ensure role-based and policy-driven access control.

---

### 4.3 Lease Management Module

**Responsibilities:**
- Create time-bound access leases
- Define access scope and duration
- Automatically expire leases after the defined time
- Allow owners to revoke access manually

**Security Objective:**  
Enable secure, temporary delegation of access without sharing credentials.

---

### 4.4 Cryptography Engine

**Responsibilities:**
- Encrypt user data using AES before storage
- Perform secure key exchange using RSA
- Hash sensitive values
- Generate and verify digital signatures
- Support encoding and decoding mechanisms

**Security Objective:**  
Ensure confidentiality, integrity, and authenticity of data.

---

### 4.5 Audit & Logging Module

**Responsibilities:**
- Log authentication events
- Log lease creation, revocation, and expiry
- Log all access attempts (successful and failed)

**Security Objective:**  
Provide accountability and support security auditing.

---

## 5. Data Storage Layer

The data storage layer securely stores:

- User credentials (hashed and salted)
- Role information
- Encrypted user data
- Access lease metadata
- Audit logs

### Storage Security Rules
- Plaintext passwords are never stored
- Decrypted data is never persisted
- Database access is restricted to the backend server only

---

## 6. End-to-End Security Flow

1. User logs in with username and password
2. Multi-factor authentication is completed
3. User role is identified
4. Access request is evaluated using the Access Control Matrix
5. Lease validity and expiry time are checked
6. Digital signature of the lease is verified
7. Data is decrypted only if all checks succeed
8. All actions are recorded in audit logs

---

## 7. Architectural Justification

This architecture was chosen because it:
- Clearly separates security responsibilities
- Centralizes access control enforcement
- Prevents unauthorized data access
- Reduces the impact of component compromise
- Aligns with secure system design principles

---

## 8. Mapping Architecture to Security Concepts

| Security Concept | Architectural Component |
|-----------------|-------------------------|
| Authentication | Authentication Module |
| Authorization | Authorization Module |
| Encryption | Cryptography Engine |
| Hashing | Cryptography Engine |
| Digital Signature | Cryptography Engine |
| Encoding | Cryptography Engine |
| Accountability | Audit & Logging Module |

---

## 9. Conclusion

The TrustLease architecture provides a secure, modular, and well-structured foundation for implementing time-bound delegated data access.  
Each security concept is explicitly mapped to a dedicated architectural component, ensuring clarity, enforceability, and strong security guarantees.

---
