# TrustLease  
## Secure Time-Bound Delegated Data Access System

---

## 📌 Project Overview

**TrustLease** is a secure system that allows a data owner to **temporarily delegate access** to sensitive data to another user without sharing credentials.  
Access is **time-bound**, **revocable**, and **cryptographically enforced**, ensuring strong security and controlled data sharing.

This project is developed as part of **23CSE313 – Foundations of Cyber Security (Lab Evaluation 1)** and demonstrates the practical implementation of core security concepts.

---

## 🎯 Objectives

- Implement secure **authentication and multi-factor authentication**
- Enforce **authorization using an Access Control Matrix**
- Protect data using **encryption and secure key exchange**
- Ensure integrity and authenticity using **hashing and digital signatures**
- Demonstrate **encoding techniques** for secure data transfer
- Design a **realistic and original security-focused application**

---

## 👥 User Roles (Subjects)

- **Owner**  
  Uploads data and grants time-bound access to other users.

- **Delegate**  
  Receives temporary, limited access to data based on a valid lease.

- **Admin**  
  Manages system policies and monitors audit logs (no access to user data).

---

## 📦 System Objects

- **Secure Data** – Encrypted user data stored in the system  
- **Access Lease** – Time-bound permission granted by the owner  
- **Audit Logs** – Records of all security-sensitive actions  

---

## 🔐 Core Security Features

### 1. Authentication
- Username and password-based login
- Secure password storage using hashing with salt
- Multi-Factor Authentication (OTP via email)

### 2. Authorization
- Access Control Matrix enforcing permissions
- Role-based and policy-driven access
- Time-bound access validation before every request

### 3. Encryption
- AES encryption for stored data
- RSA-based secure key exchange (hybrid encryption)

### 4. Hashing & Digital Signature
- Salted hashing for passwords
- Hash-based digital signatures on access leases
- Ensures integrity, authenticity, and non-repudiation

### 5. Encoding
- Base64 encoding for access tokens and secure payload transmission

---

## 🧠 Novelty of the System

Unlike traditional systems that rely on static or role-based access, **TrustLease introduces a time-bound delegation model**, where access is **leased temporarily**, automatically expires, and can be revoked at any time.

This approach provides **fine-grained control, improved security, and real-world relevance**, especially for enterprise and cloud-based systems.

---

## 📊 Access Control Matrix

| Subject \ Object | Secure Data | Access Lease | Audit Logs |
|------------------|-------------|--------------|------------|
| Owner            | Read / Write | Create / Revoke | Read |
| Delegate         | Read (if lease valid) | ❌ | ❌ |
| Admin            | ❌ | ❌ | Read |

---

## 🏗️ System Architecture (High-Level)

- **Frontend**: Web Interface
- **Backend**: Flask (Python)
- **Database**: SQLite / PostgreSQL
- **Crypto Engine**: AES, RSA, Hashing, Digital Signature
- **Authentication Module**: Login + OTP
- **Access Control Module**: Lease validation & policy enforcement
- **Audit Module**: Security event logging

---

## 🔁 System Flow Summary

1. User registers and logs in securely  
2. Multi-factor authentication is completed  
3. Owner uploads data (encrypted before storage)  
4. Owner creates a time-bound access lease  
5. Lease is digitally signed and stored  
6. Delegate accesses data only if:
   - authenticated
   - authorized
   - lease is valid and not expired  
7. All actions are logged for auditing  

---

## 🧪 Security Considerations

- Prevents password sharing
- Ensures least-privilege access
- Supports revocation and automatic expiry
- Protects against unauthorized access and data tampering

---

## 📚 Course Alignment

This project satisfies all requirements specified in the **23CSE313 – Foundations of Cyber Security Lab Evaluation 1**, including:
- Authentication & MFA
- Authorization (Access Control)
- Encryption & Key Exchange
- Hashing & Digital Signatures
- Encoding Techniques
- Security analysis and attack awareness

---

## 🧾 Project Status

✅ Phase 0 – Planning & Architecture Completed  
✅ Phase 1 – Backend Setup  
✅ Phase 2 – Authentication  
⬜ Phase 3 – Authorization  
⬜ Phase 4 – Encryption & Key Exchange  
⬜ Phase 5 – Digital Signatures & Encoding  

---

## 👩‍💻 Author

**Shreya B**  
Department of Computer Science and Engineering  
Amrita Vishwa Vidyapeetham

---
