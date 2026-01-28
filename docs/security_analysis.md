1. Introduction

TrustLease is a secure data-sharing system designed to support time-bound delegated access.
The system follows a defense-in-depth approach by combining authentication, authorization, cryptography, and audit logging to protect sensitive resources.

2. Security Objectives

The primary security objectives of TrustLease are:

Confidentiality – Prevent unauthorized data access

Integrity – Detect and prevent data tampering

Authentication – Verify user identity

Authorization – Enforce role-based access

Non-Repudiation – Prevent denial of actions

Accountability – Record all critical actions

3. Security Mechanisms Implemented
3.1 Authentication

Password-based login

Passwords stored using secure hashing with salt

Multi-Factor Authentication using OTP

3.2 Authorization

Role-Based Access Control (RBAC)

Roles include Owner, Delegate, and Admin

Backend-enforced access checks

3.3 Cryptography

AES encryption used for secure data storage

RSA used for digital signatures

Hashing (SHA-256) used for integrity checks

3.4 Delegated Access Control

Time-bound leases define access duration

Automatic lease expiry

Manual revocation by owner

3.5 Audit Logging

All security-critical events are logged

Logs include user, action, timestamp, and IP address

Logs are accessible only to administrators

4. Threat Model
4.1 Threat Actors

Unauthorized external user

Malicious delegate

Compromised user credentials

5. Possible Attacks and Countermeasures
5.1 Password Guessing / Brute Force

Attack: Attacker attempts to guess user passwords
Countermeasure:

Password hashing with salt

Multi-Factor Authentication

5.2 Session Hijacking

Attack: Attacker steals session cookie
Countermeasure:

Server-side session validation

OTP verification before session activation

5.3 Privilege Escalation

Attack: Delegate attempts owner/admin actions
Countermeasure:

Role-based access control

Backend permission enforcement

5.4 Lease Tampering

Attack: Modify lease details in database
Countermeasure:

Lease hashing

Digital signature verification

5.5 Replay Attacks

Attack: Reusing old access tokens
Countermeasure:

Time-bound leases

Token validation against active lease

5.6 Unauthorized Resource Access

Attack: Accessing resources via URL manipulation
Countermeasure:

Authorization checks on every request

Token verification and role validation

6. Encoding vs Encryption

Encoding (Base64) is used only for safe token transport

Encryption (AES) is used for data confidentiality

Encoding does not provide security by itself

7. Security Strength Summary
Security Aspect	   Implemented
Authentication	    ✅
MFA	                ✅
Authorization	    ✅
Encryption	        ✅
Digital Signature	✅
Audit Logging	    ✅

8. Conclusion

TrustLease successfully demonstrates a secure system design by integrating authentication, authorization, cryptographic protection, delegated access control, and audit logging.
The system is resilient against common attacks and follows best practices in secure application development.