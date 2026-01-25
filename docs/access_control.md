# Access Control Design – TrustLease

---

## 1. Introduction

Access control is a core security requirement in TrustLease.  
The system ensures that users can access data **only if they are explicitly authorized**, for a **specific purpose**, and for a **limited duration**.

TrustLease uses a **policy-driven Access Control Matrix** combined with **time-bound delegation** to enforce fine-grained authorization.

---

## 2. Access Control Model Used

### Model Chosen: **Access Control Matrix**

The Access Control Matrix model was chosen because:
- It clearly defines **who can access what**
- It is easy to justify and enforce programmatically
- It supports fine-grained permissions
- It aligns directly with the lab evaluation requirements

---

## 3. Subjects (Users)

The system defines the following subjects:

1. **Owner**
   - Creator and owner of the data
   - Responsible for granting and revoking access

2. **Delegate**
   - Receives temporary access from the owner
   - Has no ownership or administrative privileges

3. **Admin**
   - Oversees system operations and audit logs
   - Does not access user data

---

## 4. Objects (Resources)

The system protects the following objects:

1. **Secure Data**
   - Encrypted data uploaded by the owner

2. **Access Lease**
   - Time-bound permission granting access to data

3. **Audit Logs**
   - Records of authentication, authorization, and access events

---

## 5. Access Control Matrix

The following matrix defines the allowed operations:

| Subject \ Object | Secure Data | Access Lease | Audit Logs |
|------------------|-------------|--------------|------------|
| **Owner**        | Read, Write | Create, Revoke | Read |
| **Delegate**     | Read (only if lease is valid) | ❌ | ❌ |
| **Admin**        | ❌ | ❌ | Read |

---

## 6. Policy Definition and Justification

### Owner Policies
- Owners require full read and write access to their own data.
- Owners are allowed to create and revoke access leases.
- Owners can view audit logs related to their data for accountability.

**Justification:**  
Owners are the rightful controllers of their data and must have full authority over access decisions.

---

### Delegate Policies
- Delegates are granted **read-only access**.
- Access is strictly **time-bound**.
- Access is automatically revoked when the lease expires.
- Delegates cannot create, modify, or delegate further access.

**Justification:**  
Delegates should follow the principle of **least privilege**, receiving only the minimum access required.

---

### Admin Policies
- Admins can only view audit logs.
- Admins cannot access user data or leases.

**Justification:**  
This prevents insider threats and protects user privacy while allowing system monitoring.

---

## 7. Time-Bound Delegated Access (Core Feature)

TrustLease introduces **delegated access leases** with the following properties:
- Defined start and expiry time
- Specific data scope
- Non-transferable
- Revocable at any time by the owner

Access is granted **only if the lease is active and valid**.

---

## 8. Enforcement of Access Control

Access control is enforced **programmatically** in the backend:

1. User authentication is verified
2. User role is identified
3. Requested resource is identified
4. Access Control Matrix is checked
5. Lease validity and expiry time are verified
6. Digital signature of the lease is verified
7. Access is granted or denied

All checks must pass before data access is allowed.

---

## 9. Handling Unauthorized Access

If access is denied:
- The request is blocked immediately
- An error response is returned
- The event is logged in audit logs

This helps detect misuse and potential attacks.

---

## 10. Mapping to Lab Evaluation Requirements

| Requirement | Implementation |
|-----------|----------------|
| Access Control Model | Access Control Matrix |
| Policy Definition | Explicit subject–object policies |
| Justification | Least privilege & ownership-based access |
| Enforcement | Backend authorization checks |

---

## 11. Conclusion

The access control mechanism in TrustLease ensures that:
- Only authorized users can access sensitive data
- Access is limited in scope and time
- Permissions are enforced consistently and securely

This design provides a strong foundation for secure, real-world data sharing systems.

---
