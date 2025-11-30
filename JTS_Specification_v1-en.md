# Project Archive Document: Janus Token System (JTS)

**Title:** Janus Token System (JTS): A Two-Component Architecture for Secure, Revocable, and Confidential API Authentication

**Status:** Standard Draft, Version 1.1

**Author/Pioneer:** ukungzulfah

**Publication Date:** November 30, 2025

> **Abstract:**
> This document defines the **Janus Token System (JTS)**, a new authentication standard designed to address security and scalability challenges in modern distributed application ecosystems (e.g., microservices architecture). JTS introduces a two-component architecture that fundamentally separates **short-term access proof (`BearerPass`)** from **long-term session proof (`StateProof`)**. This approach enables extremely fast and *stateless* access verification while retaining the vital capability for *stateful* session management, including instant session revocation. This document defines three operational profiles: **JTS-S (Standard)** for full integrity with complete security features, **JTS-L (Lite)** for lightweight implementation with minimal complexity, and **JTS-C (Confidentiality)** for total payload confidentiality. This specification also introduces new claim terminology to replace less intuitive legacy terms.

---

### **Copyright License**
> Copyright © 2025, ukungzulfah. All Rights Reserved.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this specification and associated documentation ("the Software"), to use, copy, modify, merge, publish, distribute, and/or sell copies of the Software, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

---

### **1. Introduction**

#### **1.1. Modern Authentication Challenges**
In modern software architecture, applications are broken down into small, independent services (microservices). This model demands an authentication system that is lightweight, decentralized, and not reliant on a single, monolithic centralized session.

#### **1.2. Limitations of Early-Generation Stateless Token Models**
First-generation stateless token-based authentication models provided a partial solution but introduced significant weaknesses:
1.  **Session Revocation Vulnerability:** Issued tokens cannot be forcibly invalidated from the server-side before their expiration time.
2.  **Information Exposure:** The token payload is often merely encoded, not encrypted, so the data within can be read by any party holding the token.
3.  **Key Management Complexity:** The use of a shared symmetric key creates a high-risk single point of failure in a distributed environment.

#### **1.3. A New Paradigm: Janus Token System (JTS)**
JTS is proposed as an evolution to address these weaknesses. With its principle of duality, JTS combines *stateless* efficiency with *stateful* security.

### **2. Core JTS Concepts**

#### **2.1. Duality Principle**
JTS separates the role of a token into two:
1.  **Access:** Granting permission to access resources for a very short duration.
2.  **Session:** Proving the validity of the user's overall authentication session.

#### **2.2. The Two JTS Components**
1.  **`BearerPass`:** A cryptographically signed, short-lived access token. It is used in every API request and verified statelessly.
2.  **`StateProof`:** An opaque and stateful long-lived session token. It is used exclusively to obtain a new `BearerPass` and is stored securely on the client-side. Its existence in the server's database determines the validity of a session.

### **3. JTS Terminology and Claims**

As a refinement, JTS introduces more explicit and intuitive claim terminology, moving away from ambiguous legacy terms.

| JTS Claim | Full Name       | Description                                                                 | Replaces |
| :-------- | :-------------- | :-------------------------------------------------------------------------- | :------- |
| **`prn`** | **Principal**   | Unique identifier for the authenticated principal (usually a user).         | `sub`    |
| **`aid`** | **Anchor ID**   | A unique ID that "anchors" the `BearerPass` to the session record on the server. | `sid`    |
| **`tkn_id`**| **Token ID**      | A unique identifier for each `BearerPass`, preventing replay attacks.        | `jti`    |
| `exp`     | Expiration Time | Token expiration time (retained from RFC 7519).                             | -        |
| `aud`     | Audience        | The intended recipient for this token (retained from RFC 7519).             | -        |
| `iat`     | Issued At       | The time the token was issued (retained from RFC 7519).                     | -        |

#### **3.2. Extended Claims**

JTS defines additional claims for more robust security and functionality:

| JTS Claim | Full Name          | Description                                                               | Required |
| :-------- | :----------------- | :------------------------------------------------------------------------ | :------- |
| **`dfp`** | **Device Fingerprint** | Hash of device characteristics for binding the token to a specific device. | No       |
| **`perm`**| **Permissions**    | An array of strings defining the permissions/scopes the token holds.      | No       |
| **`grc`** | **Grace Period**   | Time tolerance (in seconds) after `exp` for in-flight requests.           | No       |
| **`org`** | **Organization**   | Tenant/organization identifier for multi-tenant systems.                | No       |
| **`atm`** | **Auth Method**    | Authentication method used (e.g., `pwd`, `mfa:totp`, `sso`).              | No       |
| **`ath`** | **Auth Time**      | Unix timestamp of when the user last performed an active authentication.    | No       |
| **`spl`** | **Session Policy** | The concurrent session policy in effect (`allow_all`, `single`, `max:n`). | No       |

**Example Payload with Extended Claims:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "tkn_id": "token-instance-98765",
  "aud": "https://api.example.com/billing",
  "exp": 1764515700,
  "iat": 1764515400,
  "dfp": "sha256:a1b2c3d4e5f6...",
  "perm": ["read:profile", "write:posts", "billing:view"],
  "grc": 30,
  "org": "tenant-acme-corp",
  "atm": "mfa:totp",
  "ath": 1764512000
}
```

### **4. Standard Profile: JTS-S (Integrity)**

This profile focuses on speed, integrity, and session revocation capabilities.

#### **4.1. `BearerPass` Structure (JWS Format)**
`BearerPass` in the JTS-S profile is a **JSON Web Signature (JWS)** signed with **asymmetric cryptography (e.g., RS256)**.

**Example Header:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

**Note:** The `kid` (Key ID) claim is MANDATORY to support key rotation (see Section 7).

**Example Payload:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "tkn_id": "token-instance-98765",
  "aud": "https://api.example.com/billing",
  "exp": 1764515700,
  "iat": 1764515400
}
```

#### **4.2. Workflow**
1.  **Authentication:** User logs in -> Server creates a session record in the DB, generating a `StateProof` (stored in the DB) and a `BearerPass` (JWS). The `StateProof` is sent via an `HttpOnly` cookie, the `BearerPass` via the JSON body.
2.  **Resource Access:** Client sends the `BearerPass` in the header -> Server verifies the JWS signature using the public key.
3.  **Renewal:** `BearerPass` expires -> Client calls the `/renew` endpoint with the `StateProof` in the cookie -> Server validates the `StateProof` in the DB; if valid, issues a new `BearerPass`.
4.  **Revocation (Logout):** Client calls `/logout` -> Server deletes the session record associated with the `StateProof` from the DB. The session becomes immediately invalid.

#### **4.3. Cookie Requirements and CSRF Protection**

The `StateProof` stored in a cookie MUST meet the following security requirements:

**MANDATORY Cookie Attributes:**
```
Set-Cookie: jts_state_proof=<token>; 
  HttpOnly; 
  Secure; 
  SameSite=Strict; 
  Path=/jts; 
  Max-Age=604800
```

| Attribute   | Value       | Description                                                   |
| :---------- | :---------- | :------------------------------------------------------------ |
| `HttpOnly`  | MANDATORY   | Prevents access from JavaScript (mitigates XSS).              |
| `Secure`    | MANDATORY   | Cookie is only sent over HTTPS.                               |
| `SameSite`  | `Strict`    | Prevents sending the cookie on cross-site requests (mitigates CSRF). |
| `Path`      | `/jts`      | Limits the cookie to be sent only to JTS endpoints.           |
| `Max-Age`   | As per policy | Cookie lifetime according to session policy.                  |

**Additional CSRF Protection:**

For the `/renew` and `/logout` endpoints, the server MUST validate at least ONE of the following mechanisms:

1.  **Origin Header Validation:** Ensure the `Origin` or `Referer` header comes from an allowed domain.
2.  **Custom Header Requirement:** Require a custom header that cannot be set by a standard form submission:
    ```
    X-JTS-Request: 1
    ```
3.  **Double-Submit Cookie Pattern:** Send a CSRF token value in both a cookie AND in the request body/header, then validate that they match.

#### **4.4. StateProof Rotation**

To enhance security and detect token theft, JTS REQUIRES `StateProof` rotation on every renewal operation.

**Mechanism:**
1.  Client calls `/renew` with the old `StateProof`.
2.  Server validates the old `StateProof` in the database.
3.  If valid:
    a.  Server DELETES or MARKS the old `StateProof` as *consumed*.
    b.  Server issues a NEW `StateProof` and a new `BearerPass`.
    c.  The new `StateProof` is sent via a `Set-Cookie` header.
4.  If the old `StateProof` is already marked *consumed* (replay detected):
    a.  The server MUST immediately revoke ALL sessions associated with that `aid`.
    b.  The server MUST return a `JTS-401-05` (Session Compromised) error.
    c.  The server SHOULD send a security notification to the user.

**Rotation Diagram:**
```
[Client]                              [Auth Server]                    [Database]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|                               |
    |                                       |-- Validate StateProof_v1 ---->|
    |                                       |<-- Valid, mark as consumed ---|
    |                                       |                               |
    |                                       |-- Generate StateProof_v2 ---->|
    |                                       |<-- Stored --------------------|
    |                                       |                               |
    |<-- 200 OK (BearerPass_new) -----------|                               |
    |<-- Set-Cookie: StateProof_v2 ---------|                               |
    |                                       |                               |
```

**Anomaly Detection (Replay Attack):**
```
[Attacker]                            [Auth Server]                    [Database]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|  (stolen token)               |
    |                                       |-- Validate StateProof_v1 ---->|
    |                                       |<-- CONSUMED! Replay detected -|
    |                                       |                               |
    |                                       |-- REVOKE all sessions (aid) ->|
    |                                       |<-- Done ----------------------|
    |                                       |                               |
    |<-- 401 JTS-401-05 (Compromised) ------|
    |                                       |                               |
```

#### **4.5. Handling Race Conditions in Concurrent Renewals**

In scenarios where a user has multiple tabs/windows or renewal requests occur almost simultaneously, there is a risk of a *false positive* replay detection. JTS defines a **Rotation Grace Window** mechanism to handle this condition.

**Problem:**
```
[Tab A]                               [Auth Server]                    [Database]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Mark SP_v1 consumed -------->|
    |                                     |                               |
[Tab B]  (slightly delayed)              |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Check SP_v1 --------------->|
    |                                     |<-- CONSUMED! (false positive) |
    |<-- 401 JTS-401-05 ??? --------------|  (user not compromised!)      |
```

**Solution: Rotation Grace Window**

The server MUST implement a **rotation grace window** with the following specifications:

1.  **Grace Window Duration:** The server MUST store the `previous_state_proof` for **5-10 seconds** after a rotation.
2.  **Dual Validation:** During the grace window, the server MUST accept BOTH the `current_state_proof` AND the `previous_state_proof`.
3.  **Response for Previous Token:** If a request uses a `previous_state_proof` that is still within the grace window:
    -   The server MUST return the SAME `StateProof` and `BearerPass` that were already generated for the `current_state_proof`.
    -   The server MUST NOT generate new tokens (prevents token divergence).
4.  **After Grace Window:** A request with a `previous_state_proof` that has passed the grace window MUST be treated as a replay attack.

**Database Implementation:**
```sql
CREATE TABLE jts_sessions (
    aid                   VARCHAR(64) PRIMARY KEY,
    prn                   VARCHAR(128) NOT NULL,
    current_state_proof   VARCHAR(256) NOT NULL,
    previous_state_proof  VARCHAR(256),           -- Previous token
    rotation_timestamp    TIMESTAMP,              -- When the last rotation occurred
    -- ... other columns
);
```

**Validation Logic:**
```
function validate_state_proof(incoming_sp):
    session = db.find_by_current_sp(incoming_sp)
    if session:
        return VALID, session
    
    session = db.find_by_previous_sp(incoming_sp)
    if session:
        grace_window = 10 seconds
        if now() - session.rotation_timestamp < grace_window:
            return VALID_WITHIN_GRACE, session  // Return existing tokens
        else:
            trigger_replay_detection(session.aid)
            return REPLAY_DETECTED, null
    
    return INVALID, null
```

**Concurrent Renewal Diagram (Handled):**
```
[Tab A]                               [Auth Server]                    [Database]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Rotate: SP_v1 -> SP_v2 ---->|
    |                                     |   (store previous=SP_v1)      |
    |<-- 200 OK (BP_new, SP_v2) ----------|                               |
    |                                     |                               |
[Tab B]  (within 10 seconds)             |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Check SP_v1 --------------->|
    |                                     |<-- Found in previous_sp,      |
    |                                     |    within grace window -------|
    |<-- 200 OK (BP_new, SP_v2) ----------|  (same tokens as Tab A)       |
    |                                     |                               |
```

> **Note:** Both tabs now have the same `StateProof` (SP_v2), thus remaining synchronized.

#### **4.6. Grace Period for In-Flight Requests**

To handle race conditions where a `BearerPass` expires while a request is in flight:

**Specification:**
-   A Resource Server MAY provide a time tolerance (*grace period*) after the `exp` time.
-   The grace period MUST NOT exceed **60 seconds**.
-   If the `grc` claim is present in the payload, its value defines the grace period in seconds.
-   If the `grc` claim is not present, the default grace period is **0 seconds** (no tolerance).

**Validation Logic:**
```
current_time = now()
effective_expiry = token.exp + token.grc (or 0 if grc is not present)

if current_time > effective_expiry:
    return ERROR_TOKEN_EXPIRED
else:
    return VALID
```

**Note:** The grace period does NOT extend the token's lifetime for auditing purposes. The original `exp` time is still used for logging.

### **5. Lite Profile: JTS-L (Lite)**

This profile is designed for low-complexity use cases that require ease of implementation without sacrificing the core security principles of JTS.

#### **5.1. When to Use JTS-L**

JTS-L is suitable for the following scenarios:

| Scenario                        | Recommendation      | Reason                                             |
| :------------------------------ | :------------------ | :------------------------------------------------- |
| Startup MVP / Prototype         | ✅ JTS-L            | Quick to implement, can be upgraded to JTS-S later. |
| Internal Tools / Admin Panel    | ✅ JTS-L            | Small user base, lower risk.                       |
| Simple Single-Page Application  | ✅ JTS-L            | No need for complex replay detection.              |
| Public API with sensitive data  | ❌ Use JTS-S        | Needs replay protection and device binding.        |
| Fintech / Healthcare            | ❌ Use JTS-S/C      | Maximum compliance and security required.          |
| Multi-tenant SaaS               | ❌ Use JTS-S        | Needs isolation and complete audit trails.         |

#### **5.2. Key Differences from JTS-S**

| Feature                   | JTS-S (Standard)                 | JTS-L (Lite)                    |
| :------------------------ | :------------------------------- | :------------------------------ |
| StateProof Rotation       | ✅ MANDATORY every `/renew`      | ❌ OPTIONAL                     |
| Replay Detection          | ✅ Built-in via consumed marking | ⚠️ Manual / none                 |
| Device Fingerprint (`dfp`)  | ✅ Recommended                   | ❌ Not required                 |
| Grace Period (`grc`)      | ✅ Supported                     | ✅ Supported                     |
| Extended Claims           | ✅ Full                          | ⚠️ Minimal subset               |
| Concurrent Session Policy | ✅ Complete                      | ⚠️ Only `allow_all`              |
| Database Complexity       | High (tracking consumed tokens)  | Low (simple session table)      |
| Error Codes               | Complete (all codes)             | Essential subset                |

#### **5.3. JTS-L `BearerPass` Structure**

`BearerPass` in JTS-L still uses **JWS with asymmetric cryptography**, but with a more minimalist payload.

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JTS-L/v1",
  "kid": "auth-server-key-2025-001"
}
```

**Minimal Payload:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "exp": 1764515700,
  "iat": 1764515400
}
```

**Note:** The `tkn_id` claim is **OPTIONAL** in JTS-L because replay detection is not required.

#### **5.4. JTS-L Workflow (Simplified)**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JTS-L SIMPLIFIED FLOW                                 │
└─────────────────────────────────────────────────────────────────────────────┘

[Client]                              [Auth Server]                    [Database]
    │                                       │                               │
    │── POST /login (credentials) ─────────>│                               │
    │                                       │── Create Session ────────────>│
    │                                       │<── Session ID ────────────────│
    │<── 200 OK ────────────────────────────│                               │
    │    BearerPass (body)                  │                               │
    │    StateProof (cookie)                │                               │
    │                                       │                               │
    │   ... BearerPass expires ...          │                               │
    │                                       │                               │
    │── POST /renew (StateProof) ──────────>│                               │
    │                                       │── Check Session Exists ──────>│
    │                                       │<── Valid ─────────────────────│
    │                                       │   (NO rotation, NO consumed)  │
    │<── 200 OK ────────────────────────────│                               │
    │    BearerPass_new (body)              │                               │
    │    (StateProof unchanged)             │                               │
    │                                       │                               │
```

**Key Differences:**
-   `StateProof` is **NOT rotated** on each `/renew`—the same token can be used multiple times as long as the session is active.
-   The server only needs to check if the session record **exists** in the database, without needing to track a "consumed" status.
-   Database complexity is significantly reduced.

#### **5.5. JTS-L Database Schema**

The database for JTS-L is much simpler:

```sql
-- JTS-L: Simple Session Table
CREATE TABLE jts_sessions (
    aid             VARCHAR(64) PRIMARY KEY,  -- Anchor ID (StateProof)
    prn             VARCHAR(128) NOT NULL,    -- Principal (User ID)
    created_at      TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    last_active     TIMESTAMP DEFAULT NOW(),
    user_agent      TEXT,                     -- Optional: for session list
    ip_address      VARCHAR(45)               -- Optional: for audit
);

-- Index for query by user
CREATE INDEX idx_sessions_prn ON jts_sessions(prn);
```

**Compare with JTS-S which requires:**
```sql
-- JTS-S: Full Session Table with Rotation Tracking
CREATE TABLE jts_sessions (
    aid                  VARCHAR(64) PRIMARY KEY,
    prn                  VARCHAR(128) NOT NULL,
    current_state_proof  VARCHAR(256) NOT NULL,
    previous_state_proof VARCHAR(256),        -- For grace window
    state_proof_version  INTEGER DEFAULT 1,
    consumed_at          TIMESTAMP,             -- Replay detection
    device_fingerprint   VARCHAR(128),
    created_at           TIMESTAMP DEFAULT NOW(),
    expires_at           TIMESTAMP NOT NULL,
    last_active          TIMESTAMP DEFAULT NOW(),
    -- ... more columns
);

-- Additional table for tracking consumed tokens
CREATE TABLE jts_consumed_tokens (
    tkn_id          VARCHAR(64) PRIMARY KEY,
    aid             VARCHAR(64) REFERENCES jts_sessions(aid),
    consumed_at     TIMESTAMP DEFAULT NOW()
);
```

#### **5.6. Subset of Error Codes for JTS-L**

JTS-L is only REQUIRED to implement the following subset of error codes:

| Error Code   | Error Key            | Description                                 |
| :----------- | :------------------- | :------------------------------------------ |
| `JTS-400-01` | `malformed_token`    | The token could not be parsed.              |
| `JTS-401-01` | `bearer_expired`     | The BearerPass has expired.                 |
| `JTS-401-02` | `signature_invalid`  | The signature is invalid.                   |
| `JTS-401-03` | `stateproof_invalid` | The StateProof is invalid.                  |
| `JTS-401-04` | `session_terminated` | The session has been terminated.            |

**The following error codes are NOT required in JTS-L:**
-   `JTS-401-05` (session_compromised) — no replay detection
-   `JTS-401-06` (device_mismatch) — no device binding
-   `JTS-403-03` (org_mismatch) — no multi-tenant support

#### **5.7. Migrating from JTS-L to JTS-S**

JTS-L is designed to be easily upgradable to JTS-S as security needs increase:

**Migration Steps:**

1.  **Update Header Type:**
    ```json
    // Before
    { "typ": "JTS-L/v1" }
    // After
    { "typ": "JTS-S/v1" }
    ```

2.  **Add Database Columns:**
    ```sql
    ALTER TABLE jts_sessions 
    ADD COLUMN current_state_proof VARCHAR(256),
    ADD COLUMN state_proof_version INTEGER DEFAULT 1,
    ADD COLUMN consumed_at TIMESTAMP,
    ADD COLUMN device_fingerprint VARCHAR(128);
    ```

3.  **Implement StateProof Rotation:** Update the `/renew` logic to generate a new StateProof.

4.  **Add `tkn_id` to Payload:** Start generating a unique token ID for each BearerPass.

5.  **Gradual Rollout:** 
    -   Phase 1: Server accepts both JTS-L and JTS-S tokens
    -   Phase 2: All new tokens are JTS-S
    -   Phase 3: Reject JTS-L tokens after the max session lifetime

#### **5.8. JTS-L Limitations and Risks**

> ⚠️ **WARNING:** Implementers MUST understand the following risks before choosing JTS-L:

| Risk                        | Impact                                                        | Mitigation                               |
| :-------------------------- | :------------------------------------------------------------ | :--------------------------------------- |
| **No replay detection**     | A stolen StateProof can be used multiple times without detection. | Use a shorter `exp` for the session.       |
| **No device binding**       | The token can be used from a different device.                | Implement IP-based rate limiting.        |
| **Theft is not detected**   | The user will not be notified if their token is stolen.       | Monitor login patterns, notify on new IP.  |

**Mitigation Recommendations for JTS-L:**
-   Set a shorter `StateProof` expiry (max 24 hours vs. 7 days in JTS-S)
-   Implement rate limiting on the `/renew` endpoint
-   Log all renewal activity for manual auditing
-   Consider email notifications for logins from a new IP/location

---

### **6. Confidentiality Profile: JTS-C (Confidentiality)**

This profile adds a layer of encryption for total payload confidentiality.

#### **6.1. `BearerPass` Structure (JWE Format)**
`BearerPass` in the JTS-C profile is a **JSON Web Encryption (JWE)**. The JWS token from the standard profile is "wrapped" or encrypted into a JWE.

#### **6.2. Workflow**
*   **Token Creation ("Signed-then-Encrypted"):**
    1.  Create a JWS as in the JTS-S profile.
    2.  Encrypt the entire JWS using the **public key of the intended Resource Server**. The result is a JWE.
*   **Token Verification ("Decrypted-then-Verified"):**
    1.  The Resource Server receives the JWE.
    2.  The server decrypts the JWE using its **own private key**. The result is the original JWS.
    3.  The server verifies the JWS using the **public key of the Authentication Server**.

### **7. Security Analysis and Error Handling**

#### **7.1. Security Analysis**

*   **Session Revocation:** Fully resolved through the management of `StateProof` in the server's database.
*   **Credential Leakage:** Minimized by the mandatory use of asymmetric cryptography and securing the `StateProof` in an `HttpOnly` cookie.
*   **Information Leakage:** Minimized in JTS-S/JTS-L with a minimalist payload and fully resolved in JTS-C through JWE encryption.
*   **Replay Attacks:** Mitigated with a unique `tkn_id` and **StateProof rotation** in JTS-S. **Note:** JTS-L does not provide automatic replay protection.
*   **XSS Attacks:** The risk of `StateProof` session token theft is significantly reduced due to the `HttpOnly` flag on the cookie.
*   **CSRF Attacks:** Mitigated by a combination of `SameSite=Strict` and additional header validation.
*   **Token Theft:** Mitigated with **Device Fingerprint (`dfp`)** in JTS-S. **Note:** JTS-L does not support device binding.

#### **7.2. Standard Error Codes**

JTS defines standard error codes for implementation consistency and ease of debugging:

**Error Response Format:**
```json
{
  "error": "bearer_expired",
  "error_code": "JTS-401-01",
  "message": "BearerPass has expired",
  "action": "renew",
  "retry_after": 0,
  "timestamp": 1764515800
}
```

**List of Error Codes:**

| Error Code    | HTTP Status | Error Key              | Description                                            | Action   |
| :------------ | :---------- | :--------------------- | :----------------------------------------------------- | :------- |
| `JTS-400-01`  | 400         | `malformed_token`      | Token could not be parsed or has an invalid format.    | `reauth` |
| `JTS-400-02`  | 400         | `missing_claims`       | Required claims are missing from the token.            | `reauth` |
| `JTS-401-01`  | 401         | `bearer_expired`       | The BearerPass has expired.                            | `renew`  |
| `JTS-401-02`  | 401         | `signature_invalid`    | The BearerPass signature is invalid.                   | `reauth` |
| `JTS-401-03`  | 401         | `stateproof_invalid`   | The StateProof is invalid or not found in the DB.      | `reauth` |
| `JTS-401-04`  | 401         | `session_terminated`   | The session was terminated (logout or concurrent policy).| `reauth` |
| `JTS-401-05`  | 401         | `session_compromised`  | A replay attack was detected; all sessions are revoked.| `reauth` |
| `JTS-401-06`  | 401         | `device_mismatch`      | The device fingerprint does not match.                 | `reauth` |
| `JTS-403-01`  | 403         | `audience_mismatch`    | The token is not intended for this resource.           | `none`   |
| `JTS-403-02`  | 403         | `permission_denied`    | The token does not have the required permissions.      | `none`   |
| `JTS-403-03`  | 403         | `org_mismatch`         | The token belongs to a different organization/tenant.  | `none`   |
| `JTS-500-01`  | 500         | `key_unavailable`      | The public key for verification is unavailable.        | `retry`  |

**Action Values:**
-   `renew`: The client should call the `/renew` endpoint to get a new BearerPass.
-   `reauth`: The user must re-authenticate (log in).
-   `retry`: The request can be retried after `retry_after` seconds.
-   `none`: No action can fix this condition.

### **8. Key Management**

#### **8.1. Key ID Requirement**

Every `BearerPass` MUST include a `kid` (Key ID) claim in the header to identify the key used for signing.

**Header Format with kid:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

#### **8.2. Key Rotation Procedure**

To replace a signing key without invalidating already issued tokens:

**Steps:**
1.  **Generate New Key Pair:** Create a new key pair with a unique `kid`.
2.  **Publish Public Key:** Add the new public key to the JWKS endpoint. The server MUST support multiple active public keys.
3.  **Start Signing with New Key:** All new `BearerPass` tokens are signed with the new key.
4.  **Retire Old Key:** After `max_bearer_lifetime` + buffer (recommendation: 15 minutes), remove the old public key from the JWKS.

**JWKS Endpoint Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "auth-server-key-2025-002",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "auth-server-key-2025-001",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB",
      "exp": 1764520000
    }
  ]
}
```

**Note:** The `exp` field in a key entry indicates when the key will be retired (optional, for client information).

#### **8.3. Standard JWKS Endpoint**

JTS defines a standard path for the JWKS (JSON Web Key Set) endpoint so that Resource Servers can consistently find public keys.

**Standard Path:**
```
GET /.well-known/jts-jwks
```

**Requirements:**

| Aspect           | Specification                                         |
| :--------------- | :---------------------------------------------------- |
| **Path**         | `/.well-known/jts-jwks` (MANDATORY)                   |
| **Method**       | `GET`                                                 |
| **Authentication** | Not required (public endpoint)                        |
| **Content-Type** | `application/json`                                    |
| **CORS**         | MUST allow cross-origin requests from valid domains |

**Caching:**

The server MUST include appropriate caching headers:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600, stale-while-revalidate=60
ETag: "jwks-v2-abc123"
```

| Header                   | Recommended Value      | Description                                               |
| :----------------------- | :--------------------- | :-------------------------------------------------------- |
| `Cache-Control`          | `max-age=3600`         | Cache for 1 hour.                                         |
| `stale-while-revalidate` | `60`                   | Allow a stale response for 60 seconds while revalidating. |
| `ETag`                   | Hash of the JWKS content | For conditional requests.                                 |

**Discovery (Optional):**

To support auto-discovery, the Auth Server MAY provide a metadata endpoint:

```
GET /.well-known/jts-configuration
```

**Response:**
```json
{
  "issuer": "https://auth.example.com",
  "jwks_uri": "https://auth.example.com/.well-known/jts-jwks",
  "token_endpoint": "https://auth.example.com/jts/login",
  "renewal_endpoint": "https://auth.example.com/jts/renew",
  "revocation_endpoint": "https://auth.example.com/jts/logout",
  "supported_profiles": ["JTS-L/v1", "JTS-S/v1", "JTS-C/v1"],
  "supported_algorithms": ["RS256", "ES256"]
}
```

#### **8.4. Supported Algorithms**

JTS recommends the following algorithms:

| Algorithm | Type       | Recommendation       | Notes                                      |
| :-------- | :--------- | :------------------- | :----------------------------------------- |
| `RS256`   | Asymmetric | RECOMMENDED          | RSA with SHA-256, widely supported.        |
| `RS384`   | Asymmetric | SUPPORTED            | RSA with SHA-384.                          |
| `RS512`   | Asymmetric | SUPPORTED            | RSA with SHA-512.                          |
| `ES256`   | Asymmetric | RECOMMENDED          | ECDSA with P-256, more efficient.          |
| `ES384`   | Asymmetric | SUPPORTED            | ECDSA with P-384.                          |
| `ES512`   | Asymmetric | SUPPORTED            | ECDSA with P-521.                          |
| `PS256`   | Asymmetric | SUPPORTED            | RSASSA-PSS with SHA-256.                   |
| `HS256`   | Symmetric  | **NOT ALLOWED**      | Does not align with JTS principles.        |
| `HS384`   | Symmetric  | **NOT ALLOWED**      | Does not align with JTS principles.        |
| `HS512`   | Symmetric  | **NOT ALLOWED**      | Does not align with JTS principles.        |
| `none`    | -          | **FORBIDDEN**        | No signature, highly insecure.             |

### **9. Concurrent Session Policy**

JTS defines policies to handle situations where a single user has multiple active sessions.

> **Note:** Concurrent session policies only apply to **JTS-S** and **JTS-C**. The **JTS-L** profile only supports the `allow_all` policy by default.

#### **9.1. Policy Options**

| Policy          | `spl` Claim | Behavior                                                  |
| :-------------- | :---------- | :-------------------------------------------------------- |
| **Allow All**   | `allow_all` | All sessions are valid simultaneously without limits.       |
| **Single**      | `single`    | Only one active session. A new login invalidates the old one. |
| **Max N**       | `max:3`     | Maximum of N active sessions. The oldest is evicted if exceeded. |
| **Notify**      | `notify`    | All sessions are valid, but the user is notified of others. |

#### **9.2. Implementation**

When a user logs in and the policy limits the number of sessions:
```
1. User logs in -> Server checks the number of active sessions for this `prn`
2. If count >= limit:
   a. "single" policy: Revoke all old sessions, create a new one
   b. "max:n" policy: Revoke the oldest session (FIFO), create a new one
3. Create a new session record in the DB
4. Return StateProof and BearerPass
```

#### **9.3. Session Notification**

For the `notify` policy, the server SHOULD provide an endpoint to view active sessions:

```
GET /jts/sessions
Authorization: Bearer <BearerPass>

Response:
{
  "sessions": [
    {
      "aid": "session-anchor-abc",
      "device": "Chrome on Windows",
      "ip_prefix": "192.168.1.x",
      "created_at": 1764500000,
      "last_active": 1764515000,
      "current": true
    },
    {
      "aid": "session-anchor-def",
      "device": "Safari on iPhone",
      "ip_prefix": "10.0.0.x",
      "created_at": 1764400000,
      "last_active": 1764510000,
      "current": false
    }
  ]
}
```

### **10. Multi-Platform Support**

#### **10.1. Web Platform (Default)**

For web applications, `StateProof` is stored in an `HttpOnly` cookie as per Section 4.3.

#### **10.2. Mobile/Native Platforms**

For native mobile and desktop applications where cookies are not practical:

**Storage:**
-   **iOS:** Keychain Services with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
-   **Android:** EncryptedSharedPreferences or Keystore System
-   **Desktop:** OS Credential Manager (Windows Credential Vault, macOS Keychain)

**StateProof Submission:**
```
POST /jts/renew
X-JTS-StateProof: <encrypted_state_proof>
Content-Type: application/json
```

**Additional Requirements for Non-Cookie:**
-   The `StateProof` MUST be encrypted when stored on the client.
-   Requests with the `X-JTS-StateProof` header MUST include an `X-JTS-Device-ID` for validation.
-   The server MUST validate that the `Device-ID` matches the one registered during the initial authentication.

#### **10.3. Server-to-Server (M2M)**

For machine-to-machine communication:

-   `StateProof` is NOT used (no concept of a "user session").
-   `BearerPass` is issued with a longer `exp` (recommendation: 1 hour).
-   The `prn` claim contains a service/machine identifier, not a user.
-   The `atm` claim is set to `client_credentials`.

**Example M2M Payload:**
```json
{
  "prn": "service:payment-processor",
  "aid": "m2m-static-anchor",
  "tkn_id": "token-m2m-12345",
  "aud": "https://api.example.com/internal",
  "exp": 1764519000,
  "iat": 1764515400,
  "atm": "client_credentials",
  "perm": ["internal:process_payment", "internal:read_accounts"]
}
```

### **11. Conclusion**

Janus Token System (JTS) offers a balanced authentication framework, combining the high performance of stateless verification with the strict security controls of stateful session management. With its two-component architecture, clear terminology, and flexible operational profiles, JTS is designed to be a robust and secure authentication standard for the next generation of applications.

**Three Profiles for Various Needs:**

| Profile                   | Use Case                           | Complexity | Security      |
| :------------------------ | :--------------------------------- | :--------- | :------------ |
| **JTS-L (Lite)**          | MVP, Internal Tools, Simple Apps   | ⭐ Low      | ⭐⭐ Basic     |
| **JTS-S (Standard)**      | Production Apps, Public APIs       | ⭐⭐ Medium | ⭐⭐⭐⭐ High      |
| **JTS-C (Confidentiality)**| Fintech, Healthcare, High-Security | ⭐⭐⭐ High   | ⭐⭐⭐⭐⭐ Maximum   |

**Advantages of JTS over previous generation token systems:**
1.  **Instant Revocation:** Through `StateProof` management and token rotation (JTS-S/C).
2.  **Token Theft Detection:** Through a rotation mechanism that detects replay (JTS-S/C).
3.  **Layered Protection:** CSRF protection, device binding, and optional encryption.
4.  **Error Standardization:** Consistent error codes for debugging and handling.
5.  **Platform Flexibility:** Support for web, mobile, and server-to-server.
6.  **Key Management:** Clear key rotation procedure with no downtime.
7.  **Progressive Enhancement:** A clear migration path from JTS-L → JTS-S → JTS-C as an application grows.

---

### **Appendix A: Implementation Checklist**

Implementers MUST meet the following checklist for JTS compliance:

#### **JTS-L (Lite) Checklist:**

**Required (MUST):**
- [ ] Use asymmetric cryptography (RS256, ES256, etc.)
- [ ] Include `kid` in the header of every BearerPass
- [ ] Store StateProof in an HttpOnly cookie with SameSite=Strict
- [ ] Validate CSRF on `/renew` and `/logout` endpoints
- [ ] Return error responses according to the standard format (subset)

**Recommended (SHOULD):**
- [ ] Set StateProof expiry to a maximum of 24 hours
- [ ] Implement rate limiting on `/renew`
- [ ] Log all renewal activities

---

#### **JTS-S (Standard) Checklist:**

**Required (MUST):**
- [ ] Use asymmetric cryptography (RS256, ES256, etc.)
- [ ] Include `kid` in the header of every BearerPass
- [ ] Store StateProof in an HttpOnly cookie with SameSite=Strict
- [ ] Implement StateProof rotation on every `/renew`
- [ ] Detect replay and revoke sessions when detected
- [ ] Validate CSRF on `/renew` and `/logout` endpoints
- [ ] Return error responses according to the standard format (full)

**Recommended (SHOULD):**
- [ ] Implement device fingerprinting (`dfp`)
- [ ] Support grace periods for in-flight requests
- [ ] Provide a `/sessions` endpoint for visibility
- [ ] Implement concurrent session policies
- [ ] Send security notifications when anomalies are detected

**Optional (MAY):**
- [ ] Implement an introspection endpoint
- [ ] Support multi-tenancy with the `org` claim

---

#### **JTS-C (Confidentiality) Checklist:**

**Required (MUST):**
- [ ] All JTS-S requirements
- [ ] Implement JWE encryption (signed-then-encrypted)
- [ ] Manage encryption keys separately from signing keys

**Optional (MAY):**
- [ ] Support multiple Resource Server encryption keys
- [ ] Implement a key exchange protocol for encryption keys

---

### **Appendix B: Complete Flow Example**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JTS AUTHENTICATION FLOW                               │
└─────────────────────────────────────────────────────────────────────────────┘

[User]          [Client App]         [Auth Server]        [Resource Server]
   │                 │                     │                      │
   │─── Login ──────>│                     │                      │
   │                 │─── POST /login ────>│                      │
   │                 │    (credentials)    │                      │
   │                 │                     │── Create Session ───>│ [DB]
   │                 │                     │<─ Session Record ────│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass (body)│                      │
   │                 │    StateProof (cookie)                     │
   │                 │                     │                      │
   │                 │─────────── GET /api/resource ─────────────>│
   │                 │            Authorization: Bearer <BP>      │
   │                 │                     │                      │
   │                 │                     │    Verify signature  │
   │                 │                     │    (stateless)       │
   │                 │<────────── 200 OK ─────────────────────────│
   │<── Data ───────│                     │                      │
   │                 │                     │                      │
   │    ... BearerPass expires ...        │                      │
   │                 │                     │                      │
   │                 │─── POST /renew ────>│                      │
   │                 │    (StateProof cookie)                     │
   │                 │                     │── Validate SP_v1 ───>│ [DB]
   │                 │                     │<─ Valid, consumed ───│
   │                 │                     │── Store SP_v2 ──────>│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass_new   │                      │
   │                 │    StateProof_v2 (cookie)                  │
   │                 │                     │                      │
   │─── Logout ─────>│                     │                      │
   │                 │─── POST /logout ───>│                      │
   │                 │    (StateProof cookie)                     │
   │                 │                     │── Delete Session ───>│ [DB]
   │                 │<── 200 OK ─────────│                      │
   │<── Logged out ─│                     │                      │
   │                 │                     │                      │
```

---

### **Appendix C: References**

-   RFC 7519 - JSON Web Token (JWT)
-   RFC 7515 - JSON Web Signature (JWS)
-   RFC 7516 - JSON Web Encryption (JWE)
-   RFC 7517 - JSON Web Key (JWK)
-   RFC 6749 - The OAuth 2.0 Authorization Framework
-   OWASP Session Management Cheat Sheet
-   OWASP Cross-Site Request Forgery Prevention Cheat Sheet
