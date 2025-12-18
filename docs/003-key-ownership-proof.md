# RFC-003: Key Ownership Proof Protocol

**Version:** 1.0
**Status:** Draft
**Authors:** CapiscIO Core Team
**Created:** 2025-12-12
**Requires:** RFC-002 (Trust Badge Specification)

---

## 1. Abstract

This RFC defines the **Key Ownership Proof (PoP) Protocol** for CapiscIO Trust Badge issuance. The protocol enables agents to cryptographically prove they control the private key associated with their DID before receiving a badge, providing stronger identity assurance than account-based authorization alone.

This protocol implements the IAL-1 (Proof of Possession) assurance level defined in RFC-002 §7.2.1.

---

## 2. Motivation

RFC-002 §7.2 defines badge issuance with account-based authorization (IAL-0), where badges are issued based on authenticated account ownership. While sufficient for many use cases, this model has limitations:

1. **No key binding proof**: IAL-0 badges prove "Account X requested a badge for DID Y" but not "the requester controls DID Y's private key."
2. **Bearer token semantics**: IAL-0 badges can be used by anyone who possesses them.
3. **Delegation ambiguity**: Without key binding, it's unclear whether the badge holder can legitimately sign delegation chains.

The PoP protocol addresses these limitations by requiring agents to prove key ownership before badge issuance, enabling:

- **Cryptographic key binding** via the `cnf` claim
- **Replay protection** via single-use challenges
- **Audit trails** linking badges to specific proof events

---

## 3. Terminology

| Term | Definition |
|------|------------|
| **Challenge** | A server-generated nonce that the agent must sign |
| **Proof JWS** | A signed JWT proving the agent controls the DID's private key |
| **PoP Badge** | A badge issued after successful PoP verification, containing a `cnf` claim |
| **DID Document** | The W3C DID Document containing the agent's public key(s) |

### 3.1 Header Conventions

To avoid collision between API keys and badges in the `Authorization` header:

| Header | Purpose | When Used |
|--------|---------|----------|
| `X-Capiscio-Registry-Key` | Registry API key | Phase 1 (challenge request); Phase 2 IAL-0 mode |
| `Authorization: Bearer <badge>` | Badge authentication | Any request authenticated by badge |
| `X-Capiscio-Badge` | Explicit badge header | Alternative to `Authorization: Bearer` (see RFC-002 §9.1) |

**Rules:**

1. Registry API keys MUST use `X-Capiscio-Registry-Key`. They MUST NOT use `Authorization: Bearer`.
2. `Authorization: Bearer` is reserved exclusively for badge tokens.
3. When both an API key and badge are needed on the same request, use `X-Capiscio-Registry-Key` for the API key and either `Authorization: Bearer` or `X-Capiscio-Badge` for the badge.

> **Design Decision: Unauthenticated Phase 2 for IAL-1**
>
> Phase 2 badge issuance in IAL-1 mode MAY proceed without `X-Capiscio-Registry-Key` or badge authentication, relying solely on the PoP proof for authentication. This enables "no API key after registration" for agents using PoP.
>
> **What Unauthenticated Phase 2 Provides:**
> - Proof that the requester controlled the DID's private key at issuance time.
> - A badge with `ial="1"` and a `cnf` claim binding the badge to the proven key.
>
> **What Unauthenticated Phase 2 Does NOT Provide:**
> - It does NOT remove the need for ownership checks at agent registration time. Phase 1 remains authenticated.
> - It does NOT provide request-level PoP. The issued badge is still a bearer token that can be replayed within its TTL.
> - It does NOT prove the presenter currently controls the key—only that they controlled it at issuance time.
>
> **Security Guardrails (REQUIRED when allowing unauthenticated Phase 2):**
> - Phase 1 MUST remain authenticated (API key or badge). Anonymous challenge issuance is NOT allowed.
> - Rate limits differ between phases: Phase 1 (authenticated) can use tighter per-account limits; Phase 2 (unauthenticated) MUST throttle primarily by DID and `account_id` from the challenge record, with IP as a volumetric backstop only (see §8.4).
> - Proof `exp` MUST be ≤ `iat + 60` seconds.
> - Challenge TTL MUST be ≤ 10 minutes (600 seconds).
> - Implementations MAY add proof-of-work or bot defense for high-volume environments (future work).
>
> Implementations that prefer simpler security MAY require `X-Capiscio-Registry-Key` or badge for Phase 2 as well.

---

## 4. Protocol Overview

The PoP protocol is a two-phase challenge-response flow:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Key Ownership Proof Protocol                         │
└─────────────────────────────────────────────────────────────────────────────┘

  Agent                                Registry (CA)
    │                                       │
    │  ┌─────────────────────────────────┐  │
    │  │ PHASE 1: Challenge Request      │  │
    │  └─────────────────────────────────┘  │
    │                                       │
    │  POST /v1/agents/{did}/badge/challenge│
    │  X-Capiscio-Registry-Key: <api_key>   │
    │  { badge_ttl: 300, badge_aud: [...]}  │
    │──────────────────────────────────────►│
    │                                       │
    │                          ┌────────────┴────────────┐
    │                          │ 1. Verify authorization │
    │                          │ 2. Verify agent exists  │
    │                          │ 3. Generate challenge   │
    │                          │ 4. Store with TTL       │
    │                          └────────────┬────────────┘
    │                                       │
    │  200 OK                               │
    │  { challenge_id, nonce,               │
    │    challenge_expires_at, proof_aud,   │
    │    htu, htm, badge_aud, badge_ttl }   │
    │◄──────────────────────────────────────│
    │                                       │
    │  ┌─────────────────────────────────┐  │
    │  │ Agent constructs and signs      │  │
    │  │ proof JWS using DID private key │  │
    │  │ (includes cid, exp claims)      │  │
    │  └─────────────────────────────────┘  │
    │                                       │
    │  ┌─────────────────────────────────┐  │
    │  │ PHASE 2: Badge Issuance         │  │
    │  └─────────────────────────────────┘  │
    │                                       │
    │  POST /v1/agents/{did}/badge          │
    │  (PoP proof authenticates request)    │
    │  { mode:"ial1", challenge_id,         │
    │    proof_jws }                        │
    │──────────────────────────────────────►│
    │                                       │
    │                          ┌────────────┴────────────┐
    │                          │ 1. Verify PoP proof     │
    │                          │ 2. Lookup challenge     │
    │                          │ 3. Check not expired    │
    │                          │ 4. Check not used       │
    │                          │ 5. Resolve DID Document │
    │                          │ 6. Verify proof_jws sig │
    │                          │ 7. Mark challenge used  │
    │                          │ 8. Issue badge with cnf │
    │                          └────────────┬────────────┘
    │                                       │
    │  200 OK                               │
    │  { badge: "<jws>", jti, subject,      │
    │    trust_level, expires_at }          │
    │◄──────────────────────────────────────│
    │                                       │
```

---

## 5. Endpoints

### 5.1 Challenge Request

```
POST /v1/agents/{did}/badge/challenge
```

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `did` | string | Yes | URL-encoded DID of the agent (e.g., `did:web:registry.capisc.io:agents:my-agent`) |

**Request Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `X-Capiscio-Registry-Key` | Conditional | Registry API key (required if not using badge auth) |
| `Authorization` | Conditional | `Bearer <badge>` for badge-authenticated requests |
| `X-Capiscio-Badge` | Conditional | Alternative to `Authorization: Bearer` for badge auth (see RFC-002 §9.1) |
| `Content-Type` | Yes | `application/json` |

> **Authentication:** At least one of `X-Capiscio-Registry-Key`, `Authorization: Bearer <badge>`, or `X-Capiscio-Badge` MUST be present. For newly registered agents without a badge yet, use the API key. `X-Capiscio-Badge` is provided as an alternative for clients where `Authorization` header manipulation is restricted.
>
> **Badge Authentication Constraints (when using a badge via `Authorization: Bearer` or `X-Capiscio-Badge`):**
> - Badge MUST be registry-issued (trust level 1–4). Self-signed level 0 badges MUST NOT be accepted.
> - Badge `sub` MUST equal the route `{did}`. Cross-agent challenge creation is NOT allowed.
> - Badge `aud` MUST include the registry origin. If the badge has no `aud` claim, the registry MUST treat it as self-audienced per RFC-002 §8.3.

**Request Body:**

```json
{
  "badge_ttl": 300,
  "challenge_ttl": 300,
  "badge_aud": ["https://api.example.com"]
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `badge_ttl` | integer | No | 300 | Requested badge TTL in seconds. MUST respect issuance constraints in RFC-002 §7.2 (min 60, max 3600 unless deployment overrides). |
| `challenge_ttl` | integer | No | 300 | Challenge validity window in seconds (max 600). |
| `badge_aud` | string[] | No | null | Requested audience for the issued badge (stored in challenge, immutable) |

**Response (200 OK):**

```json
{
  "challenge_id": "ch-550e8400-e29b-41d4-a716-446655440000",
  "nonce": "dGhpcyBpcyBhIHJhbmRvbSBub25jZQ",
  "challenge_expires_at": "2025-12-12T10:05:00Z",
  "proof_aud": "https://registry.capisc.io",
  "htu": "https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent/badge",
  "htm": "POST",
  "badge_aud": ["https://api.example.com"],
  "badge_ttl": 300
}
```

| Field | Type | Description |
|-------|------|-------------|
| `challenge_id` | string | Prefixed UUID identifying this challenge (`ch-` + UUID). Used for replay prevention. |
| `nonce` | string | Base64url-encoded random bytes (minimum 32 bytes, no padding) |
| `challenge_expires_at` | string | ISO 8601 timestamp when challenge expires (default: 5 minutes) |
| `proof_aud` | string | Expected audience for the proof JWS (always the registry origin) |
| `htu` | string | HTTP URI the proof is bound to (badge endpoint). See §6.4 for canonicalization. |
| `htm` | string | HTTP method the proof is bound to (`POST`) |
| `badge_aud` | string[] | Echoed back; will be set as `aud` in the issued badge. Immutable after challenge creation. |
| `badge_ttl` | integer | Echoed back; will be used as badge TTL. |

> **Normative:** `proof_aud` MUST equal the registry issuer origin (the `iss` value that will appear in issued badges). Clients MUST use this exact value in the proof JWT `aud` claim.

**Error Responses:**

| Code | Error | Description |
|------|-------|-------------|
| 400 | `invalid_did` | DID is malformed or unsupported |
| 401 | `unauthorized` | Missing or invalid authorization |
| 403 | `agent_not_owned` | Authenticated account does not own this agent |
| 404 | `agent_not_found` | Agent with this DID does not exist |
| 429 | `rate_limit_exceeded` | Too many challenge requests |

### 5.2 Badge Issuance with PoP

```
POST /v1/agents/{did}/badge
```

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `did` | string | Yes | URL-encoded DID of the agent |

**Request Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `X-Capiscio-Registry-Key` | Conditional | Required for IAL-0 mode; optional for IAL-1 mode |
| `Authorization` | Conditional | `Bearer <badge>` for badge-authenticated requests |
| `X-Capiscio-Badge` | Conditional | Alternative to `Authorization: Bearer` for badge auth (see RFC-002 §9.1) |
| `Content-Type` | Yes | `application/json` |

### 5.2.1 Authentication Modes

| Mode | Authentication Required | Use Case |
|------|------------------------|----------|
| **IAL-1 (PoP)** | PoP proof alone is sufficient | Post-registration badge refresh |
| **IAL-0 (Legacy)** | `X-Capiscio-Registry-Key` or badge required | Account-attested issuance |

For IAL-1 mode, the PoP proof cryptographically authenticates the request. The registry MAY accept unauthenticated requests if:
1. The `challenge_id` is valid and not expired
2. The `proof_jws` verifies against the DID's public key
3. The agent DID exists and is active in the registry

This enables "no API key after registration" for agents that use PoP.

**Request Body (IAL-1 mode):**

```json
{
  "mode": "ial1",
  "challenge_id": "ch-550e8400-e29b-41d4-a716-446655440000",
  "proof_jws": "eyJhbGciOiJFZERTQSIsInR5cCI6InBvcCtqd3QiLCJraWQiOiJkaWQ6d2ViOnJlZ2lzdHJ5LmNhcGlzYy5pbzphZ2VudHM6bXktYWdlbnQja2V5LTEifQ..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | string | Yes | MUST be `"ial1"` for PoP-authenticated issuance |
| `challenge_id` | string | Yes | Challenge ID from phase 1 (prefixed UUID: `ch-` + UUID) |
| `proof_jws` | string | Yes | Signed proof JWT (see §6) |

> **Challenge → Badge Immutability:**
> - The registry MUST use `badge_aud` and `badge_ttl` values stored in the challenge record at issuance time.
> - The registry MUST ignore any Phase 2 body fields that attempt to supply or override `badge_aud` or `badge_ttl`.
> - This binding is immutable: badge parameters are locked at challenge creation (Phase 1).

**Request Body (IAL-0 mode):**

```json
{
  "mode": "ial0",
  "domain": "example.com",
  "badge_ttl": 300,
  "badge_aud": ["https://api.example.com"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | string | Yes | MUST be `"ial0"` for account-attested issuance |
| `domain` | string | No | Domain for badge scope |
| `badge_ttl` | integer | No | Requested badge TTL in seconds |
| `badge_aud` | string[] | No | Requested audience for the issued badge |

> **Migration Note:** For backward compatibility during transition, if `mode` is absent:
> - Presence of `challenge_id` + `proof_jws` implies `mode: "ial1"`
> - Absence of both implies `mode: "ial0"`
>
> **DEPRECATED:** Mode inference from body shape is deprecated. New implementations MUST always include explicit `mode`. Servers SHOULD reject requests without `mode` after 2025-06-01.

**Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
    "jti": "770e8400-e29b-41d4-a716-446655440001",
    "subject": "did:web:registry.capisc.io:agents:my-agent",
    "issuer": "https://registry.capisc.io",
    "trust_level": "2",
    "issued_at": "2025-12-12T10:00:30Z",
    "expires_at": "2025-12-12T10:05:30Z",
    "assurance_level": "IAL-1",
    "cnf": {
      "kid": "did:web:registry.capisc.io:agents:my-agent#key-1"
    }
  },
  "message": "Badge issued with proof of possession"
}
```

**Error Responses:**

| Code | Error | Description |
|------|-------|-------------|
| 400 | `invalid_challenge_id` | Challenge ID is malformed |
| 400 | `invalid_proof` | Proof JWS is malformed or missing required claims |
| 401 | `unauthorized` | Missing or invalid authorization (IAL-0 mode, or deployments requiring auth for Phase 2) |
| 403 | `challenge_expired` | Challenge has expired |
| 403 | `challenge_used` | Challenge has already been used (replay attempt) |
| 403 | `proof_verification_failed` | Proof signature does not verify against DID keys |
| 403 | `subject_mismatch` | Proof `sub` does not match route DID |
| 403 | `cid_mismatch` | Proof `cid` does not match `challenge_id` |
| 403 | `audience_mismatch` | Proof `aud` does not match `proof_aud` |
| 403 | `htu_mismatch` | Proof `htu` does not match canonical badge endpoint |
| 403 | `iat_invalid` | Proof `iat` is outside valid window |
| 403 | `exp_too_long` | Proof `exp` exceeds `iat + 60` seconds |
| 403 | `exp_outside_challenge_window` | Proof `exp` is after challenge expiration |
| 403 | `proof_expired` | Proof `exp` has passed |
| 403 | `kid_not_found` | Proof `kid` not found in DID Document `verificationMethod` |
| 403 | `key_not_in_authentication` | Proof `kid` not in DID Document `authentication` relationship |
| 404 | `challenge_not_found` | Challenge does not exist |
| 404 | `agent_not_found` | Agent with this DID does not exist |
| 502 | `did_resolution_failed` | Failed to resolve DID Document |
| 502 | `did_document_invalid` | DID Document is malformed, wrong content-type, or fails schema validation |

### 5.2.2 Phase 2 Validation Checklist

Implementations MUST perform the following validation steps in order:

| Step | Check | Failure Error |
|------|-------|---------------|
| 1 | `challenge_id` has `ch-` prefix followed by valid UUID | `invalid_challenge_id` |
| 2 | Challenge exists in storage | `challenge_not_found` |
| 3 | Challenge `did` matches route `{did}` | `subject_mismatch` |
| 4 | Challenge `used` is `false` | `challenge_used` |
| 5 | Challenge `challenge_expires_at` > now | `challenge_expired` |
| 6 | Proof JWS is well-formed (3 parts, valid base64url) | `invalid_proof` |
| 7 | Proof header `typ` = `pop+jwt` | `invalid_proof` |
| 8 | Proof payload `cid` = challenge `challenge_id` | `cid_mismatch` |
| 9 | Proof payload `nonce` = challenge `nonce` (exact base64url string match) | `invalid_proof` |
| 10 | Proof payload `aud` = challenge `proof_aud` | `audience_mismatch` |
| 11 | Proof payload `htu` = challenge `htu` (byte-equal) | `htu_mismatch` |
| 12 | Proof payload `htm` = `POST` | `invalid_proof` |
| 13 | Proof payload `iat` ≤ now + 60s (not in future, with clock skew tolerance) | `iat_invalid` |
| 14 | Proof payload `iat` ≥ challenge `created_at` - 60s (not before challenge) | `iat_invalid` |
| 15 | Proof payload `iat` ≤ challenge `challenge_expires_at` (within challenge window) | `iat_invalid` |
| 16 | Proof payload `exp` ≤ `iat` + 60 | `exp_too_long` |
| 17 | Proof payload `exp` > now | `proof_expired` |
| 18 | Proof payload `exp` ≤ challenge `challenge_expires_at` | `exp_outside_challenge_window` |
| 19 | Proof payload `sub` = route `{did}` | `subject_mismatch` |
| 20 | Resolve DID Document for `sub` (see §9.7 for safety requirements) | `did_resolution_failed` |
| 21 | Proof header `kid` equals a `verificationMethod[].id` in the resolved DID Document | `kid_not_found` |
| 22 | `kid` is listed in DID Document `authentication` relationship (see note below) | `key_not_in_authentication` |
| 23 | Signature verifies against resolved public key | `proof_verification_failed` |
| 24 | Atomically set challenge `used = true` | (internal error if fails) |

> **Key Relationship Matching (Step 22):** DID Documents can express `authentication` relationships in different ways per DID Core:
> - As a string reference: `"authentication": ["did:web:...#key-1"]`
> - As an embedded object: `"authentication": [{"id": "did:web:...#key-1", ...}]`
>
> **Matching Rules:**
> - Implementations MUST accept both forms.
> - Implementations MUST compare the **full `kid` DID URL string** for equality against each `authentication[]` string OR each `authentication[].id` string.
> - Implementations MUST NOT drop or ignore fragments. The fragment (e.g., `#key-1`) is essential for key identification.
> - `kid` values containing query components (`?...`) SHOULD be rejected as malformed.
> - Comparison is **exact string equality**—no normalization is performed.

> **Implementation Note:** Steps 1-5 are cheap and SHOULD be performed before parsing the proof JWS. This allows quick rejection of replay attempts and expired challenges before incurring signature verification costs.

---

## 6. Proof JWS Specification

The proof JWS is a signed JWT that proves the agent controls the DID's private key.

### 6.1 Header

```json
{
  "alg": "EdDSA",
  "typ": "pop+jwt",
  "kid": "did:web:registry.capisc.io:agents:my-agent#key-1"
}
```

| Field | Requirement | Description |
|-------|-------------|-------------|
| `alg` | REQUIRED | Signing algorithm. MUST be `EdDSA` (Ed25519) or `ES256`. |
| `typ` | REQUIRED | MUST be `pop+jwt` to distinguish from other JWTs. |
| `kid` | REQUIRED | Key ID referencing the signing key in the DID Document. See §6.5 for format by DID method. |

### 6.2 Payload

```json
{
  "cid": "ch-550e8400-e29b-41d4-a716-446655440000",
  "nonce": "dGhpcyBpcyBhIHJhbmRvbSBub25jZQ",
  "sub": "did:web:registry.capisc.io:agents:my-agent",
  "aud": "https://registry.capisc.io",
  "htu": "https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent/badge",
  "htm": "POST",
  "iat": 1733997500,
  "exp": 1733997560,
  "jti": "660e8400-e29b-41d4-a716-446655440001"
}
```

| Claim | Requirement | Description |
|-------|-------------|-------------|
| `cid` | REQUIRED | The `challenge_id` from the challenge response (including `ch-` prefix). Strengthens auditability. |
| `nonce` | REQUIRED | The exact `nonce` base64url string from the challenge response. Verifiers MUST compare the exact base64url string (not decoded bytes). |
| `sub` | REQUIRED | The agent's DID. MUST match the DID in the request path. |
| `aud` | REQUIRED | The `proof_aud` value from the challenge response. |
| `htu` | REQUIRED | HTTP URI the proof is bound to. See §6.4 for canonicalization. |
| `htm` | REQUIRED | HTTP method. MUST be `POST`. |
| `iat` | REQUIRED | Issued At timestamp. MUST be within the challenge validity window (see §5.2.2 steps 13–15). |
| `exp` | REQUIRED | Expiration timestamp. MUST be `iat + 60` seconds or less. Reduces risk if challenges leak. |
| `jti` | REQUIRED | Unique identifier for this proof. Used for audit logging. |

### 6.3 Signature

The proof MUST be signed using the private key corresponding to a public key in the agent's DID Document.

```
signature = EdDSA_Sign(Agent_PrivateKey, ASCII(base64url(header) + "." + base64url(payload)))
```

### 6.4 HTU Canonicalization

To prevent false negatives from URL encoding differences, the following canonicalization rule applies:

**Rule:** The proof `htu` MUST be the **exact byte string** returned in the challenge response `htu` field. Agents MUST NOT re-encode, normalize, or modify the URL in any way.

The registry:
1. Generates `htu` in canonical form at challenge creation time
2. Stores the exact bytes in the challenge record
3. Compares proof `htu` using byte-for-byte equality

**Canonical form (registry-generated):**
- Scheme and host: lowercase
- Default ports omitted (no `:443` for HTTPS)
- Path: percent-encoded per RFC 3986, with DID colons encoded as `%3A`
- No trailing slash
- No query string or fragment

**Example:**
```
Challenge htu: https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent/badge
Proof htu:     https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent/badge  ✓

Proof htu:     https://registry.capisc.io/v1/agents/did:web:registry.capisc.io:agents:my-agent/badge  ✗ (not encoded)
```

> **Note:** Since agents MUST copy the `htu` byte-for-byte, no case normalization examples are needed. The registry always generates lowercase `htu` values.

**Implementation Guardrails:**

1. **Challenge generation:** Do NOT round-trip the `htu` through URL parsers that rewrite percent-encoding. Construct `htu` by direct string concatenation or template.
2. **Proof verification:** Compare `proof.htu` to the **stored challenge `htu` string** using strict byte equality (or string equality in languages without byte strings). Do NOT reconstruct the URL from the incoming request; do NOT parse, normalize, or decode before comparison.
3. **Test vectors (informative):**

| Challenge `htu` | Proof `htu` | Result |
|-----------------|-------------|--------|
| `https://r.io/v1/agents/did%3Aweb%3Ar.io%3Aa/badge` | `https://r.io/v1/agents/did%3Aweb%3Ar.io%3Aa/badge` | ✓ Match |
| `https://r.io/v1/agents/did%3Aweb%3Ar.io%3Aa/badge` | `https://r.io/v1/agents/did%3Aweb%3AR.IO%3Aa/badge` | ✗ Case differs |
| `https://r.io/v1/agents/did%3Aweb%3Ar.io%3Aa/badge` | `https://r.io/v1/agents/did:web:r.io:a/badge` | ✗ Not encoded |
| `https://r.io/v1/agents/did%3Aweb%3Ar.io%3Aa/badge` | `https://r.io/v1/agents/did%3aweb%3ar.io%3aa/badge` | ✗ Lowercase hex |

### 6.5 Key ID (`kid`) Format by DID Method

#### 6.5.1 `did:web`

For `did:web`, `kid` MUST be a DID URL referencing a `verificationMethod` in the DID Document:

```
did:web:registry.capisc.io:agents:my-agent#key-1
```

The fragment (`#key-1`) MUST match the `id` suffix of a `verificationMethod` entry.

#### 6.5.2 `did:key`

**Normative Rule:** `kid` MUST equal a `verificationMethod[].id` in the resolved DID Document.

**Interoperability Note:** Different `did:key` resolvers may produce different DID Documents. The registry validates `kid` by exact match against `verificationMethod[].id` in the resolved document—it does not special-case by string shape.

**Example (standard form per did:key spec):**
```
DID:     did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
kid:     did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

**Validation:** The registry MUST resolve the `did:key` DID Document and verify `kid` matches a `verificationMethod[].id` entry. Do NOT assume a particular fragment format or construct `kid` programmatically.

---

## 7. Key Discovery and Resolution

### 7.1 DID Method-Specific Resolution

The CA MUST resolve keys using the DID method's defined resolution mechanism:

#### 7.1.1 `did:key`

For `did:key` identifiers, the public key is encoded directly in the DID itself:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
        └──────────────────────────────────────────────────┘
                    Multibase-encoded public key
```

**Resolution:**

1. Parse the multibase-encoded portion after `did:key:`
2. Decode using the multibase prefix (`z` = base58btc)
3. Parse the multicodec prefix to determine key type (`0xed01` = Ed25519)
4. Extract the raw public key bytes

No network fetch is required.

#### 7.1.2 `did:web`

For `did:web` identifiers, fetch the DID Document from the domain using the standard `did:web` resolution rules:

**Resolution Rule:**

Path components after the domain are converted to URL path segments, with `/did.json` appended:

- `did:web:example.com` → `https://example.com/.well-known/did.json`
- `did:web:example.com:path:to:resource` → `https://example.com/path/to/resource/did.json`

**CapiscIO Example:**

```
did:web:registry.capisc.io:agents:my-agent
→ https://registry.capisc.io/agents/my-agent/did.json
```

**Resolution Steps:**

1. Transform DID to HTTPS URL per the rules above
2. Fetch the DID Document over HTTPS (TLS required)
3. Extract public keys from `verificationMethod` array

**DID Document Example:**

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:registry.capisc.io:agents:my-agent",
  "verificationMethod": [{
    "id": "did:web:registry.capisc.io:agents:my-agent#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:registry.capisc.io:agents:my-agent",
    "publicKeyJwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url-encoded-public-key"
    }
  }],
  "authentication": ["did:web:registry.capisc.io:agents:my-agent#key-1"]
}
```

### 7.2 Key Selection

The CA MUST verify the proof signature against a key that:

1. Is listed in the `verificationMethod` array of the DID Document
2. Has an `id` matching the `kid` in the proof JWS header
3. Is referenced in the `authentication` relationship (for authentication proofs)

### 7.3 Trust Anchor Hierarchy

**Important:** The DID Document is the authoritative source for key material.

```
┌─────────────────────────────────────────────────────────────┐
│                    Trust Anchor Hierarchy                    │
├─────────────────────────────────────────────────────────────┤
│  1. DID Document (authoritative)                            │
│     └── Resolved via DID method rules                       │
│     └── MUST be used for all PoP verification               │
│                                                             │
│  2. AgentCard jwks_url (NOT a trust anchor)                 │
│     └── Used for runtime verification, not PoP             │
│     └── Subject to substitution attacks if unsigned         │
└─────────────────────────────────────────────────────────────┘
```

The CA MUST NOT use `jwks_url` from the AgentCard as the primary trust anchor for PoP verification. The AgentCard is not cryptographically bound to the DID and could be modified.

### 7.4 Registration-Time Pinned Keys (Implementation Note)

> **Warning:** This section describes an OPTIONAL implementation-specific fallback. It is NOT part of the normative protocol and creates a potential downgrade path.

Some implementations MAY store public keys at agent registration time as a fallback when DID resolution fails. If implemented:

**Hard Requirements:**

1. **Scope limitation:** MUST only apply to DIDs under the registry's own namespace (e.g., `did:web:registry.capisc.io:*`)
2. **Immutability:** Pinned keys MUST be signed by the registry CA and immutable after registration
3. **Explicit policy flag:** MUST require an explicit configuration flag (`allow_pinned_key_fallback: true`) to enable
4. **Audit logging:** All uses of pinned key fallback MUST be logged with reason code `did_resolution_fallback`
5. **Deprecation path:** Implementations SHOULD plan to remove this fallback once DID resolution is reliable

**Rejected Alternative:** Using pinned keys for arbitrary DIDs is explicitly NOT ALLOWED as it bypasses DID resolution security guarantees.

---

## 8. Challenge Storage and Replay Prevention

### 8.1 Storage Requirements

Implementations MUST store challenges with:

| Field | Type | Description |
|-------|------|-------------|
| `challenge_id` | string | Primary key (prefixed UUID: `ch-` + UUID) |
| `nonce` | string | Minimum 32 bytes of entropy, returned and stored as a base64url string (no padding) for exact comparison |
| `did` | string | Agent DID this challenge is for |
| `account_id` | string | Account that requested the challenge. MUST be recorded from Phase 1 authentication. For unauthenticated Phase 2 requests, this field reflects the authenticated account from Phase 1 (the challenge creator). |
| `badge_aud` | string[] | Requested badge audience (immutable after creation) |
| `badge_ttl` | integer | Requested badge TTL |
| `proof_aud` | string | Expected proof audience (registry origin) |
| `htu` | string | Canonical HTTP URI for proof binding |
| `challenge_expires_at` | timestamp | Challenge expiration time |
| `used` | boolean | Whether challenge has been consumed |
| `used_at` | timestamp | When challenge was consumed |
| `issued_badge_jti` | string | JTI of badge issued (for audit) |
| `created_at` | timestamp | When challenge was created |
| `client_ip` | string | IP address of requester (for audit) |

### 8.2 TTL and Expiration

- Default challenge TTL: 5 minutes (300 seconds)
- Maximum challenge TTL: 10 minutes (600 seconds)
- Expired challenges SHOULD be garbage collected after 24 hours (for audit retention)

### 8.3 Replay Prevention

Challenges MUST be single-use:

1. Before issuing a badge, check `used = false`
2. Atomically set `used = true` and `used_at = now()` when issuing
3. Reject any subsequent attempts to use the same `challenge_id`

Implementations SHOULD use atomic compare-and-swap operations or database transactions to prevent race conditions.

### 8.4 Rate Limiting

**Phase 1 (Challenge Requests):**

| Limit | Default | Scope |
|-------|---------|-------|
| Challenge requests | 10 per minute | Per DID |
| Challenge requests | 100 per minute | Per account |
| Challenge requests | 50 per minute | Per IP address |

**Phase 2 (Badge Issuance):**

For unauthenticated Phase 2 IAL-1 requests, rate limiting MUST NOT rely solely on IP address. The primary throttle dimensions are:

| Limit | Default | Scope | Notes |
|-------|---------|-------|-------|
| Badge issuance | 10 per minute | Per DID (`sub`) | Primary limit |
| Badge issuance | 50 per minute | Per `account_id` from challenge record | From Phase 1 auth |
| Badge issuance | 10,000 per minute | Per IP address | Volumetric backstop only |
| Failed proof attempts | 5 per 15 minutes | Per DID | Triggers cooldown |
| Failed proof attempts | 1,000 per 15 minutes | Per IP address | High backstop |

> **Rationale:** Since Phase 1 is authenticated, the `account_id` stored in the challenge record provides a trust anchor for Phase 2. Per-DID and per-account limits are more meaningful than per-IP for abuse prevention. IP limits remain high as a volumetric backstop against botnets.

After exceeding the failed proof limit, the DID SHOULD be temporarily blocked from new challenges (cooldown period: 15 minutes).

**429 Response Guidance:**

When unauthenticated Phase 2 hits a rate limit, the response MUST include:
- `Retry-After` header with seconds until retry is allowed
- Response body SHOULD include: `{"error": "rate_limit_exceeded", "message": "Retry with X-Capiscio-Registry-Key for higher limits."}`

---

## 9. Security Considerations

### 9.1 Nonce Entropy

The `nonce` MUST be generated using a cryptographically secure random number generator with at least 256 bits of entropy.

### 9.2 Time Binding

The proof `iat` MUST be validated:

- `iat` MUST NOT be in the future (with clock skew tolerance of 60 seconds)
- `iat` MUST be after the challenge was created

### 9.3 Audience Binding

The proof `aud` MUST exactly match the `proof_aud` in the challenge response to prevent proof reuse across different services.

### 9.4 HTTP Binding

The `htu` and `htm` claims bind the proof to a specific HTTP request, preventing interception and replay to different endpoints.

### 9.5 Key Rotation

For `did:web`, key rotation is supported by updating the DID Document:

1. Agent updates DID Document with new key
2. Agent requests new challenge
3. Agent signs proof with new key
4. CA verifies against updated DID Document
5. New badge is issued with `cnf` referencing new key

For `did:key`, key rotation means a new DID. The agent should:

1. Register a new agent with the new `did:key`
2. Request badges for the new identity
3. Optionally migrate any delegations to the new identity

### 9.6 DID Document Caching

Implementations MAY cache DID Documents with appropriate TTL:

- Recommended cache TTL: 5 minutes
- Cache MUST be invalidated on proof verification failure
- Cache SHOULD support `max-age` and `stale-while-revalidate` semantics

### 9.7 DID Resolution Safety (SSRF Protection)

Resolving `did:web` identifiers requires fetching `https://{domain}/.../did.json` from arbitrary domains. This is a classic SSRF attack surface. Implementations MUST enforce the following safety requirements:

**Network-Level Requirements:**

| Requirement | Value | Rationale |
|-------------|-------|--------|
| Protocol | HTTPS only | Prevent downgrade attacks |
| Redirects | MUST NOT follow | Prevent redirect-based SSRF (see note below) |
| Connection timeout | ≤ 5 seconds | Prevent slowloris |
| Response timeout | ≤ 10 seconds | Prevent slow-read attacks |
| Max response size | ≤ 64 KB | Prevent memory exhaustion |

> **Redirect Policy:** The "MUST NOT follow redirects" requirement is a deliberate security stance. Misconfigured servers (e.g., `www.` redirects, `http→https` redirects, CDN edge redirects) will fail DID resolution by design. Operators of `did:web` identifiers MUST ensure `https://{domain}/.../did.json` responds directly with a 200 status and the DID Document—not a 3xx redirect.

**IP Address Restrictions:**

Before connecting, implementations MUST resolve the domain to IP addresses and reject:

- Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`, `::1`
- Link-local: `169.254.0.0/16`, `fe80::/10`
- Multicast: `224.0.0.0/4`, `ff00::/8`
- Reserved: `0.0.0.0/8`, `::`
- **Literal IP hosts:** Reject `did:web` where the host portion is a literal IPv4 or IPv6 address (e.g., `did:web:192.168.1.1`). Domain names are required.

**DNS Rebinding Protection:**

Implementations SHOULD:

1. Resolve DNS once and pin the IP for the duration of the request
2. Reject if DNS returns multiple A/AAAA records with mixed public/private addresses
3. Consider using a DNS resolver that blocks rebinding attacks

**Response Validation:**

- `Content-Type` MUST be `application/json` or `application/did+json`
- Response MUST parse as valid JSON
- Implementations SHOULD validate the DID Document against DID Core schema

**Implementation Note:** Libraries like Go's `net/http` with custom `DialContext` or Node's `undici` with `connect` hooks can enforce these restrictions. Do NOT rely on application-level URL parsing alone.

---

## 10. Implementation Notes

### 10.1 SDK Support

The CapiscIO CLI and SDKs SHOULD provide helpers for the PoP flow:

**CLI:**

```bash
# Request badge with PoP (automatic challenge handling)
capiscio badge request \
  --key private.jwk \
  --did "did:web:registry.capisc.io:agents:my-agent" \
  --pop

# Or step by step
capiscio badge challenge --did "did:web:..." > challenge.json
capiscio badge prove --key private.jwk --challenge challenge.json > proof.jws
capiscio badge request --challenge-id <id> --proof proof.jws
```

**Go SDK:**

```go
client := badge.NewClient(caURL, apiKey)
result, err := client.RequestBadgeWithPoP(ctx, badge.PoPOptions{
    DID:        "did:web:registry.capisc.io:agents:my-agent",
    PrivateKey: privateKey,
    TTL:        5 * time.Minute,
})
```

### 10.2 Backward Compatibility

The badge endpoint MUST support both modes:

- **PoP mode (IAL-1)**: When `mode: "ial1"` with `challenge_id` and `proof_jws` are present
- **Legacy mode (IAL-0)**: When `mode: "ial0"` with `domain`, `badge_ttl`, and optional `badge_aud` are present

This allows gradual migration without breaking existing integrations.

### 10.3 Audit Logging

Implementations SHOULD log:

- Challenge requests (who, when, which DID)
- Proof verification attempts (success/failure, reason)
- Badge issuance events (JTI, DID, assurance level)

---

## 11. Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_did` | 400 | DID is malformed or uses unsupported method |
| `invalid_challenge_id` | 400 | Challenge ID missing `ch-` prefix or UUID portion is invalid |
| `invalid_mode` | 400 | Request `mode` is not `"ial0"` or `"ial1"` |
| `invalid_proof` | 400 | Proof JWS is malformed or missing required claims |
| `invalid_proof_header` | 400 | Proof JWS header is invalid |
| `invalid_proof_signature` | 400 | Proof signature is malformed |
| `missing_cid` | 400 | Proof JWT missing required `cid` claim |
| `missing_exp` | 400 | Proof JWT missing required `exp` claim |
| `unauthorized` | 401 | Missing or invalid authorization (IAL-0 mode, or deployments requiring auth for Phase 2) |
| `challenge_expired` | 403 | Challenge has expired |
| `challenge_used` | 403 | Challenge has already been used |
| `proof_verification_failed` | 403 | Proof signature does not verify |
| `proof_expired` | 403 | Proof `exp` has passed |
| `subject_mismatch` | 403 | Proof `sub` does not match route DID |
| `audience_mismatch` | 403 | Proof `aud` does not match `proof_aud` |
| `cid_mismatch` | 403 | Proof `cid` does not match `challenge_id` |
| `htu_mismatch` | 403 | Proof `htu` does not match canonical badge endpoint |
| `iat_invalid` | 403 | Proof `iat` is outside valid window |
| `exp_too_long` | 403 | Proof `exp` exceeds `iat + 60` seconds |
| `exp_outside_challenge_window` | 403 | Proof `exp` is after challenge expiration |
| `challenge_not_found` | 404 | Challenge does not exist |
| `agent_not_found` | 404 | Agent with this DID does not exist |
| `rate_limit_exceeded` | 429 | Too many requests |
| `did_resolution_failed` | 502 | Network, DNS, timeout, TLS, or parse failure during DID Document fetch |
| `did_document_invalid` | 502 | DID Document is malformed or fails schema validation |
| `kid_not_found` | 403 | Proof `kid` does not match any `verificationMethod[].id` in DID Document |
| `key_not_in_authentication` | 403 | Proof `kid` not referenced in DID Document `authentication` relationship |

---

## 12. References

- [RFC-001: Agent Governance and Communication Protocol (AGCP)](./001-agcp.md)
- [RFC-002: CapiscIO Trust Badge Specification](./002-trust-badge.md)
- [RFC 7800: Proof-of-Possession Key Semantics for JWTs](https://datatracker.ietf.org/doc/html/rfc7800)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [did:key Method Specification](https://w3c-ccg.github.io/did-method-key/)
- [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/)

---

## Appendix A: Example Flow

### A.1 Complete PoP Badge Request

**Step 1: Request Challenge**

```bash
curl -X POST "https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent/badge/challenge" \
  -H "X-Capiscio-Registry-Key: sk_live_abc123" \
  -H "Content-Type: application/json" \
  -d '{"badge_ttl": 300, "challenge_ttl": 300, "badge_aud": ["https://api.example.com"]}'
```

**Response:**

```json
{
  "challenge_id": "ch-550e8400-e29b-41d4-a716-446655440000",
  "nonce": "dGhpcyBpcyBhIHJhbmRvbSBub25jZQ",
  "challenge_expires_at": "2025-12-12T10:05:00Z",
  "proof_aud": "https://registry.capisc.io",
  "htu": "https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent/badge",
  "htm": "POST",
  "badge_aud": ["https://api.example.com"],
  "badge_ttl": 300
}
```

**Step 2: Construct Proof JWS**

Header:
```json
{
  "alg": "EdDSA",
  "typ": "pop+jwt",
  "kid": "did:web:registry.capisc.io:agents:my-agent#key-1"
}
```

Payload:
```json
{
  "cid": "ch-550e8400-e29b-41d4-a716-446655440000",
  "nonce": "dGhpcyBpcyBhIHJhbmRvbSBub25jZQ",
  "sub": "did:web:registry.capisc.io:agents:my-agent",
  "aud": "https://registry.capisc.io",
  "htu": "https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent/badge",
  "htm": "POST",
  "iat": 1733997500,
  "exp": 1733997560,
  "jti": "660e8400-e29b-41d4-a716-446655440001"
}
```

Sign with agent's Ed25519 private key.

**Step 3: Request Badge with Proof (no API key needed)**

```bash
curl -X POST "https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent/badge" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "ial1",
    "challenge_id": "ch-550e8400-e29b-41d4-a716-446655440000",
    "proof_jws": "eyJhbGciOiJFZERTQSIsInR5cCI6InBvcCtqd3QiLCJraWQiOiJkaWQ6d2ViOnJlZ2lzdHJ5LmNhcGlzYy5pbzphZ2VudHM6bXktYWdlbnQja2V5LTEifQ..."
  }'
```

**Response:**

```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
    "jti": "770e8400-e29b-41d4-a716-446655440001",
    "subject": "did:web:registry.capisc.io:agents:my-agent",
    "issuer": "https://registry.capisc.io",
    "trust_level": "2",
    "issued_at": "2025-12-12T10:00:30Z",
    "expires_at": "2025-12-12T10:05:30Z",
    "assurance_level": "IAL-1",
    "cnf": {
      "kid": "did:web:registry.capisc.io:agents:my-agent#key-1"
    }
  }
}
```

### A.2 Issued Badge Claims

```json
{
  "jti": "770e8400-e29b-41d4-a716-446655440001",
  "iss": "https://registry.capisc.io",
  "sub": "did:web:registry.capisc.io:agents:my-agent",
  "aud": ["https://api.example.com"],
  "iat": 1733997630,
  "exp": 1733997930,
  "ial": "1",
  "key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "base64url-encoded-public-key"
  },
  "cnf": {
    "kid": "did:web:registry.capisc.io:agents:my-agent#key-1"
  },
  "pop_challenge_id": "ch-550e8400-e29b-41d4-a716-446655440000",
  "vc": {
    "type": ["VerifiableCredential", "AgentIdentity"],
    "credentialSubject": {
      "domain": "example.com",
      "level": "2"
    }
  }
}
```

### A.3 did:key Example

For agents using `did:key`, the `kid` MUST match a `verificationMethod[].id` in the resolved DID Document:

**Proof JWS Header (standard form per did:key spec):**
```json
{
  "alg": "EdDSA",
  "typ": "pop+jwt",
  "kid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
}
```

> **Note:** The registry accepts whatever `verificationMethod[].id` appears in the resolved DID Document. See §6.5.2 for interoperability guidance.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-12 | Initial release |

