# RFC-002: CapiscIO Trust Badge Specification

**Version:** 1.0
**Status:** Approved
**Authors:** CapiscIO Core Team
**Created:** 2025-12-09
**Updated:** 2025-12-09
**Requires:** RFC-001 (AGCP)

---

## 1. Abstract

This RFC defines the **CapiscIO Trust Badge**, the cryptographic identity credential for AI agents in the CapiscIO ecosystem. Trust Badges are signed JSON Web Tokens (JWS) that provide portable, verifiable identity for agents participating in AGCP-governed workflows.

Trust Badges implement the SVID (Secure Verifiable Identity Document) concept referenced in RFC-001 §4.2, enabling the cryptographic signature validation required for delegation chain integrity.

---

## 2. Relationship to RFC-001 (AGCP)

| AGCP Concept (RFC-001) | Badge Implementation (RFC-002) |
|------------------------|-------------------------------|
| Agent Identity (`agent_id`) | Badge `sub` claim (DID) |
| SVID Signature Validation | Badge JWS signature |
| Short-lived TTL | Badge `exp` claim (default 5 min) |
| Revocation Lists | Badge `jti` + revocation endpoint |
| Trust Graph membership | Badge `iss` (CA) + `vc.level` |
| Delegation Chain signing | Agent signs with key from Badge |

**Invariant Preservation:**

The Trust Badge does NOT grant authority. It proves identity. Authority is governed by:

1. The **Trust Graph** (RFC-001 §3.1) — who may delegate to whom
2. The **Policy Decision Point** (RFC-001 §3.3) — what actions are permitted
3. The **Transitive Intersection** (RFC-001 §2.1) — the Golden Rule

A valid Badge is a **necessary but not sufficient** condition for an agent to participate in a workflow.

**Verifier Obligation:**

Verifiers MUST treat the Badge as an authentication primitive only and MUST obtain authorization decisions from the Policy Decision Point (PDP) or equivalent policy engine. Building "if Badge.sub == X then allow Y" logic directly in services violates this invariant.

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|------|------------|
| **Badge** | A signed JWS token asserting agent identity |
| **CA (Certificate Authority)** | The CapiscIO Registry that issues and signs Badges |
| **Issuer** | The CA identified by the `iss` claim |
| **Subject** | The agent identified by the `sub` claim (DID) |
| **Verifier** | Any entity that validates a Badge |
| **Trust Level** | A numeric indicator (1-3) of validation rigor |

---

## 4. Badge Structure

### 4.1 Format

A Trust Badge is a JWS (JSON Web Signature) in Compact Serialization format:

```
<base64url-header>.<base64url-payload>.<base64url-signature>
```

> **Note:** Although the header uses `typ: "JWT"`, Badges are used as signed identity assertions and not as OAuth access tokens.

### 4.2 Header

```json
{
  "alg": "EdDSA",
  "typ": "JWT"
}
```

| Field | Requirement | Value |
|-------|-------------|-------|
| `alg` | REQUIRED | `EdDSA` (Ed25519). Implementations MAY support `ES256`. |
| `typ` | REQUIRED | `JWT` |

### 4.3 Payload (Claims)

```json
{
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "https://registry.capisc.io",
  "sub": "did:web:registry.capisc.io:agents:my-agent-001",
  "aud": ["https://api.example.com"],
  "iat": 1733788800,
  "exp": 1733789100,
  "key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "base64url-encoded-public-key"
  },
  "vc": {
    "type": ["VerifiableCredential", "AgentIdentity"],
    "credentialSubject": {
      "domain": "finance.example.com",
      "level": "1"
    }
  }
}
```

#### 4.3.1 Standard JWT Claims

| Claim | Requirement | Description |
|-------|-------------|-------------|
| `jti` | REQUIRED | Badge ID (UUID v4). Used for revocation and audit. |
| `iss` | REQUIRED | Issuer URL. MUST be the CA that signed the Badge. In production, `iss` MUST identify a CA in the verifier's registry CA allowlist. Self-signed issuers are only permitted in non-production environments (see §13.1). |
| `sub` | REQUIRED | Subject DID. MUST be a valid `did:web` identifier referencing the agent's DID Document (see §6). |
| `aud` | OPTIONAL | Audience. Array of trust domains/services where Badge is valid. |
| `iat` | REQUIRED | Issued At. Unix timestamp (seconds). |
| `exp` | REQUIRED | Expiry. Unix timestamp (seconds). |

#### 4.3.2 CapiscIO-Specific Claims

| Claim | Requirement | Description |
|-------|-------------|-------------|
| `key` | REQUIRED | Subject's public key (JWK). Enables offline verification and delegation binding. Non-production deployments MAY temporarily relax this requirement as described below. |
| `vc` | REQUIRED | Verifiable Credential object containing identity assertions. |

> **Implementation Note:** In non-production environments, implementations MAY omit `key` for test badges when offline verification is not required. Production badges MUST always include `key`.

#### 4.3.3 Verifiable Credential Object

| Field | Requirement | Description |
|-------|-------------|-------------|
| `vc.type` | REQUIRED | MUST include `"VerifiableCredential"` and `"AgentIdentity"`. |
| `vc.credentialSubject.domain` | REQUIRED | Agent's home domain. MUST be validated according to the trust level's requirements in §5. |
| `vc.credentialSubject.level` | REQUIRED | Trust level: `"1"`, `"2"`, or `"3"`. |

**Extensibility:**

Additional fields in `credentialSubject` MUST NOT change the semantics of `level` and MUST be treated as informational by verifiers. Verifiers MUST ignore unknown fields.

### 4.4 Signature

The signature is computed over the JWS Signing Input using the CA's private key:

```
signature = EdDSA_Sign(CA_PrivateKey, ASCII(base64url(header) + "." + base64url(payload)))
```

---

## 5. Trust Levels

Trust Levels indicate the validation rigor applied by the CA during Badge issuance.

| Level | Name | Validation Requirements | Use Case |
|-------|------|------------------------|----------|
| `"1"` | Domain Validated (DV) | DNS TXT record OR HTTP challenge proving control of `domain` field | Development, internal agents |
| `"2"` | Organization Validated (OV) | DV + Organization existence verification (DUNS, legal entity lookup) | Production, B2B agents |
| `"3"` | Extended Validated (EV) | OV + Manual review + Legal agreement with CapiscIO | High-trust, regulated industries |

**Domain Requirement:**

For all trust levels, the `vc.credentialSubject.domain` field MUST be present and MUST have been validated according to the level's requirements. The CA MUST NOT issue a Badge without completing the domain validation challenge.

**Verifier Behavior:**

- Verifiers MUST treat `level` as opaque beyond numeric comparison.
- Verifiers MAY enforce minimum trust levels via policy.
- Verifiers MUST NOT invent additional semantics for trust levels.

---

## 6. DID Method: `did:web`

CapiscIO adopts the W3C-standard [`did:web`](https://w3c-ccg.github.io/did-method-web/) method for agent identifiers. This provides standards compliance, broad tooling support, and a clear portability story.

### 6.1 Syntax

Agent DIDs take the form:

```
did:web:registry.capisc.io:agents:<agent-id>
```

| Component | Description | Example |
|-----------|-------------|---------|
| `did:web` | DID method prefix | `did:web` |
| `registry.capisc.io` | Domain hosting the DID Document | `registry.capisc.io` |
| `agents` | Path segment | `agents` |
| `<agent-id>` | Unique identifier (UUID or slug) | `my-agent-001` |

### 6.2 Resolution

Per the `did:web` specification, the DID resolves to an HTTPS URL:

```
did:web:registry.capisc.io:agents:my-agent-001
  → https://registry.capisc.io/agents/my-agent-001/did.json
```

| Endpoint | URL | Returns |
|----------|-----|---------|
| DID Document | `GET https://registry.capisc.io/agents/<id>/did.json` | W3C DID Document |
| Agent API (internal) | `GET https://registry.capisc.io/v1/agents/<id>` | Full agent record with AgentCard |

**DID Document Structure:**

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:web:registry.capisc.io:agents:my-agent-001",
  "verificationMethod": [{
    "id": "did:web:registry.capisc.io:agents:my-agent-001#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:web:registry.capisc.io:agents:my-agent-001",
    "publicKeyMultibase": "z6Mkf..."
  }],
  "authentication": ["did:web:registry.capisc.io:agents:my-agent-001#key-1"],
  "service": [{
    "id": "did:web:registry.capisc.io:agents:my-agent-001#agent",
    "type": "AgentService",
    "serviceEndpoint": "https://my-agent.example.com/a2a"
  }]
}
```

The DID Document is auto-generated from the agent's stored public key and AgentCard. The `/v1/agents/<id>` endpoint remains the authoritative source; `/agents/<id>/did.json` is a standards-compliant view.

**Key Alignment:**

Implementations SHOULD ensure that the public key in the Badge `key` claim matches the primary `verificationMethod` in the agent's DID Document. A mismatch indicates either key rotation in progress or configuration drift and SHOULD be treated as a warning and investigated.

For v1, verifiers are not required to cross-check Badge `key` against the DID Document; the Badge signature from the CA is the source of truth for authentication. DID Documents exist for standards compatibility and portability.

### 6.3 Portability

Because CapiscIO uses standard `did:web`, agents have a clear migration path:

| Scenario | DID |
|----------|-----|
| Hosted by CapiscIO | `did:web:registry.capisc.io:agents:my-agent` |
| Self-hosted (migrated) | `did:web:my-company.com:agents:my-agent` |

To migrate, the agent operator:
1. Exports their keys and AgentCard from CapiscIO
2. Hosts `/agents/<id>/did.json` on their own domain
3. Updates the Badge `sub` to the new DID

This eliminates vendor lock-in concerns.

**Issuance Scope:**

In v1, all Badges are issued by the CapiscIO Registry CA, even when agents later migrate their DIDs to a self-hosted `did:web` domain. Organizations that fully exit CapiscIO MAY operate their own CA and issuance infrastructure; such flows are out of scope for this RFC and MAY be defined in future RFCs.

### 6.4 Relationship to AgentCard

- The **Badge** proves: "This runtime instance controls the private key for `sub` and is authorized by the CA."
- The **DID Document** describes: "Agent `sub` has this public key and these service endpoints."
- The **AgentCard** describes: "Agent `sub` has these capabilities, skills, and detailed metadata."

Verifiers use the Badge for **authentication**. They MAY resolve the DID Document for key verification and MAY fetch the AgentCard for **capability discovery**.

---

## 7. Badge Lifecycle

### 7.1 Lifecycle States

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ PENDING  │───►│  ACTIVE  │───►│ EXPIRED  │    │ REVOKED  │
└──────────┘    └────┬─────┘    └──────────┘    └──────────┘
                     │                               ▲
                     └───────────────────────────────┘
                            (revocation)
```

| State | Description |
|-------|-------------|
| PENDING | Badge requested but not yet issued |
| ACTIVE | Badge issued and within validity period (`iat` ≤ now < `exp`) |
| EXPIRED | Current time ≥ `exp` |
| REVOKED | Badge `jti` appears on revocation list |

### 7.2 Issuance

**Preconditions:**

1. Agent MUST be registered in the Registry with a public key.
2. Agent MUST have completed trust level validation (per §5).
3. Requester MUST be authenticated (Clerk session or API Key).

**Issuance Flow:**

```
Agent                          Registry (CA)
  │                                 │
  │  POST /v1/agents/{id}/badge     │
  │  {ttl: 300}                     │
  │────────────────────────────────►│
  │                                 │
  │                                 │ 1. Verify agent exists
  │                                 │ 2. Verify agent has public key
  │                                 │ 3. Generate jti (UUID)
  │                                 │ 4. Build claims
  │                                 │ 5. Sign with CA private key
  │                                 │
  │  200 OK                         │
  │  {badge: "<jws>", expiresAt: …} │
  │◄────────────────────────────────│
  │                                 │
```

**Issuance Constraints:**

| Constraint | Default | Notes |
|------------|---------|-------|
| Minimum TTL | 60 seconds | Implementations MAY configure lower for testing |
| Maximum TTL | 3600 seconds (1 hour) | Implementations MAY configure higher for special use cases |
| Default TTL | 300 seconds (5 minutes) | Agents needing continuous operation require ~12 badges/hour |
| Rate Limit | 100 badges per agent per hour | Implementations MAY adjust based on deployment scale |

These are spec defaults. Implementations MAY configure different values but SHOULD document deviations.

### 7.3 Renewal

Badges are short-lived and MUST be renewed before expiry.

**Automatic Renewal (Recommended):**

The `capiscio badge keep` daemon monitors Badge expiry and renews automatically:

```bash
capiscio badge keep \
  --key private.jwk \
  --sub "did:web:registry.capisc.io:agents:my-agent" \
  --out badge.jwt \
  --exp 5m \
  --renew-before 1m
```

**Manual Renewal:**

Agents MAY request a new Badge at any time via the issuance endpoint.

### 7.4 Revocation

**v1 Scope:**

In v1, all Badges are issued by the CapiscIO Registry CA (`iss = "https://registry.capisc.io"`), and revocation and agent status endpoints are hosted on the same origin. Future RFCs MAY define additional CAs and corresponding revocation endpoints.

**Revocation Semantics:**

- Revocation is by `jti` (Badge ID) only.
- Revoking a Badge does NOT revoke the agent or other Badges.
- To disable an agent entirely, use `POST /v1/agents/{id}/disable` (see below).

**Agent-Level Disablement:**

Verifiers SHOULD treat any Badge with `sub` belonging to a disabled agent as invalid, even if the Badge itself is not individually revoked. Gateways MUST check agent status using `GET https://registry.capisc.io/v1/agents/{id}/status` before accepting any Badge for that `sub`.

```
GET /v1/agents/{id}/status

Response:
{
  "id": "my-agent-001",
  "status": "active",       // or "disabled", "suspended"
  "disabledAt": null,
  "reason": null
}
```

```
POST /v1/agents/{id}/disable
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "reason": "Security incident"  // Optional
}
```

**Revocation API:**

```
POST https://registry.capisc.io/v1/badges/{jti}/revoke
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "reason": "Key compromise suspected"
}
```

**Revocation Check:**

```
GET https://registry.capisc.io/v1/badges/{jti}/status

Response:
{
  "jti": "550e8400-...",
  "revoked": false
}

// OR

{
  "jti": "550e8400-...",
  "revoked": true,
  "reason": "Key compromise suspected",
  "revokedAt": "2025-12-09T15:30:00Z"
}
```

**Revocation List (Bulk Sync):**

```
GET https://registry.capisc.io/v1/revocations?since=2025-12-09T00:00:00Z

Response:
{
  "revocations": [
    {"jti": "...", "revokedAt": "..."},
    ...
  ],
  "nextCursor": "..."
}
```

**Cache Staleness Guidance:**

Verifiers operating in offline or semi-connected mode MUST:

1. Prioritize the `jti` check from their local revocation cache.
2. If the cache is stale (older than a configured threshold, default 5 minutes) AND network is available, attempt to sync revocations before treating a previously unseen `jti` as valid.
3. If sync fails, verifiers MAY proceed with the stale cache for badges within their TTL window, but SHOULD log a warning.

This ensures availability while maintaining security posture.

---

## 8. Verification

### 8.1 Verification Flow

```
1. Parse JWS token
2. Decode header and payload (unverified)
3. Validate structure:
   a. Header contains alg=EdDSA, typ=JWT
   b. Payload contains required claims (jti, iss, sub, iat, exp, vc)
4. Fetch CA public key:
   a. Online: GET {iss}/.well-known/jwks.json
   b. Offline: Load pre-configured CA JWK
5. Verify signature against CA public key
6. Validate claims:
   a. exp > current_time (not expired)
   b. iat <= current_time (not issued in future)
   c. iss is in verifier's trusted issuer list
   d. aud (if present) includes verifier's identity
7. Check revocation status against the CA:
   a. Online: GET https://registry.capisc.io/v1/badges/{jti}/status
   b. Offline: Check local revocation cache (see §7.4 Cache Staleness)
8. Check agent status:
   a. Online: GET https://registry.capisc.io/v1/agents/{id}/status
   b. Offline: Consult locally cached agent status
   c. Reject if status is not "active"
9. Return verified claims OR reject with error
```

### 8.2 Verification Modes

| Mode | Key Source | Revocation Check | Use Case |
|------|------------|------------------|----------|
| **Online** | Fetch from `{iss}/.well-known/jwks.json` | Real-time API call | High-security, always-connected |
| **Offline** | Pre-loaded CA JWK | Local cache (sync periodically) | Air-gapped, edge, latency-sensitive |

### 8.3 Audience Validation

If the Badge contains an `aud` claim:

- Verifier MUST check that its own identity appears in `aud`.
- If `aud` is present and verifier is not listed, verification MUST fail.
- If `aud` is absent, the Badge is valid for any audience.

**Production Recommendations:**

- Issuers SHOULD include `aud` for production badges.
- `aud` entries SHOULD be origin URIs or stable trust domain identifiers, e.g., `https://api.example.com` or `urn:capiscio:trust-domain:finance-us`.
- For high-risk workflows, verifiers SHOULD require `aud` to be present and matched.
- Verifiers MAY log warnings when accepting badges without `aud` in production.

**Registry Self-Audience:**

When an agent uses a Badge to authenticate to the Registry API itself (e.g., to update its own profile), the Registry MUST accept badges where:

- `aud` is absent (open audience), OR
- `aud` includes `https://registry.capisc.io`

Agents managing their own Registry records SHOULD request badges with `aud: ["https://registry.capisc.io"]` for defense-in-depth.

### 8.4 Error Codes

| Error | Description |
|-------|-------------|
| `BADGE_MALFORMED` | JWS structure is invalid |
| `BADGE_SIGNATURE_INVALID` | Signature verification failed |
| `BADGE_EXPIRED` | Current time ≥ `exp` |
| `BADGE_NOT_YET_VALID` | Current time < `iat` |
| `BADGE_ISSUER_UNTRUSTED` | `iss` not in trusted issuer list |
| `BADGE_AUDIENCE_MISMATCH` | Verifier not in `aud` |
| `BADGE_REVOKED` | Badge `jti` is on revocation list |
| `BADGE_CLAIMS_INVALID` | Required claims missing or malformed |
| `BADGE_AGENT_DISABLED` | Agent `sub` is disabled (see §7.4) |

These are spec-level error codes, not HTTP status codes. Gateways and libraries MAY expose these as machine-readable error codes in JSON responses or logs:

```json
{"error": "BADGE_EXPIRED", "message": "Badge expired at 2025-12-09T15:05:00Z"}
```

---

## 9. Transport

### 9.1 HTTP Header

Badges MUST be transmitted via HTTP header:

```http
X-Capiscio-Badge: eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOi...
```

Alternatively, the standard `Authorization` header MAY be used:

```http
Authorization: Badge eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOi...
```

### 9.2 Transport Security

- Badges MUST only be transmitted over HTTPS (TLS 1.2+).
- Deployments SHOULD prefer TLS 1.3 where available.
- Badges MUST NOT be logged in full (log `jti` only).
- Badges SHOULD NOT be included in URL query parameters.

---

## 10. Security Considerations

### 10.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Badge theft** (logs, proxies) | Short TTL (5 min default), HTTPS mandatory, log `jti` only |
| **Replay attack** | Short TTL; v1 accepts replay within TTL window |
| **CA key compromise** | Key rotation procedures, HSM for production |
| **Mis-issuance** | Audit logs, rate limiting, trust level validation |
| **Expired Badge acceptance** | Strict `exp` validation required |
| **Wrong issuer acceptance** | Explicit trusted issuer allowlist |

### 10.2 Replay Protection (v1)

In v1, Badges are **short-lived bearer tokens**:

- Replay within TTL window is acceptable.
- Verifiers MUST NOT assume request uniqueness.
- For request-level binding, use `X-Capiscio-Request-Sig` (future RFC).

### 10.3 Key Management

| Environment | CA Key Storage | Recommendation |
|-------------|----------------|----------------|
| Development | Environment variable or file | Acceptable |
| Staging | Encrypted file or secret manager | Recommended |
| Production | HSM (Vault, AWS KMS, GCP KMS) | Required |

### 10.4 Assumptions

- All Badge transport occurs over TLS.
- Badge issuance endpoints are authenticated and rate-limited.
- Verifiers explicitly configure trusted issuers.
- CA private key is protected per §10.3.

---

## 11. JWKS Endpoint

The CA MUST expose its public key(s) at a well-known endpoint:

```
GET /.well-known/jwks.json

Response:
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "ca-key-2025-01",
      "x": "base64url-encoded-public-key",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

**Key Rotation:**

- New keys SHOULD be added before old keys are retired.
- Old keys MUST remain in JWKS until all Badges signed with them expire.
- `kid` (Key ID) SHOULD include a date or version indicator.

---

## 12. API Reference

### 12.1 Badge Issuance

```
POST /v1/agents/{agentId}/badge
Authorization: Bearer <token>
Content-Type: application/json

Request:
{
  "ttl": 300,           // Optional, seconds, default 300
  "audience": ["..."]   // Optional, array of audience URIs
}

Response (200 OK):
{
  "badge": "<jws-token>",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "expiresAt": "2025-12-09T15:05:00Z"
}

Errors:
- 400: Invalid request (TTL out of range)
- 401: Unauthorized
- 404: Agent not found
- 409: Agent has no public key registered
- 429: Rate limit exceeded
```

### 12.2 Badge Status

```
GET /v1/badges/{jti}/status

Response (200 OK):
{
  "jti": "550e8400-...",
  "sub": "did:web:registry.capisc.io:agents:my-agent",
  "revoked": false,
  "expiresAt": "2025-12-09T15:05:00Z"
}
```

### 12.3 Badge Revocation

```
POST /v1/badges/{jti}/revoke
Authorization: Bearer <admin-token>
Content-Type: application/json

Request:
{
  "reason": "Key compromise suspected"  // Optional
}

Response (200 OK):
{
  "jti": "550e8400-...",
  "revoked": true,
  "revokedAt": "2025-12-09T15:30:00Z"
}

Errors:
- 401: Unauthorized
- 403: Forbidden (not admin or not badge owner)
- 404: Badge not found
```

### 12.4 JWKS

```
GET /.well-known/jwks.json

Response (200 OK):
{
  "keys": [...]
}
```

### 12.5 Revocation List

```
GET /v1/revocations?since={ISO8601}&limit={int}

Response (200 OK):
{
  "revocations": [
    {
      "jti": "...",
      "revokedAt": "2025-12-09T15:30:00Z",
      "reason": "..."
    }
  ],
  "nextCursor": "...",
  "syncedAt": "2025-12-09T16:00:00Z"
}
```

---

## 13. Implementation Notes

### 13.1 CLI Commands

| Command | Description |
|---------|-------------|
| `capiscio key gen` | Generate Ed25519 keypair |
| `capiscio badge issue` | Request Badge from CA |
| `capiscio badge issue --self-sign` | Self-sign for local development only |
| `capiscio badge verify <token>` | Verify a Badge locally |
| `capiscio badge keep` | Daemon for automatic renewal |
| `capiscio trust add <jwk-file>` | Add CA public key to local trust store |
| `capiscio trust list` | List trusted CA keys |
| `capiscio trust remove <kid>` | Remove a trusted CA key |

**Offline Trust Store:**

For agents and verifiers operating in offline or air-gapped environments, the local trust store provides the CA public keys needed for badge verification without network access:

```bash
# Fetch and store the production CA key
curl -s https://registry.capisc.io/.well-known/jwks.json | \
  capiscio trust add --from-jwks -

# Verify a badge offline
capiscio badge verify <token> --offline
```

The trust store is located at `~/.capiscio/trust/` (or `$CAPISCIO_TRUST_PATH`).

**Self-Signed Badges (Development Only):**

In development environments, verifiers MAY trust a locally configured issuer for self-signed badges. The `--self-sign` flag generates a badge where the agent acts as its own issuer.

> ⚠️ **Warning:** In production, verifiers MUST restrict `iss` to the registry CA allowlist. Self-signed issuers MUST NOT be trusted in production deployments.

### 13.2 Server Responsibilities

| Responsibility | Endpoint |
|----------------|----------|
| CA key management | Internal |
| Badge issuance | `POST /v1/agents/{id}/badge` |
| JWKS publication | `GET /.well-known/jwks.json` |
| DID Document | `GET /agents/{id}/did.json` |
| Revocation management | `POST /v1/badges/{jti}/revoke` |
| Status checks | `GET /v1/badges/{jti}/status` |
| Revocation list | `GET /v1/revocations` |

### 13.3 Gateway Integration

The CapiscIO Gateway (RFC-001 §4.1 Pattern 2) validates Badges as follows:

1. Extract `X-Capiscio-Badge` header
2. Verify per §8.1 (including agent status check)
3. If valid:
   - Forward request with `X-Capiscio-Agent-ID: {sub}` header
   - Attach `X-Capiscio-Badge-JTI: {jti}` for downstream audit correlation
4. If invalid, return `401 Unauthorized` with error code from §8.4

The `X-Capiscio-Badge-JTI` header enables downstream services to correlate logs without storing or logging full tokens, consistent with §9.2.

**Authorization Delegation:**

Gateways MUST NOT make authorization decisions based solely on `sub` or other Badge claims and MUST delegate final authorization to the PDP or equivalent policy engine.

---

## 14. Future Work

The following are explicitly out of scope for v1:

| Feature | Target RFC |
|---------|------------|
| Per-request signing (`X-Capiscio-Request-Sig`) | RFC-003 |
| Delegation tokens (constrained badges) | RFC-003 |
| Hardware key binding (TPM/HSM on agent) | RFC-004 |
| Federated trust (cross-CA) | RFC-005 |
| Non-repudiation / audit-grade proofs | RFC-006 |

---

## Appendix A: Full Example

### A.1 Badge Request

```bash
curl -X POST https://registry.capisc.io/v1/agents/my-agent-001/badge \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ttl": 300}'
```

### A.2 Badge Response

```json
{
  "badge": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJpc3MiOiJodHRwczovL3JlZ2lzdHJ5LmNhcGlzYy5pbyIsInN1YiI6ImRpZDp3ZWI6cmVnaXN0cnkuY2FwaXNjLmlvOmFnZW50czpteS1hZ2VudC0wMDEiLCJpYXQiOjE3MzM3ODg4MDAsImV4cCI6MTczMzc4OTEwMCwia2V5Ijp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiLi4uIn0sInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJBZ2VudElkZW50aXR5Il0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRvbWFpbiI6ImZpbmFuY2UuZXhhbXBsZS5jb20iLCJsZXZlbCI6IjEifX19.SIGNATURE",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "expiresAt": "2025-12-09T15:05:00Z"
}
```

### A.3 Using the Badge

```bash
curl https://api.example.com/v1/task \
  -H "X-Capiscio-Badge: eyJhbGciOiJFZERTQSIs..." \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "a2a/sendMessage", ...}'
```

---

## Appendix B: Comparison with Related Standards

| Feature | CapiscIO Badge | SPIFFE SVID | W3C VC | X.509 |
|---------|---------------|-------------|--------|-------|
| Format | JWS (JWT) | X.509 or JWT | JSON-LD | ASN.1 |
| Identifier | `did:web` | SPIFFE ID | DID | Subject DN |
| Issuer Model | Centralized CA | Per-domain SPIRE | Decentralized | Hierarchical CA |
| Offline Verify | ✅ (embedded key) | ✅ (trust bundle) | ✅ (DID cache) | ✅ (CA chain) |
| Revocation | Blocklist API | TTL-based | StatusList2021 | CRL/OCSP |
| Primary Use | AI Agent Identity | Workload Identity | Human/Org Identity | Server Identity |

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-09 | Initial release (Approved) |
