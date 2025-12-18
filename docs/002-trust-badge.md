# RFC-002: CapiscIO Trust Badge Specification

**Version:** 1.1
**Status:** Approved
**Authors:** CapiscIO Core Team
**Created:** 2025-12-09
**Updated:** 2025-12-12
**Requires:** RFC-001 (AGCP), RFC-003 (Key Ownership Proof Protocol, for IAL-1)

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
| Trust Graph membership | Badge `iss` (CA) + `vc.credentialSubject.level` |
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
| **CA (Certificate Authority)** | The CapiscIO Registry that issues and signs registry-backed badges (levels 1–4). Self-signed level 0 badges do not use the CA; the agent acts as its own issuer. |
| **Issuer** | The entity that signed the Badge, identified by the `iss` claim. For registry-backed badges, this is the CA. For self-signed badges, `iss` = `sub`. |
| **Subject** | The agent identified by the `sub` claim (DID) |
| **Verifier** | Any entity that validates a Badge |
| **Trust Level** | A numeric indicator (0–4) of validation rigor. Level 0 = self-signed; levels 1–4 = registry-backed. |

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
  "typ": "JWT",
  "kid": "ca-key-2025-01"
}
```

| Field | Requirement | Value |
|-------|-------------|-------|
| `alg` | REQUIRED | `EdDSA` (Ed25519). Implementations MAY support `ES256`. |
| `typ` | REQUIRED | `JWT` |
| `kid` | RECOMMENDED | Key ID referencing the signing key in the issuer's JWKS. For registry-issued badges, this SHOULD match a `kid` in `/.well-known/jwks.json`. For self-signed level 0 badges, this SHOULD be the subject's key fragment (e.g., `did:key:z6Mk...#z6Mk...`). Omitting `kid` forces verifiers to try all keys in the JWKS, which is inefficient. |

### 4.3 Payload (Claims)

```json
{
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "https://registry.capisc.io",
  "sub": "did:web:registry.capisc.io:agents:my-agent-001",
  "aud": ["https://api.example.com"],
  "iat": 1733788800,
  "exp": 1733789100,
  "ial": "0",
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
| `iss` | REQUIRED | Issuer URL or DID. For registry-issued badges (levels 1–4), MUST be the CA URL (e.g., `https://registry.capisc.io`). For self-signed badges (level 0), `iss` = `sub` (the agent's `did:key`). In production environments that rely on registry-backed badges, `iss` MUST identify a CA in the verifier's registry CA allowlist. Verifiers that explicitly opt into trusting self-signed level 0 badges MAY additionally allow specific `did:key` issuers that have been added to their local trust store. |
| `sub` | REQUIRED | Subject DID. MUST be a valid DID identifier. For development (level 0), `sub` SHOULD be a `did:key`. For production (levels 1–4), `sub` SHOULD be a `did:web` (see §6). |
| `aud` | OPTIONAL | Audience. Array of trust domains/services where Badge is valid. |
| `iat` | REQUIRED | Issued At. Unix timestamp (seconds). |
| `exp` | REQUIRED | Expiry. Unix timestamp (seconds). |
| `nbf` | OPTIONAL | Not Before. Unix timestamp (seconds). If present, Badge MUST NOT be accepted before this time. |

#### 4.3.2 CapiscIO-Specific Claims

| Claim | Requirement | Description |
|-------|-------------|-------------|
| `key` | REQUIRED | Subject's public key (JWK). This is the **agent's signing key**, not the CA key. Verifiers use this key to verify signatures the agent produces (e.g., delegation tokens, PoP proofs). Non-production deployments MAY temporarily relax this requirement as described below. |
| `vc` | REQUIRED | Verifiable Credential object containing identity assertions. For level 0, `vc` MUST contain at least `credentialSubject.level = "0"`; other fields are OPTIONAL. |
| `ial` | REQUIRED | Identity Assurance Level. `"0"` for account-attested issuance, `"1"` for proof-of-possession issuance. See §7.2.1 for definitions. |

**Level 0 IAL Constraint:**

For trust level `"0"` (self-signed) badges, `ial` MUST be `"0"` and `cnf` MUST NOT be present. IAL-1 requires issuer-subject separation; a self-signed badge where `iss = sub` cannot provide meaningful issuance-time key binding assurance beyond the self-asserted signature itself. Badges with `vc.credentialSubject.level="0"` and `ial="1"` MUST be rejected.

> **Implementation Note:** In non-production environments, implementations MAY omit `key` for test badges when offline verification is not required. Production badges MUST always include `key`.

**Key Rotation Behavior:**

The `key` claim is embedded at badge issuance time. If the agent rotates its keys after badge issuance:

- **Verifiers MUST use the embedded `key`** for verifying agent-produced signatures for the lifetime of the badge.
- **Key rotation requires a new badge.** The old badge remains valid until expiry but binds to the old key.
- If `did_doc_hash` is present and a verifier detects a mismatch with the current DID Document, the verifier SHOULD log a warning but MUST NOT reject the badge solely on this basis. The mismatch indicates key rotation occurred and a newer badge should be requested.

This ensures deterministic verification: the badge is self-contained and does not require re-resolution during its validity window.

#### 4.3.3 Conditional and Optional Claims

The following claims have conditional or optional requirements:

| Claim | Requirement | Description |
|-------|-------------|-------------|
| `cnf` | REQUIRED if `ial="1"` | Confirmation key (RFC 7800). Binds the badge to a specific key holder. MUST be present when `ial="1"`. MUST NOT be present when `ial="0"`. |
| `agent_card_hash` | OPTIONAL | SHA-256 hash of the canonical AgentCard JSON at issuance time. Enables verifiers to detect AgentCard drift. Format: `sha256:<base64url-hash>`. See **Canonical Hashing** below. |
| `did_doc_hash` | OPTIONAL | SHA-256 hash of the DID Document at issuance time. Enables verifiers to detect key rotation. Format: `sha256:<base64url-hash>`. |
| `pop_challenge_id` | OPTIONAL | Reference to the PoP challenge that was used during issuance (see §7.2.2). Provides audit trail for PoP-issued badges. |

**Confirmation Key (`cnf`) Semantics:**

The `cnf` claim records which key was verified during PoP issuance. It does NOT by itself enforce request-level proof-of-possession—that requires a separate request-signature mechanism (future work).

- **If `ial="1"`:** `cnf` MUST be present. It proves the issuer verified key control at badge issuance time.
- **If `ial="0"`:** `cnf` MUST NOT be present. Verifiers MUST NOT interpret absence of `cnf` as evidence of anything other than account-attested issuance.

Verifiers MAY use `cnf` for request-level PoP when the deployment implements a request-signature mechanism. Until such a mechanism is standardized, `cnf` serves as an audit record of issuance-time key binding.

This claim is populated automatically when badges are issued via the PoP challenge flow (§7.2.2, RFC-003).

For v1, implementations MUST use `cnf.kid` (not `cnf.jkt` or `cnf.jwk`):

```json
{
  "cnf": {
    "kid": "did:web:registry.capisc.io:agents:my-agent#key-1"
  }
}
```

**`cnf.kid` Requirements:**

- `cnf.kid` MUST be a DID URL fragment referencing a `verificationMethod` in the agent's DID Document.
- For `did:web`, this is typically `{did}#key-1` or another fragment defined in the DID Document.
- For `did:key`, the fragment is the full multibase-encoded key: `{did}#{multibase-key}`.
- For `ial="1"` badges, verifiers MUST resolve the DID Document and dereference `cnf.kid` to a `verificationMethod`.
- Verifiers MUST compare the public key material from that `verificationMethod` to the badge's embedded `key` claim. Keys match if the underlying public key bytes are equivalent after normalizing formats (e.g., `publicKeyMultibase` vs JWK `x` for Ed25519).
- If the keys do not match exactly, the verifier MUST reject the badge with `BADGE_CLAIMS_INVALID`.

**Canonical Hashing:**

When computing `agent_card_hash` or `did_doc_hash`, implementations MUST use the following canonicalization rules to ensure deterministic hashing:

1. **Serialize as JSON** using RFC 8785 (JSON Canonicalization Scheme / JCS):
   - Object keys sorted lexicographically (Unicode code point order)
   - No whitespace between tokens
   - Numbers in shortest form without trailing zeros
   - Strings escaped per RFC 8259
2. **Encode as UTF-8** bytes
3. **Hash with SHA-256**
4. **Encode hash as base64url** (no padding)
5. **Prefix with `sha256:`**

Example: `sha256:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564`

#### 4.3.4 Verifiable Credential Object

| Field | Requirement | Description |
|-------|-------------|-------------|
| `vc.type` | REQUIRED | MUST include `"VerifiableCredential"` and `"AgentIdentity"`. |
| `vc.credentialSubject.domain` | REQUIRED for levels ≥ 2 | Agent's home domain. MUST be validated according to the trust level's requirements in §5. OPTIONAL for level 1. |
| `vc.credentialSubject.level` | REQUIRED | Trust level: `"0"`, `"1"`, `"2"`, `"3"`, or `"4"`. For level `"0"`, verifiers MUST treat this as self-asserted only and MUST NOT infer any registry validation from its presence. |

**Extensibility:**

Additional fields in `credentialSubject` MUST NOT change the semantics of `level` and MUST be treated as informational by verifiers. Verifiers MUST ignore unknown fields.

### 4.4 Signature

The signature is computed over the JWS Signing Input using the issuer's private key (registry CA for levels 1–4, the agent's own key for level 0):

```
signature = EdDSA_Sign(Issuer_PrivateKey, ASCII(base64url(header) + "." + base64url(payload)))
```

---

## 5. Trust Levels

Trust Levels indicate the validation rigor applied during Badge issuance. For levels 1–4, this describes CA validation by the CapiscIO Registry; for level 0, it indicates that no external validation was performed.

| Level | Name | Validation Requirements | Use Case |
|-------|------|------------------------|----------|
| `"0"` | Self-Signed (SS) | None. Agent uses `did:key` and self-signs badges. | Local development, testing, demos |
| `"1"` | Registered (REG) | Account registration with CapiscIO Registry. Domain validation OPTIONAL. | Development, internal agents |
| `"2"` | Domain Validated (DV) | Level 1 + DNS TXT record OR HTTP challenge proving control of `domain` field | Production, B2B agents |
| `"3"` | Organization Validated (OV) | DV + Organization existence verification (DUNS, legal entity lookup) | High-trust production |
| `"4"` | Extended Validated (EV) | OV + Manual review + Legal agreement with CapiscIO | Regulated industries |

**Recommended DID and Issuer Mapping:**

| Level | Typical DID | Issuer |
|-------|-------------|--------|
| 0 | `did:key` | Self-signed (`iss` = `sub`) |
| 1–4 | `did:web` | CapiscIO Registry CA |

**Domain Requirement:**

For trust levels 2 and above, the `vc.credentialSubject.domain` field MUST be present and MUST have been validated according to the level's requirements.

For trust level 1, domain validation is OPTIONAL. If the `domain` field is present but not validated, verifiers SHOULD treat it as informational only.

For trust level 0 (self-signed), `vc` MUST include `credentialSubject.level = "0"`. Other fields (including `domain`) are OPTIONAL. The badge is still a pure identity assertion based on key ownership; the `vc` is present to keep the payload shape consistent across all trust levels. **Level 0 badges are always IAL-0**; they cannot claim PoP assurance because there is no issuer-subject separation.

**Verifier Behavior:**

- Verifiers MUST treat `level` as opaque beyond numeric comparison.
- Verifiers MAY enforce minimum trust levels via policy.
- Verifiers MUST NOT invent additional semantics for trust levels.
- In production, verifiers SHOULD reject level `"0"` badges by default and MAY explicitly opt in to trust selected `did:key` issuers via local policy for tightly scoped use cases.

---

## 6. DID Methods

CapiscIO supports two W3C-standard DID methods to balance production security with development ergonomics.

### 6.0 Method Overview

| Method | Use Case | Resolution | Uniqueness |
|--------|----------|------------|------------|
| `did:key` | Development, testing, self-signed | Decode from DID itself | Cryptographic (key = DID) |
| `did:web` | Production, registry-hosted | HTTPS fetch | Registry or domain owner |

### 6.1 `did:key` (Development Mode)

The [`did:key`](https://w3c-ccg.github.io/did-method-key/) method derives the DID directly from the public key. This provides **zero-friction identity** for development and testing.

**Syntax:**

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
       └─────────────────────────────────────────────────────┘
                    Multibase-encoded public key
```

**Key Properties:**

- **No registration required**: Generate a keypair → you have a DID
- **No hosting required**: DID is self-describing, no resolution endpoint needed
- **Cryptographic uniqueness**: Impossible to have collisions (DID = hash of key)
- **Portable**: Take your key anywhere, DID follows

**Generation:**

```bash
# Generate keypair and did:key in one command
capiscio key gen --out my-agent.jwk
# Output includes: did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
```

**Encoding (Ed25519):**

1. Take raw 32-byte Ed25519 public key
2. Prepend multicodec prefix `0xed01` (Ed25519 public key)
3. Encode with multibase base58-btc (`z` prefix)

```
did:key:z + base58btc(0xed01 || public_key_bytes)
```

**Resolution:**

`did:key` is self-resolving. The DID Document is deterministically constructed from the DID itself:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [{
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }],
  "authentication": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]
}
```

**Trust Model:**

With `did:key`, the agent self-signs its own badges. There is no CA vouching for identity. Verifiers MUST explicitly add the agent's public key to their local trust store to accept these badges.

> ⚠️ **Warning:** `did:key` badges are for development only. Production verifiers MUST NOT accept `did:key` badges unless the specific key has been explicitly trusted.

### 6.2 `did:web` (Production Mode)

The [`did:web`](https://w3c-ccg.github.io/did-method-web/) method resolves DIDs via HTTPS. This is the **production method** for registry-issued identities.

**Syntax:**

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

### 6.3 `did:web` Resolution

Per the `did:web` specification, the DID resolves to an HTTPS URL:

```
did:web:registry.capisc.io:agents:my-agent-001
  → https://registry.capisc.io/agents/my-agent-001/did.json
```

| Endpoint | URL | Path Parameter | Returns |
|----------|-----|----------------|--------|
| DID Document | `GET https://registry.capisc.io/agents/<agent-id>/did.json` | `<agent-id>` from DID path | W3C DID Document |
| Agent API | `GET {iss}/v1/agents/{did}` | URL-encoded DID | Full agent record with AgentCard |

> **Path Parameter Conventions:**
>
> - **`<agent-id>`**: The path segment extracted from a `did:web` DID. For `did:web:registry.capisc.io:agents:my-agent-001`, the agent-id is `my-agent-001`. Used only for DID Document resolution per the `did:web` specification.
> - **`{did}`**: The full DID, URL-encoded. Used for all `/v1/agents/*` API endpoints. Example: `did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent-001`.

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

The DID Document is auto-generated from the agent's stored public key and AgentCard. The `/v1/agents/{did}` endpoint remains the authoritative source; `/agents/<agent-id>/did.json` is a standards-compliant view.

**Key Alignment:**

Implementations SHOULD ensure that the public key in the Badge `key` claim matches the primary `verificationMethod` in the agent's DID Document. A mismatch indicates either key rotation in progress or configuration drift and SHOULD be treated as a warning and investigated.

- For `ial="1"`, verifiers MUST resolve the DID Document and enforce `cnf.kid` key equivalence with `key` (per §8.1 step 7). A mismatch is a hard rejection.
- For `ial="0"`, cross-checking `key` against the DID Document is OPTIONAL; the CA signature is sufficient for authentication.

DID Documents exist for standards compatibility and portability.

### 6.4 Portability

Because CapiscIO uses standard `did:web`, agents have a clear migration path:

| Scenario | DID |
|----------|-----|
| Hosted by CapiscIO | `did:web:registry.capisc.io:agents:my-agent` |
| Self-hosted (migrated) | `did:web:my-company.com:agents:my-agent` |

To migrate, the agent operator:
1. Exports their keys and AgentCard from CapiscIO
2. Hosts `/agents/<id>/did.json` on their own domain
3. Registers the new DID and requests new badges where `sub` is the new DID

This eliminates vendor lock-in concerns.

**Issuance Scope:**

In production, Badges are issued by the CapiscIO Registry CA for `did:web:registry.capisc.io:*` identities. When agents migrate their DIDs to a self-hosted `did:web` domain, they MAY continue using registry-issued badges or operate their own CA (out of scope for this RFC).

### 6.5 Upgrade Path: `did:key` → `did:web`

Agents MAY start with `did:key` for development and upgrade to `did:web` for production:

1. **Development**: Use `did:key` with self-signed badges
2. **Staging**: Register with CapiscIO Registry, receive `did:web:registry.capisc.io:agents:<id>`
3. **Production**: Optionally complete domain validation for higher trust level

The keypair MAY be reused across this transition. The `did:key` and `did:web` will be different identifiers, but they can share the same underlying key material.

### 6.6 Relationship to AgentCard

- The **Badge** proves (depends on `ial`):
  - `ial="0"`: "The issuer attested this identity for an authorized account." (No proof of key control.)
  - `ial="1"`: "The issuer verified the requester controlled the private key for `sub` during issuance (PoP)." The badge may still be replayed if stolen unless the deployment also enforces request-level PoP (future work).
- The **DID Document** describes: "Agent `sub` has this public key and these service endpoints."
- The **AgentCard** describes: "Agent `sub` has these capabilities, skills, and detailed metadata."

Verifiers use the Badge for **authentication**. For registry-backed badges (levels 1–4), they MAY resolve the DID Document for key verification and MAY fetch the AgentCard for **capability discovery**. Level 0 `did:key` badges do not have an external DID Document.

---

## 7. Badge Lifecycle

> **Scope:** The issuance, renewal, and revocation flows in this section apply to **registry-issued badges** (trust levels 1–4). Self-signed level 0 badges are issued and managed locally via the CLI as described in §13.1 and are not subject to registry revocation.

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

**Preconditions (for registry-issued badges, levels 1–4):**

1. Agent MUST be registered in the Registry with a public key.
2. Agent MUST have completed trust level validation for the requested level (per §5).
3. Authentication depends on issuance mode:
   - For `mode="ial0"`, the requester MUST be authenticated via registry credential (`X-Capiscio-Registry-Key` or Clerk session).
   - For `mode="ial1"`, the challenge endpoint MUST be registry-authenticated, and the completion call is authenticated by `proof_jws` (registry credential OPTIONAL).

> **Note:** These preconditions do not apply to level 0 self-signed badges, which are issued locally via `capiscio badge issue --self-sign`.

**Issuance Flow:**

```
Agent                          Registry (CA)
  │                                 │
  │  POST /v1/agents/{did}/badge    │
  │  X-Capiscio-Registry-Key: ...   │
  │  {mode: "ial0", ttl: 300}       │
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

### 7.2.1 Identity Assurance Levels

Trust Levels (§5) describe *validation rigor* (domain verification, organization checks, etc.). **Identity Assurance Levels** describe *key binding assurance*—how confident the verifier can be that the badge holder controls the DID's private key.

| Assurance Level | Name | Preconditions | What It Proves | What It Does NOT Prove |
|-----------------|------|---------------|----------------|------------------------|
| **IAL-0** | Account-Attested | Authenticated account (Clerk session or API Key) + agent ownership check | "Account X requested a badge for agent DID Y" | Requester holds the DID private key |
| **IAL-1** | Proof of Possession (PoP) | IAL-0 + successful PoP challenge-response | "Requester held the private key bound to DID Y at issuance time" | Presenter still controls key at verification time; request-level PoP (badge can be replayed if stolen) |

**Current Implementation (IAL-0):**

The current `POST /v1/agents/{did}/badge` endpoint implements IAL-0. Badges issued at this level:

- Are **bearer tokens** bound to the authenticated account
- Prove that an authorized account holder requested the badge
- Do NOT cryptographically prove the requester controls the agent's private key
- Are suitable for controlled environments where account authorization is sufficient

**Proof of Possession Issuance (IAL-1):**

IAL-1 badges are issued via a two-phase challenge-response flow defined in RFC-003. Badges issued at this level:

- Require the requester to sign a challenge nonce with the DID's private key
- Prove that the requester controls the private key corresponding to the DID
- Include the `cnf` claim binding the badge to the verified key
- Are suitable for high-security environments requiring cryptographic key binding

**Verifier Guidance:**

| Environment | Recommended Assurance Level |
|-------------|----------------------------|
| Development, testing | IAL-0 sufficient |
| Internal enterprise agents | IAL-0 or IAL-1 based on policy |
| Production B2B agents | IAL-1 recommended |
| Regulated industries | IAL-1 required |

**Issuer Guidance:**

For trust levels 2–4, issuers SHOULD issue badges with `ial="1"` by default. IAL-0 issuance for levels 2–4 is permitted for backward compatibility but SHOULD be phased out.

Verifiers MAY enforce minimum assurance levels via policy. The `ial` claim is the authoritative indicator of issuance assurance; the `cnf` claim provides supporting evidence of key binding but is not the primary indicator.

### 7.2.2 Proof of Possession Issuance Flow

> **Reference:** The complete PoP challenge protocol is defined in RFC-003: Key Ownership Proof Protocol.

**Audience Terminology:**

The challenge response contains `proof_aud` (the audience for the proof JWT, always the registry origin) and `badge_aud` (the requested audience for the issued badge). These are distinct: `proof_aud` binds the proof to the registry; `badge_aud` is propagated to the issued badge's `aud` claim.

**Overview:**

```
Agent                              Registry (CA)
  │                                     │
  │  POST /v1/agents/{did}/badge/challenge
  │  X-Capiscio-Registry-Key: ...       │
  │  { badge_aud: [...] }               │
  │────────────────────────────────────►│
  │                                     │
  │  200 OK                             │
  │  { challenge_id, nonce, expires_at, │
  │    proof_aud, htu, htm, badge_aud } │
  │◄────────────────────────────────────│
  │                                     │
  │  [Agent signs challenge with DID key]
  │                                     │
  │  POST /v1/agents/{did}/badge        │
  │  { mode:"ial1", challenge_id,       │
  │    proof_jws }  (no API key needed) │
  │────────────────────────────────────►│
  │                                     │
  │                        1. Verify PoP proof (authenticates request)
  │                        2. Verify challenge exists, not expired
  │                        3. Resolve DID Document
  │                        4. Verify proof_jws signature
  │                        5. Mark challenge as used
  │                        6. Issue badge with cnf claim
  │                                     │
  │  200 OK                             │
  │  { badge: "<jws>", cnf: {...} }     │
  │◄────────────────────────────────────│
```

**Key Resolution:**

For signature verification, the CA resolves keys based on the DID method:

- **`did:key`**: Keys are derivable from the DID itself; no network fetch required.
- **`did:web`**: Keys are fetched from the DID Document per the `did:web` specification. Path components after the domain are converted to URL path segments, with `/did.json` appended. For example:
  - `did:web:example.com` → `https://example.com/.well-known/did.json`
  - `did:web:registry.capisc.io:agents:my-agent` → `https://registry.capisc.io/agents/my-agent/did.json`

The CA MUST NOT use the `jwks_url` from the AgentCard as the primary trust anchor. The DID Document is authoritative for key material.

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

In v1 production, all registry-backed badges (levels 1–4) are issued by the CapiscIO Registry CA (`iss = "https://registry.capisc.io"`), and revocation and agent status endpoints are hosted on the same origin. Level 0 self-signed badges use `iss = sub` (the agent's `did:key`) and are not covered by registry revocation APIs—revocation for level 0 is effectively "remove the key from the local trust store" plus TTL expiry. Future RFCs MAY define additional CAs and corresponding revocation endpoints.

**Revocation Semantics:**

- Revocation is by `jti` (Badge ID) only.
- Revoking a Badge does NOT revoke the agent or other Badges.
- To disable an agent entirely, use `POST /v1/agents/{did}/disable` (see below).

**Agent-Level Disablement:**

Verifiers SHOULD treat any Badge with `sub` belonging to a disabled agent as invalid, even if the Badge itself is not individually revoked. Gateways MUST check agent status using `GET {iss}/v1/agents/{did}/status` before accepting any Badge for that `sub`.

```
GET {iss}/v1/agents/{did}/status

Response:
{
  "did": "did:web:registry.capisc.io:agents:my-agent-001",
  "status": "active",       // or "disabled", "suspended"
  "disabledAt": null,
  "reason": null
}
```

```
POST {iss}/v1/agents/{did}/disable
X-Capiscio-Registry-Key: <admin-api-key>
Content-Type: application/json

{
  "reason": "Security incident"  // Optional
}
```

**Revocation API:**

```
POST {iss}/v1/badges/{jti}/revoke
X-Capiscio-Registry-Key: <admin-api-key>
Content-Type: application/json

{
  "reason": "Key compromise suspected"
}
```

**Revocation Check:**

```
GET {iss}/v1/badges/{jti}/status

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
GET {iss}/v1/revocations?since=2025-12-09T00:00:00Z

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

> **Note:** For registry-issued badges (levels 1–4), all steps apply. For self-signed level 0 badges, the verifier loads the public key from its local trust store (step 4b) and skips registry revocation/agent status checks (steps 7–8) since no CA is involved.

```
1. Parse JWS token
2. Decode header and payload (unverified)
3. Validate structure:
   a. Header contains alg=EdDSA, typ=JWT
   b. Payload contains required claims (jti, iss, sub, iat, exp, ial, key, vc)
   c. vc.credentialSubject.level is present
   d. ial is "0" or "1"
   e. If ial="1", cnf MUST be present (reject if absent)
   f. If ial="0", cnf MUST NOT be present (reject if present)
   g. If level="0", ial MUST be "0" (reject level 0 badges with ial="1")
   h. Verifiers MUST reject badges missing `key` unless explicitly configured for non-production testing
4. Fetch verification key:
   a. Registry-issued (levels 1–4): GET {iss}/.well-known/jwks.json or use cached CA JWK. Verifiers MUST NOT dereference `{iss}` unless it is already in the trusted issuer allowlist (SSRF defense).
   b. Self-signed (level 0): Load the public key for `iss` (which equals `sub`) from the local trust store
5. Verify signature against verification key
6. Validate claims:
   a. exp > current_time (not expired)
   b. iat <= current_time (not issued in future)
   c. iss is in verifier's trusted issuer list (for level 0, the did:key must be explicitly trusted)
   d. aud (if present) includes verifier's identity
7. Validate IAL-1 key binding (if ial="1"):
   a. Resolve the DID Document for `sub`
   b. Dereference `cnf.kid` to a `verificationMethod` in the DID Document
   c. Compare the public key material from that `verificationMethod` to the badge `key` claim
   d. If keys do not match exactly (same key bytes after format normalization), reject with BADGE_CLAIMS_INVALID
8. Check revocation status (registry-issued only):
   a. Online: GET {iss}/v1/badges/{jti}/status
   b. Offline: Check local revocation cache (see §7.4 Cache Staleness)
9. Check agent status (registry-issued only):
   a. Online: GET {iss}/v1/agents/{did}/status
   b. Offline: Consult locally cached agent status
   c. Reject if status is not "active"
10. Return verified claims OR reject with error
```

### 8.2 Verification Modes

| Mode | Key Source | Revocation Check | Use Case |
|------|------------|------------------|----------|
| **Online** (levels 1–4) | Fetch from `{iss}/.well-known/jwks.json` | Real-time API call | High-security, always-connected |
| **Offline** (levels 1–4) | Pre-loaded CA JWK | Local cache (sync periodically) | Air-gapped, edge, latency-sensitive |
| **Self-signed** (level 0) | Local trust store | None (TTL-based only) | Development, testing, demos |

### 8.3 Audience Validation

If the Badge contains an `aud` claim:

- Verifier MUST check that its own identity appears in `aud`.
- If `aud` is present and verifier is not listed, verification MUST fail.
- If `aud` is absent, the Badge is valid for any audience.

**Production Recommendations:**

- For trust levels 2–4, issuers SHOULD include `aud`. Verifiers in production environments SHOULD require `aud` via policy (reject badges without `aud` by default).
- `aud` entries SHOULD be origin URIs or stable trust domain identifiers, e.g., `https://api.example.com` or `urn:capiscio:trust-domain:finance-us`.
- For high-risk workflows, verifiers MUST require `aud` to be present and matched.
- Verifiers MAY log warnings when accepting badges without `aud` in production.
- For trust levels 0–1, `aud` remains OPTIONAL but RECOMMENDED for defense-in-depth.

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
| `BADGE_AGENT_DISABLED` | Agent `sub` is disabled (see §7.4). Applies only to registry-issued badges (levels 1–4). Level 0 self-signed badges are not tracked in the registry and cannot be "disabled" via registry status. |

These are spec-level error codes, not HTTP status codes. Gateways and libraries MAY expose these as machine-readable error codes in JSON responses or logs:

```json
{"error": "BADGE_EXPIRED", "message": "Badge expired at 2025-12-09T15:05:00Z"}
```

---

## 9. Transport

### 9.1 HTTP Header

Badges MUST be transmitted via HTTP header. Implementations MUST support both of the following headers:

**Preferred (proxy-compatible):**

```http
Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOi...
```

**Alternative (explicit):**

```http
X-Capiscio-Badge: eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOi...
```

The `Authorization: Bearer` form is RECOMMENDED for production deployments due to better compatibility with proxies, load balancers, and existing tooling. Despite using the Bearer scheme, CapiscIO Badges are identity assertions and are NOT OAuth 2.0 access tokens.

**Header Precedence:**

If both headers are present, verifiers MUST use `X-Capiscio-Badge` (the explicit header takes precedence). However, verifiers SHOULD reject requests containing both headers unless explicitly configured to allow it. This prevents confusion attacks in mixed environments where OAuth tokens and Badges coexist on the same endpoints.

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
| **Issuer key compromise** (registry CA for prod, agent key for level 0) | Key rotation procedures, HSM for production CA |
| **Mis-issuance** | Audit logs, rate limiting, trust level validation |
| **Expired Badge acceptance** | Strict `exp` validation required |
| **Wrong issuer acceptance** | Explicit trusted issuer allowlist |

### 10.2 Replay Protection (v1)

In v1, Badges are **short-lived bearer tokens**:

- Replay within TTL window is acceptable.
- Verifiers MUST NOT assume request uniqueness.
- For request-level binding, use `X-Capiscio-Request-Sig` (future RFC).

### 10.3 Key Management

| Environment | Issuer Key Storage | Recommendation |
|-------------|----------------|----------------|
| Development | Environment variable or file | Acceptable |
| Staging | Encrypted file or secret manager | Recommended |
| Production | HSM (Vault, AWS KMS, GCP KMS) | Required |

> **Note:** This table applies primarily to the registry CA keys used for levels 1–4. Self-signed level 0 agent keys follow the same general guidance; in non-development environments, secure storage is recommended even for agent keys.

### 10.4 Assumptions

- All Badge transport occurs over TLS.
- Badge issuance endpoints are authenticated and rate-limited.
- Verifiers explicitly configure trusted issuers.
- CA private key is protected per §10.3.

---

## 11. JWKS Endpoint

> **Scope:** This section applies to registry-issued badges (trust levels 1–4). Self-signed level 0 badges do not use a JWKS endpoint.

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

> **Scope:** This section documents the Registry API for registry-issued badges (trust levels 1–4). Self-signed level 0 badges are managed locally via the CLI (see §13.1).

**Registry Authentication:**

Registry API endpoints use `X-Capiscio-Registry-Key` for API key authentication (or Clerk session cookies for browser-based access). This header is distinct from `Authorization: Bearer`, which is reserved for badge authentication.

### 12.1 Badge Issuance

```
POST /v1/agents/{did}/badge
Content-Type: application/json
```

**IAL-0 request (registry-authenticated):**

```http
X-Capiscio-Registry-Key: <api-key>
```

```json
{
  "mode": "ial0",
  "ttl": 300,
  "badge_aud": ["..."]
}
```

> **Note:** `badge_aud` is copied into the issued badge's `aud` claim.

**IAL-1 request (PoP-authenticated, no registry key required):**

```json
{
  "mode": "ial1",
  "challenge_id": "...",
  "proof_jws": "..."
}
```

**Authentication Rules:**

- For `mode="ial0"`, `X-Capiscio-Registry-Key` (or Clerk session cookie) is **REQUIRED**.
- For `mode="ial1"`, the request is authenticated by `proof_jws` and `X-Capiscio-Registry-Key` is **OPTIONAL**.

**Response (200 OK):**

```json
{
  "badge": "<jws-token>",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "expiresAt": "2025-12-09T15:05:00Z"
}
```

**Errors:**

- 400: Invalid request (TTL out of range, malformed proof)
- 401: Unauthorized (missing auth for IAL-0, invalid proof for IAL-1)
- 404: Agent not found
- 409: Agent has no public key registered
- 429: Rate limit exceeded

### 12.1.1 IAL-1 Challenge Endpoint

Initiate a Proof of Possession challenge for IAL-1 badge issuance.

```
POST /v1/agents/{did}/badge/challenge
X-Capiscio-Registry-Key: <api-key>
Content-Type: application/json
```

**Request:**

```json
{
  "badge_aud": ["https://api.example.com"],
  "badge_ttl": 300,
  "challenge_ttl": 300
}
```

| Field | Requirement | Description |
|-------|-------------|-------------|
| `badge_aud` | OPTIONAL | Audience claim to include in the issued badge |
| `badge_ttl` | OPTIONAL | Requested badge TTL in seconds (default: 300). MUST respect issuance constraints in §7.2 (min 60, max 3600 unless deployment overrides). |
| `challenge_ttl` | OPTIONAL | Challenge validity window in seconds (default: 300, max: 600) |

**Response (200 OK):**

```json
{
  "challenge_id": "ch-550e8400-e29b-41d4-a716-446655440000",
  "nonce": "random-challenge-nonce-base64url",
  "challenge_expires_at": "2025-12-09T15:05:00Z",
  "proof_aud": "https://registry.capisc.io",
  "htu": "https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent-001/badge",
  "htm": "POST",
  "badge_aud": ["https://api.example.com"],
  "badge_ttl": 300
}
```

| Field | Description |
|-------|-------------|
| `challenge_id` | Unique identifier for this challenge (use in badge request) |
| `nonce` | Random value the agent must sign |
| `challenge_expires_at` | Challenge expiration (typically 5 minutes) |
| `proof_aud` | Audience for the proof JWT (always the registry origin) |
| `htu` | HTTP Target URI for the proof. MUST be the exact final URL including URL encoding, scheme, host, and path. |
| `htm` | HTTP Method for the proof |
| `badge_aud` | Echo of requested badge audience |
| `badge_ttl` | Echo of requested badge TTL |

**Errors:**

- 401: Unauthorized (missing or invalid API key)
- 404: Agent not found
- 409: Agent has no public key registered
- 429: Rate limit exceeded (challenge creation is rate-limited)

**Additional errors for `POST /v1/agents/{did}/badge` with `mode="ial1"`:**

- 400: Challenge expired
- 409: Challenge already used

> **Reference:** The proof JWT format and signing requirements are defined in RFC-003: Key Ownership Proof Protocol.

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
X-Capiscio-Registry-Key: <admin-api-key>
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
- 401: Unauthorized (missing or invalid API key)
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
| `capiscio key gen` | Generate Ed25519 keypair and `did:key` |
| `capiscio badge issue` | Request Badge from CA (requires registry account) |
| `capiscio badge issue --self-sign` | Self-sign Badge using `did:key` (development only) |
| `capiscio badge verify <token>` | Verify a Badge locally |
| `capiscio badge keep` | Daemon for automatic renewal |
| `capiscio trust add <jwk-file>` | Add public key to local trust store |
| `capiscio trust list` | List trusted keys |
| `capiscio trust remove <kid>` | Remove a trusted key |

**Offline Trust Store:**

For agents and verifiers operating in offline or air-gapped environments, the local trust store provides the trusted public keys (registry CA keys and explicitly trusted agent keys) needed for badge verification without network access:

```bash
# Fetch and store the production CA key
curl -s https://registry.capisc.io/.well-known/jwks.json | \
  capiscio trust add --from-jwks -

# Verify a badge offline
capiscio badge verify <token> --offline
```

The trust store is located at `~/.capiscio/trust/` (or `$CAPISCIO_TRUST_PATH`).

**Self-Signed Badges (Development Only):**

In development environments, the `--self-sign` flag generates a `did:key`-based badge where the agent acts as its own issuer:

```bash
# Generate keypair (outputs did:key)
capiscio key gen --out my-agent.jwk
# → did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK

# Issue self-signed badge
capiscio badge issue --self-sign --key my-agent.jwk --exp 1h > badge.jwt

# Verify (must trust the key first)
capiscio trust add my-agent.jwk
capiscio badge verify badge.jwt
```

Self-signed badges have:
- `sub`: The `did:key` derived from the keypair
- `iss`: Same as `sub` (agent is its own issuer)
- `vc.credentialSubject.level`: `"0"` (self-signed)

> ⚠️ **Warning:** In production, verifiers MUST restrict `iss` to the registry CA allowlist. Self-signed `did:key` badges MUST NOT be accepted in production unless the specific key has been explicitly trusted.

### 13.2 Server Responsibilities

| Responsibility | Endpoint |
|----------------|----------|
| CA key management | Internal |
| Badge issuance | `POST /v1/agents/{did}/badge` |
| JWKS publication | `GET /.well-known/jwks.json` |
| DID Document | `GET /agents/{agent-id}/did.json` |
| Revocation management | `POST /v1/badges/{jti}/revoke` |
| Status checks | `GET /v1/badges/{jti}/status` |
| Revocation list | `GET /v1/revocations` |

### 13.3 Gateway Integration

The CapiscIO Gateway (RFC-001 §4.1 Pattern 2) validates Badges as follows:

1. Extract badge from `Authorization: Bearer <badge>` or `X-Capiscio-Badge` header (per §9.1 precedence rules)
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

- Per-request signing (`X-Capiscio-Request-Sig`)
- Delegation tokens (constrained badges)
- Hardware key binding (TPM/HSM on agent)
- Federated trust (cross-CA)
- Non-repudiation / audit-grade proofs

---

## Appendix A: Full Example

### A.1 Badge Request

```bash
curl -X POST https://registry.capisc.io/v1/agents/did%3Aweb%3Aregistry.capisc.io%3Aagents%3Amy-agent-001/badge \
  -H "X-Capiscio-Registry-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"mode": "ial0", "ttl": 300, "badge_aud": ["https://api.example.com"]}'
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
| Identifier | `did:key` (dev) / `did:web` (prod) | SPIFFE ID | DID | Subject DN |
| Issuer Model | Self-signed (dev) / Centralized CA (prod) | Per-domain SPIRE | Decentralized | Hierarchical CA |
| Offline Verify | ✅ (embedded key) | ✅ (trust bundle) | ✅ (DID cache) | ✅ (CA chain) |
| Revocation | Blocklist API | TTL-based | StatusList2021 | CRL/OCSP |
| Primary Use | AI Agent Identity | Workload Identity | Human/Org Identity | Server Identity |

---

## Changelog

| Version | Date | Changes |
|---------|-----------|---------|
| 1.1 | 2025-12-12 | Added §12.1.1 challenge endpoint; split `badge_ttl`/`challenge_ttl`; exact `htu` URL encoding; challenge replay errors; SSRF defense note; unified path parameter conventions; **IAL-1 key binding now MUST match** (bait-and-switch defense); **level 0 badges MUST be IAL-0** (self-signed IAL-1 paradox fix) |
| 1.0 | 2025-12-09 | Initial release (Approved) |
