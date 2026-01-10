# RFC-005: Policy Definition, Distribution, and Enforcement (PDEP)

**Version:** 0.2  
**Status:** Draft  
**Authors:** CapiscIO Core Team  
**Created:** 2025-12-24  
**Updated:** 2026-01-02  
**Requires:** RFC-001 (AGCP), RFC-002 (Trust Badges), RFC-004 (Transaction and Hop Attestations)

---

## 1. Abstract

This RFC defines the CapiscIO **Policy Definition, Distribution, and Enforcement Plane (PDEP)**. PDEP standardizes:

1. A policy **decision contract** between Policy Enforcement Points (PEPs) and Policy Decision Points (PDPs).
2. A signed **policy bundle** format and distribution mechanism.
3. A first-class **obligations** model to express conditional controls (for example rate limiting, redaction, and escalation) as part of an allow decision.
4. Canonical **telemetry** that links runtime traces to the exact policy decision and policy version.

PDEP is engine-agnostic: the decision logic may be implemented in OPA, Cedar, or other policy engines. CapiscIO standardizes the inputs, outputs, distribution, and observability, not the policy language itself.

---

## 2. Relationship to Other RFCs

| Capability | RFC | How it is used here |
|---|---|---|
| Trust Badges (agent identity) | RFC-002 | PEP authenticates subjects and includes `subject.did`, `subject.badge_jti`, and `subject.ial` in the decision input. |
| Transaction and hop chain of custody | RFC-004 | PEP propagates `txn_id` and may include current hop metadata in the decision input and telemetry. |
| Trust graph and invariant preservation | RFC-001 | PDEP is authorization. It must not weaken the invariant that identity does not imply authority. |

**Invariant Preservation:**

A valid Trust Badge is necessary for authentication but is not sufficient for authorization. PEPs must call a PDP or apply a signed local policy bundle. Services must not implement authorization as ad hoc checks on badge claims.

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **PAP** | Policy Administration Point. Authoring and publishing policies. |
| **PDP** | Policy Decision Point. Evaluates a request and returns a decision. |
| **PEP** | Policy Enforcement Point. Intercepts a request, queries PDP or evaluates local bundle, and enforces the decision and obligations. |
| **Bundle** | A signed collection of policy artifacts and metadata distributed to PEPs. |
| **Decision** | The PDP result: allow or deny, plus obligations and decision metadata. |
| **Obligation** | A conditional contract attached to an allow decision that the PEP must enforce. |
| **Decision ID** | A stable identifier for a single decision evaluation. Used for audit and telemetry correlation. |

---

## 4. Goals and Non-Goals

### 4.1 Goals

- Define a stable, engine-agnostic policy **input and output contract**.
- Define signed **policy bundles** for distribution and offline enforcement.
- Standardize **obligations** so allow decisions can be constrained.
- Define canonical **telemetry** linking runtime traces to policy versions and decisions.
- Support both **online** PDP calls and **offline** local evaluation.

### 4.2 Non-Goals

- Defining a new policy language.
- Replacing OpenTelemetry or vendor APM systems.
- Providing non-repudiation of full request bodies (payload hashing is out of scope for v0.1).
- Defining governance workflows for policy review and approvals (organizational process is out of scope).

---

## 5. Architecture Overview

### 5.1 Components

```
Request
  │
  ▼
PEP (Gateway, Sidecar, Agent Runtime)
  │   ├─ (Online) Query PDP over HTTPS
  │   └─ (Offline) Evaluate local signed bundle
  ▼
Enforce decision + obligations
  │
  ▼
Downstream service
```

### 5.2 Enforcement Modes

| Mode | Where decisions come from | Use case |
|---|---|---|
| Online | PDP API | High assurance, rapid policy changes |
| Offline | Signed bundle cached at PEP | Edge, air-gapped, latency-sensitive |
| Hybrid | Bundle default + PDP override | Gradual rollout and resilience |

---

## 6. Policy Bundle Format and Signing

### 6.1 Bundle Requirements (Normative)

- Bundles MUST be signed by an issuer key that PEPs trust.
- PEPs MUST verify the signature before accepting a bundle.
- Bundles MUST be immutable once published. New policy is a new bundle.
- Bundles SHOULD be small enough for frequent distribution (target under 5 MB).

### 6.2 Bundle Metadata Example (Normative)

```json
{
  "bundle_id": "polb_01JFP8F4WQ1JQK8H0YV6QJ4K2M",
  "version": "1.2.0",
  "issued_at": "2025-12-24T00:00:00Z",
  "issuer": "https://registry.capisc.io",
  "audience": ["urn:capiscio:workspace:acme-prod"],
  "scope": {
    "env": ["prod"],
    "peps": ["gateway", "sidecar", "agent-runtime"]
  },
  "policies": [
    {
      "policy_id": "pol_approve_external_agents",
      "language": "capiscio.rego.v1",
      "entrypoints": ["allow"],
      "content": "base64url(<bytes>)",
      "content_type": "text/plain",
      "sha256": "base64url(<sha256-bytes>)"
    }
  ],
  "digest": {
    "alg": "sha256",
    "value": "base64url(<sha256-of-canonical-metadata>)"
  }
}
```

### 6.3 Bundle Packaging

Implementations MAY package bundles as:
- A single JSON with embedded policy content (small bundles), or
- A signed manifest plus separate content blobs (larger bundles).

If separate blobs are used, each blob MUST be referenced by digest and verified before use.

#### 6.3.1 Bundle Digest (OPTIONAL)

The `digest` field is OPTIONAL. It provides a content-addressable identifier for the bundle metadata, independent of the JWS signature. This is useful for:
- Content-addressed storage systems
- Bundle deduplication across PEPs
- Audit trails that reference bundles by content hash

**Canonicalization (Normative):**

If `digest` is included, it MUST be computed as follows:

1. Start with the bundle metadata JSON.
2. Remove the `digest` field entirely (to avoid self-reference).
3. Canonicalize using RFC 8785 (JCS): keys sorted lexicographically, strings escaped per RFC 8259.
4. UTF-8 encode.
5. SHA-256 hash.
6. base64url encode without padding.

The JWS signature already provides integrity; `digest` is for content-addressing only. PEPs MUST NOT use `digest` as a substitute for signature verification.

### 6.4 Bundle Signing Format (Normative)

Bundles MUST be signed as a JWS (compact serialization) wrapping the bundle metadata JSON.

**Header requirements:**

```json
{
  "alg": "EdDSA",
  "typ": "capiscio.policy-bundle+jwt",
  "kid": "<key-id>"
}
```

- `alg` MUST be `EdDSA` (Ed25519). Implementations MAY support `ES256` as a fallback.
- `typ` MUST be `capiscio.policy-bundle+jwt`.
- `kid` MUST be present and MUST reference a key in the PEP's configured trust store.

**Key discovery:**

PEPs MUST obtain bundle signing keys via one of:

1. **Configured JWKS endpoint:** PEP fetches keys from a configured URL (e.g., `https://registry.capisc.io/.well-known/jwks.json`) with issuer allowlist validation.
2. **Pinned key bundle:** For air-gapped deployments, keys are provisioned out-of-band as a static JWKS file.

PEPs MUST reject bundles signed by unknown `kid` values. PEPs SHOULD cache JWKS with appropriate TTL and refresh logic.

**SSRF Hardening (Normative):**

When fetching JWKS from configured endpoints, PEPs MUST apply SSRF protections:
- MUST validate that the URL scheme is `https` (not `http`, `file`, `ftp`, etc.).
- For `connected-prod` deployments: MUST reject URLs resolving to private IP ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), and link-local addresses (`169.254.0.0/16`, `fe80::/10`).
- MUST enforce DNS resolution timeouts (RECOMMENDED: 5 seconds) and connection timeouts (RECOMMENDED: 10 seconds).
- See RFC-002 §12.3 for baseline SSRF guidance applicable to all CapiscIO components.

**Verification:**

1. Parse JWS and extract header.
2. Validate `typ == capiscio.policy-bundle+jwt`.
3. Resolve `kid` to a trusted public key.
4. Verify signature over the JWS signing input.
5. Parse payload as bundle metadata JSON.
6. Verify `bundle.issuer` matches a configured allowlist.
7. Verify `bundle.audience` includes the PEP's configured audience.

---

## 7. Distribution and Caching

### 7.1 Bundle Fetch (Online)

PEPs MAY fetch the latest bundle from a configured endpoint:

- `GET /v1/policy/bundles/latest`

PEPs MUST validate:
- TLS, issuer identity, and signature
- audience and scope compatibility
- freshness policy (for example `max_bundle_age`)

### 7.2 Caching Rules (Normative)

- PEPs MUST cache the last known good bundle.
- PEPs MUST NOT switch to an unverified bundle.
- If fetching fails, PEPs SHOULD continue using the cached bundle until it expires by local policy.

### 7.3 Bundle Expiry

Bundles MAY include a recommended maximum age. If a bundle is older than `max_bundle_age`, the PEP SHOULD treat the deployment as degraded and follow the configured failure policy (see §10.4).

---

## 8. Decision Contract

### 8.1 Decision Input (Normative)

The PEP sends a decision request containing:

- **subject**: who is acting
- **action**: what is being attempted
- **resource**: what is being acted on
- **transport**: request context (method, route, audience)
- **context**: transaction and hop metadata
- **environment**: workspace and runtime context

#### 8.1.1 Input Schema (Illustrative)

```json
{
  "decision_version": "capiscio.pdep.v0.1",
  "subject": {
    "did": "did:web:registry.capisc.io:agents:agent-123",
    "badge_jti": "550e8400-e29b-41d4-a716-446655440000",
    "ial": "1",
    "trust_level": "2"
  },
  "action": {
    "name": "a2a.sendMessage"
  },
  "resource": {
    "type": "a2a.inbox",
    "id": "urn:capiscio:inbox:partner-foo"
  },
  "transport": {
    "protocol": "http",
    "method": "POST",
    "route": "POST /v1/a2a/sendMessage",
    "target_aud": "https://api.partner.example.com",
    "client_ip": "203.0.113.10"
  },
  "context": {
    "txn_id": "6f8c3d8e-2c1c-4b53-9a93-8cb0f7c8c4db",
    "hop_id": "hop_01JFP8K7XW7X9S4W2A1R7QG3D9"
  },
  "environment": {
    "workspace": "urn:capiscio:workspace:acme-prod",
    "pep_id": "pep_gateway_us_east_1",
    "time": "2025-12-24T00:00:01Z"
  }
}
```

### 8.2 Route Canonicalization (Operational Reality)

PEPs often see raw paths (for example `/v1/invoices/123`) and may not know the canonical template (`/v1/invoices/{id}`).

- PEPs SHOULD canonicalize routes when possible using explicit configuration (for example OpenAPI specs or route tables).
- If the PEP cannot canonicalize, it MUST pass the raw path in `transport.route`.
- Policy authors MUST account for high-cardinality raw routes. Use prefix matching, wildcards, or regex in the underlying engine to avoid brittle policies.

---

## 9. Decision Response

### 9.1 Response Fields (Normative)

A decision response MUST include:

- `decision`: `"allow"` or `"deny"`
- `decision_id`: unique ID for this evaluation
- `policy`: metadata identifying the policy basis (bundle id, policy ids, version)
- `obligations`: array of obligations (may be empty)
- `reason`: optional human-readable reason
- `ttl_seconds`: optional cache hint for local decision caching

#### 9.1.1 Response Example

```json
{
  "decision": "allow",
  "decision_id": "pdec_01JFP8M2E7D2QW8F0F3W9H4C1K",
  "policy": {
    "bundle_id": "polb_01JFP8F4WQ1JQK8H0YV6QJ4K2M",
    "bundle_version": "1.2.0",
    "policy_ids": ["pol_approve_external_agents"]
  },
  "obligations": [
    {
      "type": "rate_limit",
      "params": {
        "rpm": 10,
        "key": "rate_limit:{{subject.did}}"
      }
    },
    {
      "type": "redact",
      "params": {
        "fields": ["/pii/email", "/pii/phone"]
      }
    }
  ],
  "reason": "DV agents may message partner inbox with rate limiting and redaction.",
  "ttl_seconds": 30
}
```

---

## 10. Obligations

### 10.1 Obligations Semantics (Normative)

- Obligations are enforced by the PEP, not the PDP.
- If `decision="allow"` and an obligation cannot be enforced, the PEP MUST follow its configured failure policy:
  - fail-closed: deny
  - fail-open: allow but emit degraded telemetry and alerts

### 10.2 Standard Obligations (v0.1)

This RFC standardizes a minimal set. PEPs MAY support more.

#### rate_limit

- `params.rpm` (integer): requests per minute
- `params.key` (string): bucket key

**Templating (Normative):**  
PEPs SHOULD support variable substitution in `params.key` using the decision input fields. Example:

- `"rate_limit:{{subject.did}}"` enforces per-agent limits.
- `"rate_limit:{{context.txn_id}}"` enforces per-transaction limits.

If templating is not supported, the PEP MUST treat `params.key` as a literal string and SHOULD emit a warning in telemetry.

#### redact

- `params.fields` (array of strings): JSON Pointers (RFC 6901) identifying fields to redact.
- Examples: `"/pii/email"`, `"/pii/phone"`, `"/data/0/ssn"` (array index).
- Redaction applies to request or response payloads only when the PEP has access to structured representations (for example JSON). If the PEP cannot parse the payload, it MUST apply a conservative behavior configured by the deployment (deny or pass-through and alert).
- JSON Pointer is chosen over dotted paths to handle keys containing dots and array indices unambiguously.

#### require_step_up

- `params.mode` (string): `"human_review"` or `"manual_approval"`
- PEP behavior is deployment-specific, but it MUST block the action until the step-up is satisfied.

### 10.3 Obligations Ordering

PEPs SHOULD enforce obligations in this order:
1. rate_limit
2. redact
3. require_step_up

If a deployment needs different ordering, it must be explicitly configured and documented.

### 10.4 Failure Policy (Fail-Closed vs Fail-Open)

Default is fail-closed.

- If PDP is unreachable and no valid local bundle is available, PEP SHOULD deny.
- If an obligation cannot be enforced, PEP SHOULD deny.

**Operational Telemetry (Normative):**  
When enforcement fails due to PDP unavailability or missing valid cached decisions, the PEP SHOULD emit a distinct alerting signal:

- Metric (RECOMMENDED): `capiscio_pep_pdp_unreachable_count`
- Span or log attributes (RECOMMENDED):
  - `capiscio.policy.error_code = PDP_UNAVAILABLE`
  - `capiscio.policy.degraded = true` (only if configured fail-open)

### 10.5 Decision Caching

PEPs MAY cache allow decisions for up to `ttl_seconds` when provided, but only when:
- the subject identity is stable (badge_jti binding is present), and
- caching does not violate local security policy.

PEPs MUST NOT cache deny decisions unless explicitly configured.

### 10.6 Decision ID Requirements

- `decision_id` MUST be globally unique within the issuer scope.
- PEP telemetry MUST include `capiscio.policy.decision_id` (see §11).

### 10.7 Emergency Break-Glass Override

Break-glass is a controlled mechanism to bypass normal policy to restore service during outages.

#### 10.7.1 Override Token

A break-glass override token is a signed JWS with:
- issuer: a root administrative issuer configured in PEP trust
- short TTL (RECOMMENDED: 5 minutes)
- scope: defines what the override can bypass

#### 10.7.2 Scope Wildcards (Normative)

To ensure overrides are operationally usable during broad outages, scope fields MUST support wildcards.

- `methods`: MAY include `"*"` to match any method.
- `routes`: MAY include `"*"` to match any route, or prefix wildcards such as `"GET /v1/*"`.

PEPs MUST apply deterministic matching:
- exact match wins over wildcard
- prefix wildcards match by string prefix
- `"*"` matches all

PEPs SHOULD require narrow scopes by default but MUST allow `"*"`.

#### 10.7.3 Enforcement Rules

- Override tokens MUST be validated before use.
- Override MUST be visible in telemetry via:
  - `capiscio.policy.override = true`
  - `capiscio.policy.override_jti` (token id)
- Override MUST NOT disable authentication. It only bypasses authorization checks.

#### 10.7.4 Override Token Required Claims (Normative)

To ensure interoperability, break-glass override tokens MUST include the following claims:

| Claim | Requirement | Description |
|-------|-------------|-------------|
| `jti` | REQUIRED | Unique token identifier for audit correlation. |
| `iat` | REQUIRED | Issued-at timestamp (Unix seconds). |
| `exp` | REQUIRED | Expiration timestamp. SHOULD be short (recommended: 5 minutes). |
| `iss` | REQUIRED | Issuer identifier. MUST be a root administrative issuer in PEP trust config. |
| `sub` | REQUIRED | Operator identity (user ID or service account) invoking break-glass. |
| `aud` | OPTIONAL | Target PEPs or workspaces. If present, PEP MUST verify membership. |
| `scope` | REQUIRED | Object defining bypass scope (see §10.7.2). |
| `reason` | REQUIRED | Human-readable justification for the override. Logged in telemetry. |

**Example override token payload:**

```json
{
  "jti": "bg_01JFP9K2M3N4P5Q6R7S8T9U0V1",
  "iat": 1735689600,
  "exp": 1735689900,
  "iss": "https://admin.capisc.io",
  "sub": "user_ops_alice",
  "aud": ["urn:capiscio:workspace:acme-prod"],
  "scope": {
    "methods": ["*"],
    "routes": ["/v1/agents/*"]
  },
  "reason": "Emergency restore after PDP outage incident INC-2026-001"
}
```

---

## 11. Telemetry and Observability

To enable a durable chain of custody and policy forensics, implementations MUST be capable of emitting structured telemetry events.

### 11.1 Canonical Policy Event Schema (Normative)

When a decision is enforced, the PEP MUST be capable of emitting a structured event with these fields.

| Field | Type | Description |
|---|---|---|
| `capiscio.txn_id` | String | Stable workflow transaction ID (RFC-004). |
| `capiscio.hop.hop_id` | String | Current hop ID if present (RFC-004). |
| `capiscio.agent.did` | String | Acting agent DID. |
| `capiscio.badge.jti` | String | Trust Badge JTI. |
| `capiscio.policy.decision` | String | `allow` or `deny`. |
| `capiscio.policy.decision_id` | String | Decision ID (required). |
| `capiscio.policy.bundle_id` | String | Bundle ID used for decision. |
| `capiscio.policy.bundle_version` | String | Bundle version. |
| `capiscio.policy.policy_ids` | Array | Policy identifiers that contributed to the decision. |
| `capiscio.policy.obligations` | Array | Obligation types applied (not full params by default). |
| `event.name` | String | RECOMMENDED: `capiscio.policy_enforced`. |

**Redaction default:** Implementations SHOULD log obligation types but not full parameters unless explicitly enabled.

#### 11.1.1 Event Schema to OTel Attribute Mapping (Normative)

The event schema uses nested field names (e.g., `capiscio.hop.hop_id`) while OTel span attributes are typically flat. Implementations MUST use the following canonical mapping:

| Event Schema Field | OTel Span Attribute |
|--------------------|--------------------|
| `capiscio.txn_id` | `capiscio.txn_id` |
| `capiscio.hop.hop_id` | `capiscio.hop_id` |
| `capiscio.agent.did` | `capiscio.agent.did` |
| `capiscio.badge.jti` | `capiscio.badge.jti` |
| `capiscio.policy.decision` | `capiscio.policy.decision` |
| `capiscio.policy.decision_id` | `capiscio.policy.decision_id` |
| `capiscio.policy.bundle_id` | `capiscio.policy.bundle_id` |
| `capiscio.policy.bundle_version` | `capiscio.policy.bundle_version` |
| `capiscio.policy.override` | `capiscio.policy.override` |
| `capiscio.policy.override_jti` | `capiscio.policy.override_jti` |

Note: `capiscio.hop.hop_id` in events maps to `capiscio.hop_id` in OTel for consistency with RFC-004 OTel conventions.

### 11.2 OpenTelemetry Mapping (Normative)

If OpenTelemetry is used:

- `capiscio.policy.decision_id` MUST be a span attribute.
- `capiscio.txn_id` SHOULD map to the OTel TraceId when `txn_id` is a UUID (v4 or v7) by using the underlying 16 bytes.
  - If `txn_id` is not a UUID, generate a new TraceId and attach `capiscio.txn_id` as an attribute.

Minimum span attributes:

```yaml
capiscio.txn_id: <txn_id>
capiscio.hop_id: <hop_id>
capiscio.agent.did: <did>
capiscio.badge.jti: <badge_jti>
capiscio.policy.decision: <allow|deny>
capiscio.policy.decision_id: <decision_id>
capiscio.policy.bundle_id: <bundle_id>
capiscio.policy.bundle_version: <bundle_version>
```

### 11.3 Logging and Redaction (Normative)

1. No full tokens: do not log break-glass tokens, hop JWS, or badge JWTs by default.
2. JTI only: logging `badge_jti` is required; logging full badge payload is forbidden by default.
3. Payload capture: if a deployment enables request capture, it MUST be explicitly opt-in and controlled.

### 11.4 Vendor Export Guidelines (Non-Normative)

- Datadog:
  - Map `capiscio.txn_id` to trace id when possible.
  - Map `capiscio.agent.did` to a principal identifier for pivoting.
- Splunk / ELK:
  - Index `capiscio.*` fields as keyword strings.
- Honeycomb:
  - Use `capiscio.txn_id` as a high-cardinality grouping key.

---

## 12. APIs (Reference)

This section is descriptive and may be implemented differently by deployments.

### 12.1 PDP Decision API (Online Mode)

`POST /v1/policy/decide`

Request: decision input (see §8)  
Response: decision response (see §9)

### 12.2 Bundle APIs

- `GET /v1/policy/bundles/latest`
- `GET /v1/policy/bundles/{bundle_id}`

---

## 13. Security Considerations

- PEPs MUST verify bundle signatures and enforce issuer allowlists.
- PEPs MUST treat `subject.badge_jti` and `subject.did` as security-relevant. Do not accept missing binding fields in production unless explicitly configured.
- Bundle endpoints and PDP endpoints MUST implement SSRF defenses where they fetch remote resources (if any).
- Break-glass tokens are powerful. They MUST be short-lived, auditable, and restricted to trusted operational identities.

---

## 14. Implementation Notes

### 14.1 Engine Agnosticism

The contract supports OPA, Cedar, and custom engines by standardizing the input and output shape.

### 14.2 Route Canonicalization

Mapping raw HTTP paths to templates requires configuration (for example OpenAPI). When canonicalization is not possible, pass raw paths and avoid fragile exact-match policies.

### 14.3 Policy Authoring Guidance

Prefer policies that match on:
- action name
- audience
- subject trust level and ial
- route prefix rather than full raw paths

### 14.4 Offline Evaluation

Offline evaluation SHOULD be limited to a bounded set of rules. Use online PDP for high-complexity decisions when possible.

---

## 15. Future Work

- Standardized metrics derivation (for example `capiscio.policy.hop_latency_ms`).
- Head-based sampling rules for high-value `txn_id`s.
- Per-request proof binding between hop attestations and policy decisions.
- Federated policy issuers and cross-CA policy trust.
- Richer obligation types (for example DLP classifiers, sandboxing, human-in-the-loop workflows).

---

## Changelog

| Version | Date | Changes |
|---|---|---|
| 0.2 | 2026-01-02 | **Added:** Bundle signing format (§6.4) with JWS wire format and key discovery; digest canonicalization rules (§6.3.1); SSRF hardening for JWKS fetch; Override token required claims (§10.7.4). **Changed:** `redact` obligation now uses JSON Pointer (RFC 6901) instead of dotted paths. **Added:** Event-to-OTel attribute mapping table (§11.1.1). |
| 0.1 | 2025-12-24 | Initial draft. Includes obligations, signed bundles, decision contract, telemetry with decision_id, route canonicalization note, break-glass override with wildcard scope support, and fail-closed operational telemetry guidance. |
