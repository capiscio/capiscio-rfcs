# RFC-005: PDP Integration Profile (PIP)

**Version:** 1.0
**Status:** Draft
**Authors:** CapiscIO Core Team
**Created:** 2025-12-24
**Updated:** 2026-02-25
**Requires:** RFC-002 (Trust Badge Specification), RFC-004 (Transaction and Hop Binding), RFC-008 (Delegated Authority Envelopes)
**Supersedes:** RFC-005 v0.2 (PDEP)

---

## 1. Abstract

This RFC defines the **PDP Integration Profile (PIP)**, the canonical interface contract between CapiscIO Policy Enforcement Points (PEPs) and external Policy Decision Points (PDPs).

PIP standardizes:

1. The **decision request schema** — the attributes PEPs MUST provide to PDPs, including Authority Envelope context from RFC-008.
2. The **decision response schema** — the structure PDPs MUST return.
3. **Obligation semantics** — enforceable contracts attached to allow decisions, with handling rules per Enforcement Mode.
4. **Constraint narrowing responsibility** — the PDP's role as the authority escalation guardrail for delegated envelopes.

PIP is engine-agnostic. The decision logic may reside in OPA, Cedar, cloud IAM, or any other policy engine. CapiscIO standardizes the wire contract, not the policy language.

**What PIP is not:** PIP does not define policy authoring, policy bundling, policy distribution, policy lifecycle, conflict resolution, or PDP execution semantics. Those are deployment concerns outside the CapiscIO protocol boundary.

---

## 2. Relationship to Other RFCs

| CapiscIO RFC | Relationship |
|---|---|
| RFC-002 (Trust Badge) | PEP extracts `subject.did`, `subject.badge_jti`, `subject.trust_level`, and `subject.ial` from the Badge for the decision request. |
| RFC-004 (TCHB) | PEP includes `context.txn_id` and `context.hop_id` for transaction correlation. |
| RFC-008 (DAE) | PEP extracts envelope attributes (`capability_class`, `constraints`, `parent_constraints`, `envelope_id`, `delegation_depth`, `enforcement_mode`) for the decision request. RFC-008 §9.2 step 9 and §11 delegate the PDP wire contract to this specification. |

**Invariant Preservation:**

A valid Trust Badge is necessary for authentication but is not sufficient for authorization. A valid Authority Envelope establishes scoped authority but the PDP makes the final authorization decision. PEPs MUST NOT implement authorization as ad hoc checks on badge claims or envelope fields.

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|---|---|
| **PDP** | Policy Decision Point. An external engine that evaluates an authorization request and returns a decision. CapiscIO does not implement a PDP. |
| **PEP** | Policy Enforcement Point. Intercepts requests, constructs PDP queries from Badge and Envelope data, and enforces the resulting decision and obligations. |
| **Decision** | The PDP result: ALLOW or DENY, plus obligations and metadata. |
| **Obligation** | A conditional contract attached to an ALLOW decision that the PEP must attempt to enforce. |
| **Enforcement Mode** | One of EM-OBSERVE, EM-GUARD, EM-DELEGATE, EM-STRICT as defined in RFC-008 §10. Governs how PEP handles PDP decisions and obligations. |

---

## 4. Goals and Non-Goals

### 4.1 Goals

* Define the canonical **decision request attribute schema** for PDP queries.
* Define the canonical **decision response schema** including obligations.
* Define **obligation semantics** per Enforcement Mode.
* Define **constraint narrowing** as a first-class PDP responsibility.
* Define a minimal **break-glass override** contract for operational safety.

### 4.2 Non-Goals

* Policy language, policy evaluation semantics, or policy conflict resolution.
* Policy bundle format, signing, distribution, or caching.
* Policy administration, authoring, or lifecycle management.
* PDP availability strategies or failover architectures.
* Replacing OpenTelemetry or vendor-specific telemetry integrations.

---

## 5. Decision Request Schema (Normative)

### 5.1 Attribute Groups

Every decision request MUST include `pip_version` with value `"capiscio.pip.v1"` for this specification version. PEPs MUST reject responses from PDPs that do not recognize the version.

The PEP MUST construct a decision request containing the following attribute groups. Attributes sourced from Authority Envelopes (RFC-008) are REQUIRED when an Envelope is present. When no Envelope is present (badge-only mode), envelope-sourced fields MUST be `null`.

| Attribute | Source | Requirement | Description |
|-----------|--------|-------------|-------------|
| `subject.did` | Badge `sub` or Envelope `subject_did` | REQUIRED | DID of the acting agent. |
| `subject.badge_jti` | Badge `jti` | REQUIRED | Active badge session identifier. |
| `subject.ial` | Badge `ial` | REQUIRED | Identity Assurance Level. |
| `subject.trust_level` | Badge `vc.credentialSubject.level` | REQUIRED | Trust Level (RFC-002). |
| `action.capability_class` | Envelope `capability_class` | REQUIRED if Envelope present | Dot-notation capability namespace (RFC-008 §7). |
| `action.operation` | Request context | REQUIRED | Specific operation (e.g., tool name, HTTP method + route). |
| `resource.identifier` | Request context | REQUIRED | Target resource identifier. |
| `context.txn_id` | Envelope `txn_id` or RFC-004 header | REQUIRED | Transaction correlation ID. |
| `context.hop_id` | RFC-004 hop attestation | OPTIONAL | Current hop identifier. |
| `context.envelope_id` | Envelope `envelope_id` | REQUIRED if Envelope present | Audit correlation for the governing Envelope. |
| `context.delegation_depth` | Computed from chain | REQUIRED if Envelope present | Current depth in the delegation chain. |
| `context.constraints` | Envelope `constraints` | REQUIRED if Envelope present | Constraint object for this Envelope. |
| `context.parent_constraints` | Parent Envelope `constraints` | REQUIRED if derived Envelope | Parent constraints for narrowing validation. `null` for root Envelopes. |
| `context.enforcement_mode` | PEP configuration | REQUIRED | Active Enforcement Mode (RFC-008 §10). |
| `environment.workspace` | PEP configuration | OPTIONAL | Workspace or tenant identifier. |
| `environment.pep_id` | PEP configuration | OPTIONAL | PEP instance identifier. |
| `environment.time` | PEP clock | RECOMMENDED | Request evaluation time (ISO 8601). |

### 5.2 Example Request

```json
{
  "pip_version": "capiscio.pip.v1",
  "subject": {
    "did": "did:web:registry.capisc.io:agents:worker-1",
    "badge_jti": "550e8400-e29b-41d4-a716-446655440000",
    "ial": "1",
    "trust_level": "2"
  },
  "action": {
    "capability_class": "tools.database.read",
    "operation": "database_query"
  },
  "resource": {
    "identifier": "urn:capiscio:tool:database-prod:query"
  },
  "context": {
    "txn_id": "018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11",
    "hop_id": "hop_01JFP8K7XW7X9S4W2A1R7QG3D9",
    "envelope_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "delegation_depth": 2,
    "constraints": {
      "tables": ["users"],
      "operations": ["SELECT"]
    },
    "parent_constraints": {
      "tables": ["users", "orders"],
      "operations": ["SELECT", "INSERT"]
    },
    "enforcement_mode": "EM-DELEGATE"
  },
  "environment": {
    "workspace": "urn:capiscio:workspace:acme-prod",
    "pep_id": "pep_gateway_us_east_1",
    "time": "2026-02-25T12:00:01Z"
  }
}
```

### 5.3 Route Canonicalization

PEPs often see raw paths (e.g., `/v1/invoices/123`) rather than route templates (`/v1/invoices/{id}`). PEPs SHOULD canonicalize routes when possible via explicit configuration (e.g., OpenAPI specs). If canonicalization is not possible, the PEP MUST pass the raw path. Policy authors MUST account for high-cardinality raw routes using prefix matching or wildcards.

---

## 6. Decision Response Schema (Normative)

### 6.1 Response Fields

| Field | Requirement | Type | Description |
|-------|-------------|------|-------------|
| `decision` | REQUIRED | String | `"ALLOW"` or `"DENY"`. |
| `decision_id` | REQUIRED | String | Globally unique identifier for this evaluation. Used for audit correlation. |
| `obligations` | REQUIRED | Array | Obligation objects (may be empty). |
| `reason` | OPTIONAL | String | Human-readable explanation. |
| `ttl` | OPTIONAL | Integer | Decision cache lifetime in seconds. See §6.3 for caching rules. |

### 6.3 Decision Caching Rules

PEPs MAY cache ALLOW decisions when:

* The subject identity is stable (`badge_jti` binding is present), and
* Caching does not violate local security policy.

PEPs MUST NOT cache a decision beyond the **earliest** of:

* The `ttl` value from the PDP response.
* The governing Envelope's `expires_at` (if an Envelope is present).
* The Badge's expiration (`exp` claim).

This prevents temporal authority extension — a cached ALLOW decision MUST NOT outlive the artifacts that justified it.

PEPs MUST NOT cache DENY decisions unless explicitly configured.

### 6.4 Example Response

```json
{
  "decision": "ALLOW",
  "decision_id": "pdec_01JFP8M2E7D2QW8F0F3W9H4C1K",
  "obligations": [
    {
      "type": "rate_limit.apply",
      "params": {
        "rpm": 10,
        "key": "rate_limit:{{subject.did}}"
      }
    }
  ],
  "reason": "Agent authorized for database read with rate limiting.",
  "ttl": 30
}
```

---

## 7. Obligation Semantics (Normative)

### 7.1 Obligation Envelope

Every obligation MUST conform to the following shape:

```json
{
  "type": "<string>",
  "params": { }
}
```

* `type` is a string identifying the obligation kind. Types are deployment-defined; this specification does not mandate a vocabulary.
* `params` is an opaque object carrying obligation-specific parameters.

Obligations are returned by the PDP and enforced by the PEP. The PDP does not enforce obligations.

### 7.2 Enforcement Mode Obligation Matrix

Obligation handling varies by the active Enforcement Mode (RFC-008 §10):

| Enforcement Mode | Obligation Handling |
|-----------------|---------------------|
| EM-OBSERVE | Obligations are logged. Enforcement is not attempted. |
| EM-GUARD | Obligations are logged. Enforcement is best-effort; failure does not block. |
| EM-DELEGATE | Obligations MUST be attempted. Failure is logged but does not block the request. |
| EM-STRICT | Obligations MUST be enforced. Failure to enforce any obligation MUST block the request. |

### 7.3 Unrecognized Obligations

If a PEP receives an obligation with a `type` it does not recognize:

| Enforcement Mode | Behavior |
|-----------------|----------|
| EM-OBSERVE | Log and skip. |
| EM-GUARD | Log and skip. |
| EM-DELEGATE | Log warning; proceed (best-effort). |
| EM-STRICT | MUST DENY. An unrecognized obligation cannot be enforced, therefore fail-closed. |

### 7.4 Default Failure Policy

The default policy is fail-closed. If the PDP is unreachable and no cached decision is available, the PEP MUST deny the request, with one exception:

**EM-OBSERVE mode:** In EM-OBSERVE, PDP unavailability MAY result in ALLOW, since EM-OBSERVE is non-blocking by definition (RFC-008 §10). However, the PEP MUST emit `capiscio.policy.decision = "ALLOW_OBSERVE"` to distinguish this from a PDP-evaluated ALLOW. All other Enforcement Modes MUST deny on PDP unavailability.

When enforcement fails due to PDP unavailability, the PEP MUST emit:

* Metric (RECOMMENDED): `capiscio_pep_pdp_unreachable_count`
* Log attribute (REQUIRED): `capiscio.policy.error_code = PDP_UNAVAILABLE`
* Log attribute (REQUIRED in EM-OBSERVE fallback): `capiscio.policy.decision = ALLOW_OBSERVE`

---

## 8. Constraint Narrowing (Normative)

This section defines the PDP's role in validating the monotonic narrowing invariant (RFC-008 §8).

### 8.1 PDP Responsibility

When a decision request includes `context.parent_constraints` (i.e., the Envelope is derived, not root), the PDP MUST evaluate whether `context.constraints` represents a valid narrowing of `context.parent_constraints`.

* Narrowing validation is **semantic** — it depends on constraint types known to the PDP's policy logic.
* The PEP MUST NOT attempt semantic narrowing validation. The PEP's role is to project both constraint sets into the request and enforce the PDP's decision.

### 8.2 Narrowing Rules

* If `context.parent_constraints` is `null` (root Envelope), no narrowing check applies.
* If `context.parent_constraints` is non-null, the PDP MUST confirm that the child's effective authority is a subset of or equal to the parent's.
* If the PDP does not recognize a constraint type present in either `constraints` or `parent_constraints`, it MUST treat narrowing as **unverifiable** and return DENY. Unrecognized constraints cannot be validated for subset relationships.
* If the PDP determines that narrowing is violated (child authority exceeds parent), it MUST return DENY.

### 8.3 PEP Narrowing Guard

If a decision request includes non-null `context.parent_constraints` and the PDP returns ALLOW, the PEP MUST verify that the PDP's response acknowledges narrowing was evaluated. If the PDP does not support narrowing validation (i.e., it ignores `parent_constraints` and returns ALLOW unconditionally), the PEP MUST treat this as a misconfiguration and DENY the request.

This prevents a naïve PDP from silently collapsing the delegation invariant.

### 8.4 Security Invariant

Constraint narrowing is the authority escalation guardrail. Without it, a delegated Envelope could claim broader authority than its parent granted. The PDP is the sole component responsible for enforcing this invariant at the semantic level. If narrowing validation is absent or advisory-only, the delegation model provides no escalation protection.

---

## 9. Break-Glass Override (Normative)

Break-glass is an exceptional mechanism to bypass PDP authorization during outages. It is not an alternative authorization path.

### 9.1 Override Token

A break-glass override token is a signed JWS with the following REQUIRED claims:

| Claim | Description |
|-------|-------------|
| `jti` | Unique token identifier. |
| `iat` | Issued-at (Unix seconds). |
| `exp` | Expiration (Unix seconds). SHOULD be short (RECOMMENDED: 5 minutes). |
| `iss` | Root administrative issuer, configured in PEP trust. |
| `sub` | Operator identity invoking break-glass. |
| `scope` | Object defining bypass scope: `methods` (array, supports `"*"`) and `routes` (array, supports prefix wildcards). |
| `reason` | Human-readable justification. |

### 9.2 Enforcement Rules

* When a valid override token is present, the PEP MUST skip PDP evaluation entirely and emit a policy enforcement event with `decision = "ALLOW"` and `capiscio.policy.override = true`.
* Override tokens MUST be cryptographically validated before use.
* Override MUST NOT bypass authentication — only authorization.
* Override MUST be visible in telemetry: `capiscio.policy.override = true`, `capiscio.policy.override_jti = <jti>`.
* PEPs MUST apply deterministic scope matching: exact match wins over wildcards; prefix wildcards match by string prefix; `"*"` matches all.

---

## 10. Telemetry (Normative)

PIP adds two REQUIRED telemetry fields to the CapiscIO canonical telemetry set (RFC-004 §10):

| Field | Type | Description |
|---|---|---|
| `capiscio.policy.decision_id` | String | The `decision_id` from the PDP response. REQUIRED on every policy enforcement event. |
| `capiscio.policy.decision` | String | `ALLOW`, `DENY`, or `ALLOW_OBSERVE`. REQUIRED on every policy enforcement event. |

PEPs MUST emit these fields on every decision enforcement. Correlation with `capiscio.txn_id`, `capiscio.hop_id`, `capiscio.badge.jti`, and `capiscio.authority.envelope_hash` follows the conventions defined in RFC-004 §10 and RFC-008 §9.2.

Implementations SHOULD use event name `capiscio.policy_enforced`.

Logging MUST NOT include full tokens, badge payloads, or override token contents. Log `decision_id`, `badge_jti`, and `override_jti` only.

---

## 11. Security Considerations

* **PDP unreachability.** Default fail-closed. PEPs MUST NOT silently allow requests when the PDP cannot be reached unless an explicit break-glass override is active or the Enforcement Mode is EM-OBSERVE (see §7.4).
* **Constraint bypass risk.** If narrowing validation is not performed (PDP does not support it, or the PEP short-circuits), the delegation chain provides no escalation protection. Deployments MUST ensure their PDP validates narrowing for all recognized constraint types.
* **Obligation enforcement gaps.** In EM-DELEGATE mode, obligation failures are tolerated. Deployments transitioning to EM-STRICT MUST audit obligation support before switching modes.
* **Break-glass abuse.** Override tokens are powerful. Short TTLs, mandatory telemetry, and operator identity recording are the primary controls. Deployments SHOULD alert on override token usage.

---

## 12. Future Work

* Standardized constraint vocabulary registry for common narrowing patterns.
* Federated PDP trust for cross-organizational policy evaluation.
* Richer obligation types (DLP classifiers, sandboxing, human-in-the-loop workflows).

---

## Appendix A: Illustrative Obligation Types (Non-Normative)

The following obligation types are provided as interoperability examples. They are not normative. Deployments MAY define any obligation types their PEPs can enforce.

### rate_limit.apply

```json
{
  "type": "rate_limit.apply",
  "params": {
    "rpm": 10,
    "key": "rate_limit:{{subject.did}}"
  }
}
```

PEPs SHOULD support `{{field}}` template substitution in `params` values using decision request fields. If templating is not supported, treat values as literals and log a warning.

### redact.fields

```json
{
  "type": "redact.fields",
  "params": {
    "fields": ["/pii/email", "/pii/phone"]
  }
}
```

`fields` uses JSON Pointer (RFC 6901) for unambiguous path references.

### log.enhanced

```json
{
  "type": "log.enhanced",
  "params": {
    "level": "audit",
    "include_params_hash": true
  }
}
```

### require_step_up

```json
{
  "type": "require_step_up",
  "params": {
    "mode": "human_review"
  }
}
```

PEP MUST block the action until the step-up condition is satisfied. Behavior is deployment-specific.

---

## Changelog

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-02-25 | Complete rewrite: PDEP replaced with PDP Integration Profile (PIP). Removed policy bundles, distribution, PAP, offline evaluation. Added envelope-aware decision request schema (§5), constraint narrowing as PDP responsibility (§8), enforcement mode obligation matrix (§7.2), decision caching temporal bounds (§6.3), PEP narrowing misconfiguration guard (§8.3), EM-OBSERVE PDP unavailability exception (§7.4), break-glass deterministic PDP skip (§9.2). Obligation types demoted to non-normative appendix. |
| 0.2 | 2026-01-02 | (PDEP) Bundle signing format, digest canonicalization, SSRF hardening, override token claims. |
| 0.1 | 2025-12-24 | (PDEP) Initial draft. |
