# RFC-008: Delegated Authority Envelopes

**Version:** 0.2
**Status:** Draft
**Authors:** CapiscIO Core Team
**Created:** 2026-01-20
**Updated:** 2026-02-25
**Requires:** RFC-001 (AGCP), RFC-002 (Trust Badge Specification), RFC-003 (Key Ownership Proof Protocol), RFC-004 (Transaction and Hop Binding)

---

## 1. Abstract

This RFC defines the **Authority Envelope**, the cryptographic artifact that conveys scoped, delegatable authority between agents in the CapiscIO ecosystem.

Where RFC-002 Trust Badges establish *identity* ("who is this agent?"), Authority Envelopes establish *authority* ("what may this agent do, and who granted that authority?"). Envelopes form verifiable delegation chains where each link can only **narrow** the authority granted by its parent — never widen it. This monotonic narrowing property is the formal mechanism implementing the Golden Rule defined in RFC-001 §2.1.

This specification defines:

* The Authority Envelope format (JWS-signed JSON payload).
* The delegation lineage model (chain construction via `parent_authority_hash`).
* The capability class hierarchy (dot-notation namespaces with prefix matching).
* Monotonic constraint narrowing rules.
* The Enforcement Point (PEP) model and verification sequence.
* Four Enforcement Modes governing PEP behavior.
* The PDP attribute projection contract (with forward reference to RFC-005 PIP for wire schema).
* Envelope reuse model and invocation-layer replay requirements.
* Cross-linking with RFC-004 transaction and hop identifiers.

This specification is **transport-agnostic**. Bindings for HTTP, MCP, and A2A are provided as non-normative appendices.

---

## 2. Relationship to Other RFCs

| CapiscIO RFC | Relationship to This Specification |
|---|---|
| RFC-001 (AGCP) | Defines the Golden Rule (§2.1) and Trust Graph (§3.1) that Authority Envelopes implement. Envelopes are the formal delegation artifact referenced by AGCP's authority model. |
| RFC-002 (Trust Badge) | Badges provide identity. Envelopes provide authority. An Envelope MUST reference the issuer's Badge via `issuer_badge_jti` and (except at root) the subject's Badge via `subject_badge_jti`. |
| RFC-003 (Key Ownership Proof) | Ensures the signing key in an Authority Envelope is bound to the claimed DID. Verifiers MUST confirm key ownership before accepting an Envelope signature. |
| RFC-004 (TCHB) | Provides the `txn_id` that links Envelopes to the transport-layer hop chain. Hop Attestations MAY carry `authority_envelope_hash` to bind a specific transport hop to the governing authority. |
| RFC-006 (MCP Tool Authority) | Defines single-hop tool invocation evidence. Authority Envelopes supply the authorization input that RFC-006 enforcement points evaluate. |
| RFC-007 (MCP Server Identity) | Establishes server identity. The `subject_did` in a root Envelope MAY reference a server DID discovered via RFC-007. |

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|------|------------|
| **Authority Envelope** | A JWS-signed JSON payload that conveys scoped, delegatable authority from an issuer to a subject. |
| **Capability Class** | A dot-delimited namespace string (e.g., `tools.database.read`) identifying the scope of permitted operations. |
| **Constraint** | An opaque key-value object within an Envelope that further restricts the granted authority. Constraints are interpreted by the PDP. |
| **Delegation Chain** | An ordered sequence of Authority Envelopes linked by `parent_authority_hash`, rooted at an initial grant. |
| **Delegation Depth** | The remaining number of times authority may be re-delegated. Decremented by at least 1 at each delegation step. |
| **Enforcement Mode** | A deployment-level configuration that determines how a PEP responds to verification outcomes. One of: EM-OBSERVE, EM-GUARD, EM-DELEGATE, EM-STRICT. |
| **Monotonic Narrowing** | The invariant that a derived Envelope's effective authority MUST be a subset of or equal to its parent's authority. Authority can only be reduced, never amplified. |
| **PDP (Policy Decision Point)** | An external policy engine (e.g., OPA, Cedar, cloud IAM) that evaluates authorization requests. CapiscIO does not implement a PDP; it integrates with them. |
| **PEP (Policy Enforcement Point)** | A runtime component that intercepts requests, constructs PDP queries from Envelope data, and enforces the resulting decisions. The PEP is the authoritative enforcement boundary. |
| **Root Envelope** | The first Envelope in a delegation chain, issued by an entity with original authority. Has no `parent_authority_hash`. |

---

## 4. Goals and Non-Goals

### 4.1 Goals

* Define a portable, cryptographically verifiable artifact for scoped authority delegation between agents.
* Ensure authority can only narrow as it propagates through a delegation chain (monotonic narrowing).
* Provide a transport-agnostic envelope format usable across HTTP, MCP, A2A, and future protocols.
* Define clear verification and enforcement sequences for Policy Enforcement Points.
* Enable integration with external policy engines without mandating a specific PDP implementation.
* Support audit and forensic analysis through stable identifiers and deterministic verification.

### 4.2 Non-Goals

* **Policy engine implementation.** This RFC does not define a PDP. It defines the interface between PEPs and external PDPs.
* **Constraint vocabulary.** Specific constraint types (e.g., IP allowlists, rate limits) are not defined here. The constraints object is opaque to this specification.
* **Transport binding details.** Normative transport bindings are out of scope. Non-normative appendices illustrate HTTP, MCP, and A2A patterns.
* **Advisory enforcement (Judge).** Advisory, non-blocking evaluation is deferred to future work (§18).
* **Composition security.** Authority merging across independent delegation chains is deferred to future work (§18).
* **Principal classification.** Distinguishing human, agent, service, or organizational identities is outside the delegation invariant model. PDP policies requiring identity classification MAY resolve this from DID metadata or via future extensions.
* **Originator persistence (dual-auth).** Workflows requiring simultaneous multi-principal evaluation (e.g., human-on-behalf-of-agent) are out of scope. Delegated Authority Envelopes model authority propagation, not originator persistence.
* **Discovery and distribution.** How agents discover or request Authority Envelopes is not defined here.

---

## 5. Authority Envelope Format

### 5.1 JWS Structure

An Authority Envelope is a JWS (JSON Web Signature) in Compact Serialization:

```
<base64url-header>.<base64url-payload>.<base64url-signature>
```

### 5.2 Header

```json
{
  "alg": "EdDSA",
  "typ": "capiscio-authority-envelope+jws",
  "kid": "did:web:example.com:agents:orchestrator#key-1"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `alg` | REQUIRED | Signing algorithm. MUST be present. Implementations MUST reject `"none"`. EdDSA (Ed25519) is RECOMMENDED for new deployments. Acceptable algorithms are governed by the CapiscIO Algorithm Registry (see §17.2). |
| `typ` | REQUIRED | MUST be `capiscio-authority-envelope+jws`. |
| `kid` | REQUIRED | DID key reference of the signing key. MUST match the issuer's Badge-bound key, verifiable via RFC-003. |

### 5.3 Payload

```json
{
  "envelope_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "issuer_did": "did:web:example.com:agents:orchestrator",
  "subject_did": "did:web:example.com:agents:worker-1",
  "txn_id": "018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11",
  "parent_authority_hash": null,
  "capability_class": "tools.database",
  "constraints": {
    "tables": ["users", "orders"],
    "operations": ["SELECT"]
  },
  "delegation_depth_remaining": 2,
  "enforcement_mode_min": null,
  "issued_at": 1737331200,
  "expires_at": 1737331500,
  "issuer_badge_jti": "b8f2c6a5-2d6f-4e44-9f55-2a1d6d9e0f12",
  "subject_badge_jti": "c9a3d7b6-3e7g-5f55-0g66-3b2e7e1f1g23"
}
```

### 5.4 Payload Claims

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `envelope_id` | string | REQUIRED | Unique identifier for this Envelope (UUID). Used for audit correlation. See §12 for envelope reuse semantics. |
| `issuer_did` | string | REQUIRED | DID of the entity granting authority. |
| `subject_did` | string | REQUIRED | DID of the entity receiving authority. |
| `txn_id` | string | REQUIRED | Transaction identifier, as defined in RFC-004 §4. Links the authority delegation to the transport-layer hop chain. |
| `parent_authority_hash` | string ∣ null | REQUIRED | SHA-256 hash of the parent Authority Envelope's JWS Compact Serialization (hex-encoded, lowercase). `null` for root Envelopes. |
| `capability_class` | string | REQUIRED | Dot-delimited capability namespace. See §7. |
| `constraints` | object | REQUIRED | Opaque constraint object interpreted by the PDP. MAY be empty (`{}`). |
| `delegation_depth_remaining` | integer | REQUIRED | Non-negative integer. The number of additional delegation steps permitted. MUST be decremented by at least 1 when creating a derived Envelope. When 0, the subject MUST NOT further delegate. |
| `enforcement_mode_min` | string ∣ null | OPTIONAL | Minimum Enforcement Mode the issuer requires of downstream PEPs. If set, MUST be one of: `EM-OBSERVE`, `EM-GUARD`, `EM-DELEGATE`, `EM-STRICT`. PEPs MUST operate at this level or stricter. `null` means no issuer-mandated minimum. |
| `issued_at` | integer | REQUIRED | Unix timestamp (seconds) of Envelope creation. |
| `expires_at` | integer | REQUIRED | Unix timestamp (seconds) after which this Envelope MUST be rejected. |
| `issuer_badge_jti` | string | REQUIRED | The `jti` of the issuer's current Trust Badge (RFC-002). Binds the Envelope to a specific badge session. |
| `subject_badge_jti` | string ∣ null | REQUIRED | The `jti` of the subject's current Trust Badge. MUST be present for all non-root Envelopes (i.e., where `parent_authority_hash` is non-null). For root Envelopes, MAY be `null` only if the subject has not yet established a badge session; in this case the PEP MUST require an alternative subject authentication mechanism as defined by RFC-002. |

---

## 6. Delegation Lineage Model

### 6.1 Root Envelopes

A root Envelope is the origin of a delegation chain. It has the following characteristics:

* `parent_authority_hash` MUST be `null`.
* `issuer_did` identifies the original authority holder.
* `delegation_depth_remaining` sets the maximum chain length. A root Envelope may have any non-negative value; it is not constrained to a specific "depth."
* `subject_badge_jti` MAY be `null` only if the subject has not yet established a badge session. When `subject_badge_jti` is null, the PEP MUST require an alternative subject authentication mechanism (e.g., RFC-002 root-origin model or out-of-band identity confirmation). A null `subject_badge_jti` does NOT exempt the subject from identity verification.

Root Envelopes are typically issued by orchestrators, platform operators, or human-initiated workflows.

### 6.2 Derived Envelopes

A derived Envelope extends an existing delegation chain. Creating a derived Envelope requires:

1. The subject of the parent Envelope becomes the issuer of the derived Envelope.
2. `parent_authority_hash` MUST be set to the SHA-256 hash of the parent Envelope's JWS Compact Serialization (hex-encoded, lowercase).
3. All monotonic narrowing rules (§8) MUST be satisfied.
4. `delegation_depth_remaining` MUST be strictly less than the parent's value (decremented by at least 1).
5. The derived Envelope MUST be signed by the issuer's Badge-bound key.

### 6.3 Chain Construction

A delegation chain is an ordered list of Envelopes `[E₀, E₁, ..., Eₙ]` where:

* `E₀` is the root Envelope (`parent_authority_hash == null`).
* For each `Eᵢ` (i > 0): `Eᵢ.parent_authority_hash == SHA-256(Eᵢ₋₁)`.
* For each `Eᵢ` (i > 0): `Eᵢ.issuer_did == Eᵢ₋₁.subject_did`.
* For each `Eᵢ` (i > 0): `Eᵢ.delegation_depth_remaining < Eᵢ₋₁.delegation_depth_remaining`.

### 6.4 Context-Handoff Invariant

When delegating authority across a trust boundary:

* The issuer MUST present a valid Authority Envelope to its PEP.
* The PEP MUST verify the envelope and confirm the issuer's right to delegate (i.e., `delegation_depth_remaining > 0`).
* The derived Envelope MUST be created and signed before the delegated request is dispatched.
* The receiving PEP MUST independently verify the full delegation chain before acting.

This ensures that at no point does authority exist without a verifiable cryptographic record.

---

## 7. Capability Class Hierarchy

### 7.1 Dot Notation

Capability classes use dot-delimited namespaces to represent a hierarchy of permissions:

```
tools
tools.database
tools.database.read
tools.database.read.query
tools.filesystem
tools.filesystem.write
```

Each segment MUST match the pattern `[a-z][a-z0-9_]*` (lowercase alphanumeric with underscores, starting with a letter).

### 7.2 Prefix Matching

A capability class `C_child` is considered **within the scope of** `C_parent` if and only if:

* `C_child == C_parent`, or
* `C_child` starts with `C_parent` followed by a dot (`.`).

Examples:

| Parent | Child | Within Scope? |
|--------|-------|---------------|
| `tools.database` | `tools.database` | ✅ Yes (equal) |
| `tools.database` | `tools.database.read` | ✅ Yes (child extends parent) |
| `tools.database` | `tools.database.read.query` | ✅ Yes (transitive) |
| `tools.database` | `tools.filesystem` | ❌ No (different branch) |
| `tools.database.read` | `tools.database` | ❌ No (child is broader) |

### 7.3 Wildcard Semantics

This specification does not define wildcard operators. A capability class of `tools` grants access to the entire `tools.*` subtree via prefix matching. Explicit enumeration of leaf capabilities is RECOMMENDED for high-assurance deployments.

---

## 8. Monotonic Constraint Narrowing

### 8.1 Invariant

For every derived Envelope `E_child` with parent `E_parent`, the effective authority of `E_child` MUST be a subset of or equal to the effective authority of `E_parent`. This invariant MUST hold across all dimensions:

1. **Capability class** (§8.2)
2. **Temporal bounds** (§8.3)
3. **Delegation depth** (§8.4)
4. **Constraints** (§8.5)

A PEP MUST reject any derived Envelope that violates monotonic narrowing.

### 8.2 Capability Narrowing

`E_child.capability_class` MUST be within the scope of `E_parent.capability_class` as defined in §7.2.

**Valid:** Parent grants `tools.database`; child narrows to `tools.database.read`.

**Invalid:** Parent grants `tools.database.read`; child claims `tools.database`.

### 8.3 Temporal Narrowing

`E_child.expires_at` MUST be less than or equal to `E_parent.expires_at`. A derived Envelope MUST NOT outlive its parent.

`E_child.issued_at` MUST be greater than or equal to `E_parent.issued_at`. A derived Envelope MUST NOT predate its parent.

### 8.4 Depth Decrement

`E_child.delegation_depth_remaining` MUST be strictly less than `E_parent.delegation_depth_remaining`. The typical decrement is 1, but issuers MAY decrement by more to limit further delegation.

### 8.5 Constraint Subset Rule

`E_child.constraints` MUST represent restrictions that are equal to or stricter than `E_parent.constraints`. Because constraints are opaque to this specification, constraint narrowing validation is a **PDP responsibility**, not a PEP responsibility. PEPs MUST NOT attempt to compute constraint subset relationships directly.

* The PEP MUST NOT attempt semantic interpretation of constraints for narrowing validation beyond the structural checks defined in this specification (§8.2–§8.4).
* PEPs MUST include both `context.constraints` and `context.parent_constraints` in the PDP attribute projection (§11.1) when evaluating a derived Envelope.
* The PDP MUST evaluate whether the child's constraints are a valid narrowing of the parent's constraints according to its policy logic.
* If the PDP cannot determine narrowing validity, it MUST return DENY.

The concrete PDP request/response schema and narrowing validation semantics are defined in RFC-005 (PDP Integration Profile).

---

## 9. Enforcement Point Model

### 9.1 PEP Responsibilities

The PEP is the **sole authoritative enforcement boundary**. PEPs:

* MUST intercept all requests that require authority verification.
* MUST execute the full verification sequence (§9.2) before permitting execution.
* MUST enforce decisions returned by the PDP.
* MUST emit audit events for all verification outcomes (success and failure).
* MUST NOT expose bypass mechanisms, debug modes, or administrative overrides that skip verification in production deployments.

### 9.2 Verification Sequence

The PEP MUST execute the following steps in order. Failure at any step MUST result in denial (fail-closed), subject to the active Enforcement Mode (§10).

1. **Badge Verification.** Verify the issuer's Trust Badge per RFC-002: signature validity, expiration, revocation status, and trust level.

2. **Key Ownership.** Confirm the signing key (`kid` in the Envelope header) is bound to the issuer's DID via RFC-003 Key Ownership Proof.

3. **Envelope Signature.** Verify the JWS signature of the Authority Envelope using the authenticated key.

4. **Expiration.** Confirm `now < expires_at`. Confirm `issued_at <= now`.

5. **Invocation Evidence.** For side-effecting operations, confirm the request includes invocation-layer replay evidence (RFC-004 hop attestation or RFC-006 invocation evidence). See §12.

6. **Badge Binding.** Confirm `issuer_badge_jti` matches the presented Badge's `jti`. If `subject_badge_jti` is non-null, confirm it matches the subject's presented Badge.

7. **Chain Integrity.** If `parent_authority_hash` is non-null, retrieve the parent Envelope and verify:
   * `parent_authority_hash` matches `SHA-256(parent JWS)`.
   * `issuer_did` matches parent's `subject_did`.
   * All monotonic narrowing rules (§8) hold.
   * Recurse to the root Envelope.

8. **Delegation Depth.** If the request involves further delegation, confirm `delegation_depth_remaining > 0`.

9. **PDP Query.** Construct the attribute projection (§11.1) and query the PDP. Enforce the returned decision per RFC-005 (PDP Integration Profile).

### 9.3 Agent Self-Enforcement Prohibition

Agents MUST NOT evaluate their own Authority Envelopes to make authorization decisions. Self-enforcement creates a conflict of interest where the agent being governed is also the authority evaluating governance.

All enforcement MUST occur at a PEP that is architecturally separate from the agent runtime:

* SDK-embedded PEPs that intercept calls before they reach the agent logic are acceptable.
* Sidecar proxies and API gateways are acceptable.
* Agent code that reads its own Envelope and decides whether to proceed is NOT acceptable.

### 9.4 Delegation Validation Performance

For deep delegation chains, PEPs SHOULD implement:

* **Envelope caching.** Verified Envelopes MAY be cached by `envelope_id` for the duration of `expires_at`. Cached entries MUST be invalidated if the associated Badge is revoked.
* **Batch signature verification.** When verifying a chain of N Envelopes, implementations MAY batch-verify signatures where the cryptographic library supports it.
* **Chain depth limits.** PEPs SHOULD enforce a configurable maximum chain depth (RECOMMENDED default: 10) to bound verification cost.

---

## 10. Enforcement Modes

Enforcement Modes govern how a PEP responds to verification outcomes. They are configured per-PEP or per-deployment. If an Authority Envelope specifies `enforcement_mode_min`, the PEP MUST operate at that level or stricter.

### 10.1 EM-OBSERVE

* Verification is performed.
* All outcomes are logged.
* Requests are **never blocked** regardless of verification result.
* Use case: initial rollout, shadow-mode validation, telemetry collection.

### 10.2 EM-GUARD

* Verification is performed.
* All outcomes are logged.
* Requests are **blocked on verification failure** (invalid signature, expired, revoked badge, narrowing violation).
* PDP denials are **logged but not enforced** (request proceeds).
* Use case: incremental adoption where cryptographic identity and envelope integrity are enforced, while policy decisions remain advisory. This mode is intended for rollouts where operators want to validate that identity infrastructure is working before enabling policy enforcement.

### 10.3 EM-DELEGATE

* Verification is performed.
* All outcomes are logged.
* Requests are **blocked on verification failure**.
* PDP denials are **enforced** (request is blocked).
* Obligations are **logged but best-effort** (failure to enforce an obligation does not block the request).
* Use case: production deployments with policy enforcement and obligation tolerance.

### 10.4 EM-STRICT

* Verification is performed.
* All outcomes are logged.
* Requests are **blocked on verification failure**.
* PDP denials are **enforced**.
* Obligations are **enforced** (failure to enforce any obligation blocks the request).
* Use case: high-assurance environments, regulated workloads, financial operations.

### 10.5 Mode Ordering

The modes form a strict total order of increasing strictness:

```
EM-OBSERVE < EM-GUARD < EM-DELEGATE < EM-STRICT
```

If an Envelope specifies `enforcement_mode_min = "EM-GUARD"`, a PEP configured for EM-OBSERVE MUST upgrade to EM-GUARD for that request. A PEP configured for EM-STRICT remains at EM-STRICT (it is already stricter).

---

## 11. PDP Integration

CapiscIO does not implement a Policy Decision Point. This section defines the attributes that PEPs MUST provide when querying external PDPs. The concrete PDP request/response wire schema, obligation envelope format, and unrecognized obligation handling are defined in RFC-005 (PDP Integration Profile).

### 11.1 Attribute Projection

When querying a PDP, the PEP MUST construct an authorization request containing the following canonical attributes:

| Attribute | Source | Description |
|-----------|--------|-------------|
| `subject.did` | Envelope `subject_did` | The DID of the agent requesting action. |
| `subject.badge_jti` | Envelope `subject_badge_jti` | The active badge session. |
| `subject.trust_level` | Badge `vc.credentialSubject.level` | The Trust Level from RFC-002. |
| `action.capability_class` | Envelope `capability_class` | The requested capability. |
| `action.operation` | Request context | The specific operation being attempted (e.g., tool name, method). |
| `resource.identifier` | Request context | The target resource identifier. |
| `context.txn_id` | Envelope `txn_id` | The transaction correlation ID. |
| `context.envelope_id` | Envelope `envelope_id` | The specific Envelope ID. |
| `context.delegation_depth` | Computed from chain | The current depth in the delegation chain. |
| `context.constraints` | Envelope `constraints` | The constraint object for PDP evaluation. |
| `context.parent_constraints` | Parent Envelope `constraints` | Parent constraints for narrowing validation. `null` for root Envelopes. |
| `context.enforcement_mode` | PEP configuration | The active Enforcement Mode. |

The PDP is responsible for interpreting these attributes against its policy rules. CapiscIO does not prescribe the policy language or evaluation engine.

### 11.2 PDP Decision Requirements

The PDP MUST return a decision that the PEP can enforce. At minimum:

* The decision MUST be binary: ALLOW or DENY.
* The PDP MAY return obligations that the PEP must attempt to enforce.
* Obligation handling semantics vary by Enforcement Mode (§10).

The wire format for PDP requests and responses, obligation schema, and per-mode obligation handling rules are specified in RFC-005 (PDP Integration Profile). Implementations MUST conform to RFC-005 for PDP interoperability.

---

## 12. Envelope Reuse and Replay Protection

### 12.1 Multi-Use Envelopes

An Authority Envelope is a delegation grant, not a per-action token. An Authority Envelope MAY authorize multiple actions within its validity window (`issued_at` to `expires_at`). Each action authorized by an Envelope MUST be independently recorded via RFC-004 hop attestation or RFC-006 invocation evidence.

### 12.2 Invocation-Layer Replay Prevention

Replay prevention for individual actions MUST be implemented at the invocation layer, not the envelope layer:

* PEPs MUST treat `envelope_id` as an audit correlation identifier, not an invocation nonce.
* PEPs MUST NOT assume `envelope_id` uniqueness implies an action is non-replayed.
* `envelope_id` is not sufficient for action replay prevention and MUST NOT be the sole replay control.
* For side-effecting operations (writes, mutations, tool executions), PEPs operating in **EM-DELEGATE** or **EM-STRICT** mode MUST require invocation-layer evidence (RFC-004 `hop_id` or RFC-006 invocation evidence) in addition to the Authority Envelope. Requests lacking invocation evidence for side-effecting operations MUST be denied in these modes.
* In **EM-OBSERVE** and **EM-GUARD** modes, the absence of invocation evidence for side-effecting operations MUST be logged as a warning.

### 12.3 Envelope Identity

* `envelope_id` SHOULD be a UUID v7 (time-ordered) to optimize audit queries.
* `envelope_id` uniqueness is REQUIRED within the scope of a `txn_id`. Implementations MUST NOT reuse an `envelope_id` for a different delegation grant within the same transaction.

---

## 13. Badge Composition and Verification Order

Authority Envelopes bind to Trust Badges but do not replace them. The complete verification stack for a request is:

```
┌─────────────────────────────────────────┐
│ 1. Trust Badge (RFC-002)                │  "Who is this agent?"
│    Verify signature, expiry, revocation │
├─────────────────────────────────────────┤
│ 2. Key Ownership (RFC-003)              │  "Does this key belong to this DID?"
│    Confirm kid → DID binding            │
├─────────────────────────────────────────┤
│ 3. Authority Envelope (this RFC)        │  "What may this agent do?"
│    Verify signature, chain, narrowing   │
├─────────────────────────────────────────┤
│ 4. Invocation Evidence (RFC-004/006)    │  "Is this action uniquely recorded?"
│    Verify hop attestation / evidence    │
├─────────────────────────────────────────┤
│ 5. PDP Query (RFC-005)                  │  "Does policy allow this?"
│    Attribute projection → decision      │
├─────────────────────────────────────────┤
│ 6. Obligation Enforcement (RFC-005)     │  "What else must happen?"
│    Execute obligations per EM-mode      │
└─────────────────────────────────────────┘
```

Failure at any layer MUST prevent progression to subsequent layers (fail-closed), subject to the active Enforcement Mode.

---

## 14. RFC-004 Cross-Linking

Authority Envelopes and Hop Attestations serve complementary roles:

| Artifact | Defined In | Purpose | Links To |
|----------|-----------|---------|----------|
| Authority Envelope | This RFC | Who granted what authority | `txn_id` → RFC-004 transaction |
| Hop Attestation | RFC-004 | Who sent what over which transport | `authority_envelope_hash` → this RFC |

### 14.1 Linking Rules

* Authority Envelopes carry `txn_id` (REQUIRED) which corresponds to the `txn_id` defined in RFC-004 §4.
* Hop Attestations MAY carry an `authority_envelope_hash` claim (SHA-256 of the governing Authority Envelope's JWS). This is RECOMMENDED for side-effecting actions (writes, mutations, tool executions) and OPTIONAL for read-only operations.
* The `txn_id` provides global correlation. The `authority_envelope_hash` provides local binding between a specific transport hop and its governing authority.

### 14.2 Audit Reconstruction

Given a `txn_id`, an auditor can reconstruct:

1. The **delegation chain**: all Authority Envelopes sharing that `txn_id`, ordered by `parent_authority_hash`.
2. The **hop chain**: all Hop Attestations sharing that `txn_id`, ordered by `parent_hop_hash` (RFC-004).
3. The **binding**: which hops were governed by which authority, via `authority_envelope_hash`.

---

## 15. Transport Requirements

This specification is transport-agnostic. Implementations MUST ensure:

* Authority Envelopes are transmitted over encrypted channels (TLS 1.2+ or equivalent).
* Envelopes are transmitted as JWS Compact Serialization strings.
* The transport mechanism provides a dedicated field or header for the Envelope; it MUST NOT be embedded in application-layer payloads where it could be stripped or modified by intermediaries.

Non-normative transport bindings are provided in Appendices A, B, and C.

---

## 16. Registry Outage Behavior

Registry dependency varies by operation. This section distinguishes between operations that require live registry access and those that do not.

### 16.1 Chain Retrieval

Delegation chain verification SHOULD NOT require registry access if the chain is available locally. Acceptable chain presentation strategies:

* **Full chain in request.** The requesting agent transmits all Envelopes in the chain. The PEP verifies locally without registry calls.
* **Partial chain with local cache.** The PEP caches previously-verified Envelopes by `envelope_id` and resolves missing links from cache.
* **Registry-assisted resolution.** The PEP fetches missing Envelopes from the Registry. This is a fallback, not a primary strategy.

PEPs SHOULD prefer full-chain presentation to minimize registry dependency.

### 16.2 Revocation Checks

Badge revocation verification (RFC-002) may require live registry access. When the Registry is unreachable for revocation checks, behavior is governed by the active Enforcement Mode:

| Enforcement Mode | Revocation Check Outage Behavior |
|-----------------|----------------------------------|
| EM-OBSERVE | Log warning, proceed. |
| EM-GUARD | Proceed with cached revocation data if available. Log warning. DENY if no cached data and badge trust level requires registry verification. |
| EM-DELEGATE | Use cached revocation data with short grace period (RECOMMENDED: 5 minutes). DENY if grace period exceeded and no valid cache. |
| EM-STRICT | DENY immediately. No grace period, no fallback. |

PEPs SHOULD cache registry responses (badge revocation lists, trust level metadata) with appropriate TTLs to reduce outage impact.

---

## 17. Security Considerations

### 17.1 Threats and Mitigations

| Threat | Mitigation |
|--------|------------|
| Envelope forgery | JWS signature verification using Badge-bound key (RFC-002, RFC-003). |
| Authority escalation via modified constraints | Monotonic narrowing enforced by PEP and PDP (§8). |
| Action replay | Invocation-layer replay prevention (§12). Hop attestation or invocation evidence per action. |
| Badge theft enabling Envelope signing | Badge-bound key via RFC-003; short badge TTL (RFC-002 default 5 min). |
| Chain injection (inserting fake intermediate) | `parent_authority_hash` cryptographic chaining; `issuer_did == parent.subject_did` check. |
| PEP bypass | Agent self-enforcement prohibition (§9.3). Architectural separation of PEP from agent. |
| Constraint widening | PDP evaluates parent-child constraint pairs; DENY on invalid narrowing (§8.5). |
| Stale authority after badge revocation | `issuer_badge_jti` binding; revocation check in verification sequence step 1. |
| Infinite delegation depth | `delegation_depth_remaining` decrement; configurable max chain depth (§9.4). |
| Registry SSRF via DID resolution | This RFC does not require DID resolution for Envelope verification. If implementations perform DID resolution, they MUST apply SSRF protections per RFC-002 guidance. |

### 17.2 Cryptographic Requirements

* Signing algorithms MUST be asymmetric. Symmetric algorithms (HMAC) MUST NOT be used.
* Implementations MUST reject `alg: "none"`.
* EdDSA (Ed25519) is RECOMMENDED for new deployments.
* ECDSA curves (P-256 via ES256, P-384 via ES384) are acceptable.
* RSA algorithms are NOT RECOMMENDED for new deployments due to key size and performance characteristics.
* This specification does not define a closed algorithm set. Acceptable algorithms beyond the recommendations above are governed by deployment policy. Future versions or a dedicated CapiscIO Algorithm Registry MAY formalize the supported set.
* Key rotation MUST be coordinated with Badge re-issuance; an Envelope signed with a rotated-out key MUST be rejected.

### 17.3 Envelope Size Limits

Implementations SHOULD enforce a maximum Envelope payload size of 8 KB to prevent denial-of-service via oversized constraint objects. Envelopes exceeding this limit MAY be rejected.

---

## 18. Future Work

* **Judge (Advisory Enforcement).** A non-blocking evaluation mode that produces recommendations without preventing execution. Useful for training, auditing, and gradual rollout of new policies.
* **Composition Security.** Rules for merging or intersecting authority from independent delegation chains. Required for multi-principal workflows where an agent acts on behalf of multiple authorities simultaneously.
* **Principal Classification.** An optional `principal_type` claim or equivalent mechanism enabling PDPs to distinguish human, agent, service, and organizational identities without resolving DID metadata. This is additive and backward-compatible.
* **Dual-Auth / On-Behalf-Of.** Patterns for preserving originator identity alongside actor identity throughout a delegation chain (analogous to OAuth RFC 8693 `act` claim). Candidate mechanisms include parallel claims, co-signed envelopes, or composite authority artifacts. These patterns are orthogonal to the monotonic narrowing model and MUST NOT compromise delegation invariants.
* **Constraint Vocabulary Registry.** A standardized set of well-known constraint types with defined narrowing semantics, reducing PDP complexity for common patterns.
* **Envelope Request Protocol.** A protocol for agents to request Authority Envelopes from upstream delegators, enabling automated delegation workflows.
* **Selective Disclosure.** Mechanisms for presenting Authority Envelopes to verifiers without revealing the full constraint set (e.g., zero-knowledge proofs of constraint satisfaction).
* **Revocation.** Dedicated Envelope revocation mechanisms beyond badge-session binding (e.g., Envelope-specific revocation lists).

---

## Appendix A: HTTP Binding (Non-Normative)

Authority Envelopes SHOULD be transmitted via a dedicated HTTP header:

```http
POST /v1/tools/database/query HTTP/1.1
Host: api.example.com
Authorization: Bearer <trust_badge_jws>
X-Capiscio-Txn: 018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11
X-Capiscio-Hop: <hop_attestation_jws>
X-Capiscio-Authority: <authority_envelope_jws>
Content-Type: application/json

{ "query": "SELECT * FROM users WHERE active = true" }
```

* `X-Capiscio-Authority` carries the Authority Envelope.
* `Authorization` carries the Trust Badge.
* `X-Capiscio-Txn` and `X-Capiscio-Hop` carry RFC-004 artifacts.
* When a delegation chain has multiple Envelopes, the full chain MAY be transmitted as a comma-separated list in `X-Capiscio-Authority` or via a `X-Capiscio-Authority-Chain` header containing the JSON array of JWS strings.

---

## Appendix B: MCP Binding (Non-Normative)

In MCP JSON-RPC contexts, Authority Envelopes SHOULD be included in the request metadata:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "database_query",
    "arguments": { "query": "SELECT * FROM users" },
    "_meta": {
      "capiscio": {
        "authority_envelope": "<authority_envelope_jws>",
        "txn_id": "018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11",
        "hop_attestation": "<hop_attestation_jws>"
      }
    }
  }
}
```

The `_meta.capiscio` namespace prevents collisions with other MCP metadata extensions.

---

## Appendix C: A2A Binding (Non-Normative)

In the Agent-to-Agent (A2A) protocol, Authority Envelopes are carried as an A2A extension:

**Agent Card Declaration:**

```json
{
  "capabilities": {
    "extensions": [
      {
        "uri": "urn:capiscio:ext:authority-envelope:v1",
        "description": "CapiscIO Authority Envelope support",
        "required": true
      }
    ]
  }
}
```

**Request Metadata:**

```json
{
  "method": "message/send",
  "params": {
    "message": { "..." : "..." },
    "metadata": {
      "capiscio.authority_envelope": "<authority_envelope_jws>",
      "capiscio.txn_id": "018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11"
    }
  }
}
```

* The extension is declared in `capabilities.extensions` per A2A extension conventions.
* Authority data is carried in `metadata` maps on `SendMessageRequest` or `Task` objects.
* The Trust Badge MAY be carried as a bearer token in the A2A `SecurityScheme`.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.2 | 2026-02-25 | Root envelope semantics clarified (§6.1). Multi-use envelopes with invocation-layer replay (§12). PDP schema moved to RFC-005 PIP; §11 retains attribute projection only. Algorithm list relaxed (§17.2). Registry outage split into chain retrieval vs revocation (§16). EM-GUARD clarified as identity-enforced/policy-advisory (§10.2). Jailer removed. |
| 0.1 | 2026-01-20 | Initial draft. |
