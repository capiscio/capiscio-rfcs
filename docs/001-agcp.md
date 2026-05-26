# RFC-001: Agent Governance Control Plane (AGCP)

**Version:** 1.2
**Status:** Approved
**Authors:** CapiscIO Core Team
**Created:** 2025-12-05
**Updated:** 2026-05-26

---

## 1. Executive Summary & Threat Model

### 1.1 The Product Goal

To establish **CapiscIO** as the enforcement plane for **Level 2 Agentic Contexts**. We provide the infrastructure to move enterprise governance from static, perimeter-based access control to verifiable **Transitive Authority**.

**The Strategic Wedge:**

> **Level 1 risks are prompt injection. Level 2 risks are when Agent B empties your bank account because Agent A asked it to "help with finances."**
> We are not a firewall for hallucinations; we are the control plane for systems of interacting agents.

**Governing Principle:**

> **"LLMs can propose actions. They cannot define what is allowed."**

CapiscIO treats the LLM layer as an untrusted signal source. All authorization decisions are made by the deterministic enforcement plane — the Policy Enforcement Point (PEP) — operating against cryptographically verifiable artifacts. No LLM output, reasoning trace, or chain-of-thought can authorize an action. Declared intent, not inferred intent, governs what agents are permitted to do.

### 1.2 Threat Model Summary

| Threat | Status | Mechanism |
| :--- | :--- | :--- |
| **Authority Escalation** | 🛡️ **Blocked** | Transitive Intersection (Golden Rule) |
| **Context/Orchestration Drift** | 🛡️ **Blocked** | Signed Trace ID + Intent Locking |
| **Forged Delegation** | 🛡️ **Blocked** | SVID Signature Validation |
| **Confused Deputy** | 🛡️ **Blocked** | Monotonic narrowing via Authority Envelopes (RFC-008); a high-privilege agent cannot be manipulated by a low-privilege caller into exercising authority the caller does not hold. Delegation chains are cryptographically bound. |
| **Rogue/Revoked Agent** | 🛡️ **Blocked** | Short-lived TTL + Revocation Lists |
| **Prompt Injection** | ❌ *Out of Scope* | Handled by Model Firewall |
| **Data Exfiltration** | ❌ *Out of Scope* | Handled by DLP / Egress Filtering |
| **LLM-based authorization bypass** | 🛡️ **Blocked by design** | RFC-010 classifier outputs are advisory signal only. They MUST NOT be the sole basis for a DENY decision. The RFC-009 PEP is the sole authoritative enforcement boundary. Classifier verdicts enrich enforcement; they do not make authorization decisions. |

### 1.3 What CapiscIO Is NOT

To avoid category confusion:

- **NOT a Model Firewall** (we do not inspect prompt syntax).
- **NOT a DLP Tool** (we do not scan packets for PII regex).
- **NOT a Service Mesh** (we govern permissions, not packets).
- **IS:** The governance enforcement layer for **systems of interacting agents**.

---

## 2. Core Architecture: The "Trace & Enforce" Pattern

> **Diagram Required:** *[Engineering Action]* A sequence diagram showing: User → Planner Agent → Executor Agent → Database, with Trace ID propagation and Authority Intersection at each hop. Each arrow should show the "Effective Scope" shrinking.

### 2.1 The Invariant (The "Golden Rule")

We abstract implementation complexity into a single, verifiable security guarantee:

> **"No agent can take an action that exceeds the authority of the human or system identity that triggered the workflow."**

*Implementation:* The effective authority at any hop is the **intersection** of the Originator's scope, every Intermediate Agent's maximum scope, and the Requested Action.

### 2.2 Originator Types (Defining "Intent")

- **Human Originator:** Intent is derived from a verifiable user action (authenticated via IdP).
- **System Originator:** Intent must be **declared and signed** before execution.
    - *Example:* A nightly batch job declares intent `generate_quarterly_report` and is signed by `system:finance-automation`. Any agent invoked by this job inherits this scope and cannot exceed it.

**Scope Boundary — Automated Intent Classification:**

CapiscIO does not perform automated intent classification from natural language requests. Reliable automated mapping of open-ended natural language to bounded, cryptographically enforceable capability classes is an unsolved problem in the general case. CapiscIO solves the enforcement layer: given a declared intent, enforce it deterministically. How a system maps a user's expressed goal to a declared capability class before issuing an Authority Envelope (RFC-008) is the responsibility of the orchestration layer above CapiscIO.

For purpose-built agents with bounded tool surfaces, declared intent is specified at registration time via the Pre-Authorized Action Manifest (RFC-009). For open-ended conversational agents, the orchestration layer must supply a structured intent declaration before root envelope issuance. CapiscIO enforces what is declared; it does not classify what was meant.

### 2.3 Verification Locality Principle

Runtime trust verification MUST NOT require synchronous interaction with the Registry or any centralized service.

This is a foundational invariant of the architecture. All trust artifacts produced by CapiscIO — Badges (RFC-002), Authority Envelopes (RFC-008), Hop Attestations (RFC-004) — are cryptographically self-verifiable. A verifier in possession of the artifact and the issuer's public key material can validate authenticity, integrity, and claims without network access to the issuing authority.

The architecture treats **issuance** and **verification** as strictly separate concerns:

| Concern | Network Required | Central Service Role |
|---------|-----------------|---------------------|
| **Issuance** | Yes | The Registry (or CA) authenticates the subject, applies trust-level validation, and signs the artifact. This is an online, coordinated operation. |
| **Verification** | No | Verifiers validate artifacts using locally available cryptographic material (cached issuer keys, pre-distributed JWKS). No registry callback is required. |
| **Revocation** | Recommended | Revocation status is distributed as a cacheable, eventually-consistent data stream. Verifiers SHOULD maintain a local revocation cache synchronized periodically (see §4.3). Verification proceeds against the local cache, not a synchronous endpoint call. |
| **Trust Augmentation** | Optional | Online services provide enhanced trust signals — analytics, federation metadata, organizational context — that augment but do not gate runtime verification. |

**Rationale:**

Runtime verification that depends on synchronous registry access creates a single point of failure, prevents edge and offline operation, and imposes latency on every trust decision. By separating issuance (inherently coordinated) from verification (inherently local), the architecture achieves the operational profile of PKI and mTLS: centralized issuance, decentralized verification.

**Normative Requirements:**

1. Verifiers MUST be able to validate any CapiscIO trust artifact using only locally cached cryptographic material and a local revocation cache.
2. Implementations MUST NOT embed synchronous registry calls in the verification critical path.
3. SDK and library implementations MUST provide a verification API that operates without network access when initialized with issuer key material.
4. The Registry MUST publish issuer keys via a cacheable JWKS endpoint. Verifiers SHOULD cache this material with a TTL appropriate to their security posture.
5. Revocation data MUST be distributable as a cacheable artifact (see §4.3). Verifiers synchronize revocation state asynchronously, not per-verification.

**Scope:**

This principle governs verification only. Issuance, registration, trust-level validation, and trust anchor distribution remain coordinated operations that require Registry interaction. The Registry is the authoritative source for these operations and is not diminished by this principle.

---

## 3. Component Deep Dive

### 3.1 The Agent Registry (Trust Anchor and Coordination)

The Registry is the authoritative source for identity issuance, trust anchor distribution, and delegation right coordination. It serves as the Certificate Authority (CA) for trust levels 1–4 and the canonical source of agent metadata, trust graph relationships, and revocation state.

**Operational Role:**

The Registry is essential for **issuance and coordination** operations: registering agents, issuing badges, distributing trust anchors (JWKS), managing revocation state, and maintaining the trust graph. These are inherently coordinated, online operations.

The Registry is NOT required for **runtime verification**. Per the Verification Locality Principle (§2.3), verifiers operate against locally cached cryptographic material and revocation state. The Registry distributes the material; it does not participate in each verification decision.

Alternative trust anchor distribution mechanisms — cached JWKS bundles, federated key distribution, out-of-band provisioning — are valid provided they deliver authentic issuer key material and timely revocation data.

- **Trust Graph:** Defines **who may delegate authority, not who may communicate**.
    - *Crucial Distinction:* Agent A being allowed to *call* Agent B (network) does not mean Agent A can *delegate authority* to Agent B (governance). Communication ≠ Delegation.

### 3.2 The Trace ID (Structured Evidence)

The Trace ID is a cryptographically signed envelope containing the full execution lineage.

**Schema:**

```json
{
  "trace_id": "uuid-v4",
  "originator": {
    "type": "human",
    "id": "user:alice@corp.com",
    "initial_scope_hash": "sha256:a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
  },
  "delegation_chain": [
    {
      "agent_id": "agent:planner-v1",
      "timestamp": 1715000000,
      "effective_scope_hash": "sha256:b3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
      "signature": "sig_planner_v1..."
    }
  ]
}
```

### 3.3 The Policy Decision Point (PDP)

- **Role:** OPA is the *executor*. **CapiscIO defines the governance primitives**: Originator, Delegation Chain, Intent Class, and Authority Envelope.
- **Intent Classes:** Governance-defined categories (e.g., `financial_write`), **not LLM-inferred semantics**. We do not guess intent; we enforce declared intent.

### 3.4 Component Responsibility Matrix

The following matrix defines which component owns each capability. This separation is normative for implementations and SDK design.

#### Core (CLI, Libraries, SDKs, PEP)

Core components operate at the runtime boundary. They MUST function independently of the Server for all verification operations.

| Responsibility | Description |
|---------------|-------------|
| **Local trust verification** | Validate badges, envelopes, and hop attestations using locally cached issuer keys and revocation data. No synchronous server calls. |
| **Runtime authority mediation** | Evaluate authority at enforcement boundaries. Gate execution based on cryptographic trust artifacts. |
| **Authority evaluation** | Compute effective scope via transitive intersection (§2.1). Enforce monotonic narrowing (RFC-008). |
| **Signing** | Sign hop attestations, delegation tokens, and runtime evidence using the agent's private key. |
| **Portable trust semantics** | Produce and consume trust artifacts in standard formats (JWS, DID, protobuf). No server-specific wire formats in the verification path. |
| **Runtime event emission** | Emit canonical runtime events for enforcement decisions, authority transitions, and execution provenance. |

#### Server (Registry, Control Plane)

Server components provide coordination, issuance, and visibility. They are essential infrastructure but MUST NOT appear in the runtime verification critical path.

| Responsibility | Description |
|---------------|-------------|
| **Identity issuance** | Register agents, issue badges, manage trust levels. Online, coordinated operation. |
| **Trust anchor distribution** | Publish issuer JWKS, distribute CA public keys. Verifiers cache this material. |
| **Revocation management** | Accept revocation requests, maintain revocation state, serve revocation lists and status endpoints for cache synchronization. |
| **Federation** | Coordinate trust across organizational and domain boundaries. Manage trust graph relationships. |
| **Analytics and visibility** | Aggregate runtime events, provide audit views, surface compliance and posture dashboards. |
| **Enterprise augmentation** | Policy management workflows, organizational controls, multi-tenancy, billing. |

**Boundary Rule:**

If removing the Server causes runtime verification to fail, the implementation violates the Verification Locality Principle (§2.3). Verification depends on cached artifacts distributed by the Server, not on the Server's runtime availability.

---

## 4. Enforcement Strategy & Guarantees

### 4.1 Integration Patterns

We guarantee that **every external action and every A2A handoff** is subject to the same transitive authority check.

| Pattern | Use Case | Implementation |
| :--- | :--- | :--- |
| **1. In-Process SDK** | **Core.** LangChain, AutoGen. | `capiscio.guard()` wrapper acting as PEP. |
| **2. Sidecar Proxy** | **Containerized Agents.** | Envoy filter/Sidecar intercepting egress. |
| **3. API Gateway** | **SaaS/Black-Box.** | Middleware at ingress/egress boundary. |
| **4. Serverless** | **Cloud Functions.** | Function Decorator validating Trace ID. |

### 4.2 Failure Modes and Guarantees

The system fails securely by default.

- **Missing Trace ID** → **AUTOMATIC DENY**.
- **Forged Trace ID (Signature Mismatch)** → **DENY + ALERT (Sev 1)**.
- **Delegation path not permitted in Trust Graph** → **DENY**.
- **Scope Intersection resolves to Empty Set** → **DENY**.

### 4.3 Revocation (The Kill Switch)

Identities and policies must be revocable mid-flight.

- **Short-Lived SVIDs:** Default TTL is 1 hour.
- **Revocation Distribution:** The Registry maintains authoritative revocation state. PEPs consume revocation data via:
    - **Pull:** Periodic sync against the bulk revocation list endpoint (default interval: 30s).
    - **Push:** Real-time notification channel for "Emergency Stop" events (sub-second propagation).
- PEPs verify revocation status against their **local revocation cache**, not via synchronous per-verification callbacks to the Registry (per §2.3).
- **Result:** An agent detected as "rogue" is cryptographically barred from further delegation within <60 seconds.

---

## 5. Audit & Compliance

**Value Proposition:**

> **"This is the first audit trail that can explain multi-agent decisions deterministically."**

**Log Schema:**

- `trace_id`: Global transaction reference.
- `originator_identity`: The root source of authority.
- `authority_at_decision`: The specific intersection of permissions used.
- `policy_version`: Exact version of the rules engine used.
- `decision`: `ALLOW` | `DENY`

**Immutability:** Audit reconstruction requires policies to be versioned immutably. **Policy bundles cannot be mutated retroactively.** A decision made today must be reconstructible 3 years from now using `Policy_v1.2` and the signed `Trace_ID`.

---

## 6. Technical Defaults (Reference Implementation)

- **Trust Model:** **PKI with SPIFFE.**
- **Latency Budget:** **<5ms p95 (Warm Cache).**
    - *Note:* Cold start latency (bundle fetch) <50ms. Bundle TTL default is 60s.
- **Deployment:** **Hybrid.** Control Plane (Registry/PDP) is SaaS; Data Plane (PEPs) lives in the Customer VPC.

!!! note "Co-Located PDP Deployment (Non-Normative)"
    A valid deployment variant embeds the PDP within the same process as the PEP (e.g., an OPA evaluator embedded in the CapiscIO server). In this configuration, policy evaluation is in-process with no network hop, reducing decision latency to sub-millisecond. The co-located PDP implements the same `PDPClient` interface as an external PDP; the PEP middleware is unaware of whether the PDP is local or remote. See RFC-005 Appendix B for the reference implementation details.

---

## Changelog

- **v1.2 (2026-05-26):** Added Verification Locality Principle as foundational invariant (§2.3). Reframed Registry role from runtime dependency to trust anchor distribution and coordination (§3.1). Added Component Responsibility Matrix defining Core vs Server boundaries (§3.4). Clarified revocation as cached/distributed data stream, not synchronous callback (§4.3). Added Appendix A with operational trust flow examples.
- **v1.1 (2026-04-30):** Added Governing Principle statement (§1.1). Added Confused Deputy and LLM-based authorization bypass threat rows (§1.2). Added intent classification scope boundary (§2.2).
- **v1.0 (2025-12-05):** Initial public release

---

## Appendix A: Operational Trust Flow Examples

This appendix provides concrete examples illustrating how the Verification Locality Principle (§2.3) operates in practice. Each scenario demonstrates that runtime trust verification proceeds without synchronous registry interaction.

### A.1 Level 0 Offline Verification

**Scenario:** An agent operates in an air-gapped environment with no network access. The agent was issued a Trust Badge before deployment.

**Trust Flow:**

```
1. Agent presents Trust Badge (JWS compact format) to local PEP
2. PEP extracts issuer DID from badge `iss` claim
3. PEP looks up issuer JWKS from local trust anchor cache
   └── Cache populated during deployment (USB, secure transfer, etc.)
4. PEP verifies JWS signature against cached public key
5. PEP checks `exp` claim against local system time
6. PEP checks badge `jti` against local revocation list
   └── Revocation list snapshot from deployment date
7. Verification succeeds → Agent identity confirmed
```

**What did NOT happen:**

- No HTTPS call to registry
- No JWKS fetch over network
- No revocation status query

**Operational Notes:**

- The revocation list is stale (deployment date), which is acceptable per §2.3 (Revocation MAY use cached data)
- This is the "Offline Operation" profile — first-class, not degraded mode

### A.2 Cached Revocation Validation

**Scenario:** An online PEP receives a badge for an agent that was revoked 5 minutes ago. The PEP's revocation cache was last synced 30 seconds ago.

**Trust Flow:**

```
1. Agent presents Trust Badge to PEP
2. PEP verifies JWS signature (succeeds)
3. PEP checks exp claim (valid)
4. PEP checks jti against local revocation cache
   └── Cache contains jti (revoked 5 min ago, synced 30s ago)
5. Badge found on revocation list → DENY
```

**Key Point:** Revocation was detected entirely from cache. The 30-second sync interval means worst-case revocation propagation is <60 seconds — without per-verification callbacks.

### A.3 Disconnected Runtime Mediation

**Scenario:** A multi-agent workflow is running. Network connectivity to the registry is lost mid-execution.

**Trust Flow (Normal):**

```
1. Agent A delegates to Agent B with Authority Envelope
2. Agent B presents envelope + badge to local PEP
3. PEP verifies badge signature (local JWKS cache)
4. PEP verifies envelope signature (local JWKS cache)
5. PEP validates monotonic narrowing (local computation)
6. PEP queries co-located PDP (OPA in-process)
7. PDP returns ALLOW → Execution proceeds
```

**When Network Drops:**

```
8. Background revocation sync fails (network error)
9. PEP continues operating with cached revocation data
10. New delegations continue to verify (signatures local)
11. PDP queries continue (PDP is co-located or cached)
12. Audit events buffer locally (forwarded when network returns)
```

**Result:** The workflow completes successfully. When network returns, buffered events sync and revocation cache refreshes.

### A.4 Authority Narrowing (Monotonic)

**Scenario:** Originator grants broad authority. Each delegation in the chain narrows scope.

**Trust Flow:**

```
Originator (Human Operator)
  └── Issues Root Envelope: capabilities = ["tools.*"]

Agent A receives Root Envelope
  └── Narrows: capabilities = ["tools.database.*"]
  └── Issues Child Envelope to Agent B

Agent B receives Child Envelope
  └── Narrows: capabilities = ["tools.database.read"]
  └── Issues Grandchild Envelope to Agent C

Agent C presents Grandchild Envelope to PEP
  └── PEP validates chain:
      1. Grandchild ⊆ Child ⊆ Root (monotonic narrowing satisfied)
      2. All signatures valid (local JWKS)
      3. No envelope in chain revoked (local cache)
      4. Delegation depth respected (count = 3, max = 5)
  └── Effective authority: tools.database.read ONLY
```

**What the PEP computed locally:**

- Capability intersection across 3 envelopes
- Signature verification for 3 envelopes
- Revocation check for 3 envelope hashes
- Delegation depth arithmetic

**No network call required.**

### A.5 Envelope Chaining with Hop Binding

**Scenario:** A transaction spans 4 agents, each recording a hop attestation.

**Trust Flow:**

```
Transaction: txn_id = "txn_abc123"

Hop 1: Originator → Agent A
  └── Authority Envelope E1 (root)
  └── Hop Attestation H1: signed(txn_id, hop_id=1, envelope_hash=E1)

Hop 2: Agent A → Agent B
  └── Authority Envelope E2 (child of E1)
  └── Hop Attestation H2: signed(txn_id, hop_id=2, envelope_hash=E2, parent_hop=H1)

Hop 3: Agent B → Agent C
  └── Authority Envelope E3 (child of E2)
  └── Hop Attestation H3: signed(txn_id, hop_id=3, envelope_hash=E3, parent_hop=H2)

Hop 4: Agent C → Tool Server
  └── Presents E3 + H3 + badge to PEP
  └── PEP reconstructs chain from hop attestations
  └── PEP verifies: E3 ⊆ E2 ⊆ E1 (all local)
  └── PEP verifies: H3.parent_hop = H2.hash, H2.parent_hop = H1.hash
  └── Full provenance established without registry query
```

**Audit Reconstruction:**

Later, auditors reconstruct the full transaction from the signed attestation chain. No registry call is needed — the chain is self-verifying.

### A.6 Local Signature Verification

**Scenario:** An SDK wrapper verifies a badge before invoking a guarded function.

**Trust Flow:**

```python
from capiscio import guard, BadgeVerifier

# Trust anchor cache loaded at process start
verifier = BadgeVerifier(
    trust_anchors="/etc/capiscio/jwks/",
    revocation_cache="/var/capiscio/revocation/"
)

@guard(verifier=verifier, required_level=1)
def query_database(query: str):
    # Function executes only if badge verification passes
    return db.execute(query)

# At call time:
# 1. guard() extracts badge from context
# 2. verifier.verify(badge) runs entirely in-process:
#    - Parse JWS
#    - Lookup issuer JWKS from local file
#    - Verify signature (cryptographic op)
#    - Check expiration (clock comparison)
#    - Check revocation (local file lookup)
# 3. If verification passes, query_database() executes
# 4. If verification fails, raises UnauthorizedError
```

**Latency:** <1ms for warm verification (no I/O, pure computation).

### A.7 Emergency Revocation Propagation

**Scenario:** A compromised agent is detected. Emergency revocation is triggered.

**Trust Flow:**

```
T+0:     Security team issues emergency revocation for agent X
T+0:     Registry updates revocation list, emits push notification
T+2s:    Push notification reaches subscribed PEPs
T+2s:    PEPs update local revocation cache
T+3s:    Agent X attempts to use cached badge at PEP
T+3s:    PEP checks local cache → badge revoked → DENY

Alternatively (pull-only deployment):
T+0:     Revocation issued
T+30s:   PEP sync interval fires, pulls new revocation list
T+30s:   Local cache updated
T+31s:   Agent X attempts action → DENY
```

**Key Point:** Even "emergency" revocation uses the distributed cache model. PEPs never call back to the registry synchronously per-verification. The push channel accelerates propagation but is not a verification dependency.

---

*These examples are non-normative illustrations of the Verification Locality Principle. Implementations may vary in caching strategies, sync intervals, and deployment topology.*
