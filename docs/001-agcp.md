# RFC-001: Agent Governance Control Plane (AGCP)

**Version:** 1.0
**Status:** Approved
**Authors:** CapiscIO Core Team
**Created:** 2025-12-05
**Updated:** 2025-12-05

---

## 1. Executive Summary & Threat Model

### 1.1 The Product Goal

To establish **CapiscIO** as the enforcement plane for **Level 2 Agentic Contexts**. We provide the infrastructure to move enterprise governance from static, perimeter-based access control to verifiable **Transitive Authority**.

**The Strategic Wedge:**

> **Level 1 risks are prompt injection. Level 2 risks are when Agent B empties your bank account because Agent A asked it to "help with finances."**
> We are not a firewall for hallucinations; we are the control plane for systems of interacting agents.

### 1.2 Threat Model Summary

| Threat | Status | Mechanism |
| :--- | :--- | :--- |
| **Authority Escalation** | 🛡️ **Blocked** | Transitive Intersection (Golden Rule) |
| **Context/Orchestration Drift** | 🛡️ **Blocked** | Signed Trace ID + Intent Locking |
| **Forged Delegation** | 🛡️ **Blocked** | SVID Signature Validation |
| **Rogue/Revoked Agent** | 🛡️ **Blocked** | Short-lived TTL + Revocation Lists |
| **Prompt Injection** | ❌ *Out of Scope* | Handled by Model Firewall |
| **Data Exfiltration** | ❌ *Out of Scope* | Handled by DLP / Egress Filtering |

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

---

## 3. Component Deep Dive

### 3.1 The Agent Registry (The Foundation)

The Registry is the authoritative locus of truth for identity, authority, and delegation rights. **Without it, verifiable transitive enforcement is impossible.**

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
- **Revocation Propagation:** PEPs consume a lightweight CRL/OCSP stream (polled every 30s) **or** a Push-Notification channel for "Emergency Stop" events (sub-second propagation).
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

---

## Changelog

- **v1.0 (2025-12-05):** Initial public release
