# CapiscIO RFCs

Request for Comments (RFCs) define the CapiscIO trust architecture — cryptographic identity, authority mediation, and enforcement for AI agents.

## Architecture Overview

CapiscIO is a **runtime trust layer**. At the core, it provides:

1. **Local verification** — Validate agent identity without network access (RFC-002)
2. **Authority mediation** — Enforce capability boundaries at runtime (RFC-008)
3. **Signed execution** — Cryptographic evidence of actions and delegation (RFC-001, RFC-004)

The architecture separates **issuance** (coordinated, online) from **verification** (local, offline-capable). This is the Verification Locality Principle (RFC-001 §2.3): all trust artifacts are self-verifiable given cached issuer keys and revocation data. No synchronous registry call is required for runtime verification.

---

## RFC Index by Layer

### Runtime Trust (Core)

These RFCs define the cryptographic primitives that operate at runtime. They are the foundation.

| RFC | Title | Status | Purpose |
|-----|-------|--------|---------|
| [RFC-002](002-trust-badge.md) | Trust Badge Specification | ✅ Approved | Agent identity credential — self-verifiable JWS |
| [RFC-003](003-key-ownership-proof.md) | Key Ownership Proof Protocol | ✅ Approved | Proof of key control for badge issuance |
| [RFC-008](008-delegated-authority-envelopes.md) | Delegated Authority Envelopes | ✅ Approved | Scoped authority containers — monotonic narrowing |
| [RFC-004](004-tchb-transaction-hop-binding.md) | Transaction and Hop Binding | ✅ Approved | Signed execution lineage across agent hops |

### Enforcement (PEP/PDP)

These RFCs define how trust decisions are made and enforced at system boundaries.

| RFC | Title | Status | Purpose |
|-----|-------|--------|---------|
| [RFC-001](001-agcp.md) | Agent Governance Control Plane | ✅ Approved | Architecture overview — Trace & Enforce pattern |
| [RFC-005](005-policy-definition-distribution-enforcement.md) | PDP Integration Profile | ✅ Approved | Policy engine integration (OPA, Cedar) |
| [RFC-009](009-pre-authorized-action-manifest.md) | Pre-Authorized Action Manifest | 📝 Draft | Action manifest protocol for pre-authorization |
| [RFC-010](010-intent-classification-policy-intelligence.md) | Intent Classification and Policy Intelligence | 📝 Draft | Advisory classifier signals (NOT authorization) |
| [RFC-011](011-runtime-event-semantics.md) | Runtime Event Semantics | 📝 Draft | Authority transition events for audit and compliance |

### MCP Integration

These RFCs extend the trust model to Model Context Protocol (MCP) tools and servers.

| RFC | Title | Status | Purpose |
|-----|-------|--------|---------|
| [RFC-006](006-mcp-tool-authority-evidence.md) | MCP Tool Authority and Evidence | ✅ Approved | Tool-level authority and execution evidence |
| [RFC-007](007-mcp-server-identity-discovery.md) | MCP Server Identity and Discovery | ✅ Approved | MCP server identity via DID and Agent Card |

### Coordination (Server)

The registry provides issuance, trust anchor distribution, and coordination. It is essential infrastructure but is NOT in the runtime verification critical path.

| Component | Role | RFCs |
|-----------|------|------|
| Identity Issuance | Register agents, issue badges, manage trust levels | RFC-002 §7, RFC-003 |
| Trust Anchor Distribution | Publish JWKS, distribute CA public keys | RFC-002 §11 |
| Revocation Management | Maintain revocation state, serve revocation lists | RFC-002 §7.5 |
| Federation | Cross-org trust relationships, trust graph | RFC-001 §3.1 |

---

## Foundational Invariants

These principles are normative across all RFCs:

| Invariant | Statement | Reference |
|-----------|-----------|-----------|
| **Verification Locality** | Runtime verification MUST NOT require synchronous registry interaction | RFC-001 §2.3 |
| **Transitive Authority** | No agent can exceed the authority of the originator | RFC-001 §2.1 |
| **Monotonic Narrowing** | Authority can only shrink, never expand, through delegation | RFC-008 §3 |
| **Declared Intent** | LLMs propose; the enforcement plane decides | RFC-001 §1.1 |

---

## RFC Process

| Stage | Description |
|-------|-------------|
| **Draft** | Initial proposal under discussion |
| **Review** | Formal review period (minimum 2 weeks) |
| **Approved** | Accepted for implementation |
| **Superseded** | Replaced by a newer RFC |

## Contributing

See [Contributing](CONTRIBUTING.md) for guidelines on proposing new RFCs.
