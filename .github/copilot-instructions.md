# capiscio-rfcs - GitHub Copilot Instructions

## ABSOLUTE RULE: RFCs ARE READ-ONLY

**DO NOT modify any files in this repository without explicit team authorization.**

RFCs are frozen protocol specifications. Implementation must conform to RFCs, not the other way around. If RFC changes are needed, document the proposed change and stop.

---

## Repository Purpose

**capiscio-rfcs** contains the formal protocol specifications for the CapiscIO ecosystem.

These define the wire formats, security properties, and compliance requirements that all implementations must follow.

**Default Branch:** `main`

## RFC Index

| RFC | Title | Status |
|-----|-------|--------|
| RFC-001 | Agent Card Protocol (AGCP) | Active |
| RFC-002 | Trust Badge Specification | v1.3 Frozen |
| RFC-003 | Key Ownership Proof (PoP) | 100% Implemented |
| RFC-004 | Transaction Chain Hop Binding (TCHB) | Draft |
| RFC-005 | Policy Definition, Distribution & Enforcement (PDEP) | Draft |
| RFC-006 | MCP Tool Authority Evidence | Active |
| RFC-007 | MCP Server Identity & Discovery | Active |

## Structure

```
capiscio-rfcs/
└── docs/
    ├── index.md
    ├── 001-agcp.md
    ├── 002-trust-badge.md
    ├── 003-key-ownership-proof.md
    ├── 004-tchb-transaction-hop-binding.md
    ├── 005-policy-definition-distribution-enforcement.md
    ├── 006-mcp-tool-authority-evidence.md
    ├── 007-mcp-server-identity-discovery.md
    └── CONTRIBUTING.md
```

## Usage by Other Repos

- **capiscio-core**: Implements badge verification, PoP, DID resolution per RFC-002/003
- **capiscio-server**: Implements badge issuance, registry, PoP endpoints per RFC-002/003
- **capiscio-sdk-python**: Implements SimpleGuard, badge verification per RFC-002/003
- **capiscio-mcp-python**: Implements MCP guard per RFC-006/007
- **capiscio-docs**: References RFCs in public documentation

## When to Reference This Repo

- Validating that an implementation matches the spec
- Looking up required/optional fields in badge claims
- Checking trust level definitions (0-3)
- Verifying DID method requirements
- Understanding the PoP challenge/proof flow
