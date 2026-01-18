# Capiscio RFCs

This repository contains the technical specifications and architectural decisions for the Capiscio platform.

## Active RFCs

| RFC | Title | Status | Version | Implementation |
|-----|-------|--------|---------|----------------|
| [RFC-001](docs/001-agcp.md) | Agent Governance Control Plane (AGCP) | ✅ Approved | - | ✅ Implemented |
| [RFC-002](docs/002-trust-badge.md) | Trust Badge Specification | ✅ Approved | v1.4 | ✅ Implemented |
| [RFC-003](docs/003-key-ownership-proof.md) | Key Ownership Proof Protocol | ✅ Approved | - | ✅ Implemented |
| [RFC-004](docs/004-tchb-transaction-hop-binding.md) | Transaction and Hop Binding (TCHB) | 📝 Draft | v0.3 | ⏳ Not Implemented |
| [RFC-005](docs/005-policy-definition-distribution-enforcement.md) | Policy Definition, Distribution, and Enforcement (PDEP) | 📝 Draft | v0.2 | ⏳ Not Implemented |

> **⚠️ Note:** Draft RFCs (RFC-004, RFC-005) are design documents that have not yet been implemented.
> Do not expect CLI, SDK, or Server support for draft specifications.

## RFC Process

1. **Draft:** Open a PR with a new RFC in `rfcs/`
2. **Review:** Discussion happens in the PR
3. **Approved:** Merged to main
4. **Superseded:** Noted in the RFC header with pointer to replacement

## RFC Numbering

- `001-099`: Core Architecture
- `100-199`: Protocol Specifications
- `200-299`: SDK & Integration
- `300-399`: Security & Trust

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for RFC authoring guidelines.
