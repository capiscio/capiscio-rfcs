# RFC-009: Pre-Authorized Action Manifest Protocol

**Version:** 1.0  
**Status:** Draft
**Authors:** CapiscIO Core Team  
**Created:** 2026-04-30  
**Updated:** 2026-04-30  
**Requires:** RFC-001 (AGCP), RFC-005 (Policy Definition, Distribution & Enforcement), RFC-008 (Delegated Authority Envelopes)

---

## 1. Abstract

This RFC defines the **Pre-Authorized Action Manifest** (PAM), the cryptographic artifact that declares the bounded action surface an agent is authorized to operate within before any tool call is issued. Where RFC-008 Authority Envelopes establish *what authority has been delegated*, Action Manifests establish *what actions are permitted within that authority* — at the level of specific tools, action signatures, capability classes, and operational constraints.

The manifest is a signed, version-hashed artifact registered at agent onboarding time and referenced on every agent-to-agent communication via the **Intent Envelope**, a required artifact in A2A protocol messages. Enforcement is deterministic: the RFC-009 Policy Enforcement Point (PEP) checks each incoming tool call against the Capability Binding Registry and the manifest before any PDP query is executed.

**Governing Principle:** This specification implements CapiscIO's core architectural invariant: LLMs can propose actions. They cannot define what is allowed. All authorization decisions are made by the deterministic enforcement plane. RFC-010 classifier output is advisory signal consumed at Step 1C; it does not make authorization decisions and MUST NOT be the sole basis for a DENY.

This specification defines:

* The Action Manifest format and schema, built as a CapiscIO Extension Profile over OASF (Open Agentic Schema Framework) records.
* The **Capability Binding Registry** — an authoritative, server-side mapping of `(tool_name, action_signature) → capability_class`, registered at manifest onboarding time and consulted deterministically at Step 1A.
* The Intent Envelope — a signed artifact carried on A2A requests that references the governing manifest.
* The three-phase validation model: Step 1A (deterministic capability binding check), Step 1B (deterministic manifest scope check), Step 1C (advisory RFC-010 signal enrichment), followed by Step 2 (RFC-005 PDP query).
* PERMISSIVE and STRICT transition modes for deployments where manifests are not yet present on all agents.
* The SDK provisioning model: zero developer configuration via `CapiscIO.connect()`.
* Delegation pass-through semantics: an agent may delegate any capability it holds at 1:1 parity by default.
* Rejection codes: `CAPABILITY_BINDING_MISMATCH` (deterministic binding failure), `MANIFEST_SCOPE_VIOLATION` (manifest ceiling violation), `INTENT_CLASSIFICATION_MISMATCH` (classifier mismatch advisory), and others.

This specification is **transport-agnostic**. A normative A2A binding and a non-normative MCP binding are provided in appendices.

---

## 2. Relationship to Other RFCs

| CapiscIO RFC | Relationship to This Specification |
|---|---|
| RFC-001 (AGCP) | Defines the Golden Rule and declared intent model. RFC-009 manifests are the formal realization of declared intent at the action surface level. RFC-001 §2.2 states system originators must declare and sign intent before execution; PAMs are that signed declaration. |
| RFC-005 (Policy Enforcement) | RFC-009 Step 2 validation is a RFC-005 PDP query. Manifests provide additional PDP input attributes beyond those defined in RFC-005 alone. |
| RFC-008 (Delegated Authority Envelopes) | RFC-009 manifests operate within the authority established by RFC-008 envelopes. The manifest does not replace the envelope; it declares the specific action surface permitted within the envelope's capability class. A root envelope MUST exist before a manifest reference is valid. |
| RFC-010 (Intent Classification) | RFC-010 classifiers produce a classification verdict that the RFC-009 PEP consumes as an additional input to Step 1 validation. RFC-010 does not create a separate enforcement gate; all blocks happen at the RFC-009 PEP. |

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|---|---|
| **Action Manifest** | A signed, version-hashed artifact declaring the complete bounded action surface an agent is pre-authorized to operate within. Registered at agent onboarding time. |
| **Action Binding** | An authoritative, deterministic mapping of a specific `(tool_name, action_signature)` pair to a capability class. Registered in the Capability Binding Registry at manifest onboarding time. |
| **Action Signature** | A structured identifier for a specific invocation pattern of a tool. Consists of: the tool name, an operation discriminator (e.g., the `action` parameter value for polymorphic tools), required parameter names, and a declared side-effect class. Enables deterministic capability binding for tools with parameter-dependent behavior (e.g., `manage_user(action="delete")` versus `manage_user(action="update")`). |
| **Capability Binding Registry** | An authoritative server-side store mapping `(tool_name, action_signature) → capability_class`. Registered at agent manifest onboarding. Consulted deterministically at Step 1A. Versioned per binding schema version. Distinct from the Manifest Registry: the Capability Binding Registry stores action-level bindings; the Manifest Registry stores full manifest artifacts. |
| **Intent Envelope** | A signed artifact carried on A2A requests that references the governing Action Manifest and declares the capability class and action type of the intended operation. |
| **Manifest Hash** | The SHA-256 hash of the Action Manifest's OASF OCI content-addressed artifact. Carried on the Intent Envelope for verification. |
| **Binding Schema Version** | A monotonically incrementing version identifier for an agent's set of Action Bindings in the Capability Binding Registry. Referenced in the manifest and used for three-way consistency validation at Step 1A. |
| **Three-Way Consistency Check** | The Step 1A requirement that manifest_hash, tool_inventory_hash, and binding_schema_version all match their registered values before proceeding. Any mismatch escalates or blocks. Prevents stale-binding attacks and version drift. |
| **Manifest Registry** | The CapiscIO server-side registry where Action Manifests are registered, versioned, and retrieved by manifest hash. |
| **OASF Extension Profile** | A CapiscIO-defined extension to Open Agentic Schema Framework records that adds capability class, authority ceiling, constraint vocabulary, and action binding fields. |
| **Delegation Pass-Through** | The default behavior permitting an agent to delegate any capability it holds to a downstream agent at 1:1 parity, consistent with RFC-008 monotonic narrowing semantics where equal scope is valid. |
| **PERMISSIVE Mode** | Transition mode in which agents without an Intent Envelope are warned and logged but not blocked. |
| **STRICT Mode** | Production mode in which agents without a valid Intent Envelope referencing a registered manifest are blocked at Step 1A. |
| **CAPABILITY_BINDING_MISMATCH** | Rejection code emitted when the Capability Binding Registry lookup returns a different capability class than the one declared on the Intent Envelope. Deterministic. Not classifier-dependent. |
| **MANIFEST_SCOPE_VIOLATION** | Rejection code emitted at Step 1B when a tool call violates the manifest's declared scope: tool name not in `allowed_tools`, declared action type exceeds the `action_type_ceiling`, or declared boundary exceeds the `boundary_ceiling`. Deterministic. Not classifier-dependent. |
| **INTENT_CLASSIFICATION_MISMATCH** | Warning code emitted at Step 1C when the RFC-010 classifier verdict is inconsistent with the capability class or action type declared on the Intent Envelope. Advisory only — does not block execution. |

---

## 4. Goals and Non-Goals

### 4.1 Goals

* Define a verifiable, pre-registered artifact that declares agent action scope before execution begins.
* Provide a required A2A message artifact that downstream agents can verify without round-trips to a central authority.
* Define deterministic Step 1 enforcement that catches the most dangerous action surface violations (operation type mismatch, boundary crossing) locally without PDP overhead.
* Enable zero-friction developer onboarding: manifest provisioning is handled automatically by `CapiscIO.connect()`.
* Support incremental adoption through PERMISSIVE/STRICT transition modes.
* Define delegation pass-through semantics that do not penalize legitimate multi-agent workflows.

### 4.2 Non-Goals

* RFC-009 does not solve automated intent classification for open-ended natural language requests. That problem is addressed by RFC-010 as an advisory input layer. RFC-009 enforcement is always deterministic.
* RFC-009 does not define a general-purpose capability class vocabulary. Vocabulary is defined by the CapiscIO Capability Class Registry (separate publication). RFC-009 defines the manifest schema and enforcement model that consumes that vocabulary.
* RFC-009 does not define behavioral monitoring or dynamic trust adjustment over time. That is addressed by a future RFC.
* RFC-009 does not require enumeration of every possible tool call path for open-ended agents. It requires declaration of the capability class ceiling and action type boundaries. Individual tool call paths are validated against those ceilings, not against an exhaustive enumeration.

---

## 5. Action Manifest Schema

### 5.1 Overview

An Action Manifest is an OASF record extended with CapiscIO-specific fields. It is serialized as JSON, registered in the Manifest Registry, content-addressed via OCI/ORAS, and signed with the registering agent's Badge-bound key.

The manifest is registered once at agent onboarding. Updates require a new version with a new manifest hash. The previous version remains valid until explicitly revoked.

### 5.2 OASF Extension Profile

CapiscIO defines the following OASF record extensions under the namespace `capiscio.v1`:

```json
{
  "oasf_version": "0.3",
  "record_type": "agent.capability_manifest",
  "agent_did": "did:web:example.com:agents:invoice-processor",
  "manifest_version": "1.0.0",
  "issued_at": 1746000000,
  "expires_at": 1777536000,
  "issuer_badge_jti": "b8f2c6a5-2d6f-4e44-9f55-2a1d6d9e0f12",
  "capiscio.v1": {
    "binding_schema_version": 3,
    "capability_classes": [
      {
        "class": "finance.invoicing.management",
        "action_type_ceiling": ["Read", "Write"],
        "boundary_ceiling": "Intra-org",
        "allowed_tools": [
          "read_invoice",
          "write_invoice",
          "approve_invoice",
          "list_invoices",
          "manage_invoice"
        ],
        "denied_tools": [],
        "constraints": {
          "max_records_per_query": 500,
          "allowed_resource_patterns": ["invoices/*"]
        }
      },
      {
        "class": "finance.invoicing.admin",
        "action_type_ceiling": ["Read", "Write", "Execute"],
        "boundary_ceiling": "Intra-org",
        "allowed_tools": [
          "manage_invoice",
          "delete_invoice"
        ],
        "denied_tools": [],
        "constraints": {}
      }
    ],
    "action_bindings": [
      {
        "tool_name": "write_invoice",
        "action_signature": {
          "operation_discriminator": null,
          "required_params": ["invoice_id", "amount", "vendor_id"],
          "declared_side_effect_class": "Write"
        },
        "capability_class": "finance.invoicing.management"
      },
      {
        "tool_name": "read_invoice",
        "action_signature": {
          "operation_discriminator": null,
          "required_params": ["invoice_id"],
          "declared_side_effect_class": "Read"
        },
        "capability_class": "finance.invoicing.management"
      },
      {
        "tool_name": "manage_invoice",
        "action_signature": {
          "operation_discriminator": {"param": "action", "value": "read"},
          "required_params": ["invoice_id"],
          "declared_side_effect_class": "Read"
        },
        "capability_class": "finance.invoicing.management"
      },
      {
        "tool_name": "manage_invoice",
        "action_signature": {
          "operation_discriminator": {"param": "action", "value": "delete"},
          "required_params": ["invoice_id"],
          "declared_side_effect_class": "Write"
        },
        "capability_class": "finance.invoicing.admin"
      }
    ],
    "delegation_policy": {
      "pass_through_allowed": true,
      "max_delegatable_depth": null
    },
    "enforcement_profile": "STRICT",
    "unknown_tool_behavior": "DENY"
  },
  "skills": [
    {
      "id": "invoice-processing",
      "name": "Invoice Processing",
      "description": "Read and write operations on invoice records within the Acme finance system.",
      "tags": ["finance", "invoicing"]
    }
  ]
}
```

### 5.3 CapiscIO Extension Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `capiscio.v1.capability_classes` | array | REQUIRED | One or more capability class declarations. Each entry declares a capability class, its action type ceiling, boundary ceiling, permitted and denied tools, and opaque constraints. |
| `capiscio.v1.capability_classes[].class` | string | REQUIRED | Dot-notation capability class per RFC-008 §7.1. MUST be within the scope of the governing Authority Envelope's capability class. |
| `capiscio.v1.capability_classes[].action_type_ceiling` | array | REQUIRED | Permitted action types. Values: Read, Write, Execute, Orchestrate, Provision. All tool calls under this class MUST match a declared action type. |
| `capiscio.v1.capability_classes[].boundary_ceiling` | string | REQUIRED | Maximum trust boundary for operations under this class. Values: Local, Intra-org, External. |
| `capiscio.v1.capability_classes[].allowed_tools` | array | REQUIRED | Enumerated list of permitted tool names. An empty array means no tools are permitted under this class (unsatisfiable — treated as DENY). MUST NOT be null. |
| `capiscio.v1.capability_classes[].denied_tools` | array | OPTIONAL | Explicit tool deny list. Takes precedence over `allowed_tools`. |
| `capiscio.v1.capability_classes[].constraints` | object | OPTIONAL | Opaque constraint object interpreted by the PDP per RFC-005. MAY be empty. |
| `capiscio.v1.delegation_policy.pass_through_allowed` | boolean | REQUIRED | Whether the agent may delegate capabilities to downstream agents at 1:1 parity. Default: true. Setting false blocks all delegation from this agent. |
| `capiscio.v1.delegation_policy.max_delegatable_depth` | integer or null | OPTIONAL | Maximum delegation depth the agent may set on derived envelopes. null means no restriction beyond RFC-008 §8.4. |
| `capiscio.v1.enforcement_profile` | string | REQUIRED | Default enforcement mode for this agent's PEP. One of: PERMISSIVE, STRICT. STRICT is RECOMMENDED for production. |
| `capiscio.v1.unknown_tool_behavior` | string | REQUIRED | Behavior when a tool call's tool name is not in any `allowed_tools` list. One of: DENY (fail-closed), WARN (log and proceed — only valid in PERMISSIVE enforcement profile). |
| `capiscio.v1.binding_schema_version` | integer | REQUIRED | Monotonically incrementing version of the agent's Action Bindings in the Capability Binding Registry. Incremented whenever any `action_bindings` entry is added, modified, or removed. Used in the three-way consistency check at Step 1A. |
| `capiscio.v1.action_bindings` | array | REQUIRED | Array of Action Binding objects mapping `(tool_name, action_signature)` to a capability class. See §5.7 Capability Binding Registry. When a tool call arrives, the PEP resolves the action signature from the actual call parameters and looks up the matching binding. |
| `capiscio.v1.action_bindings[].tool_name` | string | REQUIRED | The tool name this binding applies to. |
| `capiscio.v1.action_bindings[].action_signature.operation_discriminator` | object or null | REQUIRED | If the tool uses a parameter to discriminate between distinct behaviors (e.g., `action="delete"` vs `action="read"`), specifies the parameter name and discriminating value. Null for tools with uniform behavior across all invocations. |
| `capiscio.v1.action_bindings[].action_signature.required_params` | array | REQUIRED | The parameter names that must be present for this signature to match. Used to disambiguate bindings for overloaded tools. |
| `capiscio.v1.action_bindings[].action_signature.declared_side_effect_class` | string | REQUIRED | The declared side-effect class for this action signature. One of: Read, Write, Execute, Orchestrate, Provision. Declared by the manifest author at registration time. Not inferred. Must be consistent with the `action_type_ceiling` of the bound capability class. |
| `capiscio.v1.action_bindings[].capability_class` | string | REQUIRED | The capability class this action signature maps to. MUST be present in `capiscio.v1.capability_classes`. |

### 5.4 Empty Allowlist Principle

An `allowed_tools` array that is empty MUST be treated as unsatisfiable, not unrestricted. A manifest entry with an empty `allowed_tools` is equivalent to DENY for all tools under that capability class. This prevents misconfiguration from silently granting broad access.

A `denied_tools` array that is empty means no tools are explicitly denied. This is the normal case for most capability classes. The `denied_tools` field is an explicit deny list that takes precedence over `allowed_tools` — it is not subject to the Empty Allowlist Principle.

### 5.5 Manifest Signature

The manifest MUST be signed by the registering agent's Badge-bound key using the same JWS Compact Serialization format as RFC-008 Authority Envelopes. The signature covers the canonical UTF-8 JSON serialization of the manifest object (excluding whitespace).

```
<base64url(header)>.<base64url(manifest_payload)>.<base64url(signature)>
```

Header:
```json
{
  "alg": "EdDSA",
  "typ": "capiscio-action-manifest+jws",
  "kid": "did:web:example.com:agents:invoice-processor#key-1"
}
```

### 5.6 Manifest Hash Computation

The manifest hash is computed as:

```
manifest_hash = lowercase(hex(SHA-256(JWS_Compact_Serialization_bytes)))
```

This hash is the stable reference carried on Intent Envelopes. A manifest update produces a new hash and requires re-registration.

### 5.7 Capability Binding Registry

#### 5.7.1 Purpose

The Capability Binding Registry is the authoritative server-side store for Action Bindings. It holds the deterministic mapping of `(tool_name, action_signature) → capability_class` for every registered agent. It is the primary enforcement input for Step 1A (§7.2).

The registry closes the parameter-escalation attack vector: without it, an agent could use the same tool name with different parameters to escalate from one capability class to another. By binding at the action-signature level — not just the tool-name level — the registry ensures that `manage_user(action="delete")` and `manage_user(action="update")` map to distinct, explicitly registered capability classes. No parameter combination can produce a class escalation not declared at registration time.

#### 5.7.2 Action Binding Schema

Each Action Binding in the registry conforms to the following structure:

```json
{
  "agent_did": "did:web:example.com:agents:invoice-processor",
  "binding_schema_version": 3,
  "tool_name": "manage_invoice",
  "action_signature": {
    "operation_discriminator": {
      "param": "action",
      "value": "delete"
    },
    "required_params": ["invoice_id"],
    "declared_side_effect_class": "Write"
  },
  "capability_class": "finance.invoicing.admin",
  "registered_at": 1746000000,
  "registered_by_badge_jti": "b8f2c6a5-2d6f-4e44-9f55-2a1d6d9e0f12"
}
```

#### 5.7.3 Action Signature Resolution

When a tool call arrives at the PEP, the PEP MUST resolve the action signature before performing the registry lookup. Resolution algorithm:

1. Extract `tool_name` from the tool call.
2. Fetch all registered bindings for this `agent_did` and `tool_name` from local cache or registry.
3. If `operation_discriminator` is non-null for any binding, examine the tool call parameters for the specified `param`. If the `param` is present and its value matches a binding's `value`, select that binding. If multiple operation discriminators match, select the most specific (longest matching param path).
4. If `operation_discriminator` is null for a binding, it is the default binding for that tool name. Use it when no discriminator-based match is found.
5. If no binding matches: `CAPABILITY_BINDING_MISMATCH` with unregistered signature path. DENY in STRICT mode.
6. If the resolved binding's `capability_class` does not match the `capability_class` declared on the Intent Envelope: `CAPABILITY_BINDING_MISMATCH`. DENY regardless of mode.

**Parameter Matching Semantics.** When resolving an action signature, the PEP MUST use superset matching on tool call parameters:

* All parameters declared in the binding's `operation_discriminator` MUST be present in the tool call with matching values. Missing required discriminator parameters are a mismatch.
* Tool call parameters not referenced by any `operation_discriminator` are tolerated — their presence does not cause a mismatch. However, PEPs SHOULD log undeclared parameters as an `UNDECLARED_PARAMS` audit event to support binding completeness analysis.
* This ensures that bindings remain forward-compatible as tool schemas evolve (new optional parameters do not break existing bindings), while discriminator-specified parameters are strictly enforced.

#### 5.7.4 Registry API

| Endpoint | Method | Description |
|---|---|---|
| `/v1/bindings/agents/{did}` | POST | Register or update the full binding set for an agent. Atomically replaces the previous version and increments `binding_schema_version`. |
| `/v1/bindings/agents/{did}/version` | GET | Returns the current `binding_schema_version` and binding set hash for consistency validation. |
| `/v1/bindings/agents/{did}/lookup` | GET | Resolve a `(tool_name, params_json)` pair to a capability class. Used for PEP cache warming. |
| `/v1/bindings/agents/{did}/revoke` | POST | Revoke all bindings for an agent. Requires Badge auth with PoP proof. |

All registry responses MUST be signed by the CapiscIO server. PEPs MUST verify the server signature before caching binding data.

#### 5.7.5 Three-Way Consistency Check

At Step 1A, the PEP MUST verify three-way consistency before performing any binding lookup:

1. **Manifest hash match.** The `manifest_hash` on the Intent Envelope MUST match the hash of the manifest retrieved from the Manifest Registry for this agent.
2. **Tool inventory hash match (conditional).** When RFC-010 is active: the tool inventory hash recorded at session init (RFC-010 `tool_inventory_hash`) MUST match the hash of the tool set declared in the current manifest's `allowed_tools` aggregate. When RFC-010 is not active, this check is SKIPPED.
3. **Binding schema version match.** The `binding_schema_version` embedded in the retrieved manifest MUST match the `binding_schema_version` returned by the Capability Binding Registry for this agent.

If any of the applicable checks fail, the PEP MUST NOT proceed to binding lookup. Behavior:

| Failure condition | STRICT mode | PERMISSIVE mode |
|---|---|---|
| Manifest hash mismatch | DENY + `MANIFEST_VERSION_MISMATCH` | WARN + log + escalate |
| Tool inventory hash mismatch (RFC-010 active only) | DENY + `MANIFEST_VERSION_MISMATCH` | WARN + log + escalate |
| Binding schema version mismatch | DENY + `CAPABILITY_BINDING_MISMATCH` | WARN + log + escalate |

This prevents stale-binding attacks where a tool is re-registered under a new signature but an old manifest still references the previous binding version.

#### 5.7.6 OASF Relationship

The Capability Binding Registry is designed as an OASF Attachable Object under the `capiscio.v1.bindings` extension namespace. This follows the OASF community extension model (OASF Discussion #314) for dynamic associations that provide additional functionality beyond the core agent record. Implementing CapiscIO registries SHOULD publish Action Binding sets as OASF attachable objects alongside the agent's OASF record to enable cross-platform capability discovery.

Integration with the MCP Registry (registry.modelcontextprotocol.io) for initial tool discovery during registration is non-normative but RECOMMENDED. When a developer registers an MCP server with CapiscIO, the SDK MAY query the MCP Registry for the server's tool list to pre-populate the `action_bindings` template before the developer declares side-effect classes and operation discriminators.

---

## 6. Intent Envelope

### 6.1 Purpose

The Intent Envelope is a signed artifact that an agent (the requestor) supplies on every A2A request. It declares:

1. Which Action Manifest governs this request (by manifest hash).
2. Which capability class the requestor claims for this operation.
3. Which action type the requestor declares for this operation.
4. The delegation chain reference linking this request to its RFC-008 Authority Envelope.

The receiving agent's RFC-009 PEP uses the Intent Envelope to perform Step 1 validation before any PDP query.

### 6.2 Intent Envelope Schema

```json
{
  "envelope_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "manifest_hash": "a1b2c3d4e5f6...",
  "capability_class": "finance.invoicing.management",
  "declared_action_type": "Write",
  "declared_boundary": "Intra-org",
  "authority_envelope_hash": "e5f6a7b8c9d0...",
  "txn_id": "018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11",
  "tool_name": "write_invoice",
  "prompt_summary": "Process approved invoice INV-2024-0042 for vendor Acme Supplies",
  "issued_at": 1746000123,
  "expires_at": 1746000423,
  "issuer_did": "did:web:taxco.example:agents:taxbot",
  "issuer_badge_jti": "c9a3d7b6-3e7g-5f55-0g66-3b2e7e1f1g23"
}
```

### 6.3 Intent Envelope Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `envelope_id` | string | REQUIRED | UUID for this Intent Envelope. Used for audit correlation. |
| `manifest_hash` | string | REQUIRED | SHA-256 hash of the requestor's registered Action Manifest JWS. The receiving PEP retrieves and caches the manifest by this hash. |
| `capability_class` | string | REQUIRED | The capability class the requestor claims for this operation. MUST be present in the referenced manifest. |
| `declared_action_type` | string | REQUIRED | The action type the requestor declares for this tool call. One of: Read, Write, Execute, Orchestrate, Provision. MUST be within the `action_type_ceiling` for the declared `capability_class` in the manifest. |
| `declared_boundary` | string | REQUIRED | The trust boundary within which this operation is declared to execute. One of: Local, Intra-org, External. MUST not exceed the `boundary_ceiling` for the declared `capability_class` in the manifest. |
| `authority_envelope_hash` | string | REQUIRED | SHA-256 hash of the governing RFC-008 Authority Envelope JWS. Links the Intent Envelope to the delegation chain. |
| `txn_id` | string | REQUIRED | Transaction identifier per RFC-004. Links this request to the full hop chain for audit reconstruction. |
| `tool_name` | string | REQUIRED | The exact tool name being invoked. MUST be present in the `allowed_tools` for the declared `capability_class` in the manifest. |
| `prompt_summary` | string \| null | OPTIONAL | A human-readable, selectively disclosable summary of the user or system intent that originated this request. Preserved for audit and forensic reconstruction. Not enforced cryptographically. MUST NOT be used for authorization decisions. RECOMMENDED for all requests originating from a human interaction. |
| `issued_at` | integer | REQUIRED | Unix timestamp of Intent Envelope creation. |
| `expires_at` | integer | REQUIRED | Unix timestamp after which this Intent Envelope MUST be rejected. RECOMMENDED: 300 seconds (5 minutes) for most deployments. |
| `issuer_did` | string | REQUIRED | DID of the agent issuing this Intent Envelope (the requestor). |
| `issuer_badge_jti` | string | REQUIRED | The `jti` of the issuer's current Trust Badge. Binds the Intent Envelope to a specific badge session per RFC-002. |

### 6.4 Intent Envelope Signature

The Intent Envelope MUST be signed by the requestor's Badge-bound key:

```
<base64url(header)>.<base64url(intent_envelope_payload)>.<base64url(signature)>
```

Header:
```json
{
  "alg": "EdDSA",
  "typ": "capiscio-intent-envelope+jws",
  "kid": "did:web:taxco.example:agents:taxbot#key-1"
}
```

---

## 7. Three-Phase Validation Model

### 7.1 Overview

RFC-009 validation is a strict sequence of three phases within Step 1, followed by Step 2. Failure at any phase MUST prevent all subsequent phases from executing. All three Step 1 phases must pass before Step 2 executes.

The three phases are explicitly named and sequenced to prevent mental collapse of distinct enforcement concerns:

```
Incoming Tool Call + Intent Envelope
        │
        ▼
┌─────────────────────────────────────────┐
│ STEP 1A: Capability Binding Validation  │
│ (Deterministic. Capability Binding      │
│  Registry lookup. No PDP.)              │
│                                         │
│ a. Intent Envelope present?             │
│ b. Signature + expiry valid?            │
│ c. Three-way consistency check:         │
│    - manifest_hash matches registry?    │
│    - tool_inventory_hash matches?       │
│    - binding_schema_version matches?    │
│ d. Action signature resolved?           │
│ e. Registry binding → declared class?  │
│                                         │
│ PASS → Step 1B                         │
│ FAIL → CAPABILITY_BINDING_MISMATCH     │
│        or MANIFEST_VERSION_MISMATCH    │
│        (DENY, do not continue)          │
└─────────────────────────────────────────┘
        │
        ▼ (on PASS)
┌─────────────────────────────────────────┐
│ STEP 1B: Manifest Scope Check           │
│ (Deterministic. Local manifest check.   │
│  No PDP.)                               │
│                                         │
│ f. tool_name in allowed_tools for class?│
│ g. declared_action_type within ceiling? │
│ h. declared_boundary within ceiling?    │
│                                         │
│ PASS → Step 1C                         │
│ FAIL → MANIFEST_SCOPE_VIOLATION         │
│        (DENY, do not continue)          │
└─────────────────────────────────────────┘
        │
        ▼ (on PASS)
┌─────────────────────────────────────────┐
│ STEP 1C: RFC-010 Signal Enrichment      │
│ (Advisory. Non-blocking by default.     │
│  Classifier output only.)               │
│                                         │
│ i. RFC-010 active and verdict present?  │
│ j. Composite confidence ≥ threshold?    │
│ k. Classifier class consistent with     │
│    declared class?                      │
│                                         │
│ Consistent or inactive → Step 2        │
│ Inconsistent → log INTENT_CLASSIF-     │
│   ICATION_MISMATCH warning, escalate   │
│   if confidence below threshold        │
│                                         │
│ NOTE: Step 1C MUST NOT block execution  │
│ solely on classifier output. It MAY     │
│ escalate. It MUST NOT DENY.             │
└─────────────────────────────────────────┘
        │
        ▼ (on PASS through all Step 1 phases)
┌─────────────────────────────────────────┐
│ STEP 2: PDP Authorization Query         │
│ (RFC-005, existing path)                │
│                                         │
│ PIP projection includes:                │
│ - agent identity (RFC-002 badge)        │
│ - capability_class                      │
│ - declared_action_type                  │
│ - declared_boundary                     │
│ - manifest_hash                         │
│ - tool_name                             │
│ - intent_envelope_hash                  │
│ - RFC-008 authority envelope claims     │
│ - classification.* (RFC-010, advisory)  │
│                                         │
│ ALLOW → execute tool call               │
│ DENY  → SCOPE_INSUFFICIENT              │
└─────────────────────────────────────────┘
```

### 7.2 Step 1A: Capability Binding Validation (Deterministic)

Step 1A is the authoritative, deterministic check that the tool call's action signature maps to the declared capability class via the Capability Binding Registry. It does not contact the PDP. It is not probabilistic. A mismatch at Step 1A is a hard security boundary, not an advisory signal.

**Step 1A sequence (in order, fail-closed at each sub-step):**

1. **Intent Envelope presence.** If no Intent Envelope is present, behavior is governed by the active enforcement mode (§8). In STRICT mode, DENY immediately with `SCOPE_INSUFFICIENT`. In PERMISSIVE mode, log warning and proceed directly to Step 2 without any Step 1 checks.

2. **Signature verification.** Verify the Intent Envelope JWS signature against the issuer's Badge-bound key per RFC-002 and RFC-003. MUST reject `alg: "none"`. On failure: `INTENT_ENVELOPE_INVALID`.

3. **Expiry check.** `expires_at` MUST be in the future. On failure: `INTENT_ENVELOPE_EXPIRED`.

4. **Manifest retrieval.** Retrieve the Action Manifest by `manifest_hash` from local cache or Manifest Registry. On failure: `MANIFEST_NOT_FOUND`. Cache manifests with TTL aligned to manifest `expires_at`.

5. **Three-way consistency check.** Per §5.7.5, verify:
   * The retrieved manifest's hash matches the `manifest_hash` on the Intent Envelope.
   * If RFC-010 is active, the tool inventory hash recorded at session init matches the hash of the manifest's declared tool surface.
   * The `binding_schema_version` in the retrieved manifest matches the version returned by the Capability Binding Registry for this agent.
   * On any mismatch: `MANIFEST_VERSION_MISMATCH` (manifest or inventory) or `CAPABILITY_BINDING_MISMATCH` (binding version). DENY in STRICT mode; escalate in PERMISSIVE.

6. **Action signature resolution.** Extract the tool name and relevant parameters from the tool call. Apply the resolution algorithm in §5.7.3 to identify the matching Action Binding in the Capability Binding Registry. If no binding matches the resolved signature: `CAPABILITY_BINDING_MISMATCH` (unregistered signature path).

7. **Binding class check.** The `capability_class` returned by the Capability Binding Registry lookup MUST exactly match the `capability_class` declared on the Intent Envelope. If they differ: `CAPABILITY_BINDING_MISMATCH`. This check is deterministic. It is not influenced by RFC-010 classifier output.

### 7.3 Step 1B: Manifest Scope Check (Deterministic)

Step 1B validates that the declared action is within the capability class boundaries declared in the manifest. It uses the manifest retrieved in Step 1A. No additional network calls are required.

**Step 1B sequence (in order, fail-closed at each sub-step):**

8. **Tool authorization.** Verify `tool_name` is present in `allowed_tools` for the declared `capability_class` in the retrieved manifest. If not present: `MANIFEST_SCOPE_VIOLATION` with `rejected_tool` and `presented_class` fields.

9. **Action type check.** Verify `declared_action_type` is within the `action_type_ceiling` for the declared `capability_class`. If the action type exceeds the ceiling: `MANIFEST_SCOPE_VIOLATION`.

10. **Boundary check.** Verify `declared_boundary` does not exceed the `boundary_ceiling` for the declared `capability_class`. If the boundary exceeds the ceiling: `MANIFEST_SCOPE_VIOLATION`.

### 7.4 Step 1C: RFC-010 Signal Enrichment (Advisory)

Step 1C receives the RFC-010 classifier verdict if RFC-010 is active. It is advisory. It MUST NOT block execution solely on classifier output.

**Step 1C is governed by the following invariant:**

> Step 1C may escalate. Step 1C MUST NOT DENY.

Decisions to DENY are made at Step 1A and Step 1B (deterministic) or Step 2 (PDP). Step 1C routes anomalous signals to the escalation handler and logs mismatch events. It does not add a third enforcement gate.

**Step 1C sequence:**

11. **RFC-010 verdict availability.** If RFC-010 is not active or the classifier timed out, skip to Step 2.

12. **Confidence threshold check.** If the composite confidence score is below the configured threshold (default: 0.7): route to escalation handler (§9). Do not block. Do not proceed silently — escalation is required.

13. **Classifier class consistency.** If the RFC-010 classified capability class differs from the declared capability class: log `INTENT_CLASSIFICATION_MISMATCH` warning event with `rfc010_verdict_class` and `declared_class` fields. Route to escalation handler. Do not block.

**Note:** An `INTENT_CLASSIFICATION_MISMATCH` event emitted at Step 1C is a warning event, not a block event. It is correlated to the `capiscio.policy_enforced` event by `txn_id` for forensic analysis and feeds the RFC-010 Policy Recommendation Engine. A pattern of persistent Step 1C mismatches for a given agent is the signal for a server-side manifest refinement recommendation.

### 7.5 Rejection Code Summary

| Code | Phase | Type | Condition |
|---|---|---|---|
| `CAPABILITY_BINDING_MISMATCH` | Step 1A | Deterministic DENY | Registry binding maps tool+signature to a different class than declared; unregistered signature; binding_schema_version mismatch. |
| `MANIFEST_VERSION_MISMATCH` | Step 1A | Deterministic DENY or escalate | manifest_hash or tool_inventory_hash inconsistency detected during three-way check. |
| `INTENT_ENVELOPE_INVALID` | Step 1A | Deterministic DENY | Signature verification failed or required fields missing. |
| `INTENT_ENVELOPE_EXPIRED` | Step 1A | Deterministic DENY | Intent Envelope `expires_at` is in the past. |
| `MANIFEST_NOT_FOUND` | Step 1A | Deterministic DENY | manifest_hash references an unregistered or revoked manifest. |
| `MANIFEST_SCOPE_VIOLATION` | Step 1B | Deterministic DENY | Tool name not in `allowed_tools` for the declared capability class; `declared_action_type` exceeds `action_type_ceiling`; `declared_boundary` exceeds `boundary_ceiling`. |
| `INTENT_CLASSIFICATION_MISMATCH` | Step 1C | Warning + escalate (MUST NOT DENY) | RFC-010 classifier verdict inconsistent with declared class. Advisory only — routes to escalation handler. |
| `SCOPE_INSUFFICIENT` | Step 1A (STRICT, no envelope) or Step 2 | DENY | Intent Envelope absent in STRICT mode; or PDP returned DENY at Step 2. |
| `CLASSIFIER_SOLE_DENY_VIOLATION` | Step 2 (PDP monitoring) | Warning | PDP deny based exclusively on `classification.*` fields with no deterministic corroboration. Logged; decision re-evaluated without classifier fields. |

### 7.6 Step 2: PDP Authorization Query

Step 2 is the existing RFC-005 PDP query path, extended with RFC-009 attribute projections.

The PIP projection for RFC-009 requests MUST include the following additional fields beyond those defined in RFC-005:

```json
{
  "intent": {
    "manifest_hash": "<hash>",
    "binding_schema_version": 3,
    "capability_class": "finance.invoicing.management",
    "declared_action_type": "Write",
    "declared_side_effect_class": "Write",
    "declared_boundary": "Intra-org",
    "tool_name": "write_invoice",
    "intent_envelope_hash": "<hash of intent envelope JWS>",
    "prompt_summary": "<if present, selectively disclosed>"
  }
}
```

The PDP MAY use these fields for fine-grained policy decisions. Existing RFC-005 policies that do not reference `intent.*` fields are unaffected. The `classification.*` fields from RFC-005 §5.1 (RFC-010 classifier output) are projected separately and are subject to the normative constraint in RFC-005 §5.1: they MUST NOT be the sole basis for a DENY decision.

---

## 8. Enforcement Modes

### 8.1 PERMISSIVE Mode

PERMISSIVE mode is intended for development environments and incremental rollout where not all agents in a deployment have been updated to supply Intent Envelopes.

In PERMISSIVE mode:
* Agents without an Intent Envelope are NOT blocked. A warning event is emitted.
* Agents with an Intent Envelope undergo full Step 1 validation.
* Agents with an Intent Envelope referencing an unregistered manifest are logged and warned but NOT blocked.

PERMISSIVE mode MUST NOT be used in production environments where enforcement guarantees are required.

### 8.2 STRICT Mode

STRICT mode is the production-default and RECOMMENDED mode.

In STRICT mode:
* Agents without an Intent Envelope are DENIED immediately. `SCOPE_INSUFFICIENT` is emitted.
* Agents with an invalid Intent Envelope (expired, bad signature, missing fields) are DENIED.
* Agents with an Intent Envelope referencing an unregistered manifest are DENIED with `MANIFEST_NOT_FOUND`.
* All Step 1 checks are enforced fail-closed.

### 8.3 Mode Configuration

Enforcement mode is configured at the PEP level, not in policy YAML. This is consistent with RFC-008's `enforcement_mode` placement on `EvaluateToolAccessRequest`. The `@guard` decorator accepts an `intent_enforcement_mode` parameter:

```python
@guard(
    config="policy.yaml",
    capability_class="finance.invoicing.management",
    intent_enforcement_mode="strict"   # or "permissive"
)
async def write_invoice(ctx, params):
    ...
```

Default: `"strict"` in production SDK builds.

---

## 9. Escalation Protocol

### 9.1 Escalation Triggers

The following conditions trigger escalation rather than immediate block or allow:

* **Low RFC-010 confidence.** When RFC-010 is active and the classifier confidence for any REQUIRED axis is below the configured threshold (default: 0.7), the PEP SHOULD pause execution and route to the escalation handler rather than proceeding or blocking.
* **Declared action type is Irreversible.** When the `declared_action_type` maps to an inherently irreversible operation (Delete, bulk mutation, Provision) and `boundary_ceiling` is External, a human gate escalation is RECOMMENDED regardless of confidence.
* **Manifest version mismatch.** If the manifest referenced by the Intent Envelope has been superseded by a newer version, the PEP SHOULD warn and continue (not block), but MUST log the version delta.

### 9.2 Escalation Handler Interface

Escalation is routed to a registered `EscalationHandler`. The SDK provides a no-op default that logs and blocks. Operators MAY register custom handlers:

```python
guard = CapiscIO.connect(
    config="policy.yaml",
    escalation_handler=MyHumanApprovalHandler()
)
```

The escalation handler receives:
* The Intent Envelope
* The triggering condition (low confidence, irreversible action, etc.)
* The RFC-010 classification verdict (if available)
* The pending tool call parameters

The handler MUST return ALLOW or DENY within the configured timeout (default: 30 seconds). If the handler times out, the PEP MUST DENY (fail-closed).

---

## 10. Delegation Pass-Through Semantics

### 10.1 Default Pass-Through

By default (`delegation_policy.pass_through_allowed: true`), an agent MAY delegate any capability class it holds to a downstream agent at 1:1 parity. This is consistent with RFC-008 §8.2, which defines equal capability class as a valid narrowing (subset-or-equal).

Delegation at 1:1 parity is not an expansion of scope and MUST NOT be treated as a policy violation. Restricting pass-through is an optional operator policy choice, not a default security requirement.

### 10.2 Optional Restriction

Operators who require that agents delegate only a narrower subset of their capability classes MAY configure per-class delegation restrictions in the manifest:

```json
{
  "capiscio.v1": {
    "capability_classes": [
      {
        "class": "finance.invoicing.management",
        "action_type_ceiling": ["Read", "Write"],
        "boundary_ceiling": "Intra-org",
        "allowed_tools": [...],
        "delegatable_action_types": ["Read"]
      }
    ]
  }
}
```

The optional `delegatable_action_types` field restricts which action type sub-ceiling the agent may pass to a downstream agent. This is evaluated by the PDP as an optional policy constraint, not a PEP structural check. When absent, the full `action_type_ceiling` is delegatable.

### 10.3 Delegation Validation at Issuance

When an agent creates a derived RFC-008 Authority Envelope for a downstream agent, the RFC-008 PEP MUST verify that `delegation_policy.pass_through_allowed` is true on the delegating agent's manifest before permitting derived envelope creation. If `pass_through_allowed` is false, all delegation attempts MUST fail with `SCOPE_INSUFFICIENT`.

---

## 11. SDK Provisioning: Zero Developer Friction

### 11.1 Automatic Manifest Management

Action Manifest creation, registration, and versioning are handled automatically by `CapiscIO.connect()`. Developers do not create, sign, or register manifests manually.

At `CapiscIO.connect()` time, the SDK:

1. Inspects all `@guard`-decorated functions in the connected agent to enumerate the tool surface (tool names, declared capability classes, action types).
2. Constructs an Action Manifest reflecting the declared surface.
3. Compares the candidate manifest to the last registered manifest by content hash.
4. If changed, signs and registers the new manifest with the Manifest Registry.
5. Returns the current `manifest_hash` for inclusion in outbound Intent Envelopes.
6. Caches the manifest locally for Step 1 validation of inbound requests.

This provisioning happens once per session initialization. Developers interact only with `@guard` decorators; manifest management is invisible.

### 11.2 Manifest Versioning

Manifests are immutable after registration. Any change to the declared tool surface (adding a tool, changing a capability class, updating a boundary ceiling) results in a new manifest version with a new hash. Old versions remain retrievable for audit purposes and are not automatically revoked.

The Manifest Registry MUST maintain a version chain: each manifest version records the hash of its predecessor.

### 11.3 Intent Envelope Construction

Outbound Intent Envelopes are constructed automatically by the SDK at tool dispatch time. The developer does not construct envelopes manually.

```python
# Developer code — unchanged from current usage
@guard(
    config="policy.yaml",
    capability_class="finance.invoicing.management"
)
async def write_invoice(ctx, params):
    # SDK intercepts the tool call, constructs and attaches
    # the Intent Envelope automatically before dispatch
    ...
```

The SDK resolves `declared_action_type` from the tool's `@guard` metadata and the manifest's `action_type_ceiling`. Where a tool can perform multiple action types (e.g., a tool that reads and writes depending on parameters), the SDK uses the highest applicable action type from the ceiling.

---

## 12. A2A Protocol Binding (Normative)

### 12.1 Intent Envelope as Required A2A Field

In A2A protocol messages governed by RFC-009, the Intent Envelope MUST be present in the `_meta` extension field of the JSON-RPC request:

```json
{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": { "...": "..." },
  "_meta": {
    "capiscio_txn": "<txn_id>",
    "capiscio_hop": "<hop_attestation_jws>",
    "capiscio_intent": "<intent_envelope_jws>"
  }
}
```

The `capiscio_intent` field carries the JWS Compact Serialization of the Intent Envelope.

### 12.2 Receiving Agent Obligations

A receiving agent operating under RFC-009 MUST:

1. Extract the Intent Envelope from `_meta.capiscio_intent`.
2. Execute Step 1 validation before processing the request payload.
3. Execute Step 2 PDP query on Step 1 pass.
4. Return structured rejection responses on failure per §7.3.

### 12.3 Rejection Response Format

```json
{
  "code": "MANIFEST_SCOPE_VIOLATION",
  "declared_class": "finance.invoicing.management",
  "declared_action_type": "Read",
  "rejected_tool": "delete_invoice",
  "manifest_hash": "a1b2c3d4...",
  "intent_envelope_id": "b2c3d4e5...",
  "txn_id": "018f4e1d..."
}
```

---

## 13. Manifest Registry

### 13.1 Registry Operations

| Operation | Description |
|---|---|
| `POST /v1/manifests` | Register a new manifest version. Requires agent Badge auth. Returns `manifest_hash`. |
| `GET /v1/manifests/{hash}` | Retrieve a manifest by hash. Returns the full manifest JWS. |
| `GET /v1/manifests/agent/{did}/current` | Retrieve the current active manifest for an agent DID. |
| `GET /v1/manifests/agent/{did}/versions` | Retrieve the full version chain for an agent DID. |
| `POST /v1/manifests/{hash}/revoke` | Revoke a specific manifest version. Requires agent Badge auth with PoP proof. |

### 13.2 Registry Outage Behavior

PEPs SHOULD cache manifests locally by `manifest_hash` with TTL aligned to the manifest's `expires_at` field. When the Registry is unreachable:

* Requests referencing a cached manifest: proceed normally.
* Requests referencing an uncached manifest: behavior governed by enforcement mode. STRICT: DENY. PERMISSIVE: warn and proceed.

---

## 14. Security Considerations

| Threat | Mitigation |
|---|---|
| Manifest forgery | JWS signature verification against Badge-bound key (RFC-002, RFC-003). Manifest hash on Intent Envelope detects substitution. |
| Tool name spoofing | `tool_name` on Intent Envelope is verified against `allowed_tools` in the retrieved manifest. Manifest is retrieved by cryptographic hash, not by agent-supplied metadata. |
| Parameter-based capability escalation | An agent invoking `manage_user(action="delete")` when only `manage_user(action="read")` is authorized. Mitigated by action-signature-level binding in the Capability Binding Registry (§5.7). The registry maps `(tool_name, operation_discriminator, params)` → class. A parameter value that escalates behavior maps to a different (higher) class and is blocked by the Step 1A binding check. Tool-name-only enforcement would not catch this. |
| Stale binding attack | A tool re-registers under a new action signature but an old manifest still references the previous binding version. The three-way consistency check at Step 1A detects `binding_schema_version` mismatch and denies or escalates before any binding lookup is performed. |
| Tool inventory drift | Tool surface changes between session init and enforcement time. Detected by tool_inventory_hash mismatch in the three-way consistency check. The hash is computed at `CapiscIO.connect()` time and compared at each Step 1A execution. |
| Stale manifest reference | Manifest version chain allows operators to revoke old versions. Short Intent Envelope TTL (default 300s) limits exposure window. Three-way consistency check detects manifest_hash mismatch. |
| Intent Envelope replay | `intent_envelope_id` uniqueness enforced within `txn_id` scope. `expires_at` limits replay window. |
| Pass-through exploitation | `delegation_policy.pass_through_allowed` is per-manifest, operator-controlled. RFC-008 monotonic narrowing prevents scope expansion regardless. |
| Classifier output misuse as policy condition | Policy authors may write DENY rules based solely on `classification.*` fields. Mitigated by the normative constraint in RFC-005 §5.1 and the `CLASSIFIER_SOLE_DENY_VIOLATION` detection mechanism. The dashboard policy editor MUST display a warning when any `classification.*` field is the sole condition in a DENY rule. Classifier output enriches enforcement; it does not authorize enforcement decisions. |
| Classifier manipulation to bypass Step 1C | An adversary crafts action descriptors or tool metadata to bias classifier output toward a safe classification while the actual action is harmful. Step 1C does not block — it escalates. The deterministic blocks at Step 1A and Step 1B are not influenced by classifier output. A classifier that is fully compromised cannot bypass Step 1A or Step 1B. |
| Version consistency state inconsistency | The three-way check requires live access to the Manifest Registry and Capability Binding Registry for version confirmation. Registry unavailability degrades to cached values. The PEP MUST NOT proceed without at least a cached version match. If no cached version data is available and the registry is unreachable, STRICT mode denies. |
| Registry SSRF | Manifest retrieval MUST apply the same SSRF protections defined in RFC-002 §7.3.7 for any network calls to the Manifest Registry. |
| Prompt summary manipulation | `prompt_summary` is informational only and is never used for authorization decisions. It is preserved for audit. PEPs MUST NOT base enforcement decisions on `prompt_summary` content. |

---

## 15. Future Work

* **Capability Class Registry.** A standardized, publicly maintained registry of typed capability class definitions with formal `action_type_ceiling`, `boundary_ceiling`, and `allowed_tools` profiles. Enables cross-organizational interoperability without custom vocabulary negotiation.
* **Manifest Composition.** Rules for merging manifests from multiple registries or principals when an agent acts under authority from multiple sources simultaneously.
* **Structured Constraint Vocabulary.** Typed constraint types beyond the opaque constraints object, aligned with the Mastercard Verifiable Intent constraint registry pattern. Enables deterministic PDP evaluation without per-deployment policy interpretation.
* **RFC-010 Integration Tightening.** As RFC-010 classifier confidence improves empirically, future revisions may allow high-confidence RFC-010 verdicts to partially substitute for declared capability class in Step 1, reducing manifest enumeration burden for open-ended agents.

---

## Appendix A: MCP Transport Binding (Non-Normative)

For MCP tool calls, the Intent Envelope SHOULD be carried in the `_meta` field of the JSON-RPC `tools/call` request:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "write_invoice",
    "arguments": { "...": "..." }
  },
  "_meta": {
    "capiscio_txn": "<txn_id>",
    "capiscio_hop": "<hop_attestation_jws>",
    "capiscio_intent": "<intent_envelope_jws>"
  }
}
```

The `capiscio-mcp` package handles this automatically when `CapiscIO.connect()` is initialized.

---

## Appendix B: Glossary of Rejection Codes

| Code | Phase | Type | Description |
|---|---|---|---|
| `CAPABILITY_BINDING_MISMATCH` | Step 1A | Deterministic DENY | The Capability Binding Registry maps the resolved action signature to a different capability class than declared on the Intent Envelope; or the action signature has no registered binding; or the binding_schema_version in the manifest does not match the registry. This is a hard security boundary. Not classifier-dependent. |
| `MANIFEST_VERSION_MISMATCH` | Step 1A | Deterministic DENY (STRICT) or escalate (PERMISSIVE) | The three-way consistency check detected a mismatch: manifest_hash on the Intent Envelope does not match the retrieved manifest; or tool_inventory_hash does not match the current manifest tool surface. |
| `MANIFEST_NOT_FOUND` | Step 1A | Deterministic DENY | manifest_hash references an unregistered or revoked manifest. |
| `INTENT_ENVELOPE_EXPIRED` | Step 1A | Deterministic DENY | Intent Envelope `expires_at` is in the past. |
| `INTENT_ENVELOPE_INVALID` | Step 1A | Deterministic DENY | JWS signature verification failed, or required fields are missing or malformed. |
| `MANIFEST_SCOPE_VIOLATION` | Step 1B | Deterministic DENY | tool_name not in `allowed_tools`; `declared_action_type` exceeds `action_type_ceiling`; `declared_boundary` exceeds `boundary_ceiling`. This is the deterministic manifest scope enforcement gate. |
| `INTENT_CLASSIFICATION_MISMATCH` | Step 1C | Warning event + escalate (MUST NOT DENY) | RFC-010 classifier verdict identifies a higher-risk class or action type than declared. Routes to the escalation handler and logs a warning event correlated to the `capiscio.policy_enforced` event by `txn_id`. Advisory only. |
| `SCOPE_INSUFFICIENT` | Step 1A (no envelope, STRICT mode) or Step 2 | DENY | Intent Envelope absent in STRICT mode; or RFC-005 PDP returned DENY at Step 2. |
| `CLASSIFIER_SOLE_DENY_VIOLATION` | Step 2 monitoring | Warning only | PDP deny decision based exclusively on `classification.*` fields with no corroborating deterministic attribute. The PEP logs this warning and re-evaluates the PDP decision without classifier fields. If the re-evaluated decision is ALLOW, the deny is overridden and the violation is reported to the server-side Policy Recommendation Engine. |

---

## Changelog

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-04-30 | Initial published version. Defines the Pre-Authorized Action Manifest format, Capability Binding Registry, Intent Envelope, three-phase validation model, PERMISSIVE/STRICT enforcement modes, delegation pass-through semantics, SDK provisioning model, A2A and MCP transport bindings, and Manifest Registry operations. |
