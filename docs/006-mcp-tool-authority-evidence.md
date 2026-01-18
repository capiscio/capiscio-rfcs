# RFC-006: MCP Tool Authority and Evidence

**Version:** 0.3
**Status:** Draft
**Authors:** CapiscIO Core Team
**Created:** 2026-01-14
**Updated:** 2026-01-14
**Requires:** RFC-002 (Trust Badge Specification)
**Related:** RFC-005 (PDEP)

---

## 1. Abstract

This RFC defines how CapiscIO cryptographic identity and authority primitives are applied to **individual MCP tool invocations**.

It specifies a deterministic mechanism by which:

* an agent’s identity is verified at runtime,
* authorization is enforced prior to tool execution, and
* a tamper-evident evidence record is emitted for every invocation attempt.

This specification is **language-, framework-, and platform-agnostic**. It is explicitly scoped to **single-hop tool execution within a single organization** and does not define federation, discovery, or multi-agent delegation semantics.

---

## 2. Motivation

Machine Control Platform (MCP) servers expose powerful tools to autonomous agents, including file systems, databases, and privileged APIs. MCP itself does not define how tool execution authority is authenticated, authorized, or audited.

As a result:

* Tool actions may be executed without verifiable agent identity.
* Authorization decisions are opaque or non-deterministic.
* Post-incident analysis lacks cryptographic evidence of *who did what*.

This RFC establishes a minimal, enforceable standard to ensure that **every MCP tool invocation is identity-bound, policy-checked, and auditable**.

The goals of this RFC are:

* Prevent unauthorized or unintended tool execution.
* Ensure deterministic authorization outcomes.
* Produce verifiable evidence suitable for audit and forensic review.

---

## 3. Scope

### 3.1 In Scope

* Single MCP server enforcing authority over tool execution.
* Single agent invoking a tool in a single organizational trust domain.
* Identity verification using CapiscIO Trust Badges transmitted per request.
* Policy-based allow/deny decisions at tool invocation time.
* Mandatory emission of structured evidence logs.

### 3.2 Out of Scope

* Multi-hop delegation or agent-to-agent invocation chains.
* Cross-organizational or federated trust models.
* Global policy distribution frameworks.
* Vendor-specific logging or telemetry integrations.

---

## 4. Definitions

* **Agent**
  An autonomous software entity acting on behalf of a user or system.

* **MCP Server**
  A runtime that exposes tools to agents and mediates their execution.

* **Tool**
  Any callable capability exposed by an MCP server that may read or mutate state.

* **Trust Badge**
  A signed, short-lived cryptographic identity credential issued to an agent, as defined in RFC-002.

* **Policy Decision Point (PDP)**
  The component responsible for evaluating whether a tool invocation is authorized.

* **Evidence Log**
  A structured, immutable record describing the identity, decision, and context of a tool invocation.

---

## 5. Caller Authentication Assumptions

This RFC supports **progressive assurance**.

### 5.1 CapiscIO-Enabled Callers

Agents MAY present a CapiscIO Trust Badge via request headers.
When present, the MCP server MUST treat the caller as a **verified agent principal**.

### 5.2 Non-CapiscIO Callers

If no Trust Badge is present, the MCP server MAY accept the request under a reduced-assurance model (for example, API key or anonymous access), subject to restrictive policy.

### 5.3 Assurance Recording

Every evidence log MUST record the authentication assurance level used, for example:

* `badge`
* `apikey`
* `anonymous`

---

## 6. Runtime Behavior

### 6.1 Identity Transmission

For HTTP-based transports, Trust Badges MUST be transmitted via headers.
The `Authorization: Bearer <token>` header is RECOMMENDED.

If no identity material is provided, the request MUST be evaluated under reduced assurance.

> **Non-HTTP Transports (Non-Normative):** MCP implementations using stdio, websocket, or other non-HTTP transports MAY convey CapiscIO identity and context via protocol-specific metadata mechanisms. This RFC does not prescribe a canonical binding; implementations SHOULD document their chosen mechanism.

---

### 6.2 Identity Verification

When a Trust Badge is present, the MCP server MUST:

1. Verify the cryptographic signature.
2. Validate expiry (`exp`) and issuance (`iat`).
3. Check revocation status.
4. Validate issuer trust.

If verification fails, the invocation MUST be rejected with an authorization error and logged.

After verification, implementations SHOULD discard the raw badge and retain only:

* agent identifier (`sub`)
* badge identifier (`jti`)

---

### 6.3 Policy Authorization

Before executing a tool, the MCP server MUST perform a deterministic authorization check using:

* Verified agent identity (if present)
* Invocation metadata (tool name, action)
* Applicable policy rules

The policy evaluation MUST produce one of two outcomes:

* `ALLOW`
* `DENY`

If the decision is `DENY`, the tool MUST NOT be executed.

> **Implementation Note:** Implementations SHOULD use RFC-005 PDEP when policy complexity exceeds static tool ACLs. For simple deployments, local policy evaluation is sufficient.

---

### 6.4 Authority Enforcement

If `ALLOW`, the MCP server MUST ensure execution occurs **within the effective authority boundary** defined by policy.

Implementations MUST NOT expand the agent’s authority beyond what policy permits.

---

## 7. Evidence Logging

### 7.1 Logging Requirement

Every tool invocation attempt, whether allowed or denied, MUST emit an evidence log entry.

Logs MUST be structured JSON and MUST conform to the schema defined below.

---

### 7.2 Required Fields

| Field                     | Description                        |
| ------------------------- | ---------------------------------- |
| `event.name`              | MUST be `capiscio.tool_invocation` |
| `capiscio.agent.did`      | Agent DID or equivalent principal  |
| `capiscio.badge.jti`      | Badge identifier, if present       |
| `capiscio.auth.level`     | `badge`, `apikey`, or `anonymous`  |
| `capiscio.target`         | Tool identifier                    |
| `capiscio.policy_version` | Policy version used                |
| `capiscio.decision`       | `ALLOW` or `DENY`                  |

### 7.2.1 Optional Fields

| Field                       | Description                                              |
| --------------------------- | -------------------------------------------------------- |
| `capiscio.tool.params_hash` | SHA-256 hash of canonicalized tool parameters (optional) |
| `capiscio.deny_reason`      | Error code when decision is `DENY` (optional)            |

**Parameter Hashing (Non-Normative):**

When `capiscio.tool.params_hash` is included:

1. Canonicalize tool parameters using RFC 8785 (JCS)
2. Compute SHA-256 hash
3. Encode as `sha256:<base64url-hash>`

This enables forensic comparison without logging sensitive parameter values.

---

### 7.3 JSON Schema (Normative)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "capiscio:rfc-006:tool-invocation:v0.3",
  "type": "object",
  "required": [
    "event.name",
    "capiscio.agent.did",
    "capiscio.auth.level",
    "capiscio.target",
    "capiscio.policy_version",
    "capiscio.decision"
  ],
  "properties": {
    "event.name": { "const": "capiscio.tool_invocation" },
    "capiscio.agent.did": { "type": "string" },
    "capiscio.badge.jti": { "type": "string" },
    "capiscio.auth.level": {
      "type": "string",
      "enum": ["badge", "apikey", "anonymous"]
    },
    "capiscio.target": { "type": "string" },
    "capiscio.policy_version": { "type": "string" },
    "capiscio.decision": {
      "type": "string",
      "enum": ["ALLOW", "DENY"]
    },
    "capiscio.tool.params_hash": { "type": "string" },
    "capiscio.deny_reason": { "type": "string" }
  },
  "additionalProperties": true
}
```

Sensitive payloads or tool parameters MUST NOT be logged. Use `capiscio.tool.params_hash` for forensic comparison.

### 7.4 Schema Versioning

Evidence log consumers:

* MUST accept logs with the same major version (e.g., `v0.*`)
* MAY accept logs from earlier minor versions
* MUST reject logs with incompatible major versions

---

## 8. Telemetry Emission

### 8.1 Normative Requirements

* Evidence logs MUST be emitted as structured JSON.
* Logs MUST be transport-neutral (stdout, file, syslog are implementation-defined).

### 8.2 Recommendations

* Implementations SHOULD emit OpenTelemetry spans for each tool invocation.
* Implementations SHOULD expose counters and latency histograms for:

  * authorization decisions
  * verification failures
  * policy evaluation time

### 8.3 Out of Scope

Vendor-specific telemetry integrations (e.g., Datadog, Grafana, Sentry) are explicitly out of scope.

---

## 9. Security Considerations

* Systems MUST fail closed on verification or policy errors.
* Trust Badges MUST be transmitted over encrypted channels.
* Badge lifetimes SHOULD be short to reduce replay risk.
* Policy versions MUST be immutable and auditable.
* Enforcement points MUST be non-bypassable.

---

## 10. Error Codes

When a tool invocation is denied, implementations SHOULD use standardized error codes in `capiscio.deny_reason`:

| Code                  | Description                                    |
| --------------------- | ---------------------------------------------- |
| `TOOL_BADGE_INVALID`  | Badge verification failed (signature, expiry)  |
| `TOOL_BADGE_REVOKED`  | Badge has been revoked                         |
| `TOOL_AUTH_MISSING`   | No identity material provided                  |
| `TOOL_ISSUER_UNTRUSTED` | Badge issuer not in trusted allowlist        |
| `TOOL_POLICY_DENIED`  | Policy evaluation returned DENY                |
| `TOOL_NOT_FOUND`      | Requested tool does not exist                  |

These codes align with RFC-002 error conventions.

---

## 11. Implementation Guidance (Non-Normative)

This RFC may be implemented as:

* Middleware
* Decorators
* Sidecar proxies
* API gateways

Implementations should modularize:

* identity verification
* policy evaluation
* evidence logging

to allow future evolution without breaking compliance.

---

## 12. Changelog

* **v0.3**
  Added `capiscio.tool.params_hash` for forensic comparison without logging sensitive params.
  Added standardized error codes (§10).
  Added schema versioning guidance (§7.4).
  Added non-normative RFC-005 PDEP reference for complex policy scenarios.
  Added non-normative note on non-HTTP transport bindings.

* **v0.2**
  Added progressive assurance model, telemetry section, and clarified adoption assumptions.
