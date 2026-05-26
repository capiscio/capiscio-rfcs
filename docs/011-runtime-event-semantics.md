# RFC-011: Runtime Event Semantics

**Version:** 1.0
**Status:** Draft
**Authors:** CapiscIO Core Team
**Created:** 2026-05-26
**Updated:** 2026-05-26
**Requires:** RFC-001 (AGCP), RFC-002 (Trust Badge), RFC-008 (Delegated Authority Envelopes)

---

## 1. Abstract

This RFC defines the **canonical event semantics** for CapiscIO runtime components. Events model **authority transitions** — the moments when trust decisions are made, authority changes hands, and enforcement actions occur. They are NOT telemetry or observability signals; they are first-class runtime artifacts that support audit, compliance, and provenance reconstruction.

Events are emitted locally at enforcement boundaries (PEPs, sidecars, SDK wrappers). They are structured, typed, and carry references to the cryptographic artifacts (badges, envelopes, hop attestations) that were in scope at the time of the transition. Event emission does not depend on a central service; events can be buffered, batched, and forwarded asynchronously.

This specification defines:

* The event taxonomy (six categories, ~25 event types)
* The event envelope format (JSON, signed when required)
* Emission points and timing guarantees
* Relationship to audit logs and compliance systems
* Non-goals: observability, metrics, distributed tracing

---

## 2. Relationship to Other RFCs

| RFC | Relationship |
|-----|--------------|
| RFC-001 (AGCP) | Defines the Trace & Enforce pattern. Events record enforcement decisions made per §4.2. Events reference `trace_id` from RFC-001 §3.2. |
| RFC-002 (Trust Badge) | Identity events reference badge `jti`. Verification events record badge verification outcomes. |
| RFC-004 (TCHB) | Events carry `txn_id` and `hop_id` to link to the transport-layer hop chain. |
| RFC-008 (DAE) | Authority events reference `authority_envelope_hash`. Delegation events record envelope issuance. |
| RFC-009 (PEP Spec) | PEP implementations MUST emit the events defined in this RFC at the specified emission points. |

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|------|------------|
| **Event** | A structured record of an authority transition or enforcement action, emitted at a specific point in time. |
| **Event Type** | A dot-delimited identifier (e.g., `authority.granted`) categorizing the event. |
| **Emission Point** | The code location or system boundary where an event is generated. |
| **Authority Transition** | A change in effective authority: grant, delegation, narrowing, denial, or revocation. |
| **Event Envelope** | The JSON structure containing event metadata, type, payload, and optional signature. |

---

## 4. Design Principles

### 4.1 Events Model Authority Transitions

Events are NOT generic log entries. They model discrete authority transitions:

| Category | Models |
|----------|--------|
| Identity | "Agent X presented credential Y, and verification succeeded/failed." |
| Authority | "Authority was requested/granted/denied/narrowed/delegated." |
| Runtime | "Enforcement boundary attached/detached; execution started/completed." |
| Tool | "Tool invocation was requested/permitted/denied/executed." |
| Resource | "Resource access was requested/permitted/denied." |
| Trust | "Cryptographic operation completed (signature, attestation, verification)." |

If an action does not involve an authority transition, enforcement decision, or trust operation, it is NOT a CapiscIO event. Use application-level logging for general diagnostics.

### 4.2 Local Emission, Asynchronous Forwarding

Events are emitted at the enforcement boundary (PEP, sidecar, SDK wrapper). Emission is a local operation; it MUST NOT block on network I/O to a central service. Events MAY be:

* Written to a local buffer or file
* Forwarded asynchronously to an event collector
* Batched and compressed for efficiency
* Signed for integrity when required by deployment policy

This aligns with the Verification Locality Principle (RFC-001 §2.3): runtime operations do not depend on synchronous central services.

### 4.3 Events Are Not Observability

| Concern | CapiscIO Events | Observability Systems |
|---------|-----------------|----------------------|
| Purpose | Audit, compliance, provenance | Performance, debugging, alerting |
| Granularity | Authority transitions only | All operations |
| Retention | Long-term (compliance windows) | Short-term (days/weeks) |
| Schema | Fixed, versioned, normative | Flexible, implementation-defined |
| Consumers | Auditors, compliance, forensics | SRE, developers, monitoring |

Implementations MAY forward CapiscIO events to observability systems (OTLP, Datadog, etc.) for correlation, but the event schema and emission rules are defined by this RFC, not by observability conventions.

---

## 5. Event Taxonomy

### 5.1 Identity Events

Identity events record badge verification outcomes.

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `identity.verified` | Badge verification succeeded | `badge_jti`, `subject_did`, `trust_level`, `ial` |
| `identity.invalid` | Badge verification failed | `badge_jti` (if parseable), `error_code`, `reason` |
| `identity.expired` | Badge expired during use | `badge_jti`, `subject_did`, `expired_at` |
| `identity.revoked` | Badge found on revocation list | `badge_jti`, `subject_did`, `revoked_at` |

### 5.2 Authority Events

Authority events record changes to effective authority.

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `authority.requested` | Authority request received at PEP | `subject_did`, `requested_capabilities`, `envelope_hash` |
| `authority.granted` | PDP returned ALLOW | `subject_did`, `effective_capabilities`, `envelope_hash`, `policy_version` |
| `authority.denied` | PDP returned DENY | `subject_did`, `requested_capabilities`, `reason`, `policy_version` |
| `authority.narrowed` | Authority narrowed via delegation | `parent_envelope_hash`, `child_envelope_hash`, `narrowed_capabilities` |
| `authority.delegated` | New envelope issued | `issuer_did`, `subject_did`, `envelope_hash`, `delegation_depth` |
| `authority.expired` | Envelope expired during use | `envelope_hash`, `expired_at` |

### 5.3 Runtime Events

Runtime events record enforcement boundary lifecycle.

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `runtime.attached` | PEP/sidecar attached to runtime | `component_id`, `attached_at`, `enforcement_mode` |
| `runtime.detached` | PEP/sidecar detached | `component_id`, `detached_at`, `reason` |
| `execution.started` | Governed execution began | `txn_id`, `hop_id`, `subject_did`, `envelope_hash` |
| `execution.completed` | Governed execution finished | `txn_id`, `hop_id`, `outcome`, `duration_ms` |
| `execution.aborted` | Governed execution terminated early | `txn_id`, `hop_id`, `reason`, `error_code` |

### 5.4 Tool Events

Tool events record MCP tool invocation decisions.

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `tool.requested` | Tool invocation requested | `tool_name`, `server_did`, `subject_did`, `envelope_hash` |
| `tool.permitted` | Tool invocation authorized | `tool_name`, `server_did`, `subject_did` |
| `tool.denied` | Tool invocation denied | `tool_name`, `server_did`, `subject_did`, `reason` |
| `tool.executed` | Tool invocation completed | `tool_name`, `server_did`, `outcome`, `duration_ms` |

### 5.5 Resource Events

Resource events record access to protected resources.

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `resource.network.requested` | Network access requested | `target_url`, `method`, `subject_did` |
| `resource.network.permitted` | Network access allowed | `target_url`, `method` |
| `resource.network.denied` | Network access blocked | `target_url`, `method`, `reason` |
| `resource.filesystem.requested` | Filesystem access requested | `path`, `operation`, `subject_did` |
| `resource.filesystem.permitted` | Filesystem access allowed | `path`, `operation` |
| `resource.filesystem.denied` | Filesystem access blocked | `path`, `operation`, `reason` |
| `resource.shell.requested` | Shell execution requested | `command_hash`, `subject_did` |
| `resource.shell.permitted` | Shell execution allowed | `command_hash` |
| `resource.shell.denied` | Shell execution blocked | `command_hash`, `reason` |

### 5.6 Trust Events

Trust events record cryptographic operations.

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `trust.signature.created` | Artifact signed | `artifact_type`, `artifact_hash`, `signer_did` |
| `trust.signature.verified` | Signature verification succeeded | `artifact_type`, `artifact_hash`, `signer_did` |
| `trust.signature.invalid` | Signature verification failed | `artifact_type`, `artifact_hash`, `error_code` |
| `trust.attestation.generated` | Hop attestation created | `hop_id`, `attester_did`, `attestation_hash` |
| `trust.revocation.checked` | Revocation status checked | `jti`, `revoked`, `cache_age_seconds` |

---

## 6. Event Envelope Format

### 6.1 Structure

```json
{
  "schema_version": "1.0",
  "event_id": "evt_550e8400-e29b-41d4-a716-446655440000",
  "event_type": "authority.granted",
  "timestamp": "2026-05-26T14:30:00.123Z",
  "emitter": {
    "component_id": "pep-sidecar-prod-1",
    "component_type": "sidecar",
    "version": "2.4.1"
  },
  "context": {
    "trace_id": "tr_a1b2c3d4e5f6",
    "txn_id": "txn_123456",
    "hop_id": "hop_001"
  },
  "payload": {
    "subject_did": "did:web:registry.capisc.io:agents:my-agent",
    "effective_capabilities": ["tools.database.read", "tools.database.write"],
    "envelope_hash": "sha256:abc123...",
    "policy_version": "policy_v2.1.0"
  },
  "signature": "<optional JWS signature>"
}
```

### 6.2 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Event schema version. MUST be `"1.0"` for this RFC. |
| `event_id` | string | Unique event identifier. MUST be UUID v4 prefixed with `evt_`. |
| `event_type` | string | Event type from §5 taxonomy. |
| `timestamp` | string | ISO 8601 timestamp with millisecond precision. |
| `emitter.component_id` | string | Identifier of the emitting component. |
| `emitter.component_type` | string | One of: `sdk`, `sidecar`, `gateway`, `pep`. |
| `payload` | object | Event-specific data per §5 tables. |

### 6.3 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `emitter.version` | string | Version of the emitting component. |
| `context.trace_id` | string | RFC-001 trace ID linking to the originator workflow. |
| `context.txn_id` | string | RFC-004 transaction ID. |
| `context.hop_id` | string | RFC-004 hop ID. |
| `signature` | string | JWS compact signature over the event for integrity. |

### 6.4 Signature

Events MAY be signed for integrity and non-repudiation. When signed:

1. The `signature` field contains a JWS compact signature.
2. The signing input is the UTF-8 bytes of the JSON object excluding the `signature` field, canonicalized per RFC 8785 (JCS).
3. The signing key SHOULD be the emitting component's key (for sidecars/PEPs) or the agent's key (for SDKs).
4. Signature verification is OPTIONAL for consumers; signed events provide higher assurance for compliance scenarios.

---

## 7. Emission Points

### 7.1 PEP Emission Requirements

PEP implementations conforming to RFC-009 MUST emit the following events:

| Emission Point | Events |
|----------------|--------|
| Badge verification complete | `identity.verified` OR `identity.invalid`/`expired`/`revoked` |
| Authority request received | `authority.requested` |
| PDP decision received | `authority.granted` OR `authority.denied` |
| Envelope issuance | `authority.delegated` |
| Execution boundary enter | `execution.started` |
| Execution boundary exit | `execution.completed` OR `execution.aborted` |
| Tool invocation decision | `tool.permitted` OR `tool.denied` |
| Tool invocation complete | `tool.executed` |

### 7.2 SDK Emission Requirements

SDK implementations (e.g., `capiscio.guard()` wrappers) SHOULD emit:

| Emission Point | Events |
|----------------|--------|
| Guard wrapper invoked | `execution.started` |
| Guard wrapper returned | `execution.completed` |
| Local signature created | `trust.signature.created` |
| Local verification performed | `trust.signature.verified` OR `trust.signature.invalid` |

### 7.3 Timing Guarantees

| Guarantee | Level | Description |
|-----------|-------|-------------|
| Emission occurs | MUST | Events MUST be emitted at the specified emission points. |
| Emission is synchronous | SHOULD | Events SHOULD be emitted before the triggering operation returns. |
| Emission does not block | MUST | Event emission MUST NOT block on network I/O. Local buffering is acceptable. |
| Order preserved | SHOULD | Events from a single emitter SHOULD be delivered in emission order. |

---

## 8. Event Consumers

### 8.1 Audit Systems

Audit systems consume events for compliance and forensic analysis. They SHOULD:

* Persist events for the required compliance retention period
* Index by `trace_id`, `subject_did`, `event_type`, and `timestamp`
* Support reconstruction of authority chains from `authority.*` events
* Verify event signatures when present

### 8.2 Compliance Dashboards

Compliance dashboards aggregate events for posture visualization. They MAY:

* Compute metrics (deny rate, average authority depth, etc.)
* Alert on anomalous patterns (spike in `identity.invalid`, etc.)
* Correlate with external signals (SIEM, IdP logs)

### 8.3 Observability Integration

Events MAY be forwarded to observability systems for operational correlation:

* OTLP export as span events
* Datadog/Splunk as structured logs
* Prometheus metrics derived from event counts

However, observability systems are NOT the authoritative consumer. The event schema is defined by this RFC; observability integrations adapt to it.

---

## 9. Security Considerations

### 9.1 Event Integrity

Unsigned events can be forged by any component with write access to the event transport. For high-assurance deployments:

* Enable event signing (§6.4)
* Use tamper-evident event stores (append-only, signed blocks)
* Verify signatures before accepting events for compliance purposes

### 9.2 Sensitive Data

Events MAY contain DIDs, capability names, and tool names. They MUST NOT contain:

* Actual request/response payloads
* Secrets, tokens, or credentials
* PII beyond identifiers already present in badges

Implementations SHOULD support redaction policies for sensitive fields.

### 9.3 Denial of Service

High-frequency event emission can overwhelm consumers. Implementations SHOULD:

* Support sampling for high-volume event types
* Rate-limit event emission per component
* Use backpressure signals from event transport

---

## 10. Implementation Notes

### 10.1 Buffering and Batching

Implementations SHOULD buffer events locally and batch for transmission:

* Buffer size: 100 events or 10 seconds (whichever first)
* Compression: gzip recommended for batches > 10KB
* Retry: exponential backoff on transport failure

### 10.2 Event Transport

This RFC does not mandate a specific transport. Common options:

| Transport | Use Case |
|-----------|----------|
| Local file | Air-gapped deployments, forensic capture |
| NATS / Kafka | High-throughput streaming |
| OTLP (gRPC) | Observability integration |
| HTTPS POST | Simple collector integration |

### 10.3 Schema Evolution

The `schema_version` field enables forward compatibility. Consumers MUST:

* Ignore unknown fields
* Fail gracefully on unknown `event_type` values
* Support at least the current and previous schema version

---

## 11. Conformance

### 11.1 PEP Conformance

A PEP implementation conforms to this RFC if it:

1. Emits all events specified in §7.1 at the correct emission points
2. Uses the event envelope format defined in §6
3. Populates all required fields per §6.2
4. Does not emit events for non-authority-transition operations

### 11.2 SDK Conformance

An SDK implementation conforms to this RFC if it:

1. Emits events specified in §7.2 at the correct emission points
2. Uses the event envelope format defined in §6
3. Provides an API for consumers to subscribe to events

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-05-26 | Initial draft |
