# RFC-004: CapiscIO Transaction and Hop Binding Protocol (TCHB)

**Version:** 0.3
**Status:** Draft
**Authors:** CapiscIO Core Team
**Created:** 2025-12-24
**Updated:** 2026-01-02
**Requires:** RFC-002 (Trust Badge Specification)

---

## 1. Abstract

This RFC defines a lightweight protocol for binding multi-hop agent workflows into a verifiable chain of custody.

The protocol introduces:

* A stable **transaction identifier** (`txn_id`) propagated across hops.
* A signed **Hop Attestation (HA)** that binds each hop to:

  1. the transaction (`txn_id`),
  2. the immediate parent hop (optional `parent_hop_hash`), and
  3. the specific **Trust Badge session** used to authenticate (`badge_jti`).

This yields a self-verifying “tracking number” for agent workflows without requiring a global ledger.

---

## 2. Motivation

In an agentic workflow, requests traverse multiple agents and services. Standard tracing correlates spans, but does not produce a cryptographic chain that can be audited for tampering.

We need a minimal mechanism to answer:

* Which agent initiated each hop?
* Which authenticated badge session was used?
* How did the request propagate across participants?
* Can we detect missing or injected hops after the fact?

---

## 3. Goals and Non-Goals

### 3.1 Goals

* Provide a stable `txn_id` across a workflow.
* Provide a signed Hop Attestation per hop.
* Bind each hop to the Trust Badge session (`badge_jti`) used for authentication.
* Support verification at gateways/services (synchronous) and reconstruction in telemetry pipelines (asynchronous).
* Support HTTP and non-HTTP transports (example mapping for MCP/JSON-RPC).

### 3.2 Non-Goals

* Payload integrity or non-repudiation of request bodies (no `body_hash` in v0.2).
* Global ordering guarantees.
* A global registry of hops.
* Per-request proof-of-possession beyond the hop signature itself.
* Replacing OpenTelemetry or existing tracing systems.

---

## 4. Terminology

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHOULD”, “SHOULD NOT”, and “MAY” are to be interpreted as described in RFC 2119.

| Term                            | Definition                                                              |
| ------------------------------- | ----------------------------------------------------------------------- |
| **Transaction (`txn_id`)**      | A stable ID that groups a workflow across multiple hops.                |
| **Hop**                         | A single propagation step from one participant to the next.             |
| **Hop Attestation (HA)**        | A signed JWS asserting hop metadata and bindings.                       |
| **Badge Session (`badge_jti`)** | The `jti` claim of the Trust Badge used for authentication on that hop. |
| **Synchronous Verification**    | On-request checks performed by the receiving service or gateway.        |
| **Asynchronous Audit**          | Offline reconstruction and linkage verification in logs/event sinks.    |

---

## 5. Protocol Overview

Each hop carries:

1. `X-Capiscio-Txn`: a stable transaction ID.
2. `X-Capiscio-Hop`: a Hop Attestation JWS, signed by the initiating agent.
3. A Trust Badge (RFC-002) used to authenticate the caller.

The receiving service verifies:

* The Trust Badge is valid.
* The HA signature is valid using the agent key bound in the presented badge.
* The HA is bound to the presented badge via `badge_jti`.
* The HA is bound to the current request via `htu` and `htm` (with canonicalization rules).

Parent linkage (`parent_hop_hash`) is intended primarily for asynchronous audit and MUST NOT be required for request acceptance.

---

## 6. Transport and Propagation

### 6.1 HTTP Headers (Normative)

Implementations MUST support the following headers:

```http
X-Capiscio-Txn: <txn_id>
X-Capiscio-Hop: <hop_attestation_jws>
Authorization: Bearer <trust_badge_jws>     ; per RFC-002
```

Header requirements:

* `X-Capiscio-Txn` MUST be present for CapiscIO-governed hops.
* `X-Capiscio-Hop` MUST be present for CapiscIO-governed hops.
* The Trust Badge MUST be present per the deployment’s authentication rules.

### 6.2 Propagation Rules (Normative)

* Intermediaries that forward a request (gateway, agent, service mesh) MUST forward `X-Capiscio-Txn`.
* Intermediaries MUST generate a new `X-Capiscio-Hop` for the outbound request they initiate.
* Intermediaries SHOULD include `parent_hop_hash` when they have access to the inbound hop attestation they received.

### 6.3 Non-HTTP Transports (MCP / JSON-RPC) (Normative)

For JSON-RPC protocols like MCP, the CapiscIO context MUST be propagated in a standardized metadata field. One acceptable mapping is:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": { "...": "..." },
  "_meta": {
    "capiscio_txn": "<txn_id>",
    "capiscio_hop": "<hop_attestation_jws>"
  }
}
```

For non-HTTP transports, `htu` MUST be the canonical target identifier for that transport.

**MCP `htu` Canonicalization (Normative):**

For MCP (Model Context Protocol) transports, `htu` MUST use the following format:

```
mcp://<server-identifier>/<method>
```

Where:
- `<server-identifier>` is the MCP server's advertised name or endpoint (e.g., `filesystem`, `github`, `slack`).
- `<method>` is the JSON-RPC method being invoked (e.g., `tools/call`, `resources/read`).

**Example:** `mcp://filesystem/tools/call`

For MCP servers accessed via stdio or other local transports, `<server-identifier>` SHOULD be the server's canonical name as declared in its manifest.

---

## 7. Identifiers

### 7.1 Transaction ID (`txn_id`) (Normative)

* `txn_id` MUST be a string.
* `txn_id` SHOULD be a UUID (v4 or v7) to maximize interoperability with tracing systems.
* `txn_id` MUST be treated as an opaque identifier by verifiers.

### 7.2 Hop ID (`hop_id`) (Normative)

* Each Hop Attestation MUST contain a unique `hop_id` (UUID recommended).
* `hop_id` uniqueness is scoped to the issuer. Collisions across issuers are not expected but are not protocol-breaking.

---

## 8. Hop Attestation (HA)

### 8.1 Format (Normative)

A Hop Attestation is a JWS (compact serialization):

```
<base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

### 8.2 HA Header (Normative)

Example:

```json
{
  "alg": "EdDSA",
  "typ": "capiscio.hop+jwt",
  "kid": "did:web:example.com:agents:my-agent#key-1"
}
```

Requirements:

* `alg` MUST be `EdDSA` (Ed25519).
* `typ` MUST be `capiscio.hop+jwt`.
* `kid` SHOULD be present and SHOULD reference the signing key identifier. For `did:web`, this SHOULD be a DID URL fragment to a verification method.

### 8.3 HA Payload (Claims) (Normative)

Example payload:

```json
{
  "txn_id": "018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11",
  "hop_id": "550e8400-e29b-41d4-a716-446655440000",
  "parent_hop_hash": "sha256:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564",
  "iss": "did:web:example.com:agents:my-agent",
  "target_aud": "https://api.partner.com",
  "badge_jti": "b8f2c6a5-2d6f-4e44-9f55-2a1d6d9e0f12",
  "iat": 1733788800,
  "exp": 1733789100,
  "htm": "POST",
  "htu": "https://api.partner.com/v1/task"
}
```

Claims:

| Claim             | Requirement | Description                                                              |
| ----------------- | ----------- | ------------------------------------------------------------------------ |
| `txn_id`          | REQUIRED    | Stable workflow transaction ID.                                          |
| `hop_id`          | REQUIRED    | Unique hop identifier.                                                   |
| `parent_hop_hash` | OPTIONAL    | Hash of the immediate parent hop attestation (see §8.5).                 |
| `iss`             | REQUIRED    | Agent DID that issued the hop. MUST equal the `sub` claim of the presented Trust Badge (see §9.2). |
| `target_aud`      | REQUIRED    | Target audience identifier for this hop (typically the receiver origin). This is a single origin string, distinct from RFC-002 Badge `aud` (which is an array). |
| `badge_jti`       | REQUIRED    | Trust Badge `jti` bound to this hop.                                     |
| `iat`             | REQUIRED    | Issued-at (Unix seconds).                                                |
| `exp`             | REQUIRED    | Expiration (Unix seconds).                                               |
| `htm`             | REQUIRED    | HTTP method (or equivalent) bound to the hop.                            |
| `htu`             | REQUIRED    | Target URI (or canonical target identifier) bound to the hop.            |
| `body_hash`       | RESERVED    | Not used in v0.2. MUST be ignored if present.                            |

#### 8.3.1 `badge_jti` Binding (Normative)

* `badge_jti` MUST be present in every Hop Attestation.
* Verifiers MUST confirm `badge_jti` equals the `jti` claim of the presented Trust Badge.
* If the badge is revoked, the hop’s credibility is reduced to “unsigned context” for governance purposes. (The request may still have been processed historically, but audit systems can flag it.)

### 8.4 Lifetime (Normative)

* HA `exp - iat` SHOULD be short (recommended: 5 minutes) and SHOULD NOT exceed the Trust Badge lifetime.
* Verifiers MUST reject Hop Attestations that are expired.

### 8.5 Parent Hop Hash (Normative)

When included, `parent_hop_hash` MUST be computed over the parent hop attestation using the canonical hashing rules in §8.6.

**Audit Obligation:** The hash chain binds hop payloads but does not bind signatures. Asynchronous audit systems that verify `parent_hop_hash` linkage MUST also independently verify the parent hop's signature to ensure the parent was not forged. The hash alone is insufficient for tamper detection.

### 8.6 Canonical Hashing (Normative)

When hashing a hop attestation for `parent_hop_hash`, implementations MUST:

1. Decode the parent hop JWS payload JSON.
2. Canonicalize JSON using RFC 8785 (JCS).
3. UTF-8 encode.
4. SHA-256 hash.
5. base64url encode without padding.
6. Prefix with `sha256:`.

---

## 9. Verification

### 9.1 Verification vs Audit (Normative Split)

**Synchronous verification** (at gateway or service) MUST verify the current hop’s authenticity and bindings, but MUST NOT require access to the parent hop.

**Asynchronous audit** (in telemetry pipelines) SHOULD reconstruct hop chains and verify parent linkage.

### 9.2 Synchronous Verification Algorithm (Normative)

Given a request containing `X-Capiscio-Txn`, `X-Capiscio-Hop`, and a Trust Badge:

1. Parse Trust Badge and validate per RFC-002 (signature, `exp`, issuer trust, audience rules as applicable).
2. Parse Hop Attestation JWS.
3. Validate HA structure:

   * `alg == EdDSA`
   * `typ == capiscio.hop+jwt`
   * required HA claims present
4. Verify `txn_id` matches `X-Capiscio-Txn`. If mismatch, reject.
5. Verify `badge_jti` is present. If missing, reject.
6. Verify `badge_jti == badge.jti`. If mismatch, reject.
7. Verify `iss == badge.sub`. If mismatch, reject. This prevents semantically mis-attributed hops where the signature is valid but the claimed issuer differs from the authenticated caller.
8. Verify HA signature using the **agent public key** from the presented Trust Badge `key` claim (RFC-002).

   * If the deployment requires DID resolution, it MAY instead verify using the DID document, but this is OPTIONAL.
9. Validate time claims with skew tolerance (recommended: 60 seconds).
10. Validate request binding:

    * Verify `htm` matches the request method.
    * Verify `htu` matches the canonicalized target (see §9.3).
11. If all checks pass, accept request and emit telemetry per §10.

### 9.3 `htu` Canonicalization (Normative)

Real deployments use reverse proxies. The receiver may see an internal URL that does not match what the caller signed. To avoid brittle failures:

* Verifiers MUST canonicalize the target identity for `htu` comparison using one of the following configured modes.

**Mode A (Path-only verification):**

* Compare only the path and query (if used), ignoring scheme and host.
* Recommended when services sit behind gateways that rewrite scheme/host.

**Mode B (Public Identity URI verification):**

* Verifier is configured with a “public identity origin” (for example `https://api.partner.com`).
* Verifier reconstructs `htu` as: `<public_origin><request_path_and_query>`.
* Compare against HA `htu`.

A deployment MUST document which mode it uses. Mode B is RECOMMENDED for production because it preserves host binding.

#### 9.3.1 Query String Normalization (Normative)

If the `htu` includes a query string, implementations MUST normalize before signing and comparing:

1. **Include or exclude:** A deployment MUST document whether query strings are included in `htu`. If excluded, signers MUST omit the query; verifiers MUST strip it before comparison.
2. **If included:**
   - Query parameters MUST be sorted lexicographically by key (byte order).
   - Keys and values MUST be percent-encoded using the following algorithm:
     - Decode any existing percent-encoded **unreserved characters** (RFC 3986 §2.3: `A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`).
     - **Reserved characters** (RFC 3986 §2.2: `:/?#[]@!$&'()*+,;=`) MUST NOT be decoded; they remain percent-encoded.
     - Re-encode all characters outside the unreserved set using uppercase hex (`%2F`, not `%2f`).
     - Encode spaces as `%20` (not `+`).
   - Empty query (`?` with no parameters) MUST be treated as absent (omit `?`).
   - Duplicate keys are preserved in sorted order.
3. **Example:** `?b=2&a=1` normalizes to `?a=1&b=2`. `?name=hello%20world` and `?name=hello+world` both normalize to `?name=hello%20world`.

Failure to normalize consistently will cause false rejections or create bypass opportunities if different components normalize differently.

### 9.4 Parent Linkage Checks (Normative)

* The verifier (Service B) will often not have Hop N-1.
* Therefore, synchronous verifiers MUST NOT fail a request if `parent_hop_hash` cannot be validated.
* Parent linkage verification is primarily the responsibility of the asynchronous audit layer.

---

## 10. Telemetry and Observability

Implementations MUST be capable of emitting structured telemetry events to enable reconstruction of a durable chain of custody.

### 10.1 Canonical Hop Event Schema (Normative)

When a hop is emitted (client) or verified (server), implementations MUST be capable of emitting a structured log event containing these fields. Field names SHOULD use the `capiscio.` namespace.

| Field                      | Type           | Description                                                                       |
| -------------------------- | -------------- | --------------------------------------------------------------------------------- |
| `capiscio.txn_id`          | String         | Stable workflow transaction ID.                                                   |
| `capiscio.hop.hop_id`      | String         | Unique ID of the current hop.                                                     |
| `capiscio.hop.parent_hash` | String or null | Hash of the parent hop.                                                           |
| `capiscio.hop.sig_kid`     | String         | The `kid` used to sign the hop.                                                   |
| `capiscio.agent.did`       | String         | Agent DID initiating the hop (from HA `iss`).                                     |
| `capiscio.badge.jti`       | String         | The `jti` of the Trust Badge used for authentication.                             |
| `capiscio.target_aud`      | String         | Intended audience of the hop (from HA `target_aud`).                              |
| `event.name`               | String         | RECOMMENDED: `capiscio.hop_verified` (server) or `capiscio.hop_emitted` (client). |

Implementations SHOULD include additional operational fields when available (duration, status code, error code), but MUST NOT change the semantics of the required fields.

### 10.2 OpenTelemetry (OTel) Mapping (Normative)

If OpenTelemetry is used, implementations MUST map CapiscIO context as follows.

**1. Trace ID mapping:**

* If `capiscio.txn_id` is a valid UUID (v4 or v7), implementations SHOULD use the underlying 16 bytes as the OTel `TraceId`.
* If `txn_id` is not a UUID, generate a new OTel `TraceId` and attach `capiscio.txn_id` as a span attribute.

**2. Span attributes:**
These attributes MUST be attached to the active span while processing the request:

```yaml
capiscio.txn_id: <txn_id>
capiscio.hop_id: <hop_id>
capiscio.parent_hash: <parent_hop_hash>
capiscio.agent.did: <iss>
capiscio.badge.jti: <badge_jti>
```

**3. Context propagation:**

* Implementations MUST preserve `X-Capiscio-Txn` and `X-Capiscio-Hop` across service boundaries.
* OTel Baggage MAY be used for convenience but MUST NOT replace the HTTP headers as the source of truth.

### 10.3 Logging and Redaction (Normative)

Logging pipelines MUST enforce:

1. **No full tokens:** MUST NOT log the full `X-Capiscio-Hop` JWS or Trust Badge JWT by default.
2. **JTI only:** Logging `capiscio.badge.jti` is REQUIRED; logging full badge payload is FORBIDDEN by default.
3. **No payload capture:** Request bodies SHOULD NOT be logged unless explicitly configured for full-capture debugging.

---

## 11. Security Considerations

### 11.1 Threats and Mitigations

| Threat                             | Mitigation                                                                         |
| ---------------------------------- | ---------------------------------------------------------------------------------- |
| Hop forgery                        | HA is signed, verified against badge-bound agent key.                              |
| Badge theft used to sign fake hops | `badge_jti` binding REQUIRED, reduces blast radius and improves audit correlation. |
| Replay within TTL                  | Short HA TTL; production gateways SHOULD maintain a short-lived replay cache keyed by (`badge_jti`, `hop_id`). |
| Proxy rewriting breaks `htu`       | Canonicalization modes in §9.3.                                                    |
| Token leakage in logs              | Redaction rules in §10.3.                                                          |

### 11.2 SSRF Note

This RFC does not require DID resolution for HA verification because the badge embeds the agent key. If a deployment does perform DID resolution, it SHOULD apply SSRF protections similar to RFC-002 verifier guidance.

---

## 12. Implementation Notes (Non-Normative)

### 12.1 Fan-In and Aggregation

If an agent aggregates inputs from multiple upstream hops:

* The agent SHOULD choose the primary causal parent for `parent_hop_hash`, or
* Omit `parent_hop_hash` if no clear primary parent exists, effectively starting a new hop chain linked only by `txn_id`.

### 12.2 Recommended Defaults

* `txn_id`: UUID v7 if available; else UUID v4.
* HA TTL: 5 minutes.
* `htu` verification: Mode B (Public Identity URI) in production.

---

## 13. Future Work

* Optional per-request signing separate from HA (to reduce reliance on bearer credentials).
* Constrained delegation artifacts.
* Standardized metric names derived from spans (example `capiscio.hop_latency`).
* Sampling guidance for high-value transactions.
* Optional `body_hash` as an experimental extension once streaming-safe patterns exist.

---

## Appendix A: Canonical Hop Event JSON Schema (Normative)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "capiscio:schema:rfc-004:hop-event:v0.2",
  "title": "CapiscIO Hop Event",
  "type": "object",
  "required": [
    "event.name",
    "capiscio.txn_id",
    "capiscio.hop.hop_id",
    "capiscio.agent.did",
    "capiscio.badge.jti",
    "capiscio.target_aud"
  ],
  "properties": {
    "event.name": {
      "type": "string",
      "enum": ["capiscio.hop_emitted", "capiscio.hop_verified"]
    },
    "capiscio.txn_id": { "type": "string" },

    "capiscio.hop.hop_id": { "type": "string" },
    "capiscio.hop.parent_hash": { "type": ["string", "null"] },
    "capiscio.hop.sig_kid": { "type": "string" },

    "capiscio.agent.did": { "type": "string" },
    "capiscio.badge.jti": { "type": "string" },
    "capiscio.target_aud": { "type": "string" }
  },
  "additionalProperties": true
}
```

---

## Appendix B: Vendor Export Guidelines (Non-Normative)

### Datadog

* Map `capiscio.txn_id` to `trace_id` when feasible.
* Map `capiscio.agent.did` to `usr.id` to enable “User” pivot views.

### Splunk / ELK

* Ensure `capiscio.*` fields are indexed as keyword strings (not full-text) to allow exact filtering on transaction IDs.

### Honeycomb

* Use `capiscio.txn_id` as the high-cardinality grouping key for BubbleUp analysis.
* Attach `capiscio.agent.did` and `capiscio.badge.jti` as first-class fields for slicing.

---

## Appendix C: Example HTTP Exchange (Non-Normative)

**Outbound request:**

```http
POST /v1/task HTTP/1.1
Host: api.partner.com
Authorization: Bearer <badge>
X-Capiscio-Txn: 018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11
X-Capiscio-Hop: <hop_attestation_jws>
Content-Type: application/json

{ ... }
```

**Server emits event:**

```json
{
  "event.name": "capiscio.hop_verified",
  "capiscio.txn_id": "018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11",
  "capiscio.hop.hop_id": "550e8400-e29b-41d4-a716-446655440000",
  "capiscio.hop.parent_hash": null,
  "capiscio.hop.sig_kid": "did:web:example.com:agents:my-agent#key-1",
  "capiscio.agent.did": "did:web:example.com:agents:my-agent",
  "capiscio.badge.jti": "b8f2c6a5-2d6f-4e44-9f55-2a1d6d9e0f12",
  "capiscio.target_aud": "https://api.partner.com"
}
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.3 | 2026-01-02 | **Added:** `iss == badge.sub` semantic binding (§9.2 step 7); MCP `htu` canonicalization (§6.3); explicit percent-encoding algorithm. **Changed:** `aud` → `target_aud` to distinguish from RFC-002 Badge `aud`. **Fixed:** Query normalization rules (sorting, encoding, `%20` not `+`); parent hash audit obligation note; replay cache upgraded to SHOULD. |
| 0.2 | 2025-12-24 | Initial draft. |
