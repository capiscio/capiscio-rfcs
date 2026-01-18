# RFC-007: MCP Server Identity Disclosure and Verification

**Version:** 0.4  
**Status:** Draft  
**Authors:** CapiscIO Core Team  
**Created:** 2026-01-15  
**Updated:** 2026-01-15  
**Requires:** RFC-002 (Trust Badge Specification)  
**Related:** RFC-006 (MCP Tool Authority and Evidence), RFC-004 (Transaction Hop Binding)

---

## 1. Abstract

This RFC defines a mechanism for **MCP servers** to disclose a **cryptographically verifiable server identity** to MCP clients.

CapiscIO extends MCP's transport security assumptions (for example TLS for HTTP transports) with an explicit **server principal** that can be verified independently of network origin. MCP authorization is primarily concerned with client authorization to a server; this RFC focuses on **server identity to the client**.

This RFC standardizes:

* **Server identity disclosure** (DID + optional Trust Badge).
* **Transport mappings** (HTTP headers normative, MCP/JSON-RPC metadata normative).
* **Client verification algorithm** including issuer trust, trust-level handling, and revocation checks.
* **Minimal discovery metadata** for implementations that want an out-of-band identity document, without defining a registry.

---

## 2. Relationship to Other RFCs

| Capability                                   | RFC     | How it is used here                                                                                     |
| -------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------- |
| Trust Badges and trust levels                | RFC-002 | Server presents badge; client verifies issuer, claims, trust level, expiry, and revocation.             |
| MCP Tool Authority and Evidence              | RFC-006 | RFC-006 is client→server (tool invocation authority). RFC-007 is server→client (server identity).       |
| Transport mappings for MCP/JSON-RPC metadata | RFC-004 | Uses the same `_meta` pattern for non-HTTP transports.                                                  |

Invariant: **Origin is not identity.** TLS, IP allowlists, and gateways identify an endpoint or channel, not the server principal operating it.

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and "MAY" are to be interpreted as described in RFC 2119.

| Term              | Definition                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------- |
| MCP Server        | A service implementing MCP over a transport (stdio, streamable HTTP, or custom).             |
| Server DID        | A DID representing the MCP server principal.                                                 |
| Server Badge      | A Trust Badge (RFC-002) issued for the server DID.                                           |
| Trust Level       | 0–4 as defined in RFC-002. Level 0 is self-signed (`did:key`); Levels 1–4 are CA-issued.     |
| Verified Server   | A server whose disclosed identity has been verified by the client per Section 7.             |
| Unverified Origin | A server that has disclosed no cryptographic identity material.                              |

---

## 4. Goals and Non-Goals

### 4.1 Goals

* Provide a standard way for an MCP server to disclose a **verifiable principal identity** (DID + optional badge).
* Support **HTTP** and **non-HTTP** transports with a consistent mapping approach.
* Define a **deterministic client verification algorithm**, including revocation checks.
* Define client behavior when a server discloses **no identity**.

### 4.2 Non-Goals

* Defining a global MCP server registry or marketplace.
* Replacing MCP's authorization model (OAuth-based) or transport security requirements.
* Defining a new DID method. DID method usage is inherited from existing CapiscIO trust levels.

---

## 5. Protocol Overview

### 5.1 Server Disclosure

An MCP server MAY disclose:

1. **Server DID** (required when disclosure is enabled)
2. **Server Badge** (optional; recommended for Trust Levels 1–4)

### 5.2 Client Classification

Based on disclosed identity, clients MUST classify the server into one of these states:

| State                 | Condition                                             | Semantics                                      |
| --------------------- | ----------------------------------------------------- | ---------------------------------------------- |
| `VERIFIED_PRINCIPAL`  | DID + badge verified per Section 7                    | Cryptographic identity confirmed at trust level |
| `DECLARED_PRINCIPAL`  | DID provided, no badge (or badge verification failed) | Identity claimed but not cryptographically proven |
| `UNVERIFIED_ORIGIN`   | No identity disclosed                                 | Unknown principal; transport origin only        |

**Critical distinction:**

* `UNVERIFIED_ORIGIN` means **no cryptographic identity** was presented. This is semantically different from Trust Level 0.
* Trust Level 0 (`did:key`, self-signed) is still a **cryptographic identity**, just without third-party attestation.

Clients MUST NOT conflate "no identity" with "Trust Level 0".

---

## 6. Transport and Propagation

### 6.1 HTTP Response Headers (Normative)

Implementations using HTTP-based transports MUST support disclosing server identity via response headers:

```
Capiscio-Server-DID: <did>
Capiscio-Server-Badge: <trust_badge_jws>
```

Requirements:

* `Capiscio-Server-DID` MUST be present when server identity disclosure is enabled.
* `Capiscio-Server-Badge` SHOULD be present for Trust Levels 0–4 (required for Levels 1–4).
* These headers MUST be treated as **server-to-client** disclosure only.
* This RFC does not redefine MCP authorization headers. MCP's `Authorization: Bearer <access-token>` remains reserved for OAuth access tokens in HTTP transports.

### 6.2 Non-HTTP Transports (MCP / JSON-RPC) (Normative)

For JSON-RPC transports like MCP (including stdio), the server identity MUST be disclosed in a standardized metadata field.

The server identity MUST be included in the result of the MCP `initialize` response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "capabilities": { "...": "..." },
    "_meta": {
      "capiscio_server_did": "<did>",
      "capiscio_server_badge": "<trust_badge_jws>"
    }
  }
}
```

Notes:

* `capiscio_server_badge` is optional but recommended.
* For stdio, this mechanism avoids mixing non-protocol output on stdout (MCP requires stdout remain valid protocol messages).
* This pattern is consistent with RFC-004 `_meta` propagation conventions.

---

## 7. Client Verification (Normative)

Given a disclosed DID and optional badge, a client verifies as follows.

### 7.1 Inputs

* `server_did` from transport mapping (Section 6).
* Optional `server_badge` from transport mapping (Section 6).
* Client trust configuration:
  * `trusted_issuers` — list of trusted badge issuers
  * `min_trust_level` — minimum required trust level (optional)
  * `offline_mode` — whether to skip online revocation checks (optional)
  * `accept_level_zero` — whether to accept self-signed badges (optional, default `false` in production)

### 7.2 Algorithm

1. **No DID disclosed:**
   * Classify server as `UNVERIFIED_ORIGIN`.
   * This is NOT Trust Level 0. The server has presented no cryptographic identity.
   * Apply local policy (typically: block or warn).
   * STOP.

2. **DID disclosed, no badge:**
   * Classify server as `DECLARED_PRINCIPAL`.
   * The server claims an identity but has not proven it cryptographically.
   * Apply local policy.
   * STOP.

3. **Badge verification (RFC-002):**
   * Verify badge signature is valid.
   * Verify `exp` (expiration) is in the future.
   * Verify `sub` (subject) matches `server_did`.
   * Verify issuer is in `trusted_issuers` for the badge's trust level.

4. **Trust level enforcement:**
   * Extract trust level from badge.
   * If trust level is 0 (self-signed, `did:key` issuer):
     * Clients SHOULD reject by default in production unless `accept_level_zero` is `true`.
     * Self-signed badges are appropriate for development and testing only.
   * If `min_trust_level` is configured, reject badges below that level.

5. **Revocation check:**
   * For Trust Levels 1–4 (CA-issued), clients SHOULD check revocation status when online.
   * Clients MAY operate in offline mode with cached trust stores.
   * Revocation check failure SHOULD be treated as verification failure.

6. **Origin binding (transport-dependent):**

   Origin binding verifies that the disclosed DID corresponds to the transport endpoint. The applicability depends on the MCP transport in use.

   **6a. HTTP Streamable Transport:**

   For HTTP-based MCP endpoints, clients SHOULD verify origin binding when `did:web` is used:

   * **Host binding (RECOMMENDED):** If `server_did` is `did:web:<host>:...`, verify that `<host>` matches the HTTP origin host.
   * **Path binding (SHOULD for multi-server deployments):** If `server_did` includes path components (e.g., `did:web:example.com:mcp:filesystem`), the DID path SHOULD correspond to the MCP endpoint URL path.

   Examples:

   | MCP Endpoint URL | Expected Server DID | Notes |
   |------------------|---------------------|-------|
   | `https://mcp.example.com/` | `did:web:mcp.example.com` | Single server per subdomain |
   | `https://api.example.com/mcp/filesystem` | `did:web:api.example.com:mcp:filesystem` | Path-based multi-server |
   | `https://api.example.com/mcp/database` | `did:web:api.example.com:mcp:database` | Path-based multi-server |

   **6b. stdio Transport:**

   For stdio-based MCP servers (subprocess), there is no network origin. Origin binding is NOT APPLICABLE.

   * Clients MAY use `did:key` for local/development servers.
   * Clients MAY use `did:web` if the server binary is associated with a known publisher, but no runtime binding check is possible.

   **6c. Gateway/Proxy Deployments:**

   When MCP servers are deployed behind a gateway or reverse proxy:

   * The disclosed DID identifies the **logical MCP server**, not the gateway infrastructure.
   * The gateway host MAY differ from the DID host if the gateway is a transparent routing layer.
   * Clients SHOULD document their gateway trust model and MAY skip host binding when a trusted gateway is configured.

7. **Result:**
   * If all checks pass, classify as `VERIFIED_PRINCIPAL` with the badge's trust level.
   * If any check fails, classify as `DECLARED_PRINCIPAL` and apply local policy.

---

## 8. Error Codes

When server identity verification fails, implementations SHOULD use standardized error codes:

| Code                          | Description                                              |
| ----------------------------- | -------------------------------------------------------- |
| `SERVER_IDENTITY_MISSING`     | No server identity disclosed (`UNVERIFIED_ORIGIN`)       |
| `SERVER_BADGE_MISSING`        | DID disclosed but no badge (`DECLARED_PRINCIPAL`)        |
| `SERVER_BADGE_INVALID`        | Badge signature or expiry verification failed            |
| `SERVER_BADGE_REVOKED`        | Server badge has been revoked                            |
| `SERVER_TRUST_INSUFFICIENT`   | Trust level below required `min_trust_level`             |
| `SERVER_DID_MISMATCH`         | Badge subject does not match disclosed DID               |
| `SERVER_ISSUER_UNTRUSTED`     | Badge issuer not in `trusted_issuers`                    |
| `SERVER_DOMAIN_MISMATCH`      | `did:web` host does not match transport origin           |
| `SERVER_PATH_MISMATCH`        | `did:web` path does not match MCP endpoint path          |

These codes align with RFC-006 error conventions.

---

## 9. Minimal Discovery Document (Optional)

To support out-of-band discovery of server identity (without defining a registry), an MCP server MAY publish a discovery document at:

```
/.well-known/capiscio/mcp-server.json
```

Example:

```json
{
  "server_did": "did:web:mcp.example.com:servers:filesystem",
  "server_badge": "<trust_badge_jws>",
  "trust_level": 2,
  "updated_at": "2026-01-15T00:00:00Z"
}
```

Rules:

* `server_did` MUST match the in-band disclosed DID when both are enabled.
* Clients MAY use this document to pre-fetch identity and cache verification results.
* This RFC does not define indexing, search, or listing APIs.

---

## 10. Security Considerations

* Clients MUST distinguish between:
  * **Transport authenticity** (e.g., TLS channel to a domain)
  * **Principal identity** (CapiscIO DID + badge)

* **Unverified Origin ≠ Trust Level 0:**
  * `UNVERIFIED_ORIGIN` = no identity presented (unknown principal)
  * Trust Level 0 = self-signed identity (known principal, unattested)

* **Failure policy:**
  * Verification failures SHOULD result in `DECLARED_PRINCIPAL` (if DID was disclosed) or `UNVERIFIED_ORIGIN` (if not).
  * Clients enforcing high assurance SHOULD fail closed when `min_trust_level` is required.

* **Replay protection:**
  * Badge expiration (`exp`) provides time-bound validity.
  * Short-lived badges reduce replay window.

---

## 11. Implementation Notes (Non-Normative)

* For MCP stdio servers, identity disclosure should occur during `initialize` to keep stdout protocol-clean.
* For HTTP servers, response headers provide a low-friction disclosure mechanism with no MCP schema changes.
* Logging and evidence for server verification state should follow the structured logging conventions defined in RFC-006 telemetry schemas.

---

## 12. Future Work

* Optional registry/discovery APIs for curated server catalogs.
* Standard UI patterns for "verified vs declared vs unverified" server surfaces.
* Negotiation of server identity within MCP capability exchange beyond `_meta`.
* Cross-registry federation for server identity.

---

## Changelog

| Version | Date       | Changes                                                                                         |
| ------- | ---------- | ----------------------------------------------------------------------------------------------- |
| 0.4     | 2026-01-15 | Expanded origin binding for HTTP, stdio, and gateway patterns. Added path binding for multi-server deployments. |
| 0.3     | 2026-01-15 | Distinguished `UNVERIFIED_ORIGIN` from Trust Level 0. Added error codes. Editorial cleanup.     |
| 0.2     | 2026-01-15 | Aligned headers to `Capiscio-Server-*`. Added revocation. Added changelog. Structural refactor. |
| 0.1     | 2026-01-15 | Initial draft.                                                                                  |
