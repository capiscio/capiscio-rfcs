# RFC-010: Intent Classification and Policy Intelligence

**Version:** 1.0  
**Status:** Draft
**Authors:** CapiscIO Core Team  
**Created:** 2026-04-30  
**Updated:** 2026-04-30  
**Requires:** RFC-001 (AGCP), RFC-005 (Policy Definition, Distribution & Enforcement), RFC-008 (Delegated Authority Envelopes), RFC-009 (Pre-Authorized Action Manifest Protocol)

---

## 1. Abstract

This RFC defines the **Intent Classification and Policy Intelligence** layer — a two-component system that provides adaptive intelligence above the deterministic enforcement substrate defined by RFC-009.

The two components are architecturally and functionally distinct:

**Component A — Agent-Side Classifier:** An ephemeral sub-agent, provisioned automatically at `CapiscIO.connect()` time, that classifies each proposed tool call against a five-axis risk taxonomy and a capability class vocabulary before the RFC-009 Step 1 enforcement check executes. The classifier is a separate process from the agent under governance, operating under its own session-scoped identity and system prompt. Its output is an advisory classification verdict consumed by the RFC-009 PEP. The block, when it occurs, happens at the RFC-009 enforcement gate — not at the classifier.

**Component B — Server-Side Policy Recommendation Engine:** A server-side system that analyzes the event corpus accumulated from RFC-009 enforcement decisions and RFC-010 classification events, and surfaces human-reviewable recommendations for Action Manifest refinements. Approved recommendations update the agent's registered manifest. Declined recommendations are logged. No manifest update occurs without explicit human approval.

Neither component makes authorization decisions. The RFC-009 PEP is the sole authoritative enforcement boundary.

This specification defines:

* The five-axis classification taxonomy and its reliability tiers.
* Default axis profile: the minimum reliable axis set for production deployments.
* Confidence weighting model for multi-axis composite scoring.
* The Classifier Sub-Agent: identity model, context isolation requirements, integration contract, and session lifecycle.
* Classifier integration model: interface contract for external LLM providers. CapiscIO does not host a classifier; operators integrate a supported provider.
* The Policy Recommendation Engine: event corpus analysis, recommendation schema, and human approval workflow.
* Dashboard representation of classifier sub-agents and recommendation events.
* The `capiscio.intent_classified` event type.

---

## 2. Relationship to Other RFCs

| CapiscIO RFC | Relationship to This Specification |
|---|---|
| RFC-001 (AGCP) | RFC-010 operates strictly within RFC-001's declared-intent model. The classifier does not infer intent from natural language to authorize actions. It classifies the structural properties of a proposed tool call against a pre-defined taxonomy. The authorization decision remains with the RFC-009 PEP under RFC-001's enforcement model. |
| RFC-005 (Policy Enforcement) | RFC-010 classification verdicts are projected into the RFC-005 PIP attribute set as additional inputs to the PDP query. The PDP MAY use classifier verdicts in policy rules but is not required to. |
| RFC-008 (Delegated Authority Envelopes) | RFC-010 classification operates within the authority bounds established by RFC-008. The classifier does not modify or extend delegation chains. |
| RFC-009 (Pre-Authorized Action Manifest) | RFC-010 is the intelligence layer that enriches RFC-009 enforcement. RFC-010 classifier output is consumed at RFC-009 Step 1 (§7.2, sub-step 8). The RFC-009 PEP is the enforcement gate. RFC-010 adds signal; RFC-009 makes the decision. |

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|---|---|
| **Classifier Sub-Agent** | An ephemeral, session-scoped agent provisioned automatically by `CapiscIO.connect()` that classifies tool calls against the five-axis taxonomy. Operates under a distinct DID and context window from the agent under governance. |
| **Five-Axis Taxonomy** | The five orthogonal dimensions along which a proposed tool call is classified: Action Type, Boundary, Sensitivity, Scale, and Reversibility. Each axis is independent and carries distinct risk information. |
| **Default Axis Profile** | The minimum required axis set for RFC-010 compliance: Action Type and Boundary. These two axes are locally determinable, require no external integration, and produce reliable classifications. |
| **Extended Axis Profile** | The full five-axis set. Sensitivity, Scale, and Reversibility are OPTIONAL axes that require additional integration or accept reduced reliability. |
| **Axis Confidence Score** | A per-axis floating-point value in [0.0, 1.0] representing the classifier's confidence in its classification for that axis. |
| **Composite Confidence Score** | A weighted aggregate of per-axis confidence scores. Used by the RFC-009 PEP to determine whether to proceed, escalate, or apply conservative defaults. |
| **Confidence Threshold** | The minimum composite confidence score below which the RFC-009 PEP routes to the escalation handler rather than proceeding. Default: 0.7. Configurable per deployment. |
| **Conservative Default** | The fallback classification applied when an axis cannot be classified with sufficient confidence. Each axis has a defined conservative default that errs toward higher restriction. |
| **Policy Recommendation Engine** | The server-side component that analyzes RFC-009 and RFC-010 event corpora to surface human-reviewable Action Manifest refinement recommendations. |
| **Recommendation** | A proposed change to an agent's registered Action Manifest, produced by the Policy Recommendation Engine. Requires explicit human approval before any manifest update occurs. |
| **Session-Scoped DID** | A DID issued to the Classifier Sub-Agent for the duration of a single agent session. Derived from the parent agent's trust chain. Revoked automatically at session close. |
| **capiscio.intent_classified** | The event type emitted by the RFC-010 classifier after each tool call classification. Correlated to `capiscio.policy_enforced` events by `txn_id`. |

---

## 4. Goals and Non-Goals

### 4.1 Goals

* Provide a structured classification layer that enriches RFC-009 enforcement with actionable per-axis risk signals.
* Define a default axis profile that is reliable by default, without requiring external data catalog integration.
* Define confidence weighting that degrades gracefully when optional axes produce uncertain results.
* Define a Classifier Sub-Agent architecture that is cryptographically isolated from the agent under governance.
* Define an integration model that supports multiple external LLM providers without CapiscIO hosting inference infrastructure.
* Define a Policy Recommendation Engine that improves Action Manifest accuracy over time without bypassing human governance.
* Achieve zero developer friction: all RFC-010 provisioning is handled by `CapiscIO.connect()`.

### 4.2 Normative Constraint — Classifier Output Usage

RFC-010 classifier outputs are advisory signal. The following constraint is normative and applies to all implementations:

> `classification.*` attributes produced by the RFC-010 Classifier MUST NOT be the sole basis for a DENY decision. Implementations MUST NOT use classifier-derived fields as primary authorization conditions in PDP policy rules.

Classifier outputs MAY be used for:
* Escalation routing when composite confidence is below threshold.
* Enrichment of audit and observability event payloads.
* Input to the Policy Recommendation Engine for manifest refinement suggestions.
* Informational signals in policy rules, when combined with deterministic attributes.

Classifier outputs MUST NOT be used for:
* Standalone DENY conditions without deterministic corroboration from RFC-009 Step 1A or Step 1B.
* Overriding the results of Step 1A Capability Binding Validation.
* Determining whether a tool call's action signature matches a registered binding.

This constraint exists because classifier outputs are probabilistic and subject to the reliability limitations documented in §5.1. The deterministic enforcement floor is defined by RFC-009 Steps 1A and 1B. The RFC-010 classifier enriches that floor; it does not replace it.

### 4.3 Non-Goals

* RFC-010 does not make authorization decisions. The RFC-009 PEP is the sole enforcement boundary.
* RFC-010 does not solve general-purpose natural language intent classification for open-ended LLM agents. The five-axis taxonomy classifies the structural properties of proposed tool calls, not semantic user intent.
* RFC-010 does not define behavioral trust scoring or dynamic trust level evolution based on observed behavior over time. That is addressed by a future RFC.
* RFC-010 does not define the classifier model itself. It defines the interface contract that a compliant classifier must satisfy.
* RFC-010 does not require operators to enable the Extended Axis Profile. The Default Axis Profile (Action Type + Boundary) is sufficient for RFC-010 compliance.

---

## 5. The Five-Axis Classification Taxonomy

### 5.1 Overview

RFC-010 classifies each proposed tool call across five orthogonal axes. Each axis captures distinct risk information that the others do not. The axes are:

| Axis | Values | Reliability Tier | Determinability |
|---|---|---|---|
| Action Type | Read, Write, Execute, Orchestrate, Provision | HIGH | Locally determinable from tool invocation metadata |
| Boundary | Local, Intra-org, External | HIGH | Locally determinable from target endpoint configuration |
| Sensitivity | Public, Internal, Confidential, Restricted, Regulated | MEDIUM | Requires data catalog integration or resource path inference |
| Scale | Targeted, Bounded, Unbounded | MEDIUM-LOW | Unknowable for reads until after execution; declarable for writes |
| Reversibility | Reversible, Recoverable, Irreversible | LOW | Requires system topology knowledge; conservative default applies |

### 5.2 Axis Definitions

**Action Type.** The category of operation the tool call performs. Directly derivable from the tool name, method signature, and declared capability class. This axis is REQUIRED in the Default Axis Profile.

* Read: retrieves data without mutation. No side effects.
* Write: creates or mutates a bounded set of records.
* Execute: invokes a process, workflow, or external computation.
* Orchestrate: spawns or delegates to one or more sub-agents.
* Provision: creates persistent capabilities, credentials, or service configurations that outlast the current session.

**Boundary.** The trust domain within which the tool call operates. Derivable from the target endpoint's network address and the configured trust zone registry. This axis is REQUIRED in the Default Axis Profile.

* Local: same process or host. No network traversal.
* Intra-org: within the organization's defined trust perimeter. Internal endpoints, private networks.
* External: crosses the organization's trust boundary. Third-party APIs, public internet.

**Sensitivity.** The data classification tier of the resources the tool call accesses or produces. Requires integration with an organizational data catalog (Collibra, Alation, or equivalent) or inference from resource path patterns. OPTIONAL axis.

* Public: non-sensitive, publicly accessible data.
* Internal: business-confidential, not publicly accessible.
* Confidential: commercially sensitive, restricted distribution.
* Restricted: access controlled, audit required.
* Regulated: subject to legal or regulatory constraints (HIPAA, PCI DSS, GDPR, etc.).

**Scale.** The extent of data or resources affected by the tool call. Reliably determinable for write operations from request parameters. Often unknowable for read operations until after execution. OPTIONAL axis.

* Targeted: a single, identified record or resource.
* Bounded: a defined, finite set of records within a declared scope.
* Unbounded: no explicit upper bound on affected records or resources.

**Reversibility.** Whether the effects of the tool call can be undone. The least reliably classifiable axis; depends on downstream system topology, backup availability, and timing. OPTIONAL axis. Conservative default is IRREVERSIBLE.

* Reversible: effects can be fully undone by a compensating operation.
* Recoverable: effects can be partially undone or restored from backup within a defined window.
* Irreversible: effects cannot be undone. Deletion, external commitments, cascade triggers.

### 5.3 Reliability Tiers and Conservative Defaults

When a classifier cannot achieve sufficient confidence on an axis, the conservative default MUST be applied. Conservative defaults always select the higher-restriction value:

| Axis | Conservative Default | Rationale |
|---|---|---|
| Action Type | Write | Errs toward assuming mutation |
| Boundary | External | Errs toward assuming trust boundary crossing |
| Sensitivity | Restricted | Errs toward assuming sensitive data |
| Scale | Unbounded | Errs toward assuming large-scale impact |
| Reversibility | Irreversible | Errs toward assuming permanent effect |

A conservative default does NOT automatically trigger a block. It means the composite confidence score will reflect the reduced reliability, which may trigger escalation if the composite score falls below the configured threshold.

### 5.4 Default Axis Profile vs. Extended Axis Profile

**Default Axis Profile (REQUIRED for RFC-010 compliance):**

* Action Type — MUST be classified on every tool call.
* Boundary — MUST be classified on every tool call.

These two axes are locally determinable without external integration and produce consistently reliable classifications. A deployment that classifies only these two axes achieves meaningful security signal with minimal operational overhead.

**Extended Axis Profile (OPTIONAL, operator-configured):**

* Sensitivity — MAY be enabled if a data catalog integration is available.
* Scale — MAY be enabled. For write operations, Scale is declared in the tool call parameters. For read operations, Scale is classified conservatively as Unbounded unless the query includes explicit bounds.
* Reversibility — MAY be enabled. Conservative default (Irreversible) applies whenever the classifier confidence is below threshold. Operators SHOULD treat low-confidence Reversibility classifications as Irreversible in all escalation routing logic.

Profile selection is configured in the operator's deployment settings, not in developer code.

---

## 6. Confidence Weighting Model

### 6.1 Per-Axis Confidence Scores

The classifier MUST return a confidence score for each axis it classifies, expressed as a floating-point value in [0.0, 1.0].

* 0.0: no confidence — conservative default will be applied.
* 0.5: uncertain — classification is plausible but not reliable.
* 0.7: confident — classification is reliable for most enforcement purposes.
* 1.0: certain — deterministic classification from structural metadata.

For Action Type and Boundary, well-configured classifiers SHOULD achieve confidence ≥ 0.9 on the large majority of tool calls, since both axes are derivable from structured metadata rather than semantic inference.

For Sensitivity, Scale, and Reversibility, confidence will vary significantly based on available integration depth. Operators SHOULD not expect average confidence above 0.7 for these axes without data catalog integration.

### 6.2 Composite Confidence Score

The composite confidence score is computed as a weighted average of active axis scores:

```
composite = Σ (axis_weight[i] × axis_confidence[i]) / Σ axis_weight[i]
```

Default axis weights:

| Axis | Default Weight | Notes |
|---|---|---|
| Action Type | 0.40 | Highest weight — most reliable, most impactful |
| Boundary | 0.30 | High weight — reliable, directly governs trust boundary enforcement |
| Sensitivity | 0.15 | Lower weight — reliable only with catalog integration |
| Scale | 0.10 | Low weight — often uncertain for reads |
| Reversibility | 0.05 | Lowest weight — least reliable axis |

Axis weights are configurable per deployment. Operators who do not enable an optional axis MUST redistribute its weight among the active axes proportionally. The weights for active axes MUST sum to 1.0.

### 6.3 Threshold Behavior

| Composite Score | Default Behavior |
|---|---|
| ≥ 0.85 | Proceed. High confidence. Full classification passed to RFC-009 PEP. |
| 0.70 – 0.84 | Proceed with logging. Moderate confidence. Conservative defaults applied to low-confidence axes. |
| 0.50 – 0.69 | Escalate to escalation handler (RFC-009 §9). Classification is uncertain. |
| < 0.50 | Mandatory escalation. Insufficient confidence to classify. Emit `INTENT_CLASSIFICATION_MISMATCH` with `reason: LOW_CONFIDENCE`. PEP routes to escalation handler — PEP MUST NOT deny solely on low composite confidence. The escalation handler decides disposition per RFC-009 §9.2. |

Threshold values are configurable per deployment. The defaults above are RECOMMENDED for production.

---

## 7. Classifier Sub-Agent Architecture

### 7.1 Design Principles

The Classifier Sub-Agent MUST satisfy four architectural properties:

1. **Separate context window.** The classifier sees only a structured action descriptor for each tool call. It does not receive the agent's conversation history, system prompt, user messages, or accumulated context. This limits the attack surface to the action descriptor and prevents prompt injection in the agent's context from reaching the classifier.

2. **Separate trust domain.** The classifier operates under a distinct session-scoped DID, separate from the agent under governance. The agent cannot instruct the classifier directly. The classifier receives its input from the RFC-009 PEP intercept layer, not from the agent.

3. **Separate system prompt and policy corpus.** The classifier's instructions come from the RFC-010 configuration bundle (capability class vocabulary, axis definitions, tool inventory snapshot). The agent cannot modify the classifier's instructions.

4. **Read-only relative to authorization.** The classifier MUST NOT issue, modify, or extend Authority Envelopes or Action Manifests. It produces a classification verdict only. The RFC-009 PEP applies that verdict.

### 7.2 Session Lifecycle

The Classifier Sub-Agent lifecycle is bound to the parent agent session:

```
CapiscIO.connect() called
    │
    ▼
Classifier Sub-Agent provisioned
    ├── Session-scoped DID issued (derived from parent agent trust chain)
    ├── Tool inventory snapshot fetched and version-hashed
    ├── RFC-010 configuration bundle fetched (axis weights, thresholds, profile)
    ├── External LLM provider connection initialized
    └── Classifier registered in session audit log
    │
    ▼ [Tool calls during session]
    │
    ▼
Agent session closes
    ├── Classifier Sub-Agent DID revoked
    ├── Session audit log flushed to server
    └── Tool inventory snapshot discarded
```

### 7.3 Session-Scoped DID

The Classifier Sub-Agent is issued a session-scoped DID of the form:

```
did:capiscio:session:<parent_agent_did_fragment>:<session_uuid>
```

Example:
```
did:capiscio:session:taxbot.example-agents-taxbot:018f4e1d-7e5d
```

This DID:
* Is valid only for the duration of the session.
* Cannot issue Trust Badges.
* Cannot create or sign Authority Envelopes.
* Appears in session audit logs and the dashboard System Agents section.
* Is automatically revoked when the session closes (TTL = session duration).

The `did:capiscio` method is defined by this specification for session-scoped ephemeral identifiers. It is not a W3C-registered DID method. Implementations MUST NOT use `did:capiscio` DIDs outside the scope of RFC-010 session lifecycle management.

### 7.4 Action Descriptor

The only input the Classifier Sub-Agent receives per tool call is a structured action descriptor. This descriptor is constructed by the RFC-009 PEP from tool call metadata and MUST NOT include conversational context.

```json
{
  "tool_name": "write_invoice",
  "tool_description": "Creates or updates an invoice record in the Acme finance system.",
  "capability_class_declared": "finance.invoicing.management",
  "action_type_declared": "Write",
  "boundary_declared": "Intra-org",
  "parameters": {
    "invoice_id": "INV-2024-0042",
    "amount": 4250.00,
    "vendor_id": "ACME-SUPPLIES-001"
  },
  "target_endpoint": "https://finance.acme.internal/api/invoices",
  "tool_inventory_hash": "a1b2c3d4...",
  "session_id": "018f4e1d-7e5d"
}
```

Parameters are included to enable Scale classification (bounded vs. unbounded queries). The classifier MUST NOT retain parameter values between calls. Each action descriptor is evaluated independently.

### 7.5 Classification Verdict

The classifier returns a structured verdict for each action descriptor:

```json
{
  "session_id": "018f4e1d-7e5d",
  "tool_name": "write_invoice",
  "axes": {
    "action_type": {
      "classified": "Write",
      "confidence": 0.97,
      "source": "tool_metadata"
    },
    "boundary": {
      "classified": "Intra-org",
      "confidence": 0.95,
      "source": "endpoint_config"
    },
    "sensitivity": {
      "classified": "Confidential",
      "confidence": 0.63,
      "source": "resource_path_inference"
    },
    "scale": {
      "classified": "Targeted",
      "confidence": 0.88,
      "source": "parameter_analysis"
    },
    "reversibility": {
      "classified": "Reversible",
      "confidence": 0.51,
      "conservative_default_applied": false,
      "source": "llm_inference"
    }
  },
  "capability_class_verdict": "finance.invoicing.management",
  "capability_class_confidence": 0.94,
  "composite_confidence": 0.87,
  "consistent_with_declaration": true,
  "classifier_did": "did:capiscio:session:taxbot.example-agents-taxbot:018f4e1d",
  "classified_at": 1746000124
}
```

The `consistent_with_declaration` field is `true` when the classifier's capability class verdict matches the declared class in the Intent Envelope. When `false`, the RFC-009 PEP emits `INTENT_CLASSIFICATION_MISMATCH`.

### 7.6 Tool Inventory Snapshot

At `CapiscIO.connect()` time, the Classifier Sub-Agent receives a version-hashed snapshot of the available tool inventory:

* Tool names and descriptions from all connected MCP servers.
* A2A Agent Card skills from registered downstream agents.
* The capability class manifest (RFC-009) for this agent.

The snapshot is signed by the CapiscIO server at delivery time. The classifier MUST reject tool inventory updates that do not carry a valid server signature. If the tool inventory changes mid-session (new MCP server attached, new tool registered), the classifier is re-initialized with the updated inventory and the re-initialization is logged in the session audit record.

The tool inventory snapshot is the classifier's primary source of knowledge about the available action surface. It does not have access to the internet or external knowledge sources during classification.

---

## 8. Classifier Integration Model

### 8.1 CapiscIO Does Not Host Inference Infrastructure

RFC-010 does not require CapiscIO to host or operate a classifier model. Operators integrate an external LLM provider via the RFC-010 Classifier Integration Contract. CapiscIO publishes reference configurations for supported providers.

This design decision reflects two principles: (a) hosting a high-performance LLM is cost-prohibitive for early-stage deployments, and (b) the classifier integration model is itself a form of operator governance — operators choose the model that matches their security posture and budget.

### 8.2 Classifier Integration Contract

Any LLM provider integration MUST satisfy the following interface contract:

**Input:** The action descriptor JSON defined in §7.4, serialized as a string.

**System prompt:** A standardized classification prompt distributed by CapiscIO as part of the RFC-010 configuration bundle. Operators MUST NOT modify the system prompt. The system prompt embeds the five-axis taxonomy definitions, the capability class vocabulary for this agent, and the tool inventory snapshot.

**Output:** A classification verdict JSON matching the schema defined in §7.5. The integration MUST parse the model's response and validate it against the verdict schema before returning it to the RFC-009 PEP. If the model's response cannot be parsed as a valid verdict, the integration MUST return a verdict with `composite_confidence: 0.0` and `consistent_with_declaration: false`.

**Latency requirement:** The classifier MUST return a verdict within the configured timeout (default: 2 seconds). Infrastructure deployments with high call volume SHOULD target sub-second classification latency. If the timeout is exceeded, the integration MUST return a low-confidence verdict (not block or error). The RFC-009 PEP then applies threshold behavior per §6.3. Classification SHOULD execute in parallel with RFC-009 Step 1A and Step 1B where the PEP architecture permits, so that classifier latency does not add to the critical path when Steps 1A and 1B pass.

**Statelessness:** The integration MUST NOT pass conversation history between calls. Each action descriptor is classified independently.

### 8.3 Recommended Providers

CapiscIO publishes reference configurations for the following integrations. Recommendations are based on empirical evaluation of classification accuracy on the five-axis taxonomy (as of publication date — consult docs.capisc.io/rfc010/providers for current recommendations):

| Provider | Model | Profile | Notes |
|---|---|---|---|
| Anthropic | claude-haiku-4 | Accuracy | Highest classification accuracy on Sensitivity and Reversibility axes. Recommended for high-assurance deployments where Extended Axis Profile is enabled. |
| OpenAI | gpt-4o-mini | Speed / Cost | Best cost-per-classification ratio. Reliable on Action Type and Boundary (Default Axis Profile). Recommended as default for most deployments. |
| Google | gemini-2.0-flash | Balanced | Strong on boundary classification. Good cost profile. Recommended for deployments with high call volume. |
| Local (Ollama) | llama3.2:3b | Air-gapped | For deployments with no external network egress. Accuracy on optional axes is reduced. Only Default Axis Profile recommended. |

Provider configurations are maintained in the CapiscIO documentation at docs.capisc.io/rfc010/providers. Operators configure the provider in deployment settings, not in developer code.

### 8.4 Provider Configuration

Provider selection is configured in the CapiscIO dashboard under Agent Settings > Intent Classification. The configuration includes:

* Provider (Anthropic, OpenAI, Google, Local, or custom endpoint)
* API key (stored encrypted in the CapiscIO secrets store; never exposed to developer code)
* Active axis profile (Default or Extended)
* Axis weights (if overriding defaults)
* Confidence threshold (if overriding default 0.7)
* Timeout (default 2 seconds)

None of these settings require developer code changes. `CapiscIO.connect()` fetches the active configuration at session initialization.

### 8.5 classification.* PIP Attribute Namespace

RFC-010 classifier output is projected into the RFC-005 PIP attribute space under the `classification.*` namespace. This namespace is segregated from all deterministic enforcement attributes to enforce the constraint defined in §4.1.

**Namespace definition:**

| PIP Attribute | Source | Description |
|---|---|---|
| `classification.action_type` | Axis verdict | Classifier-determined action type. One of: Read, Write, Execute, Orchestrate, Provision. |
| `classification.action_type_confidence` | Axis confidence | Per-axis confidence score in [0.0, 1.0]. |
| `classification.boundary` | Axis verdict | Classifier-determined boundary. One of: Local, Intra-org, External. |
| `classification.boundary_confidence` | Axis confidence | Per-axis confidence score. |
| `classification.sensitivity` | Axis verdict | Classifier-determined sensitivity tier. Present only when Extended Axis Profile is active and Sensitivity axis is enabled. |
| `classification.sensitivity_confidence` | Axis confidence | Per-axis confidence score. |
| `classification.scale` | Axis verdict | Classifier-determined scale. Present only when Extended Axis Profile is active. |
| `classification.scale_confidence` | Axis confidence | Per-axis confidence score. |
| `classification.reversibility` | Axis verdict | Classifier-determined reversibility. Present only when Extended Axis Profile is active. |
| `classification.reversibility_confidence` | Axis confidence | Per-axis confidence score. |
| `classification.composite_confidence` | Composite score | Weighted aggregate across all active axes. |
| `classification.capability_class_match` | Verdict | Boolean. Whether the classifier's capability class verdict matches the declared class on the Intent Envelope. |

**Usage constraint (normative):** PDP deny rules MUST NOT be written with a `classification.*` attribute as the sole condition. If a PDP deny decision is based exclusively on `classification.*` fields, the RFC-009 PEP MUST detect this and log a `CLASSIFIER_SOLE_DENY_VIOLATION` event, then re-evaluate the decision without classifier fields. This detection is implemented by the PEP, which tracks which attribute groups were present in the PDP input and whether the deny reason references only `classification.*` fields.

**Dashboard enforcement:** The CapiscIO policy dashboard editor MUST display a visual warning when a policy author writes a DENY rule where every condition references a `classification.*` attribute and no deterministic attribute is present. The warning text is: "This deny rule depends solely on classifier output. Classifier verdicts are probabilistic and MUST NOT be the sole basis for a deny decision. Add a deterministic condition or restructure as an escalation rule."

---

## 9. Dashboard Integration

### 9.1 Classifier Sub-Agents in the Dashboard

Classifier Sub-Agents appear in the dashboard under a dedicated **System Agents** section, visually and structurally separate from registered agent identities. They are not listed in the Agent Registry.

System Agents display:

* Session-scoped DID
* Parent agent DID
* Session start and close timestamps
* Total tool calls classified in session
* Mismatch count (calls where `consistent_with_declaration: false`)
* Active axis profile and provider
* Tool inventory snapshot hash and version

### 9.2 `capiscio.intent_classified` Event

After each tool call classification, the Classifier Sub-Agent emits a `capiscio.intent_classified` event to `POST /v1/events`.

```json
{
  "event_type": "capiscio.intent_classified",
  "session_id": "018f4e1d-7e5d",
  "txn_id": "018f4e1d-7e5d-7a9f-a9d2-8b6a0f2c9b11",
  "tool_name": "write_invoice",
  "classifier_did": "did:capiscio:session:taxbot.example-agents-taxbot:018f4e1d",
  "parent_agent_did": "did:web:taxco.example:agents:taxbot",
  "capability_class_declared": "finance.invoicing.management",
  "capability_class_verdict": "finance.invoicing.management",
  "consistent_with_declaration": true,
  "composite_confidence": 0.87,
  "axes": { "...": "..." },
  "active_profile": "extended",
  "classified_at": 1746000124
}
```

This event is correlated to the corresponding `capiscio.policy_enforced` event by `txn_id`. The event viewer shows both events side by side: what the classifier determined, and what the PEP decided.

### 9.3 Mismatch Events

When `consistent_with_declaration: false`, the `capiscio.intent_classified` event is surfaced in the dashboard as a high-severity alert alongside the `INTENT_CLASSIFICATION_MISMATCH` policy enforcement event. The operator sees:

* What capability class was declared by the agent
* What capability class the classifier determined
* Which axis produced the mismatch
* The composite confidence at time of mismatch
* The pending tool call that was blocked

Persistent mismatch patterns (the same agent repeatedly declaring one class while the classifier consistently determines another) are automatically flagged as Policy Recommendation candidates.

---

## 10. Policy Recommendation Engine

### 10.1 Purpose

The Policy Recommendation Engine analyzes the accumulated event corpus from RFC-009 and RFC-010 events and surfaces recommendations for Action Manifest refinements. Its purpose is to improve manifest accuracy over time as agent behavior is observed, without requiring manual analysis by operators.

The recommendation engine is a server-side component. It is not part of the agent's runtime path and does not affect enforcement decisions.

### 10.2 Event Corpus

The recommendation engine operates on events correlated by agent DID:

* `capiscio.policy_enforced` events: which tool calls were allowed, which were denied, and why.
* `capiscio.intent_classified` events: classifier verdicts, confidence scores, and mismatch flags.
* `capiscio.intent_classified` events where `consistent_with_declaration: false`: the most actionable signal for manifest refinement.

The corpus is analyzed on a configurable schedule (default: daily). The recommendation engine does not operate in real time.

### 10.3 Recommendation Types

| Type | Trigger | Proposed Change |
|---|---|---|
| `ADD_TOOL` | A tool appears frequently in `SCOPE_INSUFFICIENT` denials for a given agent and capability class. | Add the tool to `allowed_tools` for that class. |
| `REMOVE_TOOL` | A tool has never been called by an agent in 90 days and does not appear in escalation events. | Remove the tool from `allowed_tools` for that class (reduce attack surface). |
| `ELEVATE_CLASS` | The classifier consistently determines a higher-scope capability class than the one declared. | Add the higher-scope class to the manifest or replace the existing class. |
| `RESTRICT_BOUNDARY` | All observed calls under a capability class use Intra-org boundary; External is declared. | Narrow the `boundary_ceiling` to Intra-org. |
| `SPLIT_CLASS` | A single capability class covers tools with significantly different risk profiles (e.g., Read and Delete in the same class). | Propose splitting into two classes with narrower tool sets. |

### 10.4 Recommendation Schema

```json
{
  "recommendation_id": "rec_a1b2c3d4",
  "agent_did": "did:web:taxco.example:agents:taxbot",
  "current_manifest_hash": "a1b2c3d4...",
  "type": "ADD_TOOL",
  "capability_class": "finance.invoicing.management",
  "proposed_change": {
    "field": "allowed_tools",
    "operation": "add",
    "value": "delete_invoice"
  },
  "evidence": {
    "denial_count_30d": 14,
    "first_observed": "2026-04-01T00:00:00Z",
    "last_observed": "2026-04-29T15:22:10Z",
    "classifier_verdict_consistency": 0.91
  },
  "confidence": 0.88,
  "generated_at": "2026-04-30T06:00:00Z",
  "status": "pending"
}
```

### 10.5 Human Approval Workflow

Every recommendation requires explicit human approval before any manifest change occurs. The approval workflow is:

1. Recommendation appears in the dashboard under Agent Governance > Policy Recommendations.
2. The operator reviews the evidence (denial history, classifier verdict consistency, risk profile of the proposed tool).
3. The operator selects APPROVE or DECLINE.
4. On APPROVE: a new manifest version is created incorporating the change, signed by the CapiscIO server, and registered with a new manifest hash. The agent's `CapiscIO.connect()` call on next session initialization picks up the updated manifest automatically.
5. On DECLINE: the recommendation is archived with the decliner's identity and a required reason code. The same recommendation will not be regenerated for 30 days.
6. The audit trail records: the recommendation, the evidence corpus snapshot, the approver or decliner identity, the decision timestamp, and the resulting manifest hash (on APPROVE).

No manifest update occurs without an explicit human APPROVE action. The recommendation engine cannot update manifests autonomously.

### 10.6 Recommendation Audit Trail

The following fields are recorded for every recommendation decision:

| Field | Description |
|---|---|
| `recommendation_id` | Stable identifier for the recommendation. |
| `decision` | APPROVE or DECLINE. |
| `decided_by_did` | DID of the human operator who made the decision. |
| `decided_at` | Timestamp of the decision. |
| `reason_code` | Required on DECLINE. One of: NOT_NEEDED, SECURITY_CONCERN, INCORRECT_EVIDENCE, DEFERRED. |
| `resulting_manifest_hash` | Hash of the new manifest version on APPROVE. Null on DECLINE. |

---

## 11. Zero Developer Friction

### 11.1 Developer Experience Contract

From the developer's perspective, RFC-010 does not exist. The `@guard` decorator and `CapiscIO.connect()` call are unchanged:

```python
guard = CapiscIO.connect(
    config="policy.yaml"
)

@guard(
    config="policy.yaml",
    capability_class="finance.invoicing.management"
)
async def write_invoice(ctx, params):
    ...
```

The Classifier Sub-Agent is provisioned, runs, and terminates without any developer interaction. Its output is consumed by the RFC-009 PEP without any additional developer configuration.

### 11.2 What Happens Automatically at Connect

When `CapiscIO.connect()` is called, the following RFC-010 initialization occurs automatically:

1. Fetch RFC-010 configuration bundle from server (axis profile, axis weights, confidence thresholds, provider config).
2. Initialize connection to configured LLM provider using server-stored API key.
3. Fetch and version-hash the current tool inventory snapshot.
4. Issue session-scoped DID for the Classifier Sub-Agent.
5. Register session in dashboard System Agents section.
6. Wire classifier into the `@guard` intercept path (between tool dispatch and RFC-009 Step 1 check).

If the configured LLM provider is unreachable at connect time, RFC-010 degrades gracefully: the classifier is marked inactive, all tool calls are classified with `composite_confidence: 0.0`, and the RFC-009 PEP applies conservative defaults and routes to the escalation handler per the configured threshold behavior. The agent is not blocked from starting.

---

## 12. Security Considerations

| Threat | Mitigation |
|---|---|
| Classifier compromise via prompt injection | Separate context window: classifier only sees structured action descriptors, not conversational context. The attack surface is the action descriptor schema, not the full agent context. |
| Agent instructing classifier to misclassify | Classifier receives input from the RFC-009 PEP intercept layer, not from the agent. The agent has no interface to the classifier. |
| Adversarial tool inventory manipulation | Tool inventory snapshot is signed by the CapiscIO server at delivery. Classifier rejects unsigned or invalidly signed inventory updates. |
| LLM sandbagging: classifier deliberately underperforming | Conservative defaults apply when confidence is below threshold. Low-confidence classification routes to escalation, not to allow. The fail path is escalation, not bypass. |
| Provider outage enabling bypass | Classifier outage produces `composite_confidence: 0.0`, which routes to the escalation handler. The agent is not silently permitted to proceed without classification. |
| Recommendation engine approving malicious expansions | Every recommendation requires human APPROVE. The recommendation engine cannot autonomously update manifests. The audit trail records approver identity and evidence snapshot. |
| Session-scoped DID impersonation | Session DIDs are issued by the CapiscIO server and are cryptographically bound to the parent session. They cannot be forged or reused across sessions. |
| Operator policy drift: classifier output used as primary authorization condition | Policy authors may write DENY rules based solely on `classification.*` fields, treating probabilistic signal as authoritative. Mitigated by three mechanisms: (1) §4.1 normative constraint prohibiting classifier-sole DENY rules; (2) `CLASSIFIER_SOLE_DENY_VIOLATION` detection in the PEP with automatic re-evaluation; (3) dashboard policy editor visual warning when a DENY rule has only `classification.*` conditions. The combination of normative RFC constraint, runtime detection, and authoring-time warning creates defense in depth against policy drift. |
| False precision from composite confidence scoring | A composite confidence score may appear precise while masking low reliability on critical axes. Mitigated by: (a) per-axis confidence scores are logged separately, not just the composite; (b) the Policy Recommendation Engine surfaces patterns of low per-axis confidence to operators; (c) conservative defaults on uncertain axes propagate into escalation routing even when composite score appears adequate. |

### 12.1 Important Limitation: Classifier Trust Boundary

The Classifier Sub-Agent is architecturally separated from the agent under governance, but both run on the same host infrastructure. A compromised host can observe or manipulate both. RFC-010 security is not a substitute for host-level isolation in high-assurance deployments. For regulated environments requiring hardware-level isolation, operators SHOULD deploy the Classifier Sub-Agent in a separate runtime environment from the agent under governance.

### 12.2 LLM Reliability Caveat

Published empirical research (AgentDojo, sandbagging benchmarks) demonstrates that LLMs can strategically underperform when aware of evaluation contexts. RFC-010 acknowledges this limitation explicitly: the classifier is an advisory layer, not a primary authorization mechanism. The RFC-009 PEP provides the deterministic enforcement floor. RFC-010 enriches that enforcement with risk signal; it does not replace it. This is the correct division of responsibility and is the architectural reason why the classifier output cannot authorize actions — only the RFC-009 PEP can.

### 12.3 CLASSIFIER_SOLE_DENY_VIOLATION Detection

When the RFC-009 PEP detects that a PDP deny decision was based exclusively on `classification.*` attributes, it MUST:

1. Log a `CLASSIFIER_SOLE_DENY_VIOLATION` warning event with: the `txn_id`, the specific `classification.*` fields that triggered the deny, the PDP rule identifier if available, and the timestamp.

2. Re-evaluate the PDP query with all `classification.*` fields removed from the attribute projection.

3. If the re-evaluated decision is ALLOW: override the deny, permit execution, and report the violation to the server-side Policy Recommendation Engine. The recommendation engine will surface a recommendation to the operator to refactor the policy rule.

4. If the re-evaluated decision is DENY: the deny stands (there is a deterministic basis for the denial, likely from RFC-009 Step 1 or RFC-008 envelope attributes). Log the outcome.

This mechanism prevents false denials caused by classifier noise while preserving legitimate denials grounded in deterministic policy. The violation event is visible in the dashboard under Policy Events, distinct from the Step 1A/1B enforcement events.

---

## 13. Future Work

* **Behavioral Trust Scoring.** Dynamic evolution of an agent's trust level based on observed classification behavior over time — consistent declarations, low mismatch rates, and clean audit history as inputs to a trust score that influences PDP policy. Defined in a future RFC.
* **Classifier Fine-Tuning Pipeline.** As the event corpus grows, CapiscIO will define a pipeline for fine-tuning small classification models on operator-specific tool vocabularies, improving accuracy on the Extended Axis Profile without relying on large general-purpose models.
* **Federated Inventory.** Cross-organizational tool inventory sharing, enabling classifiers to recognize tool surfaces from partner organizations without requiring manual registration.
* **Autonomous Recommendation Tiers.** For low-risk recommendation types (REMOVE_TOOL for tools unused for 180+ days, RESTRICT_BOUNDARY where External is never observed), a future RFC may define an operator-opt-in auto-approval tier with a mandatory 48-hour review window before application.
* **Server-Proxied Classification.** In high-assurance deployments, classifier API keys SHOULD NOT reside on the agent host. A future RFC may define a server-proxied classification mode where the CapiscIO control plane holds LLM provider credentials and the SDK sends action descriptors to the server for forwarding. This eliminates the host-compromise credential exposure described in §12.1 at the cost of an additional network hop (~50–200ms per classification). Operators requiring this trade-off can implement it today as a custom classifier endpoint; a standardized protocol is deferred.

---

## Changelog

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-04-30 | Initial published version. Defines the five-axis classification taxonomy, Default and Extended axis profiles, confidence weighting model, Classifier Sub-Agent architecture and session lifecycle, classifier integration contract, Policy Recommendation Engine, dashboard integration, and `capiscio.intent_classified` event type. |
