# Annex IV Technical Documentation

*Prepared under Article 11 of Regulation (EU) 2024/1689*

---

| Field | Value |
|---|---|
| **Regulation** | EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10 |
| **Coverage matrix version** | v1 |
| **Bundle generated** | 2026-04-10T12:00:00.000Z |
| **Reporting period** | 2026-04-01T00:00:00.000Z → 2026-04-30T23:59:59.999Z |
| **Agent DID** | `did:sanctuary:meridian-hr-screening-agent` |
| **Legal provider** | Meridian Financial Holdings, Inc. |
| **Provider contact** | ai-compliance@meridian.example.com |
| **Intended purpose** | Automated CV screening and candidate shortlisting for open requisitions |
| **Annex III classification** | §4 employment, workers management, self-employment |
| **Signer DID** | `did:key:z7QHBxxcLqomx211xvujOFroz7D5f8ytJN5MwIUimnwDVtA` |
| **Signer public key (base64url)** | `wccXC6qJsdtdcb7ozha6M-w-X_MrSTeTMCFIpp8A1bQ` |

---


## Introduction

This document is the Annex IV Technical Documentation for the
high-risk AI system identified above, prepared under Article 11 of
Regulation (EU) 2024/1689 (the "EU AI Act").

The document maps each numbered Annex IV section to the evidence
that the Sanctuary Framework auto-emits for that section, and
identifies exactly where enterprise-supplied business context is
required. Sections marked **FULL** are machine-verifiable against
the live Sanctuary instance that generated this bundle. Sections
marked **PARTIAL** carry auto-filled structured evidence alongside
explicit `[MANUAL INPUT REQUIRED: ...]` markers for enterprise
completion. Sections marked **MANUAL ONLY** are outside Sanctuary's
architectural scope and must be authored by the enterprise in full.

**How to use this document:**

1. Review each section below in order.
2. For every `[MANUAL INPUT REQUIRED: ...]` marker, replace the
   marker with the relevant enterprise fact.
3. Verify the auto-filled evidence against the live Sanctuary
   instance by running the listed `evidence_emitter` tools.
4. Sign the completed document with the provider's legal signature
   (the Sanctuary cryptographic signature below is the runtime
   authenticity attestation, not a substitute for a signed legal
   declaration).

---

## §1 — General Description

### Annex IV §1(a) — General description: intended purpose, provider, version

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Its intended purpose, the name of the provider and the version of the system [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: cryptographic provider identity (primary Ed25519 DID + public key via identity_list and identity_set_primary), Sanctuary version and implementation metadata (via manifest), and signed SHR instance_id. The template pre-populates the version-and-identity portion of this row with machine-verifiable cryptographic evidence.

**Evidence emitter tools:**

- `identity_list`
- `identity_set_primary`
- `manifest`
- `shr_generate`

**Enterprise input required:**

Intended purpose of the agent (business function), legal provider name and registered entity, and version-naming conventions used by the enterprise.

---

### Annex IV §1(b) — Interaction with external hardware or software

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "How the AI system interacts, or can be used to interact, with hardware or software [...] that is not part of the AI system itself [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: SHR layers.l2.model_provenance (provider, open-weights flag, local-inference flag, optional weights hash), MCP tool inventory (via manifest) listing every integration point the agent exposes, and the outbound context-gating policy manifest (via context_gate_list_policies) showing which provider endpoints the agent is permitted to contact and under what field-level constraints.

**Evidence emitter tools:**

- `shr_generate`
- `manifest`
- `context_gate_list_policies`

**Enterprise input required:**

Upstream LLM contracts and data processing agreements, third-party API integrations, downstream systems consuming agent output, and any hardware peripherals the agent orchestrates.

---

### Annex IV §1(c) — Versions of relevant software and firmware

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The versions of relevant software or firmware [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Sanctuary MCP server version (from manifest and SHR implementation block), Node.js runtime version, MCP SDK version, and platform string. The template emits a versioned software manifest for the Sanctuary layer itself.

**Evidence emitter tools:**

- `manifest`
- `shr_generate`
- `monitor_health`

**Enterprise input required:**

LLM model version and weights hash (if not set in model_provenance), agent harness version (OpenClaw or other), operating system patch level, container image digest, and any other 'relevant' software outside Sanctuary's runtime scope.

---

### Annex IV §1(d) — Forms in which the system is placed on the market

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The description of all the forms in which the AI system is placed on the market or put into service [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: forms in which the AI system is placed on the market or put into service].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Sanctuary is a runtime sovereignty layer and has no visibility into the commercial forms in which the enterprise distributes or operates the agent.

---

### Annex IV §1(e) — Description of the hardware on which the system runs

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The description of the hardware on which the AI system is intended to run [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: execution environment attestation (via exec_attest) reporting CPU vendor, TEE availability, operating system string, and Node.js runtime; sovereignty_audit environment fingerprint. The template emits the detected hardware context as structured evidence.

**Evidence emitter tools:**

- `exec_attest`
- `monitor_health`
- `sovereignty_audit`

**Enterprise input required:**

Production hardware specifications, TEE attestation evidence from the actual deployment environment, geographic location of the execution environment, and any hardware security modules or trusted hardware used in production.

---

### Annex IV §1(f) — Basic description of the user interface

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A basic description of the user interface provided to the deployer [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: description of the user interface provided to the deployer].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

User interface design is an agent-level or enterprise-level product decision outside Sanctuary's scope.

---



## §2 — Detailed Description of Elements

### Annex IV §2(a) — Methods and steps performed for development

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The methods and steps performed for the development of the AI system [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: development methodology, design iterations, training procedures, validation steps].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Sanctuary is a runtime sovereignty layer and is not involved in model development, training, or pre-deployment validation.

---

### Annex IV §2(b) — Design specifications and key design choices

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The design specifications of the system, namely the general logic of the AI system [...] the key design choices including the rationale and assumptions made [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: machine-readable Principal Policy YAML (tier rules, approval channel configuration, anomaly thresholds), context gating policy manifest, sovereignty profile, and the full MCP tool inventory. Together these constitute the declarative design specification of the Sanctuary sovereignty layer.

**Evidence emitter tools:**

- `principal_policy_view`
- `context_gate_list_policies`
- `sovereignty_profile_get`
- `manifest`

**Enterprise input required:**

Agent-level business logic, decision algorithms, the rationale for key design choices (why this policy, why these thresholds), assumptions made during development, and any non-Sanctuary architectural components.

---

### Annex IV §2(c) — Description of system architecture

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The description of the system architecture explaining how software components build on or feed into each other and integrate into the overall processing [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: SHR four-layer architecture description (L1 Cognitive Sovereignty, L2 Operational Isolation, L3 Selective Disclosure, L4 Verifiable Reputation) with status flags per layer, tool inventory showing every component interface, sovereignty audit environment analysis, and federation peer topology if configured.

**Evidence emitter tools:**

- `shr_generate`
- `manifest`
- `sovereignty_audit`
- `federation_status`

**Enterprise input required:**

Agent-level architecture (LLM orchestration, prompt templates, tool-use loops), upstream data flows into the agent, downstream systems consuming agent output, and the integration story between Sanctuary and the rest of the enterprise stack.

---

### Annex IV §2(d) — Data requirements: training data datasheets

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Where applicable, the data requirements in terms of datasheets describing the training methodologies and techniques and the training data sets used, including [...] provenance, scope and main characteristics; how the data was obtained and selected; labelling procedures [...] and data cleaning methodologies [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: training data description, provenance, scope, labelling, cleaning, and governance].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Sanctuary is a runtime sovereignty layer and has no visibility into model training. Training data governance is entirely the responsibility of the model provider or enterprise data team.

---

### Annex IV §2(e) — Assessment of human oversight measures per Article 14

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Assessment of the human oversight measures needed in accordance with Article 14, including an assessment of the technical measures needed to facilitate the interpretation of the outputs of AI systems by the deployers [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy approval channel configuration (stderr / dashboard / webhook), Tier 1 require-approval rule count, Tier 2 anomaly-triggered approval rule count, Tier 3 auto-allow tool list, baseline anomaly tracker status, and denial-on-timeout behaviour. The template pre-populates the technical-measures half of the human oversight assessment.

**Evidence emitter tools:**

- `principal_policy_view`
- `sovereignty_audit`
- `shr_generate`
- `principal_baseline_view`

**Enterprise input required:**

Operator identities, roles, training, authority, and escalation procedures; mapping between Sanctuary's approval channel and the enterprise's stop-button workflow; rationale for why the chosen oversight tier is appropriate to the risk profile of the deployed agent.

---

### Annex IV §2(f) — Pre-determined changes to the system and performance

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Where applicable, a description of pre-determined changes to the AI system and its performance [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: pre-determined changes to the AI system and its performance, if any].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Pre-determined changes are a product-roadmap and provider-level concept outside Sanctuary's runtime scope.

---

### Annex IV §2(g) — Validation and testing procedures, metrics

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The validation and testing procedures used, including information about the validation and testing data used [...] and the main metrics used to measure [...] accuracy, robustness and compliance with other relevant requirements [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: audit log entries within the reporting period showing tool-call success/failure rates, gate decision counts (approve / deny / auto-allow), and any injection_detected entries triggered by the prompt injection detector. These provide runtime validation evidence from actual deployment.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`
- `sovereignty_audit`

**Enterprise input required:**

Model evaluation metrics (accuracy, precision, recall, F1), bias testing results, robustness testing against adversarial inputs, the validation dataset description, and the metric methodology the enterprise used to assess the agent before deployment.

---

### Annex IV §2(h) — Cybersecurity measures

**Coverage:** **FULL** — auto-emitted from Sanctuary, zero enterprise input required, machine-verifiable

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A detailed description of the cybersecurity measures put in place [...]."

**Evidence emitted by Sanctuary:**

Machine-verifiable inventory of Sanctuary's cybersecurity primitives, every item reproducible by running the listed tools against a live instance: (1) L1 Cognitive Sovereignty — AES-256-GCM namespace encryption with HKDF per-namespace key derivation, Argon2id master key derivation, Ed25519 self-custodied identity, Merkle integrity tracking; reported by sovereignty_audit and shr_generate under layers.l1. (2) L2 Operational Isolation — three-tier Principal Policy gate with out-of-band approval channel, tool-call audit logging, and denial-on-timeout semantics; reported by principal_policy_view and shr_generate under layers.l2. (3) L2 Outbound context gating — per-provider field policies classifying agent context as allow / redact / hash / summarize / deny before any outbound call; reported by context_gate_list_policies and context_gate_enforcer_status. (4) L3 Selective Disclosure — Pedersen commitments on Ristretto255, Schnorr proofs, and bit-decomposition range proofs; reported by sovereignty_audit and shr_generate under layers.l3. (5) L4 Verifiable Reputation — Ed25519-signed attestations in EAS-compatible format with sovereignty-gated trust tiers; reported by sovereignty_audit and shr_generate under layers.l4. (6) Execution attestation — cryptographic execution attestation via exec_attest. The full tool inventory of this Sanctuary instance is reproducible by running manifest.

**Evidence emitter tools:**

- `sovereignty_audit`
- `shr_generate`
- `manifest`
- `principal_policy_view`
- `context_gate_list_policies`
- `context_gate_enforcer_status`
- `exec_attest`

**Enterprise input required:**

_(none — this row is fully auto-emitted)_

---



## §3 — Monitoring, Functioning and Control

### Annex IV §3 — Monitoring, functioning and control of the system

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Detailed information about the monitoring, functioning and control of the AI system [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: encrypted audit log queryable via monitor_audit_log and exportable in CEF/OCSF via audit_export_siem; health dashboard via monitor_health; outbound context gating enforcer status; Principal Policy baseline anomaly tracker state. Together these constitute the runtime monitoring substrate for the Sanctuary layer.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`
- `monitor_health`
- `context_gate_enforcer_status`
- `principal_baseline_view`

**Enterprise input required:**

Operational SLAs, on-call rotation, incident response procedures, escalation workflows, monitoring dashboards outside Sanctuary, and the enterprise's overall observability stack.

---



## §4 — Performance Metrics

### Annex IV §4 — Appropriateness of performance metrics

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A description of the appropriateness of the performance metrics for the specific AI system [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: performance metrics and their appropriateness for the specific agent deployment].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Performance metrics are agent-specific and model-specific; Sanctuary does not measure model accuracy or task performance.

---



## §5 — Risk Management System (Article 9)

### Annex IV §5 — Risk management system per Article 9

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A detailed description of the risk management system in accordance with Article 9 [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy tier structure (Tier 1 block, Tier 2 anomaly-triggered, Tier 3 auto-allow), baseline anomaly tracker configuration, outbound context gating policies, and sovereignty audit gap analysis with prioritised recommendations. These constitute Sanctuary's runtime risk management controls.

**Evidence emitter tools:**

- `principal_policy_view`
- `principal_baseline_view`
- `sovereignty_audit`
- `context_gate_list_policies`

**Enterprise input required:**

Enterprise-level risk register, residual risk analysis, risk treatment plan, acceptance criteria for residual risks, periodic risk review cadence, and the link between identified risks and the Sanctuary controls above.

---



## §6 — Changes Through Lifecycle

### Annex IV §6 — Description of relevant changes made through lifecycle

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A description of any change made to the system through its lifecycle [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: audit log entries within the reporting period showing all policy changes, identity operations (create, rotate, set_primary), state operations, and any configuration changes; identity rotation chain via identity_list. These provide a cryptographically anchored timeline of Sanctuary-layer changes during the period.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`
- `identity_list`

**Enterprise input required:**

Agent-level version changes (model updates, prompt changes), business-context narrative for why changes were made, and any changes to non-Sanctuary components of the stack.

---



## §7 — Standards Applied

### Annex IV §7 — Harmonised standards applied

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A list of the harmonised standards applied in full or in part [...] and, where such harmonised standards have not been applied, a detailed description of the solutions adopted to meet the requirements set out in Chapter III, Section 2 [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: list of harmonised standards applied, or description of alternative solutions].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Standards conformance is a legal declaration made by the provider. Sanctuary does not assert conformance to any harmonised standard.

---



## §8 — EU Declaration of Conformity

### Annex IV §8 — Copy of the EU declaration of conformity

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A copy of the EU declaration of conformity referred to in Article 47 [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: EU declaration of conformity per Article 47].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

The EU declaration of conformity is a formal legal document signed by the provider. Sanctuary cannot generate or provide it.

---



## §9 — Post-Market Monitoring Plan (Article 72)

### Annex IV §9 — Post-market monitoring plan per Article 72

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A detailed description of the system in place to evaluate the AI system performance in the post-market phase in accordance with Article 72, including the post-market monitoring plan referred to in Article 72(3) [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: post-market monitoring plan per Article 72(3)].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

The post-market monitoring plan is a provider-authored governance document. Sanctuary's SIEM exporter can feed the monitoring pipeline, but the plan itself is enterprise-authored.

---




---

## Document Signature

This document is cryptographically signed by the provider's primary
Ed25519 identity (DID `did:key:z7QHBxxcLqomx211xvujOFroz7D5f8ytJN5MwIUimnwDVtA`, public key
`wccXC6qJsdtdcb7ozha6M-w-X_MrSTeTMCFIpp8A1bQ`). The signature for this document is recorded
in the bundle manifest `00_bundle_manifest.json` under the entry
with this filename, alongside its SHA-256 digest.

**Verification procedure:** compute the SHA-256 of this file's raw
byte content, compare it against the `sha256` field for this file
in the bundle manifest, then verify the `signature` field against
the SHA-256 using the signer's public key with Ed25519. A successful
check proves this document was emitted by the named Sanctuary
instance and has not been altered since generation.

---

## Disclaimer

**This document is not legal advice.** It is a technical artifact
generated by the Sanctuary Framework EU AI Act Compliance Artifact
Generator. It is not a legal interpretation of Regulation (EU)
2024/1689 and does not constitute a legal opinion. Consult qualified
legal counsel before filing or relying on this document for
regulatory submissions, self-assessment, or CE marking procedures.

The coverage claims in this document reflect the state of the
Sanctuary Framework v0.7.0 runtime as of the
generation timestamp above. The coverage matrix is versioned
(`v1`) and aligned to the regulation text
identified by `EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10`; if the European Commission
publishes implementing acts, delegated acts, or guidance that
modifies the applicable requirements, this document must be
regenerated against the updated matrix.

---

*Generated by [Sanctuary Framework](https://github.com/eriknewton/sanctuary-framework)
v0.7.0 · Author: Erik Newton · License: Apache-2.0*
