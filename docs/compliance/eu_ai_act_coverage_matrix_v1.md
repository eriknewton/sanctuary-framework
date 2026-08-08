---
title: EU AI Act Coverage Matrix v1
description: Row-by-row mapping from Sanctuary primitives to Regulation (EU) 2024/1689 requirements
---

# EU AI Act Coverage Matrix v1

**Matrix version:** `v1`
**Regulation:** EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10
**OJ reference:** OJ L, 2024/1689, 12 July 2024
**Full enforcement date:** 2026-08-02
**Aligned to text version:** OJ published text
**Last full review:** 2026-07-05
**Next review due:** 2026-09-01

---

## Summary

| Coverage | Rows | Share |
|---|---|---|
| **Full** (auto-emitted, machine-verifiable, zero enterprise input) | 5 | 11% |
| **Partial** (structured evidence emitted; enterprise supplies business context) | 24 | 52% |
| **Manual only** (Sanctuary has no visibility; enterprise authors in full) | 17 | 37% |
| **Total** | 46 | 100% |

### The 5 full rows (core spine)

Every "full" row was individually verified against source. The audit-log rows (Article 12(1) and Article 15(5) first subparagraph) were re-verified against the current tree (server package v1.6.1) on 2026-07-05 to reflect the tamper-evident audit-chain hardening (PR #274 and follow-ups #290, #320, #396, #461, #501); checkpoint-signing and false-PASS verifier bounds remain tracked in **IC-05, IC-06** (`docs/audit/inert-capability-register.md`). The remaining rows carry their original 2026-04-10 verification against v0.7.0 source. See per-row review_notes for verification findings and any corrections applied. If a claim of "full coverage" on any other row appears in a downstream document, the matrix has drifted and needs re-verification.

1. **Annex IV §2(h)** - Cybersecurity measures
2. **Article 12(1)** - Automatic logging of events over lifetime
3. **Article 12(2)(a)** - Logs enable identification of Article 79(1) risks
4. **Article 12(2)(b)** - Logs facilitate monitoring operation per Article 26(5)
5. **Article 15(5) first subparagraph** - Resilience against unauthorised third-party alteration

### Notes

- Matrix v1 is aligned to the OJ-published text of Regulation (EU) 2024/1689. It does not yet reflect any implementing acts or delegated acts that the European Commission may publish before the 2026-08-02 enforcement date. Review the `next_review_due` field and bump regulation_version whenever the aligned text changes.
- Verbatim regulation text uses [...] elisions for length; text is never paraphrased. Clause identifiers (clause_id) are separately queryable so templates can render citations without parsing the verbatim quotes.
- Every 'full' row was individually verified against source. The audit-log rows (Article 12(1), Article 15(5) first subparagraph) were re-verified against the current tree (server package v1.6.1) on 2026-07-05 to reflect the tamper-evident audit-chain hardening (PR #274 and follow-ups #290, #320, #396, #461, #501). Checkpoint-signing and false-PASS verifier bounds remain tracked in **IC-05, IC-06** (`docs/audit/inert-capability-register.md`). The remaining rows carry their original 2026-04-10 verification against v0.7.0 source. See per-row review_notes for verification findings and any corrections applied.
- NOT LEGAL ADVICE. This matrix is a technical mapping from Sanctuary primitives to regulation clause identifiers; it is not a legal interpretation of the EU AI Act.

---

## Row-by-row mapping

### Annex IV §1(a) - General description: intended purpose, provider, version

- **Row ID:** `annex_iv_1_a_general_description`
- **Clause ID:** `annex-iv-1-a`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Its intended purpose, the name of the provider and the version of the system [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: cryptographic provider identity (primary Ed25519 DID + public key via identity_list and identity_set_primary), Sanctuary version and implementation metadata (via manifest), and signed SHR instance_id. The template pre-populates the version-and-identity portion of this row with machine-verifiable cryptographic evidence.

**Evidence emitter tools:** `identity_list`, `identity_set_primary`, `manifest`, `shr_generate`

**Enterprise input required:**

Intended purpose of the agent (business function), legal provider name and registered entity, and version-naming conventions used by the enterprise.

**Review notes:**

Partial is honest here: Sanctuary can emit a cryptographic provider identity and a software version, but 'intended purpose' is inherently a business-function narrative that Sanctuary cannot infer. Resist any temptation to call this full.

---

### Annex IV §1(b) - Interaction with external hardware or software

- **Row ID:** `annex_iv_1_b_hardware_software_interaction`
- **Clause ID:** `annex-iv-1-b`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "How the AI system interacts, or can be used to interact, with hardware or software [...] that is not part of the AI system itself [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: SHR layers.l2.model_provenance (provider, open-weights flag, local-inference flag, optional weights hash), MCP tool inventory (via manifest) listing every integration point the agent exposes, and the outbound context-gating policy manifest (via context_gate_list_policies) showing which provider endpoints the agent is permitted to contact and under what field-level constraints.

**Evidence emitter tools:** `shr_generate`, `manifest`, `context_gate_list_policies`

**Enterprise input required:**

Upstream LLM contracts and data processing agreements, third-party API integrations, downstream systems consuming agent output, and any hardware peripherals the agent orchestrates.

**Review notes:**

Sanctuary genuinely covers ~60% of this row when model_provenance is populated by the integrator. The template emits a structured interaction manifest and marks the business-context narrative as [MANUAL INPUT REQUIRED].

---

### Annex IV §1(c) - Versions of relevant software and firmware

- **Row ID:** `annex_iv_1_c_software_versions`
- **Clause ID:** `annex-iv-1-c`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The versions of relevant software or firmware [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Sanctuary MCP server version (from manifest and SHR implementation block), Node.js runtime version, MCP SDK version, and platform string. The template emits a versioned software manifest for the Sanctuary layer itself.

**Evidence emitter tools:** `manifest`, `shr_generate`, `monitor_health`

**Enterprise input required:**

LLM model version and weights hash (if not set in model_provenance), agent harness version (OpenClaw or other), operating system patch level, container image digest, and any other 'relevant' software outside Sanctuary's runtime scope.

**Review notes:**

Downgraded from full during verification (2026-04-10). Sanctuary auto-emits its own version + Node version, but 'relevant software' extends beyond Sanctuary and the enterprise must enumerate the rest. Partial is the honest call.

---

### Annex IV §1(d) - Forms in which the system is placed on the market

- **Row ID:** `annex_iv_1_d_forms_on_market`
- **Clause ID:** `annex-iv-1-d`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The description of all the forms in which the AI system is placed on the market or put into service [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: forms in which the AI system is placed on the market or put into service].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Sanctuary is a runtime sovereignty layer and has no visibility into the commercial forms in which the enterprise distributes or operates the agent.

**Review notes:**

Structural manual row - commercial distribution is not a Sanctuary concern and will not become one.

---

### Annex IV §1(e) - Description of the hardware on which the system runs

- **Row ID:** `annex_iv_1_e_hardware_description`
- **Clause ID:** `annex-iv-1-e`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The description of the hardware on which the AI system is intended to run [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: execution environment attestation (via exec_attest) reporting CPU vendor, TEE availability, operating system string, and Node.js runtime; sovereignty_audit environment fingerprint. The template emits the detected hardware context as structured evidence.

**Evidence emitter tools:** `exec_attest`, `monitor_health`, `sovereignty_audit`

**Enterprise input required:**

Production hardware specifications, TEE attestation evidence from the actual deployment environment, geographic location of the execution environment, and any hardware security modules or trusted hardware used in production.

**Review notes:**

In local-process mode Sanctuary emits tee_available=false, which is honest but incomplete - production may run on TEE-capable hardware that Sanctuary does not detect. SHR degradation NO_TEE is flagged automatically.

---

### Annex IV §1(f) - Basic description of the user interface

- **Row ID:** `annex_iv_1_f_instructions_of_use`
- **Clause ID:** `annex-iv-1-f`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "A basic description of the user interface provided to the deployer [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: description of the user interface provided to the deployer].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

User interface design is an agent-level or enterprise-level product decision outside Sanctuary's scope.

**Review notes:**

Structural manual row.

---

### Annex IV §2(a) - Methods and steps performed for development

- **Row ID:** `annex_iv_2_a_development_methods`
- **Clause ID:** `annex-iv-2-a`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The methods and steps performed for the development of the AI system [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: development methodology, design iterations, training procedures, validation steps].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Sanctuary is a runtime sovereignty layer and is not involved in model development, training, or pre-deployment validation.

**Review notes:**

Structural manual row - model development is outside Sanctuary's architectural scope.

---

### Annex IV §2(b) - Design specifications and key design choices

- **Row ID:** `annex_iv_2_b_design_specifications`
- **Clause ID:** `annex-iv-2-b`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The design specifications of the system, namely the general logic of the AI system [...] the key design choices including the rationale and assumptions made [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: machine-readable Principal Policy YAML (tier rules, approval channel configuration, anomaly thresholds), context gating policy manifest, sovereignty profile, and the full MCP tool inventory. Together these constitute the declarative design specification of the Sanctuary sovereignty layer.

**Evidence emitter tools:** `principal_policy_view`, `context_gate_list_policies`, `sovereignty_profile_get`, `manifest`

**Enterprise input required:**

Agent-level business logic, decision algorithms, the rationale for key design choices (why this policy, why these thresholds), assumptions made during development, and any non-Sanctuary architectural components.

**Review notes:**

Borderline partial - Sanctuary emits the policy and gating specifications as structured data, but 'key design choices including rationale' is inherently a narrative field that requires enterprise authorship. Kept partial deliberately.

---

### Annex IV §2(c) - Description of system architecture

- **Row ID:** `annex_iv_2_c_system_architecture`
- **Clause ID:** `annex-iv-2-c`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The description of the system architecture explaining how software components build on or feed into each other and integrate into the overall processing [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: SHR four-layer architecture description (L1 Cognitive Sovereignty, L2 Operational Isolation, L3 Selective Disclosure, L4 Verifiable Reputation) with status flags per layer, tool inventory showing every component interface, sovereignty audit environment analysis, and federation peer topology if configured.

**Evidence emitter tools:** `shr_generate`, `manifest`, `sovereignty_audit`, `federation_status`

**Enterprise input required:**

Agent-level architecture (LLM orchestration, prompt templates, tool-use loops), upstream data flows into the agent, downstream systems consuming agent output, and the integration story between Sanctuary and the rest of the enterprise stack.

**Review notes:**

Borderline partial - Sanctuary emits a complete architectural description of its own layer but this row requires the architecture of the AI system as a whole. Enterprise wraps the Sanctuary layer in a broader architecture narrative.

---

### Annex IV §2(d) - Data requirements: training data datasheets

- **Row ID:** `annex_iv_2_d_data_requirements`
- **Clause ID:** `annex-iv-2-d`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Where applicable, the data requirements in terms of datasheets describing the training methodologies and techniques and the training data sets used, including [...] provenance, scope and main characteristics; how the data was obtained and selected; labelling procedures [...] and data cleaning methodologies [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: training data description, provenance, scope, labelling, cleaning, and governance].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Sanctuary is a runtime sovereignty layer and has no visibility into model training. Training data governance is entirely the responsibility of the model provider or enterprise data team.

**Review notes:**

Classification is structurally stable across EU AI Act revisions.

---

### Annex IV §2(e) - Assessment of human oversight measures per Article 14

- **Row ID:** `annex_iv_2_e_human_oversight_assessment`
- **Clause ID:** `annex-iv-2-e`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Assessment of the human oversight measures needed in accordance with Article 14, including an assessment of the technical measures needed to facilitate the interpretation of the outputs of AI systems by the deployers [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy approval channel configuration (stderr / dashboard / webhook), Tier 1 require-approval rule count, Tier 2 anomaly-triggered approval rule count, Tier 3 auto-allow tool list, baseline anomaly tracker status, and denial-on-timeout behaviour. The template pre-populates the technical-measures half of the human oversight assessment.

**Evidence emitter tools:** `principal_policy_view`, `sovereignty_audit`, `shr_generate`, `principal_baseline_view`

**Enterprise input required:**

Operator identities, roles, training, authority, and escalation procedures; mapping between Sanctuary's approval channel and the enterprise's stop-button workflow; rationale for why the chosen oversight tier is appropriate to the risk profile of the deployed agent.

**Review notes:**

Borderline partial. Sanctuary provides the oversight mechanism inventory with zero enterprise input (~70% of the row). Enterprise provides the people-and-process assessment.

---

### Annex IV §2(f) - Pre-determined changes to the system and performance

- **Row ID:** `annex_iv_2_f_predetermined_changes`
- **Clause ID:** `annex-iv-2-f`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Where applicable, a description of pre-determined changes to the AI system and its performance [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: pre-determined changes to the AI system and its performance, if any].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Pre-determined changes are a product-roadmap and provider-level concept outside Sanctuary's runtime scope.

**Review notes:**

Structural manual row.

---

### Annex IV §2(g) - Validation and testing procedures, metrics

- **Row ID:** `annex_iv_2_g_validation_and_testing`
- **Clause ID:** `annex-iv-2-g`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The validation and testing procedures used, including information about the validation and testing data used [...] and the main metrics used to measure [...] accuracy, robustness and compliance with other relevant requirements [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: audit log entries within the reporting period showing tool-call success/failure rates, gate decision counts (approve / deny / auto-allow), and any injection_detected entries triggered by the prompt injection detector. These provide runtime validation evidence from actual deployment.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`, `sovereignty_audit`

**Enterprise input required:**

Model evaluation metrics (accuracy, precision, recall, F1), bias testing results, robustness testing against adversarial inputs, the validation dataset description, and the metric methodology the enterprise used to assess the agent before deployment.

**Review notes:**

Sanctuary emits runtime operational evidence but does not participate in pre-deployment model validation.

---

### Annex IV §2(h) - Cybersecurity measures

- **Row ID:** `annex_iv_2_h_cybersecurity`
- **Clause ID:** `annex-iv-2-h`
- **Coverage:** **FULL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "A detailed description of the cybersecurity measures put in place [...]."

**Evidence emitted by Sanctuary:**

Machine-verifiable inventory of Sanctuary's cybersecurity primitives, every item reproducible by running the listed tools against a live instance: (1) L1 Cognitive Sovereignty - AES-256-GCM namespace encryption with HKDF per-namespace key derivation, Argon2id master key derivation, Ed25519 self-custodied identity, Merkle integrity tracking; reported by sovereignty_audit and shr_generate under layers.l1. (2) L2 Operational Isolation - three-tier Principal Policy gate with out-of-band approval channel, tool-call audit logging, and denial-on-timeout semantics; reported by principal_policy_view and shr_generate under layers.l2. (3) L2 Outbound context gating - per-provider field policies classifying agent context as allow / redact / hash / summarize / deny before any outbound call; reported by context_gate_list_policies and context_gate_enforcer_status. (4) L3 Selective Disclosure - Pedersen commitments on Ristretto255, Schnorr proofs, and bit-decomposition range proofs; reported by sovereignty_audit and shr_generate under layers.l3. (5) L4 Verifiable Reputation - Ed25519-signed attestations in EAS-compatible format with sovereignty-gated trust tiers; reported by sovereignty_audit and shr_generate under layers.l4. (6) Execution attestation - cryptographic execution attestation via exec_attest. The full tool inventory of this Sanctuary instance is reproducible by running manifest.

**Evidence emitter tools:** `sovereignty_audit`, `shr_generate`, `manifest`, `principal_policy_view`, `context_gate_list_policies`, `context_gate_enforcer_status`, `exec_attest`

**Enterprise input required:**

_(none - this row is fully auto-emitted)_

**Review notes:**

Verified against v0.7.0 source on 2026-04-10: every emitter in the array corresponds to a registered MCP tool in index.ts, and every primitive named in the prose is reported by at least one listed tool. DELIBERATELY EXCLUDED: prompt injection detection. The InjectionDetector subsystem (server/src/security/injection-detector.ts) is wired into the Principal Policy gate and is a real runtime control, but in v0.7.0 its configuration state is not exposed via any MCP tool - it is only indirectly evidenced through `injection_detected:*` entries in the audit log (visible via monitor_audit_log / audit_export_siem). Claiming injection detection as part of this row's full coverage would require source-code inspection, which violates the full-coverage bar. Injection detection runtime activity is evidenced via the Art. 12 risk management support row instead. If v0.8.0+ adds an `injection_detector_status` MCP tool, revisit and add to this row.

---

### Annex IV §3 - Monitoring, functioning and control of the system

- **Row ID:** `annex_iv_3_monitoring_functioning_control`
- **Clause ID:** `annex-iv-3`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Detailed information about the monitoring, functioning and control of the AI system [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: encrypted audit log queryable via monitor_audit_log and exportable in CEF/OCSF via audit_export_siem; health dashboard via monitor_health; outbound context gating enforcer status; Principal Policy baseline anomaly tracker state. Together these constitute the runtime monitoring substrate for the Sanctuary layer.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`, `monitor_health`, `context_gate_enforcer_status`, `principal_baseline_view`

**Enterprise input required:**

Operational SLAs, on-call rotation, incident response procedures, escalation workflows, monitoring dashboards outside Sanctuary, and the enterprise's overall observability stack.

**Review notes:**

Sanctuary provides the monitoring substrate; the enterprise wraps it in operational processes. Borderline partial.

---

### Annex IV §4 - Appropriateness of performance metrics

- **Row ID:** `annex_iv_4_performance_metrics`
- **Clause ID:** `annex-iv-4`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "A description of the appropriateness of the performance metrics for the specific AI system [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: performance metrics and their appropriateness for the specific agent deployment].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Performance metrics are agent-specific and model-specific; Sanctuary does not measure model accuracy or task performance.

**Review notes:**

Structural manual row.

---

### Annex IV §5 - Risk management system per Article 9

- **Row ID:** `annex_iv_5_risk_management`
- **Clause ID:** `annex-iv-5`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "A detailed description of the risk management system in accordance with Article 9 [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy tier structure (Tier 1 block, Tier 2 anomaly-triggered, Tier 3 auto-allow), baseline anomaly tracker configuration, outbound context gating policies, and sovereignty audit gap analysis with prioritised recommendations. These constitute Sanctuary's runtime risk management controls.

**Evidence emitter tools:** `principal_policy_view`, `principal_baseline_view`, `sovereignty_audit`, `context_gate_list_policies`

**Enterprise input required:**

Enterprise-level risk register, residual risk analysis, risk treatment plan, acceptance criteria for residual risks, periodic risk review cadence, and the link between identified risks and the Sanctuary controls above.

**Review notes:**

Sanctuary emits runtime controls; enterprise maps them to an Article 9 risk management framework.

---

### Annex IV §6 - Description of relevant changes made through lifecycle

- **Row ID:** `annex_iv_6_lifecycle_changes`
- **Clause ID:** `annex-iv-6`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "A description of any change made to the system through its lifecycle [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: audit log entries within the reporting period showing all policy changes, identity operations (create, rotate, set_primary), state operations, and any configuration changes; identity rotation chain via identity_list. These provide a cryptographically anchored timeline of Sanctuary-layer changes during the period.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`, `identity_list`

**Enterprise input required:**

Agent-level version changes (model updates, prompt changes), business-context narrative for why changes were made, and any changes to non-Sanctuary components of the stack.

**Review notes:**

Sanctuary captures its own layer's change timeline; enterprise provides the broader change narrative.

---

### Annex IV §7 - Harmonised standards applied

- **Row ID:** `annex_iv_7_standards_applied`
- **Clause ID:** `annex-iv-7`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "A list of the harmonised standards applied in full or in part [...] and, where such harmonised standards have not been applied, a detailed description of the solutions adopted to meet the requirements set out in Chapter III, Section 2 [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: list of harmonised standards applied, or description of alternative solutions].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Standards conformance is a legal declaration made by the provider. Sanctuary does not assert conformance to any harmonised standard.

**Review notes:**

Structural manual row - standards conformance is a provider legal declaration, not a Sanctuary primitive.

---

### Annex IV §8 - Copy of the EU declaration of conformity

- **Row ID:** `annex_iv_8_eu_declaration_of_conformity`
- **Clause ID:** `annex-iv-8`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "A copy of the EU declaration of conformity referred to in Article 47 [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: EU declaration of conformity per Article 47].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

The EU declaration of conformity is a formal legal document signed by the provider. Sanctuary cannot generate or provide it.

**Review notes:**

Structural manual row - legal document only.

---

### Annex IV §9 - Post-market monitoring plan per Article 72

- **Row ID:** `annex_iv_9_post_market_monitoring_plan`
- **Clause ID:** `annex-iv-9`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "A detailed description of the system in place to evaluate the AI system performance in the post-market phase in accordance with Article 72, including the post-market monitoring plan referred to in Article 72(3) [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: post-market monitoring plan per Article 72(3)].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

The post-market monitoring plan is a provider-authored governance document. Sanctuary's SIEM exporter can feed the monitoring pipeline, but the plan itself is enterprise-authored.

**Review notes:**

See the Art. 12 post-market monitoring support row for Sanctuary's concrete contribution to this area.

---

### Article 12(1) - Automatic logging of events over lifetime

- **Row ID:** `art_12_automatic_logging`
- **Clause ID:** `art-12-1`
- **Coverage:** **FULL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "High-risk AI systems shall technically allow for the automatic recording of events ('logs') over the lifetime of the system."

**Evidence emitted by Sanctuary:**

Every tool call in the Sanctuary runtime automatically produces an audit entry via the Principal Policy gate. Router.ts wraps all tool invocations through gate.evaluate(), which appends to the audit log on every outcome path (gate_allow, gate_allow_proxy, gate_deny, gate_escalate, gate_unclassified, injection_detected). Entries are persisted as AES-256-GCM authenticated ciphertext under an HKDF-derived audit-log key and are linked into a tamper-evident hash chain: each persisted entry carries a sequence number and a prev_hash, and an entry_hash computed over its sequence, prev_hash, timestamp, and ciphertext. Every critical outcome is written durably (fsync plus read-after-write byte verification) before the gate returns, so a completed gate decision is on disk, not held only in memory. Entries are queryable via monitor_audit_log or exportable in CEF/OCSF via audit_export_siem. No tool call bypasses the audit path.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`

**Enterprise input required:**

_(none - this row is fully auto-emitted)_

**Review notes:**

Re-verified against the current tree (server package v1.6.1) on 2026-07-05. router.ts routes every tool call through gate.evaluate(); principal-policy/gate.ts appends to the audit log on every outcome. UPDATED for the audit-chain hardening (PR #274, merged 2026-05-16, plus follow-ups #290, #320, #396, #461, #501): entries are now linked by a per-entry prev_hash chain (PersistedAuditEnvelopeV2 in operational/audit-log.ts, schema version 2) over AES-256-GCM ciphertext, and periodic checkpoint records carry a SHA-256 root over the covered entry hashes, Ed25519-signed when a signing identity is available (unsigned and marked as such otherwise). The signature binds the checkpoint root, not each individual entry; per-entry integrity is the AES-256-GCM authentication tag plus the prev_hash link. Durability is now enforced: critical gate outcomes use appendCritical, which awaits a durable write (file plus directory fsync) and a read-after-write round-trip verification and throws AuditPersistenceError on any storage, disk-full, permission, or torn-write failure. The earlier fire-and-forget caveat no longer applies to critical entries; only best-effort telemetry appends (for example injection_detected) use the un-awaited path, and those are still tracked and rethrown by flush(). Art. 12(1) requires the system to technically *allow* automatic recording, which remains satisfied and is now backed by a verifiable chain.

---

### Article 12(2)(a) - Logs enable identification of Article 79(1) risks

- **Row ID:** `art_12_post_market_monitoring_support`
- **Clause ID:** `art-12-2-a`
- **Coverage:** **FULL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The logging capabilities shall enable the recording of events relevant for identifying situations that may result in the AI system presenting a risk within the meaning of Article 79(1) [...] and for facilitating the post-market monitoring referred to in Article 72."

**Evidence emitted by Sanctuary:**

The audit_export_siem tool exports audit log entries in two SIEM-standard formats: Common Event Format (CEF, newline-delimited) and Open Cybersecurity Schema Framework (OCSF, JSON array). Both formats are directly ingestible by Splunk, Datadog, QRadar, and any other enterprise SIEM platform, which are the standard substrate for Article 72 post-market monitoring pipelines. Exports support time-window filters (since / until), tool name filters, gate decision filters (approve / deny / auto-allow), layer filters (l1 / l2 / l3 / l4), and result filters (success / failure). Bulk exports up to 1000 events per call.

**Evidence emitter tools:** `audit_export_siem`, `monitor_audit_log`

**Enterprise input required:**

_(none - this row is fully auto-emitted)_

**Review notes:**

Verified against v0.7.0 source on 2026-04-10: audit/siem-tools.ts:18-77 registers audit_export_siem with CEF and OCSF format support and the full filter set. Re-tiered to Tier 1 (operator approval required) in loader.ts on 2026-06-15: the bulk export reveals each operation's policy tier and decision, so SIEM forwarding is an operator function, not an agent auto-allow (CISO MED-1).

---

### Article 12(2)(b) - Logs facilitate monitoring operation per Article 26(5)

- **Row ID:** `art_12_risk_management_support`
- **Clause ID:** `art-12-2-b`
- **Coverage:** **FULL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The logging capabilities shall enable the recording of events relevant for [...] facilitating the monitoring of the operation of the high-risk AI system referred to in Article 26(5)."

**Evidence emitted by Sanctuary:**

Gate decisions are logged with structured operation prefixes (gate_allow:, gate_allow_proxy:, gate_deny:, gate_escalate:, gate_unclassified:, injection_detected:) directly filterable via audit_export_siem's filter_decision enum (approve / deny / auto-allow) and via monitor_audit_log's operation_type parameter. The Principal Policy baseline anomaly tracker state (behavioural model, known-namespaces, frequency baselines, anomaly thresholds) is queryable via principal_baseline_view. Together these provide the machine-queryable substrate for deployer operation monitoring under Article 26(5).

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`, `principal_baseline_view`

**Enterprise input required:**

_(none - this row is fully auto-emitted)_

**Review notes:**

Verified against v0.7.0 source on 2026-04-10. gate.ts writes structured operation strings on every gate outcome; baseline.ts is the anomaly source and is exposed via principal_baseline_view. Minor correction during verification: principal_baseline_view added to emitter list (original draft listed only monitor_audit_log).

---

### Article 12(3) - Required log content for Annex III §1(a) systems

- **Row ID:** `art_12_log_content`
- **Clause ID:** `art-12-3`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "For high-risk AI systems referred to in point 1(a) of Annex III, the logging capabilities shall provide, at a minimum: (a) recording of the period of each use of the system [...]; (b) the reference database against which input data has been checked by the system; (c) the input data for which the search has led to a match; (d) the identification of the natural persons involved in the verification of the results [...]."

**Evidence emitted by Sanctuary:**

Auto-filled where the agent routes through Sanctuary: period of use (audit log timestamps with since/until filters), tool inputs (captured in audit entry details field), and identification of principals who approved Tier 1 operations (captured via identity_id in audit entries and identity provenance via identity_list). Gate decisions are bound to the identity that requested the operation.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`, `identity_list`

**Enterprise input required:**

Reference database identifier (the external database the agent queries) - only captured if the agent explicitly logs it to Sanctuary state. Natural-person verifier identification beyond the Sanctuary principal identity (e.g., the human operator's HR record or employee ID). Input data captured only when the agent passes it through a Sanctuary tool call.

**Review notes:**

Row applies only to Annex III §1(a) (biometric remote identification) systems. For other Annex III categories this row is not triggered. Coverage depends on whether the agent actually routes its biometric checks through Sanctuary-tracked tool calls.

---

### Article 19(1) - Log retention for at least six months

- **Row ID:** `art_12_retention`
- **Clause ID:** `art-19-1`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Providers of high-risk AI systems shall keep the logs referred to in Article 12(1), automatically generated by their high-risk AI systems, to the extent such logs are under their control. [...] the logs shall be kept for a period appropriate to the intended purpose of the high-risk AI system, of at least six months [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Sanctuary's audit log persists entries by default until configured size or entry caps trigger authenticated rotation (defaults: 100,000 entries / 100 MB), at which point the oldest entries are pruned behind a master-MAC'd rotation anchor so the cut is tamper-evident. Enterprises retaining beyond those caps must archive via audit_export_siem, which is exportable at any time for archival to enterprise storage.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`

**Enterprise input required:**

The enterprise's declared log retention policy (how long logs are kept, in which storage tier, who has access), the archival pipeline configuration feeding enterprise long-term storage, and the written policy document satisfying the 'period appropriate to the intended purpose' requirement.

**Review notes:**

Note: this row cites Article 19(1) rather than Article 12: retention is specifically an Article 19 provider obligation, not an Article 12 logging capability. The capability to retain exists in Sanctuary; the on-disk log grows until the configured size/entry caps trigger authenticated rotation (defaults 100,000 entries / 100 MB), so a high-volume deployment must archive via audit_export_siem to satisfy a retention window beyond those caps. The declared policy is an enterprise artefact.

---

### Article 13(3)(a) - Identity and contact details of the provider

- **Row ID:** `art_13_3_a_provider_identity`
- **Clause ID:** `art-13-3-a`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The instructions for use shall contain at least the following information: (a) the identity and the contact details of the provider and, where applicable, of its authorised representative [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: cryptographic provider identity - primary Ed25519 public key, DID, instance_id, and key creation timestamp via identity_list and identity_set_primary. The signed SHR carries the same identity in its signed_by field, providing a verifiable link between the provider identity and the capability assertions of the system.

**Evidence emitter tools:** `identity_list`, `identity_set_primary`, `shr_generate`

**Enterprise input required:**

Legal provider name, registered legal entity, registered business address, contact email, and authorised representative details (if applicable). These are legal-entity facts that must be supplied by the enterprise.

**Review notes:**

Sanctuary emits the cryptographic identity; the enterprise supplies the legal identity. Both are required for complete Art. 13(3)(a) coverage.

---

### Article 13(3)(b)(ii) - Performance characteristics, capabilities and limitations

- **Row ID:** `art_13_3_b_ii_capabilities_and_limitations`
- **Clause ID:** `art-13-3-b-ii`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The characteristics, capabilities and limitations of performance of the high-risk AI system, including [...] its intended purpose [...] the level of accuracy, including its metrics [...] and any known or foreseeable circumstance [...] which may lead to risks to the health and safety or fundamental rights [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: SHR four-layer capability report with explicit status flags per layer (active / degraded / inactive), the SHR degradations[] array listing honest self-declared gaps (e.g., NO_TEE, PROCESS_ISOLATION_ONLY), the full MCP tool inventory (via manifest), and the sovereignty audit gap analysis. Together these constitute a machine-readable capability manifest with explicit, honest limitations.

**Evidence emitter tools:** `shr_generate`, `manifest`, `sovereignty_audit`

**Enterprise input required:**

Agent-level accuracy metrics and their measurement methodology, false-positive and false-negative rates on the agent's business task, known failure modes specific to the deployment, and the link between technical capabilities and fundamental-rights risk.

**Review notes:**

Sanctuary's SHR is structurally a transparency artefact - it is designed to honestly declare capabilities and degradations. This row is where SHR data feeds user-facing disclosures.

---

### Article 13(3)(b)(iv) - Technical capabilities to interpret system output

- **Row ID:** `art_13_3_b_iv_output_interpretation`
- **Clause ID:** `art-13-3-b-iv`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Where appropriate, its performance regarding specific persons or groups of persons on which the system is intended to be used; [...] where appropriate, specifications for the input data, or any other relevant information in terms of the training, validation and testing data sets used, taking into account the intended purpose of the AI system [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: signed SHR + tamper-evident, hash-chained audit with checkpoint signatures only where a signer is wired + Concordia bridge attestations (where used) give machine-readable provenance for every tool call the agent made during the reporting period. Production audit checkpoints are currently unsigned until **IC-05** closes, and `audit-chain verify --no-strict` can return PASS with findings until **IC-06** closes. This enables output interpretation of the form 'this agent action came from these inputs at this time, cryptographically signed where a signer is present and independently verifiable.'

**Evidence emitter tools:** `shr_generate`, `monitor_audit_log`, `audit_export_siem`, `bridge_verify`

**Enterprise input required:**

Business-facing explanation translating the cryptographic trail into user-comprehensible narrative, performance characteristics on specific populations, and intended-purpose-specific input specifications.

**Review notes:**

Sanctuary provides the cryptographic substrate for output provenance; enterprise renders it into user-facing disclosure text. Art. 13 is fundamentally a disclosure UX obligation that Sanctuary does not render.

---

### Article 14(4)(a)-(c) - Oversight enables understanding and interpretation

- **Row ID:** `art_14_interpret_outputs`
- **Clause ID:** `art-14-4-a-c`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "[The measures shall enable the persons to whom human oversight is assigned to]: (a) [...] properly understand the relevant capacities and limitations of the high-risk AI system [...]; (b) [...] remain aware of [...] automation bias [...]; (c) [...] correctly interpret the high-risk AI system's output [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: SHR is designed to be human-readable with explicit per-layer status flags and honest degradation declarations. Principal Policy is inspectable YAML that a human overseer can read directly. Tool inventory (via manifest) gives the oversight persons a complete list of what the agent can do.

**Evidence emitter tools:** `shr_generate`, `principal_policy_view`, `manifest`

**Enterprise input required:**

Training materials for human overseers, the specific automation-bias awareness program, how oversight persons are trained to correctly interpret agent output, and any UI tools the enterprise provides to support oversight.

**Review notes:**

Sanctuary emits artefacts designed to be interpretable; the enterprise builds the training-and-support layer around them.

---

### Article 14(4)(e) - Intervention, interruption, and stop button

- **Row ID:** `art_14_intervene_interrupt`
- **Clause ID:** `art-14-4-e`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "[The measures shall enable the persons to whom human oversight is assigned to]: (e) [...] intervene on the operation of the high-risk AI system or interrupt the system through a 'stop' button or similar procedure that allows the system to come to a halt in a safe state."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy approval channel configuration (stderr / dashboard / webhook), Tier 1 require-approval rule count, denial-on-timeout behaviour, and gate decision semantics. These collectively document Sanctuary's pre-execution intervention capability - every Tier 1 tool call is halted pending human approval.

**Evidence emitter tools:** `principal_policy_view`, `sovereignty_audit`

**Enterprise input required:**

The enterprise's declared mapping between Sanctuary's approval channel and its Article 14(4)(e) stop-button workflow, the operational procedure for invoking the stop button, and acceptance that pre-execution gating satisfies the 'halt in a safe state' requirement for the specific agent.

**Review notes:**

Downgraded from full during audit (2026-04-10). Sanctuary's approval gate is a pre-execution intervention, not a mid-stream kill switch. Whether pre-execution gating satisfies Art. 14(4)(e) is an enterprise-declared operational judgement. Honest partial.

---

### Article 14(4)(d) - Decide not to use or to disregard the output

- **Row ID:** `art_14_decide_not_to_use`
- **Clause ID:** `art-14-4-d`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "[The measures shall enable the persons to whom human oversight is assigned to]: (d) [...] decide, in any particular situation, not to use the high-risk AI system or to otherwise disregard, override or reverse the output of the high-risk AI system [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy denial semantics - every Tier 1 operation defaults to deny on approval timeout, providing a structural 'decide not to use' control at the policy layer. Tier 1 tools include export, import, key rotation, and secure delete.

**Evidence emitter tools:** `principal_policy_view`

**Enterprise input required:**

The enterprise's declared mapping between Sanctuary's deny semantics and its Art. 14(4)(d) decision-not-to-use workflow, and operator authority to invoke the decision.

**Review notes:**

Downgraded from full during audit (2026-04-10). Sanctuary provides the capability; enterprise provides the operational declaration.

---

### Article 14(4) chapeau - Operator competence, training, and authority

- **Row ID:** `art_14_operator_training`
- **Clause ID:** `art-14-4-chapeau`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "[Human oversight measures shall be commensurate with the risks, level of autonomy and context of use of the high-risk AI system] [...] ensured through [...] the following types of measures, as appropriate to the circumstances [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: operator identities, roles, competence, training program, and authority to override].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

People-and-process facts that Sanctuary cannot observe or emit.

**Review notes:**

Structural manual row - operator governance is an HR function.

---

### Article 15(5) - Cybersecurity measures appropriate to the risks

- **Row ID:** `art_15_cybersecurity_appropriate`
- **Clause ID:** `art-15-5`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "High-risk AI systems shall be resilient against attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities. The technical solutions aiming to ensure the cybersecurity of high-risk AI systems shall be appropriate to the relevant circumstances and the risks."

**Evidence emitted by Sanctuary:**

Auto-filled: the full cybersecurity measures inventory (see Annex IV §2(h) row for complete description). Sanctuary emits the list of measures with structured status flags.

**Evidence emitter tools:** `sovereignty_audit`, `shr_generate`, `principal_policy_view`, `context_gate_list_policies`

**Enterprise input required:**

Appropriateness assertion: the enterprise must declare that the Sanctuary-reported measures are appropriate to the specific risks of the deployment context (risk-matched narrative linking identified risks to selected controls).

**Review notes:**

Downgraded from full during audit (2026-04-10). Art. 15(5) requires measures 'appropriate to the risks' - the appropriateness claim is a risk-matched narrative the enterprise owns. The pure-description version survives as a full row at Annex IV §2(h); this row is the risk-adequacy half of the same content.

---

### Article 15(5) first subparagraph - Resilience against unauthorised third-party alteration

- **Row ID:** `art_15_resilience_alteration`
- **Clause ID:** `art-15-5-resilience`
- **Coverage:** **FULL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "High-risk AI systems shall be resilient against attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities."

**Evidence emitted by Sanctuary:**

Resilience against unauthorised third-party alteration is enforced across multiple subsystems, each independently verifiable via an MCP tool call: (1) L1 state store - AES-256-GCM authenticated encryption with HKDF per-namespace keys, Merkle root per namespace, monotonic version counter per (namespace, key), and anti-rollback checks on every read; reported by monitor_health (state_integrity flag) and via version numbers returned by state_list. (2) L1 audit log - AES-256-GCM authenticated ciphertext persisted under an HKDF-derived audit-log key, linked into a tamper-evident hash chain (per-entry sequence plus prev_hash plus entry_hash), with periodic checkpoint records carrying a SHA-256 root over the covered entry hashes, Ed25519-signed when a signing identity is available; a rotation anchor authenticated by a master-derived MAC makes a truncation or prune of the tail detectable. Reported by monitor_health and the audit-chain verifier; integrity findings surface as a P1 anomaly. (See review_notes for the exact non-repudiation bound.) (3) L1 identity - Ed25519 self-custodied keypairs; signed identity operations (sign, rotate, verify) and signed SHR generation; reported by shr_generate signature block. (4) L2 execution gate - every tool call routed through router.ts -> ApprovalGate.evaluate() -> Principal Policy tier check before execution; no bypass path; reported by principal_policy_view and the audit log trail of gate_* entries. (5) L2 outbound context gating - per-provider field policies applied before any outbound call; reported by context_gate_enforcer_status.

**Evidence emitter tools:** `sovereignty_audit`, `shr_generate`, `monitor_health`, `state_list`, `principal_policy_view`, `context_gate_enforcer_status`

**Enterprise input required:**

_(none - this row is fully auto-emitted)_

**Review notes:**

Re-verified against the current tree (server package v1.6.1) on 2026-07-05. UPDATED for the audit-chain hardening wave (PR #274 merged 2026-05-16, plus #290, #320, #396, #461, #501). The three items earlier drafts had corrected AWAY are now present and must be stated: (1) the audit log now carries a SHA-256 root over each checkpoint's entry-hash set (computeAuditRoot in audit/chain.ts), so integrity coverage is no longer state-store-only; (2) checkpoint records are Ed25519-signed over domain-separated canonical JSON when a signing identity is available (records are marked unsigned with a reason otherwise), so there is non-repudiation at checkpoint granularity, though NOT a distinct signature on each individual entry; (3) entries are chained by prev_hash (PersistedAuditEnvelopeV2, schema version 2), so a tamper-evident transcript does now exist. The precise bound: per-entry tamper-evidence is the AES-256-GCM authentication tag plus the prev_hash link (keyed to the master); Ed25519 non-repudiation is at checkpoint granularity over the Merkle-style root, and is conditional on a signing identity being present at checkpoint time. Non-repudiation against a compromised-master-key insider who forges the checkpoint signer is still out of scope; the row survives as full because Art. 15(5) targets unauthorised third parties, and the chain plus signed checkpoint plus master-MAC'd rotation anchor are resilient against that threat model.

---

### Article 15(5) second subparagraph - Resilience against data and model poisoning

- **Row ID:** `art_15_resilience_poisoning`
- **Clause ID:** `art-15-5-poisoning`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The technical solutions to address AI specific vulnerabilities shall include, where appropriate, measures to prevent, detect, respond to, resolve and control for attacks trying to manipulate the training data set ('data poisoning'), or pre-trained components used in training ('model poisoning'), inputs designed to cause the AI model to make a mistake ('adversarial examples' or 'model evasion'), [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: the Principal Policy gate runs a prompt injection detector pre-check on every tool call; when flagged, the gate appends 'injection_detected:*' entries to the audit log, which are visible via monitor_audit_log and exportable via audit_export_siem. The detector covers role override, security bypass, encoding evasion, data exfiltration, and prompt stuffing signals at runtime.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`

**Enterprise input required:**

Training-time threats (data poisoning, model poisoning) are entirely outside Sanctuary's runtime scope - training data governance is the model provider's responsibility. The runtime adversarial-input detection is partial coverage of the 'adversarial examples' subset of Art. 15(5).

**Review notes:**

The injection detector exists (security/injection-detector.ts) and its activity IS evidenced via audit log entries, even though its configuration state is not directly queryable. Partial is honest: runtime adversarial-input detection is covered; training-time poisoning is not.

---

### Article 15(3) - Declared accuracy levels and metrics

- **Row ID:** `art_15_accuracy_metrics`
- **Clause ID:** `art-15-3`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "The levels of accuracy and the relevant accuracy metrics of high-risk AI systems shall be declared in the accompanying instructions of use."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: accuracy levels and metrics on the agent's business task].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Sanctuary does not measure agent task accuracy.

**Review notes:**

Structural manual row.

---

### Article 15(4) - Technical redundancy and fail-safe measures

- **Row ID:** `art_15_redundancy_failsafe`
- **Clause ID:** `art-15-4`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "High-risk AI systems shall be as resilient as possible [...] The robustness of high-risk AI systems may be achieved through technical redundancy solutions, which may include backup or fail-safe plans."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: technical redundancy and fail-safe plans for the deployment].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Redundancy architecture is an operational decision at the deployment level outside Sanctuary's scope.

**Review notes:**

Structural manual row.

---

### Article 26(1) - Use in accordance with instructions for use

- **Row ID:** `art_26_per_instructions`
- **Clause ID:** `art-26-1`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Deployers of high-risk AI systems shall take appropriate technical and organisational measures to ensure they use such systems in accordance with the instructions for use accompanying the systems [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: declaration of use in accordance with instructions].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Deployer-facing attestation, not a Sanctuary primitive.

**Review notes:**

Structural manual row.

---

### Article 26(2) - Assign human oversight to competent natural persons

- **Row ID:** `art_26_human_oversight_assigned`
- **Clause ID:** `art-26-2`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Deployers shall assign human oversight to natural persons who have the necessary competence, training and authority, as well as the necessary support."

**Evidence emitted by Sanctuary:**

Auto-filled: Sanctuary's approval channel configuration (stderr / dashboard / webhook) provides the technical substrate to which the enterprise binds its assigned human overseers. The Principal Policy Tier 1 rule list documents which operations require human approval.

**Evidence emitter tools:** `principal_policy_view`

**Enterprise input required:**

Identity of assigned overseers, their competence assessment, training records, authority scope, and the support infrastructure provided to them.

**Review notes:**

Sanctuary provides the technical oversight surface; enterprise assigns the people.

---

### Article 26(4) - Input data relevance and representativeness

- **Row ID:** `art_26_input_data_relevance`
- **Clause ID:** `art-26-4`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "[...] deployers shall ensure that input data is relevant and sufficiently representative in view of the intended purpose of the high-risk AI system."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: declaration of input data relevance and representativeness].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Input data governance is a deployer responsibility outside Sanctuary's runtime scope.

**Review notes:**

Structural manual row.

---

### Article 26(5) - Monitor operation and inform provider of incidents

- **Row ID:** `art_26_monitor_and_inform`
- **Clause ID:** `art-26-5`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Deployers shall monitor the operation of the high-risk AI system on the basis of the instructions for use [...]. When deployers have reason to consider that the use in accordance with the instructions for use may result in that AI system presenting a risk [...] they shall, without undue delay, inform the provider [...] and suspend the use of that system."

**Evidence emitted by Sanctuary:**

Auto-filled: the runtime monitoring substrate - encrypted audit log queryable and exportable in SIEM-standard formats, health dashboard, and anomaly baseline tracker. Provides the technical means to monitor and detect risk situations.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`, `monitor_health`, `principal_baseline_view`

**Enterprise input required:**

The enterprise's incident response workflow, the 'inform provider' communication channel and contacts, the suspension procedure, and the documented risk-detection criteria.

**Review notes:**

Sanctuary provides the detect-and-export half; enterprise provides the report-and-suspend half.

---

### Article 26(6) - Deployers keep logs for at least six months

- **Row ID:** `art_26_retain_logs`
- **Clause ID:** `art-26-6`
- **Coverage:** **PARTIAL**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Deployers of high-risk AI systems shall keep the logs automatically generated by that high-risk AI system, to the extent such logs are under their control, for a period appropriate to the intended purpose of the high-risk AI system, of at least six months [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Sanctuary's audit log persists entries by default until configured size or entry caps trigger authenticated rotation (defaults: 100,000 entries / 100 MB); it is exportable for archival at any time via audit_export_siem in CEF/OCSF formats suitable for long-term SIEM retention. A deployment whose six-month window exceeds those caps must archive via that export.

**Evidence emitter tools:** `monitor_audit_log`, `audit_export_siem`

**Enterprise input required:**

The enterprise's declared log retention policy, long-term archival pipeline, access control on archived logs, and written policy document satisfying the 'period appropriate to the intended purpose' requirement.

**Review notes:**

Downgraded from full during audit (2026-04-10). Sanctuary captures and exports; enterprise declares and archives. The retention policy is an enterprise governance artefact.

---

### Article 26(7) - Inform workers and workers' representatives (employment)

- **Row ID:** `art_26_workers_representatives`
- **Clause ID:** `art-26-7`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Before putting into service or using a high-risk AI system at the workplace, deployers who are employers shall inform workers' representatives and the affected workers that they will be subject to the use of the high-risk AI system."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: worker and workers' representative notification evidence].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Labour-relations obligation outside Sanctuary's scope.

**Review notes:**

Structural manual row. Applies only to employment-context deployments (Annex III §4).

---

### Article 26(9) - Data protection impact assessment per GDPR Art. 35

- **Row ID:** `art_26_dpia`
- **Clause ID:** `art-26-9`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Where applicable, deployers of high-risk AI systems shall use the information provided under Article 13 of this Regulation to comply with their obligation to carry out a data protection impact assessment under Article 35 of Regulation (EU) 2016/679 [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: DPIA under GDPR Article 35, where applicable].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

DPIA is a GDPR governance document. Sanctuary's transparency artefacts (SHR, audit log) may feed into a DPIA, but the assessment itself is enterprise-authored.

**Review notes:**

Structural manual row.

---

### Article 26(8) - Registration in EU database for Annex III systems

- **Row ID:** `art_26_eu_database_registration`
- **Clause ID:** `art-26-8`
- **Coverage:** **MANUAL ONLY**
- **Last reviewed:** 2026-04-10 by Erik Newton

**Requirement (verbatim, with `[...]` elisions):**

> "Deployers of high-risk AI systems referred to in Annex III that [...] are public authorities, [...] or deployers acting on their behalf, shall register themselves, select the system and register its use in the EU database referred to in Article 71 [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: EU database registration under Article 71, where applicable].

**Evidence emitter tools:** _(none - this row is manual_only)_

**Enterprise input required:**

Registration in the EU database is a legal procedural step the enterprise performs directly with the European Commission.

**Review notes:**

Structural manual row. Applies only to public authorities and those acting on their behalf.

---


## Disclaimer

**NOT LEGAL ADVICE.** This matrix is a technical mapping from Sanctuary primitives to Regulation (EU) 2024/1689 clause identifiers; it is not a legal interpretation of the EU AI Act and does not constitute a legal opinion. Consult qualified legal counsel before filing or relying on any compliance artifact generated from this matrix.

---

_Generated from `server/src/compliance/eu_ai_act/coverage_matrix.ts` via the `GENERATE_EXAMPLE=1` test pipeline. To regenerate: `cd server && GENERATE_EXAMPLE=1 npm test -- example-bundle`._

_Sanctuary Framework · Author: Erik Newton · License: Apache-2.0_
