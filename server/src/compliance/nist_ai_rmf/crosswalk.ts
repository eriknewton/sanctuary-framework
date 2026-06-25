/**
 * Sanctuary MCP Server, NIST AI RMF 1.0 Crosswalk v1
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * ─────────────────────────────────────────────────────────────────────
 * Maps NIST AI Risk Management Framework 1.0 (NIST AI 100-1)
 * subcategories to the SAME Sanctuary control catalog enumerated by the
 * EU AI Act coverage matrix (server/src/compliance/eu_ai_act/
 * coverage_matrix.ts). The evidence_emitter MCP tool names ARE the
 * shared control catalog: a reviewer comparing the two packs sees the
 * EU AI Act <-> NIST AI RMF overlap directly through shared tool names.
 *
 * HONESTY DISCIPLINE (the whole point of this file):
 *   - "covered" ONLY where a real, shipped Sanctuary mechanism enforces
 *     or directly produces the evidence for a subcategory.
 *   - The AI RMF is ~72 subcategories, and most of GOVERN (and large
 *     parts of MAP/MANAGE) are ORGANISATIONAL: policies, accountability
 *     structures, workforce diversity, legal review, stakeholder
 *     engagement. A runtime software framework has no mechanism for
 *     these. They are marked "not-applicable" with an honest note. This
 *     is NOT a Sanctuary deficiency; it is the correct scope boundary.
 *   - "partial" where Sanctuary emits structured evidence but the
 *     organisation must supply the surrounding narrative/process.
 *   - "gap" where a subcategory is genuinely technical and a tool could
 *     bear on it, but Sanctuary ships nothing that does today.
 *
 * NOT A CERTIFICATION. This is a tooling-coverage map, not a NIST
 * conformity assessment. See the preamble notes[] below.
 *
 * Subcategory summaries are short paraphrases for navigation, NOT
 * verbatim quotes of NIST AI 100-1.
 * ─────────────────────────────────────────────────────────────────────
 */

import type {
  NistCrosswalk,
  NistSubcategory,
  NistCoverageStats,
  NistCoverageFlag,
} from "./types.js";

export const FRAMEWORK_VERSION =
  "NIST AI RMF 1.0 (NIST AI 100-1), published 2023-01-26";

const REVIEW_DATE = "2026-06-25";

// ── The crosswalk rows ───────────────────────────────────────────────
//
// Ordering follows the AI RMF core: GOVERN, MAP, MEASURE, MANAGE.

const SUBCATEGORIES: NistSubcategory[] = [
  // ═══════════════════════════════════════════════════════════════════
  // GOVERN, policies, processes, procedures, and accountability
  // structures. Almost entirely organisational by design.
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "GOVERN 1.1",
    function: "GOVERN",
    category: "GOVERN 1",
    summary:
      "Legal and regulatory requirements involving AI are understood, " +
      "managed, and documented.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Understanding and documenting legal/regulatory requirements is " +
      "an organisational governance activity. Sanctuary has no mechanism " +
      "for it. (The EU AI Act pack helps an org PRODUCE a regulatory " +
      "artefact, but that is downstream of this governance subcategory.)",
    review_notes:
      "Organisational. Firmly not-applicable.",
  },
  {
    id: "GOVERN 1.2",
    function: "GOVERN",
    category: "GOVERN 1",
    summary:
      "A trustworthy-AI policy is integrated and characteristics are " +
      "tied to organisational risk tolerance.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Authoring and integrating an org-level trustworthy-AI policy is a " +
      "human governance act. Sanctuary's Principal Policy is a runtime " +
      "enforcement artefact, not the organisational risk-tolerance policy " +
      "this subcategory means.",
    review_notes:
      "Organisational. Tempting to over-read 'policy' as the Principal " +
      "Policy file, but that conflates a runtime enforcement config with " +
      "an org risk-tolerance statement. Kept not-applicable.",
  },
  {
    id: "GOVERN 1.3",
    function: "GOVERN",
    category: "GOVERN 1",
    summary:
      "Processes and procedures are in place to determine the needed " +
      "level of risk management based on impact.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Determining the appropriate level of risk management is an " +
      "organisational process decision.",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 1.4",
    function: "GOVERN",
    category: "GOVERN 1",
    summary:
      "The risk-management process and outcomes are established through " +
      "transparent policies, procedures, and other controls.",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view", "sovereignty_audit"],
    evidence_note:
      "Sanctuary contributes one transparent, machine-readable CONTROL " +
      "to the risk-management process: the inspectable Principal Policy " +
      "(tier rules, approval channel) via principal_policy_view, plus the " +
      "sovereignty_audit gap analysis. The broader policy/procedure set " +
      "is organisational.",
    review_notes:
      "UNSURE, flagged for reviewer. This is borderline not-applicable " +
      "vs partial. I called it partial because Sanctuary genuinely ships " +
      "a 'transparent control' (the inspectable policy) that is one of " +
      "the 'other controls' this subcategory enumerates. A stricter " +
      "reviewer may downgrade to not-applicable. Do NOT read as covered.",
  },
  {
    id: "GOVERN 1.5",
    function: "GOVERN",
    category: "GOVERN 1",
    summary:
      "Ongoing monitoring and periodic review of the risk-management " +
      "process and its effectiveness are planned.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Planning a periodic review cadence is an organisational activity. " +
      "(Sanctuary's runtime monitoring substrate appears under MEASURE/" +
      "MANAGE, not here.)",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 1.6",
    function: "GOVERN",
    category: "GOVERN 1",
    summary:
      "Mechanisms are in place to inventory AI systems and the inventory " +
      "is resourced per organisational risk priorities.",
    coverage: "partial",
    evidence_emitter: ["manifest", "identity_list", "shr_generate"],
    evidence_note:
      "Per Sanctuary-protected agent, the tool inventory (manifest), the " +
      "cryptographic identity inventory (identity_list), and the signed " +
      "capability report (shr_generate) constitute a machine-readable " +
      "per-system inventory entry. The ORG-WIDE inventory and its " +
      "resourcing are organisational.",
    review_notes:
      "UNSURE, flagged. Sanctuary inventories ONE system's capabilities " +
      "well, but GOVERN 1.6 means an organisation-wide AI system " +
      "inventory. Partial is the honest call (single-system substrate, " +
      "not the org inventory). A reviewer could argue not-applicable.",
  },
  {
    id: "GOVERN 1.7",
    function: "GOVERN",
    category: "GOVERN 1",
    summary:
      "Processes for decommissioning and phasing out AI systems safely " +
      "are established.",
    coverage: "partial",
    evidence_emitter: ["state_list", "monitor_audit_log"],
    evidence_note:
      "Sanctuary provides the technical substrate for safe data " +
      "handling at decommission: enumerable state (state_list), secure " +
      "deletion (a gated Tier 1 operation), and an audit trail of the " +
      "teardown (monitor_audit_log). The decommissioning PROCESS itself " +
      "is organisational.",
    review_notes:
      "UNSURE, flagged. The secure-delete + audit-trail mechanism is " +
      "real and bears on safe data decommission, but GOVERN 1.7 is " +
      "primarily about a process. Partial, leaning generous; a reviewer " +
      "may downgrade to not-applicable.",
  },
  {
    id: "GOVERN 2.1",
    function: "GOVERN",
    category: "GOVERN 2",
    summary:
      "Roles, responsibilities, and lines of communication for AI risk " +
      "management are documented and clear.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Org roles/responsibilities are an HR and governance concern with " +
      "no Sanctuary mechanism.",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 2.2",
    function: "GOVERN",
    category: "GOVERN 2",
    summary:
      "Training ensures personnel know their AI risk-management roles " +
      "and responsibilities.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Workforce training. No Sanctuary mechanism.",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 2.3",
    function: "GOVERN",
    category: "GOVERN 2",
    summary:
      "Executive leadership is responsible and accountable for AI " +
      "risk-management decisions.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Executive accountability. No software mechanism.",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 3.1",
    function: "GOVERN",
    category: "GOVERN 3",
    summary:
      "Decision-making about AI risks reflects a diverse, equitable, and " +
      "inclusive set of perspectives.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Workforce diversity and inclusive decision-making. No software " +
      "mechanism.",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 3.2",
    function: "GOVERN",
    category: "GOVERN 3",
    summary:
      "Policies define human oversight roles and team competencies for " +
      "AI systems.",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view", "principal_baseline_view"],
    evidence_note:
      "Sanctuary supplies the TECHNICAL human-oversight surface those " +
      "policies bind to: the approval channel and Tier 1 require-approval " +
      "rules (principal_policy_view) and the anomaly baseline tracker " +
      "(principal_baseline_view). Defining roles and competencies is " +
      "organisational.",
    review_notes:
      "Partial. Mirrors the EU pack's Art. 26(2) partial mapping " +
      "(same tools). The mechanism is real; the role/competency " +
      "definition is the org's.",
  },
  {
    id: "GOVERN 4.1",
    function: "GOVERN",
    category: "GOVERN 4",
    summary:
      "Organisational policies foster a critical-thinking and " +
      "safety-first mindset in AI design and deployment.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Organisational culture. No software mechanism.",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 4.2",
    function: "GOVERN",
    category: "GOVERN 4",
    summary:
      "Teams document the risks and potential impacts of the AI " +
      "technology they design, develop, deploy, and use.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Documenting risks/impacts is an organisational authoring activity " +
      "(Sanctuary's audit substrate can FEED such docs but does not " +
      "author the risk/impact narrative).",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 4.3",
    function: "GOVERN",
    category: "GOVERN 4",
    summary:
      "Organisational practices are in place to enable AI testing, " +
      "incident identification, and information sharing.",
    coverage: "partial",
    evidence_emitter: ["monitor_audit_log", "audit_export_siem"],
    evidence_note:
      "Sanctuary provides the incident-identification and information-" +
      "sharing SUBSTRATE: the queryable audit log (monitor_audit_log) and " +
      "SIEM export in CEF/OCSF (audit_export_siem) for forwarding to " +
      "enterprise incident pipelines. The practices/processes around it " +
      "are organisational.",
    review_notes:
      "Partial. The export-to-SIEM mechanism is a real contribution to " +
      "'information sharing'; the org practice is theirs.",
  },
  {
    id: "GOVERN 5.1",
    function: "GOVERN",
    category: "GOVERN 5",
    summary:
      "Mechanisms collect, evaluate, and integrate feedback from " +
      "external parties and affected communities.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Stakeholder engagement. No software mechanism.",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 5.2",
    function: "GOVERN",
    category: "GOVERN 5",
    summary:
      "Mechanisms enable AI actors to regularly incorporate adjudicated " +
      "feedback from relevant stakeholders.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Stakeholder feedback process. No software mechanism.",
    review_notes: "Organisational.",
  },
  {
    id: "GOVERN 6.1",
    function: "GOVERN",
    category: "GOVERN 6",
    summary:
      "Policies address AI risks associated with third-party software, " +
      "data, and supply chain.",
    coverage: "partial",
    evidence_emitter: [
      "context_gate_list_policies",
      "context_gate_enforcer_status",
    ],
    evidence_note:
      "Sanctuary ships ONE concrete third-party-risk CONTROL: outbound " +
      "context gating, which classifies agent context per provider " +
      "endpoint as allow/redact/hash/summarize/deny before any outbound " +
      "call (context_gate_list_policies, context_gate_enforcer_status). " +
      "This bounds data flowing to third-party services. Supply-chain " +
      "policy itself is organisational.",
    review_notes:
      "UNSURE, flagged. Context gating is genuinely a third-party data-" +
      "egress control, which is one slice of GOVERN 6.1 (third-party " +
      "DATA risk). It does NOT cover third-party software provenance or " +
      "supply-chain vetting. Partial, narrowly scoped; do not read as " +
      "broad supply-chain coverage.",
  },
  {
    id: "GOVERN 6.2",
    function: "GOVERN",
    category: "GOVERN 6",
    summary:
      "Contingency processes handle failures or incidents in third-party " +
      "data or AI systems deemed high-risk.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Contingency planning for third-party failures is an " +
      "organisational process.",
    review_notes: "Organisational.",
  },

  // ═══════════════════════════════════════════════════════════════════
  // MAP, context is recognised and risks related to context are
  // identified. Heavily organisational (intended purpose, impact
  // assessment), with a few technical-context subcategories Sanctuary
  // can emit.
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "MAP 1.1",
    function: "MAP",
    category: "MAP 1",
    summary:
      "Intended purpose, context of use, and assumptions are understood " +
      "and documented.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Intended purpose is a business-function narrative Sanctuary cannot " +
      "infer (this matches the EU pack's repeated 'intended purpose is " +
      "manual' finding).",
    review_notes: "Organisational / business narrative.",
  },
  {
    id: "MAP 1.2",
    function: "MAP",
    category: "MAP 1",
    summary:
      "Interdisciplinary AI actors and their expertise are mapped to " +
      "the system context.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Team/expertise mapping. No software mechanism.",
    review_notes: "Organisational.",
  },
  {
    id: "MAP 1.5",
    function: "MAP",
    category: "MAP 1",
    summary:
      "Organisational risk tolerances are determined and documented.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Risk-tolerance determination. Organisational.",
    review_notes: "Organisational.",
  },
  {
    id: "MAP 2.1",
    function: "MAP",
    category: "MAP 2",
    summary:
      "The specific tasks and methods to implement the AI system are " +
      "defined and documented (system requirements, dependencies).",
    coverage: "partial",
    evidence_emitter: ["manifest", "shr_generate", "context_gate_list_policies"],
    evidence_note:
      "Sanctuary emits the runtime DEPENDENCY/INTEGRATION map for the " +
      "system: the MCP tool inventory (manifest), the four-layer " +
      "capability report (shr_generate), and the outbound endpoints the " +
      "agent may contact (context_gate_list_policies). Task definition " +
      "and method documentation are organisational.",
    review_notes:
      "Partial. Maps to the same tools as EU Annex IV §1(b)/§2(c). The " +
      "integration/dependency surface is real; the task narrative is " +
      "the org's.",
  },
  {
    id: "MAP 2.2",
    function: "MAP",
    category: "MAP 2",
    summary:
      "Information about the AI system's knowledge limits and how output " +
      "will be used is documented.",
    coverage: "partial",
    evidence_emitter: ["shr_generate"],
    evidence_note:
      "The signed Sovereignty Health Report (shr_generate) carries an " +
      "explicit degradations[] array declaring honest capability limits " +
      "(e.g. NO_TEE, PROCESS_ISOLATION_ONLY) of the SANCTUARY layer. " +
      "Model/agent knowledge limits and downstream output use are " +
      "organisational.",
    review_notes:
      "UNSURE, flagged. The SHR declares SANCTUARY-LAYER limits " +
      "honestly, but MAP 2.2 means the AI MODEL's knowledge limits, " +
      "which Sanctuary does not measure. Partial is generous; a strict " +
      "reviewer may downgrade to not-applicable. Do not overstate.",
  },
  {
    id: "MAP 2.3",
    function: "MAP",
    category: "MAP 2",
    summary:
      "Scientific integrity and TEVV (test, evaluation, verification, " +
      "validation) considerations are identified and documented.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note:
      "Pre-deployment TEVV of the model is outside Sanctuary's runtime " +
      "scope (matches the EU pack's 'validation/testing is manual' " +
      "finding).",
    review_notes: "Organisational / pre-deployment.",
  },
  {
    id: "MAP 3.1",
    function: "MAP",
    category: "MAP 3",
    summary:
      "Potential benefits of the AI system are examined relative to " +
      "comparable non-AI alternatives.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Benefit analysis. Organisational.",
    review_notes: "Organisational.",
  },
  {
    id: "MAP 3.4",
    function: "MAP",
    category: "MAP 3",
    summary:
      "Processes for operator and practitioner proficiency with system " +
      "performance and trustworthiness are defined and assessed.",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view"],
    evidence_note:
      "Sanctuary supplies the technical oversight surface (approval " +
      "channel, Tier 1 rules via principal_policy_view) operators act " +
      "through. Operator proficiency assessment is organisational.",
    review_notes:
      "UNSURE, flagged. Thin mapping: the tool provides the surface, " +
      "not proficiency assessment. Leaning partial only because the " +
      "oversight mechanism is real. A reviewer may call not-applicable.",
  },
  {
    id: "MAP 4.1",
    function: "MAP",
    category: "MAP 4",
    summary:
      "Approaches to map risks from third-party entities (legal, " +
      "intellectual-property, data-privacy) are identified.",
    coverage: "partial",
    evidence_emitter: [
      "context_gate_list_policies",
      "context_gate_enforcer_status",
    ],
    evidence_note:
      "Outbound context gating is a concrete data-privacy control on " +
      "third-party egress (allow/redact/hash/summarize/deny per provider " +
      "endpoint). It maps one risk (third-party data exposure); legal/IP " +
      "risk mapping is organisational.",
    review_notes:
      "Partial, narrowly scoped to the data-egress slice. Same tools as " +
      "GOVERN 6.1; consistent.",
  },
  {
    id: "MAP 5.1",
    function: "MAP",
    category: "MAP 5",
    summary:
      "Likelihood and magnitude of each identified impact are " +
      "characterised based on context and feedback.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Impact characterisation. Organisational analysis.",
    review_notes: "Organisational.",
  },

  // ═══════════════════════════════════════════════════════════════════
  // MEASURE, identified risks are assessed, analysed, and tracked
  // using quantitative/qualitative tools. This is where Sanctuary's
  // runtime monitoring/audit substrate genuinely covers the
  // SECURITY/PROVENANCE characteristics; model-quality measurement
  // (accuracy, bias) is out of scope.
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "MEASURE 1.1",
    function: "MEASURE",
    category: "MEASURE 1",
    summary:
      "Approaches and metrics for measurement of AI risks are selected " +
      "and documented; gaps are noted.",
    coverage: "partial",
    evidence_emitter: ["sovereignty_audit"],
    evidence_note:
      "sovereignty_audit emits a structured gap analysis of the " +
      "Sanctuary sovereignty controls with prioritised recommendations: " +
      "a concrete, machine-readable risk-measurement output for the " +
      "security/sovereignty dimension. Selecting the org's full metric " +
      "set is organisational.",
    review_notes:
      "Partial. The gap analysis is real and on-point for the " +
      "sovereignty risk dimension; it is not the org's full metric set.",
  },
  {
    id: "MEASURE 1.3",
    function: "MEASURE",
    category: "MEASURE 1",
    summary:
      "Internal experts and independent assessors periodically assess " +
      "the measurement approach.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Independent assessment process. Organisational.",
    review_notes: "Organisational.",
  },
  {
    id: "MEASURE 2.1",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "Test sets, metrics, and details about the tools used for TEVV are " +
      "documented.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Pre-deployment TEVV documentation. Out of runtime scope.",
    review_notes: "Organisational / pre-deployment.",
  },
  {
    id: "MEASURE 2.4",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "The functioning and behaviour of the AI system is monitored in " +
      "deployment (production monitoring).",
    coverage: "covered",
    evidence_emitter: [
      "monitor_audit_log",
      "audit_export_siem",
      "monitor_health",
      "principal_baseline_view",
    ],
    evidence_note:
      "Shipped runtime monitoring: every tool call is recorded in the " +
      "encrypted audit log (monitor_audit_log), exportable in CEF/OCSF " +
      "to a SIEM (audit_export_siem); monitor_health reports live state-" +
      "integrity and subsystem status; principal_baseline_view exposes " +
      "the behavioural anomaly baseline. Production monitoring of the " +
      "Sanctuary-mediated behaviour is machine-verifiable.",
    review_notes:
      "Covered, scoped to behaviour MEDIATED BY Sanctuary tool calls " +
      "(the gate sees every tool call; it does not see the model's " +
      "internal reasoning). This scope note matters: covered for the " +
      "deployment-monitoring mechanism, not a claim to observe model " +
      "cognition.",
  },
  {
    id: "MEASURE 2.6",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "The AI system is evaluated for safety risks and for behaviour in " +
      "unexpected settings; mechanisms exist to halt/deactivate.",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view", "monitor_audit_log"],
    evidence_note:
      "Sanctuary ships a real pre-execution HALT mechanism: every Tier 1 " +
      "operation is gated pending human approval and denies on timeout " +
      "(principal_policy_view), with the decision recorded " +
      "(monitor_audit_log). This is the 'mechanism to halt/deactivate' " +
      "half. Safety EVALUATION of the model is organisational.",
    review_notes:
      "Partial. The halt mechanism is genuinely shipped (mirrors EU " +
      "Art. 14(4)(e), itself an honest partial because it is pre-" +
      "execution gating, not a mid-stream kill switch). The safety-" +
      "evaluation half is out of scope.",
  },
  {
    id: "MEASURE 2.7",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "AI system security and resilience (e.g. against adversarial " +
      "attacks, data poisoning, exfiltration) are evaluated and " +
      "documented.",
    coverage: "covered",
    evidence_emitter: [
      "sovereignty_audit",
      "shr_generate",
      "principal_policy_view",
      "context_gate_enforcer_status",
      "monitor_audit_log",
    ],
    evidence_note:
      "Shipped security/resilience controls, each independently " +
      "verifiable: AES-256-GCM encryption at rest with HKDF per-namespace " +
      "keys and Ed25519 self-custody (sovereignty_audit, shr_generate); " +
      "the three-tier approval gate with no-bypass routing " +
      "(principal_policy_view); outbound context gating that blocks " +
      "data exfiltration to third parties (context_gate_enforcer_status); " +
      "and a runtime prompt-injection detector whose hits land as " +
      "injection_detected:* audit entries (monitor_audit_log). This is " +
      "the same control set the EU pack marks 'full' at Annex IV §2(h) " +
      "and Art. 15(5).",
    review_notes:
      "Covered. This is Sanctuary's strongest mapping and the EU<->NIST " +
      "overlap is exact (same tools as the EU 'full' cybersecurity rows). " +
      "Honesty caveat carried over from the EU pack: TRAINING-time data/" +
      "model poisoning is NOT covered (runtime only); the injection " +
      "detector's config is not itself queryable, only its audit hits. " +
      "Covered is correct for the runtime security/resilience evaluation " +
      "mechanism.",
  },
  {
    id: "MEASURE 2.8",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "Risks associated with transparency and accountability are " +
      "examined and documented (provenance, model cards, lineage).",
    coverage: "covered",
    evidence_emitter: [
      "shr_generate",
      "monitor_audit_log",
      "audit_export_siem",
      "identity_list",
      "bridge_verify",
    ],
    evidence_note:
      "Shipped transparency/accountability primitives: a signed " +
      "Sovereignty Health Report (shr_generate) with honest degradation " +
      "declarations; a complete, queryable, AES-256-GCM-protected audit " +
      "trail of every tool call (monitor_audit_log, audit_export_siem); " +
      "cryptographic identity provenance and rotation chain " +
      "(identity_list); and cryptographic verification of Concordia " +
      "bridge attestations (bridge_verify). Together these provide " +
      "machine-verifiable provenance and accountability for agent " +
      "actions.",
    review_notes:
      "UNSURE, flagged. I marked this covered because the provenance/" +
      "accountability MECHANISM (signed reports + cryptographic audit " +
      "trail + identity lineage) is fully shipped and verifiable. " +
      "BUT MEASURE 2.8 also reaches model lineage / model cards, which " +
      "Sanctuary does NOT produce. A reviewer focused on model-card " +
      "lineage may downgrade to partial. Covered is for the action-" +
      "provenance reading; I am flagging the scope explicitly.",
  },
  {
    id: "MEASURE 2.9",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "The AI model is explained and validated to inform responsible " +
      "use and governance (explainability, interpretability).",
    coverage: "gap",
    evidence_emitter: [],
    evidence_note:
      "Model explainability/interpretability is technical but Sanctuary " +
      "ships NO mechanism for it (it sees tool calls, not model " +
      "internals). Honest gap rather than not-applicable, because this is " +
      "a technical (not organisational) subcategory a tool could address.",
    review_notes:
      "Gap (not not-applicable) on purpose: this is a technical " +
      "capability Sanctuary lacks, not an org-process row.",
  },
  {
    id: "MEASURE 2.10",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "Privacy risk of the AI system is examined and documented.",
    coverage: "partial",
    evidence_emitter: [
      "context_gate_list_policies",
      "context_gate_enforcer_status",
      "sovereignty_audit",
    ],
    evidence_note:
      "Sanctuary ships concrete privacy CONTROLS: outbound context " +
      "gating with per-field redact/hash/summarize/deny classification " +
      "before any external call, and a selective-disclosure layer " +
      "(Pedersen commitments / range proofs) surfaced via " +
      "sovereignty_audit. These bound data exposure. The privacy-risk " +
      "ASSESSMENT narrative (e.g. a DPIA) is organisational.",
    review_notes:
      "Partial. The egress/redaction and selective-disclosure controls " +
      "are real privacy mechanisms; the documented privacy-risk " +
      "assessment is the org's.",
  },
  {
    id: "MEASURE 2.11",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "Fairness and bias of the AI system are evaluated and results " +
      "documented.",
    coverage: "gap",
    evidence_emitter: [],
    evidence_note:
      "Fairness/bias evaluation is technical but Sanctuary ships no " +
      "mechanism for it (it does not inspect model outputs for bias). " +
      "Honest gap.",
    review_notes:
      "Gap (technical capability absent), not not-applicable.",
  },
  {
    id: "MEASURE 2.13",
    function: "MEASURE",
    category: "MEASURE 2",
    summary:
      "Effectiveness of the deployed measurement approach is evaluated " +
      "after deployment.",
    coverage: "partial",
    evidence_emitter: ["sovereignty_audit", "monitor_health"],
    evidence_note:
      "Sanctuary's self-assessment outputs (sovereignty_audit gap " +
      "analysis, monitor_health subsystem status) let an org evaluate " +
      "whether the sovereignty controls are functioning post-deployment. " +
      "Evaluating the FULL measurement approach is organisational.",
    review_notes:
      "UNSURE, flagged. Thin: the self-audit outputs support this for " +
      "the sovereignty dimension only. Partial leaning generous.",
  },
  {
    id: "MEASURE 3.1",
    function: "MEASURE",
    category: "MEASURE 3",
    summary:
      "Approaches/mechanisms exist to identify and track existing, " +
      "unanticipated, and emergent AI risks.",
    coverage: "partial",
    evidence_emitter: ["principal_baseline_view", "monitor_audit_log"],
    evidence_note:
      "Sanctuary ships a behavioural anomaly baseline tracker " +
      "(principal_baseline_view) that flags deviations from learned " +
      "frequency/namespace baselines, plus the audit trail " +
      "(monitor_audit_log) to track them. This is a real emergent-" +
      "anomaly tracking mechanism for tool-call behaviour. Broader " +
      "emergent-risk identification is organisational.",
    review_notes:
      "Partial. The anomaly tracker genuinely identifies unanticipated " +
      "tool-call behaviour; it is not a general emergent-risk program.",
  },
  {
    id: "MEASURE 3.3",
    function: "MEASURE",
    category: "MEASURE 3",
    summary:
      "Feedback from end users and impacted communities about system " +
      "performance is captured and assessed.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "End-user feedback capture. Organisational.",
    review_notes: "Organisational.",
  },
  {
    id: "MEASURE 4.1",
    function: "MEASURE",
    category: "MEASURE 4",
    summary:
      "Measurement approaches for trustworthiness are connected to " +
      "deployment context and validated with domain experts.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Expert validation of measures. Organisational.",
    review_notes: "Organisational.",
  },
  {
    id: "MEASURE 4.2",
    function: "MEASURE",
    category: "MEASURE 4",
    summary:
      "Measurement results regarding trustworthiness are informed by " +
      "domain-expert and user feedback about operational deployment.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Feedback-informed measurement. Organisational.",
    review_notes: "Organisational.",
  },

  // ═══════════════════════════════════════════════════════════════════
  // MANAGE, risks are prioritised and acted upon. Sanctuary covers the
  // runtime RISK-RESPONSE and TREATMENT mechanisms (gating, deny,
  // monitoring, incident substrate); prioritisation/decision processes
  // are organisational.
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "MANAGE 1.2",
    function: "MANAGE",
    category: "MANAGE 1",
    summary:
      "Treatment of identified AI risks is prioritised based on impact, " +
      "likelihood, and available resources.",
    coverage: "not-applicable",
    evidence_emitter: [],
    evidence_note: "Risk prioritisation decision-making. Organisational.",
    review_notes: "Organisational.",
  },
  {
    id: "MANAGE 1.3",
    function: "MANAGE",
    category: "MANAGE 1",
    summary:
      "Responses to high-priority AI risks are developed, planned, and " +
      "documented (mitigate, transfer, avoid, accept).",
    coverage: "partial",
    evidence_emitter: [
      "principal_policy_view",
      "context_gate_list_policies",
    ],
    evidence_note:
      "Sanctuary ships concrete risk-RESPONSE controls that an org maps " +
      "to its treatment plan: the approval-gate tiers (mitigate via human " +
      "approval / avoid via deny-on-timeout) and outbound context gating " +
      "(mitigate data-egress risk). Selecting and documenting the " +
      "response strategy is organisational.",
    review_notes:
      "Partial. The enforcement controls are real treatment mechanisms; " +
      "the response PLAN is the org's. Mirrors EU Annex IV §5.",
  },
  {
    id: "MANAGE 2.1",
    function: "MANAGE",
    category: "MANAGE 2",
    summary:
      "Resources are allocated to apply risk treatments, including " +
      "supersession, deactivation, or non-deployment options.",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view"],
    evidence_note:
      "Sanctuary provides the technical 'decide-not-to-use' control: " +
      "Tier 1 operations default to deny on approval timeout " +
      "(principal_policy_view). Resource allocation is organisational.",
    review_notes:
      "UNSURE, flagged. The deny-on-timeout 'non-use' control is real " +
      "(mirrors EU Art. 14(4)(d)), but MANAGE 2.1 is mostly about " +
      "resource allocation, which Sanctuary does not touch. Partial " +
      "leaning generous; a reviewer may downgrade.",
  },
  {
    id: "MANAGE 2.2",
    function: "MANAGE",
    category: "MANAGE 2",
    summary:
      "Mechanisms are in place and applied to sustain the value of " +
      "deployed AI systems (ongoing maintenance, controls).",
    coverage: "partial",
    evidence_emitter: ["monitor_health", "sovereignty_audit"],
    evidence_note:
      "Sanctuary's live health reporting (monitor_health) and self-audit " +
      "(sovereignty_audit) sustain the sovereignty controls in operation. " +
      "Broader value-sustainment maintenance is organisational.",
    review_notes:
      "UNSURE, flagged. Thin mapping; partial only for the control-" +
      "health-sustainment slice.",
  },
  {
    id: "MANAGE 2.3",
    function: "MANAGE",
    category: "MANAGE 2",
    summary:
      "Procedures follow to respond to and recover from a previously " +
      "unknown risk when it is identified.",
    coverage: "partial",
    evidence_emitter: ["monitor_audit_log", "audit_export_siem"],
    evidence_note:
      "Sanctuary provides the incident-response SUBSTRATE: a queryable " +
      "audit trail (monitor_audit_log) and SIEM export (audit_export_siem) " +
      "to drive enterprise incident-response/recovery pipelines. The " +
      "response/recovery PROCEDURES are organisational.",
    review_notes:
      "Partial. The audit/export substrate is real; the procedures are " +
      "the org's.",
  },
  {
    id: "MANAGE 2.4",
    function: "MANAGE",
    category: "MANAGE 2",
    summary:
      "Mechanisms are in place and applied, and responsibilities " +
      "assigned, to supersede, disengage, or deactivate AI systems that " +
      "demonstrate unacceptable performance or behaviour.",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view", "monitor_audit_log"],
    evidence_note:
      "Sanctuary ships the DISENGAGE/DEACTIVATE mechanism at the action " +
      "layer: every Tier 1 operation halts pending human approval and " +
      "denies on timeout (principal_policy_view), recorded in the audit " +
      "trail (monitor_audit_log). Assigning the responsibility is " +
      "organisational.",
    review_notes:
      "Partial. Honest caveat (same as EU Art. 14(4)(e)): this is pre-" +
      "execution gating, not a mid-stream kill switch for an already-" +
      "running model. The deactivation-of-action mechanism is real.",
  },
  {
    id: "MANAGE 3.1",
    function: "MANAGE",
    category: "MANAGE 3",
    summary:
      "AI risks and benefits from third-party resources are regularly " +
      "monitored, and risk controls are applied and documented.",
    coverage: "partial",
    evidence_emitter: [
      "context_gate_enforcer_status",
      "context_gate_list_policies",
      "monitor_audit_log",
    ],
    evidence_note:
      "Outbound context gating is an applied, documented risk control on " +
      "third-party data egress (enforcer status + policy listing), and " +
      "calls to third-party endpoints are recorded in the audit trail. " +
      "Monitoring third-party BENEFITS and full supply-chain risk is " +
      "organisational.",
    review_notes:
      "Partial, scoped to the third-party data-egress control. Consistent " +
      "with GOVERN 6.1 / MAP 4.1.",
  },
  {
    id: "MANAGE 3.2",
    function: "MANAGE",
    category: "MANAGE 3",
    summary:
      "Pre-trained models or other third-party AI used in the system " +
      "are monitored as part of regular risk monitoring.",
    coverage: "gap",
    evidence_emitter: [],
    evidence_note:
      "Monitoring the behaviour of an embedded third-party/pre-trained " +
      "model is technical, but Sanctuary ships no model-level monitoring " +
      "(it monitors tool calls, not model weights/behaviour). Honest gap.",
    review_notes:
      "Gap (technical capability absent), not not-applicable.",
  },
  {
    id: "MANAGE 4.1",
    function: "MANAGE",
    category: "MANAGE 4",
    summary:
      "Post-deployment monitoring plans are implemented, including " +
      "mechanisms for capturing and evaluating input from users and " +
      "incidents.",
    coverage: "partial",
    evidence_emitter: [
      "monitor_audit_log",
      "audit_export_siem",
      "monitor_health",
      "principal_baseline_view",
    ],
    evidence_note:
      "Sanctuary implements the technical post-deployment MONITORING " +
      "substrate of such a plan: continuous audit logging, SIEM export, " +
      "health reporting, and anomaly baselining. The plan itself and the " +
      "user-input capture are organisational.",
    review_notes:
      "Partial. Strong substrate mapping (same tools as MEASURE 2.4); the " +
      "plan and user-feedback loop are the org's. Mirrors EU Annex IV §9 " +
      "/ Art. 72.",
  },
  {
    id: "MANAGE 4.2",
    function: "MANAGE",
    category: "MANAGE 4",
    summary:
      "Measurable activities for continual improvement are integrated, " +
      "including mechanisms for incorporating updates and changes.",
    coverage: "partial",
    evidence_emitter: ["monitor_audit_log", "identity_list"],
    evidence_note:
      "Sanctuary cryptographically records changes within its layer " +
      "(policy/identity/state operations in the audit trail; identity " +
      "rotation chain via identity_list), giving a verifiable change " +
      "timeline. The continual-improvement PROGRAM is organisational.",
    review_notes:
      "Partial. The change-timeline mechanism is real (mirrors EU Annex " +
      "IV §6); the improvement program is the org's.",
  },
  {
    id: "MANAGE 4.3",
    function: "MANAGE",
    category: "MANAGE 4",
    summary:
      "Incidents and errors are communicated to relevant AI actors and " +
      "documented; processes for tracking and response are followed.",
    coverage: "partial",
    evidence_emitter: ["audit_export_siem", "monitor_audit_log"],
    evidence_note:
      "Sanctuary's SIEM export (CEF/OCSF) feeds incident communication " +
      "and tracking pipelines, and the audit log is the documented record " +
      "of gate decisions and injection detections. The communication " +
      "process and external reporting are organisational.",
    review_notes:
      "Partial. Export/record mechanism is real; the comms process is " +
      "the org's.",
  },
];

// ── The exported crosswalk ───────────────────────────────────────────

export const NIST_CROSSWALK_V1: NistCrosswalk = {
  crosswalk_version: "v1",
  framework_version: FRAMEWORK_VERSION,
  framework: {
    name: "NIST AI Risk Management Framework",
    official_reference: "NIST AI 100-1 (AI RMF 1.0)",
    published: "2023-01-26",
    aligned_to: "AI RMF 1.0 core (GOVERN, MAP, MEASURE, MANAGE)",
    last_full_review: REVIEW_DATE,
  },
  notes: [
    "TOOLING-COVERAGE MAP, NOT A CERTIFICATION. This crosswalk states " +
      "which NIST AI RMF subcategories a shipped Sanctuary mechanism " +
      "bears on. It is not a NIST conformity assessment and does not " +
      "assert that an organisation has implemented the AI RMF.",
    "ORGANISATIONAL SUBCATEGORIES ARE OUT OF SCOPE. The AI RMF is " +
      "deliberately org-centric: most of GOVERN, and significant parts " +
      "of MAP/MEASURE/MANAGE, concern policies, accountability, " +
      "workforce, and stakeholder processes that a runtime software " +
      "framework structurally cannot satisfy. Those are marked " +
      "'not-applicable' with an honest note; this reflects the scope " +
      "boundary of a tool, not a deficiency.",
    "SHARED CONTROL CATALOG. Every evidence_emitter here is an MCP tool " +
      "name also used by the EU AI Act coverage matrix. The two packs " +
      "share one control catalog so a reviewer sees the EU AI Act <-> " +
      "NIST AI RMF overlap directly. The strongest overlap is the " +
      "runtime security/resilience and audit/provenance controls " +
      "(MEASURE 2.7 / 2.8 here; Annex IV §2(h) / Art. 12 / Art. 15(5) " +
      "in the EU pack).",
    "HONESTY OVER COVERAGE. 'covered' is used only where a real shipped " +
      "mechanism is independently verifiable by running the named " +
      "tool(s). 'gap' marks technical subcategories (e.g. model " +
      "explainability, bias evaluation, model-level monitoring) that " +
      "Sanctuary does NOT address today; these are honest holes, not " +
      "organisational exclusions.",
    "SUBCATEGORY COVERAGE IS PARTIAL BY SELECTION. This v1 maps the AI " +
      "RMF subcategories where Sanctuary plausibly bears on the row " +
      "plus a representative sample of the organisational rows for " +
      "context; it is not an exhaustive enumeration of all ~72 AI RMF " +
      "1.0 subcategories. Absence of a subcategory here is not a claim " +
      "about it.",
  ],
  subcategories: SUBCATEGORIES,
};

// ── Helper functions ─────────────────────────────────────────────────

export function subcategoriesByCoverage(
  crosswalk: NistCrosswalk,
  flag: NistCoverageFlag
): NistSubcategory[] {
  return crosswalk.subcategories.filter((s) => s.coverage === flag);
}

export function subcategoriesByFunction(
  crosswalk: NistCrosswalk,
  fn: NistSubcategory["function"]
): NistSubcategory[] {
  return crosswalk.subcategories.filter((s) => s.function === fn);
}

export function subcategoryById(
  crosswalk: NistCrosswalk,
  id: string
): NistSubcategory | undefined {
  return crosswalk.subcategories.find((s) => s.id === id);
}

/**
 * The set of unique Sanctuary tool names this crosswalk references as
 * evidence emitters. Used by the consistency test to assert every one
 * is also in the EU AI Act matrix's emitter set (the shared catalog).
 */
export function allEvidenceEmitters(crosswalk: NistCrosswalk): string[] {
  const set = new Set<string>();
  for (const s of crosswalk.subcategories) {
    for (const tool of s.evidence_emitter) set.add(tool);
  }
  return Array.from(set).sort();
}

export function coverageStats(crosswalk: NistCrosswalk): NistCoverageStats {
  const total = crosswalk.subcategories.length;
  const covered = subcategoriesByCoverage(crosswalk, "covered").length;
  const partial = subcategoriesByCoverage(crosswalk, "partial").length;
  const na = subcategoriesByCoverage(crosswalk, "not-applicable").length;
  const gap = subcategoriesByCoverage(crosswalk, "gap").length;
  const pct = (n: number) => (total === 0 ? 0 : Math.round((n / total) * 100));
  return {
    total,
    covered,
    partial,
    not_applicable: na,
    gap,
    covered_pct: pct(covered),
    partial_pct: pct(partial),
    not_applicable_pct: pct(na),
    gap_pct: pct(gap),
  };
}
