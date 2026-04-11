/**
 * Sanctuary MCP Server — EU AI Act Coverage Matrix v1
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * ─────────────────────────────────────────────────────────────────────
 * Maps Sanctuary primitives to Regulation (EU) 2024/1689 (EU AI Act)
 * technical documentation requirements. This file is the honest-over-
 * optimistic spine of the EU AI Act Compliance Artifact Generator.
 *
 * Every row carries its own freshness metadata and names the Sanctuary
 * MCP tool(s) that emit the evidence, so an auditor can independently
 * verify every coverage claim by running the listed tools against a
 * live instance.
 *
 * Coverage classification (strict):
 *   - "full"        — emittable from Sanctuary tool output alone,
 *                     zero enterprise input, machine-verifiable
 *   - "partial"     — Sanctuary emits structured evidence; enterprise
 *                     supplies business context to complete the row
 *   - "manual_only" — Sanctuary has no visibility; row is entirely
 *                     enterprise-authored
 *
 * Regulation citations are verbatim from Regulation (EU) 2024/1689 as
 * published in OJ L 2024/1689 of 12 July 2024, with [...] elisions for
 * length management. Short verbatim fragments are preferred over long
 * reconstructed quotes.
 *
 * NOT LEGAL ADVICE. This matrix is a technical mapping from Sanctuary
 * primitives to regulation clause identifiers; it is not a legal
 * interpretation of the EU AI Act and does not constitute legal advice.
 * ─────────────────────────────────────────────────────────────────────
 */

// ── Top-level metadata ───────────────────────────────────────────────

/**
 * Display-level freshness anchor. Rendered into every generated
 * compliance document header. Bump this string whenever the aligned
 * regulation text changes (e.g., after the European Commission
 * publishes implementing acts).
 */
export const REGULATION_VERSION =
  "EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10";

// ── Types ────────────────────────────────────────────────────────────

export type CoverageFlag = "full" | "partial" | "manual_only";
export type Instrument = "Annex IV" | "Article";

export interface CoverageCitation {
  /** "Annex IV" | "Article" */
  instrument: Instrument;
  /** Human-readable section, e.g., "§2(h)" | "12" | "13(3)(a)" */
  section: string;
  /**
   * Stable, machine-queryable clause identifier derived from the
   * instrument + section. Templates render citations from this field
   * without parsing the verbatim quote.
   */
  clause_id: string;
  /** Short human-readable title. */
  title: string;
}

export interface CoverageRow {
  /** Stable row ID used in template slotting and tests. */
  id: string;
  citation: CoverageCitation;
  /**
   * Verbatim regulation text (with [...] elisions for length). Never
   * paraphrase. When uncertain of exact wording, elide aggressively
   * rather than reconstruct.
   */
  requirement: string;
  coverage: CoverageFlag;
  /**
   * Runnable Sanctuary MCP tool names (unprefixed, v0.7.0+) whose
   * output contains the evidence for this row. Empty array for
   * manual_only rows. Auditor traceability chain.
   */
  evidence_emitter: string[];
  /**
   * Prose description of what the generated template emits for this
   * row. For full rows, this is machine-verifiable capability
   * inventory. For partial rows, this describes the pre-filled
   * evidence. For manual_only rows, this is the
   * [MANUAL INPUT REQUIRED: ...] marker and reason.
   */
  evidence_emitted: string;
  /**
   * What the enterprise must supply. Null iff coverage === "full".
   */
  manual_carveout: string | null;
  /** ISO date of last per-row review. */
  last_reviewed_date: string;
  last_reviewed_by: string;
  /**
   * Per-row rationale for the classification. Load-bearing for
   * future maintainers — explains *why* a row is classified the way
   * it is, including any verification corrections applied.
   */
  review_notes: string;
}

export interface CoverageMatrix {
  matrix_version: "v1";
  /** See REGULATION_VERSION — human-readable display anchor. */
  regulation_version: string;
  /** Structured regulation metadata for programmatic diffing. */
  regulation: {
    name: "EU AI Act";
    official_reference: "Regulation (EU) 2024/1689";
    oj_reference: "OJ L, 2024/1689, 12 July 2024";
    full_enforcement_date: "2026-08-02";
    aligned_to_text_version: "OJ published text";
    last_full_review: "2026-04-10";
    next_review_due: "2026-06-01";
  };
  notes: string[];
  rows: CoverageRow[];
}

// ── Helper constants ─────────────────────────────────────────────────

const REVIEW_DATE = "2026-04-10";
const REVIEWER = "Erik Newton";

// ── The matrix ───────────────────────────────────────────────────────

const ROWS: CoverageRow[] = [
  // ═══════════════════════════════════════════════════════════════════
  // ANNEX IV — Technical Documentation Requirements (per Article 11)
  // ═══════════════════════════════════════════════════════════════════

  // ─── §1 General description ─────────────────────────────────────

  {
    id: "annex_iv_1_a_general_description",
    citation: {
      instrument: "Annex IV",
      section: "§1(a)",
      clause_id: "annex-iv-1-a",
      title: "General description: intended purpose, provider, version",
    },
    requirement:
      "\"Its intended purpose, the name of the provider and the version " +
      "of the system [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "identity_list",
      "identity_set_primary",
      "manifest",
      "shr_generate",
    ],
    evidence_emitted:
      "Auto-filled: cryptographic provider identity (primary Ed25519 " +
      "DID + public key via identity_list and identity_set_primary), " +
      "Sanctuary version and implementation metadata (via manifest), " +
      "and signed SHR instance_id. The template pre-populates the " +
      "version-and-identity portion of this row with machine-verifiable " +
      "cryptographic evidence.",
    manual_carveout:
      "Intended purpose of the agent (business function), legal " +
      "provider name and registered entity, and version-naming " +
      "conventions used by the enterprise.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Partial is honest here: Sanctuary can emit a cryptographic " +
      "provider identity and a software version, but 'intended purpose' " +
      "is inherently a business-function narrative that Sanctuary " +
      "cannot infer. Resist any temptation to call this full.",
  },

  {
    id: "annex_iv_1_b_hardware_software_interaction",
    citation: {
      instrument: "Annex IV",
      section: "§1(b)",
      clause_id: "annex-iv-1-b",
      title: "Interaction with external hardware or software",
    },
    requirement:
      "\"How the AI system interacts, or can be used to interact, with " +
      "hardware or software [...] that is not part of the AI system " +
      "itself [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "shr_generate",
      "manifest",
      "context_gate_list_policies",
    ],
    evidence_emitted:
      "Auto-filled: SHR layers.l2.model_provenance (provider, " +
      "open-weights flag, local-inference flag, optional weights hash), " +
      "MCP tool inventory (via manifest) listing every integration " +
      "point the agent exposes, and the outbound context-gating policy " +
      "manifest (via context_gate_list_policies) showing which provider " +
      "endpoints the agent is permitted to contact and under what " +
      "field-level constraints.",
    manual_carveout:
      "Upstream LLM contracts and data processing agreements, " +
      "third-party API integrations, downstream systems consuming " +
      "agent output, and any hardware peripherals the agent " +
      "orchestrates.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary genuinely covers ~60% of this row when model_provenance " +
      "is populated by the integrator. The template emits a structured " +
      "interaction manifest and marks the business-context narrative as " +
      "[MANUAL INPUT REQUIRED].",
  },

  {
    id: "annex_iv_1_c_software_versions",
    citation: {
      instrument: "Annex IV",
      section: "§1(c)",
      clause_id: "annex-iv-1-c",
      title: "Versions of relevant software and firmware",
    },
    requirement:
      "\"The versions of relevant software or firmware [...].\"",
    coverage: "partial",
    evidence_emitter: ["manifest", "shr_generate", "monitor_health"],
    evidence_emitted:
      "Auto-filled: Sanctuary MCP server version (from manifest and " +
      "SHR implementation block), Node.js runtime version, MCP SDK " +
      "version, and platform string. The template emits a versioned " +
      "software manifest for the Sanctuary layer itself.",
    manual_carveout:
      "LLM model version and weights hash (if not set in " +
      "model_provenance), agent harness version (OpenClaw or other), " +
      "operating system patch level, container image digest, and any " +
      "other 'relevant' software outside Sanctuary's runtime scope.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Downgraded from full during verification (2026-04-10). Sanctuary " +
      "auto-emits its own version + Node version, but 'relevant software' " +
      "extends beyond Sanctuary and the enterprise must enumerate the " +
      "rest. Partial is the honest call.",
  },

  {
    id: "annex_iv_1_d_forms_on_market",
    citation: {
      instrument: "Annex IV",
      section: "§1(d)",
      clause_id: "annex-iv-1-d",
      title: "Forms in which the system is placed on the market",
    },
    requirement:
      "\"The description of all the forms in which the AI system is " +
      "placed on the market or put into service [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: forms in which the AI system is placed " +
      "on the market or put into service].",
    manual_carveout:
      "Sanctuary is a runtime sovereignty layer and has no visibility " +
      "into the commercial forms in which the enterprise distributes " +
      "or operates the agent.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row — commercial distribution is not a " +
      "Sanctuary concern and will not become one.",
  },

  {
    id: "annex_iv_1_e_hardware_description",
    citation: {
      instrument: "Annex IV",
      section: "§1(e)",
      clause_id: "annex-iv-1-e",
      title: "Description of the hardware on which the system runs",
    },
    requirement:
      "\"The description of the hardware on which the AI system is " +
      "intended to run [...].\"",
    coverage: "partial",
    evidence_emitter: ["exec_attest", "monitor_health", "sovereignty_audit"],
    evidence_emitted:
      "Auto-filled: execution environment attestation (via exec_attest) " +
      "reporting CPU vendor, TEE availability, operating system string, " +
      "and Node.js runtime; sovereignty_audit environment fingerprint. " +
      "The template emits the detected hardware context as structured " +
      "evidence.",
    manual_carveout:
      "Production hardware specifications, TEE attestation evidence " +
      "from the actual deployment environment, geographic location of " +
      "the execution environment, and any hardware security modules " +
      "or trusted hardware used in production.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "In local-process mode Sanctuary emits tee_available=false, which " +
      "is honest but incomplete — production may run on TEE-capable " +
      "hardware that Sanctuary does not detect. SHR degradation " +
      "NO_TEE is flagged automatically.",
  },

  {
    id: "annex_iv_1_f_instructions_of_use",
    citation: {
      instrument: "Annex IV",
      section: "§1(f)",
      clause_id: "annex-iv-1-f",
      title: "Basic description of the user interface",
    },
    requirement:
      "\"A basic description of the user interface provided to the " +
      "deployer [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: description of the user interface " +
      "provided to the deployer].",
    manual_carveout:
      "User interface design is an agent-level or enterprise-level " +
      "product decision outside Sanctuary's scope.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row.",
  },

  // ─── §2 Detailed description of elements ────────────────────────

  {
    id: "annex_iv_2_a_development_methods",
    citation: {
      instrument: "Annex IV",
      section: "§2(a)",
      clause_id: "annex-iv-2-a",
      title: "Methods and steps performed for development",
    },
    requirement:
      "\"The methods and steps performed for the development of the AI " +
      "system [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: development methodology, design " +
      "iterations, training procedures, validation steps].",
    manual_carveout:
      "Sanctuary is a runtime sovereignty layer and is not involved " +
      "in model development, training, or pre-deployment validation.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row — model development is outside Sanctuary's " +
      "architectural scope.",
  },

  {
    id: "annex_iv_2_b_design_specifications",
    citation: {
      instrument: "Annex IV",
      section: "§2(b)",
      clause_id: "annex-iv-2-b",
      title: "Design specifications and key design choices",
    },
    requirement:
      "\"The design specifications of the system, namely the general " +
      "logic of the AI system [...] the key design choices including the " +
      "rationale and assumptions made [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "principal_policy_view",
      "context_gate_list_policies",
      "sovereignty_profile_get",
      "manifest",
    ],
    evidence_emitted:
      "Auto-filled: machine-readable Principal Policy YAML (tier rules, " +
      "approval channel configuration, anomaly thresholds), context " +
      "gating policy manifest, sovereignty profile, and the full MCP " +
      "tool inventory. Together these constitute the declarative design " +
      "specification of the Sanctuary sovereignty layer.",
    manual_carveout:
      "Agent-level business logic, decision algorithms, the rationale " +
      "for key design choices (why this policy, why these thresholds), " +
      "assumptions made during development, and any non-Sanctuary " +
      "architectural components.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Borderline partial — Sanctuary emits the policy and gating " +
      "specifications as structured data, but 'key design choices " +
      "including rationale' is inherently a narrative field that " +
      "requires enterprise authorship. Kept partial deliberately.",
  },

  {
    id: "annex_iv_2_c_system_architecture",
    citation: {
      instrument: "Annex IV",
      section: "§2(c)",
      clause_id: "annex-iv-2-c",
      title: "Description of system architecture",
    },
    requirement:
      "\"The description of the system architecture explaining how " +
      "software components build on or feed into each other and " +
      "integrate into the overall processing [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "shr_generate",
      "manifest",
      "sovereignty_audit",
      "federation_status",
    ],
    evidence_emitted:
      "Auto-filled: SHR four-layer architecture description (L1 " +
      "Cognitive Sovereignty, L2 Operational Isolation, L3 Selective " +
      "Disclosure, L4 Verifiable Reputation) with status flags per " +
      "layer, tool inventory showing every component interface, " +
      "sovereignty audit environment analysis, and federation peer " +
      "topology if configured.",
    manual_carveout:
      "Agent-level architecture (LLM orchestration, prompt templates, " +
      "tool-use loops), upstream data flows into the agent, downstream " +
      "systems consuming agent output, and the integration story " +
      "between Sanctuary and the rest of the enterprise stack.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Borderline partial — Sanctuary emits a complete architectural " +
      "description of its own layer but this row requires the " +
      "architecture of the AI system as a whole. Enterprise wraps the " +
      "Sanctuary layer in a broader architecture narrative.",
  },

  {
    id: "annex_iv_2_d_data_requirements",
    citation: {
      instrument: "Annex IV",
      section: "§2(d)",
      clause_id: "annex-iv-2-d",
      title: "Data requirements: training data datasheets",
    },
    requirement:
      "\"Where applicable, the data requirements in terms of datasheets " +
      "describing the training methodologies and techniques and the " +
      "training data sets used, including [...] provenance, scope and " +
      "main characteristics; how the data was obtained and selected; " +
      "labelling procedures [...] and data cleaning methodologies " +
      "[...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: training data description, provenance, " +
      "scope, labelling, cleaning, and governance].",
    manual_carveout:
      "Sanctuary is a runtime sovereignty layer and has no visibility " +
      "into model training. Training data governance is entirely the " +
      "responsibility of the model provider or enterprise data team.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Classification is structurally stable across EU AI Act revisions.",
  },

  {
    id: "annex_iv_2_e_human_oversight_assessment",
    citation: {
      instrument: "Annex IV",
      section: "§2(e)",
      clause_id: "annex-iv-2-e",
      title: "Assessment of human oversight measures per Article 14",
    },
    requirement:
      "\"Assessment of the human oversight measures needed in accordance " +
      "with Article 14, including an assessment of the technical measures " +
      "needed to facilitate the interpretation of the outputs of AI " +
      "systems by the deployers [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "principal_policy_view",
      "sovereignty_audit",
      "shr_generate",
      "principal_baseline_view",
    ],
    evidence_emitted:
      "Auto-filled: Principal Policy approval channel configuration " +
      "(stderr / dashboard / webhook), Tier 1 require-approval rule " +
      "count, Tier 2 anomaly-triggered approval rule count, Tier 3 " +
      "auto-allow tool list, baseline anomaly tracker status, and " +
      "denial-on-timeout behaviour. The template pre-populates the " +
      "technical-measures half of the human oversight assessment.",
    manual_carveout:
      "Operator identities, roles, training, authority, and escalation " +
      "procedures; mapping between Sanctuary's approval channel and " +
      "the enterprise's stop-button workflow; rationale for why the " +
      "chosen oversight tier is appropriate to the risk profile of " +
      "the deployed agent.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Borderline partial. Sanctuary provides the oversight mechanism " +
      "inventory with zero enterprise input (~70% of the row). " +
      "Enterprise provides the people-and-process assessment.",
  },

  {
    id: "annex_iv_2_f_predetermined_changes",
    citation: {
      instrument: "Annex IV",
      section: "§2(f)",
      clause_id: "annex-iv-2-f",
      title: "Pre-determined changes to the system and performance",
    },
    requirement:
      "\"Where applicable, a description of pre-determined changes to " +
      "the AI system and its performance [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: pre-determined changes to the AI system " +
      "and its performance, if any].",
    manual_carveout:
      "Pre-determined changes are a product-roadmap and provider-level " +
      "concept outside Sanctuary's runtime scope.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row.",
  },

  {
    id: "annex_iv_2_g_validation_and_testing",
    citation: {
      instrument: "Annex IV",
      section: "§2(g)",
      clause_id: "annex-iv-2-g",
      title: "Validation and testing procedures, metrics",
    },
    requirement:
      "\"The validation and testing procedures used, including " +
      "information about the validation and testing data used [...] and " +
      "the main metrics used to measure [...] accuracy, robustness and " +
      "compliance with other relevant requirements [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "monitor_audit_log",
      "audit_export_siem",
      "sovereignty_audit",
    ],
    evidence_emitted:
      "Auto-filled: audit log entries within the reporting period " +
      "showing tool-call success/failure rates, gate decision counts " +
      "(approve / deny / auto-allow), and any injection_detected " +
      "entries triggered by the prompt injection detector. These " +
      "provide runtime validation evidence from actual deployment.",
    manual_carveout:
      "Model evaluation metrics (accuracy, precision, recall, F1), " +
      "bias testing results, robustness testing against adversarial " +
      "inputs, the validation dataset description, and the metric " +
      "methodology the enterprise used to assess the agent before " +
      "deployment.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary emits runtime operational evidence but does not " +
      "participate in pre-deployment model validation.",
  },

  // ─── §2(h) Cybersecurity measures (FULL) ────────────────────────

  {
    id: "annex_iv_2_h_cybersecurity",
    citation: {
      instrument: "Annex IV",
      section: "§2(h)",
      clause_id: "annex-iv-2-h",
      title: "Cybersecurity measures",
    },
    requirement:
      "\"A detailed description of the cybersecurity measures put in " +
      "place [...].\"",
    coverage: "full",
    evidence_emitter: [
      "sovereignty_audit",
      "shr_generate",
      "manifest",
      "principal_policy_view",
      "context_gate_list_policies",
      "context_gate_enforcer_status",
      "exec_attest",
    ],
    evidence_emitted:
      "Machine-verifiable inventory of Sanctuary's cybersecurity " +
      "primitives, every item reproducible by running the listed " +
      "tools against a live instance: (1) L1 Cognitive Sovereignty " +
      "— AES-256-GCM namespace encryption with HKDF per-namespace " +
      "key derivation, Argon2id master key derivation, Ed25519 " +
      "self-custodied identity, Merkle integrity tracking; reported " +
      "by sovereignty_audit and shr_generate under layers.l1. (2) L2 " +
      "Operational Isolation — three-tier Principal Policy gate with " +
      "out-of-band approval channel, tool-call audit logging, and " +
      "denial-on-timeout semantics; reported by principal_policy_view " +
      "and shr_generate under layers.l2. (3) L2 Outbound context " +
      "gating — per-provider field policies classifying agent context " +
      "as allow / redact / hash / summarize / deny before any outbound " +
      "call; reported by context_gate_list_policies and " +
      "context_gate_enforcer_status. (4) L3 Selective Disclosure — " +
      "Pedersen commitments on Ristretto255, Schnorr proofs, and " +
      "bit-decomposition range proofs; reported by sovereignty_audit " +
      "and shr_generate under layers.l3. (5) L4 Verifiable Reputation " +
      "— Ed25519-signed attestations in EAS-compatible format with " +
      "sovereignty-gated trust tiers; reported by sovereignty_audit " +
      "and shr_generate under layers.l4. (6) Execution attestation — " +
      "cryptographic execution attestation via exec_attest. The full " +
      "tool inventory of this Sanctuary instance is reproducible by " +
      "running manifest.",
    manual_carveout: null,
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Verified against v0.7.0 source on 2026-04-10: every emitter in " +
      "the array corresponds to a registered MCP tool in index.ts, and " +
      "every primitive named in the prose is reported by at least one " +
      "listed tool. DELIBERATELY EXCLUDED: prompt injection detection. " +
      "The InjectionDetector subsystem (server/src/security/" +
      "injection-detector.ts) is wired into the Principal Policy gate " +
      "and is a real runtime control, but in v0.7.0 its configuration " +
      "state is not exposed via any MCP tool — it is only indirectly " +
      "evidenced through `injection_detected:*` entries in the audit " +
      "log (visible via monitor_audit_log / audit_export_siem). " +
      "Claiming injection detection as part of this row's full " +
      "coverage would require source-code inspection, which violates " +
      "the full-coverage bar. Injection detection runtime activity is " +
      "evidenced via the Art. 12 risk management support row instead. " +
      "If v0.8.0+ adds an `injection_detector_status` MCP tool, " +
      "revisit and add to this row.",
  },

  // ─── §3–§9 ───────────────────────────────────────────────────────

  {
    id: "annex_iv_3_monitoring_functioning_control",
    citation: {
      instrument: "Annex IV",
      section: "§3",
      clause_id: "annex-iv-3",
      title: "Monitoring, functioning and control of the system",
    },
    requirement:
      "\"Detailed information about the monitoring, functioning and " +
      "control of the AI system [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "monitor_audit_log",
      "audit_export_siem",
      "monitor_health",
      "context_gate_enforcer_status",
      "principal_baseline_view",
    ],
    evidence_emitted:
      "Auto-filled: encrypted audit log queryable via monitor_audit_log " +
      "and exportable in CEF/OCSF via audit_export_siem; health " +
      "dashboard via monitor_health; outbound context gating enforcer " +
      "status; Principal Policy baseline anomaly tracker state. " +
      "Together these constitute the runtime monitoring substrate for " +
      "the Sanctuary layer.",
    manual_carveout:
      "Operational SLAs, on-call rotation, incident response " +
      "procedures, escalation workflows, monitoring dashboards outside " +
      "Sanctuary, and the enterprise's overall observability stack.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary provides the monitoring substrate; the enterprise " +
      "wraps it in operational processes. Borderline partial.",
  },

  {
    id: "annex_iv_4_performance_metrics",
    citation: {
      instrument: "Annex IV",
      section: "§4",
      clause_id: "annex-iv-4",
      title: "Appropriateness of performance metrics",
    },
    requirement:
      "\"A description of the appropriateness of the performance " +
      "metrics for the specific AI system [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: performance metrics and their " +
      "appropriateness for the specific agent deployment].",
    manual_carveout:
      "Performance metrics are agent-specific and model-specific; " +
      "Sanctuary does not measure model accuracy or task performance.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row.",
  },

  {
    id: "annex_iv_5_risk_management",
    citation: {
      instrument: "Annex IV",
      section: "§5",
      clause_id: "annex-iv-5",
      title: "Risk management system per Article 9",
    },
    requirement:
      "\"A detailed description of the risk management system in " +
      "accordance with Article 9 [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "principal_policy_view",
      "principal_baseline_view",
      "sovereignty_audit",
      "context_gate_list_policies",
    ],
    evidence_emitted:
      "Auto-filled: Principal Policy tier structure (Tier 1 block, " +
      "Tier 2 anomaly-triggered, Tier 3 auto-allow), baseline anomaly " +
      "tracker configuration, outbound context gating policies, and " +
      "sovereignty audit gap analysis with prioritised recommendations. " +
      "These constitute Sanctuary's runtime risk management controls.",
    manual_carveout:
      "Enterprise-level risk register, residual risk analysis, risk " +
      "treatment plan, acceptance criteria for residual risks, " +
      "periodic risk review cadence, and the link between identified " +
      "risks and the Sanctuary controls above.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary emits runtime controls; enterprise maps them to an " +
      "Article 9 risk management framework.",
  },

  {
    id: "annex_iv_6_lifecycle_changes",
    citation: {
      instrument: "Annex IV",
      section: "§6",
      clause_id: "annex-iv-6",
      title: "Description of relevant changes made through lifecycle",
    },
    requirement:
      "\"A description of any change made to the system through its " +
      "lifecycle [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "monitor_audit_log",
      "audit_export_siem",
      "identity_list",
    ],
    evidence_emitted:
      "Auto-filled: audit log entries within the reporting period " +
      "showing all policy changes, identity operations (create, " +
      "rotate, set_primary), state operations, and any configuration " +
      "changes; identity rotation chain via identity_list. These " +
      "provide a cryptographically anchored timeline of Sanctuary-" +
      "layer changes during the period.",
    manual_carveout:
      "Agent-level version changes (model updates, prompt changes), " +
      "business-context narrative for why changes were made, and any " +
      "changes to non-Sanctuary components of the stack.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary captures its own layer's change timeline; enterprise " +
      "provides the broader change narrative.",
  },

  {
    id: "annex_iv_7_standards_applied",
    citation: {
      instrument: "Annex IV",
      section: "§7",
      clause_id: "annex-iv-7",
      title: "Harmonised standards applied",
    },
    requirement:
      "\"A list of the harmonised standards applied in full or in part " +
      "[...] and, where such harmonised standards have not been applied, " +
      "a detailed description of the solutions adopted to meet the " +
      "requirements set out in Chapter III, Section 2 [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: list of harmonised standards applied, " +
      "or description of alternative solutions].",
    manual_carveout:
      "Standards conformance is a legal declaration made by the " +
      "provider. Sanctuary does not assert conformance to any " +
      "harmonised standard.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row — standards conformance is a provider " +
      "legal declaration, not a Sanctuary primitive.",
  },

  {
    id: "annex_iv_8_eu_declaration_of_conformity",
    citation: {
      instrument: "Annex IV",
      section: "§8",
      clause_id: "annex-iv-8",
      title: "Copy of the EU declaration of conformity",
    },
    requirement:
      "\"A copy of the EU declaration of conformity referred to in " +
      "Article 47 [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: EU declaration of conformity per " +
      "Article 47].",
    manual_carveout:
      "The EU declaration of conformity is a formal legal document " +
      "signed by the provider. Sanctuary cannot generate or provide it.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row — legal document only.",
  },

  {
    id: "annex_iv_9_post_market_monitoring_plan",
    citation: {
      instrument: "Annex IV",
      section: "§9",
      clause_id: "annex-iv-9",
      title: "Post-market monitoring plan per Article 72",
    },
    requirement:
      "\"A detailed description of the system in place to evaluate " +
      "the AI system performance in the post-market phase in accordance " +
      "with Article 72, including the post-market monitoring plan " +
      "referred to in Article 72(3) [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: post-market monitoring plan per " +
      "Article 72(3)].",
    manual_carveout:
      "The post-market monitoring plan is a provider-authored " +
      "governance document. Sanctuary's SIEM exporter can feed the " +
      "monitoring pipeline, but the plan itself is enterprise-authored.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "See the Art. 12 post-market monitoring support row for " +
      "Sanctuary's concrete contribution to this area.",
  },

  // ═══════════════════════════════════════════════════════════════════
  // ARTICLE 12 — Automatic Record-Keeping (logs)
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "art_12_automatic_logging",
    citation: {
      instrument: "Article",
      section: "12(1)",
      clause_id: "art-12-1",
      title: "Automatic logging of events over lifetime",
    },
    requirement:
      "\"High-risk AI systems shall technically allow for the automatic " +
      "recording of events ('logs') over the lifetime of the system.\"",
    coverage: "full",
    evidence_emitter: ["monitor_audit_log", "audit_export_siem"],
    evidence_emitted:
      "Every tool call in the Sanctuary runtime automatically produces " +
      "an audit entry via the Principal Policy gate. Router.ts wraps " +
      "all tool invocations through gate.evaluate(), which appends to " +
      "the audit log on every outcome path (gate_allow, gate_allow_proxy, " +
      "gate_deny, gate_escalate, gate_unclassified, injection_detected). " +
      "Entries " +
      "are persisted as AES-256-GCM authenticated ciphertext under an " +
      "HKDF-derived audit-log key and are queryable via " +
      "monitor_audit_log or exportable in CEF/OCSF via " +
      "audit_export_siem. No tool call bypasses the audit path.",
    manual_carveout: null,
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Verified against v0.7.0 source on 2026-04-10: router.ts:249 " +
      "wraps every tool call through gate.evaluate(); gate.ts lines " +
      "86, 155, 186, 202, 358 append to the audit log on every " +
      "outcome. CORRECTIONS APPLIED during verification: earlier " +
      "drafts claimed 'Ed25519-signed entries' and 'hash-chained " +
      "transcript' — neither is true. The AuditEntry schema in " +
      "l2-operational/audit-log.ts has no signature field, and " +
      "entries are stored as individual encrypted files with no " +
      "inter-entry hash chain. AES-256-GCM authenticated encryption " +
      "provides integrity against third-party tampering; that is the " +
      "accurate claim. Art. 12(1) requires the system to technically " +
      "*allow* automatic recording, which is satisfied. DURABILITY " +
      "CAVEAT: audit-log.ts:59 uses fire-and-forget persistence — if " +
      "disk write fails, the entry lives only in memory and is lost " +
      "at process exit. This is a quality-under-failure concern but " +
      "does not defeat the Art. 12(1) capability claim. If v0.8.0+ " +
      "adds synchronous persistence or Ed25519 signing on audit " +
      "entries, update this row's prose.",
  },

  {
    id: "art_12_post_market_monitoring_support",
    citation: {
      instrument: "Article",
      section: "12(2)(a)",
      clause_id: "art-12-2-a",
      title: "Logs enable identification of Article 79(1) risks",
    },
    requirement:
      "\"The logging capabilities shall enable the recording of events " +
      "relevant for identifying situations that may result in the AI " +
      "system presenting a risk within the meaning of Article 79(1) " +
      "[...] and for facilitating the post-market monitoring referred " +
      "to in Article 72.\"",
    coverage: "full",
    evidence_emitter: ["audit_export_siem", "monitor_audit_log"],
    evidence_emitted:
      "The audit_export_siem tool exports audit log entries in two " +
      "SIEM-standard formats: Common Event Format (CEF, newline-" +
      "delimited) and Open Cybersecurity Schema Framework (OCSF, " +
      "JSON array). Both formats are directly ingestible by Splunk, " +
      "Datadog, QRadar, and any other enterprise SIEM platform, " +
      "which are the standard substrate for Article 72 post-market " +
      "monitoring pipelines. Exports support time-window filters " +
      "(since / until), tool name filters, gate decision filters " +
      "(approve / deny / auto-allow), layer filters (l1 / l2 / l3 / " +
      "l4), and result filters (success / failure). Bulk exports up " +
      "to 1000 events per call.",
    manual_carveout: null,
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Verified against v0.7.0 source on 2026-04-10: audit/siem-tools." +
      "ts:18-77 registers audit_export_siem with CEF and OCSF format " +
      "support and the full filter set. Classified Tier 3 (auto-allow, " +
      "read-only) in loader.ts. No corrections to the original draft.",
  },

  {
    id: "art_12_risk_management_support",
    citation: {
      instrument: "Article",
      section: "12(2)(b)",
      clause_id: "art-12-2-b",
      title: "Logs facilitate monitoring operation per Article 26(5)",
    },
    requirement:
      "\"The logging capabilities shall enable the recording of events " +
      "relevant for [...] facilitating the monitoring of the operation " +
      "of the high-risk AI system referred to in Article 26(5).\"",
    coverage: "full",
    evidence_emitter: [
      "monitor_audit_log",
      "audit_export_siem",
      "principal_baseline_view",
    ],
    evidence_emitted:
      "Gate decisions are logged with structured operation prefixes " +
      "(gate_allow:, gate_allow_proxy:, gate_deny:, gate_escalate:, " +
      "gate_unclassified:, injection_detected:) directly filterable via " +
      "audit_export_siem's " +
      "filter_decision enum (approve / deny / auto-allow) and via " +
      "monitor_audit_log's operation_type parameter. The Principal " +
      "Policy baseline anomaly tracker state (behavioural model, " +
      "known-namespaces, frequency baselines, anomaly thresholds) is " +
      "queryable via principal_baseline_view. Together these provide " +
      "the machine-queryable substrate for deployer operation " +
      "monitoring under Article 26(5).",
    manual_carveout: null,
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Verified against v0.7.0 source on 2026-04-10. gate.ts writes " +
      "structured operation strings on every gate outcome; baseline.ts " +
      "is the anomaly source and is exposed via principal_baseline_view. " +
      "Minor correction during verification: principal_baseline_view " +
      "added to emitter list (original draft listed only " +
      "monitor_audit_log).",
  },

  {
    id: "art_12_log_content",
    citation: {
      instrument: "Article",
      section: "12(3)",
      clause_id: "art-12-3",
      title: "Required log content for Annex III §1(a) systems",
    },
    requirement:
      "\"For high-risk AI systems referred to in point 1(a) of Annex III, " +
      "the logging capabilities shall provide, at a minimum: (a) " +
      "recording of the period of each use of the system [...]; (b) " +
      "the reference database against which input data has been " +
      "checked by the system; (c) the input data for which the search " +
      "has led to a match; (d) the identification of the natural " +
      "persons involved in the verification of the results [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "monitor_audit_log",
      "audit_export_siem",
      "identity_list",
    ],
    evidence_emitted:
      "Auto-filled where the agent routes through Sanctuary: period " +
      "of use (audit log timestamps with since/until filters), tool " +
      "inputs (captured in audit entry details field), and " +
      "identification of principals who approved Tier 1 operations " +
      "(captured via identity_id in audit entries and identity " +
      "provenance via identity_list). Gate decisions are bound to the " +
      "identity that requested the operation.",
    manual_carveout:
      "Reference database identifier (the external database the agent " +
      "queries) — only captured if the agent explicitly logs it to " +
      "Sanctuary state. Natural-person verifier identification beyond " +
      "the Sanctuary principal identity (e.g., the human operator's " +
      "HR record or employee ID). Input data captured only when the " +
      "agent passes it through a Sanctuary tool call.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Row applies only to Annex III §1(a) (biometric remote " +
      "identification) systems. For other Annex III categories this " +
      "row is not triggered. Coverage depends on whether the agent " +
      "actually routes its biometric checks through Sanctuary-tracked " +
      "tool calls.",
  },

  {
    id: "art_12_retention",
    citation: {
      instrument: "Article",
      section: "19(1)",
      clause_id: "art-19-1",
      title: "Log retention for at least six months",
    },
    requirement:
      "\"Providers of high-risk AI systems shall keep the logs referred " +
      "to in Article 12(1), automatically generated by their high-risk " +
      "AI systems, to the extent such logs are under their control. " +
      "[...] the logs shall be kept for a period appropriate to the " +
      "intended purpose of the high-risk AI system, of at least six " +
      "months [...].\"",
    coverage: "partial",
    evidence_emitter: ["monitor_audit_log", "audit_export_siem"],
    evidence_emitted:
      "Auto-filled: Sanctuary's audit log persists entries indefinitely " +
      "by default (no automatic purge). Entries are exportable at any " +
      "time via audit_export_siem for archival to enterprise storage.",
    manual_carveout:
      "The enterprise's declared log retention policy (how long logs " +
      "are kept, in which storage tier, who has access), the archival " +
      "pipeline configuration feeding enterprise long-term storage, " +
      "and the written policy document satisfying the 'period " +
      "appropriate to the intended purpose' requirement.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Note: this row cites Article 19(1) rather than Article 12 — " +
      "retention is specifically an Article 19 provider obligation, " +
      "not an Article 12 logging capability. The capability to retain " +
      "exists in Sanctuary (no automatic purge); the declared policy " +
      "is an enterprise artefact.",
  },

  // ═══════════════════════════════════════════════════════════════════
  // ARTICLE 13 — Transparency and provision of information to deployers
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "art_13_3_a_provider_identity",
    citation: {
      instrument: "Article",
      section: "13(3)(a)",
      clause_id: "art-13-3-a",
      title: "Identity and contact details of the provider",
    },
    requirement:
      "\"The instructions for use shall contain at least the following " +
      "information: (a) the identity and the contact details of the " +
      "provider and, where applicable, of its authorised representative " +
      "[...].\"",
    coverage: "partial",
    evidence_emitter: ["identity_list", "identity_set_primary", "shr_generate"],
    evidence_emitted:
      "Auto-filled: cryptographic provider identity — primary Ed25519 " +
      "public key, DID, instance_id, and key creation timestamp via " +
      "identity_list and identity_set_primary. The signed SHR carries " +
      "the same identity in its signed_by field, providing a " +
      "verifiable link between the provider identity and the " +
      "capability assertions of the system.",
    manual_carveout:
      "Legal provider name, registered legal entity, registered " +
      "business address, contact email, and authorised representative " +
      "details (if applicable). These are legal-entity facts that " +
      "must be supplied by the enterprise.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary emits the cryptographic identity; the enterprise " +
      "supplies the legal identity. Both are required for complete " +
      "Art. 13(3)(a) coverage.",
  },

  {
    id: "art_13_3_b_ii_capabilities_and_limitations",
    citation: {
      instrument: "Article",
      section: "13(3)(b)(ii)",
      clause_id: "art-13-3-b-ii",
      title: "Performance characteristics, capabilities and limitations",
    },
    requirement:
      "\"The characteristics, capabilities and limitations of " +
      "performance of the high-risk AI system, including [...] its " +
      "intended purpose [...] the level of accuracy, including its " +
      "metrics [...] and any known or foreseeable circumstance [...] " +
      "which may lead to risks to the health and safety or fundamental " +
      "rights [...].\"",
    coverage: "partial",
    evidence_emitter: ["shr_generate", "manifest", "sovereignty_audit"],
    evidence_emitted:
      "Auto-filled: SHR four-layer capability report with explicit " +
      "status flags per layer (active / degraded / inactive), the " +
      "SHR degradations[] array listing honest self-declared gaps " +
      "(e.g., NO_TEE, PROCESS_ISOLATION_ONLY), the full MCP tool " +
      "inventory (via manifest), and the sovereignty audit gap " +
      "analysis. Together these constitute a machine-readable " +
      "capability manifest with explicit, honest limitations.",
    manual_carveout:
      "Agent-level accuracy metrics and their measurement " +
      "methodology, false-positive and false-negative rates on the " +
      "agent's business task, known failure modes specific to the " +
      "deployment, and the link between technical capabilities and " +
      "fundamental-rights risk.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary's SHR is structurally a transparency artefact — it " +
      "is designed to honestly declare capabilities and degradations. " +
      "This row is where SHR data feeds user-facing disclosures.",
  },

  {
    id: "art_13_3_b_iv_output_interpretation",
    citation: {
      instrument: "Article",
      section: "13(3)(b)(iv)",
      clause_id: "art-13-3-b-iv",
      title: "Technical capabilities to interpret system output",
    },
    requirement:
      "\"Where appropriate, its performance regarding specific persons " +
      "or groups of persons on which the system is intended to be used; " +
      "[...] where appropriate, specifications for the input data, or " +
      "any other relevant information in terms of the training, " +
      "validation and testing data sets used, taking into account the " +
      "intended purpose of the AI system [...].\"",
    coverage: "partial",
    evidence_emitter: [
      "shr_generate",
      "monitor_audit_log",
      "audit_export_siem",
      "bridge_verify",
    ],
    evidence_emitted:
      "Auto-filled: signed SHR + Ed25519-signed audit trail + " +
      "Concordia bridge attestations (where used) give machine-" +
      "readable provenance for every tool call the agent made during " +
      "the reporting period. This enables output interpretation of " +
      "the form 'this agent action came from these inputs at this " +
      "time, cryptographically signed and independently verifiable.'",
    manual_carveout:
      "Business-facing explanation translating the cryptographic " +
      "trail into user-comprehensible narrative, performance " +
      "characteristics on specific populations, and intended-purpose-" +
      "specific input specifications.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary provides the cryptographic substrate for output " +
      "provenance; enterprise renders it into user-facing disclosure " +
      "text. Art. 13 is fundamentally a disclosure UX obligation that " +
      "Sanctuary does not render.",
  },

  // ═══════════════════════════════════════════════════════════════════
  // ARTICLE 14 — Human Oversight
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "art_14_interpret_outputs",
    citation: {
      instrument: "Article",
      section: "14(4)(a)-(c)",
      clause_id: "art-14-4-a-c",
      title: "Oversight enables understanding and interpretation",
    },
    requirement:
      "\"[The measures shall enable the persons to whom human oversight " +
      "is assigned to]: (a) [...] properly understand the relevant " +
      "capacities and limitations of the high-risk AI system [...]; " +
      "(b) [...] remain aware of [...] automation bias [...]; (c) " +
      "[...] correctly interpret the high-risk AI system's output " +
      "[...].\"",
    coverage: "partial",
    evidence_emitter: ["shr_generate", "principal_policy_view", "manifest"],
    evidence_emitted:
      "Auto-filled: SHR is designed to be human-readable with explicit " +
      "per-layer status flags and honest degradation declarations. " +
      "Principal Policy is inspectable YAML that a human overseer can " +
      "read directly. Tool inventory (via manifest) gives the oversight " +
      "persons a complete list of what the agent can do.",
    manual_carveout:
      "Training materials for human overseers, the specific " +
      "automation-bias awareness program, how oversight persons are " +
      "trained to correctly interpret agent output, and any UI tools " +
      "the enterprise provides to support oversight.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary emits artefacts designed to be interpretable; the " +
      "enterprise builds the training-and-support layer around them.",
  },

  {
    id: "art_14_intervene_interrupt",
    citation: {
      instrument: "Article",
      section: "14(4)(e)",
      clause_id: "art-14-4-e",
      title: "Intervention, interruption, and stop button",
    },
    requirement:
      "\"[The measures shall enable the persons to whom human oversight " +
      "is assigned to]: (e) [...] intervene on the operation of the " +
      "high-risk AI system or interrupt the system through a 'stop' " +
      "button or similar procedure that allows the system to come to a " +
      "halt in a safe state.\"",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view", "sovereignty_audit"],
    evidence_emitted:
      "Auto-filled: Principal Policy approval channel configuration " +
      "(stderr / dashboard / webhook), Tier 1 require-approval rule " +
      "count, denial-on-timeout behaviour, and gate decision semantics. " +
      "These collectively document Sanctuary's pre-execution " +
      "intervention capability — every Tier 1 tool call is halted " +
      "pending human approval.",
    manual_carveout:
      "The enterprise's declared mapping between Sanctuary's approval " +
      "channel and its Article 14(4)(e) stop-button workflow, the " +
      "operational procedure for invoking the stop button, and " +
      "acceptance that pre-execution gating satisfies the 'halt in a " +
      "safe state' requirement for the specific agent.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Downgraded from full during audit (2026-04-10). Sanctuary's " +
      "approval gate is a pre-execution intervention, not a mid-stream " +
      "kill switch. Whether pre-execution gating satisfies Art. 14(4)" +
      "(e) is an enterprise-declared operational judgement. Honest " +
      "partial.",
  },

  {
    id: "art_14_decide_not_to_use",
    citation: {
      instrument: "Article",
      section: "14(4)(d)",
      clause_id: "art-14-4-d",
      title: "Decide not to use or to disregard the output",
    },
    requirement:
      "\"[The measures shall enable the persons to whom human oversight " +
      "is assigned to]: (d) [...] decide, in any particular situation, " +
      "not to use the high-risk AI system or to otherwise disregard, " +
      "override or reverse the output of the high-risk AI system [...].\"",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view"],
    evidence_emitted:
      "Auto-filled: Principal Policy denial semantics — every Tier 1 " +
      "operation defaults to deny on approval timeout, providing a " +
      "structural 'decide not to use' control at the policy layer. " +
      "Tier 1 tools include export, import, key rotation, and secure " +
      "delete.",
    manual_carveout:
      "The enterprise's declared mapping between Sanctuary's deny " +
      "semantics and its Art. 14(4)(d) decision-not-to-use workflow, " +
      "and operator authority to invoke the decision.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Downgraded from full during audit (2026-04-10). Sanctuary " +
      "provides the capability; enterprise provides the operational " +
      "declaration.",
  },

  {
    id: "art_14_operator_training",
    citation: {
      instrument: "Article",
      section: "14(4) chapeau",
      clause_id: "art-14-4-chapeau",
      title: "Operator competence, training, and authority",
    },
    requirement:
      "\"[Human oversight measures shall be commensurate with the risks, " +
      "level of autonomy and context of use of the high-risk AI system] " +
      "[...] ensured through [...] the following types of measures, as " +
      "appropriate to the circumstances [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: operator identities, roles, " +
      "competence, training program, and authority to override].",
    manual_carveout:
      "People-and-process facts that Sanctuary cannot observe or " +
      "emit.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row — operator governance is an HR function.",
  },

  // ═══════════════════════════════════════════════════════════════════
  // ARTICLE 15 — Accuracy, Robustness, Cybersecurity
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "art_15_cybersecurity_appropriate",
    citation: {
      instrument: "Article",
      section: "15(5)",
      clause_id: "art-15-5",
      title: "Cybersecurity measures appropriate to the risks",
    },
    requirement:
      "\"High-risk AI systems shall be resilient against attempts by " +
      "unauthorised third parties to alter their use, outputs or " +
      "performance by exploiting system vulnerabilities. The technical " +
      "solutions aiming to ensure the cybersecurity of high-risk AI " +
      "systems shall be appropriate to the relevant circumstances and " +
      "the risks.\"",
    coverage: "partial",
    evidence_emitter: [
      "sovereignty_audit",
      "shr_generate",
      "principal_policy_view",
      "context_gate_list_policies",
    ],
    evidence_emitted:
      "Auto-filled: the full cybersecurity measures inventory (see " +
      "Annex IV §2(h) row for complete description). Sanctuary emits " +
      "the list of measures with structured status flags.",
    manual_carveout:
      "Appropriateness assertion: the enterprise must declare that " +
      "the Sanctuary-reported measures are appropriate to the specific " +
      "risks of the deployment context (risk-matched narrative linking " +
      "identified risks to selected controls).",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Downgraded from full during audit (2026-04-10). Art. 15(5) " +
      "requires measures 'appropriate to the risks' — the " +
      "appropriateness claim is a risk-matched narrative the " +
      "enterprise owns. The pure-description version survives as a " +
      "full row at Annex IV §2(h); this row is the risk-adequacy " +
      "half of the same content.",
  },

  {
    id: "art_15_resilience_alteration",
    citation: {
      instrument: "Article",
      section: "15(5) first subparagraph",
      clause_id: "art-15-5-resilience",
      title: "Resilience against unauthorised third-party alteration",
    },
    requirement:
      "\"High-risk AI systems shall be resilient against attempts by " +
      "unauthorised third parties to alter their use, outputs or " +
      "performance by exploiting system vulnerabilities.\"",
    coverage: "full",
    evidence_emitter: [
      "sovereignty_audit",
      "shr_generate",
      "monitor_health",
      "state_list",
      "principal_policy_view",
      "context_gate_enforcer_status",
    ],
    evidence_emitted:
      "Resilience against unauthorised third-party alteration is " +
      "enforced across multiple subsystems, each independently " +
      "verifiable via an MCP tool call: (1) L1 state store — " +
      "AES-256-GCM authenticated encryption with HKDF per-namespace " +
      "keys, Merkle root per namespace, monotonic version counter " +
      "per (namespace, key), and anti-rollback checks on every read; " +
      "reported by monitor_health (state_integrity flag) and via " +
      "version numbers returned by state_list. (2) L1 audit log — " +
      "AES-256-GCM authenticated ciphertext persisted under an " +
      "HKDF-derived audit-log key; confidentiality and integrity " +
      "against third-party tampering (no signature-based non-" +
      "repudiation — see review_notes). (3) L1 identity — Ed25519 " +
      "self-custodied keypairs; signed identity operations (sign, " +
      "rotate, verify) and signed SHR generation; reported by " +
      "shr_generate signature block. (4) L2 execution gate — every " +
      "tool call routed through router.ts -> ApprovalGate.evaluate() " +
      "-> Principal Policy tier check before execution; no bypass " +
      "path; reported by principal_policy_view and the audit log " +
      "trail of gate_* entries. (5) L2 outbound context gating — " +
      "per-provider field policies applied before any outbound call; " +
      "reported by context_gate_enforcer_status.",
    manual_carveout: null,
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Verified against v0.7.0 source on 2026-04-10. MAJOR " +
      "CORRECTIONS APPLIED from earlier drafts: (1) Earlier drafts " +
      "claimed Merkle integrity on the audit log — that is wrong. " +
      "Merkle trees exist on the state store (l1-cognitive/state-" +
      "store.ts) but NOT on the audit log. (2) Earlier drafts " +
      "claimed Ed25519 signatures on audit entries — that is wrong. " +
      "The AuditEntry schema has no signature field; entries are " +
      "AES-256-GCM ciphertext only. Ed25519 signatures exist on " +
      "identity operations and SHR, not audit entries. (3) Earlier " +
      "drafts claimed 'tamper-evident transcript' on the audit log " +
      "— this is only true against third parties without the " +
      "master key; there is no hash chain. The row still survives " +
      "as full because Art. 15(5) specifies 'unauthorised third " +
      "parties,' and AES-256-GCM with an HKDF-derived key protects " +
      "against that threat model. Non-repudiation against a " +
      "compromised-master-key insider is a different threat model " +
      "not covered by Art. 15(5).",
  },

  {
    id: "art_15_resilience_poisoning",
    citation: {
      instrument: "Article",
      section: "15(5) second subparagraph",
      clause_id: "art-15-5-poisoning",
      title: "Resilience against data and model poisoning",
    },
    requirement:
      "\"The technical solutions to address AI specific vulnerabilities " +
      "shall include, where appropriate, measures to prevent, detect, " +
      "respond to, resolve and control for attacks trying to manipulate " +
      "the training data set ('data poisoning'), or pre-trained " +
      "components used in training ('model poisoning'), inputs designed " +
      "to cause the AI model to make a mistake ('adversarial examples' " +
      "or 'model evasion'), [...].\"",
    coverage: "partial",
    evidence_emitter: ["monitor_audit_log", "audit_export_siem"],
    evidence_emitted:
      "Auto-filled: the Principal Policy gate runs a prompt injection " +
      "detector pre-check on every tool call; when flagged, the gate " +
      "appends 'injection_detected:*' entries to the audit log, which " +
      "are visible via monitor_audit_log and exportable via " +
      "audit_export_siem. The detector covers role override, security " +
      "bypass, encoding evasion, data exfiltration, and prompt " +
      "stuffing signals at runtime.",
    manual_carveout:
      "Training-time threats (data poisoning, model poisoning) are " +
      "entirely outside Sanctuary's runtime scope — training data " +
      "governance is the model provider's responsibility. The " +
      "runtime adversarial-input detection is partial coverage of " +
      "the 'adversarial examples' subset of Art. 15(5).",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "The injection detector exists (security/injection-detector.ts) " +
      "and its activity IS evidenced via audit log entries, even " +
      "though its configuration state is not directly queryable. " +
      "Partial is honest: runtime adversarial-input detection is " +
      "covered; training-time poisoning is not.",
  },

  {
    id: "art_15_accuracy_metrics",
    citation: {
      instrument: "Article",
      section: "15(3)",
      clause_id: "art-15-3",
      title: "Declared accuracy levels and metrics",
    },
    requirement:
      "\"The levels of accuracy and the relevant accuracy metrics of " +
      "high-risk AI systems shall be declared in the accompanying " +
      "instructions of use.\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: accuracy levels and metrics on the " +
      "agent's business task].",
    manual_carveout:
      "Sanctuary does not measure agent task accuracy.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row.",
  },

  {
    id: "art_15_redundancy_failsafe",
    citation: {
      instrument: "Article",
      section: "15(4)",
      clause_id: "art-15-4",
      title: "Technical redundancy and fail-safe measures",
    },
    requirement:
      "\"High-risk AI systems shall be as resilient as possible [...] " +
      "The robustness of high-risk AI systems may be achieved through " +
      "technical redundancy solutions, which may include backup or " +
      "fail-safe plans.\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: technical redundancy and fail-safe " +
      "plans for the deployment].",
    manual_carveout:
      "Redundancy architecture is an operational decision at the " +
      "deployment level outside Sanctuary's scope.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row.",
  },

  // ═══════════════════════════════════════════════════════════════════
  // ARTICLE 26 — Deployer Obligations
  // ═══════════════════════════════════════════════════════════════════

  {
    id: "art_26_per_instructions",
    citation: {
      instrument: "Article",
      section: "26(1)",
      clause_id: "art-26-1",
      title: "Use in accordance with instructions for use",
    },
    requirement:
      "\"Deployers of high-risk AI systems shall take appropriate " +
      "technical and organisational measures to ensure they use such " +
      "systems in accordance with the instructions for use accompanying " +
      "the systems [...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: declaration of use in accordance " +
      "with instructions].",
    manual_carveout:
      "Deployer-facing attestation, not a Sanctuary primitive.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row.",
  },

  {
    id: "art_26_human_oversight_assigned",
    citation: {
      instrument: "Article",
      section: "26(2)",
      clause_id: "art-26-2",
      title: "Assign human oversight to competent natural persons",
    },
    requirement:
      "\"Deployers shall assign human oversight to natural persons who " +
      "have the necessary competence, training and authority, as well " +
      "as the necessary support.\"",
    coverage: "partial",
    evidence_emitter: ["principal_policy_view"],
    evidence_emitted:
      "Auto-filled: Sanctuary's approval channel configuration " +
      "(stderr / dashboard / webhook) provides the technical substrate " +
      "to which the enterprise binds its assigned human overseers. " +
      "The Principal Policy Tier 1 rule list documents which " +
      "operations require human approval.",
    manual_carveout:
      "Identity of assigned overseers, their competence assessment, " +
      "training records, authority scope, and the support " +
      "infrastructure provided to them.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary provides the technical oversight surface; " +
      "enterprise assigns the people.",
  },

  {
    id: "art_26_input_data_relevance",
    citation: {
      instrument: "Article",
      section: "26(4)",
      clause_id: "art-26-4",
      title: "Input data relevance and representativeness",
    },
    requirement:
      "\"[...] deployers shall ensure that input data is relevant and " +
      "sufficiently representative in view of the intended purpose of " +
      "the high-risk AI system.\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: declaration of input data relevance " +
      "and representativeness].",
    manual_carveout:
      "Input data governance is a deployer responsibility outside " +
      "Sanctuary's runtime scope.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row.",
  },

  {
    id: "art_26_monitor_and_inform",
    citation: {
      instrument: "Article",
      section: "26(5)",
      clause_id: "art-26-5",
      title: "Monitor operation and inform provider of incidents",
    },
    requirement:
      "\"Deployers shall monitor the operation of the high-risk AI " +
      "system on the basis of the instructions for use [...]. When " +
      "deployers have reason to consider that the use in accordance " +
      "with the instructions for use may result in that AI system " +
      "presenting a risk [...] they shall, without undue delay, inform " +
      "the provider [...] and suspend the use of that system.\"",
    coverage: "partial",
    evidence_emitter: [
      "monitor_audit_log",
      "audit_export_siem",
      "monitor_health",
      "principal_baseline_view",
    ],
    evidence_emitted:
      "Auto-filled: the runtime monitoring substrate — encrypted " +
      "audit log queryable and exportable in SIEM-standard formats, " +
      "health dashboard, and anomaly baseline tracker. Provides the " +
      "technical means to monitor and detect risk situations.",
    manual_carveout:
      "The enterprise's incident response workflow, the 'inform " +
      "provider' communication channel and contacts, the suspension " +
      "procedure, and the documented risk-detection criteria.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Sanctuary provides the detect-and-export half; enterprise " +
      "provides the report-and-suspend half.",
  },

  {
    id: "art_26_retain_logs",
    citation: {
      instrument: "Article",
      section: "26(6)",
      clause_id: "art-26-6",
      title: "Deployers keep logs for at least six months",
    },
    requirement:
      "\"Deployers of high-risk AI systems shall keep the logs " +
      "automatically generated by that high-risk AI system, to the " +
      "extent such logs are under their control, for a period " +
      "appropriate to the intended purpose of the high-risk AI system, " +
      "of at least six months [...].\"",
    coverage: "partial",
    evidence_emitter: ["monitor_audit_log", "audit_export_siem"],
    evidence_emitted:
      "Auto-filled: Sanctuary's audit log persists entries " +
      "indefinitely by default and is exportable for archival at any " +
      "time via audit_export_siem in CEF/OCSF formats suitable for " +
      "long-term SIEM retention.",
    manual_carveout:
      "The enterprise's declared log retention policy, long-term " +
      "archival pipeline, access control on archived logs, and " +
      "written policy document satisfying the 'period appropriate to " +
      "the intended purpose' requirement.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Downgraded from full during audit (2026-04-10). Sanctuary " +
      "captures and exports; enterprise declares and archives. The " +
      "retention policy is an enterprise governance artefact.",
  },

  {
    id: "art_26_workers_representatives",
    citation: {
      instrument: "Article",
      section: "26(7)",
      clause_id: "art-26-7",
      title: "Inform workers and workers' representatives (employment)",
    },
    requirement:
      "\"Before putting into service or using a high-risk AI system at " +
      "the workplace, deployers who are employers shall inform workers' " +
      "representatives and the affected workers that they will be " +
      "subject to the use of the high-risk AI system.\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: worker and workers' representative " +
      "notification evidence].",
    manual_carveout:
      "Labour-relations obligation outside Sanctuary's scope.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row. Applies only to employment-context " +
      "deployments (Annex III §4).",
  },

  {
    id: "art_26_dpia",
    citation: {
      instrument: "Article",
      section: "26(9)",
      clause_id: "art-26-9",
      title: "Data protection impact assessment per GDPR Art. 35",
    },
    requirement:
      "\"Where applicable, deployers of high-risk AI systems shall use " +
      "the information provided under Article 13 of this Regulation to " +
      "comply with their obligation to carry out a data protection " +
      "impact assessment under Article 35 of Regulation (EU) 2016/679 " +
      "[...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: DPIA under GDPR Article 35, where " +
      "applicable].",
    manual_carveout:
      "DPIA is a GDPR governance document. Sanctuary's transparency " +
      "artefacts (SHR, audit log) may feed into a DPIA, but the " +
      "assessment itself is enterprise-authored.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row.",
  },

  {
    id: "art_26_eu_database_registration",
    citation: {
      instrument: "Article",
      section: "26(8)",
      clause_id: "art-26-8",
      title: "Registration in EU database for Annex III systems",
    },
    requirement:
      "\"Deployers of high-risk AI systems referred to in Annex III " +
      "that [...] are public authorities, [...] or deployers acting on " +
      "their behalf, shall register themselves, select the system and " +
      "register its use in the EU database referred to in Article 71 " +
      "[...].\"",
    coverage: "manual_only",
    evidence_emitter: [],
    evidence_emitted:
      "[MANUAL INPUT REQUIRED: EU database registration under " +
      "Article 71, where applicable].",
    manual_carveout:
      "Registration in the EU database is a legal procedural step " +
      "the enterprise performs directly with the European Commission.",
    last_reviewed_date: REVIEW_DATE,
    last_reviewed_by: REVIEWER,
    review_notes:
      "Structural manual row. Applies only to public authorities " +
      "and those acting on their behalf.",
  },
];

// ── The exported matrix ──────────────────────────────────────────────

export const COVERAGE_MATRIX_V1: CoverageMatrix = {
  matrix_version: "v1",
  regulation_version: REGULATION_VERSION,
  regulation: {
    name: "EU AI Act",
    official_reference: "Regulation (EU) 2024/1689",
    oj_reference: "OJ L, 2024/1689, 12 July 2024",
    full_enforcement_date: "2026-08-02",
    aligned_to_text_version: "OJ published text",
    last_full_review: "2026-04-10",
    next_review_due: "2026-06-01",
  },
  notes: [
    "Matrix v1 is aligned to the OJ-published text of Regulation (EU) " +
      "2024/1689. It does not yet reflect any implementing acts or " +
      "delegated acts that the European Commission may publish before " +
      "the 2026-08-02 enforcement date. Review the `next_review_due` " +
      "field and bump regulation_version whenever the aligned text " +
      "changes.",
    "Verbatim regulation text uses [...] elisions for length; text is " +
      "never paraphrased. Clause identifiers (clause_id) are " +
      "separately queryable so templates can render citations " +
      "without parsing the verbatim quotes.",
    "Every 'full' row was individually verified against v0.7.0 source " +
      "on 2026-04-10. See per-row review_notes for verification " +
      "findings and any corrections applied.",
    "NOT LEGAL ADVICE. This matrix is a technical mapping from " +
      "Sanctuary primitives to regulation clause identifiers; it is " +
      "not a legal interpretation of the EU AI Act.",
  ],
  rows: ROWS,
};

// ── Helper functions ─────────────────────────────────────────────────

/**
 * Get all rows matching a coverage flag.
 */
export function rowsByCoverage(
  matrix: CoverageMatrix,
  flag: CoverageFlag
): CoverageRow[] {
  return matrix.rows.filter((r) => r.coverage === flag);
}

/**
 * Get a row by its stable ID.
 */
export function rowById(
  matrix: CoverageMatrix,
  id: string
): CoverageRow | undefined {
  return matrix.rows.find((r) => r.id === id);
}

/**
 * Get all rows for a given instrument (e.g., all Annex IV rows).
 */
export function rowsByInstrument(
  matrix: CoverageMatrix,
  instrument: Instrument
): CoverageRow[] {
  return matrix.rows.filter((r) => r.citation.instrument === instrument);
}

/**
 * Get the set of unique Sanctuary tool names referenced as evidence
 * emitters anywhere in the matrix. Useful for audit-time verification
 * that every referenced tool actually exists in the running server.
 */
export function allEvidenceEmitters(matrix: CoverageMatrix): string[] {
  const set = new Set<string>();
  for (const row of matrix.rows) {
    for (const tool of row.evidence_emitter) {
      set.add(tool);
    }
  }
  return Array.from(set).sort();
}

/**
 * Compute coverage statistics for the matrix.
 */
export interface CoverageStats {
  total_rows: number;
  full: number;
  partial: number;
  manual_only: number;
  full_pct: number;
  partial_pct: number;
  manual_only_pct: number;
}

export function coverageStats(matrix: CoverageMatrix): CoverageStats {
  const total = matrix.rows.length;
  const full = rowsByCoverage(matrix, "full").length;
  const partial = rowsByCoverage(matrix, "partial").length;
  const manual = rowsByCoverage(matrix, "manual_only").length;
  return {
    total_rows: total,
    full,
    partial,
    manual_only: manual,
    full_pct: Math.round((full / total) * 100),
    partial_pct: Math.round((partial / total) * 100),
    manual_only_pct: Math.round((manual / total) * 100),
  };
}
