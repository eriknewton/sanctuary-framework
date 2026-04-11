/**
 * Sanctuary MCP Server — EU AI Act Compliance Bundle Types
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared types for the EU AI Act Compliance Artifact Generator.
 *
 * NOT LEGAL ADVICE. These types define the shape of a technical
 * compliance artifact bundle; they are not a legal interpretation of
 * Regulation (EU) 2024/1689.
 */

import type { CoverageFlag } from "./coverage_matrix.js";

// ── Generator input ──────────────────────────────────────────────────

/**
 * Risk classification per Annex III of Regulation (EU) 2024/1689.
 * Enterprise self-classifies; Sanctuary does not infer this.
 */
export type AnnexIIIRiskClass =
  | "§1(a) biometric remote identification"
  | "§1(b) biometric categorisation"
  | "§1(c) emotion recognition"
  | "§2 critical infrastructure"
  | "§3 education and vocational training"
  | "§4 employment, workers management, self-employment"
  | "§5 essential private and public services"
  | "§6 law enforcement"
  | "§7 migration, asylum, border control"
  | "§8 administration of justice and democratic processes"
  | "limited-risk (Art. 50 transparency only)"
  | "minimal-risk (no specific obligations)";

/**
 * Deployment context facts the enterprise supplies when generating
 * a bundle. Sanctuary cannot infer these from runtime state; they
 * are the business-classification substrate.
 */
export interface DeploymentContext {
  /** Vertical industry: finance, healthcare, hr, etc. */
  vertical?: string;
  /**
   * Risk classification per Annex III. Required for high-risk
   * bundles; omit for limited-risk or minimal-risk contexts.
   */
  annex_iii_class?: AnnexIIIRiskClass;
  /** One-sentence description of what the agent does. */
  intended_purpose?: string;
  /** Legal provider name (enterprise legal entity). */
  provider_legal_name?: string;
  /** Provider contact email. */
  provider_contact?: string;
  /**
   * Whether the deployer is a public authority or entity acting on
   * behalf of one (triggers Article 26(8) EU database registration).
   */
  deployer_is_public_authority?: boolean;
  /** Free-form notes included in the bundle introduction. */
  notes?: string;
}

/**
 * Input to `compliance_generate_eu_ai_act_bundle`.
 */
export interface ComplianceBundleInput {
  /** Agent DID (the subject of the compliance bundle). */
  agent_did: string;
  /** Enterprise-supplied deployment context. */
  deployment_context: DeploymentContext;
  /** ISO timestamp — start of reporting period. */
  period_start: string;
  /** ISO timestamp — end of reporting period. */
  period_end: string;
  /**
   * Optional override for the `generated_at` timestamp. Normally
   * omitted, in which case the generator uses `new Date().toISOString()`.
   * Used by example-bundle fixtures to produce byte-stable output
   * across regenerations. Tests and production callers should not
   * set this.
   */
  generated_at_override?: string;
  /**
   * Optional filesystem path to a prior bundle directory. When
   * supplied, the generator loads `{path}/00_bundle_manifest.json`,
   * compares it to the current bundle, and emits an additional
   * `08_delta.md` document summarising what changed. If the path is
   * unreadable or not a valid bundle, delta generation is skipped
   * with a warning in review_notes; bundle generation itself never
   * fails because of a delta problem.
   */
  delta_from_bundle_path?: string;
  /**
   * Optional post-generation side effect: if true, POST the signed
   * bundle manifest (NOT the full document bodies) to Verascore at
   * the configured verascore_url using the same signed-publish path
   * as `reputation_publish`. Bundle generation never depends on
   * Verascore being online — if the publish fails for any reason,
   * the bundle is still returned with a publish_result field
   * reporting the failure. Defaults to false.
   */
  publish_to_verascore?: boolean;
  /**
   * Optional override for the Verascore base URL used when
   * `publish_to_verascore` is true. Defaults to "https://verascore.ai".
   * Must be HTTPS and must match one of the allowed Verascore hosts
   * (verascore.ai, www.verascore.ai, api.verascore.ai).
   */
  verascore_url?: string;
}

// ── Verascore publish result (Phase 2) ───────────────────────────────

/**
 * Outcome of the optional Verascore publish side-effect. Always
 * included in the bundle result when publish_to_verascore was true,
 * regardless of whether the publish succeeded. Bundle generation
 * never fails because of a publish error.
 */
export interface VerascorePublishResult {
  /** Whether the publish was attempted at all. */
  attempted: boolean;
  /** Whether the publish succeeded. */
  published: boolean;
  /** HTTP status code from Verascore, if reached. */
  status?: number;
  /** Verascore agent ID the manifest was published under. */
  verascore_agent_id?: string;
  /** Verascore base URL used for the publish. */
  verascore_url?: string;
  /** Error message if the publish failed. */
  error?: string;
  /**
   * SHA-256 hex of the canonical manifest bytes that were POSTed.
   * Used so an auditor can cross-check which manifest was published.
   */
  published_manifest_sha256?: string;
}

// ── Delta report (Phase 2) ───────────────────────────────────────────

/**
 * One row whose coverage matrix entry changed between the prior
 * and current bundle.
 */
export interface DeltaRowChange {
  row_id: string;
  clause_id: string;
  changes: {
    coverage?: { from: string; to: string };
    evidence_emitter?: { from: string[]; to: string[] };
    last_reviewed_date?: { from: string; to: string };
  };
}

/**
 * Structured delta between two bundles. Used by the delta template
 * to render `08_delta.md`.
 */
export interface DeltaReport {
  /** Path the prior bundle was loaded from. */
  prior_bundle_path: string;
  prior_generated_at: string;
  prior_signer_did: string;
  prior_regulation_version: string;
  prior_matrix_version: string;
  current_generated_at: string;
  current_signer_did: string;
  current_regulation_version: string;
  current_matrix_version: string;
  /** True iff prior.regulation_version !== current.regulation_version. */
  regulation_version_changed: boolean;
  /** True iff prior.matrix_version !== current.matrix_version. */
  matrix_version_changed: boolean;
  /** Rows present in current but not in prior. */
  rows_added: string[];
  /** Rows present in prior but not in current. */
  rows_removed: string[];
  /** Rows whose coverage, emitter list, or last_reviewed_date changed. */
  rows_changed: DeltaRowChange[];
  /** Non-fatal warnings encountered during delta generation. */
  warnings: string[];
}

// ── Bundle output ────────────────────────────────────────────────────

/**
 * One generated file in a compliance bundle. Each file carries its
 * own SHA-256 and optional Ed25519 signature for independent
 * verification.
 */
export interface BundleFile {
  /** File basename, e.g., "01_annex_iv_technical_documentation.md". */
  filename: string;
  /** Rendered file content (Markdown or JSON). */
  content: string;
  /** MIME type for downstream tooling. */
  content_type: "text/markdown" | "application/json";
  /** Lowercase hex SHA-256 of the content bytes. */
  sha256: string;
  /**
   * Base64url Ed25519 signature over the SHA-256 digest, signed by
   * the provider's primary identity. Present for all files in a
   * signed bundle.
   */
  signature?: string;
}

/**
 * Per-row coverage summary included in the bundle manifest.
 */
export interface ManifestRowSummary {
  id: string;
  clause_id: string;
  coverage: CoverageFlag;
  evidence_emitter: string[];
}

/**
 * Bundle manifest (`00_bundle_manifest.json`). Machine-readable
 * index of the bundle with signature metadata and coverage summary.
 */
export interface BundleManifest {
  bundle_version: "1.0";
  matrix_version: "v1";
  regulation_version: string;
  generated_at: string;
  agent_did: string;
  period_start: string;
  period_end: string;
  deployment_context: DeploymentContext;
  signer: {
    did: string;
    public_key_base64url: string;
  };
  files: Array<{
    filename: string;
    content_type: "text/markdown" | "application/json";
    sha256: string;
    signature: string;
  }>;
  coverage_summary: {
    total_rows: number;
    full: number;
    partial: number;
    manual_only: number;
    full_pct: number;
    partial_pct: number;
    manual_only_pct: number;
  };
  coverage_rows: ManifestRowSummary[];
  /** Ed25519 signature over the canonical manifest body. */
  manifest_signature: string;
  disclaimer: string;
}

/**
 * The complete generated bundle. Callers (the CLI, the MCP tool
 * handler) decide whether to write it to disk or return it in-memory.
 */
export interface ComplianceBundle {
  manifest: BundleManifest;
  files: BundleFile[];
  /**
   * Present iff `publish_to_verascore` was true in the input.
   * Always reports the outcome — the bundle is returned in the
   * same shape whether the publish succeeded or failed.
   */
  publish_result?: VerascorePublishResult;
}

// ── Audit-log slice (for Article 12 / Article 26 documents) ──────────

/**
 * Lightweight view of audit log entries for the reporting period.
 * The generator fetches this from the AuditLog and formats it into
 * the Article 12 and Article 26 templates.
 */
export interface AuditPeriodSummary {
  period_start: string;
  period_end: string;
  total_entries: number;
  entries_by_layer: {
    l1: number;
    l2: number;
    l3: number;
    l4: number;
  };
  gate_decisions: {
    allow: number;
    allow_proxy: number;
    deny: number;
    escalate: number;
    unclassified: number;
  };
  injection_detected: number;
  unique_operations: string[];
  unique_identities: string[];
}
