/**
 * Sanctuary MCP Server — Sovereignty Audit Types
 *
 * Type definitions for the sovereignty audit tool's gap analysis,
 * environment fingerprinting, and scoring model.
 */

// ── Audit Result ────────────────────────────────────────────────────────

export interface SovereigntyAuditResult {
  version: "1.0";
  audited_at: string;               // ISO 8601
  environment: EnvironmentFingerprint;
  layers: {
    l1_cognitive: CognitiveAuditResult;
    l2_operational: OperationalAuditResult;
    l3_selective_disclosure: DisclosureAuditResult;
    l4_reputation: ReputationAuditResult;
  };
  overall_score: number;             // 0–100
  sovereignty_level: "full" | "partial" | "minimal" | "none";
  gaps: SovereigntyGap[];            // Ordered by severity
  recommendations: Recommendation[]; // Ordered by impact
}

// ── Environment Fingerprint ─────────────────────────────────────────────

export interface EnvironmentFingerprint {
  sanctuary_installed: boolean;
  sanctuary_version: string | null;
  openclaw_detected: boolean;
  openclaw_version: string | null;
  openclaw_config: OpenClawConfigAudit | null;
  audit_subsystem_health?: AuditSubsystemHealth;
  node_version: string;
  platform: string;
}

export type AuditSubsystemFindingKind =
  | "sequence_gap"
  | "sequence_gap_or_reorder"
  | "prev_hash_mismatch"
  | "entry_hash_mismatch"
  | "checkpoint_root_mismatch"
  | string;

export interface AuditSubsystemFinding {
  kind: AuditSubsystemFindingKind;
  message?: string;
  key?: string;
  sequence?: number;
  expected?: string | number;
  actual?: string | number;
}

export interface AuditSubsystemHealth {
  integrity_findings: AuditSubsystemFinding[];
  exit_export_aborted_by_integrity_gate: boolean;
  mcp_tools_bricked_by_integrity_gate: boolean;
}

export interface OpenClawConfigAudit {
  config_path: string | null;
  require_approval_enabled: boolean;
  sandbox_policy_active: boolean;
  sandbox_allow_list: string[];
  sandbox_deny_list: string[];
  memory_encrypted: boolean;
  env_file_exposed: boolean;
  gateway_token_set: boolean;
  dm_pairing_enabled: boolean;
  mcp_bridge_active: boolean;
}

// ── Layer Audit Results ─────────────────────────────────────────────────

export interface CognitiveAuditResult {
  status: "active" | "partial" | "inactive";
  encryption_at_rest: boolean;
  key_custody: "self" | "platform" | "none";
  integrity_verification: boolean;
  identity_cryptographic: boolean;
  state_portable: boolean;
  findings: string[];
}

export interface OperationalAuditResult {
  status: "active" | "partial" | "inactive";
  approval_gate: "three-tier" | "binary" | "none";
  behavioral_anomaly_detection: boolean;
  audit_trail_encrypted: boolean;
  audit_trail_exists: boolean;
  tool_sandboxing: "policy-enforced" | "basic" | "none";
  context_gating: boolean;
  process_isolation_hardening?: "full" | "hardened" | "basic" | "none";
  findings: string[];
}

export interface DisclosureAuditResult {
  status: "active" | "partial" | "inactive";
  commitment_scheme: "pedersen+sha256" | "sha256-only" | "none";
  zero_knowledge_proofs: boolean;
  selective_disclosure_policy: boolean;
  findings: string[];
}

export interface ReputationAuditResult {
  status: "active" | "partial" | "inactive";
  reputation_portable: boolean;
  reputation_signed: boolean;
  reputation_sybil_detection: boolean;
  sovereignty_gated_tiers: boolean;
  findings: string[];
}

// ── Back-compat aliases (L1-L4 rename PR-3) ─────────────────────────────
// The layer-numbered names stay exported as aliases so downstream imports
// keep working. The functional names above are canonical.
export type L1AuditResult = CognitiveAuditResult;
export type L2AuditResult = OperationalAuditResult;
export type L3AuditResult = DisclosureAuditResult;
export type L4AuditResult = ReputationAuditResult;

// ── Gaps and Recommendations ────────────────────────────────────────────

export interface SovereigntyGap {
  id: string;                         // e.g., "GAP-L1-001"
  layer: "L1" | "L2" | "L3" | "L4" | "cross-cutting";
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  openclaw_relevance: string | null;
  sanctuary_solution: string;
  /** Real-world incident class this gap maps to, if applicable. */
  incident_class?: IncidentClass | null;
}

export interface IncidentClass {
  /** Short identifier, e.g., "META-SEV1-2026" */
  id: string;
  /** Human-readable incident name */
  name: string;
  /** When the incident occurred */
  date: string;
  /** Brief description of what happened */
  description: string;
  /** CVE identifiers, if applicable */
  cves?: string[];
}

export interface Recommendation {
  priority: number;          // 1 = highest
  action: string;
  tool: string | null;
  effort: "immediate" | "minutes" | "hours";
  impact: "critical" | "high" | "medium";
}
