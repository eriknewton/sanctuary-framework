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
    l1_cognitive: L1AuditResult;
    l2_operational: L2AuditResult;
    l3_selective_disclosure: L3AuditResult;
    l4_reputation: L4AuditResult;
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
  node_version: string;
  platform: string;
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

export interface L1AuditResult {
  status: "active" | "partial" | "inactive";
  encryption_at_rest: boolean;
  key_custody: "self" | "platform" | "none";
  integrity_verification: boolean;
  identity_cryptographic: boolean;
  state_portable: boolean;
  findings: string[];
}

export interface L2AuditResult {
  status: "active" | "partial" | "inactive";
  approval_gate: "three-tier" | "binary" | "none";
  behavioral_anomaly_detection: boolean;
  audit_trail_encrypted: boolean;
  audit_trail_exists: boolean;
  tool_sandboxing: "policy-enforced" | "basic" | "none";
  findings: string[];
}

export interface L3AuditResult {
  status: "active" | "partial" | "inactive";
  commitment_scheme: "pedersen+sha256" | "sha256-only" | "none";
  zero_knowledge_proofs: boolean;
  selective_disclosure_policy: boolean;
  findings: string[];
}

export interface L4AuditResult {
  status: "active" | "partial" | "inactive";
  reputation_portable: boolean;
  reputation_signed: boolean;
  reputation_sybil_detection: boolean;
  sovereignty_gated_tiers: boolean;
  findings: string[];
}

// ── Gaps and Recommendations ────────────────────────────────────────────

export interface SovereigntyGap {
  id: string;                         // e.g., "GAP-L1-001"
  layer: "L1" | "L2" | "L3" | "L4" | "cross-cutting";
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  openclaw_relevance: string | null;
  sanctuary_solution: string;
}

export interface Recommendation {
  priority: number;          // 1 = highest
  action: string;
  tool: string | null;
  effort: "immediate" | "minutes" | "hours";
  impact: "critical" | "high" | "medium";
}
