/**
 * Sanctuary MCP Server — Sovereignty Gap Analyzer
 *
 * Analyzes an environment fingerprint against Sanctuary's four-layer sovereignty
 * model and produces a scored gap analysis with prioritized recommendations.
 *
 * Scoring is deterministic: same environment state → same score, every time.
 */

import type { SanctuaryConfig } from "../config.js";
import type {
  EnvironmentFingerprint,
  SovereigntyAuditResult,
  CognitiveAuditResult,
  OperationalAuditResult,
  DisclosureAuditResult,
  ReputationAuditResult,
  SovereigntyGap,
  IncidentClass,
  Recommendation,
} from "./types.js";

// ── Scoring Constants ───────────────────────────────────────────────────

// L1: 35 points max
const COGNITIVE_ENCRYPTION_AT_REST = 10;
const COGNITIVE_IDENTITY_CRYPTOGRAPHIC = 10;
const COGNITIVE_INTEGRITY_VERIFICATION = 8;
const COGNITIVE_STATE_PORTABLE = 7;

// L2: 30 points max (increased from 25 to accommodate hardening)
const OPERATIONAL_THREE_TIER_GATE = 10;
const OPERATIONAL_BINARY_GATE = 3;
const OPERATIONAL_ANOMALY_DETECTION = 5;
const OPERATIONAL_ENCRYPTED_AUDIT = 4;
const OPERATIONAL_TOOL_SANDBOXING = 2;
const OPERATIONAL_CONTEXT_GATING = 4;
const OPERATIONAL_PROCESS_HARDENING = 5;

// L3: 20 points max
// Note: Schnorr + range proofs ARE genuine zero-knowledge proofs.
// Non-interactive Fiat-Shamir is superior to interactive protocols for MCP servers
// (no round-trip latency, offline-verifiable, replay-resistant via domain separation).
const DISCLOSURE_COMMITMENT_SCHEME = 8;
const DISCLOSURE_ZK_PROOFS = 7;
const DISCLOSURE_DISCLOSURE_POLICIES = 5;

// L4: 20 points max
const REPUTATION_PORTABLE_REPUTATION = 6;
const REPUTATION_SIGNED_ATTESTATIONS = 6;
const REPUTATION_SYBIL_DETECTION = 4;
const REPUTATION_SOVEREIGNTY_GATED = 4;

const AUDIT_INTEGRITY_FINDING_PENALTY = 20;
const AUDIT_INTEGRITY_FINDING_PENALTY_CAP = 70;
const AUDIT_EXIT_EXPORT_ABORTED_PENALTY = 25;
const AUDIT_MCP_TOOLS_BRICKED_PENALTY = 25;
const AUDIT_HEALTH_DEDUCTED_KINDS = new Set([
  "sequence_gap",
  "sequence_gap_or_reorder",
  "prev_hash_mismatch",
  "entry_hash_mismatch",
  "checkpoint_root_mismatch",
]);

// Severity ordering for gap sorting
const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// ── Incident Class Catalog ─────────────────────────────────────────────
// Real-world incidents mapped to the sovereignty gaps they exploited.

const INCIDENT_META_SEV1: IncidentClass = {
  id: "META-SEV1-2026",
  name: "Meta Sev 1: Unauthorized autonomous data exposure",
  date: "2026-03-18",
  description:
    "AI agent autonomously posted proprietary code, business strategies, and user datasets " +
    "to an internal forum without human approval. Two-hour exposure window.",
};

const INCIDENT_OPENCLAW_SANDBOX: IncidentClass = {
  id: "OPENCLAW-CVE-2026",
  name: "OpenClaw sandbox escape via privilege inheritance",
  date: "2026-03-18",
  description:
    "Nine CVEs in four days. Child processes inherited sandbox.mode=off from parent, " +
    "bypassing runtime confinement. 42,900+ internet-exposed instances, 15,200 vulnerable to RCE.",
  cves: [
    "CVE-2026-32048",
    "CVE-2026-32915",
    "CVE-2026-32918",
  ],
};

const INCIDENT_CONTEXT_LEAKAGE: IncidentClass = {
  id: "CONTEXT-LEAK-CLASS",
  name: "Context leakage: Full state exposure to inference providers",
  date: "2026-03",
  description:
    "Agents send full context — conversation history, memory, secrets, internal reasoning — " +
    "to remote LLM providers on every inference call with no filtering mechanism.",
};

/** Exported for use in custom gap analysis extensions. */
export const INCIDENT_META_INBOX: IncidentClass = {
  id: "META-INBOX-2026",
  name: "Meta inbox deletion: Safety instructions stripped by context compaction",
  date: "2026-03",
  description:
    "OpenClaw agent instructed to 'always ask before taking actions' began deleting inbox " +
    "autonomously after context window compaction silently stripped the safety instruction.",
};

const INCIDENT_CLAUDE_CODE_LEAK: IncidentClass = {
  id: "CLAUDE-CODE-LEAK-2026",
  name: "Claude Code source leak: 512K lines exposed via npm source map",
  date: "2026-03-31",
  description:
    "Anthropic accidentally shipped a 59.8 MB source map in npm package v2.1.88, exposing " +
    "the full Claude Code TypeScript source — 1,900 files, internal model codenames, " +
    "unreleased features, OAuth flows, and multi-agent coordination logic.",
};

/**
 * Analyze sovereignty posture and produce a full audit result.
 */
export function analyzeSovereignty(
  env: EnvironmentFingerprint,
  config: SanctuaryConfig
): SovereigntyAuditResult {
  const cognitive = assessCognitive(env, config);
  const operational = assessOperational(env, config);
  const disclosure = assessDisclosure(env, config);
  const reputation = assessReputation(env, config);

  const cognitiveScore = scoreCognitive(cognitive);
  const operationalScore = scoreOperational(operational);
  const disclosureScore = scoreDisclosure(disclosure);
  const reputationScore = scoreReputation(reputation);

  const baseScore = cognitiveScore + operationalScore + disclosureScore + reputationScore;
  const auditHealthPenalty = scoreAuditHealthPenalty(env);
  const overallScore = Math.max(0, baseScore - auditHealthPenalty);

  const sovereigntyLevel = overallScore >= 80
    ? "full"
    : overallScore >= 50
      ? "partial"
      : overallScore >= 20
        ? "minimal"
        : "none";

  const gaps = generateGaps(env, cognitive, operational, disclosure, reputation);
  gaps.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const recommendations = generateRecommendations(env, cognitive, operational, disclosure, reputation);

  return {
    version: "1.0",
    audited_at: new Date().toISOString(),
    environment: env,
    layers: {
      l1_cognitive: cognitive,
      l2_operational: operational,
      l3_selective_disclosure: disclosure,
      l4_reputation: reputation,
    },
    overall_score: overallScore,
    sovereignty_level: sovereigntyLevel,
    gaps,
    recommendations,
  };
}

// ── Layer Assessment ────────────────────────────────────────────────────

function assessCognitive(
  env: EnvironmentFingerprint,
  config: SanctuaryConfig
): CognitiveAuditResult {
  const findings: string[] = [];
  const sanctuaryActive = env.sanctuary_installed;

  const encryptionAtRest = sanctuaryActive;
  const keyCustody = sanctuaryActive ? "self" as const : "none" as const;
  const integrityVerification = sanctuaryActive;
  const identityCryptographic = sanctuaryActive;
  const statePortable = sanctuaryActive;

  if (sanctuaryActive) {
    findings.push("AES-256-GCM encryption active for all state");
    findings.push(`Key derivation: ${config.state.key_derivation}`);
    findings.push(`Identity provider: ${config.state.identity_provider}`);
    findings.push("Merkle integrity verification enabled");
    findings.push("State export/import available");
  }

  if (env.openclaw_detected && env.openclaw_config) {
    if (!env.openclaw_config.memory_encrypted) {
      findings.push("OpenClaw agent memory (MEMORY.md, daily notes) stored in plaintext");
    }
    if (env.openclaw_config.env_file_exposed) {
      findings.push("OpenClaw .env file contains plaintext API keys/tokens");
    }
  }

  const status = encryptionAtRest && identityCryptographic
    ? "active"
    : encryptionAtRest || identityCryptographic
      ? "partial"
      : "inactive";

  return {
    status,
    encryption_at_rest: encryptionAtRest,
    key_custody: keyCustody,
    integrity_verification: integrityVerification,
    identity_cryptographic: identityCryptographic,
    state_portable: statePortable,
    findings,
  };
}

function assessOperational(
  env: EnvironmentFingerprint,
  _config: SanctuaryConfig
): OperationalAuditResult {
  const findings: string[] = [];
  const sanctuaryActive = env.sanctuary_installed;

  let approvalGate: "three-tier" | "binary" | "none" = "none";
  let behavioralAnomalyDetection = false;
  let auditTrailEncrypted = false;
  let auditTrailExists = false;
  let toolSandboxing: "policy-enforced" | "basic" | "none" = "none";
  let contextGating = false;

  if (sanctuaryActive) {
    approvalGate = "three-tier";
    behavioralAnomalyDetection = true;
    auditTrailEncrypted = true;
    auditTrailExists = true;
    contextGating = true;
    findings.push("Three-tier Principal Policy gate active");
    findings.push("Behavioral anomaly detection (BaselineTracker) enabled");
    findings.push("Encrypted audit trail active");
    findings.push("Context gating available (sanctuary/context_gate_set_policy)");
  }

  if (env.openclaw_detected && env.openclaw_config) {
    if (env.openclaw_config.require_approval_enabled) {
      if (!sanctuaryActive) {
        approvalGate = "binary";
      }
      findings.push("OpenClaw requireApproval hook enabled (binary approve/deny)");
    }
    if (env.openclaw_config.sandbox_policy_active) {
      if (!sanctuaryActive) {
        toolSandboxing = "basic";
      }
      findings.push(
        `OpenClaw sandbox policy active (${env.openclaw_config.sandbox_allow_list.length} allowed, ` +
        `${env.openclaw_config.sandbox_deny_list.length} denied)`
      );
    }
  }

  // L2 hardening is optional and can be verified via tools at runtime
  // This assessment assumes default "none"; actual hardening is measured
  // by the l2_hardening_status and l2_verify_isolation tools
  const processIsolationHardening = "none";

  const status = approvalGate === "three-tier" && auditTrailEncrypted
    ? "active"
    : approvalGate !== "none" || auditTrailExists
      ? "partial"
      : "inactive";

  return {
    status,
    approval_gate: approvalGate,
    behavioral_anomaly_detection: behavioralAnomalyDetection,
    audit_trail_encrypted: auditTrailEncrypted,
    audit_trail_exists: auditTrailExists,
    tool_sandboxing: sanctuaryActive ? "policy-enforced" : toolSandboxing,
    context_gating: contextGating,
    process_isolation_hardening: processIsolationHardening,
    findings,
  };
}

function assessDisclosure(
  env: EnvironmentFingerprint,
  _config: SanctuaryConfig
): DisclosureAuditResult {
  const findings: string[] = [];
  const sanctuaryActive = env.sanctuary_installed;

  let commitmentScheme: "pedersen+sha256" | "sha256-only" | "none" = "none";
  let zkProofs = false;
  let selectiveDisclosurePolicy = false;

  if (sanctuaryActive) {
    commitmentScheme = "pedersen+sha256";
    zkProofs = true; // Schnorr proofs + range proofs
    selectiveDisclosurePolicy = true;
    findings.push("SHA-256 + Pedersen commitment schemes active");
    findings.push("Schnorr zero-knowledge proofs (Fiat-Shamir) enabled — genuine ZK proofs");
    findings.push("Range proofs (bit-decomposition + OR-proofs) enabled — genuine ZK proofs");
    findings.push("Selective disclosure policies configurable");
    findings.push("Non-interactive proofs with replay-resistant domain separation");
  }

  const status = commitmentScheme === "pedersen+sha256" && zkProofs
    ? "active"
    : commitmentScheme !== "none"
      ? "partial"
      : "inactive";

  return {
    status,
    commitment_scheme: commitmentScheme,
    zero_knowledge_proofs: zkProofs,
    selective_disclosure_policy: selectiveDisclosurePolicy,
    findings,
  };
}

function assessReputation(
  env: EnvironmentFingerprint,
  _config: SanctuaryConfig
): ReputationAuditResult {
  const findings: string[] = [];
  const sanctuaryActive = env.sanctuary_installed;

  const reputationPortable = sanctuaryActive;
  const reputationSigned = sanctuaryActive;
  const sybilDetection = sanctuaryActive;
  const sovereigntyGated = sanctuaryActive;

  if (sanctuaryActive) {
    findings.push("Signed EAS-compatible attestations active");
    findings.push("Reputation export/import available");
    findings.push("Sybil detection heuristics enabled");
    findings.push("Sovereignty-gated reputation tiers active");
  } else {
    findings.push("No portable reputation system detected");
  }

  const status = reputationPortable && reputationSigned && sovereigntyGated
    ? "active"
    : reputationPortable || reputationSigned
      ? "partial"
      : "inactive";

  return {
    status,
    reputation_portable: reputationPortable,
    reputation_signed: reputationSigned,
    reputation_sybil_detection: sybilDetection,
    sovereignty_gated_tiers: sovereigntyGated,
    findings,
  };
}

// ── Scoring ─────────────────────────────────────────────────────────────

function scoreCognitive(cognitive: CognitiveAuditResult): number {
  let score = 0;
  if (cognitive.encryption_at_rest) score += COGNITIVE_ENCRYPTION_AT_REST;
  if (cognitive.identity_cryptographic) score += COGNITIVE_IDENTITY_CRYPTOGRAPHIC;
  if (cognitive.integrity_verification) score += COGNITIVE_INTEGRITY_VERIFICATION;
  if (cognitive.state_portable) score += COGNITIVE_STATE_PORTABLE;
  return score;
}

function scoreOperational(operational: OperationalAuditResult): number {
  let score = 0;
  if (operational.approval_gate === "three-tier") score += OPERATIONAL_THREE_TIER_GATE;
  else if (operational.approval_gate === "binary") score += OPERATIONAL_BINARY_GATE;
  if (operational.behavioral_anomaly_detection) score += OPERATIONAL_ANOMALY_DETECTION;
  if (operational.audit_trail_encrypted) score += OPERATIONAL_ENCRYPTED_AUDIT;
  if (operational.tool_sandboxing === "policy-enforced") score += OPERATIONAL_TOOL_SANDBOXING;
  else if (operational.tool_sandboxing === "basic") score += 1;
  if (operational.context_gating) score += OPERATIONAL_CONTEXT_GATING;
  // Software-based process hardening without TEE
  if (operational.process_isolation_hardening === "hardened") score += OPERATIONAL_PROCESS_HARDENING;
  else if (operational.process_isolation_hardening === "basic") score += 2;
  return score;
}

function scoreDisclosure(disclosure: DisclosureAuditResult): number {
  let score = 0;
  // Pedersen commitments + Schnorr/range proofs = genuine zero-knowledge proofs
  // Full L3 = 20 points (8 commitment + 7 proofs + 5 policies)
  if (disclosure.commitment_scheme === "pedersen+sha256") score += DISCLOSURE_COMMITMENT_SCHEME;
  else if (disclosure.commitment_scheme === "sha256-only") score += 4;
  if (disclosure.zero_knowledge_proofs) score += DISCLOSURE_ZK_PROOFS;
  if (disclosure.selective_disclosure_policy) score += DISCLOSURE_DISCLOSURE_POLICIES;
  return score;
}

function scoreReputation(reputation: ReputationAuditResult): number {
  let score = 0;
  if (reputation.reputation_portable) score += REPUTATION_PORTABLE_REPUTATION;
  if (reputation.reputation_signed) score += REPUTATION_SIGNED_ATTESTATIONS;
  if (reputation.reputation_sybil_detection) score += REPUTATION_SYBIL_DETECTION;
  if (reputation.sovereignty_gated_tiers) score += REPUTATION_SOVEREIGNTY_GATED;
  return score;
}

function scoreAuditHealthPenalty(env: EnvironmentFingerprint): number {
  const health = env.audit_subsystem_health;
  if (!health) return 0;

  const deductedFindings = health.integrity_findings.filter((finding) =>
    AUDIT_HEALTH_DEDUCTED_KINDS.has(finding.kind)
  );
  const findingsPenalty = Math.min(
    deductedFindings.length * AUDIT_INTEGRITY_FINDING_PENALTY,
    AUDIT_INTEGRITY_FINDING_PENALTY_CAP
  );

  return (
    findingsPenalty +
    (health.exit_export_aborted_by_integrity_gate ? AUDIT_EXIT_EXPORT_ABORTED_PENALTY : 0) +
    (health.mcp_tools_bricked_by_integrity_gate ? AUDIT_MCP_TOOLS_BRICKED_PENALTY : 0)
  );
}

// ── Gap Generation ──────────────────────────────────────────────────────

function generateGaps(
  env: EnvironmentFingerprint,
  cognitive: CognitiveAuditResult,
  operational: OperationalAuditResult,
  disclosure: DisclosureAuditResult,
  reputation: ReputationAuditResult
): SovereigntyGap[] {
  const gaps: SovereigntyGap[] = [];
  const oc = env.openclaw_config;
  const auditHealth = env.audit_subsystem_health;

  const deductedAuditFindings = auditHealth?.integrity_findings.filter((finding) =>
    AUDIT_HEALTH_DEDUCTED_KINDS.has(finding.kind)
  ) ?? [];

  if (deductedAuditFindings.length > 0) {
    gaps.push({
      id: "GAP-AUDIT-001",
      layer: "cross-cutting",
      severity: "critical",
      title: "Audit chain integrity is compromised",
      description:
        `${deductedAuditFindings.length} audit-chain integrity finding(s) were detected. ` +
        "A sovereignty score cannot be full while the audit trail has sequence, hash, " +
        "or checkpoint-root failures.",
      openclaw_relevance: null,
      sanctuary_solution:
        "Treat the fortress as degraded, preserve the audit store for investigation, " +
        "repair or restore the audit chain, and rerun sovereignty_audit before trusting " +
        "operator-facing health signals.",
    });
  }

  if (auditHealth?.exit_export_aborted_by_integrity_gate) {
    gaps.push({
      id: "GAP-AUDIT-002",
      layer: "cross-cutting",
      severity: "critical",
      title: "Exit export blocked by audit-integrity gate",
      description:
        "The fortress is not fully portable while sanctuary exit export is aborting " +
        "because audit-integrity findings block the export path.",
      openclaw_relevance: null,
      sanctuary_solution:
        "Resolve the audit-integrity findings before relying on exit portability. " +
        "Until export succeeds, report sovereignty as degraded.",
    });
  }

  if (auditHealth?.mcp_tools_bricked_by_integrity_gate) {
    gaps.push({
      id: "GAP-AUDIT-003",
      layer: "cross-cutting",
      severity: "critical",
      title: "MCP tools blocked by audit-integrity gate",
      description:
        "One or more MCP tool calls are refusing to run because the audit-integrity " +
        "gate is fail-closed. A fortress with bricked operations must never report " +
        "a perfect sovereignty score.",
      openclaw_relevance: null,
      sanctuary_solution:
        "Keep the integrity gate fail-closed, repair or restore the audit chain, " +
        "then verify that MCP tool calls and sovereignty_audit agree on health.",
    });
  }

  // L1 gaps
  if (oc && !oc.memory_encrypted) {
    gaps.push({
      id: "GAP-L1-001",
      layer: "L1",
      severity: "critical",
      title: "Agent memory stored in plaintext",
      description:
        "Your agent's memory (MEMORY.md, daily notes, SQLite index) is stored in plaintext " +
        "at ~/.openclaw/workspace/. Any process with file access can read your agent's full " +
        "context — preferences, decisions, conversation history.",
      openclaw_relevance:
        "Stock OpenClaw stores all agent memory in plaintext files. " +
        "There is no built-in encryption for agent state.",
      sanctuary_solution:
        "Sanctuary encrypts all state at rest with AES-256-GCM using a key derived from " +
        "Argon2id, making state opaque to any process that doesn't hold the master key. " +
        "Use sanctuary/state_write to migrate sensitive state to the encrypted store.",
      incident_class: INCIDENT_META_SEV1,
    });
  }

  if (oc && oc.env_file_exposed) {
    gaps.push({
      id: "GAP-L1-002",
      layer: "L1",
      severity: "critical",
      title: "Plaintext API keys in .env file",
      description:
        "Your .env file contains plaintext API keys and tokens. These secrets are readable " +
        "by any process with filesystem access.",
      openclaw_relevance:
        "OpenClaw stores API keys (LLM providers, gateway tokens) in a plaintext .env file.",
      sanctuary_solution:
        "Sanctuary's encrypted state store can hold secrets under the same AES-256-GCM " +
        "envelope as all other state, tied to your self-custodied identity. " +
        "Use sanctuary/state_write with namespace 'secrets'.",
    });
  }

  if (!cognitive.identity_cryptographic) {
    gaps.push({
      id: "GAP-L1-003",
      layer: "L1",
      severity: "critical",
      title: "No cryptographic agent identity",
      description:
        "Your agent has no cryptographic identity. It cannot prove it is who it claims " +
        "to be to any counterparty, sign messages, or participate in sovereignty handshakes.",
      openclaw_relevance: env.openclaw_detected
        ? "OpenClaw has no cryptographic agent identity. Agent identity is implicit " +
          "(tied to the process/session), not cryptographically verifiable."
        : null,
      sanctuary_solution:
        "Sanctuary provides Ed25519 self-custodied identity with key rotation and delegation. " +
        "Use sanctuary/identity_create to establish your cryptographic identity.",
    });
  }

  // L2 gaps
  if (operational.approval_gate === "binary" && !operational.behavioral_anomaly_detection) {
    gaps.push({
      id: "GAP-L2-001",
      layer: "L2",
      severity: "high",
      title: "Binary approval gate (no anomaly detection)",
      description:
        "Your approval gate provides binary approve/deny gating without behavioral anomaly " +
        "detection. Routine operations require the same manual approval as sensitive ones.",
      openclaw_relevance: env.openclaw_detected
        ? "OpenClaw's requireApproval hook provides binary approve/deny gating. " +
          "Sanctuary's three-tier Principal Policy adds behavioral anomaly detection " +
          "(auto-escalation when agent behavior deviates from baseline), encrypted audit " +
          "trails, and graduated approval tiers — so routine operations auto-proceed while " +
          "sensitive operations require explicit consent."
        : null,
      sanctuary_solution:
        "Sanctuary's three-tier Principal Policy gate auto-allows routine operations (Tier 3), " +
        "escalates anomalous behavior (Tier 2), and always requires human approval for " +
        "irreversible operations (Tier 1). Use sanctuary/principal_policy_view to inspect.",
      incident_class: INCIDENT_META_SEV1,
    });
  } else if (operational.approval_gate === "none") {
    gaps.push({
      id: "GAP-L2-001",
      layer: "L2",
      severity: "critical",
      title: "No approval gate",
      description:
        "No approval gate is configured. All tool calls execute without oversight.",
      openclaw_relevance: null,
      sanctuary_solution:
        "Sanctuary's Principal Policy evaluates every tool call before execution. " +
        "Enable it to get three-tier approval gating with behavioral anomaly detection.",
      incident_class: INCIDENT_META_SEV1,
    });
  }

  if (operational.tool_sandboxing === "basic") {
    gaps.push({
      id: "GAP-L2-002",
      layer: "L2",
      severity: "medium",
      title: "Basic tool sandboxing (no cryptographic attestation)",
      description:
        "Your tool sandbox enforces allow/deny lists but provides no cryptographic " +
        "attestation of execution context.",
      openclaw_relevance: env.openclaw_detected
        ? "OpenClaw's sandbox tool policy (tools.sandbox.tools) enforces allow/deny lists. " +
          "Sanctuary adds cryptographic attestation of execution context — a verifiable proof " +
          "that an operation ran within policy, not just that a policy was configured."
        : null,
      sanctuary_solution:
        "Sanctuary provides cryptographic execution attestation via sanctuary/exec_attest " +
        "and policy-enforced sandboxing with encrypted audit trails.",
      incident_class: INCIDENT_OPENCLAW_SANDBOX,
    });
  }

  if (!operational.context_gating) {
    gaps.push({
      id: "GAP-L2-003",
      layer: "L2",
      severity: "high",
      title: "No context gating for outbound inference calls",
      description:
        "Your agent sends its full context — conversation history, memory, preferences, " +
        "internal reasoning — to remote LLM providers on every inference call. There is " +
        "no mechanism to filter what leaves the sovereignty boundary. The provider sees " +
        "everything the agent knows.",
      openclaw_relevance: env.openclaw_detected
        ? "OpenClaw sends full agent context (including MEMORY.md, tool results, and " +
          "conversation history) to the configured LLM provider with every API call. " +
          "There is no built-in context filtering."
        : null,
      sanctuary_solution:
        "Sanctuary's context gating (sanctuary/context_gate_set_policy + " +
        "context_gate_filter) lets you define per-provider policies that " +
        "control exactly what context flows outbound. Redact secrets, hash identifiers, " +
        "and send only minimum-necessary context for each call.",
      incident_class: INCIDENT_CONTEXT_LEAKAGE,
    });
  }

  if (!operational.audit_trail_exists) {
    gaps.push({
      id: "GAP-L2-004",
      layer: "L2",
      severity: "high",
      title: "No audit trail",
      description:
        "No audit trail exists for tool call history. There is no record of what operations " +
        "were executed, when, or by whom.",
      openclaw_relevance: null,
      sanctuary_solution:
        "Sanctuary maintains an encrypted audit log of all operations, queryable via " +
        "monitor_audit_log.",
      incident_class: INCIDENT_CLAUDE_CODE_LEAK,
    });
  }

  // L3 gaps
  if (disclosure.commitment_scheme === "none") {
    gaps.push({
      id: "GAP-L3-001",
      layer: "L3",
      severity: "high",
      title: "No selective disclosure capability",
      description:
        "Your agent has no cryptographic mechanism to prove facts about its state without " +
        "revealing the state itself. Every disclosure is all-or-nothing: no commitments, no " +
        "zero-knowledge proofs, no selective disclosure policies.",
      openclaw_relevance: env.openclaw_detected
        ? "OpenClaw has no selective disclosure mechanism. When your agent shares information, " +
          "it shares everything or nothing — there is no way to prove a claim without " +
          "revealing the underlying data."
        : null,
      sanctuary_solution:
        "Sanctuary's L3 provides SHA-256 + Pedersen commitments with genuine zero-knowledge " +
        "proofs (Schnorr + range proofs via Fiat-Shamir transform). Your agent can prove it " +
        "has a valid credential, sufficient reputation, or a completed transaction without " +
        "exposing the underlying data. Use sanctuary/zk_commit and sanctuary/zk_prove.",
      incident_class: INCIDENT_META_SEV1,
    });
  }

  // L4 gaps
  if (!reputation.reputation_portable) {
    gaps.push({
      id: "GAP-L4-001",
      layer: "L4",
      severity: "high",
      title: "No portable reputation",
      description:
        "Your agent's reputation is platform-locked. If you move to a different harness " +
        "or platform, your track record doesn't follow.",
      openclaw_relevance: env.openclaw_detected
        ? "OpenClaw has no reputation system. Your agent's track record exists only in " +
          "conversation history, which is not structured, signed, or portable."
        : null,
      sanctuary_solution:
        "Sanctuary's L4 provides signed EAS-compatible attestations that are self-custodied, " +
        "portable, and cryptographically verifiable. Your reputation is yours, not your " +
        "platform's. Use sanctuary/reputation_record to start building portable reputation.",
    });
  }

  return gaps;
}

// ── Recommendation Generation ───────────────────────────────────────────

function generateRecommendations(
  env: EnvironmentFingerprint,
  cognitive: CognitiveAuditResult,
  operational: OperationalAuditResult,
  disclosure: DisclosureAuditResult,
  reputation: ReputationAuditResult
): Recommendation[] {
  const recs: Recommendation[] = [];

  if (env.audit_subsystem_health?.integrity_findings.some((finding) =>
    AUDIT_HEALTH_DEDUCTED_KINDS.has(finding.kind)
  )) {
    recs.push({
      priority: 1,
      action: "Repair or restore the audit chain before trusting sovereignty health",
      tool: "monitor_audit_log",
      effort: "immediate",
      impact: "critical",
    });
  }

  if (!cognitive.identity_cryptographic) {
    recs.push({
      priority: 1,
      action: "Create a cryptographic identity — your agent's foundation for all sovereignty operations",
      tool: "identity_create",
      effort: "immediate",
      impact: "critical",
    });
  }

  if (!cognitive.encryption_at_rest || (env.openclaw_config && !env.openclaw_config.memory_encrypted)) {
    recs.push({
      priority: 2,
      action: "Migrate plaintext agent state to Sanctuary's encrypted store",
      tool: "state_write",
      effort: "minutes",
      impact: "critical",
    });
  }

  recs.push({
    priority: 3,
    action: "Generate a Sovereignty Health Report to present to counterparties",
    tool: "shr_generate",
    effort: "immediate",
    impact: "high",
  });

  if (operational.approval_gate !== "three-tier") {
    recs.push({
      priority: 4,
      action: "Enable the three-tier Principal Policy gate for graduated approval",
      tool: "principal_policy_view",
      effort: "minutes",
      impact: "high",
    });
  }

  if (!operational.context_gating) {
    recs.push({
      priority: 5,
      action: "Configure context gating to control what flows to LLM providers",
      tool: "context_gate_set_policy",
      effort: "minutes",
      impact: "high",
    });
  }

  if (!reputation.reputation_signed) {
    recs.push({
      priority: 6,
      action: "Start recording reputation attestations from completed interactions",
      tool: "reputation_record",
      effort: "minutes",
      impact: "medium",
    });
  }

  if (!disclosure.selective_disclosure_policy) {
    recs.push({
      priority: 7,
      action: "Configure selective disclosure policies for data sharing",
      tool: "disclosure_set_policy",
      effort: "hours",
      impact: "medium",
    });
  }

  return recs.sort((a, b) => a.priority - b.priority);
}

// ── Report Formatting ───────────────────────────────────────────────────

/**
 * Format the audit result as a human-readable report.
 */
export function formatAuditReport(result: SovereigntyAuditResult): string {
  const { environment: env, layers, overall_score, sovereignty_level, gaps, recommendations } = result;

  const scoreBar = formatScoreBar(overall_score);
  const levelLabel = sovereignty_level.toUpperCase();

  let report = "";
  report += "═══════════════════════════════════════════════\n";
  report += "  SOVEREIGNTY AUDIT REPORT\n";
  report += `  Generated: ${result.audited_at}\n`;
  report += "═══════════════════════════════════════════════\n";
  report += "\n";
  report += `  Overall Score: ${overall_score} / 100  ${scoreBar}  ${levelLabel}\n`;
  report += "\n";

  // Environment section
  report += "  Environment:\n";
  report += `  • Sanctuary v${env.sanctuary_version ?? "?"} ${padDots("Sanctuary v" + (env.sanctuary_version ?? "?"))} ${env.sanctuary_installed ? "✓ installed" : "✗ not found"}\n`;

  if (env.openclaw_detected) {
    report += `  • OpenClaw ${padDots("OpenClaw")} ✓ detected\n`;
    if (env.openclaw_config) {
      report += `  • OpenClaw requireApproval ${padDots("OpenClaw requireApproval")} ${env.openclaw_config.require_approval_enabled ? "✓ enabled" : "✗ disabled"}\n`;
      report += `  • OpenClaw sandbox policy ${padDots("OpenClaw sandbox policy")} ${env.openclaw_config.sandbox_policy_active ? "✓ active" : "✗ inactive"}\n`;
    }
  }

  report += "\n";

  // Layer assessment table
  const cognitiveScore = scoreCognitive(layers.l1_cognitive);
  const operationalScore = scoreOperational(layers.l2_operational);
  const disclosureScore = scoreDisclosure(layers.l3_selective_disclosure);
  const reputationScore = scoreReputation(layers.l4_reputation);

  report += "  Layer Assessment:\n";
  report += "  ┌─────────────────────────────┬──────────┬───────┐\n";
  report += "  │ Layer                       │ Status   │ Score │\n";
  report += "  ├─────────────────────────────┼──────────┼───────┤\n";
  report += `  │ L1 Cognitive Sovereignty    │ ${padStatus(layers.l1_cognitive.status)} │ ${padScore(cognitiveScore, 35)} │\n`;
  report += `  │ L2 Operational Isolation    │ ${padStatus(layers.l2_operational.status)} │ ${padScore(operationalScore, 25)} │\n`;
  if (layers.l2_operational.context_gating) {
    report += `  │   └ Context Gating          │ ACTIVE   │       │\n`;
  }
  report += `  │ L3 Selective Disclosure     │ ${padStatus(layers.l3_selective_disclosure.status)} │ ${padScore(disclosureScore, 20)} │\n`;
  report += `  │ L4 Verifiable Reputation    │ ${padStatus(layers.l4_reputation.status)} │ ${padScore(reputationScore, 20)} │\n`;
  report += "  └─────────────────────────────┴──────────┴───────┘\n";
  report += "\n";

  // Gaps
  if (gaps.length > 0) {
    report += `  ⚠ ${gaps.length} SOVEREIGNTY GAP${gaps.length !== 1 ? "S" : ""} FOUND\n`;
    report += "\n";
    for (const gap of gaps) {
      const severityLabel = `[${gap.severity.toUpperCase()}]`;
      report += `  ${severityLabel} ${gap.id}: ${gap.title}\n`;
      // Wrap description to ~70 chars
      const descLines = wordWrap(gap.description, 66);
      for (const line of descLines) {
        report += `  ${line}\n`;
      }
      if (gap.incident_class) {
        const ic = gap.incident_class;
        const cveStr = ic.cves?.length ? ` (${ic.cves.join(", ")})` : "";
        report += `  → Incident precedent: ${ic.name}${cveStr} [${ic.date}]\n`;
      }
      report += `  → Fix: ${gap.sanctuary_solution.split(".")[0]}.\n`;
      if (gap.openclaw_relevance) {
        report += `  → OpenClaw context: ${gap.openclaw_relevance.split(".")[0]}.\n`;
      }
      report += "\n";
    }
  } else {
    report += "  ✓ NO SOVEREIGNTY GAPS FOUND\n";
    report += "\n";
  }

  // Recommendations
  if (recommendations.length > 0) {
    report += "  RECOMMENDED NEXT STEPS (in order):\n";
    for (const rec of recommendations) {
      const effortLabel = rec.effort === "immediate"
        ? "immediate"
        : rec.effort === "minutes"
          ? "5 min"
          : "30 min";
      report += `  ${rec.priority}. [${effortLabel}] ${rec.action}`;
      if (rec.tool) {
        report += `: ${rec.tool}`;
      }
      report += "\n";
    }
    report += "\n";
  }

  report += "═══════════════════════════════════════════════\n";

  return report;
}

// ── Helpers ─────────────────────────────────────────────────────────────

function formatScoreBar(score: number): string {
  const filled = Math.round(score / 10);
  return "[" + "■".repeat(filled) + "░".repeat(10 - filled) + "]";
}

function padDots(label: string): string {
  const totalWidth = 30;
  const dotsNeeded = Math.max(2, totalWidth - label.length - 4);
  return ".".repeat(dotsNeeded);
}

function padStatus(status: string): string {
  const label = status.toUpperCase();
  return label + " ".repeat(Math.max(0, 8 - label.length));
}

function padScore(score: number, max: number): string {
  const text = `${score}/${max}`;
  return " ".repeat(Math.max(0, 5 - text.length)) + text;
}

function wordWrap(text: string, maxWidth: number): string[] {
  const words = text.split(" ");
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    if (current.length + word.length + 1 > maxWidth && current.length > 0) {
      lines.push(current);
      current = word;
    } else {
      current = current.length > 0 ? current + " " + word : word;
    }
  }
  if (current.length > 0) lines.push(current);
  return lines;
}
