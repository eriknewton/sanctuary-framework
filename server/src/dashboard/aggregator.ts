/**
 * Sanctuary Dashboard — Protection Snapshot Aggregator
 *
 * Pulls unified protection state from the existing subsystems
 * (IdentityManager, AuditLog, ClientManager, BaselineTracker, policy)
 * and returns a single typed snapshot consumed by the API + HTML.
 *
 * The aggregator is the single source of truth for dashboard state.
 * It is pure (no I/O beyond what the injected sources already do) and
 * safe to call repeatedly — callers control freshness.
 */

import type { AuditLog, AuditEntry } from "../operational/audit-log.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { ClientManager } from "../proxy/client-manager.js";
import type { BaselineTracker } from "../principal-policy/baseline.js";
import type { PrincipalPolicy } from "../principal-policy/types.js";
import type { ReputationEvidence } from "../shr/generator.js";
import { deriveReputationDegradations } from "../shr/generator.js";
import type { SHRDegradation } from "../shr/types.js";
import type { SovereigntyTier } from "../reputation/tiers.js";

export type LayerState = "full" | "degraded" | "compromised";
export type OverallStatus = "healthy" | "degraded" | "compromised";

export interface AgentInfo {
  display_name: string;
  did: string | null;
  did_fingerprint: string | null;
  identity_count: number;
  primary_identity_id: string | null;
}

export interface CognitiveStatus {
  label: string;
  state: LayerState;
  headline: string;
  encryption: string;
  injection_blocked_today: number;
  memory_attest_ready: boolean;
}

export interface OperationalStatus {
  label: string;
  state: LayerState;
  headline: string;
  isolation_type: string;
  tee_available: boolean;
  tee_status: string;
  sandbox_status: string;
}

export interface DisclosureStatus {
  label: string;
  state: LayerState;
  headline: string;
  did_active: boolean;
  vc_count: number;
  proofs_today: number;
}

/** A single reputation-layer degradation surfaced to the dashboard widget. */
export interface ReputationActiveDegradation {
  code: string;
  severity: "info" | "warning" | "critical";
  description: string;
  mitigation?: string;
}

export interface ReputationStatus {
  label: string;
  state: LayerState;
  headline: string;
  score: number | null;
  profile_url: string | null;
  claim_cta: string | null;
  /**
   * Evidence surfaced under the L4 tile so users can tell what underlies
   * the reputation state. Null when no reputation store is wired in
   * (standalone mode, some tests).
   */
  evidence?: {
    attestation_count: number;
    tier_distribution: Record<SovereigntyTier, number>;
    most_recent_attestation_at: string | null;
    dispute_count: number;
    context_breakdown: Record<string, number>;
    verascore_linked: boolean;
  };
  /**
   * SHR-aligned L4 layer score (0-100) when evidence is available.
   * Computed with the same scoring model the gateway adapter uses so
   * counterparties and the dashboard agree on the number.
   */
  layer_score?: number;
  /** Active L4 degradations rendered under the widget. */
  active_degradations?: ReputationActiveDegradation[];
}

// ── Back-compat aliases (L1-L4 rename PR-3) ─────────────────────────────
// The layer-numbered status type names stay exported as aliases so
// downstream imports keep working. The functional names above are canonical.
export type L1Status = CognitiveStatus;
export type L2Status = OperationalStatus;
export type L3Status = DisclosureStatus;
export type L4Status = ReputationStatus;
export type L4ActiveDegradation = ReputationActiveDegradation;

export interface ActivityEntry {
  timestamp: string;
  tool: string;
  server: string;
  tier: 1 | 2 | 3;
  result: "allowed" | "denied" | "approved" | "pending";
}

export interface PendingApproval {
  id: string;
  operation: string;
  tier: 1 | 2;
  reason: string;
  created_at: string;
}

export interface UpstreamServerStatus {
  name: string;
  state: string;
  tool_count: number;
  error?: string;
}

export interface PrivacySummary {
  filtered_events: number;
  filtered_spans: number;
  classes: Record<string, number>;
  last_filtered_at: string | null;
}

export interface ProtectionSnapshot {
  overall: {
    status: OverallStatus;
    light: "green" | "yellow" | "red";
    headline: string;
  };
  agent: AgentInfo;
  layers: {
    l1: CognitiveStatus;
    l2: OperationalStatus;
    l3: DisclosureStatus;
    l4: ReputationStatus;
  };
  activity: ActivityEntry[];
  pending_approvals: PendingApproval[];
  audit: AuditEntry[];
  privacy: PrivacySummary;
  upstream_servers: UpstreamServerStatus[];
  mode: "co-located" | "standalone";
  server_version: string;
  generated_at: string;
}

export interface ReputationLookup {
  score: number | null;
  profile_url: string | null;
}

export interface AggregatorSources {
  mode: "co-located" | "standalone";
  server_version: string;
  identityManager?: IdentityManager;
  auditLog?: AuditLog;
  clientManager?: ClientManager;
  baseline?: BaselineTracker;
  policy?: PrincipalPolicy;
  activity?: ActivityEntry[];
  pendingApprovals?: PendingApproval[];
  reputation?: ReputationLookup;
  teeAvailable?: boolean;
  /**
   * Pre-computed L4 reputation evidence for the primary identity. When
   * present the dashboard renders the evidence widget under the L4 tile
   * and computes an SHR-aligned L4 layer score. Providers build this
   * via `gatherReputationEvidence` from `shr/tools.ts`.
   */
  l4Evidence?: ReputationEvidence;
  /** Clock override for deterministic staleness rendering in tests. */
  l4Now?: Date;
}

/**
 * Severity → point impact for the SHR L4 layer score. Mirrors the
 * gateway-adapter DEGRADATION_IMPACT table so the dashboard and the SHR
 * gateway export agree on the number.
 */
const REPUTATION_DEGRADATION_IMPACT: Record<"critical" | "warning" | "info", number> = {
  critical: 40,
  warning: 25,
  info: 10,
};

function computeReputationLayerScore(
  degradations: SHRDegradation[],
  status: LayerState
): number {
  if (status === "compromised") return 0;
  let score = 100;
  for (const deg of degradations) {
    score -= REPUTATION_DEGRADATION_IMPACT[deg.severity] ?? 10;
  }
  score = Math.max(0, score);
  if (degradations.length === 0 && score > 50) {
    score = Math.min(100, score + 5);
  }
  return Math.round(score);
}

const MAX_ACTIVITY = 50;
const MAX_AUDIT = 50;

function fingerprintDID(did: string): string {
  const raw = did.replace(/^did:[a-z0-9]+:/i, "");
  if (raw.length <= 12) return raw;
  return `${raw.slice(0, 6)}…${raw.slice(-6)}`;
}

function countInjectionsToday(audit: AuditEntry[]): number {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const cutoff = startOfDay.getTime();
  return audit.filter((e) => {
    const ts = new Date(e.timestamp).getTime();
    if (isNaN(ts) || ts < cutoff) return false;
    const op = (e.operation ?? "").toLowerCase();
    return op.includes("injection") || op.includes("blocked");
  }).length;
}

/** Proof-creation ops — update this allowlist when adding new ZK tools. */
const PROOF_CREATION_OPS = new Set([
  "zk_prove",
  "zk_range_prove",
  "proof_commitment",
]);

function countProofsToday(audit: AuditEntry[]): number {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const cutoff = startOfDay.getTime();
  return audit.filter((e) => {
    if (e.layer !== "l3") return false;
    if (!PROOF_CREATION_OPS.has(e.operation)) return false;
    const ts = new Date(e.timestamp).getTime();
    return !isNaN(ts) && ts >= cutoff;
  }).length;
}

function buildAgent(
  sources: AggregatorSources
): AgentInfo {
  if (!sources.identityManager) {
    return {
      display_name: "Unclaimed agent",
      did: null,
      did_fingerprint: null,
      identity_count: 0,
      primary_identity_id: null,
    };
  }
  const primary = sources.identityManager.getDefault();
  const identities = sources.identityManager.list();
  if (!primary) {
    return {
      display_name: "Unclaimed agent",
      did: null,
      did_fingerprint: null,
      identity_count: identities.length,
      primary_identity_id: null,
    };
  }
  return {
    display_name: primary.label || "Sovereign agent",
    did: primary.did,
    did_fingerprint: fingerprintDID(primary.did),
    identity_count: identities.length,
    primary_identity_id: primary.identity_id,
  };
}

function buildCognitive(
  sources: AggregatorSources,
  audit: AuditEntry[]
): CognitiveStatus {
  const hasIdentity = !!sources.identityManager?.getDefault();
  const state: LayerState = hasIdentity ? "full" : "degraded";
  return {
    label: "L1 Cognitive",
    state,
    headline: hasIdentity
      ? "State encrypted at rest"
      : "No sovereign identity — run sanctuary_bootstrap",
    encryption: "AES-256-GCM + HKDF per namespace",
    injection_blocked_today: countInjectionsToday(audit),
    memory_attest_ready: hasIdentity,
  };
}

function buildOperational(sources: AggregatorSources): OperationalStatus {
  const teeAvailable = sources.teeAvailable ?? false;
  const state: LayerState = teeAvailable ? "full" : "degraded";
  return {
    label: "L2 Operational",
    state,
    headline: teeAvailable
      ? "Hardware isolation active"
      : "Process isolation — no TEE on this host",
    isolation_type: teeAvailable ? "hardware-tee" : "process-level",
    tee_available: teeAvailable,
    tee_status: teeAvailable ? "Attested" : "Not available — normal on local dev",
    sandbox_status: "Principal Policy gate active",
  };
}

function buildDisclosure(
  sources: AggregatorSources,
  audit: AuditEntry[]
): DisclosureStatus {
  /** L4 attestation-producing ops — update when adding new VC tools. */
  const VC_ISSUING_OPS = new Set([
    "reputation_record",
    "bootstrap_provide_guarantee",
    "reputation_publish",
  ]);
  const didActive = !!sources.identityManager?.getDefault()?.did;
  const vcCount = audit.filter(
    (e) => e.layer === "l4" && VC_ISSUING_OPS.has(e.operation)
  ).length;
  return {
    label: "L3 Disclosure",
    state: didActive ? "full" : "degraded",
    headline: didActive
      ? "Selective disclosure ready"
      : "No DID — disclosure unavailable",
    did_active: didActive,
    vc_count: vcCount,
    proofs_today: countProofsToday(audit),
  };
}

function buildReputation(sources: AggregatorSources): ReputationStatus {
  const rep = sources.reputation;
  const hasDid = !!sources.identityManager?.getDefault()?.did;

  // Evidence-derived fields — present when the caller wired in a
  // reputation store. These do not replace the Verascore score; they
  // complement it so the dashboard can honestly describe the underlying
  // attestation state even when a Verascore score is attached.
  const evidenceBlock = buildReputationEvidenceBlock(sources);

  const base: ReputationStatus = rep?.score != null
    ? {
        label: "L4 Reputation",
        state: "full",
        headline: "Verascore attached",
        score: rep.score,
        profile_url: rep.profile_url,
        claim_cta: null,
      }
    : hasDid
      ? {
          label: "L4 Reputation",
          state: "degraded",
          headline: "Claim your profile",
          score: null,
          profile_url: null,
          claim_cta: "Claim your profile at verascore.ai",
        }
      : {
          label: "L4 Reputation",
          state: "degraded",
          headline: "No identity claimed",
          score: null,
          profile_url: null,
          claim_cta: "Claim your profile at verascore.ai",
        };

  if (!evidenceBlock) return base;

  // Apply the evidence-aware overrides: if any L4 degradations fire and
  // the tile is otherwise "full" (Verascore attached), downgrade the
  // state so the widget reflects the full SHR truth.
  const nextState: LayerState =
    evidenceBlock.active_degradations.length > 0 && base.state === "full"
      ? "degraded"
      : base.state;
  const nextHeadline =
    nextState === base.state
      ? base.headline
      : "Attached, but evidence is degraded";

  return {
    ...base,
    state: nextState,
    headline: nextHeadline,
    evidence: evidenceBlock.evidence,
    layer_score: evidenceBlock.layer_score,
    active_degradations: evidenceBlock.active_degradations,
  };
}

interface ReputationEvidenceBlock {
  evidence: NonNullable<ReputationStatus["evidence"]>;
  layer_score: number;
  active_degradations: ReputationActiveDegradation[];
}

function buildReputationEvidenceBlock(
  sources: AggregatorSources
): ReputationEvidenceBlock | null {
  const ev = sources.l4Evidence;
  if (!ev) return null;

  const degradations = deriveReputationDegradations(ev, sources.l4Now ?? new Date());
  const status: LayerState = degradations.length > 0 ? "degraded" : "full";
  const layer_score = computeReputationLayerScore(degradations, status);

  return {
    evidence: {
      attestation_count: ev.attestation_count,
      tier_distribution: ev.tier_distribution,
      most_recent_attestation_at: ev.most_recent_attestation_at,
      dispute_count: ev.dispute_count,
      context_breakdown: ev.context_breakdown ?? {},
      verascore_linked: ev.verascore_linked,
    },
    layer_score,
    active_degradations: degradations.map((d) => ({
      code: d.code,
      severity: d.severity,
      description: d.description,
      ...(d.mitigation !== undefined ? { mitigation: d.mitigation } : {}),
    })),
  };
}

function computeOverall(
  l1: CognitiveStatus,
  l2: OperationalStatus,
  l3: DisclosureStatus,
  l4: ReputationStatus
): ProtectionSnapshot["overall"] {
  const critical: LayerState[] = [l1.state, l3.state, l4.state];
  if (
    critical.includes("compromised") ||
    l2.state === "compromised"
  ) {
    return {
      status: "compromised",
      light: "red",
      headline: "Sovereignty compromised",
    };
  }
  const allCriticalFull = critical.every((s) => s === "full");
  if (allCriticalFull && l2.state === "full") {
    return {
      status: "healthy",
      light: "green",
      headline: "All layers full",
    };
  }
  if (allCriticalFull && l2.state === "degraded") {
    return {
      status: "healthy",
      light: "green",
      headline: "L1·L3·L4 full — L2 degraded (no TEE on this host)",
    };
  }
  return {
    status: "degraded",
    light: "yellow",
    headline: "One or more layers degraded",
  };
}

function buildUpstreamServers(
  sources: AggregatorSources
): UpstreamServerStatus[] {
  if (!sources.clientManager) return [];
  return sources.clientManager.getStatus().map((s) => {
    const entry: UpstreamServerStatus = {
      name: s.name,
      state: s.state,
      tool_count: s.tool_count,
    };
    if (s.error) entry.error = s.error;
    return entry;
  });
}

function buildPrivacySummary(audit: AuditEntry[]): PrivacySummary {
  const classes: Record<string, number> = {};
  let filteredEvents = 0;
  let filteredSpans = 0;
  let lastFilteredAt: string | null = null;

  for (const entry of audit) {
    const details = entry.details ?? {};
    const rawFindings = details.privacy_findings;
    const findings = typeof rawFindings === "number" && Number.isFinite(rawFindings)
      ? Math.max(0, rawFindings)
      : 0;
    if (findings <= 0) continue;

    filteredEvents++;
    filteredSpans += findings;
    if (!lastFilteredAt || new Date(entry.timestamp).getTime() > new Date(lastFilteredAt).getTime()) {
      lastFilteredAt = entry.timestamp;
    }

    const rawClasses = details.privacy_classes;
    if (Array.isArray(rawClasses)) {
      for (const rawClass of rawClasses) {
        const key = String(rawClass);
        classes[key] = (classes[key] ?? 0) + 1;
      }
    }
  }

  return {
    filtered_events: filteredEvents,
    filtered_spans: filteredSpans,
    classes,
    last_filtered_at: lastFilteredAt,
  };
}

/**
 * Pull a unified protection snapshot from the injected sources.
 *
 * Any missing source degrades gracefully — standalone mode may have
 * no ClientManager or live activity feed, for example, and the
 * aggregator returns a coherent snapshot with empty arrays rather
 * than throwing.
 */
export async function getProtectionSnapshot(
  sources: AggregatorSources
): Promise<ProtectionSnapshot> {
  let audit: AuditEntry[] = [];
  if (sources.auditLog) {
    try {
      const result = await sources.auditLog.query({ limit: MAX_AUDIT });
      audit = result.entries;
    } catch {
      audit = [];
    }
  }

  const agent = buildAgent(sources);
  const l1 = buildCognitive(sources, audit);
  const l2 = buildOperational(sources);
  const l3 = buildDisclosure(sources, audit);
  const l4 = buildReputation(sources);

  const activity = (sources.activity ?? []).slice(0, MAX_ACTIVITY);
  const pending_approvals = sources.pendingApprovals ?? [];
  const privacy = buildPrivacySummary(audit);
  const upstream_servers = buildUpstreamServers(sources);

  return {
    overall: computeOverall(l1, l2, l3, l4),
    agent,
    layers: { l1, l2, l3, l4 },
    activity,
    pending_approvals,
    audit: audit.slice(-MAX_AUDIT).reverse(),
    privacy,
    upstream_servers,
    mode: sources.mode,
    server_version: sources.server_version,
    generated_at: new Date().toISOString(),
  };
}
