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

import type { AuditLog, AuditEntry } from "../l2-operational/audit-log.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type { ClientManager } from "../proxy/client-manager.js";
import type { BaselineTracker } from "../principal-policy/baseline.js";
import type { PrincipalPolicy } from "../principal-policy/types.js";

export type LayerState = "full" | "degraded" | "compromised";
export type OverallStatus = "healthy" | "degraded" | "compromised";

export interface AgentInfo {
  display_name: string;
  did: string | null;
  did_fingerprint: string | null;
  identity_count: number;
  primary_identity_id: string | null;
}

export interface L1Status {
  label: string;
  state: LayerState;
  headline: string;
  encryption: string;
  injection_blocked_today: number;
  memory_attest_ready: boolean;
}

export interface L2Status {
  label: string;
  state: LayerState;
  headline: string;
  isolation_type: string;
  tee_available: boolean;
  tee_status: string;
  sandbox_status: string;
}

export interface L3Status {
  label: string;
  state: LayerState;
  headline: string;
  did_active: boolean;
  vc_count: number;
  proofs_today: number;
}

export interface L4Status {
  label: string;
  state: LayerState;
  headline: string;
  score: number | null;
  profile_url: string | null;
  claim_cta: string | null;
}

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

export interface ProtectionSnapshot {
  overall: {
    status: OverallStatus;
    light: "green" | "yellow" | "red";
    headline: string;
  };
  agent: AgentInfo;
  layers: {
    l1: L1Status;
    l2: L2Status;
    l3: L3Status;
    l4: L4Status;
  };
  activity: ActivityEntry[];
  pending_approvals: PendingApproval[];
  audit: AuditEntry[];
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

function buildL1(
  sources: AggregatorSources,
  audit: AuditEntry[]
): L1Status {
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

function buildL2(sources: AggregatorSources): L2Status {
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

function buildL3(
  sources: AggregatorSources,
  audit: AuditEntry[]
): L3Status {
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

function buildL4(sources: AggregatorSources): L4Status {
  const rep = sources.reputation;
  const hasDid = !!sources.identityManager?.getDefault()?.did;
  if (rep?.score != null) {
    return {
      label: "L4 Reputation",
      state: "full",
      headline: "Verascore attached",
      score: rep.score,
      profile_url: rep.profile_url,
      claim_cta: null,
    };
  }
  if (hasDid) {
    return {
      label: "L4 Reputation",
      state: "degraded",
      headline: "Claim your profile",
      score: null,
      profile_url: null,
      claim_cta: "Claim your profile at verascore.ai",
    };
  }
  return {
    label: "L4 Reputation",
    state: "degraded",
    headline: "No identity claimed",
    score: null,
    profile_url: null,
    claim_cta: "Claim your profile at verascore.ai",
  };
}

function computeOverall(
  l1: L1Status,
  l2: L2Status,
  l3: L3Status,
  l4: L4Status
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
  const l1 = buildL1(sources, audit);
  const l2 = buildL2(sources);
  const l3 = buildL3(sources, audit);
  const l4 = buildL4(sources);

  const activity = (sources.activity ?? []).slice(0, MAX_ACTIVITY);
  const pending_approvals = sources.pendingApprovals ?? [];
  const upstream_servers = buildUpstreamServers(sources);

  return {
    overall: computeOverall(l1, l2, l3, l4),
    agent,
    layers: { l1, l2, l3, l4 },
    activity,
    pending_approvals,
    audit: audit.slice(-MAX_AUDIT).reverse(),
    upstream_servers,
    mode: sources.mode,
    server_version: sources.server_version,
    generated_at: new Date().toISOString(),
  };
}
