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

import {
  auditChainVerdictUntampered,
  type AuditLog,
  type AuditEntry,
} from "../operational/audit-log.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { ClientManager } from "../proxy/client-manager.js";
import type { BaselineTracker } from "../principal-policy/baseline.js";
import type { PrincipalPolicy } from "../principal-policy/types.js";
import {
  buildCastleWallPosture,
  type CastleWallArmState,
} from "../principal-policy/posture.js";
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
  /**
   * The reader's pinned producer public key (base64url-no-pad), resolved lazily
   * so post-provision wiring is observed. Threaded straight into
   * `buildCastleWallPosture` so the dashboard hero shield arms on the SAME
   * cryptographic basis as `/v1` G4 (posture-routes). When it returns null
   * (macOS today / pre-provision) the wall reader falls back to the honest
   * channel-authenticated basis, never claimed as per-producer authenticated.
   *
   * The HIGH never-overclaim fix this closes: without this, a key-bearing host
   * read the wall posture on the channel basis, so a forged marker-only audit
   * entry (an in-process writer that stamped `cw_source` but could not sign)
   * would arm the shield green. With the key present, the reader re-verifies the
   * producer signature and a forgery fails closed to amber. The dashboard MUST
   * supply the same key the consumer wrote with, never a weaker basis.
   */
  resolvePinnedProducerKey?: () => string | null;
  /**
   * Slice P fail-honest signal: a producer key is EXPECTED for this fortress (the
   * daemon published one) but the dashboard could NOT load it (present but
   * unreadable / malformed). When true the wall reader refuses to render green on
   * the channel basis (the posture forces `degraded`, not armed), so the hero
   * shield goes amber rather than claiming a weaker basis than the consumer wrote
   * with. Mutually exclusive with a non-null `resolvePinnedProducerKey()`.
   */
  producerKeyExpectedButUnavailable?: boolean;
  /** Pinned public key for the broker daemon liveness producer. */
  resolveBrokerPinnedProducerKey?: () => string | null;
  /** Broker liveness producer key exists or is expected but could not be read. */
  brokerProducerKeyExpectedButUnavailable?: boolean;
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

/**
 * Window for treating an L2 gate-adjudication audit entry as evidence the
 * Principal Policy gate is live. The dashboard re-aggregates on operator view
 * (not a tight poll), so a 15-minute window keeps a genuinely-busy gate reading
 * "active" between glances without letting a long-idle (or dead) gate keep the
 * "active" claim indefinitely. Idle-but-loaded falls back to "configured",
 * which is still honest.
 */
const GATE_ADJUDICATION_WINDOW_MS = 15 * 60 * 1000;

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
  audit: AuditEntry[],
  /**
   * True only when a live audit chain was read AND verified clean this snapshot.
   * "State encrypted at rest" is an enforcement claim (the namespaces are
   * encrypted and the tamper-evident chain confirms it); we may assert it only
   * with live integrity evidence. Absent that (no audit log wired, or a read that
   * could not confirm the chain) we downgrade to the honest "Encryption
   * configured" (the crypto is set up, but nothing live confirms it right now).
   */
  hasLiveIntegrityEvidence: boolean
): CognitiveStatus {
  const hasIdentity = !!sources.identityManager?.getDefault();
  const state: LayerState = hasIdentity ? "full" : "degraded";
  let headline: string;
  if (!hasIdentity) {
    headline = "No sovereign identity — run sanctuary_bootstrap";
  } else if (hasLiveIntegrityEvidence) {
    headline = "State encrypted at rest";
  } else {
    headline = "Encryption configured (no live integrity check)";
  }
  // `memory_attest_ready` claims the memory-attestation path can actually
  // produce a verifiable attestation, not merely that an identity exists. A
  // bare identity with no live audit chain cannot anchor an attestation, so we
  // gate on the SAME live-integrity evidence that earns the "encrypted at rest"
  // claim: a signing identity AND an audit chain that was read and verified
  // clean this snapshot. Absent that, the honest answer is "not ready".
  const memoryAttestReady = hasIdentity && hasLiveIntegrityEvidence;
  return {
    label: "L1 Cognitive",
    state,
    headline,
    encryption: "AES-256-GCM + HKDF per namespace",
    injection_blocked_today: countInjectionsToday(audit),
    memory_attest_ready: memoryAttestReady,
  };
}

/**
 * Recent L2 (Principal Policy gate) adjudication evidence. The gate writes
 * `layer: "l2"` audit entries with a `gate_*` operation every time it actually
 * adjudicates an operation (`gate_allow`, `gate_deny`, `gate_injection_block`,
 * `gate_allow_proxy`, `gate_unclassified`, `gate_approval_proof`, etc.). A
 * recent such entry is positive evidence the gate is not just loaded but live
 * and adjudicating.
 *
 * Not every `layer: "l2"` entry is an adjudication: boot-time custody/rollback
 * envelope writes (e.g. `custody_rollback_suspected`) and `principal_policy_view`
 * (a policy *read*, not an enforcement decision) also carry `layer: "l2"`.
 * Counting those as adjudications would flip an unexercised or merely-viewed
 * policy to "active", overclaiming enforcement. We therefore require the
 * `gate_` operation prefix that only genuine gate decisions emit.
 */
function hasRecentGateAdjudication(audit: AuditEntry[]): boolean {
  const cutoff = Date.now() - GATE_ADJUDICATION_WINDOW_MS;
  return audit.some((e) => {
    if (e.layer !== "l2") return false;
    if (!e.operation?.startsWith("gate_")) return false;
    const ts = new Date(e.timestamp).getTime();
    return !isNaN(ts) && ts >= cutoff;
  });
}

function buildOperational(
  sources: AggregatorSources,
  audit: AuditEntry[]
): OperationalStatus {
  const teeAvailable = sources.teeAvailable ?? false;
  const state: LayerState = teeAvailable ? "full" : "degraded";
  // `sandbox_status` previously read the literal "Principal Policy gate active"
  // unconditionally, even when no policy was loaded. "Active" is an enforcement
  // claim (the gate is live and adjudicating); a loaded config alone earns only
  // "configured", and the absence of a policy must read as exactly that. We
  // reserve "active" for observed adjudication evidence (a recent L2 audit
  // entry), report "configured" when a policy is loaded but unexercised, and
  // "No Principal Policy loaded" when nothing gates operations.
  let sandbox_status: string;
  if (!sources.policy) {
    sandbox_status = "No Principal Policy loaded";
  } else if (hasRecentGateAdjudication(audit)) {
    sandbox_status = "Principal Policy gate active";
  } else {
    sandbox_status = "Principal Policy gate configured (no recent adjudication)";
  }
  return {
    label: "L2 Operational",
    state,
    headline: teeAvailable
      ? "Hardware isolation active"
      : "Process isolation — no TEE on this host",
    isolation_type: teeAvailable ? "hardware-tee" : "process-level",
    tee_available: teeAvailable,
    tee_status: teeAvailable ? "Attested" : "Not available — normal on local dev",
    sandbox_status,
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
  l4: ReputationStatus,
  enforcement: { wallArmState: CastleWallArmState; auditIntegrityOk: boolean }
): ProtectionSnapshot["overall"] {
  // Fail closed on a tamper-flagged or unreadable audit chain: the evidence the
  // overall light would be judged from is itself untrustworthy, so it can never
  // render green (mirrors posture.ts chain_verified gating).
  if (!enforcement.auditIntegrityOk) {
    return {
      status: "compromised",
      light: "red",
      headline: "Audit chain integrity check failed",
    };
  }
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
  const wallArmed = enforcement.wallArmState === "armed";

  // GREEN requires the ENFORCING layer to be proven armed, not just the
  // config-present layers (identity / DID / Verascore). A wall that is dead,
  // not-enforcing, or never wired keeps the overall light amber even when the
  // configured layers are all present. Never fake green: a green shield asserts
  // the agent is being enforced, which the configured layers alone do not prove.
  if (allCriticalFull && wallArmed && (l2.state === "full" || l2.state === "degraded")) {
    return {
      status: "healthy",
      light: "green",
      headline:
        l2.state === "full"
          ? "All layers full, Castle Wall enforcing"
          : "Castle Wall enforcing, L2 degraded (no TEE on this host)",
    };
  }
  if (allCriticalFull && !wallArmed) {
    // The configured layers are present but enforcement is not confirmed. The
    // honest amber: identity/disclosure/reputation are set up, but the one
    // enforcing layer is not proving it is on.
    return {
      status: "degraded",
      light: "yellow",
      headline: castleWallNotEnforcingHeadline(enforcement.wallArmState),
    };
  }
  return {
    status: "degraded",
    light: "yellow",
    headline: "One or more layers degraded",
  };
}

/** Honest headline for the configured-but-enforcement-not-confirmed amber. */
function castleWallNotEnforcingHeadline(arm: CastleWallArmState): string {
  switch (arm) {
    case "degraded":
      return "Layers configured, Castle Wall degraded (not enforcing)";
    case "not_installed":
      return "Layers configured, Castle Wall not installed on this host";
    default:
      return "Layers configured, Castle Wall enforcement not confirmed";
  }
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
  // A tamper-flagged or unreadable audit chain must NEVER let the rollup render
  // green: the evidence the overall light is judged from would itself be
  // untrustworthy. Track integrity here and fail closed in computeOverall.
  let auditIntegrityOk = true;
  // POSITIVE integrity evidence: a live audit chain was read AND its
  // integrity_findings came back present-and-empty THIS snapshot. Unlike
  // `auditIntegrityOk` (which defaults true so the overall light is not falsely
  // red with no audit log), this defaults FALSE and is earned only by a clean
  // live read; it gates the L1 "State encrypted at rest" enforcement claim,
  // which must never be asserted from config-presence alone (never-overclaim).
  let hasLiveIntegrityEvidence = false;
  if (sources.auditLog) {
    // Local binding so the eager-scope closure keeps the AuditLog type (and the
    // `.query` receiver terminal name stays `auditLog`, which the agent-audit
    // STRUCTURE TRIPWIRE auto-discovers + classifies this OPERATOR read under).
    const auditLog = sources.auditLog;
    try {
      // EAGER SCOPE (snapshot audit listing): this is the operator-facing rollup,
      // the SAME always-on posture surface the hero-shield arm read below already
      // wraps in the #717/#719 eager scope. This `query({ limit: MAX_AUDIT })` is
      // the snapshot's OTHER full-chain read: outside the eager scope it re-reads,
      // re-decrypts, re-hashes and chain-walks every surviving entry from disk on
      // EVERY snapshot poll (11-30s on a real 10k-entry chain, the #714 wedge), so
      // the snapshot stayed only half-bounded after #719. Run it on the
      // eagerly-maintained verified view so a poll on a 10k-entry chain is
      // bounded-cost (O(1)) instead of a full-chain re-verify per request. The
      // result shape, filtering, the `MAX_AUDIT` limit, and what entries are
      // returned are UNCHANGED: only WHERE the read runs changes. Honesty is
      // unchanged: the eager view reflects every server-written entry with NO lag,
      // `integrity_findings` is returned identically (the same `this.integrityFindings`
      // array), so `auditIntegrityOk` / `hasLiveIntegrityEvidence` are derived from
      // the same evidence, and the #717 fingerprint sentinel plus throttled backstop
      // catch out-of-band tampering. PER-TENANT SAFE: `runEagerReads` opens an
      // AsyncLocalStorage scope around THIS specific AuditLog instance's `query`,
      // which reads that instance's own in-memory verified view; a different tenant's
      // snapshot passes its own `sources.auditLog`, so there is no shared mutable
      // state and no cross-tenant read. This is an OPERATOR snapshot read only; the
      // agent-facing `query` callers and `/api/posture/evidence` keep their
      // per-request on-disk re-verification (they never open this scope).
      const result = await auditLog.runEagerReads(() =>
        auditLog.query({ limit: MAX_AUDIT }),
      );
      audit = result.entries;
      // BLOCKER-1 (round 3): the overall-light integrity gate must reflect the
      // sealed-region verdict (the routine query skips sealed content). Run the
      // shared verdict (inside the same eager-read scope) and use the UNTAMPERED
      // collapse: red/compromised only on active tamper, not on an armed box's
      // unreadable sealed history. `hasLiveIntegrityEvidence` still requires a
      // real, present findings array (a non-conforming stub earns nothing).
      const verdict = await auditLog.runEagerReads(() =>
        auditLog.getAuditChainVerdict(),
      );
      auditIntegrityOk = auditChainVerdictUntampered(verdict);
      hasLiveIntegrityEvidence =
        Array.isArray(result.integrity_findings) &&
        auditChainVerdictUntampered(verdict);
    } catch {
      audit = [];
      auditIntegrityOk = false;
      hasLiveIntegrityEvidence = false;
    }
  }

  const agent = buildAgent(sources);
  const l1 = buildCognitive(sources, audit, hasLiveIntegrityEvidence);
  const l2 = buildOperational(sources, audit);
  const l3 = buildDisclosure(sources, audit);
  const l4 = buildReputation(sources);

  // Castle Wall is the one ENFORCING layer (the thesis-gate). The overall light
  // must never claim a healthy, enforced posture from the config-present layers
  // (identity/DID/Verascore) alone while the wall is dead, not-enforcing, or
  // never wired. Reuse the honest, enforcement-evidenced posture reader (the
  // SAME signal posture-routes serves at /v1 G4) rather than a second copy.
  // The producer-key state is threaded straight into the posture reader so the
  // hero shield arms on the SAME cryptographic basis as /v1 G4: a key-bearing
  // host re-verifies the producer signature (a forged marker-only entry fails
  // closed to amber), and an expected-but-unreadable key forces non-green rather
  // than silently dropping to the weaker channel basis. Mirrors the
  // posture-routes / dispatchPosture wiring.
  let wallArmState: CastleWallArmState = "unknown";
  if (sources.auditLog) {
    try {
      const pinnedProducerKeyB64url = sources.resolvePinnedProducerKey
        ? sources.resolvePinnedProducerKey()
        : null;
      // EAGER SCOPE (hero-shield arm badge): the snapshot is the operator-facing
      // rollup; this is the SAME enforcement-evidenced arm-state the
      // `/api/posture/castle-wall` route serves and #717 already wraps. Run the
      // shaper's audit read on the eagerly-maintained verified view so a snapshot
      // poll on a 10k-entry chain is bounded-cost (O(1)) instead of an 11-30s
      // full-chain re-verify per request. PER-TENANT SAFE: `runEagerReads` opens
      // an AsyncLocalStorage scope around THIS specific AuditLog instance's call
      // and the shaper's `query` reads that instance's own in-memory verified
      // view (`this.entries`); a different tenant's snapshot passes its own
      // `sources.auditLog`, so there is no shared mutable state and no
      // cross-tenant read. Honesty is unchanged: the eager view reflects every
      // server-written entry with NO lag, the #717 fingerprint sentinel plus
      // throttled backstop catch out-of-band tampering, and the shaper's
      // freshness/evidence gating (unknown / degraded, never armed without fresh
      // verified evidence) is untouched: only WHERE its `query` runs changes.
      const wall = await sources.auditLog.runEagerReads(() =>
        buildCastleWallPosture({
          auditLog: sources.auditLog as AuditLog,
          originMachine: agent.primary_identity_id ?? "local",
          pinnedProducerKeyB64url,
          ...(sources.producerKeyExpectedButUnavailable
            ? { producerKeyExpectedButUnavailable: true }
            : {}),
        }),
      );
      wallArmState = wall.arm_state;
    } catch {
      wallArmState = "unknown";
    }
  }

  const activity = (sources.activity ?? []).slice(0, MAX_ACTIVITY);
  const pending_approvals = sources.pendingApprovals ?? [];
  const privacy = buildPrivacySummary(audit);
  const upstream_servers = buildUpstreamServers(sources);

  return {
    overall: computeOverall(l1, l2, l3, l4, { wallArmState, auditIntegrityOk }),
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
