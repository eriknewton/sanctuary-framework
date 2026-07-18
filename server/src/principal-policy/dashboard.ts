/**
 * Sanctuary MCP Server - Principal Dashboard
 *
 * HTTP-based approval channel that serves a real-time web dashboard
 * for human principals to approve/deny agent operations.
 *
 * Architecture:
 * - Node.js built-in `http`/`https` modules (no Express or external deps)
 * - SSE (Server-Sent Events) for real-time push to browser
 * - Pending approval requests block the MCP tool call via Promise
 * - Human clicks approve/deny in browser → POST /api/approve/:id → Promise resolves
 * - Timeout fallback: auto-deny (or auto-approve) if no response
 *
 * Security invariants:
 * - Binds to 127.0.0.1 by default (localhost only)
 * - Optional bearer token authentication for non-localhost deployments
 * - Optional TLS (HTTPS) via cert/key paths
 * - All decisions are audit-logged
 * - Agent cannot access the dashboard (it runs outside MCP stdin/stdout)
 */

import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { exec } from "node:child_process";
import { platform } from "node:os";
import {
  loadFortressProducerKey,
  type ProducerKeyLoad,
  type ProducerKeyLoadOptions,
} from "../castle-wall/runtime/producer-signature.js";
import {
  loadBrokerProducerKey,
  type BrokerProducerKeyLoad,
} from "../broker-mcp/producer-signature.js";
import { SANCTUARY_VERSION as PKG_VERSION } from "../config.js";
import type { SanctuaryConfig } from "../config.js";
import type { ApprovalChannel } from "./approval-channel.js";
import type { ApprovalRequest, ApprovalResponse, PrincipalPolicy } from "./types.js";
import type { BaselineTracker } from "./baseline.js";
import type {
  AuditLog,
  AuditEntry,
  AuditIntegrityFinding,
  AuditIntegrityFindingKind,
} from "../operational/audit-log.js";
import { AuditIntegrityError } from "../operational/audit-log.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { HandshakeResult } from "../handshake/types.js";
// SignedSHR type available via shr/types if needed in future
import { generateSHR, type SHRGeneratorOptions } from "../shr/generator.js";
import { gatherReputationEvidence } from "../shr/tools.js";
import { ReputationStore } from "../reputation/reputation-store.js";
import type { StorageBackend } from "../storage/interface.js";
import type { RecognitionReputationEvidence } from "./posture.js";
import { generateDashboardHTML, generateLoginHTML, generateFleetSwitcherHTML } from "./dashboard-html.js";
import { generateFortressViewHTML } from "../wrap/fortress-view.js";
import type { SovereigntyProfileStore, SovereigntyProfileUpdate, UpstreamServer } from "../sovereignty-profile.js";
import { generateSystemPrompt } from "../system-prompt-generator.js";
import type { ClientManager } from "../proxy/client-manager.js";
import { dispatchV11Request } from "../dashboard/v1_1/dispatch.js";
import type { V11Bindings } from "../dashboard/v1_1/wiring.js";
import { getProcessInstance, getProcessSince } from "../dashboard/process-identity.js";
import {
  getProtectionSnapshot,
  type AggregatorSources,
} from "../dashboard/aggregator.js";
import { constantTimeEquals } from "../http/auth.js";
import { logCaughtError } from "../http/error-envelope.js";
import { V1SessionService } from "../v1/session-service.js";
import { handleV1Request } from "../v1/router.js";
import { denyForbidden } from "../v1/http.js";
import {
  handlePostureRoute,
  POSTURE_API_PREFIX,
  POSTURE_HOME_PATH,
  POSTURE_AGENT_PATH_PREFIX,
  POSTURE_EVIDENCE_PATH,
  POSTURE_STREAM_PATH,
  type PostureRouteDeps,
} from "./posture-routes.js";
import { renderPostureHomeHTML } from "./posture-home-html.js";
import { buildFleetRoster } from "./fleet-roster.js";
import {
  applyFleetCap,
  resolveActivation,
  activateFleet,
  decodeIssuerPublicKey,
  readFleetActivation,
  resolveEntitlement,
  COMMUNITY_FREE_NODE_CAP,
  isLicenseRevoked,
  revocationVerifiability,
  persistPushedRevocationListSerialized,
  readDowngradeLog,
  runFleetReResolve,
  resolveFleetCap as resolveFleetCapPure,
  computeFleetCapacityView,
  type FleetCap,
  type ActivateFleetResult,
  type PriorCapState,
  type ReResolveRosterView,
  type FleetCapacityView,
} from "../entitlement/index.js";
import {
  buildCastleWallPosture,
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
  mapPlatform,
  failedExclusiveEgressStatus,
  type CastleWallPosture,
  type ExclusiveEgressStatus,
} from "./posture.js";
import {
  createPostureStreamRegistry,
  type PostureStreamRegistry,
} from "./posture-stream.js";
import { buildFeatureHealthPanel } from "./feature-health.js";
import { FeatureFaultRaiser } from "./feature-fault-raise.js";
import { QUERY_ANONYMITY_API_PREFIX } from "../query-anonymity/query-anonymity-routes.js";
import { PII_REWRITE_API_PREFIX } from "../query-anonymity/pii-rewrite-routes.js";
import { resolveCompositionConfig } from "../composition/composition-config.js";
import {
  V1IdempotencyStore,
  type V1AgentsDeps,
  type UnprotectOutcome,
  type ProtectLaunchOutcome,
} from "../v1/agents.js";
import { SupervisorBridge } from "../supervisor/dashboard-bridge.js";
import {
  assertNonIssuerContextHasNoIssuerAuthority,
  federationContextHasIssuerAuthority,
  federationEventHash,
  validateFederationEventHash,
  JoinCeremony,
  type FederationAppendOptions,
  type FederationAppendResult,
  type FederationContext,
  type FederationEvent,
  type FederationNodeView,
  type FederationPostureSummary,
  type FederationSyncCursor,
  type V1FederationDeps,
} from "../v1/federation.js";
import type { NodeMode } from "../mesh/constants.js";
import type { BootstrapToken } from "../mesh/lifecycle/types.js";
import {
  deriveNodePosture,
  NODE_TRUST_BOUNDARY_VERSION,
  OPERATOR_CLOUD_DISCLOSURE,
  type NodeModeForPosture,
} from "../mesh/node-posture.js";
import {
  acceptFederationEventsFailClosed,
  FEDERATION_NODE_EVICTION_EVENT_KIND,
  federationOperatorAuthorityOrigin,
  foldAcceptedFederationNodeEvictionEvent,
  foldFederationNodeEvictionEvent,
  isFederationOperatorAuthorityEvent,
  renewNodeIdentityCertificateIfDue,
  startFederationNodeCertificateAutoRenewal,
  type FederationNodeCertificateAutoRenewalHandle,
} from "../v1/federation-revocation.js";
import {
  effectiveThresholdM,
  type GuardianRevocationRequirement,
} from "../v1/federation-revocation-guardian-gate.js";
import { verifyGuardianRoster } from "../mesh/guardian/guardian-roster.js";
import {
  computeBreakGlassCompletion,
  breakGlassElapsed,
  DEFAULT_BREAK_GLASS_DELAY_MS,
  evaluateGuardianBreakGlassVeto,
  authorizeGuardianRequirementTransition,
  verifyLoweredThresholdAuthorization,
  type BreakGlassState,
  type BreakGlassVetoDecision,
  type GuardianDisableAuthorization,
  type GuardianRequirementState,
  type GuardianRequirementTransition,
  type GuardianRequirementEffect,
} from "../v1/federation-guardian-disable-gate.js";
import {
  FEDERATION_POLICY_BUNDLE_EVENT_KIND,
  foldFederationPolicyBundleEvent as foldVerifiedFederationPolicyBundleEvent,
  type FederationAppliedPolicyVersion,
  type FederationPolicyProjection,
} from "../v1/federation-policy-bundle.js";
import {
  FederationSyncStateStore,
  type FederationSyncStateSnapshot,
} from "../v1/federation-sync-state-store.js";
import { FederationReissueChallengeStore } from "../v1/federation-reissue-challenge-store.js";
import { HubNotFoundError, HubCapabilityError } from "../hub/errors.js";
import { fromBase64url } from "../core/encoding.js";
import type { ApprovalAggregator } from "./approval-aggregator.js";
import {
  APPROVAL_INBOX_API_PREFIX,
  handleApprovalInboxRoute,
} from "./approval-aggregator-routes.js";
import type { SentinelDispatcher } from "../sentinel/sentinel-dispatcher.js";
import {
  SENTINEL_API_PREFIX,
  handleSentinelRoute,
} from "../sentinel/sentinel-routes.js";
import type { DistressInbox } from "../distress/inbox.js";
import {
  DISTRESS_API_PREFIX,
  handleDistressRoute,
} from "../distress/inbox-route.js";
import type { HandoffLog } from "../coordination/handoff-log.js";
import {
  COORDINATION_API_PREFIX,
  type HandoffEventBridge,
  handleCoordinationRoute,
} from "../coordination/handoff-routes.js";
import type { ContextTransferExtractorDeps } from "../coordination/context-transfer-extractor.js";
import type { WorkflowStateTracker } from "../coordination/workflow-state-tracker.js";
import type { TrapRegistry } from "../honeypot/trap-registry.js";
import {
  HONEYPOT_API_PREFIX,
  handleHoneypotRoute,
  handleHoneypotTriggerIfMatch,
} from "../honeypot/runtime-trap-handler.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import {
  AUTO_TRIGGER_API_PREFIX,
  handleAutoTriggerRoute,
} from "../auto-trigger/auto-trigger-routes.js";
import type { ThresholdConfigStore } from "../auto-trigger/threshold-config-store.js";
import type { ActionDispatcher } from "../auto-trigger/action-dispatcher.js";
import type { CalibrationSuggester } from "../auto-trigger/calibration-suggester.js";
import type { UnifiedInboxBridge } from "./unified-inbox-bridge.js";
import {
  handleUnifiedInboxRoute,
  UNIFIED_INBOX_API_PREFIX,
  UNIFIED_INBOX_RETENTION_API_PREFIX,
} from "./unified-inbox-routes.js";
import type { UnifiedInboxPrefsStore } from "./unified-inbox-prefs-store.js";
import {
  UnifiedInboxRetentionPolicy,
  type UnifiedInboxRetentionPolicyStore,
} from "./unified-inbox-retention-policy.js";

// ── Types ───────────────────────────────────────────────────────────────

export interface DashboardConfig {
  port: number;
  host: string;
  timeout_seconds: number;
  /** SEC-002: auto_deny is always true. Field retained for interface compat but ignored. */
  auto_deny?: boolean;
  /** Bearer token for API authentication. If omitted, auth is disabled. */
  auth_token?: string;
  /** TLS configuration for HTTPS. If omitted, plain HTTP is used. */
  tls?: {
    cert_path: string;
    key_path: string;
  };
  /** Auto-open the dashboard in the default browser on startup. Default: true for localhost. */
  auto_open?: boolean;
  /**
   * C1: Allow plaintext HTTP on non-loopback interfaces. Default: false.
   * When false (default), non-loopback binding requires TLS. Set to true
   * ONLY for tailnet or other encrypted-transport environments where the
   * network layer already provides encryption.
   */
  allow_plaintext_remote?: boolean;
  /** Optional producer-key loader overrides. Tests pin platform/path here. */
  producer_key_load_options?: ProducerKeyLoadOptions;
}

interface PendingRequest {
  id: string;
  request: ApprovalRequest;
  resolve: (response: ApprovalResponse) => void;
  timer: ReturnType<typeof setTimeout>;
  created_at: string;
}

/**
 * Slice 2 (park-not-exit): the credential an operator presents to the
 * in-process unlock endpoint to lift a parked dashboard out of "locked" and
 * into "serving". Exactly one of `passphrase` / `recoveryKey` is supplied; the
 * unlock handler forwards it to `establishMaster` unchanged. NEVER persisted,
 * NEVER logged, NEVER echoed back.
 */
export type UnlockCredential =
  | { passphrase: string }
  | { recoveryKey: string };

type SSEClient = ServerResponse;

/**
 * F1 E1: poll interval for the guardian-requirement break-glass countdown.
 * There is no durable OS-level scheduler in this codebase; this mirrors the
 * node-certificate auto-renewal poll's role - it only ever DELAYS completion
 * past the durable `completesAt`, never shortens it. One hour keeps the
 * `..._tick` audit heartbeat frequent enough to prove the countdown stayed
 * continuously live without flooding the audit log over a 72h window.
 */
const FEDERATION_BREAK_GLASS_POLL_INTERVAL_MS = 60 * 60 * 1000;

/**
 * F1 E1: thrown when the guardian-requirement disable-gate refuses a
 * decrease (disable/lower) or a break-glass state transition. Carries a
 * machine-readable `code` and a human `detail`; NEVER leaks which
 * signature/nonce/roster field specifically failed beyond what the caller
 * itself supplied (fail-closed, generic-enough deny per AGENTS.md 7's spirit
 * for this operator-facing - not agent-facing - surface).
 */
export class GuardianDisableGateRefusedError extends Error {
  readonly code: string;
  constructor(code: string, detail: string) {
    super(detail);
    this.name = "GuardianDisableGateRefusedError";
    this.code = code;
  }
}

// ── Dashboard Approval Channel ──────────────────────────────────────────

// ── Session Store ────────────────────────────────────────────────────
// Short-lived sessions replace the long-lived auth token in URLs (SEC-012).

interface DashboardSession {
  id: string;
  created_at: number;
  expires_at: number;
}

const SESSION_TTL_REMOTE_MS = 5 * 60 * 1000;  // 5 minutes for remote/TLS
const SESSION_TTL_LOCAL_MS = 24 * 60 * 60 * 1000; // 24 hours for localhost
const MAX_SESSIONS = 1000;

// ── Rate Limiting ───────────────────────────────────────────────────
// Sliding-window rate limiting per remote address.
// Decision endpoints (approve/deny) have a tighter limit than general API.

const RATE_LIMIT_WINDOW_MS = 60_000; // 1-minute window
const RATE_LIMIT_GENERAL = 120;       // max general API requests per window
const RATE_LIMIT_DECISIONS = 20;      // max approve/deny decisions per window
// Federation P1: dedicated bucket for the pre-session, node-cert-authenticated
// `/v1/federation/sync/peer` route. Each request triggers one cryptographic
// envelope verification, so the budget is tighter than the general bucket and
// (unlike the dashboard buckets) does NOT exempt loopback: a remote peer can
// arrive via a loopback-presenting transport (a tunnel), so a loopback exemption
// would let such a peer flood the verify path unthrottled, and the exemption is
// itself a probing asymmetry. See checkRateLimit's `exemptLoopback` flag.
const RATE_LIMIT_FEDERATION_PEER = 60; // max peer-sync attempts per window per /64
const MAX_RATE_LIMIT_ENTRIES = 10_000; // cap the tracking map to prevent memory exhaustion
// Federation P1 DoS hardening: a global ceiling on concurrent in-flight
// crypto-verify (envelope verification) on the unauthenticated peer-sync route,
// so an unauthenticated flood cannot exhaust CPU faster than the per-/64 rate
// limit alone would bound it. Over-ceiling requests get the SAME generic
// rejection as a verify failure (no distinguishable error → no oracle).
const MAX_CONCURRENT_PEER_VERIFY = 16;

type RateLimitClass = "general" | "decisions" | "federation_peer";

interface RateLimitEntry {
  general: number[];        // timestamps of general requests
  decisions: number[];      // timestamps of decision requests
  federation_peer: number[]; // timestamps of federation peer-sync requests
}

/**
 * Federation P1 DoS hardening: return the /64 prefix key for an IPv6 address, or
 * null when the input is not an IPv6 literal (IPv4 / "unknown" / already a mapped
 * IPv4 normalized upstream). A /64 is the smallest IPv6 block a host is normally
 * delegated, so an attacker rotating source addresses within their /64 must share
 * one rate-limit bucket. We take the first four hextets after expanding any single
 * `::` zero-run. Keyed as `"<h0>:<h1>:<h2>:<h3>::/64"` so it can never collide
 * with a verbatim address key. Conservative: any parse ambiguity returns null so
 * the caller falls back to the exact-address key (fail safe; never wider than the
 * input intended).
 */
export function ipv6Slash64Prefix(addr: string): string | null {
  // Reject anything without a colon (IPv4 / "unknown") and zone ids / ports.
  if (!addr.includes(":")) return null;
  if (addr.includes("%") || addr.includes("/")) return null;
  // An IPv4-mapped form (::ffff:1.2.3.4) is an IPv4 address; do not /64 it.
  if (addr.includes(".")) return null;
  const doubleColonCount = (addr.match(/::/g) ?? []).length;
  if (doubleColonCount > 1) return null; // malformed: more than one "::"
  let hextets: string[];
  if (doubleColonCount === 1) {
    const [head, tail] = addr.split("::");
    const headParts = head ? head.split(":") : [];
    const tailParts = tail ? tail.split(":") : [];
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;
    hextets = [...headParts, ...Array<string>(missing).fill("0"), ...tailParts];
  } else {
    hextets = addr.split(":");
  }
  if (hextets.length !== 8) return null;
  // Each hextet must be 1-4 hex digits.
  for (const h of hextets) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
  }
  const prefix = hextets.slice(0, 4).map((h) => h.toLowerCase()).join(":");
  return `${prefix}::/64`;
}

/**
 * Classify a request as an HTML/SSE "view" route that must remain unthrottled.
 * Operator page loads, refreshes, and the single long-lived SSE stream are
 * exempt from the general rate limit so the dashboard never 429s the user out
 * of their own UI. API endpoints still hit the rate limiter so loops or scrapes
 * are throttled.
 */
export function isDashboardViewRoute(method: string, path: string): boolean {
  if (method !== "GET") return false;
  return (
    path === "/" ||
    path === "/dashboard" ||
    path === "/v1.0" ||
    path === "/fortress" ||
    path === "/fleet" ||
    path === "/events" ||
    path === POSTURE_HOME_PATH ||
    // The posture SSE live-refresh stream is a single long-lived connection per
    // operator tab, exactly like the v1.0 `/events` stream. It must be exempt
    // from the per-IP general rate limit so a normal reconnect (after a laptop
    // sleep, say) does not 429 the operator out of their own live board. The
    // stream handler enforces its OWN bound: a concurrency cap on open streams.
    path === POSTURE_STREAM_PATH ||
    // The per-agent drill-down HTML page is a dashboard view route too (an
    // operator page load), so it is exempt from the general rate limit the
    // same way `/posture` and `/fortress` are. Its data fetches still hit the
    // throttled JSON endpoints.
    path.startsWith(POSTURE_AGENT_PATH_PREFIX) ||
    // The Evidence View HTML shell is a dashboard view route: an operator page
    // load that loads the filterable audit table. Its data fetch (`GET
    // /api/posture/evidence`) still hits the throttled JSON endpoints.
    path === POSTURE_EVIDENCE_PATH
  );
}

/**
 * READ-STYLE EXEMPT SET for the legacy dispatcher's default-deny mutation gate.
 *
 * The gate in {@link DashboardApprovalChannel.handleLegacyRequest} is
 * DEFAULT-DENY: every non-GET method requires the operator bearer
 * (`requireToken: true`), exactly like the v1.1 routers. This set is the SMALL,
 * EXPLICIT exception — non-GET routes that genuinely neither persist nor mutate
 * nor leak state, kept loopback/session-readable for local convenience.
 *
 *   - POST `/api/query-anonymity/pii/rewrite` -> a STATELESS preview that runs
 *     the regex redactor over operator-supplied text and returns the scrubbed
 *     result. It persists nothing and exposes no operator/fleet/custody state,
 *     so it stays session-readable so the dashboard's live PII preview works
 *     without a bearer. The PERSISTING sibling
 *     (`PATCH /api/query-anonymity/pii/config`) is NOT exempt — it is gated.
 *
 * Any OTHER non-GET route is gated. Do NOT add a route here unless you can
 * confirm it neither persists nor mutates nor leaks state.
 */
function isDashboardReadStyleNonGet(method: string, path: string): boolean {
  return method === "POST" && path === `${PII_REWRITE_API_PREFIX}/rewrite`;
}

interface FederationDashboardState {
  eventLog: FederationEvent[];
  revoked: Set<string>;
  evictionMaxSerial: number;
  operatorPolicy: FederationAppliedPolicyVersion | null;
  appliedPolicyVersions: Map<string, FederationAppliedPolicyVersion>;
  nodes: Map<string, FederationNodeView>;
}

/**
 * §8.7: the operation-name PREFIX every guardian-requirement audit entry shares.
 * The §8 audit-witnessed floor matches guardian entries by this prefix (plus
 * `result === "success"` and a valid `details.generation`) rather than a
 * hardcoded op-name set, so it structurally witnesses EVERY generation-bumping
 * guardian transition, current and future. A hardcoded set was the round-2
 * coverage gap: it omitted `federation_guardian_break_glass_vetoed` /
 * `_cancelled`, which DO bump + audit the committed generation, re-opening
 * finding #1 via a stale-armed-break-glass restore. The prefix match is
 * drift-proof: a new guardian op-name cannot silently escape the floor.
 */
const GUARDIAN_AUDIT_OP_PREFIX = "federation_guardian_" as const;

/**
 * §8.6 P1: the audit integrity-finding kinds that indicate the audit COVERAGE
 * could be compromised such that a guardian entry might be HIDDEN or a higher
 * generation removed (truncation / structural / anchor / checkpoint classes). A
 * finding of any of these kinds forces the anti-rollback floor to fail TOWARD
 * latch regardless of its sequence, because it can mean the guardian set the
 * floor is derived from is INCOMPLETE. The complement (a single in-place
 * corruption, `entry_hash_mismatch` / `entry_malformed`, strictly BELOW every
 * guardian entry) does NOT compromise guardian coverage, so it does not latch.
 */
const GUARDIAN_AUDIT_COVERAGE_FINDING_KINDS: ReadonlySet<AuditIntegrityFindingKind> =
  new Set<AuditIntegrityFindingKind>([
    "storage_unavailable",
    "entry_unreadable",
    "entry_decrypt_failed",
    "sequence_gap_or_reorder",
    "prev_hash_mismatch",
    "tail_anchor_missing",
    "tail_anchor_invalid",
    "rotation_anchor_missing",
    "rotation_anchor_invalid",
    "legacy_anchor_missing",
    "legacy_anchor_mismatch",
    "checkpoint_malformed",
    "checkpoint_root_mismatch",
    "checkpoint_signature_mismatch",
    "checkpoint_signature_unverifiable",
  ]);

function newerAppliedPolicy(
  base: FederationAppliedPolicyVersion | null,
  next: FederationAppliedPolicyVersion | null,
): FederationAppliedPolicyVersion | null {
  if (!base) return next ? { ...next } : null;
  if (!next) return { ...base };
  return next.version > base.version ? { ...next } : { ...base };
}

function mergeAppliedPolicyVersions(
  base: Map<string, FederationAppliedPolicyVersion>,
  next: Map<string, FederationAppliedPolicyVersion>,
): Map<string, FederationAppliedPolicyVersion> {
  const merged = new Map<string, FederationAppliedPolicyVersion>(
    [...base].map(([nodeId, marker]) => [nodeId, { ...marker }]),
  );
  for (const [nodeId, marker] of next) {
    const prior = merged.get(nodeId);
    if (!prior || marker.version > prior.version) {
      merged.set(nodeId, { ...marker });
    }
  }
  return merged;
}

function appliedPolicyMarkerToNodeView(
  marker: FederationAppliedPolicyVersion,
): FederationNodeView["applied_policy"] {
  return {
    version: marker.version,
    hash: marker.hash,
    hash_algorithm: marker.hash_algorithm,
    applied_at: marker.applied_at,
    source_event_id: marker.source_event_id,
  };
}

/**
 * Fleet control plane, Add-Machine slice: the closed, server-typed result of
 * parsing + validating a `POST /api/fleet/enroll-token` request body. Either a
 * fully validated `{ node_id, node_mode }` pair, or a ready-to-send error
 * response. Keeping the request-body values behind this tagged result lets the
 * enroll handler branch only on the `ok` flag, so no attacker-controlled body
 * value syntactically controls any condition that dominates a mint decision.
 */
type FleetEnrollTokenBodyParse =
  | { ok: true; nodeId: string; nodeMode: NodeMode }
  | { ok: false; status: number; payload: Record<string, string> };

export class DashboardApprovalChannel implements ApprovalChannel {
  private config: DashboardConfig;
  /**
   * Shared active-stream registry for the posture SSE live-refresh endpoint
   * (`/api/posture/stream`). One per server instance so the concurrency cap is
   * enforced across every open stream. Created eagerly (cheap) so the live
   * stream is available as soon as the dashboard serves the posture surface.
   */
  private postureStreamRegistry: PostureStreamRegistry =
    createPostureStreamRegistry();
  private pending: Map<string, PendingRequest> = new Map();
  private sseClients: Set<SSEClient> = new Set();
  private httpServer: ReturnType<typeof createHttpServer> | null = null;
  private policy: PrincipalPolicy | null = null;
  private baseline: BaselineTracker | null = null;
  private auditLog: AuditLog | null = null;
  private identityManager: IdentityManager | null = null;
  private handshakeResults: Map<string, HandshakeResult> | null = null;
  private shrOpts: SHRGeneratorOptions | null = null;
  /**
   * Storage backend, injected for the Recognition panel (P5) so the dashboard
   * can list persisted Concordia-bridge commitments (`storage.list("_bridge")`)
   * and read the local attestation store for reputation EVIDENCE (counts, not a
   * score). Optional: when absent (standalone / un-wired), the Recognition panel
   * falls back to audit-event counts and a `null` (amber) reputation row. Never
   * used to fetch any external reputation score - there is no such path.
   */
  private storage: StorageBackend | null = null;
  private _sanctuaryConfig: SanctuaryConfig | null = null;
  private profileStore: SovereigntyProfileStore | null = null;
  private clientManager: ClientManager | null = null;
  /**
   * Cached read-side producer-key load result (Slice R + Slice P). `undefined` =
   * not yet loaded; otherwise a three-state {@link ProducerKeyLoad}:
   *   - `present`    → the loaded base64url key (cached permanently; the pinned
   *                    anchor is stable for a fortress).
   *   - `absent`     → no key file (channel basis, the honest macOS / pre-provision
   *                    default). NOT cached permanently: a later request re-checks
   *                    so a post-provision write is picked up (codex MEDIUM #4).
   *   - `unreadable` → a key is EXPECTED but could not be loaded; the reader fails
   *                    HONESTLY (degraded, never green) rather than dropping to the
   *                    channel basis. Also re-checked next request.
   * Loaded from the SAME canonical path the daemon publishes and the consumer
   * pins (`<storage_path>/policy/egress/audit-producer.pub`, via
   * `loadFortressProducerKey`), so the reader never uses a weaker basis than the
   * consumer wrote with (Slice P single-source contract).
   */
  private _producerKeyLoad: ProducerKeyLoad | undefined = undefined;
  private _brokerProducerKeyLoad: BrokerProducerKeyLoad | undefined = undefined;
  private dashboardHTML: string;
  private fortressHTML: string | null = null;
  private loginHTML: string;
  private authToken: string | undefined;
  private useTLS: boolean;
  /** Session TTL: longer for localhost, shorter for remote */
  private sessionTTLMs: number;
  /** SEC-012: Short-lived session store. Sessions replace URL query tokens. */
  private sessions: Map<string, DashboardSession> = new Map();
  private sessionCleanupTimer: ReturnType<typeof setInterval> | null = null;
  /** Rate limiting: per-IP request tracking */
  private rateLimits: Map<string, RateLimitEntry> = new Map();
  /**
   * Federation P1 DoS hardening: count of in-flight crypto-verify on the
   * unauthenticated `/v1/federation/sync/peer` route. Bounded by
   * MAX_CONCURRENT_PEER_VERIFY so an unauthenticated flood cannot exhaust CPU on
   * envelope verification faster than the per-/64 rate limit alone would bound.
   */
  private inFlightPeerVerify = 0;
  /** Whether the dashboard is running in standalone mode (no MCP server) */
  private _standaloneMode = false;
  /**
   * v0.10.2: when set, requests from loopback addresses (127.0.0.1 / ::1)
   * are treated as authenticated without requiring a Bearer token or
   * dashboard session cookie. Only the `startStandaloneDashboard` boot
   * path enables this, and ONLY after the supplied passphrase successfully
   * decrypts at least one stored identity - proving the caller already
   * holds the primary secret that protects every piece of Sanctuary state.
   *
   * Rationale: the dashboard auth token is a dashboard-access credential
   * layered on top of the master-key unlock. Once the operator has already
   * presented the passphrase on the command line (terminal-side auth), a
   * second login prompt in the auto-opened browser just trains users to
   * paste secrets into web forms - the exact habit Sanctuary exists to
   * discourage. Remote (non-loopback) callers still require the bearer
   * token, so this is a localhost-only ergonomics unlock, not a network
   * policy change.
   *
   * SCOPE LIMIT (loopback-no-autoauth-for-approvals): this unlock covers
   * read-only and local-dashboard convenience routes ONLY. It does NOT
   * cover the human-approval ACTION or operator-state mutation. Every
   * state-changing decision/mutation route always requires the operator
   * bearer token regardless of origin, even on loopback with auto-auth
   * enabled. The covered routes include:
   *   - POST `/api/approve/:id`, POST `/api/deny/:id` (legacy dashboard)
   *   - POST `/api/unlock`, `/api/sovereignty-profile`, `/api/proxy/servers`
   *   - POST `/api/hub/inbox/:id/{approve,deny}` (v1.1 hub inbox)
   *   - POST `/api/approval-inbox/:id/{approve,deny}` (cross-harness)
   *   - POST `/api/inbox/unified/:id/resolve` (unified inbox)
   * In the MCP threat model the wrapped agent is co-resident with the
   * operator and shares the loopback interface, so loopback origin is not
   * a proxy for operator identity; without this carve-out a co-resident
   * agent holding any loopback-HTTP primitive could self-approve its own
   * Tier-1 operation and defeat the human approval gate. The router-level
   * routes opt in via `authMiddleware(..., {requireToken:true})`; the
   * legacy dashboard routes pass `requireToken` to {@link checkAuth}.
   */
  private _autoAuthLocalhost = false;
  /**
   * v1.1 routes (dashboard HTML at /v1.1, hub API at /api/hub/*) are
   * mounted additively when set. `/` is the posture shell; `/dashboard`
   * and `/v1.1` remain v1.1 SPA compatibility aliases.
   */
  private v11Bindings: V11Bindings | null = null;

  /**
   * Federation PR-A1: RFC v7 challenge-response session ceremony +
   * opaque session tokens for the additive `/v1` API surface. Constructed
   * unconditionally - the `/v1` skeleton is always mounted; its auth is
   * fail-closed and independent of the legacy bearer/session model
   * (which it bridges through {@link V1SessionService}'s attestation
   * check, never bypasses).
   */
  private v1Sessions: V1SessionService;

  /**
   * Federation PR-A2: per-channel idempotency cache for the Tier 1 agent
   * write endpoints (/v1/agents/protect|unprotect). One instance for the
   * life of the channel so a retried, validly-signed write returns its
   * first result instead of enqueuing a second approval.
   */
  private v1Idempotency = new V1IdempotencyStore();

  /**
   * Phase S1: split-process supervisor bridge. Set by the standalone process
   * once the supervisor socket path + per-boot auth secret are known (it owns
   * the in-memory master for the transient-key handoff). When null, protect
   * fails closed with 503 `unavailable` - never a silent success, never the
   * old 501 oracle.
   */
  private supervisorBridge: SupervisorBridge | null = null;
  /** S5-P exclusive-egress posture provider (S5-6's arming-wiring producer; null while detached). */
  private _exclusiveEgressPostureProvider:
    | (() => Promise<ExclusiveEgressStatus | null> | ExclusiveEgressStatus | null)
    | null = null;

  /**
   * Slice 2 (park-not-exit): true when this dashboard booted WITHOUT a master
   * key under the supervised LaunchAgent path (`--allow-park`). A parked
   * dashboard binds the listener, answers `/api/health` (`ok:true`), reports
   * `/api/readiness` `ready:"locked"` (the identity manager is absent), serves
   * the unlock door, and serves NO protected state (no master-key-derived deps
   * are constructed). It is flipped to false by a successful in-process unlock.
   * Internal only: the wire contract for readiness stays exactly Slice 1b's
   * `ready:"locked"` whether parked or merely deps-detached.
   */
  private _parked = false;

  /**
   * Slice 2 (park-not-exit): the in-process unlock handler. Set by the
   * standalone boot path (`setUnlockHandler`) when park is enabled. Given an
   * operator-supplied credential, it re-runs the SAME `establishMaster` the
   * boot path runs and wires the unlocked deps through `setDependencies` etc.
   * Returns `true` on a successful unlock (readiness flips to `serving`),
   * `false` on a credential that fails to unlock the fortress (the process
   * stays parked, fail-closed). It NEVER reveals which rule/tier failed
   * (invariant 7) and NEVER weakens establishMaster.
   *
   * CUSTODY: the unlock endpoint that calls this requires the operator bearer
   * token EVEN ON LOOPBACK (the strictest option, like the approval-decision
   * routes) so a co-resident agent sharing the loopback interface cannot
   * self-unlock the fortress. See `handleUnlockRequest`.
   */
  private unlockHandler: ((credential: UnlockCredential) => Promise<boolean>) | null = null;

  /**
   * Federation PR-A3 state. `_federationContext` carries the fortress
   * materials (master secret accessor, principal cert + key, pinned master
   * pubkey) the join ceremony needs; it is bound out of band by the console/
   * mesh boot path via {@link setFederationContext}. Until bound, federation
   * is unprovisioned and every authorize path fails closed. `_federationEnabled`
   * is the operator-controlled on/off switch; `_federationRoster` tracks
   * joined node ids for the status summary only.
   */
  private _federationContext: FederationContext | null = null;
  private _federationEnabled = false;
  /**
   * OPTIONAL operator opt-in: when set, the /v1/federation/revoke (kill) path
   * requires an M-of-N guardian quorum before a node eviction is minted.
   * DEFAULT-OFF (`null`): the revoke path behaves exactly as the legacy single-
   * operator path. Bound out of band by the operator via
   * {@link setFederationGuardianRevocationRequirement}; surfaced to the handler
   * through `buildV1FederationDeps().requireGuardianRevocationSignOff`.
   */
  private _federationGuardianRevocationRequirement:
    | GuardianRevocationRequirement
    | null = null;
  /**
   * FAIL-CLOSED latch for the persisted guardian revocation requirement. Set
   * true when a requirement WAS persisted at rest but its fortress-master-signed
   * roster did NOT re-verify against the current pinned master on rehydrate
   * (at-rest tamper, wrong-fortress roster, or a roster stale after a legitimate
   * master rotation). While true the revoke/kill path must REFUSE every
   * revocation rather than silently drop to single-operator kill (AGENTS.md
   * constraint 5): a configured M-of-N requirement that cannot be verified must
   * not evaporate. Cleared only by a clean rehydrate or an explicit operator
   * re-pin via {@link setFederationGuardianRevocationRequirement}.
   */
  private _federationGuardianRevocationRequirementInvalid = false;
  /**
   * Monotonic generation for the guardian revocation requirement. Incremented on
   * EVERY {@link setFederationGuardianRevocationRequirement} call (including
   * `set(null)`), stamped into the durable snapshot, and rehydrated from disk on
   * boot so it keeps climbing across restarts. The durable-store merge keeps the
   * value carrying the higher generation, so a stale cross-process writer (the
   * rotate-root CLI, which persists this blob with a stale copy of this field)
   * can never clobber a fresher requirement.
   */
  private _federationGuardianRevocationRequirementGeneration = 0;
  /**
   * F1 E1: anti-replay counter for the guardian DISABLE-gate. Burns (advances)
   * on every terminal disable-gate transition (instant quorum/master-key
   * authorize, break-glass vetoed, break-glass cancelled, break-glass
   * completed). See {@link FederationSyncStateSnapshot.guardianDisableNonce}.
   */
  private _federationGuardianDisableNonce = 0;
  /**
   * FIX 1 (A3 replay, reboot leg): a DEDICATED high-water for SUPERSEDED
   * lowered-threshold records, distinct from {@link
   * _federationGuardianDisableNonce}. It advances ONLY when a lowering is
   * actually dropped (a raise/re-pin that removes a prior lowered record, or a
   * decrease that replaces one), never on a break-glass initiate. On boot,
   * {@link rehydrateGuardianRevocationRequirement} REJECTS a persisted lowered
   * record whose nonce is below this floor (a replayed, already-superseded
   * lowering). See {@link
   * FederationSyncStateSnapshot.guardianLoweredHighWater} for why it must NOT
   * key off the general disable nonce.
   */
  private _federationGuardianLoweredHighWater = 0;
  /**
   * F1 E1: the in-flight break-glass countdown, or `null` when IDLE. Every
   * mutation of this field MUST happen in the SAME set as a bump of
   * {@link _federationGuardianRevocationRequirementGeneration} (the H1 fix from
   * the design review): the two travel together under one generation so a
   * stale rotate-root CLI persist can never revive a cancelled/completed
   * countdown nor silently drop an armed one.
   */
  private _federationGuardianBreakGlass: BreakGlassState | null = null;
  /**
   * F1 E1: the poll handle driving break-glass completion. There is no durable
   * OS-level scheduler in this codebase (the M1 finding from the design
   * review); this mirrors `startFederationNodeCertificateAutoRenewal` - an
   * in-process `setInterval` that re-checks the DURABLE `completesAt` on every
   * tick and on every boot re-arm. It can only ever DELAY completion (never
   * shorten it): a missed tick, a restart, or a slow poll interval all just
   * mean completion happens at the next tick after `completesAt`, never before.
   */
  private _federationBreakGlassPoll: ReturnType<typeof setInterval> | null = null;
  /**
   * F1 E1: in-flight guard for {@link tickFederationGuardianBreakGlass}. A tick
   * awaits an async audit write + (on completion) a durable persist; without
   * this guard, a slow tick overlapping the next interval firing (or many
   * timers compressed into one macrotask flush, as happens under fake timers
   * in tests) could run two ticks CONCURRENTLY against the same audit log /
   * live fields, corrupting the audit hash chain. Skipping an overlapping tick
   * is always safe: the poll only ever needs to observe `completesAt` has
   * elapsed at SOME later tick, and the next interval (or the tick already in
   * flight) covers that.
   */
  private _federationBreakGlassTickInFlight = false;
  private readonly _federationRoster = new Set<string>();
  private _federationState: FederationDashboardState = {
    eventLog: [],
    revoked: new Set<string>(),
    evictionMaxSerial: 0,
    operatorPolicy: null,
    appliedPolicyVersions: new Map<string, FederationAppliedPolicyVersion>(),
    nodes: new Map<string, FederationNodeView>(),
  };
  private _federationRenewal: FederationNodeCertificateAutoRenewalHandle | null = null;
  /**
   * Fleet control plane PR-3: the scheduled license RE-RESOLVE timer. Each tick
   * re-verifies the active license (expiry + revocation list), applies/lifts the
   * node-count cap, auto-captures a never-activated over-cap fleet's grandfather
   * baseline (once), and logs any tier/cap transition. `_fleetPriorCap` is the
   * last cap observed, so a tick can tell whether anything changed and therefore
   * whether to log a transition. Purely a MANAGEMENT-scale re-check: it touches
   * no wall / enforcement / local-dashboard / policy-push path.
   */
  private _fleetReResolveTimer: ReturnType<typeof setInterval> | null = null;
  private _fleetPriorCap: PriorCapState | null = null;
  /**
   * Fleet control plane PR-3 fix: in-flight latch that SERIALIZES the re-resolve
   * tick. Two ticks can overlap (the hourly interval and the push-triggered
   * reconcile), and the grandfather auto-capture reads `record.status === "absent"`
   * BEFORE it writes - two concurrent ticks would both pass that guard and race on
   * the write, letting the last writer lock in a transient count or lower the
   * baseline. This holds the running tick's promise so a second call awaits it
   * (or no-ops) instead of racing. Cleared in a `finally` so a thrown tick never
   * wedges the latch. (The write itself is also grow-only at the persistence layer;
   * this latch removes the read-then-write TOCTOU window as well.)
   */
  private _fleetReResolveInFlight: Promise<void> | null = null;
  /** Default license re-resolve cadence: hourly (expiry/revocation are coarse). */
  private static readonly FLEET_RE_RESOLVE_INTERVAL_MS = 60 * 60 * 1000;
  /**
   * PR-A5 cross-machine peer-sync state. `_federationAcceptedHighWater` is the
   * highest envelope high-water accepted per sender node id (whole-envelope
   * rollback guard); `_federationOutboundHighWater` is the monotonic counter
   * this daemon stamps on the reciprocal envelopes it returns.
   */
  private readonly _federationAcceptedHighWater = new Map<string, number>();
  private _federationOutboundHighWater = 0;
  /**
   * Federation 3/3b P0: DURABLE peer-sync security state. The store persists +
   * rehydrates the per-sender accepted high-water, the outbound high-water, and
   * the folded revocation projection (revoked-node set + highest eviction
   * serial) so anti-replay and revocation memory survive a daemon restart.
   * `null` when no storage/master key is wired (tests / minimal rigs run purely
   * in memory with the same semantics).
   */
  private _federationSyncStateStore: FederationSyncStateStore | null = null;
  private _federationReissueChallengeStore = new FederationReissueChallengeStore();
  private _federationReissueChallengeStoreUnavailable = false;
  /**
   * FAIL-CLOSED latch (DUR-4 / CC-2). Set true when the durable sync-state
   * record is PRESENT but could not be decrypted/parsed on boot (at-rest
   * tamper/corruption). While true the sync paths must DENY rather than serve on
   * empty anti-replay + empty revocation memory (never silently un-revoke or
   * re-open the replay window). Cleared only by a clean (re)hydration.
   */
  private _federationSyncStateUnavailable = false;
  /**
   * RR-1 pre-wire (Federation 3/3b P0). The set of REVOKED fortress-master
   * (root) pubkeys, base64url. Empty in P0 and populated only by rotate-root
   * Slice 3c compromise recovery; wired feature-inert at all three chokepoints
   * now. Persisting/wiring 3c's population is a 3c concern, not P0's.
   */
  private readonly _federationRevokedRoots = new Set<string>();
  /**
   * Slice 3c-1: the highest accepted root-revocation serial, the replay floor
   * carried alongside {@link _federationRevokedRoots}. Loaded from the durable
   * sync-state projection on boot and preserved in {@link
   * snapshotFederationSyncState} so a re-persist never regresses it. The daemon
   * does not itself MINT root revocations (the rotate-root CLI does, persisting
   * directly into the durable store); the daemon only enforces the loaded set.
   */
  private _federationHighestRevocationSerial = 0;

  /**
   * v1.3 WP-V1.3-10 Cross-Harness Approval Inbox aggregator. Mounted
   * additively at `/api/approval-inbox/*` when set. Legacy approval
   * routes at `/api/approvals/:id/(allow|deny)` continue to serve. The
   * aggregator is a passive subscriber to the gate; the routes here are
   * the operator-facing query / decision surface.
   */
  private approvalAggregator: ApprovalAggregator | null = null;

  /**
   * v1.3 WP-V1.3-1 Phi-1 Sentinel dispatcher. Mounted additively at
   * `/api/sentinels/*` when set. Sentinel surface is read-only against
   * the audit log; subscribe/unsubscribe writes flow through the
   * dispatcher's audited paths.
   */
  private sentinelDispatcher: SentinelDispatcher | null = null;

  /**
   * HABEAS PORT distress inbox. Mounted additively at `/api/distress/*`
   * when set; read-only against the operator-readable distress inbox the
   * local listener (127.0.0.1:8741) populates. No write/delete surface.
   */
  private distressInbox: DistressInbox | null = null;

  /**
   * v1.3 WP-V1.3-3 Omega-1 Coordination Handoff Visualization.
   * Mounted additively at `/api/coordination/*` when set. Read-only
   * against the audit log; the only writes are operator-action audit
   * events (operator_coordination_view_opened,
   * operator_handoff_entry_drilled).
   */
  private handoffLog: HandoffLog | null = null;
  private handoffEventBridge: HandoffEventBridge | null = null;
  private handoffContextTransfer: ContextTransferExtractorDeps | null = null;
  private workflowStateTracker: WorkflowStateTracker | null = null;
  private handoffAuditLog:
    | import("../operational/audit-log.js").AuditLog
    | null = null;
  private handoffOperatorId: string | null = null;
  // v1.3 WP-V1.3-5 Pi-1 Honeypot Authoring: per-fortress trap registry
  // + finding store + audit log + operator id. Front-of-dispatch hook
  // consults the registry on every request; management routes at
  // /api/honeypot/* go through the dispatch path.
  private honeypotRegistry: TrapRegistry | null = null;
  private honeypotFindingStore: SentinelFindingStore | null = null;
  private honeypotAuditLog:
    | import("../operational/audit-log.js").AuditLog
    | null = null;
  private honeypotOperatorId: string | null = null;
  private honeypotFortressId: string | null = null;
  private honeypotSelector: import("../intelligence/selector.js").SubstrateSelector | null = null;
  // Pi-2: encrypted at-rest persistence for deployed honeypot traps.
  // When present, the management API's deploy + undeploy handlers
  // write through to the store; on fortress boot the host code calls
  // `store.loadAll()` and re-deploys the persisted specs into the
  // in-memory registry before this dashboard begins serving.
  private honeypotStore: import("../honeypot/trap-store.js").TrapStore | null = null;
  private honeypotToolCallRuntime:
    | import("../honeypot/tool-call-trap-runtime.js").ToolCallTrapRuntime
    | null = null;
  private honeypotCredentialRuntime:
    | import("../honeypot/credential-trap-runtime.js").CredentialTrapRuntime
    | null = null;
  private autoTriggerStore: ThresholdConfigStore | null = null;
  private autoTriggerDispatcher: ActionDispatcher | null = null;
  private autoTriggerSuggester: CalibrationSuggester | null = null;
  private unifiedInboxBridge: UnifiedInboxBridge | null = null;
  private unifiedInboxRetentionPolicy: UnifiedInboxRetentionPolicy | null = null;
  private unifiedInboxRetentionPolicyStore: UnifiedInboxRetentionPolicyStore | null = null;
  private unifiedInboxPrefsStore: UnifiedInboxPrefsStore | null = null;
  private unifiedInboxFortressId: string | null = null;
  private unifiedInboxIdentityId: string | null = null;
  /**
   * Feature-health fault-raise driver (observability Slice: OS-notification raise
   * path). Built lazily when the unified-inbox bridge is wired, it recomputes the
   * feature-health panel from the SAME integrity-judged audit read the posture
   * surface uses and raises the 3 ratified fault classes to the inbox bridge,
   * deduped + rate-limited. Display-only: it feeds NOTHING back into enforcement.
   * Ticked on the unified-inbox scheduler's cadence via `evaluateFeatureFaults`.
   */
  private featureFaultRaiser: FeatureFaultRaiser | null = null;

  constructor(config: DashboardConfig) {
    this.config = config;
    this.authToken = config.auth_token;
    this.useTLS = !!(config.tls?.cert_path && config.tls?.key_path);
    // Localhost gets 24h sessions; remote/TLS gets 5min
    const isLocalhost = config.host === "127.0.0.1" || config.host === "localhost" || config.host === "::1";
    this.sessionTTLMs = isLocalhost ? SESSION_TTL_LOCAL_MS : SESSION_TTL_REMOTE_MS;
    this.dashboardHTML = generateDashboardHTML({
      timeoutSeconds: config.timeout_seconds,
      serverVersion: PKG_VERSION,
      // Construction-time default; real value is set by setAutoAuthLocalhost()
      // below (which regenerates this HTML). Default false preserves the
      // pre-v0.10.6 remote-deployment behavior when auto-auth is not enabled.
      loopbackAutoAuth: this._autoAuthLocalhost,
    });
    this.loginHTML = generateLoginHTML({ serverVersion: PKG_VERSION });
    // Federation PR-A1: /v1 session ceremony service. Reads the live
    // authToken / auto-auth flags through accessors so later mutation
    // (setAutoAuthLocalhost) is always observed.
    this.v1Sessions = new V1SessionService({
      auth: {
        // PR-A3: the credentialed session path is a durable Ed25519 operator
        // attestation verified against THIS key - the same operator identity
        // key the OPERATOR_SIGNED write path resolves. The bearer-token path
        // is gone (replace-not-extend); loopback auto-auth remains a
        // network-position fallback only.
        resolveOperatorPublicKey: () => this.resolveOperatorPublicKey(),
        isLoopbackAutoAuthEnabled: () => this._autoAuthLocalhost,
      },
    });
    // SEC-012: Periodic cleanup of expired sessions (every 60s)
    this.sessionCleanupTimer = setInterval(() => this.cleanupSessions(), 60_000);
  }

  /**
   * Inject dependencies after construction.
   * Called from index.ts after all components are initialized.
   */
  setDependencies(deps: {
    policy: PrincipalPolicy;
    baseline: BaselineTracker;
    auditLog: AuditLog;
    identityManager?: IdentityManager;
    handshakeResults?: Map<string, HandshakeResult>;
    shrOpts?: SHRGeneratorOptions;
    sanctuaryConfig?: SanctuaryConfig;
    profileStore?: SovereigntyProfileStore;
    clientManager?: ClientManager;
    /** Storage backend for the Recognition panel (bridge list + reputation read). */
    storage?: StorageBackend;
  }): void {
    this.policy = deps.policy;
    this.baseline = deps.baseline;
    this.auditLog = deps.auditLog;
    if (deps.identityManager) this.identityManager = deps.identityManager;
    if (deps.handshakeResults) this.handshakeResults = deps.handshakeResults;
    if (deps.shrOpts) this.shrOpts = deps.shrOpts;
    if (deps.storage) this.storage = deps.storage;
    if (deps.sanctuaryConfig) this._sanctuaryConfig = deps.sanctuaryConfig;
    if (deps.profileStore) this.profileStore = deps.profileStore;
    if (deps.clientManager) this.clientManager = deps.clientManager;
  }

  /**
   * Mark this dashboard as running in standalone mode.
   * Exposed via /api/status so the frontend can show an appropriate banner.
   */
  setStandaloneMode(standalone: boolean): void {
    this._standaloneMode = standalone;
  }

  /**
   * Slice 2 (park-not-exit): mark whether this dashboard is parked (booted
   * without a master key under the supervised LaunchAgent). Internal flag;
   * does not change the readiness wire contract (`ready` is still derived from
   * the presence of the identity manager). Cleared by a successful unlock.
   */
  setParked(parked: boolean): void {
    this._parked = parked;
  }

  /** Slice 2: is this dashboard currently parked (locked, awaiting unlock)? */
  isParked(): boolean {
    return this._parked;
  }

  /**
   * Slice 2 (park-not-exit): register the in-process unlock handler. The
   * standalone boot path supplies a closure that re-runs `establishMaster`
   * with an operator-supplied credential and wires the unlocked deps. Once
   * set, `POST /api/unlock` is live. The endpoint REQUIRES the operator bearer
   * token even on loopback (custody carve-out); see `handleUnlockRequest`.
   *
   * Pass `null` to detach (tests / after a successful unlock if desired).
   */
  setUnlockHandler(
    handler: ((credential: UnlockCredential) => Promise<boolean>) | null,
  ): void {
    this.unlockHandler = handler;
  }

  /**
   * v1.1.1 hotfix: bind the v1.1 dashboard + hub API to this dashboard
   * instance. After binding, requests to `/v1.1` serve the v1.1 HTML and
   * requests under `/api/hub/*` route through the hub API. Legacy routes
   * at `/` and `/api/*` keep their pre-v1.1 behavior (additive mount).
   *
   * Pass `null` to detach the bindings (used by tests and during shutdown).
   */
  setV11Bindings(bindings: V11Bindings | null): void {
    this.v11Bindings = bindings;
  }

  /**
   * v1.3 WP-V1.3-10 Upsilon-1: bind the cross-harness approval inbox
   * aggregator. Once set, requests to `/api/approval-inbox/*` route
   * through `handleApprovalInboxRoute`. Pass `null` to detach (used by
   * tests + during shutdown).
   */
  setApprovalAggregator(aggregator: ApprovalAggregator | null): void {
    this.approvalAggregator = aggregator;
  }

  /**
   * v1.3 WP-V1.3-1 Phi-1: bind the Sentinel dispatcher. Once set,
   * requests to `/api/sentinels/*` route through `handleSentinelRoute`.
   * Pass `null` to detach (used by tests + during shutdown).
   */
  setSentinelDispatcher(dispatcher: SentinelDispatcher | null): void {
    this.sentinelDispatcher = dispatcher;
  }

  /**
   * HABEAS PORT: bind the distress inbox. Once set, requests to
   * `/api/distress/*` route through `handleDistressRoute` (read-only).
   * Pass `null` to detach.
   */
  setDistressInbox(inbox: DistressInbox | null): void {
    this.distressInbox = inbox;
  }

  /**
   * v1.3 WP-V1.3-3 Omega-1: bind the Coordination handoff log +
   * event bridge + audit log + operator id. Once set, requests to
   * `/api/coordination/*` route through `handleCoordinationRoute`.
   * Pass `null` for any field to detach.
   */
  setHandoffLog(opts: {
    handoffLog: HandoffLog | null;
    eventBridge?: HandoffEventBridge | null;
    auditLog?: import("../operational/audit-log.js").AuditLog | null;
    operatorId?: string | null;
    /**
     * v1.3 WP-V1.3-3 Omega-2: context-transfer extractor deps. When
     * provided, the handoff detail route enriches its response with a
     * `context_transfer_breakdown` field.
     */
    contextTransfer?: ContextTransferExtractorDeps | null;
    /**
     * v1.3 WP-V1.3-3 Omega-3: workflow state tracker. When provided,
     * the workflow routes emit `coordination_workflow_state_changed`
     * audit events as the tracker observes transitions and push them
     * to SSE subscribers.
     */
    workflowStateTracker?: WorkflowStateTracker | null;
  }): void {
    this.handoffLog = opts.handoffLog;
    this.handoffEventBridge = opts.eventBridge ?? null;
    this.handoffAuditLog = opts.auditLog ?? null;
    this.handoffOperatorId = opts.operatorId ?? null;
    this.handoffContextTransfer = opts.contextTransfer ?? null;
    this.workflowStateTracker = opts.workflowStateTracker ?? null;
  }

  /**
   * v1.3 WP-V1.3-5 Pi-1 Honeypot Authoring: bind the per-fortress
   * trap registry + finding store + audit log + operator id. Once
   * set, two surfaces activate:
   *   1. Front-of-dispatch trap-trigger hook: every request runs
   *      through `handleHoneypotTriggerIfMatch` BEFORE legacy/v1.1/
   *      sentinel/coordination routing. Matching traps return 404
   *      and the request never reaches the regular dispatcher.
   *   2. Management API at /api/honeypot/* routes through
   *      `handleHoneypotRoute`.
   *
   * The optional `selector` opt wires the LLM compile path; absent
   * selector forces the heuristic compile path (which still produces
   * a usable TrapSpec with warnings).
   */
  setHoneypotRegistry(opts: {
    registry: TrapRegistry | null;
    findingStore?: SentinelFindingStore | null;
    auditLog?: import("../operational/audit-log.js").AuditLog | null;
    operatorId?: string | null;
    fortressId?: string | null;
    selector?: import("../intelligence/selector.js").SubstrateSelector | null;
    /**
     * Pi-2: encrypted at-rest persistence for the deployed traps. When
     * non-null, the management API's deploy + undeploy handlers write
     * through to the store so the fortress keeps its trap deployment
     * across restart. Boot rehydration is the host's responsibility:
     * call `store.loadAll()` and `registry.deploy(spec)` for each
     * persisted spec BEFORE calling this method.
     */
    store?: import("../honeypot/trap-store.js").TrapStore | null;
    toolCallRuntime?: import("../honeypot/tool-call-trap-runtime.js").ToolCallTrapRuntime | null;
    credentialRuntime?: import("../honeypot/credential-trap-runtime.js").CredentialTrapRuntime | null;
  }): void {
    this.honeypotRegistry = opts.registry;
    this.honeypotFindingStore = opts.findingStore ?? null;
    this.honeypotAuditLog = opts.auditLog ?? null;
    this.honeypotOperatorId = opts.operatorId ?? null;
    this.honeypotFortressId = opts.fortressId ?? null;
    this.honeypotSelector = opts.selector ?? null;
    this.honeypotStore = opts.store ?? null;
    this.honeypotToolCallRuntime = opts.toolCallRuntime ?? null;
    this.honeypotCredentialRuntime = opts.credentialRuntime ?? null;
  }

  /**
   * v1.3 WP-V1.3-7 Nu-3 Auto-Trigger recommendation surface. Mounted
   * additively at `/api/auto-trigger/*`; the scheduled suggester only
   * emits read-only recommendations. Accept/reject routes are explicit
   * operator actions.
   */
  setAutoTrigger(opts: {
    store: ThresholdConfigStore | null;
    dispatcher?: ActionDispatcher | null;
    suggester?: CalibrationSuggester | null;
  }): void {
    this.autoTriggerStore = opts.store;
    this.autoTriggerDispatcher = opts.dispatcher ?? null;
    this.autoTriggerSuggester = opts.suggester ?? null;
  }

  setUnifiedInbox(opts: {
    bridge: UnifiedInboxBridge | null;
    retentionPolicy?: UnifiedInboxRetentionPolicy | null;
    retentionPolicyStore?: UnifiedInboxRetentionPolicyStore | null;
    prefsStore?: UnifiedInboxPrefsStore | null;
    fortressId?: string | null;
    identityId?: string | null;
  }): void {
    this.unifiedInboxBridge = opts.bridge;
    this.unifiedInboxRetentionPolicy =
      opts.retentionPolicy ?? new UnifiedInboxRetentionPolicy();
    this.unifiedInboxRetentionPolicyStore =
      opts.retentionPolicyStore ?? null;
    this.unifiedInboxPrefsStore = opts.prefsStore ?? null;
    this.unifiedInboxFortressId = opts.fortressId ?? null;
    this.unifiedInboxIdentityId = opts.identityId ?? null;
    // Wire the feature-health fault-raise driver onto the now-available inbox
    // bridge (the notification sink). Built once; it holds the prior panel so the
    // ON->OFF `feature_silently_off` transition can be computed across cycles.
    this.featureFaultRaiser = opts.bridge
      ? new FeatureFaultRaiser({
          bridge: opts.bridge,
          buildPanel: () => this.buildFeatureHealthPanelForRaise(),
        })
      : null;
  }

  /**
   * Recompute the feature-health panel for the fault-raise driver, from the SAME
   * integrity-judged eager audit read and the SAME producer-key load the posture
   * `/api/posture/feature-health` route uses, so the raise can never diverge from
   * the dashboard on what is green / fault. Includes the per-plugin rows so the
   * `plugin_failure_surge` class can read its host-minted error-rate fault. Pure
   * read: builds a presentation object, drives no mutation, exposes no key.
   */
  private async buildFeatureHealthPanelForRaise(): Promise<
    Awaited<ReturnType<typeof buildFeatureHealthPanel>>
  > {
    if (this.auditLog === null) {
      throw new Error("feature-health raise: audit log unavailable");
    }
    await this.ensureProducerKeyLoaded();
    await this.ensureBrokerProducerKeyLoaded();
    const load = this._producerKeyLoad;
    const brokerLoad = this._brokerProducerKeyLoad;
    const originMachine =
      this.v11Bindings?.fortressId ??
      this.identityManager?.getPrimaryIdentityId() ??
      "local";
    const auditLog = this.auditLog;
    // S5-P (codex MED fix): thread the SAME fail-closed exclusive-egress
    // snapshot every other feature-health consumer uses, so the fault-raise
    // panel's `castle_wall_egress` row agrees with the rendered dashboard row
    // (both compute `coarse_only` when the exclusive stack is down). This keeps
    // the raise path's transition memory consistent with what the operator
    // sees; `coarse_only` is not in the silent-off set, so it never spuriously
    // raises an OS notification (coarse-only stays loud on the surface, not a
    // notification - the ratified tight fault-class set is unchanged).
    const exclusiveEgress = await this.resolveExclusiveEgressPosture();
    return auditLog.runEagerReads(() =>
      buildFeatureHealthPanel({
        auditLog,
        originMachine,
        includePluginRows: true,
        pinnedProducerKeyB64url:
          load?.status === "present" ? load.keyB64url : null,
        ...(load?.status === "unreadable"
          ? { producerKeyExpectedButUnavailable: true }
          : {}),
        brokerPinnedProducerKeyB64url:
          brokerLoad?.status === "present" ? brokerLoad.keyB64url : null,
        ...(brokerLoad?.status === "unreadable"
          ? { brokerProducerKeyExpectedButUnavailable: true }
          : {}),
        ...(exclusiveEgress !== null ? { exclusiveEgress } : {}),
      }),
    );
  }

  /**
   * One feature-health fault-raise evaluation cycle, ticked on the unified-inbox
   * scheduler's cadence (`index.ts` passes this as the scheduler `onTick`). A
   * no-op when the raiser is not wired (no inbox bridge / locked log). Never
   * throws into the scheduler: the driver swallows a panel-build failure.
   */
  async evaluateFeatureFaults(): Promise<void> {
    if (!this.featureFaultRaiser) return;
    await this.featureFaultRaiser.evaluate();
  }

  /**
   * v1.3 WP-V1.3-10 dispatch entry point. Called from `handleRequest`
   * before the legacy approval route table. Returns true when served.
   */
  private async dispatchApprovalInbox(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (!this.approvalAggregator) return false;
    return handleApprovalInboxRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        aggregator: this.approvalAggregator,
        operatorId: this.identityManager?.getPrimaryIdentityId() ?? undefined,
      },
      req,
      res,
    );
  }

  /**
   * v1.3 WP-V1.3-1 Phi-1 dispatch entry point. Routes `/api/sentinels/*`
   * requests through the sentinel router when a dispatcher has been
   * bound. Returns true when served.
   */
  /**
   * HABEAS PORT dispatch entry point. Routes `/api/distress/*` requests
   * through the distress inbox router when an inbox has been bound.
   * Returns true when served.
   */
  private async dispatchDistress(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (!this.distressInbox) return false;
    // SECURITY (codex round-1 HIGH): authenticate through the dashboard's own
    // checkAuth - the SAME gate the `/api/audit-log` route uses, which already
    // serves every distress envelope. This honors bearer token AND the login
    // session cookie (the route-helper's authMiddleware checks neither cookie),
    // so the operator's browser works and a tokenless non-browser caller is
    // 401'd. checkAuth writes the 401 itself when it fails.
    const url = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);
    if (!this.checkAuth(req, url, res, { allowSession: true })) return true;
    return handleDistressRoute({ inbox: this.distressInbox }, req, res);
  }

  private async dispatchSentinel(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (!this.sentinelDispatcher) return false;
    return handleSentinelRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        dispatcher: this.sentinelDispatcher,
      },
      req,
      res,
    );
  }

  private async dispatchAutoTrigger(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (!this.autoTriggerStore || !this.autoTriggerDispatcher) return false;
    return handleAutoTriggerRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        store: this.autoTriggerStore,
        dispatcher: this.autoTriggerDispatcher,
        ...(this.autoTriggerSuggester
          ? { suggester: this.autoTriggerSuggester }
          : {}),
      },
      req,
      res,
    );
  }

  private async dispatchUnifiedInbox(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (!this.unifiedInboxBridge) return false;
    return handleUnifiedInboxRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        bridge: this.unifiedInboxBridge,
        ...(this.unifiedInboxRetentionPolicy
          ? { retentionPolicy: this.unifiedInboxRetentionPolicy }
          : {}),
        ...(this.unifiedInboxRetentionPolicyStore
          ? { retentionPolicyStore: this.unifiedInboxRetentionPolicyStore }
          : {}),
        ...(this.unifiedInboxPrefsStore
          ? { prefsStore: this.unifiedInboxPrefsStore }
          : {}),
        ...(this.auditLog
          ? { auditLog: this.auditLog }
          : {}),
        ...(this.unifiedInboxIdentityId
          ? { identityId: this.unifiedInboxIdentityId }
          : {}),
        ...(this.unifiedInboxFortressId
          ? { fortressId: this.unifiedInboxFortressId }
          : {}),
      },
      req,
      res,
    );
  }

  /**
   * v1.3 WP-V1.3-3 Omega-1 dispatch entry point. Routes
   * `/api/coordination/*` requests through the coordination router
   * when a HandoffLog has been bound. Returns true when served.
   */
  private async dispatchCoordination(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (
      !this.handoffLog ||
      !this.handoffEventBridge ||
      !this.handoffAuditLog
    ) {
      return false;
    }
    return handleCoordinationRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        handoffLog: this.handoffLog,
        auditLog: this.handoffAuditLog,
        operatorId:
          this.handoffOperatorId ??
          this.identityManager?.getPrimaryIdentityId() ??
          "operator_dashboard",
        events: this.handoffEventBridge,
        ...(this.handoffContextTransfer !== null
          ? { contextTransfer: this.handoffContextTransfer }
          : {}),
        ...(this.workflowStateTracker !== null
          ? { workflowStateTracker: this.workflowStateTracker }
          : {}),
      },
      req,
      res,
    );
  }

  /**
   * v1.3 WP-V1.3-5 Pi-1 dispatch entry point. Routes
   * `/api/honeypot/*` requests through the honeypot management
   * router when a registry has been bound. Returns true when served.
   */
  private async dispatchHoneypot(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (
      !this.honeypotRegistry ||
      !this.honeypotFindingStore ||
      !this.honeypotAuditLog
    ) {
      return false;
    }
    return handleHoneypotRoute(
      {
        authConfig: {
          loopbackAutoAuth: this._autoAuthLocalhost,
          ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        },
        registry: this.honeypotRegistry,
        findingStore: this.honeypotFindingStore,
        auditLog: this.honeypotAuditLog,
        operatorId:
          this.honeypotOperatorId ??
          this.identityManager?.getPrimaryIdentityId() ??
          "operator_dashboard",
        fortressId: this.honeypotFortressId ?? "fortress_default",
        ...(this.honeypotSelector !== null
          ? { selector: this.honeypotSelector }
          : {}),
        ...(this.honeypotStore !== null
          ? { store: this.honeypotStore }
          : {}),
        ...(this.honeypotToolCallRuntime !== null
          ? { toolCallRuntime: this.honeypotToolCallRuntime }
          : {}),
        ...(this.honeypotCredentialRuntime !== null
          ? { credentialRuntime: this.honeypotCredentialRuntime }
          : {}),
      },
      req,
      res,
    );
  }

  /**
   * v1.3 WP-V1.3-5 Pi-1 front-of-dispatch trap-trigger hook. Examines
   * every request BEFORE legacy/v1.1/sentinel/coordination routing.
   * Returns true when a deployed trap matched the request and the
   * handler emitted the audit event + sentinel finding + plausible
   * 404 response. Returns false when no trap matched; caller
   * continues with normal routing.
   */
  private async dispatchHoneypotTrap(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> {
    if (
      !this.honeypotRegistry ||
      !this.honeypotFindingStore ||
      !this.honeypotAuditLog
    ) {
      return false;
    }
    return handleHoneypotTriggerIfMatch(
      {
        registry: this.honeypotRegistry,
        findingStore: this.honeypotFindingStore,
        auditLog: this.honeypotAuditLog,
        operatorId:
          this.honeypotOperatorId ??
          this.identityManager?.getPrimaryIdentityId() ??
          "operator_dashboard",
        fortressId: this.honeypotFortressId ?? "fortress_default",
        ...(this.honeypotCredentialRuntime !== null
          ? { credentialRuntime: this.honeypotCredentialRuntime }
          : {}),
      },
      req,
      res,
    );
  }

  /**
   * v1.1 dispatch entry point. Called from `handleRequest` before the
   * legacy route table. Returns true when the request was served by v1.1
   * routes; false to fall through to legacy routing.
   *
   * Auth gating: the v1.1 dashboard HTML is served unconditionally (the
   * client script handles its own auth dance). Hub API routes run through
   * the same auth contract as legacy `/api/*` routes via the AuthConfig
   * passed to `handleHubRoute`.
   */
  private async dispatchV11(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
  ): Promise<boolean> {
    if (!this.v11Bindings) return false;
    return dispatchV11Request(
      {
        bindings: this.v11Bindings,
        ...(this.authToken !== undefined ? { authToken: this.authToken } : {}),
        loopbackAutoAuth: this._autoAuthLocalhost,
      },
      req,
      res,
      url,
      method,
    );
  }

  /**
   * Sovereignty Posture Dashboard (Phase 1) dispatch entry point. Serves the
   * posture-home HTML at `/posture` and the four gap endpoints under
   * `/api/posture/*` (G1 unwrapped roster, G2 today's-story digest, G4
   * enforcement-evidenced Castle Wall arm state, G5 per-agent effective reach).
   *
   * Auth: the JSON routes and the HTML page run through `checkAuth` - the SAME
   * gate `/api/audit-log` uses - before this dispatcher is reached (the caller
   * checks it). Returns true when served, false to fall through to legacy.
   *
   * Dependencies are resolved lazily per request so post-unlock wiring (the
   * hub binding, the operator identity) is always observed. The origin-machine
   * attribution is the fortress id so the `/v1`-compatible payloads merge into
   * a multi-machine console later without a schema break.
   */
  private async dispatchPosture(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
  ): Promise<boolean> {
    const originMachine =
      this.v11Bindings?.fortressId ??
      this.identityManager?.getPrimaryIdentityId() ??
      "local";
    // Slice R + P: load the pinned producer key once (cached) before serving so
    // the readers can re-verify producer signatures. `present` → activate the
    // signed close; `absent` → channel basis (honest macOS / pre-provision);
    // `unreadable` → fail honestly (the readers force non-green via
    // `producerKeyExpectedButUnavailable`), never the channel basis.
    await this.ensureProducerKeyLoaded();
    await this.ensureBrokerProducerKeyLoaded();
    const load = this._producerKeyLoad;
    const brokerLoad = this._brokerProducerKeyLoad;
    // Recognition precursor: resolve the composition render-gate flag via the
    // canonical resolver (default-off). The fortress config carries no composition
    // input today, so this resolves to the honest `false` default; when an input
    // is added later the same resolver picks it up without a shape change. This is
    // CONFIG, not evidence - the composition endpoint exposes only this boolean.
    const compositionEnabled =
      resolveCompositionConfig().composition_enabled;
    const deps: PostureRouteDeps = {
      auditLog: this.auditLog ?? null,
      originMachine,
      compositionEnabled,
      // Recognition panel (P5) impure sources, resolved lazily per request so
      // post-unlock wiring is observed. Both are LOCAL reads only: a count of
      // persisted bridge commitments, and the local attestation-store evidence
      // (COUNTS, never a score). They are only consulted when the route builds
      // the panel (composition-enabled); the panel is absent otherwise.
      countBridgeCommitments: () => this.countBridgeCommitments(),
      gatherRecognitionReputation: () => this.gatherRecognitionReputation(),
      listAgents: () => this.v11Bindings?.hubService.listAgents() ?? [],
      // Fleet Console Slice 1: present the federation-backed fleet roster over
      // the SAME live `V1FederationDeps` (and the SAME `isNodeRevoked`
      // projection) the `/v1` federation endpoints use, so the panel's trust
      // verdict is the federation layer's, never re-derived from a response
      // shape. The eviction serial is fleet context only. Read-only: this builds
      // a presentation object and drives no mutation, exposes no key material.
      //
      // Fleet control plane PR-B: apply the paid NODE-COUNT cap here, on the
      // DURABLE daemon roster (`_federationState.nodes`, persisted by #888). The
      // cap is resolved fail-closed from the signed, master-MAC'd activation
      // record re-verified against the pinned operator issuer key at the CURRENT
      // clock (so expiry/grace are honored live). When over the entitled count,
      // `applyFleetCap` drops the excess nodes from THIS CENTRAL roster only -
      // every dropped node keeps its free local wall, its local dashboard, kill
      // safety, and free policy-push (this path has no wall/enforcement code and
      // preserves the `policy_distribution` rail verbatim). A resolve failure can
      // only ever REMOVE paid management capacity (community floor), never grant
      // it and never touch a node's security. The count that drives the cap is
      // `summary.admitted` (active, non-revoked), already computed by
      // `buildFleetRoster` via the shared `isNodeRevoked` projection.
      fleetRoster: async () => {
        const roster = buildFleetRoster(this.buildV1FederationDeps(), {
          evictionSerial: this._federationState.evictionMaxSerial,
          operatorPolicy: this._federationState.operatorPolicy,
        });
        const cap = await this.resolveFleetCap();
        return applyFleetCap(roster, cap).roster;
      },
      resolvePinnedProducerKey: () =>
        load?.status === "present" ? load.keyB64url : null,
      producerKeyExpectedButUnavailable: load?.status === "unreadable",
      resolveBrokerPinnedProducerKey: () =>
        brokerLoad?.status === "present" ? brokerLoad.keyB64url : null,
      brokerProducerKeyExpectedButUnavailable:
        brokerLoad?.status === "unreadable",
      // Wire the shared registry so the SSE live-refresh stream is available and
      // its concurrency cap is enforced server-wide. The stream reuses `buildHome`
      // (no new data, no new green paths) on a cadence plus a heartbeat.
      streamRegistry: this.postureStreamRegistry,
      // S5-P: the exclusive-egress posture provider (fail-closed resolve lives
      // in the route layer; this passes the raw provider through so post-wiring
      // is observed lazily per request). Null until S5-6 attaches a producer.
      ...(this._exclusiveEgressPostureProvider
        ? { exclusiveEgressPosture: this._exclusiveEgressPostureProvider }
        : {}),
    };
    return handlePostureRoute(deps, req, res, url, method);
  }

  /**
   * One-surface default-flip: the v1.1 concierge is the single default page at
   * `/`; the posture board is preserved at the `/posture` alias and is folded
   * INTO the concierge (the seal expands to full posture detail; a Posture entry
   * lives in the Verify group). Nothing is lost: every byte of posture evidence
   * is reachable from the one default surface.
   *
   * Operator directive (2026-06-30): "New design should be the default, but the
   * posture data should be incorporated into the new design somewhere. ONE
   * SURFACE." Before this change `/` served the SEPARATE `renderPostureHomeHTML`
   * shell while the concierge lived only at `/dashboard` and `/v1.1`, so there
   * were two surfaces and the new design was not the default. The fix flips `/`
   * to the concierge by NO LONGER owning `/` here; the bare-root request now
   * falls through to the v1.1 dispatch ladder (which already serves the
   * concierge at `/`). The posture board stays one click away at `/posture`.
   *
   * Auth contract (Delta Review A3 remediation), preserved for `/posture`: the
   * posture shell is a STATIC page that carries no posture data - it negotiates
   * its own auth client-side (loopback auto-auth or a pasted bearer) and fetches
   * `/api/posture/*` for every byte of evidence, and those JSON routes stay
   * behind `checkAuth`. So the `/posture` shell is served WITHOUT a server-side
   * auth gate, before the auth gate, exactly as before. The `/posture` HTML
   * branch was removed from {@link handlePostureRoute} accordingly (it would now
   * be unreachable); the data routes it owns are unchanged.
   *
   * Scope: this now matches ONLY the `/posture` alias (plus the v1.1 SPA aliases
   * `/dashboard`, `/v1.1`, which it falls through for). `/`, `/v1.0`,
   * `/fortress`, `/posture/agent/:id`, and every `/api/*` route (including the
   * approval channel and the posture JSON API) are untouched and keep their
   * existing handlers and auth gates.
   *
   * Surface scope: this standalone `DashboardApprovalChannel` owns live approval
   * decisions. The SEPARATE co-located `wrap` server (`dashboard/api.ts`, the
   * `sanctuary wrap` / "Protect" HTTP server) performs the SAME default-flip: `/`
   * serves the concierge, `/posture` serves the posture shell, `/api/posture/*`
   * stays behind read auth, and `/dashboard` + `/v1.1` remain v1.1 aliases.
   *
   * Returns true when it served the posture board shell; false to fall through
   * to the existing v1.1 / legacy dispatch ladder (which serves the concierge at
   * `/`).
   */
  private dispatchRootPosture(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
  ): boolean {
    // The SPA view routes whose static shell fetches its data client-side from
    // checkAuth-gated JSON routes: the posture shell (`/posture`) and the v1.1
    // dashboard SPA aliases (`/dashboard`, `/v1.1`). NOTE (default-flip): `/` is
    // NO LONGER a posture-shell path - it falls through to the v1.1 concierge.
    const isRoot = url.pathname === "/";
    // default-flip: when v1.1 bindings are wired (the production standalone
    // dashboard ALWAYS wires them), `/` serves the v1.1 concierge - so `/`
    // falls through to the v1.1 dispatch ladder and is treated here ONLY for the
    // remote-login affordance below. When v1.1 bindings are ABSENT (a degenerate
    // bare DashboardApprovalChannel, e.g. an isolated unit-test rig), there is
    // no concierge to fall through to, so `/` keeps serving the posture board
    // shell as the honest fallback rather than 404ing.
    const isRootServedAsShell = isRoot && !this.v11Bindings;
    const isPostureShellPath =
      url.pathname === POSTURE_HOME_PATH || isRootServedAsShell;
    const isV11SpaAlias =
      url.pathname === "/dashboard" ||
      url.pathname === "/v1.1" ||
      url.pathname === "/v1.1/";
    if (method !== "GET" || (!isPostureShellPath && !isV11SpaAlias && !isRoot)) {
      return false;
    }

    // C1 remote login affordance: these shells are STATIC pages that fetch
    // `/api/posture/*` (and the v1.1 hub API) client-side for every byte of
    // data, and those JSON routes stay behind checkAuth.
    //
    // On a LOOPBACK bind the static shell is served tokenless BY DESIGN (the
    // `/` == `/posture` one-surface contract): a local operator either has
    // loopback auto-auth after a terminal unlock, or pastes a token into the
    // shell's own client-side flow, so `/` must keep serving the shell. That
    // local contract is left exactly as-is.
    //
    // On a REMOTE (non-loopback) bind there is NO loopback auto-auth, so an
    // unauthenticated browser's every data fetch 401s and the shell renders
    // empty with NO way to enter a token (the drill defect). So ONLY for a
    // remote binding, when an auth token is required AND this caller is not yet
    // authenticated, serve the login page (the SAME page `/v1.0` already serves
    // for its unauthenticated branch) so the operator gets a token box. This is
    // purely a presentation affordance: it adds NO new auth path and weakens
    // nothing - the data routes still require a valid token; this only OFFERS
    // the login box instead of a blank shell. An already-authenticated remote
    // caller (`isAuthenticated` true: bearer/session/cookie) falls through to
    // the shell.
    if (
      this.isRemoteBinding() &&
      this.authToken &&
      !this.isAuthenticated(req, url)
    ) {
      this.serveLoginPage(res);
      return true;
    }

    // Authenticated (or no-auth) case: only the posture shell is owned here.
    // The v1.1 SPA aliases keep their existing v1.1 HTML handler - fall through
    // to dispatchV11 unchanged so authenticated `/dashboard` + `/v1.1` behavior
    // does not change.
    if (!isPostureShellPath) {
      return false;
    }
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(renderPostureHomeHTML());
    return true;
  }

  /**
   * Build the evidence-gated Castle Wall arm-state the SAME way
   * `/api/posture/castle-wall` derives it, so the AUTHENTICATED `/v1/status`
   * document can report ONE honest arm-state instead of the dead
   * `{ status: "unknown" }` placeholder it carried before.
   *
   * Auth scope (Delta Review A3 remediation): this is deliberately NOT exposed
   * on the unauthenticated `/api/health` probe - that surface stays a cheap
   * O(1) liveness answer with no posture and no audit scan. The detailed
   * posture leaves the server only behind auth: this builder feeds the
   * SESSION_TOKEN-gated `/v1/status` document (and `/api/posture/castle-wall`
   * derives the same shape behind checkAuth). The native badge sources from
   * `/api/posture/castle-wall`, never from `/api/health`.
   *
   * Resolves dependencies the same way {@link dispatchPosture} does (origin
   * machine, the pinned producer key load, the unlocked audit log): green
   * (`armed`) is derived by the ONE canonical {@link buildCastleWallPosture}
   * shaper and nowhere else. The only divergence from the `/api/posture/...`
   * route is the locked/absent-audit case: that route 503s (it need not answer
   * when it cannot evidence posture), whereas a status document must answer 200,
   * so this builder returns an honest `unknown` placeholder instead of routing
   * through the shaper (whose `auditLog` input is typed non-null, so the null
   * case genuinely cannot reach it). Honesty is preserved end-to-end: when the
   * audit log is locked/absent, or the producer key is expected-but-unreadable,
   * or evidence is stale, the result is `unknown` / `degraded` (never `armed`).
   * Green (`armed`) is only ever returned for fresh, observed enforcement
   * evidence, and only from the canonical shaper.
   *
   * Never throws into the request path: any unexpected failure resolves to an
   * honest `unknown` posture so the status document always answers.
   */
  private async buildStatusCastleWall(): Promise<CastleWallPosture> {
    const originMachine =
      this.v11Bindings?.fortressId ??
      this.identityManager?.getPrimaryIdentityId() ??
      "local";
    try {
      // Reuse the same producer-key load + audit log + origin attribution the
      // posture dispatcher uses, so the two surfaces can never diverge on green.
      await this.ensureProducerKeyLoaded();
      const load = this._producerKeyLoad;
      if (this.auditLog === null) {
        // No unlocked audit log ⇒ no enforcement evidence to read. Honest
        // `unknown` (amber), never green, never a fabricated placeholder.
        return {
          origin_machine: originMachine,
          arm_state: "unknown",
          platform: mapPlatform(process.platform),
          evidence_basis: "no_evidence",
          last_enforcement_evidence_at: null,
          // Report the real freshness window (not 0) so this fallback matches
          // the canonical buildCastleWallPosture shaper, whose own
          // unknown/degraded fallbacks all return DEFAULT_ENFORCEMENT_FRESHNESS_MS.
          freshness_window_ms: DEFAULT_ENFORCEMENT_FRESHNESS_MS,
          verdict_counts: { allowed: 0, blocked: 0, operator_decisions: 0 },
          audit_integrity_ok: true,
          sealed_region_unverified_at_privilege: false,
          producer_authenticity: "not_applicable",
        };
      }
      // EAGER SCOPE (badge surface): `/v1/status` is the SESSION_TOKEN-gated
      // operator status document the native app polls for the arm badge, exactly
      // like the `/api/posture/castle-wall` route #717 already wraps. Run the
      // shaper's audit read on the eagerly-maintained verified view so a badge
      // poll on a 10k-entry chain is bounded-cost (O(1)) instead of an 11-30s
      // full-chain re-verify per request. Honesty is unchanged: the eager view
      // reflects every server-written entry with NO lag, the #717 fingerprint
      // sentinel plus throttled backstop catch out-of-band tampering, and the
      // shaper's own freshness/evidence gating (unknown / degraded, never armed
      // without fresh verified evidence) is untouched: only WHERE its `query`
      // runs changes. This is the operator/badge read, NOT the agent-facing
      // `/api/posture/evidence` audit surface (which deliberately stays
      // per-request re-verified).
      // S5-P: resolve the exclusive-egress posture (fail-closed) OUTSIDE the
      // eager read scope, then let the ONE canonical shaper apply the
      // aggregate-green cap so /v1/status and the posture routes can never
      // diverge on green.
      const exclusiveEgress = await this.resolveExclusiveEgressPosture();
      return await this.auditLog.runEagerReads(() =>
        buildCastleWallPosture({
          auditLog: this.auditLog as AuditLog,
          originMachine,
          pinnedProducerKeyB64url:
            load?.status === "present" ? load.keyB64url : null,
          ...(load?.status === "unreadable"
            ? { producerKeyExpectedButUnavailable: true }
            : {}),
          ...(exclusiveEgress !== null ? { exclusiveEgress } : {}),
        }),
      );
    } catch {
      // Defensive: a health probe must never fail. Fall back to an honest
      // `unknown` posture rather than throwing or claiming green.
      return {
        origin_machine: originMachine,
        arm_state: "unknown",
        platform: mapPlatform(process.platform),
        evidence_basis: "no_evidence",
        last_enforcement_evidence_at: null,
        // Report the real freshness window (not 0) so this fallback matches
        // the canonical buildCastleWallPosture shaper, whose own
        // unknown/degraded fallbacks all return DEFAULT_ENFORCEMENT_FRESHNESS_MS.
        freshness_window_ms: DEFAULT_ENFORCEMENT_FRESHNESS_MS,
        verdict_counts: { allowed: 0, blocked: 0, operator_decisions: 0 },
        audit_integrity_ok: false,
        sealed_region_unverified_at_privilege: false,
        producer_authenticity: "not_applicable",
      };
    }
  }

  /**
   * Recognition panel (P5): count persisted Concordia-bridge commitments by
   * listing the reserved `_bridge` namespace. This is the "committed receipts"
   * count - a LOCAL storage read with NO Concordia process running and NO
   * external fetch. Returns `undefined` when no storage backend is wired so the
   * shaper takes its documented audit-event lower-bound fallback (returning `0`
   * would assert a fact - "zero bridge commitments" - that an un-wired store
   * cannot establish, suppressing the fallback). A list failure likewise
   * propagates so the route layer's try/catch degrades to the audit-event count
   * rather than fabricating a number.
   */
  private async countBridgeCommitments(): Promise<number | undefined> {
    if (!this.storage) return undefined;
    const entries = await this.storage.list("_bridge");
    return entries.length;
  }

  /**
   * Recognition panel (P5): gather LOCAL reputation EVIDENCE (attestation counts,
   * tier distribution, dispute count, most-recent timestamp, and the local
   * `verascore_linked` publish flag) for the primary identity. This reads the
   * local attestation store ONLY - it never fetches a Verascore (or any vendor)
   * score, and it returns COUNTS, not a number-on-a-scale. Returns `null` when
   * the storage backend, master key, or a primary identity is unavailable, which
   * the panel renders as an amber "no evidence yet" row (never green).
   */
  private async gatherRecognitionReputation(): Promise<RecognitionReputationEvidence | null> {
    if (!this.storage || !this.shrOpts || !this.identityManager) return null;
    const identity = this.identityManager.getDefault();
    if (!identity) return null;
    const reputationStore = new ReputationStore(this.storage, this.shrOpts.masterKey);
    if (this.auditLog === null) return null;
    const evidence = await gatherReputationEvidence(reputationStore, this.auditLog, {
      identity_id: identity.identity_id,
      did: identity.did,
    });
    // Project to the panel's evidence shape (counts only; never a score).
    return {
      attestation_count: evidence.attestation_count,
      tier_distribution: evidence.tier_distribution,
      most_recent_attestation_at: evidence.most_recent_attestation_at,
      dispute_count: evidence.dispute_count,
      verascore_linked: evidence.verascore_linked,
    };
  }

  /**
   * Load + cache the read-side producer-key state for signature re-verification
   * (Slice R + Slice P). The key file is published by the daemon at
   * `<storage_path>/policy/egress/audit-producer.pub` and resolved through the
   * SAME single-source loader (`loadFortressProducerKey`) the consumer uses, so
   * the reader can never diverge onto a different path or basis.
   *
   * Caching rule:
   *   - `present`    → cached permanently (the pinned anchor is stable).
   *   - `absent`     → transient: leave `undefined` so a post-provision request
   *                    re-attempts the load (codex MEDIUM #4). Channel basis for
   *                    THIS request.
   *   - `unreadable` → transient (re-checked next request) AND surfaced to the
   *                    readers as `producerKeyExpectedButUnavailable` so this
   *                    request fails honestly (degraded, never channel-green).
   * Never throws into the request path; never defaults the wall green.
   */
  private async ensureProducerKeyLoaded(): Promise<void> {
    // Already loaded a real key → stable, never re-read.
    if (this._producerKeyLoad?.status === "present") return;
    const storagePath = this._sanctuaryConfig?.storage_path;
    if (typeof storagePath !== "string" || storagePath.length === 0) {
      // No storage path to read from: treat as absent (channel basis), re-checked
      // next request once config wiring lands.
      this._producerKeyLoad = undefined;
      return;
    }
    let load: ProducerKeyLoad;
    try {
      load = await loadFortressProducerKey(
        storagePath,
        this.config.producer_key_load_options,
      );
    } catch {
      // Defensive: loadFortressProducerKey already converts I/O failures into a
      // status, but never let an unexpected throw reach the request path.
      load = { status: "unreadable", reason: "producer_key_load_threw" };
    }
    // Only `present` is a permanent cache (the `status === "present"` guard
    // above short-circuits future loads). `unreadable` is stored so THIS request
    // fails honestly, and `absent` is stored as undefined - both are re-evaluated
    // on the next request, so a post-provision write (or a fixed permission) is
    // always picked up.
    this._producerKeyLoad = load.status === "absent" ? undefined : load;
  }

  private async ensureBrokerProducerKeyLoaded(): Promise<void> {
    if (this._brokerProducerKeyLoad?.status === "present") return;
    const storagePath = this._sanctuaryConfig?.storage_path;
    if (typeof storagePath !== "string" || storagePath.length === 0) {
      this._brokerProducerKeyLoad = undefined;
      return;
    }
    let load: BrokerProducerKeyLoad;
    try {
      load = await loadBrokerProducerKey(storagePath);
    } catch {
      load = { status: "unreadable", reason: "broker_producer_key_load_threw" };
    }
    this._brokerProducerKeyLoad = load.status === "absent" ? undefined : load;
  }

  /**
   * Federation PR-A1: full `/v1/status` document, served only to a valid
   * SESSION_TOKEN holder with the status-read capability. Catalog shape:
   * `{ ok, version, daemon, listener, federation, identity, castle_wall }`.
   *
   * Field discipline: identity is an EXPLICIT pick of public fields from
   * the stored identity - never a spread, so the encrypted private key
   * blob can never ride along into an HTTP response (CLAUDE.md
   * constraint 6). Federation is honestly `enabled: false` until the
   * PR-A3 listener work.
   *
   * Delta Review A3: `castle_wall` now carries the SAME evidence-gated arm-state
   * `/api/posture/castle-wall` derives (via the canonical
   * {@link buildStatusCastleWall} → {@link buildCastleWallPosture} path), not the
   * old dead `{ status: "unknown" }` placeholder. This document is served ONLY
   * to a SESSION_TOKEN holder with the status-read capability, so the detailed
   * posture (and the audit scan that derives it) stays behind auth - it is NOT
   * on the unauthenticated `/api/health` probe. Honesty is preserved: the shaper
   * returns `unknown` / `degraded` (never `armed`) whenever there is no fresh,
   * verified enforcement evidence.
   */
  private async buildV1FullStatus(): Promise<Record<string, unknown>> {
    const identity = this.identityManager?.getDefault();
    const castleWall = await this.buildStatusCastleWall();
    const federationPosture = this.buildFederationPostureSummary();
    return {
      ok: true,
      version: PKG_VERSION,
      daemon: {
        mode: this._standaloneMode ? "standalone" : "co-located",
        pid: process.pid,
      },
      listener: {
        host: this.config.host,
        port: this.config.port,
        tls: this.useTLS,
      },
      federation: {
        enabled: this._federationEnabled && this._federationContext !== null,
        provisioned: this._federationContext !== null,
        roster_size: this._federationRoster.size,
        operator_cloud_nodes: federationPosture.operator_cloud_nodes,
        provider_in_trust_boundary: federationPosture.provider_in_trust_boundary,
        tee_attested: federationPosture.tee_attested,
        trust_boundary: federationPosture,
      },
      identity: identity
        ? {
            identity_id: identity.identity_id,
            label: identity.label,
            did: identity.did,
            public_key: identity.public_key,
            created_at: identity.created_at,
          }
        : null,
      castle_wall: castleWall,
    };
  }

  /**
   * Federation PR-A2: dependency bundle for the /v1/agents endpoints. Reads
   * the live hub binding + operator identity each request so post-unlock
   * wiring is always observed. Degrades fail-closed:
   *   - no hub bound  ⇒ empty roster; unprotect returns `unavailable`.
   *   - no operator id ⇒ `resolveOperatorPublicKey` returns null, which
   *     forces every signed write to the generic 403 (never fails open).
   */
  private buildV1AgentsDeps(): V1AgentsDeps {
    const nodeId =
      this.v11Bindings?.fortressId ??
      this.identityManager?.getPrimaryIdentityId() ??
      "local";
    return {
      nodeId,
      listAgents: () => this.v11Bindings?.hubService.listAgents() ?? [],
      resolveOperatorPublicKey: () => this.resolveOperatorPublicKey(),
      enqueueUnprotect: async (agentId): Promise<UnprotectOutcome> => {
        const hub = this.v11Bindings?.hubService;
        if (!hub) return { ok: false, reason: "unavailable" };
        try {
          const result = await hub.controlAgent(agentId, "unwrap");
          // unwrap is a Tier 1 action ⇒ always the enqueued-result branch,
          // never the synchronous control-result branch.
          if ("inbox_item_id" in result) {
            return { ok: true, result };
          }
          // Defensive: a non-Tier-1 result for unwrap should not happen.
          return { ok: false, reason: "unsupported" };
        } catch (err) {
          if (err instanceof HubNotFoundError) return { ok: false, reason: "not_found" };
          if (err instanceof HubCapabilityError) return { ok: false, reason: "unsupported" };
          // HubLocalOnlyError (foreign identity) and validation errors map
          // to not-found: the agent is not addressable by this operator.
          return { ok: false, reason: "not_found" };
        }
      },
      // Phase S1: protect execution routes to the split-process supervisor.
      // When no bridge is wired, the dep is omitted and protect fails closed
      // with 503 (the handler's no-supervisor path), never a 501 oracle.
      ...(this.supervisorBridge
        ? {
            launchProtect: (spec: {
              agentId: string;
              harness: string;
              configPath: string;
            }): Promise<ProtectLaunchOutcome> =>
              this.supervisorBridge!.launchProtect(spec),
          }
        : {}),
      idempotency: this.v1Idempotency,
    };
  }

  /**
   * Phase S1: bind (or detach with `null`) the split-process supervisor
   * bridge. The standalone process calls this once the supervisor socket is up
   * and the fortress master is resident, so the dashboard can hand the
   * supervisor a transient key over the authenticated local socket at protect
   * time. Detaching reverts protect to the fail-closed 503 path.
   */
  setSupervisorBridge(bridge: SupervisorBridge | null): void {
    this.supervisorBridge = bridge;
  }

  /**
   * Unified Protect Slice 5 S5-P: bind (or detach with `null`) the
   * exclusive-egress posture provider. The provider is produced by the
   * root-supervised provisioning/boot flow (S5-6: the arming-wiring posture
   * producer, bound by dashboard-standalone on darwin) and resolves the
   * per-agent exclusive-egress posture objects + wall-level summary. While
   * detached (today: no fine-grained agent is provisioned anywhere), every
   * posture surface behaves exactly as before. Once attached, the wall
   * posture, the feature-health panel, the hero shield, /v1/status, and the
   * CLI all apply the ONE aggregate-green capping rule through the canonical
   * builders. Detaching reverts to the unwired behavior.
   */
  setExclusiveEgressPostureProvider(
    provider:
      | (() => Promise<ExclusiveEgressStatus | null> | ExclusiveEgressStatus | null)
      | null,
  ): void {
    this._exclusiveEgressPostureProvider = provider;
  }

  /**
   * Resolve the S5-P exclusive-egress posture provider FAIL-CLOSED: absent
   * provider -> null (no fine-grained agent; no cap); a provider that THROWS
   * -> `failedExclusiveEgressStatus` (caps green). Shared by every dashboard
   * consumer (posture routes deps, /v1/status, the hero-shield aggregator) so
   * all surfaces resolve identically and none can silently green through a
   * failed posture read.
   */
  private async resolveExclusiveEgressPosture(): Promise<ExclusiveEgressStatus | null> {
    const provider = this._exclusiveEgressPostureProvider;
    if (!provider) return null;
    try {
      return await provider();
    } catch (err) {
      return failedExclusiveEgressStatus(
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  /**
   * Resolve the daemon operator identity's Ed25519 public key (32 bytes), or
   * null when none is configured. Shared by the durable session-attestation
   * verifier (PR-A3), the agents OPERATOR_SIGNED write path (PR-A2), and the
   * federation admin endpoints (PR-A3) so all three trace to ONE operator key.
   *
   * Prefers the HUB-BOUND identity's key over the process default: the hub
   * lists/controls agents for `v11Bindings.identityId`, so if the default
   * identity later changes, a write signed by the new default must not act on
   * the old identity's agents (multi-identity isolation). But
   * `v11Bindings.identityId` may be a SYNTHETIC fortress-scoped id
   * (`fortress:<path>`) on a fresh standalone boot, where the real signing
   * identity only exists as the default - there `get()` returns undefined and
   * we fall back to the default so valid signed requests are not rejected. The
   * hub is single-operator in v1.1, so the fallback does not widen authority.
   */
  private resolveOperatorPublicKey(): Uint8Array | null {
    const hubIdentityId = this.v11Bindings?.identityId;
    const identity =
      (hubIdentityId ? this.identityManager?.get(hubIdentityId) : undefined) ??
      this.identityManager?.getDefault();
    if (!identity?.public_key) return null;
    try {
      const key = fromBase64url(identity.public_key);
      return key.length === 32 ? key : null;
    } catch {
      return null;
    }
  }

  /**
   * Federation PR-A3: bind (or detach with `null`) the fortress materials the
   * join ceremony needs. The console/mesh boot path supplies these once the
   * fortress master secret is unlocked; until then federation is unprovisioned
   * and every authorize path fails closed. Detaching also clears the enabled
   * flag (a federation with no materials cannot be enabled).
   */
  setFederationContext(ctx: FederationContext | null): void {
    this.stopFederationCertificateAutoRenewal();
    this.stopFleetLicenseReResolve();
    if (ctx !== null) {
      assertNonIssuerContextHasNoIssuerAuthority(ctx);
    }
    this._federationContext = ctx;
    if (ctx === null) {
      this._federationEnabled = false;
      this._federationState = {
        ...this._federationState,
        revoked: new Set<string>(),
        evictionMaxSerial: 0,
        operatorPolicy: null,
        appliedPolicyVersions: new Map<string, FederationAppliedPolicyVersion>(),
      };
      return;
    }
    this.reprojectFederationRevocations(ctx);
    if (ctx.revokedRootPubkeys instanceof Set) {
      for (const pubkey of ctx.revokedRootPubkeys) {
        this._federationRevokedRoots.add(pubkey);
      }
    }
    if (typeof ctx.highestRevocationSerial === "number") {
      this._federationHighestRevocationSerial = Math.max(
        this._federationHighestRevocationSerial,
        ctx.highestRevocationSerial,
      );
    }
    ctx.isNodeRevoked = (nodeId) => this.isFederationNodeRevoked(nodeId);
    this._federationRenewal = startFederationNodeCertificateAutoRenewal({
      renewNow: () => this.renewLocalFederationNodeCertificate(),
      config: ctx.nodeCertificateRenewal,
    });
    this.startFleetLicenseReResolve();
  }

  /**
   * Fleet control plane PR-3: start the scheduled license re-resolve timer. It
   * runs one pass immediately (so a boot into an expired/revoked/over-cap state
   * is reconciled at once) and then hourly. Idempotent: a second call clears the
   * prior timer first. The timer is `unref`'d so it never keeps the process
   * alive on its own.
   */
  private startFleetLicenseReResolve(): void {
    this.stopFleetLicenseReResolve();
    // Fire once now, then on the interval. Never let a tick throw escape.
    void this.runFleetLicenseReResolveTick();
    this._fleetReResolveTimer = setInterval(() => {
      void this.runFleetLicenseReResolveTick();
    }, DashboardApprovalChannel.FLEET_RE_RESOLVE_INTERVAL_MS);
    this._fleetReResolveTimer.unref?.();
  }

  private stopFleetLicenseReResolve(): void {
    if (this._fleetReResolveTimer !== null) {
      clearInterval(this._fleetReResolveTimer);
      this._fleetReResolveTimer = null;
    }
  }

  /**
   * One scheduled license re-resolve pass, FAIL-CLOSED and NON-THROWING. Reads
   * the durable roster, re-verifies the license (expiry + revocation), applies
   * auto-capture, and logs any transition via {@link runFleetReResolve}. A pass
   * with no unlocked custody (locked/standalone) is a no-op. Never touches a
   * node's wall.
   */
  private runFleetLicenseReResolveTick(): Promise<void> {
    // Serialize: if a tick is already running, return the SAME promise so a second
    // caller (the hourly interval firing while a push-triggered tick is mid-flight,
    // or vice versa) awaits it rather than racing the absent-record capture guard.
    // Cleared in `finally` so a thrown tick never wedges the latch.
    if (this._fleetReResolveInFlight !== null) {
      return this._fleetReResolveInFlight;
    }
    const run = this.runFleetLicenseReResolveTickOnce().finally(() => {
      this._fleetReResolveInFlight = null;
    });
    this._fleetReResolveInFlight = run;
    return run;
  }

  /**
   * The body of one re-resolve pass. NEVER call this directly except through the
   * serializing {@link runFleetLicenseReResolveTick} wrapper - calling it bare
   * reopens the concurrent-capture race the latch closes.
   */
  private async runFleetLicenseReResolveTickOnce(): Promise<void> {
    try {
      const storage = this.storage;
      const masterKey = this.shrOpts?.masterKey;
      if (!storage || !masterKey) return;
      const issuerPublicKey =
        this.resolveFleetIssuerPublicKey() ?? new Uint8Array(32);

      let rosterView: ReResolveRosterView = {
        available: false,
        admittedCount: 0,
        orderedNodeIds: [],
      };
      try {
        const roster = buildFleetRoster(this.buildV1FederationDeps(), {
          evictionSerial: this._federationState.evictionMaxSerial,
          operatorPolicy: this._federationState.operatorPolicy,
        });
        rosterView = {
          available: roster.available,
          admittedCount: roster.summary.admitted,
          orderedNodeIds: roster.nodes.map((n) => n.node_id),
        };
      } catch {
        // A roster-build hiccup leaves the safe empty view (no auto-capture, no
        // false drops); the next tick re-attempts.
      }

      const result = await runFleetReResolve({
        storage,
        master: masterKey,
        issuerPublicKey,
        now: Math.floor(Date.now() / 1000),
        roster: rosterView,
        prior: this._fleetPriorCap,
      });
      this._fleetPriorCap = {
        tier: result.cap.tier,
        maxNodes: result.cap.maxNodes,
      };
    } catch {
      // The re-resolve pass is contracted not to throw; guard anyway so a tick
      // failure is a no-op, never a crash and never a silent grant.
    }
  }

  /**
   * Operator opt-in for M-of-N guardian sign-off on the /v1/federation/revoke
   * (kill) path. Pass a {@link GuardianRevocationRequirement} (the pinned,
   * fortress-master-signed guardian roster) to REQUIRE an M-of-N guardian quorum
   * before any node eviction is minted; pass `null` to DISABLE the requirement
   * and restore the legacy single-operator revoke path. This is an additive
   * precondition only: it never relaxes the existing operator-signature gate on
   * revoke.
   *
   * This is now a THIN ADAPTER over the single chokepoint
   * {@link commitGuardianRequirementTransition} - it builds an `operator_set`
   * transition and hands it to the one mutator. All authorization, latch, and
   * roster/lowered-record verification happen in the pure
   * {@link authorizeGuardianRequirementTransition} the chokepoint calls; this
   * method contains NO direct writes to the coupled fields.
   *
   * F1 (the disable-gate): an increase (enable, or raise effective M) and a
   * noop (equal-M re-pin) are operator-only; a decrease (disable, or lower
   * effective M) REQUIRES a valid {@link GuardianDisableAuthorization} (a
   * master-key instant authorization or an M-of-N guardian quorum over the
   * CURRENT effective roster). The one behavioral change vs. the pre-chokepoint
   * setter: a `set(null)` against a LATCHED-INVALID fortress is now classified
   * as a DECREASE (a real, if unverifiable, guard is being torn down) and
   * demands that authorization, closing fail-open #1.
   *
   * Lowering the effective M (`requirement.loweredThreshold` present) rides in a
   * sibling master-signed record; the roster's signed body is NEVER mutated
   * (INV-B), so the roster's signature stays valid across reboot and the
   * lowering carries its own reboot verification (closing fail-open #2).
   */
  async setFederationGuardianRevocationRequirement(
    requirement: GuardianRevocationRequirement | null,
    authorization?: GuardianDisableAuthorization | null,
  ): Promise<void> {
    await this.commitGuardianRequirementTransition({
      kind: "operator_set",
      next: requirement,
      auth: authorization ?? null,
      loweredThreshold: requirement?.loweredThreshold ?? null,
    });
  }

  /**
   * THE SINGLE CHOKEPOINT. The ONLY writer of the four coupled guardian fields
   * (`_federationGuardianRevocationRequirement`,
   * `_federationGuardianRevocationRequirementInvalid` (the latch),
   * `_federationGuardianRevocationRequirementGeneration`,
   * `_federationGuardianDisableNonce`) plus `_federationGuardianBreakGlass` on
   * the completion path. Every public mutation and every latch transition flows
   * through here. Strict order:
   *
   *   1. READ the current live state + latch + pinned master + fortress id
   *      (no writes yet).
   *   2. CLASSIFY + AUTHORIZE (pure): {@link authorizeGuardianRequirementTransition}.
   *      Fail-closed - any missing auth / verification failure / ambiguity
   *      throws {@link GuardianDisableGateRefusedError} with NO state change
   *      (and, for a refused decrease, a loud audit).
   *   3. SNAPSHOT all coupled fields for rollback.
   *   4. APPLY the effect (single synchronous block - the atomic mutation).
   *   5. AUDIT the intent (before persist, so it is on the record even if the
   *      write fails).
   *   6. PERSIST; on throw, ROLL BACK every coupled field, re-audit, re-throw.
   *
   * INV-A: the latch clears ONLY by installing a positively-verified roster,
   * NEVER by removing the requirement - except the OR-3 carve-out (a
   * master-signed disable positively authorizes the absence and clears it).
   */
  private async commitGuardianRequirementTransition(
    t: GuardianRequirementTransition,
  ): Promise<void> {
    // 1. READ (no writes).
    const state: GuardianRequirementState = {
      requirement: this._federationGuardianRevocationRequirement,
      latchInvalid: this._federationGuardianRevocationRequirementInvalid,
      pinnedMaster: this._federationContext?.pinnedMasterPubkey ?? null,
      fortressId: this._federationContext?.fortressId ?? null,
      syncStateUnavailable: this._federationSyncStateUnavailable,
      nextDisableNonce: this._federationGuardianDisableNonce + 1,
      // Finding #5: thread the superseded-lowering high-water so the authorizer
      // rejects a below-floor lowered record on EVERY runtime install, matching
      // the boot-rehydrate floor check.
      guardianLoweredHighWater: this._federationGuardianLoweredHighWater,
    };

    // 2. AUTHORIZE (pure).
    const commit = authorizeGuardianRequirementTransition(state, t);
    if (!commit.ok) {
      // A refused DECREASE is loudly audited (the pre-chokepoint behavior).
      if (
        commit.reason === "guardian_disable_authorization_required" ||
        commit.reason === "federation_sync_state_unavailable" ||
        commit.reason === "lowered_threshold_invalid"
      ) {
        const intent =
          t.kind === "operator_set" && t.next !== null ? "lower" : "disable";
        const targetM =
          t.kind === "operator_set" && t.next !== null
            ? effectiveThresholdM(t.next)
            : null;
        await this.auditLog?.appendCritical({
          layer: "l2",
          operation: "federation_guardian_disable_quorum_refused",
          identity_id: "dashboard",
          result: "failure",
          details: {
            intent,
            target_m: targetM,
            attempted_nonce: state.nextDisableNonce,
            reason: commit.detail,
          },
        });
      }
      throw new GuardianDisableGateRefusedError(commit.reason, commit.detail);
    }
    const effect: GuardianRequirementEffect = commit.effect;

    // 3. SNAPSHOT for rollback.
    const priorRequirement = this._federationGuardianRevocationRequirement;
    const priorInvalid = this._federationGuardianRevocationRequirementInvalid;
    const priorGeneration = this._federationGuardianRevocationRequirementGeneration;
    const priorDisableNonce = this._federationGuardianDisableNonce;
    const priorLoweredHighWater = this._federationGuardianLoweredHighWater;
    const priorBreakGlass = this._federationGuardianBreakGlass;

    // 4. APPLY (atomic mutation - single synchronous block).
    this._federationGuardianRevocationRequirement = effect.requirement;
    // INV-A: the latch clears ONLY by installing a positively-verified roster
    // (effect.clearsLatch, set by the authorizer for enable/raise/repin
    // recovery), OR by the OR-3 master-signed-disable carve-out
    // (effect.masterAuthorizedNull). Every other transition leaves the latch
    // as-is: a non-master `set(null)` NEVER clears it (fail-open #1 closed).
    if (effect.clearsLatch || effect.masterAuthorizedNull) {
      this._federationGuardianRevocationRequirementInvalid = false;
    }
    // Bump the monotonic generation on EVERY committed transition so a stale
    // cross-process writer (the rotate-root CLI) can never clobber this change
    // in the durable-store merge.
    this._federationGuardianRevocationRequirementGeneration = priorGeneration + 1;
    if (effect.burnedNonce !== null) {
      // Burn the nonce (a decrease/completion): this exact authorization can
      // never be replayed for a later disable/lower.
      this._federationGuardianDisableNonce = Math.max(
        this._federationGuardianDisableNonce,
        effect.burnedNonce,
      );
    }
    // FIX 1: when this transition SUPERSEDES a prior lowered record (a raise/
    // re-pin that drops it, or a decrease that replaces it), advance the
    // DEDICATED lowered high-water past that record's nonce so a reboot rejects
    // its re-injection. Distinct from the general disable-nonce burn above: this
    // floor does NOT advance on a break-glass initiate, so a lowered fortress
    // that arms break-glass and reboots mid-countdown is not falsely rejected.
    if (effect.supersedesLoweredNonce !== null) {
      this._federationGuardianLoweredHighWater = Math.max(
        this._federationGuardianLoweredHighWater,
        effect.supersedesLoweredNonce,
      );
    }
    // Break-glass completion additionally clears the in-flight countdown here
    // (the ONE place besides veto/cancel that touches it), under the same
    // generation bump.
    if (t.kind === "break_glass_complete") {
      this._federationGuardianBreakGlass = null;
    }

    // 5. AUDIT the intent (before persist), then 6. PERSIST - BOTH inside the
    // rollback try (FIX 3 / P1): an audit-append throw AFTER the mutation was
    // applied must roll back every coupled field, exactly like a persist throw,
    // so a throw can never leave live state weakened-but-not-durably-committed.
    // Audit-before-persist ordering is preserved so intent is on the record even
    // if the durable write later fails.
    const operation = this.guardianTransitionAuditOperation(t, effect);
    try {
      await this.auditLog?.appendCritical({
        layer: "l2",
        operation,
        identity_id: "dashboard",
        result: "success",
        details: {
          enabled: effect.requirement !== null,
          transition: effect.classification,
          generation: this._federationGuardianRevocationRequirementGeneration,
          ...(effect.burnedNonce !== null ? { disable_nonce: effect.burnedNonce } : {}),
          ...(effect.requirement !== null
            ? {
                roster_version: effect.requirement.roster.version,
                guardian_m: effect.requirement.roster.m,
                guardian_effective_m: effectiveThresholdM(effect.requirement),
                guardian_n: effect.requirement.roster.n,
              }
            : {}),
        },
      });
      // Finding #2 (P0) write-ordering: write the tamper-evident "ever-
      // established" sentinel BEFORE the record persist on any transition that
      // installs OR retains a non-null requirement. The pre-fix order (record
      // first, sentinel second) left a crash window in the DANGEROUS state:
      // record-present + sentinel-absent, where a later single-file delete of the
      // record boots UN-latched (the sentinel that would have caught it was never
      // written), restoring single-operator kill. With the sentinel first, the
      // only interrupted state is sentinel-present + record-absent, which the
      // hydrate path already latches fail-closed. The sentinel is grow-only and
      // idempotent (fixed bytes), so writing it before a persist that later throws
      // is safe: the transition rolls back its live fields in the catch below, and
      // a stale sentinel with no record simply latches until the operator re-pins.
      // Kept inside the same try/rollback so a sentinel-write throw still rolls
      // back the transition.
      if (effect.requirement !== null) {
        await this._federationSyncStateStore?.markGuardianRequirementEstablished();
      }
      await this.persistFederationSyncState();
    } catch (err) {
      this._federationGuardianRevocationRequirement = priorRequirement;
      this._federationGuardianRevocationRequirementInvalid = priorInvalid;
      this._federationGuardianRevocationRequirementGeneration = priorGeneration;
      this._federationGuardianDisableNonce = priorDisableNonce;
      this._federationGuardianLoweredHighWater = priorLoweredHighWater;
      this._federationGuardianBreakGlass = priorBreakGlass;
      // The state rollback above is the load-bearing part; the failure audit is
      // best-effort. If the audit subsystem is itself the thing that threw (FIX
      // 3), do not let its re-throw mask the original error or the rollback -
      // swallow a secondary audit failure and re-throw the ORIGINAL `err`.
      try {
        await this.auditLog?.appendCritical({
          layer: "l2",
          operation: "federation_guardian_revocation_requirement_persist_failed",
          identity_id: "dashboard",
          result: "failure",
          details: {
            attempted_enabled: effect.requirement !== null,
            rolled_back_to_enabled: priorRequirement !== null,
            rolled_back_generation: priorGeneration,
          },
        });
      } catch {
        // best-effort failure audit; original error is authoritative
      }
      throw err;
    }
  }

  /**
   * The critical-audit operation string for a committed guardian-requirement
   * transition, preserving the exact operation names the pre-chokepoint call
   * sites emitted so the audit surface + posture board are unchanged.
   */
  private guardianTransitionAuditOperation(
    t: GuardianRequirementTransition,
    effect: GuardianRequirementEffect,
  ): string {
    if (t.kind === "break_glass_complete") {
      return "federation_guardian_break_glass_completed";
    }
    if (effect.authMethod === "master") {
      return "federation_guardian_disable_master_authorized";
    }
    if (effect.authMethod === "quorum") {
      return "federation_guardian_disable_quorum_authorized";
    }
    return effect.requirement === null
      ? "federation_guardian_revocation_requirement_disabled"
      : "federation_guardian_revocation_requirement_set";
  }

  /**
   * F1 E1: the nonce a NEW disable/lower authorization (quorum OR master-key)
   * must target. Guardians/the master key sign over `nextFederationGuardianDisableNonce()`
   * BEFORE the operator calls {@link setFederationGuardianRevocationRequirement};
   * on success that exact nonce burns and this getter advances past it.
   */
  nextFederationGuardianDisableNonce(): number {
    return this._federationGuardianDisableNonce + 1;
  }

  /**
   * F1: the deep, non-master, non-quorum escape hatch. Starts a loud, durable,
   * guardian-vetoable countdown that DISABLES the current guardian revocation
   * requirement if it completes unvetoed. Operator-only, only from IDLE (no
   * in-flight break-glass), only when the current requirement is non-null, and
   * only when the F3 sync-state latch is clear (same latch check as the instant
   * path - we cannot tear down a guard whose state we could not trust on boot).
   * `delayMs` defaults to {@link DEFAULT_BREAK_GLASS_DELAY_MS} (72h) and is
   * clamped to the hard 24h floor (`MIN_BREAK_GLASS_DELAY_MS`).
   *
   * DISABLE-ONLY (OR-1, Erik-ratified 2026-07-05): break-glass is the "no
   * master, no quorum" posture, so at completion there is NO signing authority
   * present to mint a reboot-verifiable lowered-M record. A break-glass `lower`
   * would therefore produce a lowered-M that self-invalidates on reboot (the
   * original fail-open #2). It is also redundant - if you can wait 72h to lower,
   * you can wait 72h to disable, and disable is the genuine "I am wedged"
   * escape. So `intent: "lower"` is REFUSED; only `disable` proceeds. Quorum-
   * lower and master-lower (which DO have a signing authority present) keep the
   * lowered record via the instant setter path.
   */
  async initiateFederationGuardianBreakGlass(
    intent: "disable" | "lower",
    targetM: number | null,
    delayMs: number = DEFAULT_BREAK_GLASS_DELAY_MS,
  ): Promise<void> {
    // OR-1: break-glass is disable-only. A lower is refused BEFORE any state
    // read so the disable-only restriction cannot silently regress (T-6).
    if (intent !== "disable") {
      throw new GuardianDisableGateRefusedError(
        "break_glass_disable_only",
        "break-glass is disable-only: it cannot lower the effective M (there is no signing authority present in the no-master no-quorum posture to mint a reboot-verifiable lowered-M record). Use the master-key or M-of-N quorum instant path to lower.",
      );
    }
    if (
      this._federationSyncStateUnavailable ||
      this._federationGuardianRevocationRequirementInvalid
    ) {
      throw new GuardianDisableGateRefusedError(
        "federation_sync_state_unavailable",
        "the durable federation sync-state is unavailable or unverified; cannot initiate break-glass",
      );
    }
    const current = this._federationGuardianRevocationRequirement;
    if (current === null) {
      throw new GuardianDisableGateRefusedError(
        "no_requirement_configured",
        "no guardian revocation requirement is configured; there is nothing to disable",
      );
    }
    if (this._federationGuardianBreakGlass !== null) {
      throw new GuardianDisableGateRefusedError(
        "break_glass_already_armed",
        "a break-glass countdown is already in flight for this fortress; cancel it before initiating another",
      );
    }

    const priorGeneration = this._federationGuardianRevocationRequirementGeneration;
    const priorBreakGlass = this._federationGuardianBreakGlass;
    const priorDisableNonce = this._federationGuardianDisableNonce;

    const nextNonce = this._federationGuardianDisableNonce + 1;
    const { initiatedAt, completesAt, delayMs: clampedDelayMs } =
      computeBreakGlassCompletion(Date.now(), delayMs);
    const state: BreakGlassState = {
      nonce: nextNonce,
      intent,
      targetM,
      initiatedAt,
      completesAt,
      delayMs: clampedDelayMs,
    };

    // H1 fix: bump the shared generation in the SAME set as the break-glass
    // mutation, exactly like the setter does for the requirement itself, so
    // the sub-object and the generation integer can never decouple across a
    // rotate-root merge.
    this._federationGuardianRevocationRequirementGeneration = priorGeneration + 1;
    this._federationGuardianBreakGlass = state;
    this._federationGuardianDisableNonce = nextNonce;

    await this.auditLog?.appendCritical({
      layer: "l2",
      operation: "federation_guardian_break_glass_initiated",
      identity_id: "dashboard",
      result: "success",
      details: {
        intent,
        target_m: targetM,
        nonce: nextNonce,
        initiated_at: initiatedAt,
        completes_at: completesAt,
        delay_ms: clampedDelayMs,
        generation: this._federationGuardianRevocationRequirementGeneration,
      },
    });

    try {
      await this.persistFederationSyncState();
    } catch (err) {
      this._federationGuardianRevocationRequirementGeneration = priorGeneration;
      this._federationGuardianBreakGlass = priorBreakGlass;
      this._federationGuardianDisableNonce = priorDisableNonce;
      await this.auditLog?.appendCritical({
        layer: "l2",
        operation: "federation_guardian_break_glass_persist_failed",
        identity_id: "dashboard",
        result: "failure",
        details: { attempted_nonce: nextNonce, stage: "initiate" },
      });
      throw err;
    }
    this.armFederationGuardianBreakGlassPoll();
  }

  /**
   * F1 E1: a single guardian (any 1-of-N in the current pinned roster) vetoes
   * the in-flight break-glass countdown. One valid signature is sufficient
   * (the deliberate asymmetry: easy to stop a teardown, hard to perform one).
   * On success the countdown is aborted, the nonce burns (so the SAME
   * authorization can never be replayed to re-arm), and the requirement is
   * left UNCHANGED.
   */
  async vetoFederationGuardianBreakGlass(
    approval: unknown,
  ): Promise<BreakGlassVetoDecision> {
    const state = this._federationGuardianBreakGlass;
    const current = this._federationGuardianRevocationRequirement;
    if (state === null || current === null) {
      return {
        vetoed: false,
        reason: "guardian_signoff_invalid",
        detail: "no break-glass countdown is currently armed",
      };
    }
    const decision = evaluateGuardianBreakGlassVeto({
      requirement: current,
      fortressId: current.roster.fortress_id,
      disableNonce: state.nonce,
      approval,
    });
    if (!decision.vetoed) {
      await this.auditLog?.appendCritical({
        layer: "l2",
        operation: "federation_guardian_break_glass_veto_refused",
        identity_id: "dashboard",
        result: "failure",
        details: { nonce: state.nonce, reason: decision.reason, detail: decision.detail },
      });
      return decision;
    }
    await this.terminateFederationGuardianBreakGlass({
      outcome: "vetoed",
      guardianId: decision.guardianId,
    });
    return decision;
  }

  /**
   * F1 E1: operator-only abort of the in-flight break-glass countdown. This is
   * how an operator whose guardians (or master key) came back online abandons
   * the slow path and instead uses the instant quorum/master-key path. Same
   * effect as a veto (nonce burns, requirement unchanged) but attributed to the
   * operator rather than a guardian.
   */
  async cancelFederationGuardianBreakGlass(): Promise<void> {
    if (this._federationGuardianBreakGlass === null) {
      throw new GuardianDisableGateRefusedError(
        "break_glass_not_armed",
        "no break-glass countdown is currently armed",
      );
    }
    await this.terminateFederationGuardianBreakGlass({ outcome: "cancelled" });
  }

  /**
   * F1: terminal-transition helper for veto/cancel/complete.
   *
   *   - `"completed"` routes through the single chokepoint
   *     {@link commitGuardianRequirementTransition} as a
   *     `break_glass_complete` transition, so the requirement/latch mutation is
   *     applied by the ONE mutator (never a second direct write). Break-glass is
   *     DISABLE-ONLY (OR-1: lower is refused at initiate), so completion always
   *     installs null.
   *   - `"vetoed"` / `"cancelled"` leave the requirement + latch UNCHANGED; they
   *     only clear the break-glass state and burn the nonce, so they keep their
   *     own break-glass-only terminal path (they do NOT route through the
   *     requirement chokepoint). H1 fix preserved: the generation is bumped in
   *     the SAME set as clearing the break-glass state.
   */
  private async terminateFederationGuardianBreakGlass(params: {
    outcome: "vetoed" | "cancelled" | "completed";
    guardianId?: string;
  }): Promise<void> {
    const state = this._federationGuardianBreakGlass;
    if (state === null) return;
    this.stopFederationGuardianBreakGlassPoll();

    if (params.outcome === "completed") {
      // Defensive: break-glass is disable-only (a lower is refused at initiate),
      // so any armed countdown must carry intent "disable". Reject a lingering
      // "lower" state rather than silently completing it (OR-1 regression guard).
      if (state.intent !== "disable") {
        this.armFederationGuardianBreakGlassPoll();
        return;
      }
      // Route the requirement/latch mutation through the ONE chokepoint. The
      // chokepoint bumps the generation, burns the nonce, clears the break-glass
      // state (t.kind === "break_glass_complete"), audits, and persists (with
      // rollback on failure). On a persist failure it throws AFTER re-arming
      // nothing, so we re-arm the poll here to preserve the "never silently
      // stuck armed" guarantee.
      try {
        await this.commitGuardianRequirementTransition({
          kind: "break_glass_complete",
          intent: "disable",
          targetM: state.targetM,
        });
      } catch {
        // The chokepoint already rolled back the coupled fields (including the
        // break-glass state back to ARMED) and audited the failure; re-arm the
        // poll so completion retries on the next tick.
        this.armFederationGuardianBreakGlassPoll();
      }
      return;
    }

    // veto / cancel: break-glass-only terminal path. The requirement + latch are
    // UNCHANGED; only the break-glass state clears and the nonce burns.
    const priorGeneration = this._federationGuardianRevocationRequirementGeneration;
    const priorBreakGlass = state;
    const priorDisableNonce = this._federationGuardianDisableNonce;

    this._federationGuardianRevocationRequirementGeneration = priorGeneration + 1;
    this._federationGuardianBreakGlass = null;
    this._federationGuardianDisableNonce = Math.max(
      this._federationGuardianDisableNonce,
      state.nonce,
    );

    const operation =
      params.outcome === "vetoed"
        ? "federation_guardian_break_glass_vetoed"
        : "federation_guardian_break_glass_cancelled";
    await this.auditLog?.appendCritical({
      layer: "l2",
      operation,
      identity_id: params.guardianId ?? "dashboard",
      result: "success",
      details: {
        nonce: state.nonce,
        intent: state.intent,
        target_m: state.targetM,
        generation: this._federationGuardianRevocationRequirementGeneration,
        ...(params.guardianId ? { guardian_id: params.guardianId } : {}),
      },
    });

    try {
      await this.persistFederationSyncState();
    } catch (err) {
      this._federationGuardianRevocationRequirementGeneration = priorGeneration;
      this._federationGuardianBreakGlass = priorBreakGlass;
      this._federationGuardianDisableNonce = priorDisableNonce;
      await this.auditLog?.appendCritical({
        layer: "l2",
        operation: "federation_guardian_break_glass_persist_failed",
        identity_id: "dashboard",
        result: "failure",
        details: { nonce: state.nonce, stage: params.outcome },
      });
      // Re-arm the poll: the break-glass was rolled back to ARMED and the poll
      // was stopped above; keep the countdown alive so it is never silently
      // stuck (the caller sees the throw and may retry the SAME veto/cancel).
      this.armFederationGuardianBreakGlassPoll();
      throw err;
    }
  }

  /**
   * F1 E1: (re)arm the in-process poll that drives break-glass completion.
   * There is no durable OS-level scheduler in this codebase (mirrors
   * `startFederationNodeCertificateAutoRenewal`): each tick re-checks the
   * DURABLE `completesAt` against the current time, so a missed tick, a
   * restart, or a slow interval can only ever DELAY completion, never shorten
   * it. Call on initiate AND on boot rehydrate (so a countdown armed before a
   * restart resumes from its persisted `completesAt`, never reset, never
   * cancelled, and never requiring guardian input to re-arm).
   */
  private armFederationGuardianBreakGlassPoll(
    intervalMs = FEDERATION_BREAK_GLASS_POLL_INTERVAL_MS,
  ): void {
    this.stopFederationGuardianBreakGlassPoll();
    const tick = (): void => {
      void this.tickFederationGuardianBreakGlass();
    };
    const timer = setInterval(tick, intervalMs);
    timer.unref?.();
    this._federationBreakGlassPoll = timer;
    // Fire an immediate tick too so a boot re-arm with an ALREADY-elapsed
    // completesAt (the daemon was down past the deadline) completes promptly
    // rather than waiting a full interval.
    tick();
  }

  private stopFederationGuardianBreakGlassPoll(): void {
    if (this._federationBreakGlassPoll !== null) {
      clearInterval(this._federationBreakGlassPoll);
      this._federationBreakGlassPoll = null;
    }
  }

  /**
   * F1 E1: one poll tick. Emits the periodic heartbeat audit while armed (so a
   * suppressed audit trail leaves a detectable gap), and applies completion
   * ONLY when the countdown has durably elapsed AND the F3 latch is clear. A
   * latched/unavailable sync-state record does NOT auto-complete (M2 fix): the
   * requirement stays as it was, fail-closed, and the poll keeps running so it
   * can complete once the operator clears the latch (e.g. via a re-pin, which
   * recovers the F3 latch on the increase path).
   */
  private async tickFederationGuardianBreakGlass(): Promise<void> {
    if (this._federationBreakGlassTickInFlight) return;
    this._federationBreakGlassTickInFlight = true;
    try {
      await this.tickFederationGuardianBreakGlassInner();
    } finally {
      this._federationBreakGlassTickInFlight = false;
    }
  }

  private async tickFederationGuardianBreakGlassInner(): Promise<void> {
    const state = this._federationGuardianBreakGlass;
    if (state === null) {
      this.stopFederationGuardianBreakGlassPoll();
      return;
    }
    await this.auditLog?.appendCritical({
      layer: "l2",
      operation: "federation_guardian_break_glass_tick",
      identity_id: "dashboard",
      result: "success",
      details: {
        nonce: state.nonce,
        completes_at: state.completesAt,
        elapsed: breakGlassElapsed(state, Date.now()),
      },
    });
    if (!breakGlassElapsed(state, Date.now())) return;
    if (
      this._federationSyncStateUnavailable ||
      this._federationGuardianRevocationRequirementInvalid
    ) {
      // Fail closed: do NOT complete while the durable record is unavailable
      // or the requirement failed to re-verify. Stay COUNTDOWN; the next tick
      // (or the operator recovering the latch) will re-evaluate.
      return;
    }
    try {
      await this.terminateFederationGuardianBreakGlass({ outcome: "completed" });
    } catch {
      // terminateFederationGuardianBreakGlass already audited the failure and
      // re-armed the poll; swallow here so the interval callback never throws.
    }
  }

  /** True when federation materials are bound (issuer or joiner context). */
  isFederationProvisioned(): boolean {
    return this._federationContext !== null;
  }

  /**
   * Federation 3/3b P0: bind the durable peer-sync security-state store and
   * rehydrate it. Call from the boot path AFTER {@link setFederationContext}
   * (the projection it loads supersedes the empty-log reprojection
   * setFederationContext just ran). Tests / minimal rigs that never call this
   * run purely in memory with the same fail-closed semantics.
   *
   * FAIL-CLOSED (DUR-4 / CC-2): a record that is PRESENT but
   * undecryptable/unparseable (at-rest tamper/corruption) makes the load THROW.
   * We catch it, latch {@link _federationSyncStateUnavailable} so the sync paths
   * DENY (never serve on empty anti-replay + empty revocation memory), and
   * return so the daemon still boots provisioned-but-not-serving rather than
   * crashing or silently resetting. A clean load clears the latch and
   * rehydrates all four fields; an absent record (fresh fortress) loads the
   * empty/zero snapshot and serves normally.
   */
  async setFederationSyncStateStore(
    store: FederationSyncStateStore | null,
  ): Promise<void> {
    this._federationSyncStateStore = store;
    if (store === null) {
      this._federationSyncStateUnavailable = false;
      return;
    }
    await this.hydrateFederationSyncState();
  }

  /**
   * Federation 3c-2: bind the durable server-issued challenge spent-set for the
   * pre-session node-cert reissue endpoint. Minimal rigs default to an in-memory
   * store; production boot replaces it with a durable store so accepted proofs
   * cannot be replayed after restart. A present-but-corrupt record latches the
   * endpoint unavailable (fail closed) without preventing dashboard boot.
   */
  async setFederationReissueChallengeStore(
    store: FederationReissueChallengeStore | null,
  ): Promise<void> {
    this._federationReissueChallengeStore = store ?? new FederationReissueChallengeStore();
    this._federationReissueChallengeStoreUnavailable = false;
    if (store === null) return;
    try {
      await store.init();
    } catch {
      this._federationReissueChallengeStoreUnavailable = true;
    }
  }

  /**
   * Load the durable sync-state snapshot into the live in-memory fields.
   * Internal to {@link setFederationSyncStateStore}; separated for testability.
   */
  private async hydrateFederationSyncState(): Promise<void> {
    const store = this._federationSyncStateStore;
    if (store === null) return;
    // Deleted-record handling (F3). `load()` deliberately collapses an ABSENT
    // record into an empty snapshot (its FROZEN `raw === null -> empty` contract,
    // correct for a genuinely fresh fortress). But an absent record can ALSO mean
    // the record was DELETED out of band by an attacker with local storage write,
    // to silently un-revoke evicted nodes and drop a configured guardian
    // requirement. We must fail closed on the deletion case WITHOUT bricking a
    // legitimately fresh-provisioned fortress.
    //
    // Brick-safety (VERIFIED against the boot + ceremony paths): provisioning
    // (mint / join / setFederationContext) does NOT itself persist a sync-state
    // record. The FIRST persist happens on the first accepted sync, the first
    // node eviction, or the first setFederationGuardianRevocationRequirement. So
    // "provisioned + no sync-state record" is a LEGITIMATE, common state on a
    // freshly-federated fortress's first boot: it must be able to accept that
    // first sync/eviction, which itself writes the record. A blanket
    // "provisioned + absent -> latch" would DENY that first sync and brick every
    // fresh federated fortress. Therefore we do NOT treat provisioned+absent as
    // anomalous on its own.
    //
    // The signal we CAN trust is POSITIVE INDEPENDENT EVIDENCE of prior
    // federation security activity that lives OUTSIDE the deleted sync-state
    // record: the durable TRUST-ROOT record carries the revoked-root set + the
    // root-revocation serial, which setFederationContext already loaded into
    // `_federationRevokedRoots` / `_federationHighestRevocationSerial`. If that
    // independent evidence shows the fortress HAS revocation history but the
    // sync-state record is absent, the record was deleted (a fresh fortress has
    // an empty revoked-root set and a zero serial). Only THEN do we latch. This
    // never trips on a fresh fortress and never bricks the first sync.
    //
    // Documented residual: a fortress whose ONLY revocation history is NODE
    // evictions (which live solely in the deleted sync-state record, with no
    // independent trust-root witness) cannot be distinguished from fresh after a
    // deletion, so its node-revocation memory still resets to empty on that boot
    // (the pre-existing status quo). Deleting a root-revocation-bearing fortress's
    // record IS caught. Closing the node-eviction residual would require
    // provisioning to write a baseline record (a ceremony change across the mesh
    // trust-root stores, out of this fix's scope); tracked as follow-up.
    let recordPresent: boolean;
    try {
      recordPresent = await store.recordExists();
    } catch {
      // A read fault (not a clean absence) is treated as unavailable: fail
      // closed rather than mis-classify a transient backend error as "fresh".
      this._federationSyncStateUnavailable = true;
      return;
    }
    if (
      !recordPresent &&
      this.isFederationProvisioned() &&
      this.hasIndependentFederationRevocationHistory()
    ) {
      // Provisioned + record absent + independent evidence of prior revocation
      // history -> the record was DELETED. Fail closed. Do NOT touch the live
      // fields (no half-applied state); latch so every sync/revoke path denies.
      this._federationSyncStateUnavailable = true;
      return;
    }
    // FIX 2 (P0): ADD an independent deletion signal for the guardian-requirement
    // case, which the root-revocation-history heuristic above MISSES. A fortress
    // that enabled a guardian requirement but never performed a root revocation
    // has NO independent revocation history, so deleting its sync-state record
    // used to boot un-latched -> rehydrate(null) cleared the requirement -> the
    // kill hook returned null -> single-operator kill was silently restored. The
    // tamper-evident "established" sentinel closes it: if a guardian requirement
    // was EVER configured (per the MAC'd `_meta` marker) but the sync-state
    // record is now absent, the record was deleted - fail closed regardless of
    // root-revocation history. A read fault on the sentinel also fails closed.
    // Finding #6 (tamper-evident sentinel, tri-state): read the sentinel once and
    // branch on absent/established/invalid. A read fault fails closed.
    let established: { status: "absent" } | { status: "established" } | { status: "invalid" };
    try {
      established = await store.guardianRequirementEstablished();
    } catch {
      this._federationSyncStateUnavailable = true;
      return;
    }
    if (!recordPresent) {
      // Record ABSENT. Both "established" (FIX 2, the deletion signal) AND
      // "invalid" (Finding #6, a corrupted sentinel that used to read as absent
      // and boot fresh) now LATCH: with the record gone there is nothing to
      // legitimize a marker we cannot attribute to the current master, so a
      // corrupt-marker + absent-record is the attack, not a rotation. Only a
      // genuinely absent marker falls through (a fresh fortress, or a guard
      // configured before this fix which the record-present backfill below would
      // have protected on a prior boot).
      if (established.status === "established" || established.status === "invalid") {
        this._federationSyncStateUnavailable = true;
        return;
      }
    }
    let snapshot: FederationSyncStateSnapshot;
    try {
      snapshot = await store.load();
    } catch {
      // Present-but-corrupt -> fail closed. Do NOT touch the live fields (no
      // half-applied state); latch unavailability so every sync path denies.
      this._federationSyncStateUnavailable = true;
      return;
    }
    // Finding #3 (pre-upgrade backfill) + Finding #6 (record-present re-stamp).
    // We are on the RECORD-PRESENT path (load succeeded). Two record-present
    // cases need a sentinel WRITE, both idempotent and grow-only:
    //   - the durable record configures a guard (guardianRevocationRequirement
    //     !== null) but the sentinel is ABSENT: a guard was configured before
    //     this fix shipped (or a crash landed the record without the sentinel per
    //     finding #2). Backfill it now so a subsequent record-delete is caught
    //     from the NEXT boot onward.
    //   - the sentinel is INVALID under the current master while the record IS
    //     present: this is the legitimate post-rotation stale-marker case (the
    //     record proves the guard is real and current-master-decryptable), so
    //     re-stamp a clean marker rather than brick.
    // A write fault fails closed. (Backfill closes the window from the next boot
    // on; it does NOT retroactively protect a record deleted before the fortress
    // ever boots under the fixed binary. That residual is irreducible without an
    // off-host witness, identical to the epoch-witness delete-both residual.)
    if (
      (snapshot.guardianRevocationRequirement !== null &&
        established.status === "absent") ||
      established.status === "invalid"
    ) {
      try {
        await store.markGuardianRequirementEstablished();
      } catch {
        this._federationSyncStateUnavailable = true;
        return;
      }
    }
    // Finding #1 + §8: reconcile the security-load-bearing floors against the
    // external anti-rollback anchor AND the guardian audit-trail floor, and LATCH
    // fail-closed on ANY regression, BEFORE adopting the snapshot's floors. Pass
    // the established-sentinel status so the §8.6 scoped-latch rule can tell a
    // never-guarded fortress (do not brick on an unrelated audit finding) from
    // one that ever configured a guard (fail closed on a coverage finding).
    if (
      await this.reconcileGuardianAntiRollbackFloors(store, snapshot, established.status)
    ) {
      this._federationSyncStateUnavailable = true;
      return;
    }
    this._federationSyncStateUnavailable = false;
    this._federationAcceptedHighWater.clear();
    for (const [nodeId, highWater] of snapshot.acceptedHighWater) {
      this._federationAcceptedHighWater.set(nodeId, highWater);
    }
    // Never regress the outbound counter below an already-issued value.
    this._federationOutboundHighWater = Math.max(
      this._federationOutboundHighWater,
      snapshot.outboundHighWater,
    );
    // The durable revocation projection is the SOLE post-restart guarantor of
    // who is revoked (CC-2). It supersedes the empty-log reprojection: union the
    // durable revoked-set over the live one and lift the eviction-serial floor.
    const mergedRevoked = new Set(this._federationState.revoked);
    for (const nodeId of snapshot.revokedNodeIds) mergedRevoked.add(nodeId);
    // PR-A (durable fleet membership): rehydrate the node roster GROW-ONLY,
    // mirroring the revoked-set union directly above. The roster is the
    // authoritative source of the paid node-count; it was in-memory ONLY before
    // this fix (rebuilt from the unpersisted event log), so it came up EMPTY on
    // every restart and the count reset to zero. We UNION the durable roster
    // OVER the live one (which on a fresh boot is empty) so a stale/older
    // durable snapshot can never DROP a node the live state already holds, and a
    // node id present only on disk is restored. On a per-id collision we keep
    // the live entry unless the durable one carries a strictly newer
    // last_sequence (the durable state is the more-recently-synced view). The
    // active count is then this grow-only roster MINUS the grow-only revoked set
    // (a node LEAVES only by eviction/revocation), computed by the existing
    // buildFleetRoster summary.admitted path -- we do NOT recount here.
    const mergedNodes = new Map(this._federationState.nodes);
    for (const [nodeId, durableNode] of snapshot.nodes) {
      const liveNode = mergedNodes.get(nodeId);
      if (
        !liveNode ||
        durableNode.last_sync.last_sequence > liveNode.last_sync.last_sequence
      ) {
        mergedNodes.set(nodeId, durableNode);
      }
    }
    this._federationState = {
      ...this._federationState,
      revoked: mergedRevoked,
      evictionMaxSerial: Math.max(
        this._federationState.evictionMaxSerial,
        snapshot.highestEvictionSerial,
      ),
      nodes: mergedNodes,
    };
    // Slice 3c-1: rehydrate the durable revoked-ROOT projection so a compromise
    // rotate's revocation of the old root SURVIVES a restart. This is the
    // standing-weakness fix for roots: union the durable set over the live one
    // (grow-only) and lift the revocation-serial floor. _federationRevokedRoots
    // is the set every enforcement chokepoint (sync, /sync/peer, join) reads.
    for (const pubkey of snapshot.revokedRootPubkeys) {
      this._federationRevokedRoots.add(pubkey);
    }
    this._federationHighestRevocationSerial = Math.max(
      this._federationHighestRevocationSerial,
      snapshot.highestRevocationSerial,
    );
    this._federationState = {
      ...this._federationState,
      operatorPolicy: newerAppliedPolicy(
        this._federationState.operatorPolicy,
        snapshot.operatorPolicy,
      ),
      appliedPolicyVersions: mergeAppliedPolicyVersions(
        this._federationState.appliedPolicyVersions,
        snapshot.appliedPolicyVersions,
      ),
    };
    this.projectAppliedPoliciesOntoRoster();
    // FIX 1: adopt the DEDICATED superseded-lowering high-water floor BEFORE
    // rehydrate so the rehydrate check can reject a below-floor lowered record.
    // Never regress it across a restart (a Math.max floor, like every other
    // replay floor in this record). This high-water advances ONLY when a
    // lowering was actually dropped, so - unlike the general disable nonce - it
    // does NOT trip on a lowered fortress that armed break-glass mid-countdown.
    this._federationGuardianLoweredHighWater = Math.max(
      this._federationGuardianLoweredHighWater,
      snapshot.guardianLoweredHighWater,
    );
    this.rehydrateGuardianRevocationRequirement(
      snapshot.guardianRevocationRequirement,
      snapshot.guardianRevocationRequirementGeneration,
    );
    // F1: never regress the disable-gate nonce floor across a restart (same
    // treatment as every other replay floor in this record). OR-2 (build-
    // critical): fold in the LOWERED-THRESHOLD record's nonce too, so a replayed
    // old lowered-M record carrying a below-floor nonce (A3) can never be
    // accepted - the floor now covers all three nonce-bearing sub-objects
    // (guardianDisableNonce, break-glass nonce (below), and the lowered record).
    this._federationGuardianDisableNonce = Math.max(
      this._federationGuardianDisableNonce,
      snapshot.guardianDisableNonce,
      snapshot.guardianRevocationRequirement?.loweredThreshold?.body.disable_nonce ?? 0,
    );
    // Boot re-arm (8.4 / design 5.3): a break-glass armed before a restart
    // resumes from its persisted completesAt, NEVER reset, NEVER cancelled,
    // and requires no guardian input to re-arm. If the daemon was down PAST
    // the deadline, the immediate tick inside armFederationGuardianBreakGlassPoll
    // completes it promptly (still gated on the F3 latch check in the tick).
    this._federationGuardianBreakGlass = snapshot.guardianBreakGlass;
    if (snapshot.guardianBreakGlass !== null) {
      this.armFederationGuardianBreakGlassPoll();
    } else {
      this.stopFederationGuardianBreakGlassPoll();
    }
  }

  /**
   * F3 deletion-latch signal: does this fortress carry POSITIVE, INDEPENDENT
   * evidence of prior federation revocation activity that lives OUTSIDE the
   * durable sync-state record?
   *
   * The evidence is the durable TRUST-ROOT record's revoked-root projection: the
   * revoked-root set and the root-revocation serial, which setFederationContext
   * loads from the trust root (a SEPARATE at-rest record from the sync-state
   * blob). A genuinely fresh fortress has an EMPTY revoked-root set and a ZERO
   * serial; a fortress that has performed a compromise root rotation has a
   * non-empty set / non-zero serial. When that evidence is present but the
   * sync-state record is ABSENT, the sync-state record was deleted (the two
   * records cannot legitimately disagree that way), so the caller fails closed.
   * When the evidence is empty, absence is indistinguishable from a fresh
   * fortress and we do NOT latch (never brick the first sync/eviction).
   */
  private hasIndependentFederationRevocationHistory(): boolean {
    return (
      this._federationRevokedRoots.size > 0 ||
      this._federationHighestRevocationSerial > 0
    );
  }

  /**
   * F1 re-gate (§1 + §8): reconcile the security-load-bearing guardian sync-state
   * floors against BOTH the external `_meta` anti-rollback anchor (§1) AND the
   * guardian AUDIT-trail floor (§8). Returns `true` when a rollback is
   * positively detected and the caller MUST LATCH fail-closed; `false` when the
   * floors are consistent (no regression).
   *
   * The threat (§1): every guardian floor (`guardianLoweredHighWater`,
   * `guardianDisableNonce`, the requirement generation) is a `Math.max` floor
   * that lives INSIDE the same rollbackable `_federation/sync-state-v1` blob as
   * the record it gates. A KEYLESS filesystem attacker captures an OLD copy of
   * that blob and, after the operator raises the threshold back up, restores it,
   * regressing the floor to the old blob's value.
   *
   *   - The external anchor (§1) catches the SINGLE-record restore (blob alone):
   *     the anchor lives in a SEPARATE `_meta` location the blob restore does not
   *     touch, so `blob.floor < anchor.floor` is a positively-detected rollback.
   *   - The audit-trail floor (§8) catches the TWO-record restore (blob + anchor
   *     BOTH rolled back): the finding-#1 attack requires a guardian transition
   *     (the raise) between capture and restore, which increments the requirement
   *     GENERATION and is critically audited BEFORE persist. The audit trail
   *     durably remembers the highest generation reached, in a location the
   *     two-record anchor+blob restore does NOT touch, so `blob.generation <
   *     auditFloor.generation` is a positively-detected rollback.
   *
   * FAIL DIRECTION: an "invalid" (present-but-tampered) anchor latches; an
   * unreadable/failed-integrity audit read fails TOWARD latch (never toward a
   * spuriously-low floor). A forged HIGH audit entry only causes an over-latch
   * (fail-closed = safe); LOWERING the audit floor requires DELETING higher
   * guardian entries, which is audit truncation, caught separately by the audit
   * head-anchor machinery.
   *
   * NO federation->core master coupling: the store retains only
   * `derivePurposeKey(master, "federation-sync-state")`, never the raw master; the
   * anchor MACs under that purpose key, and the audit floor is a read-only
   * composition over the integrity-judged audit log the dashboard already holds.
   */
  private async reconcileGuardianAntiRollbackFloors(
    store: FederationSyncStateStore,
    snapshot: FederationSyncStateSnapshot,
    establishedStatus: "absent" | "established" | "invalid",
  ): Promise<boolean> {
    // Read the external anchor (tri-state). A present-but-tampered anchor is a
    // positively-detected tamper: latch. Absent is neutral (pre-fix / first
    // boot). A read fault is surfaced as "invalid" by the store (fail toward
    // latch).
    const anchor = await store.readGuardianAntiRollbackAnchor();
    if (anchor.status === "invalid") return true;
    const anchorFloor =
      anchor.status === "valid"
        ? {
            loweredHighWater: anchor.data.lowered_high_water,
            disableNonce: anchor.data.disable_nonce,
            generation: anchor.data.requirement_generation,
          }
        : { loweredHighWater: 0, disableNonce: 0, generation: 0 };

    // §8: derive the audit-witnessed floor over the WHOLE verified guardian audit
    // set (window-independent, §8.6 P0). Unreadable / coverage-compromised ->
    // fail TOWARD latch (returns null -> latch).
    const auditFloor = await this.deriveGuardianFloorFromAudit(establishedStatus);
    if (auditFloor === null) return true;

    // Regression detection: the on-disk blob floors must be >= both witnesses.
    // The blob floor for the generation is the persisted generation; for the
    // nonce/lowered-high-water it is the persisted snapshot fields.
    const blobLoweredHighWater = snapshot.guardianLoweredHighWater;
    const blobDisableNonce = snapshot.guardianDisableNonce;
    const blobGeneration = snapshot.guardianRevocationRequirementGeneration;

    if (
      // §1 anchor regressions.
      blobLoweredHighWater < anchorFloor.loweredHighWater ||
      blobDisableNonce < anchorFloor.disableNonce ||
      blobGeneration < anchorFloor.generation ||
      // §8 audit-floor regressions (generation is the robust primary witness;
      // the other two are best-effort reinforcement, 0 when not recoverable).
      blobGeneration < auditFloor.generation ||
      blobLoweredHighWater < auditFloor.loweredHighWater ||
      blobDisableNonce < auditFloor.disableNonce
    ) {
      return true; // positively-detected rollback -> latch fail-closed
    }
    return false;
  }

  /**
   * §8 + §8.6: derive the audit-witnessed guardian floor from the
   * INTEGRITY-VERIFIED guardian audit entries. Returns `null` when the audit
   * COVERAGE could be compromised such that a guardian entry might be hidden or a
   * higher generation removed (the caller fails TOWARD latch), and a neutral
   * `{0,0,0}` floor when there is no guardian audit history at all (no first-boot
   * false positive; mirrors the epoch-witness "absent -> neutral").
   *
   * Primary witness = the requirement GENERATION recorded on every committed
   * guardian transition (`details.generation`); it is monotonic. disable_nonce /
   * the break-glass nonce are best-effort reinforcement when recoverable.
   *
   * §8.6 P0 (WINDOW-INDEPENDENT): the read must cover the WHOLE verified chain,
   * not a bounded recent tail. The prior `query({layer:"l2", limit:1000})` sliced
   * the last 1000 l2 entries AFTER the layer filter, so on a busy l2 layer (>1000
   * l2 entries since the last guardian transition, the normal steady state) the
   * guardian raise fell out of the window and the floor collapsed to 0 with ZERO
   * findings (benign forward growth, not a truncation) -> a two-record restore
   * landed. We instead stream the ENTIRE surviving verified chain
   * ({@link AuditLog.streamVerifiedChain}, which is window-independent by
   * construction and yields each entry's chain SEQUENCE) and take the max
   * generation over ALL guardian entries. Guardian transitions are rare +
   * monotonic, so this is cheap.
   *
   * §8.6 P1 (SCOPED integrity latch): `streamVerifiedChain` throws
   * `AuditIntegrityError` in strict mode when the chain does not verify; we catch
   * it and SCOPE the fail-closed decision to findings that could hide a guardian
   * entry, rather than latching on ANY finding. We fail TOWARD latch when a
   * COVERAGE/structural finding is present (truncation / gap / anchor /
   * checkpoint), OR any finding sits at-or-above the lowest guardian entry's
   * sequence, OR a finding lacks a sequence. A benign in-place single-entry
   * corruption STRICTLY BELOW every guardian entry (with no coverage finding)
   * does NOT latch: the guardian set is complete and each guardian entry
   * individually hash-verifies, so the max generation is trustworthy. When NO
   * guardian entries are found and only a coverage finding is present, we latch
   * ONLY when the established-sentinel says a guard was ever configured (else a
   * never-guarded fortress is not bricked by an unrelated l2 finding).
   */
  private async deriveGuardianFloorFromAudit(
    establishedStatus: "absent" | "established" | "invalid",
  ): Promise<
    | { generation: number; disableNonce: number; loweredHighWater: number }
    | null
  > {
    const auditLog = this.auditLog;
    if (auditLog === null) {
      // No audit log wired (minimal in-memory rig): no audit witness to compose.
      // Neutral floor, exactly like "no guardian audit history".
      return { generation: 0, disableNonce: 0, loweredHighWater: 0 };
    }

    // Collect guardian entries WITH their chain sequence over the WHOLE verified
    // chain. `onEntry` fires only after each entry is decrypt + hash verified, so
    // a collected guardian entry's `details` are individually trustworthy even if
    // the FULL-CHAIN (coverage) check later throws. `reset` drops an abandoned
    // torn-read pass so the kept set is exactly the single accepted pass.
    let guardianEntries: Array<{
      sequence: number;
      generation: number;
      disableNonce: number;
    }> = [];
    const collect = (item: { sequence: number; entry: AuditEntry }): void => {
      // §8.7 P0 DRIFT-PROOF MATCHER (fixes the round-2 op-name coverage gap):
      // do NOT depend on a hardcoded op-name set (which omitted the veto/cancel
      // ops even though they bump + audit the committed generation, re-opening
      // finding #1). Instead, structurally witness EVERY generation-bumping
      // guardian transition, current AND future, by matching ANY audit entry
      // whose operation is prefixed `federation_guardian_`, whose result is
      // "success" (a rolled-back FAILURE never committed a generation), and that
      // carries a valid non-negative-integer committed `generation`. Every
      // guardian emit sets `generation` to the CURRENT committed value, so this
      // set's max is always <= the true committed max (never over-latches), and a
      // keyless attacker cannot forge a valid MAC'd audit entry to inflate it. A
      // non-generation-bearing entry (e.g. the break-glass tick) is skipped by the
      // generation check, so it never enters the floor.
      const entry = item.entry;
      if (!entry.operation.startsWith(GUARDIAN_AUDIT_OP_PREFIX)) return;
      if (entry.result !== "success") return;
      const details = entry.details;
      if (details === undefined) return;
      const gen = details.generation;
      if (typeof gen !== "number" || !Number.isSafeInteger(gen) || gen < 0) return;
      let disableNonce = 0;
      for (const field of ["disable_nonce", "nonce"] as const) {
        const v = details[field];
        if (typeof v === "number" && Number.isSafeInteger(v) && v > disableNonce) {
          disableNonce = v;
        }
      }
      guardianEntries.push({ sequence: item.sequence, generation: gen, disableNonce });
    };

    let findings: readonly AuditIntegrityFinding[] = [];
    try {
      await auditLog.streamVerifiedChain({
        onEntry: collect,
        reset: () => {
          guardianEntries = [];
        },
      });
    } catch (err) {
      if (err instanceof AuditIntegrityError) {
        // The chain did not verify. Keep the guardian entries the (final) pass
        // streamed and SCOPE the latch decision to `err.findings` below.
        findings = err.findings;
      } else {
        // A non-integrity failure (storage unreadable, etc.): fail toward latch.
        return null;
      }
    }

    // The floor = max generation / disable-nonce over ALL guardian entries.
    let generation = 0;
    let disableNonce = 0;
    let lowestGuardianSeq = Number.POSITIVE_INFINITY;
    for (const g of guardianEntries) {
      if (g.generation > generation) generation = g.generation;
      if (g.disableNonce > disableNonce) disableNonce = g.disableNonce;
      if (g.sequence < lowestGuardianSeq) lowestGuardianSeq = g.sequence;
    }
    const haveGuardianEntries = guardianEntries.length > 0;

    // §8.6 P1: scope the fail-closed decision to findings that could HIDE a
    // guardian entry or remove a higher generation.
    if (findings.length > 0) {
      // Guard-configured but NO guardian entry recovered from the trail while
      // findings are present: the guardian evidence itself may have been the
      // corrupted/hidden entry (a corrupted guardian entry never reaches onEntry).
      // Fail TOWARD latch. A never-guarded fortress (sentinel not established)
      // with an unrelated finding is NOT bricked (falls through to the scoped
      // per-finding checks, where a non-coverage below-only finding is benign).
      if (!haveGuardianEntries && establishedStatus === "established") {
        return null;
      }
      for (const f of findings) {
        // A coverage/structural finding can hide a guardian entry anywhere ->
        // fail toward latch.
        if (GUARDIAN_AUDIT_COVERAGE_FINDING_KINDS.has(f.kind)) {
          // Exception: when NO guardian entries exist AND the fortress never
          // configured a guard, an unrelated l2 coverage finding must not brick a
          // never-guarded fortress (neutral). (The guard-configured + no-guardian
          // case already returned null above.)
          if (!haveGuardianEntries && establishedStatus !== "established") {
            continue;
          }
          return null;
        }
        // A finding lacking a sequence cannot be proven below the guardian set ->
        // fail toward latch (conservative).
        if (f.sequence === undefined) return null;
        // A finding AT OR ABOVE the lowest guardian entry could alter/hide a
        // higher-generation guardian raise -> fail toward latch. (When there are
        // guardian entries; the no-guardian cases are handled above.)
        if (f.sequence >= lowestGuardianSeq) return null;
      }
    }

    // loweredHighWater is not directly recorded per guardian audit entry today,
    // so it stays 0 (best-effort reinforcement per §8.2). The GENERATION floor
    // alone catches the two-record restore, which is the load-bearing guarantee.
    return { generation, disableNonce, loweredHighWater: 0 };
  }

  /**
   * Restore the operator's guardian revocation requirement from the durable
   * snapshot, FAIL-CLOSED. The persisted requirement carries the
   * fortress-master-signed roster verbatim; we re-verify that signature against
   * the CURRENT pinned master before enforcing it.
   *
   *   - snapshot has NO requirement -> clear the live requirement + latch
   *     (legacy single-operator revoke; not a downgrade).
   *   - roster VERIFIES against the pinned master -> restore it and enforce.
   *   - roster DOES NOT verify (at-rest tamper, wrong fortress, or a roster
   *     stale after a legitimate master rotation) -> DO NOT restore it and DO NOT
   *     drop to single-operator kill. Latch invalid so the revoke path refuses
   *     every revocation until the operator re-pins a valid roster. Collapsing
   *     this into "no requirement" would be a silent security downgrade.
   *   - no pinned master available yet -> latch invalid (fail closed) rather than
   *     enforce an unverified requirement.
   *   - a lowered-threshold record is PRESENT but does NOT verify against the
   *     pinned master (§3.4 step 4a) -> latch invalid. A lowered record that does
   *     not verify is exactly the tamper case; it must not silently drop to
   *     `roster.m` (which would RAISE the kill threshold the operator lowered)
   *     nor be enforced unverified.
   *
   * Because the roster's signed body is NEVER mutated to represent a lowering
   * (INV-B), the roster's own signature re-verifies clean here for a lowered
   * fortress - closing fail-open #2 (the pre-fix mutated-`m` roster
   * self-invalidated on reboot).
   */
  private rehydrateGuardianRevocationRequirement(
    persisted: GuardianRevocationRequirement | null,
    persistedGeneration: number,
  ): void {
    // Always adopt the persisted generation as the floor for the live counter so
    // subsequent sets climb ABOVE the last durably-committed generation across a
    // restart. Never regress it. This holds regardless of whether the roster
    // verifies below (the generation is monotonic bookkeeping, not the value).
    this._federationGuardianRevocationRequirementGeneration = Math.max(
      this._federationGuardianRevocationRequirementGeneration,
      persistedGeneration,
    );
    if (persisted === null) {
      this._federationGuardianRevocationRequirement = null;
      this._federationGuardianRevocationRequirementInvalid = false;
      return;
    }
    const pinnedMaster = this._federationContext?.pinnedMasterPubkey ?? null;
    if (pinnedMaster === null) {
      // A requirement was persisted but we cannot verify it without the pinned
      // master. Fail closed: latch invalid so the revoke path refuses.
      this._federationGuardianRevocationRequirement = null;
      this._federationGuardianRevocationRequirementInvalid = true;
      return;
    }
    try {
      verifyGuardianRoster(persisted.roster, pinnedMaster);
    } catch {
      this._federationGuardianRevocationRequirement = null;
      this._federationGuardianRevocationRequirementInvalid = true;
      return;
    }
    // §3.4 step 4a: verify the lowered-threshold record (if present) against the
    // pinned master - domain, fortress, roster-version binding, range, signature.
    // Any failure latches invalid (a lowered record that does not verify is the
    // tamper case). Absent -> effective M = roster.m (safe default).
    if (persisted.loweredThreshold !== undefined) {
      const fortressId = this._federationContext?.fortressId ?? null;
      const decision =
        fortressId === null
          ? { valid: false as const, reason: "federation_not_provisioned" }
          : verifyLoweredThresholdAuthorization({
              authorization: persisted.loweredThreshold,
              fortressId,
              rosterVersion: persisted.roster.version,
              rosterM: persisted.roster.m,
              pinnedMaster,
            });
      if (!decision.valid) {
        this._federationGuardianRevocationRequirement = null;
        this._federationGuardianRevocationRequirementInvalid = true;
        return;
      }
      // FIX 1 (A3 replay, reboot leg): even a SIGNATURE-VALID lowered record must
      // be REFUSED when its nonce is at-or-below the dedicated superseded-
      // lowering high-water. That is the replayed, already-dropped lowering
      // (lower to M', raise back, re-inject the still-valid-signed old record):
      // the signature, roster-version, and range all still pass, so the OTHER
      // checks above let it through - only the high-water catches it. A
      // signature-valid-but-stale lowered record is the tamper case, so fail
      // closed (latch invalid); we do NOT silently drop to `roster.m` (which
      // would still honor the attacker's re-injection as a "no lowering"
      // downgrade of the operator's intent) nor accept the stale lowering.
      //
      // The comparison is `<=` because the high-water is set to the EXACT nonce
      // of a lowering that was DROPPED (not one-past it): a record whose nonce
      // equals the high-water is precisely the record that was superseded. This
      // does NOT false-reject a currently-valid lowering: the high-water only
      // ever advances to a DROPPED record's nonce, and it uses the DEDICATED
      // high-water (adopted just above), NOT the general disable nonce - so a
      // freshly-installed lowering always carries a nonce STRICTLY ABOVE the
      // high-water, and a lowered fortress that armed break-glass and rebooted
      // mid-countdown (which does NOT advance this high-water) is never rejected.
      if (
        persisted.loweredThreshold.body.disable_nonce <=
        this._federationGuardianLoweredHighWater
      ) {
        this._federationGuardianRevocationRequirement = null;
        this._federationGuardianRevocationRequirementInvalid = true;
        return;
      }
    }
    this._federationGuardianRevocationRequirement = persisted;
    this._federationGuardianRevocationRequirementInvalid = false;
  }

  /**
   * Snapshot the live federation security state for the durable store.
   *
   * This carries ONLY this daemon's own in-memory copy of the revoked-ROOT
   * projection. That copy is NOT, on its own, sufficient to preserve a revocation
   * the out-of-band `rotate-root --compromised` CLI committed while the daemon was
   * running: the daemon never learns of the CLI's write, so a high-water/eviction
   * persist built from this snapshot would, by itself, omit that revoked root. The
   * cross-process preservation is enforced ONE layer down, by
   * {@link FederationSyncStateStore} (`writeNow`): it holds a cross-process lock
   * across the WHOLE read-modify-write (so the daemon's read-modify-write cannot
   * interleave with the CLI's) and then MONOTONICALLY UNIONs the grow-only security
   * fields (revoked node ids, revoked root pubkeys, the serial floors, the per-peer
   * high-waters) over this snapshot before encrypting. So a daemon persist can
   * never clobber a CLI-committed root revocation, even under a genuine write
   * overlap; the corrected invariant is "the store's locked read-modify-write
   * preserves every committed revocation across re-persists," NOT "this snapshot
   * already contains them."
   */
  private snapshotFederationSyncState(): FederationSyncStateSnapshot {
    return {
      acceptedHighWater: new Map(this._federationAcceptedHighWater),
      outboundHighWater: this._federationOutboundHighWater,
      revokedNodeIds: new Set(this._federationState.revoked),
      highestEvictionSerial: this._federationState.evictionMaxSerial,
      revokedRootPubkeys: new Set(this._federationRevokedRoots),
      highestRevocationSerial: this._federationHighestRevocationSerial,
      operatorPolicy: this._federationState.operatorPolicy
        ? { ...this._federationState.operatorPolicy }
        : null,
      appliedPolicyVersions: new Map(
        [...this._federationState.appliedPolicyVersions].map(([nodeId, marker]) => [
          nodeId,
          { ...marker },
        ]),
      ),
      // PR-A (durable fleet membership): persist the live node roster so the
      // paid node-count survives a reboot. The store deep-clones + reduces this
      // to the minimal durable per-node fields inside the SAME AEAD record, and
      // grow-only-unions it over what is already at rest, so a persist can never
      // DROP a node the disk already knows about. The store owns the clone; we
      // hand it the live Map directly.
      nodes: new Map(this._federationState.nodes),
      // Persist the operator's guardian revocation requirement so it survives a
      // restart. Carries the fortress-master-signed roster verbatim so its
      // signature can be re-verified against the pinned master on rehydrate.
      guardianRevocationRequirement:
        this._federationGuardianRevocationRequirement,
      // Stamp the monotonic generation so the durable-store merge keeps the
      // higher-generation value; a stale cross-process writer (rotate-root CLI)
      // carrying an older generation cannot clobber this requirement.
      guardianRevocationRequirementGeneration:
        this._federationGuardianRevocationRequirementGeneration,
      // F1 E1: the disable-gate anti-replay nonce floor + the in-flight
      // break-glass state, if armed. The break-glass sub-object travels under
      // the SAME generation stamped above (H1 fix): every break-glass mutation
      // bumps that same counter in the same set, so the two can never diverge
      // across a rotate-root merge.
      guardianDisableNonce: this._federationGuardianDisableNonce,
      // FIX 1: the dedicated superseded-lowering high-water (see the field doc).
      guardianLoweredHighWater: this._federationGuardianLoweredHighWater,
      guardianBreakGlass: this._federationGuardianBreakGlass,
    };
  }

  /**
   * Persist the current federation security-state snapshot. A no-op (resolves)
   * when no durable store is wired (in-memory rigs). THROWS on a store write
   * failure so the caller can fail closed: a security-state advance MUST NOT be
   * acknowledged unless it durably committed.
   *
   * A SUCCESSFUL persist clears the {@link _federationSyncStateUnavailable}
   * latch: the record is now durably present + clean, and the live fields we
   * just wrote ARE the durable truth, so the sync/revoke paths may serve again.
   * This is the operator's recovery path out of the F3 deleted-record latch (and
   * the fresh-provisioned-but-never-persisted residual): any successful persist
   * (a revoke, an accepted high-water, or an explicit
   * setFederationGuardianRevocationRequirement re-pin) re-establishes the record.
   * It CANNOT falsely clear a present-but-corrupt latch: writeNow's own
   * read-modify-write re-reads the at-rest blob and THROWS on a corrupt record,
   * so a persist over a corrupt record fails and the latch stays set.
   */
  private async persistFederationSyncState(): Promise<void> {
    const store = this._federationSyncStateStore;
    if (store === null) return;
    await store.persist(this.snapshotFederationSyncState());
    this._federationSyncStateUnavailable = false;
  }

  /** RR-1 (Federation 3/3b P0): is this fortress-master (root) pubkey revoked? */
  private isFederationRootRevoked(masterPubkeyB64u: string): boolean {
    return this._federationRevokedRoots.has(masterPubkeyB64u);
  }

  /**
   * Fail-closed guard (DUR-4): THROW when the durable sync-state record was
   * present-but-corrupt on boot, so the sync paths that catch it deny rather
   * than operate on empty anti-replay + empty revocation memory.
   */
  private assertFederationSyncStateAvailable(): void {
    if (this._federationSyncStateUnavailable) {
      throw new Error("federation_sync_state_unavailable");
    }
  }

  // ── Fleet control plane PR-B: node-count enforcement on the daemon roster ──
  //
  // The two helpers below turn the operator's persisted license into the paid
  // node-count cap applied to the DURABLE daemon federation roster, and handle a
  // pasted-license activation. Both fail CLOSED to the community floor and touch
  // NO wall / enforcement / local-dashboard / policy-push / kill-safety path -
  // enforcement only reshapes the CENTRAL roster presentation.

  /**
   * The fail-closed COMMUNITY-floor cap: the safe result whenever custody is not
   * available in this process (no unlocked fortress → no storage/master key → no
   * possible valid paid grant) or a resolve step fails. It is the plain 5-node
   * free cap with baseline 0; `applyFleetCap` with this cap drops any nodes
   * beyond 5 from the CENTRAL roster while leaving every node's wall + local
   * surface + the policy-distribution rail untouched.
   */
  private communityFloorCap(): FleetCap {
    return {
      maxNodes: COMMUNITY_FREE_NODE_CAP,
      paid: false,
      tier: "community",
      reason: "no_license",
      graceActive: false,
    };
  }

  /**
   * Resolve the pinned issuer Ed25519 public key from the fortress's DEFAULT
   * operator identity (already loaded on this channel; no per-request disk read).
   * This is the SAME identity `sanctuary license` signs with (issuance +
   * activation both happen on the operator's own fortress), so a license the
   * operator issued verifies against it. Returns null when no operator identity
   * is bound or its stored key is malformed - the caller then fails CLOSED to the
   * community floor.
   */
  private resolveFleetIssuerPublicKey(): Uint8Array | null {
    const identity = this.identityManager?.getDefault();
    return decodeIssuerPublicKey(identity?.public_key);
  }

  /**
   * Resolve the CURRENT node-count cap for this fleet, fail-closed. Reads the
   * signed, master-MAC'd activation record and re-verifies the stored license
   * against the pinned issuer key at the CURRENT clock (so expiry/grace are
   * honored live), then maps it to a {@link FleetCap}.
   *
   * FAIL-CLOSED: any missing custody (no unlocked fortress: `storage`/`shrOpts`
   * absent), missing operator identity, or resolve error returns the plain
   * community floor - never a paid cap, never unlimited. A bug here can only ever
   * REMOVE paid management capacity, never grant it, and NEVER touches a node's
   * wall (this path has no wall/enforcement code at all). Never throws.
   */
  private async resolveFleetCap(): Promise<FleetCap> {
    const storage = this.storage;
    const masterKey = this.shrOpts?.masterKey;
    if (!storage || !masterKey) {
      // No unlocked custody in this process: no license can be authenticated →
      // community floor. (A locked/standalone daemon centrally manages the free
      // tier only; its nodes' walls are unaffected.)
      return this.communityFloorCap();
    }
    const issuerPublicKey = this.resolveFleetIssuerPublicKey();
    try {
      // No pinned issuer identity → no license can verify. `resolveActivation`
      // with a 32-zero key denies the token while STILL honoring an authenticated
      // grandfather baseline (the record's MAC is keyed to the MASTER, not the
      // issuer), so an existing >5-node fleet is not force-capped merely because
      // the operator identity is momentarily unresolved.
      const cap = await resolveActivation(
        storage,
        masterKey,
        issuerPublicKey ?? new Uint8Array(32),
        Math.floor(Date.now() / 1000),
      );
      // Fleet control plane PR-3: consult the SIGNED revocation list. A paid
      // grant whose license id is on the issuer-signed revocation list is forced
      // CLOSED to the community floor even though its token still verifies and is
      // in-window (refund / compromise / kill after activation). Two fail-closed
      // triggers (coordinator-adjudicated 2026-07-06):
      //   1. the license id IS on an authenticated list -> revoked -> Community;
      //   2. the stored list is PRESENT-but-CORRUPT (listReadable:false) ->
      //      revocation state is UNVERIFIABLE, so we must NOT keep the paid tier on
      //      the basis of a list we cannot authenticate; drop to Community too. An
      //      ABSENT list (nothing revoked) is listReadable:true and keeps the grant.
      // The earlier "corrupt-file DoS" objection is void: corrupting fleet state
      // already strips paid capacity via the activation MAC, so failing closed here
      // grants an attacker nothing, while failing open is a targeted un-revoke.
      if (cap.paid) {
        const revocation = await this.revocationStatusForActiveLicense(
          storage,
          masterKey,
          issuerPublicKey ?? new Uint8Array(32),
        );
        if (revocation.revoked || revocation.listUnverifiable) {
          // Preserve the authenticated grandfather baseline so a revoked/corrupt
          // fleet keeps its historical free count, but drop the PAID lift.
          return resolveFleetCapPure(
            { granted: false, tier: "community", reason: "invalid" },
            revocation.grandfatheredBaseline,
          );
        }
      }
      return cap;
    } catch {
      // resolveActivation is contracted not to throw; guard anyway so an
      // unexpected error is the safe community floor, never a paid grant.
      return this.communityFloorCap();
    }
  }

  /**
   * Fleet control plane PR-3: resolve whether the CURRENTLY-active license is on
   * the signed revocation list (or whether that list is PRESENT-but-corrupt), plus
   * the authenticated grandfather baseline to preserve if the paid tier is dropped.
   * Reads the activation record for the resolved license id, then consults
   * {@link isLicenseRevoked}.
   *
   * FAIL-CLOSED via the SINGLE {@link revocationVerifiability} chokepoint. `revoked`
   * is true when the id is on an authenticated list; `listUnverifiable` is true
   * whenever the revocation state is UNVERIFIABLE for ANY reason the chokepoint
   * recognizes uniformly:
   *   - CORRUPT (present, MAC/parse fail),
   *   - ABSENT-after-a-push (list deleted while the custody-MAC'd witness floor /
   *     standalone anchor proves a version-N revocation existed - the delete
   *     bypass this fix closes),
   *   - ROLLED-BACK (present but below the established floor).
   * All three drop a paid grant toward Community. An ABSENT list with NO established
   * floor (a fleet that never had a revocation pushed) is `clean` and keeps the
   * grant (the legit case). A TRANSIENT storage-read error (EIO/EAGAIN, not the
   * benign ENOENT/absent) is FLOOR-CONDITIONED grace: it sets neither flag ONLY
   * when floor === 0 (nothing ever revoked); a transient that never clears on an
   * ESTABLISHED floor (> 0) is itself `unverifiable` -> drop, so a killed license
   * cannot be held paid forever by a persistently-throwing read. A genuine MAC
   * failure, or a non-transient/unclassifiable throw (symlink/chmod-000 swap), is
   * `corrupt`, never transient. Never throws.
   */
  private async revocationStatusForActiveLicense(
    storage: StorageBackend,
    masterKey: Uint8Array,
    issuerPublicKey: Uint8Array,
  ): Promise<{
    revoked: boolean;
    listUnverifiable: boolean;
    grandfatheredBaseline: number;
  }> {
    try {
      const record = await readFleetActivation(storage, masterKey);
      const baseline =
        record.status === "valid" ? record.data.grandfatheredBaseline : 0;
      let licenseId: string | null = null;
      if (record.status === "valid") {
        const resolution = resolveEntitlement({
          token: record.data.token,
          issuerPublicKey,
          now: Math.floor(Date.now() / 1000),
        });
        licenseId =
          typeof resolution.licenseId === "string" ? resolution.licenseId : null;
      }
      // THE CHOKEPOINT: one derived verdict covering absent-after-established,
      // corrupt, and rolled-back uniformly. A `transient` verdict is grace (no
      // drop). Only a `clean` verdict may keep the paid grant.
      const verifiability = await revocationVerifiability(storage, masterKey);
      const listUnverifiable = verifiability.status === "unverifiable";
      // Only consult the id-on-list check when the list is verifiably CLEAN;
      // otherwise `listUnverifiable` already forces the drop and the id lookup on a
      // deleted/corrupt list is meaningless.
      let revoked = false;
      if (verifiability.status === "clean") {
        const status = await isLicenseRevoked(storage, masterKey, licenseId);
        revoked = status.revoked;
      }
      return {
        revoked,
        listUnverifiable,
        grandfatheredBaseline: baseline,
      };
    } catch {
      return { revoked: false, listUnverifiable: false, grandfatheredBaseline: 0 };
    }
  }

  /**
   * Activate a pasted fleet license against the daemon's DURABLE roster (fleet
   * control plane PR-B). Verifies the paste through the shipped Ed25519
   * entitlement core against the pinned issuer key and, on success, persists it
   * into the signed, master-MAC'd activation record so the central roster lifts
   * its node-count cap.
   *
   * GRANDFATHER BASELINE: on first activation for a fleet already managing more
   * than the free cap, the CURRENT active node count is captured so the fleet is
   * never force-capped at the cap flip. The count is `summary.admitted` (active,
   * non-revoked) from the SAME durable federation-backed roster the console
   * shows - NOT a wrap provider (whose roster is empty by construction, the
   * defect PR-B fixes). A new/small fleet captures 0 (the plain 5-node cap).
   *
   * FAIL-CLOSED: no custody / no operator identity → `verify_failed`, persists
   * nothing. A malformed / unverifiable / expired paste is rejected and persists
   * nothing. Never throws (an unexpected internal error maps to `verify_failed`,
   * never a silent grant). Touches no wall / local-dashboard / policy-push path.
   */
  private async activateFleetLicense(
    pastedLicense: string,
  ): Promise<
    | { ok: true; tier: string; max_nodes: number | null }
    | { ok: false; reason: "malformed_token" | "verify_failed" }
  > {
    const storage = this.storage;
    const masterKey = this.shrOpts?.masterKey;
    if (!storage || !masterKey) {
      // No unlocked custody: cannot persist a signed activation record. Reject
      // fail-closed rather than pretend to activate.
      return { ok: false, reason: "verify_failed" };
    }
    const issuerPublicKey = this.resolveFleetIssuerPublicKey();
    if (issuerPublicKey === null) {
      // No pinned operator identity → no license can verify. Reject fail-closed.
      return { ok: false, reason: "verify_failed" };
    }

    // Grandfather baseline = the CURRENT active (admitted, non-revoked) node
    // count on the durable roster, captured only when it exceeds the free cap.
    // Best-effort + fail-safe to 0 (never grandfather a count we cannot read).
    let grandfatheredBaseline = 0;
    try {
      const roster = buildFleetRoster(this.buildV1FederationDeps(), {
        evictionSerial: this._federationState.evictionMaxSerial,
        operatorPolicy: this._federationState.operatorPolicy,
      });
      if (roster.available && roster.summary.admitted > COMMUNITY_FREE_NODE_CAP) {
        grandfatheredBaseline = roster.summary.admitted;
      }
    } catch {
      grandfatheredBaseline = 0;
    }

    let result: ActivateFleetResult;
    try {
      result = await activateFleet({
        storage,
        master: masterKey,
        pastedLicense,
        issuerPublicKey,
        now: Math.floor(Date.now() / 1000),
        grandfatheredBaseline,
      });
    } catch {
      // activateFleet is contracted not to throw; never let an unexpected error
      // become a grant: fail closed.
      return { ok: false, reason: "verify_failed" };
    }

    if (result.ok) {
      return { ok: true, tier: result.tier, max_nodes: result.cap.maxNodes };
    }
    return { ok: false, reason: result.reason };
  }

  /**
   * Federation PR-A3: dependency bundle for the /v1/federation endpoints.
   * Reads live context + operator key each request. Audit writes route to the
   * channel's audit log (design note 5: every ceremony step writes success
   * AND denial); when no audit log is bound the write is a no-op rather than a
   * throw, so a minimal rig still serves.
   */
  private buildV1FederationDeps(): V1FederationDeps {
    return {
      getContext: () => this._federationContext,
      isEnabled: () => this._federationEnabled,
      setEnabled: (enabled) => {
        this._federationEnabled = enabled;
      },
      resolveOperatorPublicKey: () => this.resolveOperatorPublicKey(),
      rosterNodeIds: () => [...this._federationRoster],
      recordJoin: async (certificate) => {
        // PR-A durable membership: a join ADDS a node to the roster, the
        // authoritative source of the paid node-count. Capture the prior
        // in-memory state so a persist failure can be rolled back cleanly (mirrors
        // the sibling recordAcceptedHighWater, which rolls back its in-memory
        // advance on a persist failure). `_federationState` is REPLACED wholesale
        // by both upsertFederationNode and appendLocalFederationEvent (never
        // mutated in place), so restoring the captured reference undoes both the
        // node upsert and the appended `node.joined` event; `_federationRoster` is
        // a mutated Set, so we only delete the id we added if it was not already a
        // member.
        const rosterHadNode = this._federationRoster.has(certificate.node_id);
        const priorFederationState = this._federationState;
        this._federationRoster.add(certificate.node_id);
        this.upsertFederationNode(certificate.node_id, {
          attestation_status: "verified",
          node_mode: certificate.node_mode,
        });
        this.appendLocalFederationEvent("node.joined", {
          node_id: certificate.node_id,
          node_mode: certificate.node_mode,
        });
        // Persist the new member BEFORE acknowledging the join. THROWS on a
        // persist failure so the join fails closed (never acknowledges a join
        // whose membership did not reach disk). On failure ROLL BACK the in-memory
        // mutations first so no phantom node lingers in the roster /
        // summary.admitted until reboot, THEN re-throw (stay fail-closed). The
        // durable billing basis is never inflated either way (persist failed,
        // nothing on disk); this keeps the in-memory view consistent with it.
        // Idempotent whole-snapshot write.
        try {
          await this.persistFederationSyncState();
        } catch (err) {
          this._federationState = priorFederationState;
          if (!rosterHadNode) {
            this._federationRoster.delete(certificate.node_id);
          }
          throw err;
        }
      },
      listNodes: () => [...this._federationState.nodes.values()],
      listFederationEvents: (since) => this.listFederationEvents(since),
      appendFederationEvents: async (events, options) => {
        // Fail closed: if the durable record was present-but-corrupt on boot,
        // refuse to append on empty/untrusted revocation memory.
        this.assertFederationSyncStateAvailable();
        const before = this._federationState.evictionMaxSerial;
        const beforePolicyVersion = this._federationState.operatorPolicy?.version ?? 0;
        // PR-A durable membership: a non-authority sync event UPSERTS its origin
        // node into the roster (buildFederationNodeUpsert). Snapshot the roster
        // size so a NEW node id triggers a durable persist below, keeping the
        // paid node-count reboot-stable even for a plain agent-event sync that
        // advances no eviction/policy floor.
        const beforeNodeCount = this._federationState.nodes.size;
        const result = this.appendFederationEvents(events, options);
        // Persist ONLY when an operator-authority eviction advanced the durable
        // revocation projection. On a persist failure THROW so the handler
        // denies this sync (no false "accepted" acknowledgment), but DELIBERATELY
        // do NOT un-apply the in-memory revocation: revocation is grow-only and
        // "revoked in memory but not yet durable" is the FAIL-SAFE direction
        // (un-revoking would be the dangerous one). The whole-snapshot persist is
        // idempotent, so the next successful security-state write (the peer's
        // retry, a later eviction, or any accepted high-water) carries this
        // revocation to disk; the worst case is the SAME pre-existing
        // forgotten-on-restart window this slice otherwise closes, never a
        // silent un-revoke.
        if (
          this._federationState.evictionMaxSerial > before ||
          (this._federationState.operatorPolicy?.version ?? 0) > beforePolicyVersion ||
          this._federationState.nodes.size > beforeNodeCount
        ) {
          await this.persistFederationSyncState();
        }
        return result;
      },
      acceptedHighWaterFor: (senderNodeId) =>
        this._federationAcceptedHighWater.get(senderNodeId) ?? null,
      recordAcceptedHighWater: async (senderNodeId, highWater, certificate) => {
        // Fail closed on an unavailable durable record (corrupt-on-boot).
        if (this._federationSyncStateUnavailable) return false;
        const prior = this._federationAcceptedHighWater.get(senderNodeId) ?? 0;
        // Defensive: only ever advance (the handler already gates rollback).
        const advanced = highWater > prior;
        if (advanced) {
          this._federationAcceptedHighWater.set(senderNodeId, highWater);
        }
        this.upsertFederationNode(senderNodeId, {
          attestation_status: "verified",
          ...(certificate ? { node_mode: certificate.node_mode } : {}),
        });
        // Persist the advance BEFORE acknowledging it. On a persist failure roll
        // the high-water back and report false so the handler denies (the accept
        // is not acknowledged with a high-water that a restart would forget).
        if (advanced) {
          try {
            await this.persistFederationSyncState();
          } catch {
            this._federationAcceptedHighWater.set(senderNodeId, prior);
            return false;
          }
        }
        return true;
      },
      nextOutboundHighWater: async () => {
        // Fail closed on an unavailable durable record (corrupt-on-boot).
        this.assertFederationSyncStateAvailable();
        const next = ++this._federationOutboundHighWater;
        try {
          // Persist the reserved counter BEFORE handing it out so a restart can
          // never re-emit it. On failure roll back and THROW (caller omits the
          // reciprocal slice rather than signing on an un-committed counter).
          await this.persistFederationSyncState();
        } catch (err) {
          // Roll back ONLY if no concurrent caller advanced past us (decrement is
          // monotonic-safe: if another reservation already bumped the counter, a
          // blind `next - 1` would clobber it, so only undo our own increment).
          if (this._federationOutboundHighWater === next) {
            this._federationOutboundHighWater = next - 1;
          }
          throw err;
        }
        return next;
      },
      isNodeRevoked: (nodeId) => this.isFederationNodeRevoked(nodeId),
      isRootRevoked: (masterPubkeyB64u) =>
        this.isFederationRootRevoked(masterPubkeyB64u),
      renewLocalNodeCertificate: () => {
        this.renewLocalFederationNodeCertificate();
      },
      issueReissueChallenge: async (params) => {
        if (this._federationReissueChallengeStoreUnavailable) {
          throw new Error("federation_reissue_challenge_store_unavailable");
        }
        return this._federationReissueChallengeStore.issue(params);
      },
      consumeReissueChallenge: async (params) => {
        if (this._federationReissueChallengeStoreUnavailable) return false;
        return this._federationReissueChallengeStore.consume(params);
      },
      federationPosture: () => this.buildFederationPostureSummary(),
      // DEFAULT-OFF: returns null unless the operator has opted in via
      // setFederationGuardianRevocationRequirement. When null the revoke handler
      // skips the guardian gate entirely (legacy single-operator path). When a
      // requirement was persisted but its roster failed to re-verify on
      // rehydrate, returns the `{ unavailable: true }` sentinel so the handler
      // FAILS CLOSED (refuses every revocation) instead of dropping to
      // single-operator kill.
      requireGuardianRevocationSignOff: () => {
        // Fail closed when the durable sync-state record is unavailable
        // (present-but-corrupt OR deleted-while-provisioned, F3): a revoke must
        // not proceed on revocation/guardian memory we could not trust on boot.
        // Returning the sentinel makes the revoke handler refuse rather than
        // drop to single-operator kill on an empty/untrusted requirement.
        if (
          this._federationSyncStateUnavailable ||
          this._federationGuardianRevocationRequirementInvalid
        ) {
          return { unavailable: true };
        }
        return this._federationGuardianRevocationRequirement;
      },
      audit: async ({ operation, result, identityId, details }) => {
        try {
          await this.auditLog?.append("l2", operation, identityId, details, result);
        } catch {
          // Audit-write best effort: a federation decision is never blocked
          // on the audit sink, but the decision itself already fails closed.
        }
      },
    };
  }

  private stopFederationCertificateAutoRenewal(): void {
    this._federationRenewal?.stop();
    this._federationRenewal = null;
  }

  private renewLocalFederationNodeCertificate(): void {
    const ctx = this._federationContext;
    if (ctx === null) return;
    if (!federationContextHasIssuerAuthority(ctx)) return;
    const result = renewNodeIdentityCertificateIfDue({
      certificate: ctx.localNodeCert ?? null,
      localNodeId: ctx.nodeId,
      pinnedMaster: ctx.pinnedMasterPubkey,
      operatorPrincipalCert: ctx.issuingPrincipalCert,
      operatorPrincipalPrivateKey: ctx.getIssuingPrincipalPrivateKey(),
      masterPrivateKey: ctx.getMasterPrivateKey?.(),
      isNodeRevoked: (nodeId) => this.isFederationNodeRevoked(nodeId),
      config: ctx.nodeCertificateRenewal,
    });
    if (result.renewed) {
      ctx.localNodeCert = result.certificate;
      void this.auditLog?.append(
        "l2",
        "v1_federation_node_cert_auto_renewed",
        result.certificate.node_id,
        {
          previous_expires_at: result.previousExpiresAt,
          next_expires_at: result.nextExpiresAt,
        },
        "success",
      ).catch(() => {
        // Best-effort observability only; renewal already completed.
      });
    }
  }

  private isFederationNodeRevoked(nodeId: string): boolean {
    return this._federationState.revoked.has(nodeId);
  }

  private projectAppliedPoliciesOntoRoster(): void {
    if (this._federationState.appliedPolicyVersions.size === 0) return;
    const nextNodes = new Map(this._federationState.nodes);
    for (const [nodeId, marker] of this._federationState.appliedPolicyVersions) {
      const existing = nextNodes.get(nodeId);
      if (!existing) continue;
      nextNodes.set(nodeId, this.buildFederationNodeUpsert(nextNodes, nodeId, {
        applied_policy: appliedPolicyMarkerToNodeView(marker),
      }));
    }
    this._federationState = {
      ...this._federationState,
      nodes: nextNodes,
    };
  }

  private reprojectFederationRevocations(ctx: FederationContext): void {
    const projection = {
      revokedNodeIds: new Set<string>(),
      highestEvictionSerial: 0,
    };
    const events = this._federationState.eventLog
      .filter(
        (event) =>
          event.kind === FEDERATION_NODE_EVICTION_EVENT_KIND &&
          isFederationOperatorAuthorityEvent(event, ctx.fortressId),
      )
      .sort((a, b) => a.sequence - b.sequence);
    for (const event of events) {
      const folded = foldAcceptedFederationNodeEvictionEvent({
        event,
        projection,
        fortressId: ctx.fortressId,
      });
      if (!folded.ok) continue;
    }
    this._federationState = {
      ...this._federationState,
      revoked: projection.revokedNodeIds,
      evictionMaxSerial: projection.highestEvictionSerial,
    };
  }

  private foldFederationEvictionEvent(
    event: FederationEvent,
    projection: {
      revokedNodeIds: Set<string>;
      highestEvictionSerial: number;
    },
  ): { ok: true } | { ok: false; reason: string } {
    const ctx = this._federationContext;
    if (ctx === null) return { ok: false, reason: "federation_not_provisioned" };
    const folded = foldFederationNodeEvictionEvent({
      event,
      projection,
      fortressId: ctx.fortressId,
      pinnedMaster: ctx.pinnedMasterPubkey,
      operatorPrincipalCert: ctx.issuingPrincipalCert,
    });
    if (!folded.ok) return { ok: false, reason: folded.reason };
    return { ok: true };
  }

  private foldFederationPolicyBundleEvent(
    event: FederationEvent,
    projection: FederationPolicyProjection,
  ): { ok: true } | { ok: false; reason: string } {
    const ctx = this._federationContext;
    if (ctx === null) return { ok: false, reason: "federation_not_provisioned" };
    const folded = foldVerifiedFederationPolicyBundleEvent({
      event,
      projection,
      fortressId: ctx.fortressId,
      pinnedMaster: ctx.pinnedMasterPubkey,
      operatorPrincipalCert: ctx.issuingPrincipalCert,
      applyingNodeId: ctx.nodeId,
    });
    if (!folded.ok) return { ok: false, reason: folded.reason };
    return { ok: true };
  }

  private upsertFederationNode(
    nodeId: string,
    update?: Partial<Omit<FederationNodeView, "node_id" | "last_sync" | "applied_policy">> & {
      last_sync?: Partial<FederationNodeView["last_sync"]>;
      applied_policy?: Partial<FederationNodeView["applied_policy"]>;
    },
  ): FederationNodeView {
    const nextNodes = new Map(this._federationState.nodes);
    const node = this.buildFederationNodeUpsert(nextNodes, nodeId, update);
    nextNodes.set(nodeId, node);
    this._federationState = {
      ...this._federationState,
      nodes: nextNodes,
    };
    return node;
  }

  private buildFederationNodeUpsert(
    nodes: Map<string, FederationNodeView>,
    nodeId: string,
    update?: Partial<Omit<FederationNodeView, "node_id" | "last_sync" | "applied_policy">> & {
      last_sync?: Partial<FederationNodeView["last_sync"]>;
      applied_policy?: Partial<FederationNodeView["applied_policy"]>;
    },
  ): FederationNodeView {
    const now = new Date().toISOString();
    const existing = nodes.get(nodeId);
    const nodeMode = update?.node_mode ?? existing?.node_mode ?? "unknown";
    const posture = this.buildFederationNodePosture(nodeMode);
    return {
      node_id: nodeId,
      label: update?.label ?? existing?.label ?? null,
      attestation_status: update?.attestation_status ?? existing?.attestation_status ?? "unknown",
      ...posture,
      first_seen: existing?.first_seen ?? update?.first_seen ?? now,
      last_seen: update?.last_seen ?? now,
      last_sync: {
        received_at: update?.last_sync?.received_at ?? existing?.last_sync.received_at ?? null,
        sent_at: update?.last_sync?.sent_at ?? existing?.last_sync.sent_at ?? null,
        last_sequence: update?.last_sync?.last_sequence ?? existing?.last_sync.last_sequence ?? 0,
      },
      applied_policy: {
        version: update?.applied_policy?.version ?? existing?.applied_policy.version ?? null,
        hash: update?.applied_policy?.hash ?? existing?.applied_policy.hash ?? null,
        hash_algorithm:
          update?.applied_policy?.hash_algorithm ??
          existing?.applied_policy.hash_algorithm ??
          null,
        applied_at:
          update?.applied_policy?.applied_at ??
          existing?.applied_policy.applied_at ??
          null,
        source_event_id:
          update?.applied_policy?.source_event_id ??
          existing?.applied_policy.source_event_id ??
          null,
      },
    };
  }

  private buildFederationNodePosture(
    nodeMode: NodeModeForPosture,
  ): ReturnType<typeof deriveNodePosture> {
    return deriveNodePosture({
      nodeMode,
      verifiedTeeEvidence: false,
    });
  }

  private buildFederationPostureSummary(): FederationPostureSummary {
    const nodes = [...this._federationState.nodes.values()];
    const localNodes = nodes.filter((node) => node.node_mode === "local").length;
    const operatorCloudNodes = nodes.filter((node) => node.node_mode === "operator_cloud").length;
    const sovereignTeeNodes = nodes.filter((node) => node.node_mode === "sovereign_tee").length;
    const unknownNodes = nodes.filter((node) => node.node_mode === "unknown").length;
    const providerInTrustBoundary = nodes.some(
      (node) => node.trust_boundary.provider_in_trust_boundary,
    );
    const teeAttested = nodes.some((node) => node.tee_attested === true);
    const breakGlass = this._federationGuardianBreakGlass;
    return {
      version: NODE_TRUST_BOUNDARY_VERSION,
      local_nodes: localNodes,
      operator_cloud_nodes: operatorCloudNodes,
      sovereign_tee_nodes: sovereignTeeNodes,
      unknown_nodes: unknownNodes,
      provider_in_trust_boundary: providerInTrustBoundary,
      tee_attested: teeAttested,
      disclosure: operatorCloudNodes > 0 ? OPERATOR_CLOUD_DISCLOSURE : null,
      guardian_break_glass:
        breakGlass === null
          ? { active: false }
          : {
              active: true,
              intent: breakGlass.intent,
              target_m: breakGlass.targetM,
              initiated_at: breakGlass.initiatedAt,
              completes_at: breakGlass.completesAt,
              time_remaining_ms: Math.max(0, Date.parse(breakGlass.completesAt) - Date.now()),
            },
    };
  }

  /**
   * PR-A5: emit a portable `agent.identity` federation event for an agent
   * attested on THIS node. The event rides the hash-chained log and, once a
   * peer accepts the envelope that carries it (cert-chain verified), the agent
   * is RECOGNIZED across the operator's machines without re-minting its
   * identity - the "identity survives a substrate move" property. Called by the
   * agent-protect path (and by the marquee integration test) when a fortress
   * node admits an agent. Returns the appended event for the caller to surface.
   */
  recordLocalAgentIdentity(agentId: string, agentPubkey?: string): FederationEvent {
    const payload: Record<string, unknown> = { agent_id: agentId };
    if (agentPubkey !== undefined) payload.agent_pubkey = agentPubkey;
    return this.appendLocalFederationEvent("agent.identity", payload);
  }

  private appendLocalFederationEvent(kind: string, payload: Record<string, unknown>): FederationEvent {
    const originNodeId = this._federationContext?.nodeId ?? "local";
    const previous = [...this._federationState.eventLog]
      .reverse()
      .find((event) => event.origin_node_id === originNodeId);
    const eventWithoutHash = {
      event_id: `${originNodeId}:${(previous?.sequence ?? 0) + 1}`,
      origin_node_id: originNodeId,
      sequence: (previous?.sequence ?? 0) + 1,
      occurred_at: new Date().toISOString(),
      kind,
      payload,
      previous_hash: previous?.event_hash ?? null,
    };
    const event: FederationEvent = {
      ...eventWithoutHash,
      event_hash: federationEventHash(eventWithoutHash),
    };
    this._federationState = {
      ...this._federationState,
      eventLog: [...this._federationState.eventLog, event],
    };
    return event;
  }

  private listFederationEvents(since?: FederationSyncCursor): FederationEvent[] {
    const nodeId = since?.node_id;
    const after = since?.after_sequence ?? 0;
    return this._federationState.eventLog.filter((event) => {
      if (nodeId && event.origin_node_id !== nodeId) return false;
      return event.sequence > after;
    });
  }

  private appendFederationEvents(
    events: FederationEvent[],
    options?: FederationAppendOptions,
  ): FederationAppendResult {
    const ctx = this._federationContext;
    if (ctx === null) {
      return {
        accepted: [],
        rejected: events.map((event) => ({
          event_id: event.event_id,
          reason: "federation_not_provisioned",
        })),
      };
    }
    return acceptFederationEventsFailClosed({
      events,
      fortressId: ctx.fortressId,
      senderNodeId: options?.senderNodeId,
      wireVersion: options?.wireVersion,
      isNodeRevoked: (nodeId) => this.isFederationNodeRevoked(nodeId),
      validateEvents: (batch) =>
        this.validateFederationEventsAfterRevocationGate(batch),
      appendEvents: (batch) =>
        this.appendFederationEventsAfterRevocationGate(batch),
    });
  }

  private validateFederationEventsAfterRevocationGate(
    events: FederationEvent[],
  ): FederationAppendResult {
    const staged = this.stageFederationEventsAfterRevocationGate(events);
    return { accepted: staged.accepted, rejected: staged.rejected };
  }

  private appendFederationEventsAfterRevocationGate(
    events: FederationEvent[],
  ): FederationAppendResult {
    const staged = this.stageFederationEventsAfterRevocationGate(events);
    this._federationState = staged.nextState;
    return { accepted: staged.accepted, rejected: staged.rejected };
  }

  private stageFederationEventsAfterRevocationGate(
    events: FederationEvent[],
  ): FederationAppendResult & {
    nextState: FederationDashboardState;
  } {
    const accepted: FederationEvent[] = [];
    const rejected: Array<{ event_id: string; reason: string }> = [];
    const currentState = this._federationState;
    const nextEventLog = [...currentState.eventLog];
    const knownEventIds = new Set(currentState.eventLog.map((event) => event.event_id));
    const nextNodes = new Map(currentState.nodes);
    const evictionProjection = {
      revokedNodeIds: new Set(currentState.revoked),
      highestEvictionSerial: currentState.evictionMaxSerial,
    };
    const policyProjection: FederationPolicyProjection = {
      current: currentState.operatorPolicy
        ? { ...currentState.operatorPolicy }
        : null,
      appliedByNode: new Map(
        [...currentState.appliedPolicyVersions].map(([nodeId, marker]) => [
          nodeId,
          { ...marker },
        ]),
      ),
    };
    const byNode = new Map<string, FederationEvent[]>();
    for (const event of events) {
      const list = byNode.get(event.origin_node_id) ?? [];
      list.push(event);
      byNode.set(event.origin_node_id, list);
    }

    for (const [nodeId, nodeEvents] of byNode) {
      nodeEvents.sort((a, b) => a.sequence - b.sequence);
      let last = [...nextEventLog]
        .reverse()
        .find((event) => event.origin_node_id === nodeId);
      for (const event of nodeEvents) {
        if (!validateFederationEventHash(event)) {
          rejected.push({ event_id: event.event_id, reason: "hash_mismatch" });
          continue;
        }
        if (knownEventIds.has(event.event_id)) {
          rejected.push({ event_id: event.event_id, reason: "replay" });
          continue;
        }
        if (event.sequence <= (last?.sequence ?? 0)) {
          rejected.push({ event_id: event.event_id, reason: "stale_sequence" });
          continue;
        }
        if (event.previous_hash !== (last?.event_hash ?? null)) {
          rejected.push({ event_id: event.event_id, reason: "previous_hash_mismatch" });
          continue;
        }
        const ctx = this._federationContext;
        const operatorAuthorityOrigin =
          ctx === null ? null : federationOperatorAuthorityOrigin(ctx.fortressId);
        const isEvictionKind = event.kind === FEDERATION_NODE_EVICTION_EVENT_KIND;
        const isPolicyBundleKind =
          event.kind === FEDERATION_POLICY_BUNDLE_EVENT_KIND;
        const isAuthorityOrigin =
          operatorAuthorityOrigin !== null &&
          event.origin_node_id === operatorAuthorityOrigin;
        if (isEvictionKind || isPolicyBundleKind || isAuthorityOrigin) {
          if (ctx === null || !isFederationOperatorAuthorityEvent(event, ctx.fortressId)) {
            rejected.push({ event_id: event.event_id, reason: "operator_authority_invalid" });
            continue;
          }
          if (isEvictionKind) {
            const folded = this.foldFederationEvictionEvent(event, evictionProjection);
            if (!folded.ok) {
              rejected.push({ event_id: event.event_id, reason: folded.reason });
              continue;
            }
          } else if (isPolicyBundleKind) {
            const folded = this.foldFederationPolicyBundleEvent(
              event,
              policyProjection,
            );
            if (!folded.ok) {
              rejected.push({ event_id: event.event_id, reason: folded.reason });
              continue;
            }
          }
        }
        nextEventLog.push(event);
        knownEventIds.add(event.event_id);
        accepted.push(event);
        last = event;
        if (isPolicyBundleKind && ctx !== null && policyProjection.current) {
          nextNodes.set(ctx.nodeId, this.buildFederationNodeUpsert(nextNodes, ctx.nodeId, {
            attestation_status: "verified",
            node_mode: ctx.nodeMode ?? "local",
            applied_policy: appliedPolicyMarkerToNodeView(policyProjection.current),
          }));
        }
        if (!isAuthorityOrigin) {
          nextNodes.set(nodeId, this.buildFederationNodeUpsert(nextNodes, nodeId, {
            attestation_status: "verified",
            last_sync: {
              received_at: new Date().toISOString(),
              last_sequence: event.sequence,
            },
          }));
        }
      }
    }
    return {
      accepted,
      rejected,
      nextState: {
        eventLog: nextEventLog,
        revoked: evictionProjection.revokedNodeIds,
        evictionMaxSerial: evictionProjection.highestEvictionSerial,
        operatorPolicy: policyProjection.current,
        appliedPolicyVersions: policyProjection.appliedByNode,
        nodes: nextNodes,
      },
    };
  }

  /**
   * v0.10.2: enable (or disable) the loopback auto-auth fast path. See
   * {@link _autoAuthLocalhost} for the rationale and threat model. Callers
   * should gate this on both (a) the dashboard host being a loopback
   * interface and (b) the master-key unlock having succeeded against
   * on-disk state.
   */
  setAutoAuthLocalhost(enabled: boolean): void {
    this._autoAuthLocalhost = enabled;
    // v0.10.6: the dashboard HTML embeds a LOOPBACK_AUTH constant that mirrors
    // this flag so the client-side init gate knows not to redirect-loop when
    // sessionStorage is empty. Regenerate the HTML here because construction
    // happens before the caller decides whether to enable auto-auth.
    this.dashboardHTML = generateDashboardHTML({
      timeoutSeconds: this.config.timeout_seconds,
      serverVersion: PKG_VERSION,
      loopbackAutoAuth: this._autoAuthLocalhost,
    });
  }

  /**
   * v0.10.2: is this request from a loopback interface? We treat the
   * standard IPv4/IPv6 loopback addresses plus the IPv4-mapped IPv6 form
   * as loopback so LAN clients never accidentally hit the unauthenticated
   * fast path even on hosts where the HTTP server binds 0.0.0.0.
   */
  private isLoopbackRequest(req: IncomingMessage): boolean {
    const addr = this.getRemoteAddr(req);
    return addr === "127.0.0.1" || addr === "::1" || addr === "localhost";
  }

  /**
   * C1: is this dashboard binding to a non-loopback interface?
   */
  private isRemoteBinding(): boolean {
    const h = this.config.host;
    return h !== "127.0.0.1" && h !== "::1" && h !== "localhost";
  }

  /**
   * Slice 2 (single-owner): set true when `start()` was asked to treat
   * EADDRINUSE as a benign "another owner holds the port" outcome and the
   * bind failed with EADDRINUSE. The supervised boot path checks this and
   * exits 0 (so launchd KeepAlive treats it as a successful run, never a
   * crash that churns the restart loop). Never set on the interactive path,
   * which keeps the loud operator message and a real reject/throw.
   */
  private _addrInUse = false;

  /** Slice 2: did the last `start()` lose the single-owner race (EADDRINUSE)? */
  addrInUse(): boolean {
    return this._addrInUse;
  }

  /**
   * Start the HTTP(S) server for the dashboard.
   *
   * @param opts.exitCleanOnAddrInUse Slice 2 single-owner guard. When true
   *   (the supervised LaunchAgent path), an EADDRINUSE bind failure RESOLVES
   *   cleanly and sets {@link addrInUse} instead of rejecting, so the caller
   *   can exit 0 and KeepAlive treats it as a successful run (no churn). When
   *   false/omitted (interactive `sanctuary dashboard`), EADDRINUSE still
   *   prints the loud operator banner and rejects.
   */
  async start(opts?: { exitCleanOnAddrInUse?: boolean }): Promise<void> {
    // C1: enforce TLS for non-loopback bindings. Plaintext approve/deny
    // over the wire is a credential-theft vector. The operator can opt
    // out via allow_plaintext_remote for tailnet/VPN environments where
    // the network layer already encrypts.
    if (this.isRemoteBinding() && !this.useTLS && !this.config.allow_plaintext_remote) {
      throw new Error(
        `Sanctuary Dashboard: refusing to start on non-loopback interface ` +
        `${this.config.host} without TLS.\n\n` +
        `  Approve/deny decisions over plaintext HTTP expose the auth token\n` +
        `  and operator decisions to network observers.\n\n` +
        `  Options:\n` +
        `    1. Configure TLS: set dashboard.tls.cert_path + dashboard.tls.key_path\n` +
        `       (for Tailscale: tailscale cert <hostname>)\n` +
        `    2. Set dashboard.allow_plaintext_remote: true if the network\n` +
        `       layer already encrypts (e.g. Tailscale, WireGuard)\n` +
        `    3. Bind to 127.0.0.1 (localhost only)\n`
      );
    }

    // C1: enforce auth token for non-loopback bindings. Without a token,
    // anyone who can reach the interface can approve/deny agent operations.
    if (this.isRemoteBinding() && !this.authToken) {
      this.authToken = randomBytes(32).toString("hex");
      process.stderr.write(
        `\n  C1: Non-loopback binding requires authentication.\n` +
        `  Auto-generated auth token (use this to connect from remote machines).\n\n`
      );
    }

    const handler = (req: IncomingMessage, res: ServerResponse) => this.handleRequest(req, res);

    let server;
    if (this.useTLS && this.config.tls) {
      const tlsOpts = {
        cert: await readFile(this.config.tls.cert_path),
        key: await readFile(this.config.tls.key_path),
      };
      server = createHttpsServer(tlsOpts, handler);
    } else {
      server = createHttpServer(handler);
    }
    this.httpServer = server;

    return new Promise((resolve, reject) => {

      const protocol = this.useTLS ? "https" : "http";
      const baseUrl = `${protocol}://${this.config.host}:${this.config.port}`;

      server.listen(this.config.port, this.config.host, () => {
        // Generate a pre-authenticated one-click URL
        const sessionUrl = this.authToken ? this.createSessionUrl() : baseUrl;

        // Print dashboard URL
        process.stderr.write(
          `\n  Sanctuary Principal Dashboard: ${baseUrl}\n`
        );
        if (this.authToken) {
          const hint = this.authToken.slice(0, 4) + "..." + this.authToken.slice(-4);
          process.stderr.write(
            `  Auth token: ${hint}\n`
          );
        }
        process.stderr.write(`\n`);

        // Auto-open in default browser (default: true for localhost)
        // Skip in test environments to avoid spawning browsers during CI/test runs
        const isTest = !!(process.env.VITEST || process.env.NODE_ENV === "test" || process.env.CI);
        const isLocalhost = this.config.host === "127.0.0.1" || this.config.host === "localhost" || this.config.host === "::1";
        const shouldAutoOpen = !isTest && (this.config.auto_open ?? isLocalhost);
        if (shouldAutoOpen) {
          this.openInBrowser(sessionUrl);
        }

        resolve();
      });
      server.on("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "EADDRINUSE") {
          const port = this.config.port;
          // Slice 2 single-owner: on the supervised path, another owner already
          // holds the port (the LaunchAgent process, or a prior in-app spawn).
          // This is NOT a crash; resolve cleanly so the boot path can exit 0
          // and KeepAlive treats it as a successful run (no restart churn,
          // never a tight loop). At most one listener survives; EADDRINUSE
          // loses, quietly.
          if (opts?.exitCleanOnAddrInUse) {
            this._addrInUse = true;
            process.stderr.write(
              `\n  Sanctuary Dashboard: port ${port} already owned by another ` +
                `instance; standing down (single-owner).\n\n`,
            );
            resolve();
            return;
          }
          process.stderr.write(
            `\n  ╔══════════════════════════════════════════════════════════════╗\n` +
            `  ║  Port ${port} is already in use.                              ║\n` +
            `  ║                                                              ║\n` +
            `  ║  Another Sanctuary Dashboard may still be running.           ║\n` +
            `  ║  To fix: lsof -ti:${port} | xargs kill                        ║\n` +
            `  ║  Then restart the dashboard.                                 ║\n` +
            `  ╚══════════════════════════════════════════════════════════════╝\n\n`
          );
        }
        reject(err);
      });
    });
  }

  /**
   * Stop the HTTP server and clean up.
   */
  async stop(): Promise<void> {
    // Clear all pending requests
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.resolve({
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "auto",
      });
    }
    this.pending.clear();

    // Close SSE connections
    for (const client of this.sseClients) {
      client.end();
    }
    this.sseClients.clear();

    // SEC-012: Clean up session state
    this.sessions.clear();
    if (this.sessionCleanupTimer) {
      clearInterval(this.sessionCleanupTimer);
      this.sessionCleanupTimer = null;
    }
    this.stopFederationCertificateAutoRenewal();
    this.stopFleetLicenseReResolve();
    this.stopFederationGuardianBreakGlassPoll();

    // Clean up rate limit tracking
    this.rateLimits.clear();

    // Close HTTP server
    if (this.httpServer) {
      return new Promise((resolve) => {
        this.httpServer!.close(() => resolve());
      });
    }
  }

  /**
   * Request approval from the human via the dashboard.
   * Blocks until the human approves/denies or timeout occurs.
   */
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    const id = randomBytes(8).toString("hex");

    // Also write to stderr as a fallback notification
    process.stderr.write(
      `[Sanctuary] Approval required: ${request.operation} (Tier ${request.tier}) - open dashboard to respond\n`
    );

    return new Promise<ApprovalResponse>((resolve) => {
      // Set up timeout
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const response: ApprovalResponse = {
          // SEC-002: Timeout ALWAYS denies. No configuration can change this.
          decision: "deny",
          decided_at: new Date().toISOString(),
          decided_by: "timeout",
        };
        this.broadcastSSE("request-resolved", {
          request_id: id,
          decision: response.decision,
          decided_by: "timeout",
        });
        resolve(response);
      }, this.config.timeout_seconds * 1000);

      // Store the pending request
      const pending: PendingRequest = {
        id,
        request,
        resolve,
        timer,
        created_at: new Date().toISOString(),
      };
      this.pending.set(id, pending);

      // Broadcast to all connected dashboards
      this.broadcastSSE("pending-request", {
        request_id: id,
        operation: request.operation,
        tier: request.tier,
        reason: request.reason,
        context: request.context,
        timestamp: request.timestamp,
      });
    });
  }

  // ── Authentication ──────────────────────────────────────────────────

  /**
   * Verify dashboard authentication.
   *
   * SEC-012: The long-lived auth token is ONLY accepted via the Authorization
   * header - never in URL query strings. For SSE and page loads that cannot
   * set headers, a short-lived session token (obtained via POST /auth/session)
   * is accepted via ?session= query parameter only when the caller explicitly
   * opts into session auth.
   *
   * `requireToken` is the Tier-1/state-mutation chokepoint: it fails closed
   * when no token is configured and accepts only a valid operator bearer. It
   * never accepts loopback auto-auth, ?session=, or sanctuary_session cookies.
   *
   * Returns true if auth passes, false if blocked (response already sent).
   */
  private checkAuth(
    req: IncomingMessage,
    url: URL,
    res: ServerResponse,
    opts?: { requireToken?: boolean; allowSession?: boolean },
  ): boolean {
    const deny = (): false => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return false;
    };

    const authHeader = req.headers.authorization;
    const parts = authHeader?.split(" ");
    const hasValidBearer =
      !!this.authToken &&
      parts?.length === 2 &&
      parts[0] === "Bearer" &&
      constantTimeEquals(parts[1]!, this.authToken);

    if (opts?.requireToken) {
      return hasValidBearer || deny();
    }

    if (!this.authToken) return true; // Auth disabled for non-strict routes.

    // v0.10.2: loopback auto-auth - see _autoAuthLocalhost comment. Strict
    // routes return above before this shortcut, so loopback can never release
    // a Tier-1 decision or mutate operator state by network position alone.
    if (
      this._autoAuthLocalhost &&
      this.isLoopbackRequest(req)
    ) {
      return true;
    }

    // Check Authorization: Bearer <token> header (primary auth method)
    if (hasValidBearer) {
      return true;
    }

    // SEC-012: Check ?session= query parameter for short-lived session tokens.
    // This replaces the old ?token= query parameter that exposed the long-lived
    // token, but only safe read/SSE routes opt into this branch.
    if (opts?.allowSession) {
      const sessionId = url.searchParams.get("session");
      if (sessionId && this.validateSession(sessionId)) {
        return true;
      }

      // Check sanctuary_session cookie (set by login page flow)
      const cookieSession = this.parseCookie(req, "sanctuary_session");
      if (cookieSession && this.validateSession(cookieSession)) {
        return true;
      }
    }

    // SEC-012: Long-lived token in ?token= query parameter is explicitly REJECTED.
    // This was the vulnerability - tokens in URLs leak to logs, history, and Referer headers.

    // For GET / requests from browsers, serve login page instead of JSON 401
    // (checked in handleRequest before checkAuth is called for this path)
    return deny();
  }

  /**
   * Check if a request is authenticated WITHOUT sending a response.
   * Used to decide between login page vs dashboard for GET /.
   */
  private isAuthenticated(req: IncomingMessage, url: URL): boolean {
    if (!this.authToken) return true;

    // v0.10.2: loopback auto-auth mirrors checkAuth so GET / serves the
    // dashboard HTML instead of the login page for localhost callers.
    if (this._autoAuthLocalhost && this.isLoopbackRequest(req)) {
      return true;
    }

    const authHeader = req.headers.authorization;
    if (authHeader) {
      const parts = authHeader.split(" ");
      if (
        parts.length === 2 &&
        parts[0] === "Bearer" &&
        constantTimeEquals(parts[1]!, this.authToken)
      ) {
        return true;
      }
    }

    const sessionId = url.searchParams.get("session");
    if (sessionId && this.validateSession(sessionId)) return true;

    const cookieSession = this.parseCookie(req, "sanctuary_session");
    if (cookieSession && this.validateSession(cookieSession)) return true;

    return false;
  }

  /**
   * Parse a specific cookie value from the request.
   */
  private parseCookie(req: IncomingMessage, name: string): string | null {
    const header = req.headers.cookie;
    if (!header) return null;
    for (const part of header.split(";")) {
      const [key, ...rest] = part.split("=");
      if (key?.trim() === name) {
        return rest.join("=").trim();
      }
    }
    return null;
  }

  // ── Session Management (SEC-012) ──────────────────────────────────

  /**
   * Create a short-lived session by exchanging the long-lived auth token
   * (provided in the Authorization header) for a session ID.
   */
  private createSession(): string {
    // Enforce max sessions to prevent memory exhaustion
    if (this.sessions.size >= MAX_SESSIONS) {
      this.cleanupSessions();
      // If still at limit after cleanup, evict the oldest session
      if (this.sessions.size >= MAX_SESSIONS) {
        const oldest = [...this.sessions.entries()].sort(
          (a, b) => a[1].created_at - b[1].created_at
        )[0];
        if (oldest) this.sessions.delete(oldest[0]);
      }
    }

    const id = randomBytes(32).toString("hex");
    const now = Date.now();
    this.sessions.set(id, {
      id,
      created_at: now,
      expires_at: now + this.sessionTTLMs,
    });
    return id;
  }

  /**
   * Validate a session ID - must exist and not be expired.
   */
  private validateSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    if (Date.now() > session.expires_at) {
      this.sessions.delete(sessionId);
      return false;
    }
    return true;
  }

  /**
   * Remove all expired sessions.
   */
  private cleanupSessions(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now > session.expires_at) {
        this.sessions.delete(id);
      }
    }
  }

  // ── Rate Limiting ─────────────────────────────────────────────────

  /**
   * Get the remote address from a request, normalizing IPv6-mapped IPv4.
   */
  private getRemoteAddr(req: IncomingMessage): string {
    const addr = req.socket.remoteAddress ?? "unknown";
    // Normalize ::ffff:127.0.0.1 → 127.0.0.1
    return addr.startsWith("::ffff:") ? addr.slice(7) : addr;
  }

  /**
   * Federation P1 DoS hardening: derive the rate-limit MAP KEY for an address.
   * For the federation peer class we aggregate IPv6 addresses to their /64
   * prefix, so an attacker who rotates source addresses within a single /64
   * (the smallest routable IPv6 allocation, trivially obtained) shares ONE
   * bucket instead of getting a fresh budget per address. IPv4 and non-IPv6
   * literals are keyed verbatim (no /64 concept). The dashboard/browser classes
   * keep per-exact-address keying (a NAT'd office should not share a browser
   * bucket).
   */
  private rateLimitKey(addr: string, aggregateIpv6: boolean): string {
    if (!aggregateIpv6) return addr;
    return ipv6Slash64Prefix(addr) ?? addr;
  }

  /**
   * v1.3.0 (XXXXX): loopback addresses are exempt from rate limiting.
   * The operator's local browser, autonomous tooling, and drill-via-curl
   * flows should never be locked out of their own dashboard.
   */
  private isLoopbackAddr(addr: string): boolean {
    return addr === "127.0.0.1" || addr === "::1";
  }

  /**
   * Per-class rate-limit policy. The dashboard/browser classes exempt loopback
   * (operator-local requests must never 429) and key per exact address. The
   * federation peer class does NEITHER: it must throttle loopback (a tunneled
   * remote peer can present as loopback) and aggregates IPv6 to /64 (DoS
   * hardening). Centralized so the policy difference is in one place.
   */
  private rateLimitPolicy(type: RateLimitClass): {
    limit: number;
    exemptLoopback: boolean;
    aggregateIpv6: boolean;
  } {
    switch (type) {
      case "decisions":
        return { limit: RATE_LIMIT_DECISIONS, exemptLoopback: true, aggregateIpv6: false };
      case "federation_peer":
        return {
          limit: RATE_LIMIT_FEDERATION_PEER,
          exemptLoopback: false,
          aggregateIpv6: true,
        };
      case "general":
      default:
        return { limit: RATE_LIMIT_GENERAL, exemptLoopback: true, aggregateIpv6: false };
    }
  }

  /**
   * Check rate limit for a request. Returns true if allowed, false if rate-limited.
   * When rate-limited, sends a 429 response.
   *
   * v1.3.0 (XXXXX): the dashboard/browser classes ("general"/"decisions") exempt
   * loopback (operator-local requests: browser polling, autonomous tooling,
   * drill-via-curl) must never 429. Federation P1: the "federation_peer" class
   * does NOT exempt loopback and aggregates IPv6 to /64 (see rateLimitPolicy).
   *
   * NO-ORACLE (Federation P1 §2/§3): the 429 fires identically for every caller
   * regardless of federation membership/enabled-state. It runs BEFORE any
   * federation-state check, so it leaks only "you are being throttled". The body
   * carries NO federation-state detail and the Retry-After is derived purely from
   * the FIXED window bucket (oldest timestamp + window), never from any internal
   * federation state, so it is not a timing oracle.
   */
  private checkRateLimit(
    req: IncomingMessage,
    res: ServerResponse,
    type: RateLimitClass
  ): boolean {
    const { limit, exemptLoopback, aggregateIpv6 } = this.rateLimitPolicy(type);
    const addr = this.getRemoteAddr(req);

    // Loopback exemption is per-class: dashboard/browser classes keep it; the
    // federation peer class drops it (a tunneled remote peer can present as
    // loopback, and the exemption is itself a probing asymmetry).
    if (exemptLoopback && this.isLoopbackAddr(addr)) return true;

    const key = this.rateLimitKey(addr, aggregateIpv6);
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;

    // Get or create entry for this key
    let entry = this.rateLimits.get(key);
    if (!entry) {
      // Cap the tracking map to prevent memory exhaustion
      if (this.rateLimits.size >= MAX_RATE_LIMIT_ENTRIES) {
        this.pruneRateLimits(now);
      }
      entry = { general: [], decisions: [], federation_peer: [] };
      this.rateLimits.set(key, entry);
    }

    // Prune old timestamps from the window
    entry.general = entry.general.filter(t => t > windowStart);
    entry.decisions = entry.decisions.filter(t => t > windowStart);
    entry.federation_peer = entry.federation_peer.filter(t => t > windowStart);

    const timestamps = entry[type];

    if (timestamps.length >= limit) {
      const retryAfter = Math.ceil((timestamps[0]! + RATE_LIMIT_WINDOW_MS - now) / 1000);
      res.writeHead(429, {
        "Content-Type": "application/json",
        "Retry-After": String(Math.max(1, retryAfter)),
      });
      res.end(JSON.stringify({
        error: "Rate limit exceeded",
        retry_after_seconds: Math.max(1, retryAfter),
      }));
      return false;
    }

    timestamps.push(now);
    return true;
  }

  /**
   * Remove stale entries from the rate limit map.
   */
  private pruneRateLimits(now: number): void {
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    for (const [addr, entry] of this.rateLimits) {
      const hasRecent =
        entry.general.some(t => t > windowStart) ||
        entry.decisions.some(t => t > windowStart) ||
        entry.federation_peer.some(t => t > windowStart);
      if (!hasRecent) {
        this.rateLimits.delete(addr);
      }
    }
  }

  // ── HTTP Request Handler ────────────────────────────────────────────

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const method = req.method ?? "GET";

    // CORS headers - restrict to same-origin; the dashboard is served by this server.
    // CORS: reflect ONLY the exact same-origin (the dashboard serves its own
    // UI). Cross-origin reflection for the remote fleet-switcher health probe
    // is scoped to the UNAUTHENTICATED /api/health handler ONLY, which sets its
    // own Access-Control-Allow-Origin (and never Access-Control-Allow-Credentials).
    // SECURITY: no authenticated/protected route must ever carry cross-origin
    // reflection. The earlier remote-bind same-port reflection lived in this
    // prelude and therefore leaked onto every downstream route (protected reads,
    // mutating POSTs, approval decisions) on a remote bind; it has been removed.
    // Without Access-Control-Allow-Credentials this was not a credentialed-read
    // takeover, but route-wide reflection is exactly the latent hole that turns
    // into one the day a credentials header is added. Health-only is the contract.
    const origin = req.headers.origin;
    const protocol = this.useTLS ? "https" : "http";
    const selfOrigin = `${protocol}://${this.config.host}:${this.config.port}`;
    if (origin === selfOrigin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
    // When no origin header (same-origin requests), no CORS header needed
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // v1.3 WP-V1.3-5 Pi-1: front-of-dispatch trap-trigger hook. Runs
    // BEFORE every other dispatch so an operator can deploy a trap at
    // any path (including paths that would otherwise hit legacy/v1.1
    // routes). The hook itself short-circuits when the path starts
    // with /api/honeypot, /api/sentinels, or /api/coordination so
    // management surfaces never get shadowed.
    if (this.honeypotRegistry) {
      this.dispatchHoneypotTrap(req, res)
        .then((handled) => {
          if (handled) return;
          // Continue with normal request handling.
          this.continueHandleRequest(req, res, url, method, origin, selfOrigin);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    this.continueHandleRequest(req, res, url, method, origin, selfOrigin);
  }

  /**
   * v1.3 WP-V1.3-5 Pi-1: post-honeypot-trap request continuation. The
   * front-of-dispatch trap-trigger hook may short-circuit a request;
   * when it does not, this method runs the original dispatch ladder.
   * Pulled out as a helper so the trap-hook + non-trap paths share
   * one code path through every downstream dispatcher.
   */
  private continueHandleRequest(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
    _origin: string | undefined,
    _selfOrigin: string,
  ): void {
    // One-surface root-flip: the posture board is the default page at `/` AND
    // its `/posture` alias. Intercepted here, BEFORE the v1.1 SPA dispatch and
    // the legacy route table, so `/posture` serves the one unauthenticated
    // static posture shell under the same auth contract (its data fetches stay
    // behind checkAuth). NOTE (default-flip 2026-06-30): `/` is NO LONGER served
    // here - it falls through to the v1.1 concierge below (the single default
    // surface). `dispatchRootPosture` still owns `/` ONLY for the remote-login
    // affordance (a remote unauthenticated browser gets a token box). Matches
    // `/posture` for the shell; `/dashboard`, `/v1.0`, `/v1.1`, `/fortress`,
    // `/posture/agent/:id`, and every `/api/*` route fall through untouched.
    if (this.dispatchRootPosture(req, res, url, method)) return;

    // Federation PR-A1: the additive /v1 API surface (RFC v7 session
    // ceremony + session-token-gated routes). Owns the entire /v1 prefix
    // and never falls through to legacy routing - fail-closed 401 for
    // unauthenticated callers on every /v1 path. NOTE: `/v1.0` and
    // `/v1.1` (legacy dashboard HTML) do not match this prefix.
    if (url.pathname === "/v1" || url.pathname.startsWith("/v1/")) {
      // Ceremony endpoints get the stricter decision-class rate limit
      // (auth brute-force guard); reads get the general limit. The federation
      // join-submission ceremony is an auth surface too (bootstrap-token
      // brute-force guard), so it shares the decisions budget. Federation P1: the
      // pre-session, node-cert-authenticated peer-sync route gets its OWN
      // dedicated bucket (no loopback exemption, IPv6 /64 aggregation, tighter
      // budget, global concurrent-verify ceiling) because it is reachable with no
      // session and each request triggers a crypto verification.
      const limitClass: RateLimitClass =
        url.pathname === "/v1/federation/sync/peer"
          ? "federation_peer"
          : url.pathname.startsWith("/v1/session/") ||
              url.pathname.startsWith("/v1/federation/authorize/")
            ? "decisions"
            : "general";
      if (!this.checkRateLimit(req, res, limitClass)) return;
      // Federation P1 DoS hardening: bound concurrent in-flight crypto-verify on
      // the unauthenticated peer-sync route. Over the ceiling, reject with the
      // SAME generic 403 a verify failure returns (no distinguishable error → no
      // membership/enabled-state oracle). The counter is released in a finally
      // after the handler resolves.
      //
      // DEBT (Federation P1): the per-/64 rate limit + this concurrent-verify
      // ceiling bound CPU spent on crypto verification, but do NOT bound a
      // slow-loris socket-exhaustion attack: there is no listener read/idle
      // timeout and no max-connection bound. `v1/http.ts` readJsonBody has no
      // read timeout, and the server uses Node's default `requestTimeout`. The
      // listener read/idle timeout + max-connection bound are deferred because
      // they touch shared server-listener config (not just this route).
      if (limitClass === "federation_peer") {
        if (this.inFlightPeerVerify >= MAX_CONCURRENT_PEER_VERIFY) {
          // Byte-identical to every other 403 on this route (incl.
          // Cache-Control: no-store) so the over-ceiling rejection is not a
          // wire-distinguishable oracle.
          denyForbidden(res);
          return;
        }
        this.inFlightPeerVerify++;
        handleV1Request(
          {
            sessions: this.v1Sessions,
            isLoopbackRequest: (r) => this.isLoopbackRequest(r),
            buildFullStatus: () => this.buildV1FullStatus(),
            version: PKG_VERSION,
            agents: this.buildV1AgentsDeps(),
            federation: this.buildV1FederationDeps(),
          },
          req,
          res,
          url,
          method,
        )
          .catch(() => {
            if (!res.headersSent) {
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Internal server error" }));
            }
          })
          .finally(() => {
            this.inFlightPeerVerify--;
          });
        return;
      }
      handleV1Request(
        {
          sessions: this.v1Sessions,
          isLoopbackRequest: (r) => this.isLoopbackRequest(r),
          buildFullStatus: () => this.buildV1FullStatus(),
          version: PKG_VERSION,
          agents: this.buildV1AgentsDeps(),
          federation: this.buildV1FederationDeps(),
        },
        req,
        res,
        url,
        method,
      ).catch(() => {
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Internal server error" }));
        }
      });
      return;
    }

    // v1.3 WP-V1.3-5 Pi-1 Honeypot management API at /api/honeypot/*.
    if (
      this.honeypotRegistry &&
      url.pathname.startsWith(HONEYPOT_API_PREFIX)
    ) {
      this.dispatchHoneypot(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // v1.3 WP-V1.3-10 Upsilon-1: cross-harness approval inbox routes at
    // `/api/approval-inbox/*`. Mounted additively in front of the v1.1
    // hub + legacy v1.0 surfaces; legacy `/api/approvals/:id/...` paths
    // stay live for the v1.0 dashboard.
    if (
      this.approvalAggregator &&
      url.pathname.startsWith(APPROVAL_INBOX_API_PREFIX)
    ) {
      this.dispatchApprovalInbox(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    if (
      this.unifiedInboxBridge &&
      (url.pathname.startsWith(UNIFIED_INBOX_API_PREFIX) ||
        url.pathname.startsWith(UNIFIED_INBOX_RETENTION_API_PREFIX))
    ) {
      this.dispatchUnifiedInbox(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    if (
      this.autoTriggerStore &&
      this.autoTriggerDispatcher &&
      url.pathname.startsWith(AUTO_TRIGGER_API_PREFIX)
    ) {
      this.dispatchAutoTrigger(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // v1.3 WP-V1.3-1 Phi-1: Sentinel surface at `/api/sentinels/*`.
    // Read-only against the audit log; subscribe/unsubscribe writes
    // flow through the dispatcher's audited paths.
    if (
      this.sentinelDispatcher &&
      url.pathname.startsWith(SENTINEL_API_PREFIX)
    ) {
      this.dispatchSentinel(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // HABEAS PORT: distress inbox surface at `/api/distress/*`. Read-only
    // against the operator-readable inbox the local listener populates.
    if (
      this.distressInbox &&
      url.pathname.startsWith(DISTRESS_API_PREFIX)
    ) {
      this.dispatchDistress(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // v1.3 WP-V1.3-3 Omega-1: Coordination handoff surface at
    // `/api/coordination/*`. Read-only against the audit log; only
    // writes are operator-action audit events.
    if (
      this.handoffLog &&
      url.pathname.startsWith(COORDINATION_API_PREFIX)
    ) {
      this.dispatchCoordination(req, res)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // v1.1.1 hotfix: try v1.1 dispatch first. dispatchV11 returns true when
    // the request matched a v1.1 route (dashboard HTML at /v1.1, hub API
    // at /api/hub/*). When false, fall through to the legacy route table below
    // so v1.0 surfaces stay live; `/` was already handled by the posture shell.
    if (this.v11Bindings) {
      this.dispatchV11(req, res, url, method)
        .then((handled) => {
          if (handled) return;
          this.handleLegacyRequest(req, res, url, method);
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    this.handleLegacyRequest(req, res, url, method);
  }

  private handleLegacyRequest(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    method: string,
  ): void {
    // v1.3.0 (XXXXX): /api/health is exempt from auth AND rate limiting.
    // Health checks must always respond so the multi-aggregator health probe
    // pattern (multi-server.ts) and external monitoring work reliably.
    //
    // SECURITY (Delta Review A3 remediation): this probe is UNAUTHENTICATED and
    // unthrottled, so it stays a cheap O(1) liveness answer and MUST NOT carry
    // the evidence-based Castle Wall posture. A prior revision attached the full
    // arm-state object (origin/operator id, verdict counts, enforcement
    // timestamps) here and ran an unbounded audit-log scan + per-entry Ed25519
    // re-verify on every call - that both leaked the detailed posture to any
    // anonymous caller and gave an unauthenticated DoS amplifier. The honest
    // arm-state lives ONLY behind auth: `/api/posture/castle-wall` (checkAuth;
    // the native app reaches it via loopback auto-auth) and the `/v1/status`
    // document (the v1 SESSION_TOKEN ceremony). The native badge sources its
    // arm-state from `/api/posture/castle-wall`, never from this probe. The
    // `{ ok, mode }` shape is the only contract the CLI health probe + external
    // monitors key on.
    if (method === "GET" && url.pathname === "/api/health") {
      // C1 cross-host fleet probe: the `/fleet` switcher is served by ONE host
      // and health-probes the others with `fetch(<remote>/api/health)`. The
      // browser's same-origin policy blocks the response body unless the remote
      // sends `Access-Control-Allow-Origin`, so without this header a reachable
      // remote shows offline (red dot) in the switcher.
      //
      // SCOPE (security): this permissive ACAO is added ONLY to this endpoint,
      // which is the UNAUTHENTICATED, O(1) liveness probe - it returns only
      // `{ ok, mode, instance, since }` (no secrets, no posture, no auth state),
      // so a cross-origin reader learns nothing it could not learn by connecting
      // directly. We reflect the request Origin (falling back to `*`) but NEVER
      // set `Access-Control-Allow-Credentials` here, so no cookie/bearer is ever
      // sent or honored cross-origin (the reflected-origin + credentials combo
      // is the CORS account-takeover pattern, and it is deliberately avoided).
      // No authenticated/protected route carries cross-origin reflection; they
      // keep the same-origin/same-port contract set in handleRequest().
      const healthHeaders: Record<string, string> = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": req.headers.origin ?? "*",
      };
      res.writeHead(200, healthHeaders);
      // brief D3: `{ ok, mode }` plus the opaque per-process `instance` +
      // `since` restart-detection signal. NO `ready`/`supervisor` here -
      // those would be a co-resident-agent oracle on this unauthenticated
      // probe (brief HIGH-1) and live ONLY on the auth-gated /api/readiness.
      res.end(
        JSON.stringify({
          ok: true,
          mode: "principal-policy",
          instance: getProcessInstance(),
          since: getProcessSince(),
        }),
      );
      return;
    }

    // /api/readiness (AUTH-GATED, brief D3): the readiness/supervisor signal
    // lives behind the SAME auth as the other authenticated read routes
    // (checkAuth: bearer token, session, or loopback auto-auth). It reports
    // readiness, never posture - "serving" means unlocked + read surface
    // live, NOT "your agents are protected" (that stays on the evidence-gated
    // /api/posture/castle-wall).
    //
    // `supervisor` reports the REAL bridge state, not a mask. This dashboard
    // CAN run Protect: protect routes through `this.supervisorBridge`
    // (launchProtect), and when that bridge is null Protect fails closed with
    // 503 (see buildV1Bindings). So an absent bridge is not "not applicable"
    // here - it GUARANTEES a 503 - and the honest signal is "unwired", never
    // "n/a". The bridge is wired post-unlock via setSupervisorBridge(); until
    // then "unwired" tells the host app Protect will 503. (setSupervisorBridge
    // is not called in production yet, so today this honestly reports
    // "unwired".)
    if (method === "GET" && url.pathname === "/api/readiness") {
      if (!this.checkRateLimit(req, res, "general")) return;
      if (!this.checkAuth(req, url, res, { allowSession: true })) return;
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(
        JSON.stringify({
          ready: this.identityManager ? "serving" : "locked",
          supervisor: this.supervisorBridge ? "wired" : "unwired",
        }),
      );
      return;
    }

    // Slice 2 (park-not-exit): in-process unlock door. POST /api/unlock takes
    // an operator credential, re-runs establishMaster, and (on success) wires
    // the unlocked deps so readiness flips locked -> serving with NO restart.
    //
    // CUSTODY CARVE-OUT (the new attack surface): this is the strictest auth
    // option. It REQUIRES the operator bearer token EVEN ON LOOPBACK
    // (`requireToken: true`), exactly like the Tier-1 approval-decision routes.
    // A co-resident agent sharing the loopback interface holds no proxy for
    // operator identity, so loopback auto-auth is explicitly suppressed here:
    // the agent cannot self-unlock the fortress by POSTing a guessed/known
    // credential from localhost. It is registered in the `decisions` rate-limit
    // class, but note that `checkRateLimit` short-circuits `return true` for
    // loopback callers (operator-local tooling must never 429), so loopback
    // unlock attempts are NOT actually rate-limited; the rate limit only bites
    // remote callers. Credential brute-force on loopback is instead bounded by
    // the deliberately-slow Argon2id KDF inside establishMaster (each attempt
    // pays the full key-derivation cost), and the operator bearer token is
    // STILL required even on loopback (the custody carve-out above). It returns
    // GENERIC errors (no oracle about which rule/tier failed; invariant 7) and
    // serves NO protected state until a CORRECT unlock. It NEVER auto-generates
    // a weaker credential and NEVER weakens establishMaster (the handler calls
    // the same establishMaster the boot path calls).
    if (method === "POST" && url.pathname === "/api/unlock") {
      if (!this.checkRateLimit(req, res, "decisions")) return;
      if (!this.checkAuth(req, url, res, { requireToken: true })) return;
      this.handleUnlockRequest(req, res);
      return;
    }

    // SEC-012: Session exchange does its own auth (header-only) - let it through before checkAuth
    if (method === "POST" && url.pathname === "/auth/session") {
      if (!this.checkRateLimit(req, res, "general")) return;
      try {
        this.handleSessionExchange(req, res);
      } catch {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
      return;
    }

    // For GET /v1.0: serve login page if not authenticated (instead of JSON 401).
    // Root now serves the posture shell; /dashboard and /v1.1 remain v1.1 SPA
    // aliases. The legacy four-panel dashboard moved to /v1.0; the login page
    // mirrors that move so unauthenticated requests at /v1.0 still hit the
    // legacy login flow.
    if (method === "GET" && url.pathname === "/v1.0" && this.authToken) {
      if (!this.isAuthenticated(req, url)) {
        // Login page is a view - no rate limit (auth brute force is gated on /auth/session).
        this.serveLoginPage(res);
        return;
      }
    }

    // Authenticate all other non-OPTIONS requests.
    //
    // SECURITY (default-deny on mutation): ANY non-GET method requires the
    // operator bearer token even on loopback. A co-resident agent sharing
    // loopback must not be able to release Tier-1 approvals or mutate operator
    // configuration with a short-lived session, cookie, or mere network
    // position.
    //
    // This INVERTS a prior 4-entry allowlist (`/api/approve/`, `/api/deny/`,
    // `/api/sovereignty-profile`, `/api/proxy/servers`) that fell through to
    // `{ allowSession: true }` for every other non-GET route. That allowlist
    // was the exact miss-prone pattern the v1.1 routers already replaced
    // (hub `api-router.ts`: the allowlist "DID miss" the concierge-thread
    // DELETE and SEND): it silently left the PII-config PATCH
    // (`PATCH /api/query-anonymity/pii/config`, a real operator-config +
    // consent mutation dispatched below) on session-only auth. Default-deny
    // closes that class — a newly added non-GET route is gated automatically,
    // no allowlist edit required.
    //
    // The exempt set is the SMALL, EXPLICIT exception (mirrors the hub
    // read-style exempt set): non-GET routes that genuinely neither persist nor
    // mutate state and are intentionally loopback/session-readable. Today that
    // is ONLY `POST /api/query-anonymity/pii/rewrite` — a STATELESS preview
    // that runs the regex redactor over operator-supplied text and returns the
    // result (no persistence, no state leak), kept loopback-readable so the
    // dashboard's live PII preview works without a bearer. GET/read routes keep
    // `{ allowSession: true }` as before.
    const requiresOperatorBearer =
      method !== "GET" &&
      method !== "HEAD" &&
      !isDashboardReadStyleNonGet(method, url.pathname);
    if (
      !this.checkAuth(
        req,
        url,
        res,
        requiresOperatorBearer ? { requireToken: true } : { allowSession: true },
      )
    )
      return;

    // Sovereignty Posture Dashboard: the authenticated posture surface, namely
    // the per-agent drill-down HTML at `/posture/agent/:id` and the JSON gap
    // endpoints at `/api/posture/*`. Dispatched AFTER checkAuth (same gate as
    // `/api/audit-log`) and before the legacy route table. The dispatch is
    // async; when it serves the request it returns true, otherwise we fall
    // through to the legacy table below.
    //
    // NOTE (root-flip): the `/posture` HOME HTML is NOT served here. `GET /`
    // and `GET /posture` are intercepted earlier by `dispatchRootPosture`
    // (BEFORE checkAuth) and serve the one unauthenticated static shell, and
    // `handlePostureRoute` no longer carries a `/posture` HTML branch. So
    // `POSTURE_HOME_PATH` is intentionally absent from the condition below.
    if (
      url.pathname.startsWith(POSTURE_AGENT_PATH_PREFIX) ||
      // Phase 2: the Evidence View HTML shell is served by the posture router
      // AFTER checkAuth (same gate), so it gets the same auth model as the
      // per-agent drill-down and the JSON endpoints.
      url.pathname === POSTURE_EVIDENCE_PATH ||
      url.pathname === POSTURE_API_PREFIX ||
      url.pathname.startsWith(`${POSTURE_API_PREFIX}/`) ||
      // Phase 2: the query-privacy stats endpoint is dispatched through the
      // posture router so it shares the SAME checkAuth gate as `/api/posture/*`.
      url.pathname.startsWith(`${QUERY_ANONYMITY_API_PREFIX}/`)
    ) {
      // JSON posture routes get the general rate limit; the HTML view is
      // exempt (it is a dashboard view route, like `/` and `/fortress`).
      if (!isDashboardViewRoute(method, url.pathname)) {
        if (!this.checkRateLimit(req, res, "general")) return;
      }
      this.dispatchPosture(req, res, url, method)
        .then((handled) => {
          if (handled) return;
          if (!res.headersSent) {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Not found" }));
          }
        })
        .catch(() => {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal server error" }));
          }
        });
      return;
    }

    // Rate limiting: apply general limit to authenticated API requests only.
    // HTML view routes (`/`, `/dashboard`, `/fortress`) and the long-lived SSE
    // stream (`/events`) are exempt - operator page loads and browser
    // refreshes must never 429. Decision endpoints (approve/deny) and the
    // session-exchange endpoint keep their own stricter limits below.
    if (!isDashboardViewRoute(method, url.pathname)) {
      if (!this.checkRateLimit(req, res, "general")) return;
    }

    try {
      if (method === "GET" && url.pathname === "/fleet") {
        this.serveFleetSwitcher(res);
      } else if (method === "GET" && url.pathname === "/fortress") {
        this.serveFortressView(res);
      } else if (method === "GET" && url.pathname === "/v1.0") {
        // v1.1.7: legacy v1.0 dashboard preserved at /v1.0. Root serves the
        // posture shell; /dashboard and /v1.1 remain v1.1 SPA aliases.
        if (this.fortressHTML) {
          this.serveFortressView(res);
        } else {
          this.serveDashboard(res);
        }
      } else if (method === "GET" && url.pathname === "/events") {
        this.handleSSE(req, res);
      } else if (method === "GET" && url.pathname === "/api/status") {
        this.handleStatus(res);
      } else if (method === "GET" && url.pathname === "/api/snapshot") {
        // v1.3.3 fix (F-1.3.2-N-002): the standalone dashboard served its
        // HTTP surface through this legacy route table, which never
        // registered /api/snapshot; the route only existed in the
        // co-located server (dashboard/api.ts). Direct curl hits and any
        // client following the documented snapshot endpoint got a 404 in
        // standalone mode. Serve the same ProtectionSnapshot shape here,
        // built from the dependencies this channel already holds.
        this.handleSnapshot(res);
      } else if (method === "GET" && url.pathname === "/api/pending") {
        this.handlePendingList(res);
      } else if (method === "GET" && url.pathname === "/api/audit-log") {
        this.handleAuditLog(url, res);
      } else if (method === "GET" && url.pathname === "/api/sovereignty") {
        this.handleSovereignty(res);
      } else if (method === "GET" && url.pathname === "/api/identity") {
        this.handleIdentity(res);
      } else if (method === "GET" && url.pathname === "/api/handshakes") {
        this.handleHandshakes(res);
      } else if (method === "GET" && url.pathname === "/api/shr") {
        this.handleSHR(res);
      } else if (method === "GET" && url.pathname === "/api/sovereignty-profile") {
        this.handleSovereigntyProfileGet(res);
      } else if (method === "POST" && url.pathname === "/api/sovereignty-profile") {
        this.handleSovereigntyProfileUpdate(req, res);
      } else if (method === "GET" && url.pathname === "/api/proxy/servers") {
        this.handleProxyServers(res);
      } else if (method === "POST" && url.pathname === "/api/proxy/servers") {
        this.handleProxyServersUpdate(req, res);
      } else if (method === "POST" && url.pathname === "/api/fleet/activate") {
        // Fleet control plane PR-B: the operator pastes a license key and this
        // activates it - verifies the paste through the shipped Ed25519
        // entitlement core against the pinned issuer key and, on success,
        // persists it into signed, tamper-evident fleet state so the CENTRAL
        // roster lifts its node-count cap.
        //
        // AUTH (fail-closed): activation changes the PAID PRODUCT BOUNDARY, a
        // Tier-1-class mutation, so it requires the operator BEARER TOKEN. The
        // default-deny gate above already re-checks every non-GET route with
        // `{ requireToken: true }` (fail-closed: denies when no token is
        // configured, never honors loopback auto-auth or a session), but we make
        // that explicit here so this billing-critical mutation carries its own
        // local, unmissable gate independent of the shared exempt-set logic.
        //
        // NEVER GATES SECURITY: the handler resolves MANAGEMENT capacity only. It
        // touches no wall / enforcement / local-dashboard / policy-push /
        // kill-safety path.
        if (!this.checkAuth(req, url, res, { requireToken: true })) return;
        this.handleFleetActivate(req, res);
      } else if (method === "GET" && url.pathname === "/api/fleet/status") {
        // Fleet control plane PR-3: the DOWNGRADE BANNER state. Reports the
        // current tier/cap, whether the plan is expiring/expired/revoked/over-cap
        // and why, and that renewing restores console management. Read-only; never
        // gates security; carries no key material. Fire-and-forget (the async
        // handler owns writing the response), matching this dispatch's contract.
        void this.handleFleetStatus(res);
      } else if (method === "GET" && url.pathname === "/api/fleet/downgrade-log") {
        // Fleet control plane PR-3: the OPERATOR-VISIBLE downgrade log. Answers
        // "these N nodes left the console because the plan lapsed - their walls
        // are still up" in one read. Read-only; no key material.
        void this.handleFleetDowngradeLog(res);
      } else if (
        method === "POST" &&
        url.pathname === "/api/fleet/revocation-list"
      ) {
        // Fleet control plane PR-3: push a SIGNED license revocation list. Like
        // activation this changes the paid product boundary (it can DROP a
        // license to Community), so it requires the operator bearer token and is
        // verified against the pinned issuer key + monotonic version before it is
        // persisted. NEVER gates security: it only removes paid MANAGEMENT
        // capacity for a revoked license; every node's wall stays up.
        if (!this.checkAuth(req, url, res, { requireToken: true })) return;
        this.handleFleetRevocationListPush(req, res);
      } else if (method === "GET" && url.pathname === "/api/fleet/capacity") {
        // Fleet control plane, Add-Machine slice: the honest "enrollment
        // headroom" read the Add-Machine UI needs before it invites a node.
        // Read-only; fail-closed to the community floor on any read failure;
        // never gates security; carries no key material.
        void this.handleFleetCapacity(res);
      } else if (
        method === "POST" &&
        url.pathname === "/api/fleet/enroll-token"
      ) {
        // Fleet control plane, Add-Machine slice: the dashboard-side "Add a
        // machine" button. Mints a bootstrap token through the SAME ceremony
        // primitive the CLI's `sanctuary federation authorize` drives. Changes
        // fleet membership intent, so gate it with the operator bearer token
        // exactly like `/api/fleet/activate` and `/api/fleet/revocation-list`
        // (the default-deny gate above already re-checks every non-GET route
        // with `{ requireToken: true }`; made explicit and local here too).
        // NEVER GATES SECURITY: the at-capacity pre-check is advisory
        // MANAGEMENT-CAPACITY UX, not enforcement; it touches no wall /
        // enforcement / local-dashboard / policy-push / kill-safety path.
        if (!this.checkAuth(req, url, res, { requireToken: true })) return;
        this.handleFleetEnrollToken(req, res);
      } else if (method === "POST" && url.pathname.startsWith("/api/approve/")) {
        // Decision endpoints get an additional tighter rate limit
        if (!this.checkRateLimit(req, res, "decisions")) return;
        const id = url.pathname.slice("/api/approve/".length);
        this.handleDecision(id, "approve", res);
      } else if (method === "POST" && url.pathname.startsWith("/api/deny/")) {
        // Decision endpoints get an additional tighter rate limit
        if (!this.checkRateLimit(req, res, "decisions")) return;
        const id = url.pathname.slice("/api/deny/".length);
        this.handleDecision(id, "deny", res);
      } else {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
      }
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }

  // ── Route Handlers ──────────────────────────────────────────────────

  /**
   * SEC-012: Exchange a long-lived auth token (in Authorization header)
   * for a short-lived session ID. The session ID can be used in URL
   * query parameters without exposing the long-lived credential.
   *
   * This endpoint performs its OWN auth check (header-only) because it
   * must reject query-parameter tokens and is called before the
   * normal checkAuth flow.
   */
  private handleSessionExchange(req: IncomingMessage, res: ServerResponse): void {
    if (!this.authToken) {
      // Auth disabled - sessions not needed
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ session_id: "no-auth" }));
      return;
    }

    // Only accept the long-lived token via Authorization header - NEVER from URL.
    //
    // SECURITY (invariant 7, no auth oracle): a MISSING Authorization header and
    // a PRESENT-but-WRONG bearer return a BYTE-IDENTICAL generic 401. The prior
    // split ("Authorization header required" vs "Invalid bearer token") was an
    // oracle that told an unauthenticated caller whether it had supplied a
    // header at all - a distinction a co-resident agent could probe. Both
    // failure modes now collapse to the same generic body, matching the generic
    // posture elsewhere in this file (checkAuth -> "unauthorized"; unlock ->
    // "unlock failed"). The response is sent constant-shape regardless of which
    // sub-check failed.
    const authHeader = req.headers.authorization;
    const parts = authHeader?.split(" ");
    const hasValidBearer =
      parts?.length === 2 &&
      parts[0] === "Bearer" &&
      constantTimeEquals(parts[1]!, this.authToken);
    if (!hasValidBearer) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "authentication required" }));
      return;
    }

    const sessionId = this.createSession();
    const ttlSeconds = Math.floor(this.sessionTTLMs / 1000);
    // SameSite=Lax (not Strict): the Fleet Switcher is served by ONE host but
    // its "Open Console" links navigate the SAME TAB to a DIFFERENT host's
    // dashboard root. Under SameSite=Strict the browser withholds the session
    // cookie on that cross-site top-level navigation, so a remote console the
    // operator already authenticated re-prompts for the token on every visit
    // even while the session is still valid (the C1 re-auth defect). Lax sends
    // the cookie on top-level GET navigations (the Open Console click, a typed
    // URL, a reload) so a still-valid session is reused without re-prompting.
    //
    // This does NOT weaken auth: Lax still withholds the cookie on cross-site
    // SUBREQUESTS and cross-site POSTs, so the approval-decision routes
    // (POST /api/approve/:id, /api/deny/:id) remain CSRF-safe — a cross-origin
    // page cannot drive a state-changing decision off this cookie. A request
    // with no valid token AND no valid session still gets the login page / 401
    // (isAuthenticated / checkAuth are unchanged); only a genuinely-valid,
    // unexpired session is reused. The TTL is unchanged — we reuse the existing
    // session, we do not lengthen it.
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Set-Cookie": `sanctuary_session=${sessionId}; Path=/; SameSite=Lax; Max-Age=${ttlSeconds}`,
    });
    res.end(JSON.stringify({
      session_id: sessionId,
      expires_in_seconds: ttlSeconds,
    }));
  }

  /**
   * Slice 2 (park-not-exit): handle the authenticated in-process unlock POST.
   * Auth + rate limit are enforced by the caller (operator token required even
   * on loopback). This method validates the body, forwards the credential to
   * the registered unlock handler (which re-runs establishMaster + wires the
   * unlocked deps), and returns a GENERIC result.
   *
   * Fail-closed posture:
   *   - No unlock handler registered (park not enabled): 404 generic.
   *   - Already unlocked: 409 generic (idempotent guard; the read surface is
   *     already serving, nothing to do).
   *   - Malformed / oversized body: 400 generic.
   *   - Wrong credential: 401 generic "unlock failed". NO oracle about which
   *     rule/tier failed (invariant 7); the process STAYS parked.
   *   - Success: 200 `{ unlocked: true }`; readiness has already flipped to
   *     "serving" inside the handler.
   */
  private handleUnlockRequest(req: IncomingMessage, res: ServerResponse): void {
    if (!this.unlockHandler) {
      // Park not enabled on this dashboard: no unlock door exists. Generic 404
      // so the absence of the door is not itself a state oracle.
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }
    if (!this._parked) {
      // Already unlocked (or never parked): nothing to do. Generic 409.
      res.writeHead(409, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Already unlocked" }));
      return;
    }

    let body = "";
    let destroyed = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      // Size limit: 8KB is ample for a passphrase / recovery key.
      if (body.length > 8192) {
        destroyed = true;
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        req.destroy();
      }
    });
    req.on("end", async () => {
      if (destroyed) return;
      let credential: UnlockCredential;
      try {
        const parsed = JSON.parse(body) as Record<string, unknown>;
        const passphrase = parsed.passphrase;
        const recoveryKey = parsed.recovery_key ?? parsed.recoveryKey;
        if (typeof passphrase === "string" && passphrase.length > 0) {
          credential = { passphrase };
        } else if (typeof recoveryKey === "string" && recoveryKey.length > 0) {
          credential = { recoveryKey };
        } else {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "Provide a passphrase or recovery_key",
            }),
          );
          return;
        }
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON body" }));
        return;
      }

      // Re-check the handler/park state inside the async tail: a concurrent
      // unlock could have flipped us out of parked while the body streamed.
      if (!this.unlockHandler || !this._parked) {
        res.writeHead(409, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Already unlocked" }));
        return;
      }

      let unlocked: boolean;
      try {
        unlocked = await this.unlockHandler(credential);
      } catch {
        // A handler-internal failure (wrong-key throw, wiring error) must not
        // leak detail and must leave the process parked. Generic failure.
        unlocked = false;
      }

      if (unlocked) {
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        res.end(JSON.stringify({ unlocked: true }));
        return;
      }
      // Generic, no oracle: the process stays parked, fail-closed.
      res.writeHead(401, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify({ error: "Unlock failed" }));
    });
  }

  /**
   * Fleet control plane PR-B: `POST /api/fleet/activate`. The operator pastes a
   * license blob in `{ "license": "<paste>" }`; this streams + parses the body,
   * hands the paste to {@link activateFleetLicense} (verify → persist), and
   * serializes the plain result. Auth is enforced by the caller (operator bearer
   * token, `{ requireToken: true }`, fail-closed); this handler carries no key
   * material and leaks no stack.
   *
   * Response shape:
   *   - 200 `{ ok: true, tier, max_nodes }` on a verified paste (`max_nodes` null
   *     = unlimited / Team+).
   *   - 400 `{ ok: false, reason }` on a rejected paste (bad license is a client
   *     error, never a 500 leak, never a silent grant).
   *   - 400 `{ error: "validation_error" }` when the `license` field is missing
   *     or empty; 400 `{ error: "Invalid JSON body" }` on unparseable JSON.
   *   - 500 `{ error: "internal_error" }` on an unexpected throw (no grant leaked).
   *
   * NEVER GATES SECURITY: resolves MANAGEMENT capacity only; touches no wall /
   * enforcement / local-dashboard / policy-push / kill-safety path.
   */
  private handleFleetActivate(
    req: IncomingMessage,
    res: ServerResponse,
  ): void {
    let body = "";
    let destroyed = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      // Size limit: 16KB is ample for a base64url license token paste.
      if (body.length > 16384) {
        destroyed = true;
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        req.destroy();
      }
    });
    req.on("end", async () => {
      if (destroyed) return;
      let pasted: string;
      try {
        const parsed = JSON.parse(body) as Record<string, unknown>;
        const license = parsed.license;
        if (typeof license !== "string" || license.trim().length === 0) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "validation_error",
              message: "license is required and must be a non-empty string",
            }),
          );
          return;
        }
        pasted = license;
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON body" }));
        return;
      }

      // The handler is contracted to never throw and to fail-closed, but guard
      // anyway so an unexpected internal error is a 500, never a leaked stack or
      // a silent grant.
      try {
        const result = await this.activateFleetLicense(pasted);
        if (result.ok) {
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(
            JSON.stringify({
              ok: true,
              tier: result.tier,
              max_nodes: result.max_nodes,
            }),
          );
        } else {
          // A rejected paste is a 400 client error (bad license), not a server
          // error. No secret, no stack: just the operator-facing reason.
          res.writeHead(400, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(JSON.stringify({ ok: false, reason: result.reason }));
        }
      } catch {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    });
  }

  /**
   * Fleet control plane PR-3: `GET /api/fleet/status` - the DOWNGRADE BANNER
   * state. Reports the currently-resolved tier + node cap, a plain-English banner
   * state ("ok" | "expiring" | "expired" | "revoked" | "over_cap" |
   * "revocation_list_unreadable"), the reason, and how many nodes are currently
   * dropped from the central console (their walls are unaffected). Read-only;
   * fail-closed to a community-floor banner on any read failure; NEVER gates
   * security; carries no key material.
   */
  private async handleFleetStatus(res: ServerResponse): Promise<void> {
    try {
      const cap = await this.resolveFleetCap();

      // How many nodes are out of the central console under the current cap.
      let droppedNodes = 0;
      let admitted = 0;
      let revocationListUnreadable = false;
      try {
        const roster = buildFleetRoster(this.buildV1FederationDeps(), {
          evictionSerial: this._federationState.evictionMaxSerial,
          operatorPolicy: this._federationState.operatorPolicy,
        });
        admitted = roster.summary.admitted;
        droppedNodes = applyFleetCap(roster, cap).droppedNodeCount;
      } catch {
        // Roster unavailable: report 0 dropped (honest absence), banner still valid.
      }
      const storage = this.storage;
      const masterKey = this.shrOpts?.masterKey;
      if (storage && masterKey) {
        try {
          // Source the banner's unverifiable determination from the SAME
          // chokepoint enforcement uses ({@link revocationVerifiability}), NOT a
          // parallel `readRevocationList` corrupt-only check. Enforcement drops a
          // paid grant toward Community whenever the chokepoint reports
          // `unverifiable` for ANY reason - corrupt, absent-after-an-established-
          // floor (delete bypass), rolled-back-below-floor, or a transient that
          // never clears above an established floor. A corrupt-only banner check
          // caught only the first, so a deleted/rolled-back list was CORRECTLY
          // dropped by enforcement but MISLABELED "revoked" in the banner instead
          // of the operator-actionable "re-push" (revocation-list-unreadable)
          // state. Deriving from the chokepoint makes the banner match what
          // enforcement actually did.
          const verifiability = await revocationVerifiability(storage, masterKey);
          revocationListUnreadable = verifiability.status === "unverifiable";
        } catch {
          revocationListUnreadable = true;
        }
      }

      const bannerState = this.classifyFleetBanner(
        cap,
        droppedNodes,
        revocationListUnreadable,
      );
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(
        JSON.stringify({
          tier: cap.tier,
          paid: cap.paid,
          max_nodes: cap.maxNodes,
          grace_active: cap.graceActive,
          reason: cap.reason,
          banner_state: bannerState,
          dropped_node_count: droppedNodes,
          admitted_node_count: admitted,
          revocation_list_unreadable: revocationListUnreadable,
          // The one-click reassurance every fail-closed banner MUST carry: paid
          // features drop, security never does.
          security_unaffected: true,
          renew_restores_console: !cap.paid || cap.graceActive === true,
        }),
      );
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  }

  /**
   * Classify the operator-facing banner state from the resolved cap + how many
   * nodes are currently out of console. PURE-ish (reads only its arguments):
   *  - "revocation_list_unreadable": a corrupt local revocation list (re-push);
   *    surfaced FIRST because it means the operator's revocation intent may not be
   *    applied.
   *  - "revoked" / "expired": a paid plan that has been revoked or has lapsed to
   *    Community.
   *  - "expiring": a paid grant honored during its grace window (renew soon).
   *  - "over_cap": Community/paid but more nodes than the cap (some out of console).
   *  - "ok": paid + within cap, or Community within the free cap.
   */
  private classifyFleetBanner(
    cap: FleetCap,
    droppedNodes: number,
    revocationListUnreadable: boolean,
  ): "ok" | "expiring" | "expired" | "revoked" | "over_cap" | "revocation_list_unreadable" {
    if (revocationListUnreadable) return "revocation_list_unreadable";
    if (cap.graceActive === true) return "expiring";
    if (!cap.paid) {
      // Community floor: distinguish a lapsed/revoked/expired plan from a plain
      // never-paid fortress by the fail-closed reason.
      if (cap.reason === "expired") return "expired";
      if (cap.reason === "invalid" || cap.reason === "unreadable") return "revoked";
      if (droppedNodes > 0) return "over_cap";
      return "ok";
    }
    // Paid + within window.
    return droppedNodes > 0 ? "over_cap" : "ok";
  }

  /**
   * Fleet control plane PR-3: `GET /api/fleet/downgrade-log` - the operator-
   * readable, append-only log of every tier/cap transition with its reason and
   * the affected node ids. Read-only; fail-closed to an empty log on missing
   * custody; surfaces a `readable: false` flag when the stored log is corrupt.
   * Carries no key material.
   */
  private async handleFleetDowngradeLog(res: ServerResponse): Promise<void> {
    try {
      const storage = this.storage;
      const masterKey = this.shrOpts?.masterKey;
      if (!storage || !masterKey) {
        // No unlocked custody: honest empty log rather than a fabricated one.
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        res.end(JSON.stringify({ entries: [], readable: true, custody: false }));
        return;
      }
      const log = await readDowngradeLog(storage, masterKey);
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      // Newest-first is the natural read order for an operator scanning "what
      // just changed"; the stored log is oldest-first.
      res.end(
        JSON.stringify({
          entries: [...log.entries].reverse(),
          readable: log.readable,
          custody: true,
        }),
      );
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  }

  /**
   * Fleet control plane PR-3: `POST /api/fleet/revocation-list` - accept a SIGNED
   * revocation list `{ payload, signature }`, verify it against the PINNED issuer
   * key + a strictly-greater monotonic version, and persist it. A revoked
   * license is then forced to Community by the re-resolve path. Auth is enforced
   * by the caller (operator bearer token). Response:
   *   - 200 `{ ok: true, version, revoked_count }` on a verified, newer list.
   *   - 400 `{ ok: false, reason }` on malformed / bad_signature / not_newer.
   *   - 400 `{ error: "validation_error" }` on a missing body; 500 on unexpected.
   * NEVER gates security; carries no key material; leaks no stack.
   */
  private handleFleetRevocationListPush(
    req: IncomingMessage,
    res: ServerResponse,
  ): void {
    let body = "";
    let destroyed = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      // 256KB is ample for a signed id list; a revocation list is small.
      if (body.length > 262144) {
        destroyed = true;
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        req.destroy();
      }
    });
    req.on("end", async () => {
      if (destroyed) return;
      let signed: unknown;
      try {
        signed = JSON.parse(body);
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON body" }));
        return;
      }
      try {
        const result = await this.applyPushedRevocationList(signed);
        if (result.ok) {
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(
            JSON.stringify({
              ok: true,
              version: result.version,
              revoked_count: result.revokedCount,
            }),
          );
        } else {
          res.writeHead(400, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(JSON.stringify({ ok: false, reason: result.reason }));
        }
      } catch {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    });
  }

  /**
   * Verify + persist a pushed signed revocation list, FAIL-CLOSED. Verifies
   * against the PINNED issuer key (the fortress's own operator identity, the same
   * key `resolveActivation` pins) and a strictly-greater monotonic version, then
   * persists the authenticated payload. Never throws; never persists an
   * unverified list. After a successful push it re-runs one re-resolve tick so a
   * now-revoked active license drops to Community immediately (not only on the
   * next hourly tick).
   */
  private async applyPushedRevocationList(
    signed: unknown,
  ): Promise<
    | { ok: true; version: number; revokedCount: number }
    | { ok: false; reason: "no_custody" | "no_issuer" | "malformed" | "bad_signature" | "not_newer" }
  > {
    const storage = this.storage;
    const masterKey = this.shrOpts?.masterKey;
    if (!storage || !masterKey) {
      return { ok: false, reason: "no_custody" };
    }
    const issuerPublicKey = this.resolveFleetIssuerPublicKey();
    if (issuerPublicKey === null) {
      return { ok: false, reason: "no_issuer" };
    }
    // Capture the PRE-push resolved cap as the prior state so the immediate
    // re-resolve below observes the real paid -> Community transition (and logs
    // it) even if no scheduled tick happened to run while the license was paid.
    // Without this, a boot-Community -> activate -> revoke sequence would leave
    // `_fleetPriorCap` at Community and the paid->revoked drop would go unlogged.
    try {
      const prePushCap = await this.resolveFleetCap();
      this._fleetPriorCap = {
        tier: prePushCap.tier,
        maxNodes: prePushCap.maxNodes,
      };
    } catch {
      // Best-effort prior seeding; the tick still runs and fails closed.
    }
    // The SINGLE serialized push path (shared with the CLI): a cross-process
    // O_EXCL lock re-reads the effective floor INSIDE the lock and re-verifies
    // monotonicity against it, then persists list -> anchor -> custody-MAC'd
    // witness latch in crash-safe order. Two concurrent pushes (v6 + v7) cannot
    // both pass against a stale floor and interleave the list vs the anchor/latch.
    // The floor is the EXTERNALLY-ANCHORED + witness-bound version, so a corrupt or
    // DELETED list file can never roll it back to 0.
    let result: Awaited<ReturnType<typeof persistPushedRevocationListSerialized>>;
    try {
      result = await persistPushedRevocationListSerialized({
        storage,
        master: masterKey,
        signed,
        issuerPublicKey,
      });
    } catch {
      // A genuine persist/IO error (or lock contention past the bounded timeout):
      // fail closed. Nothing partially trusted - the max() floor keeps any partial
      // write safe. Report `malformed` is wrong; surface a distinct persist error.
      return { ok: false, reason: "malformed" };
    }
    if (!result.ok) {
      return { ok: false, reason: result.reason };
    }
    // Reconcile immediately: a now-revoked active license drops to Community and
    // the transition is logged without waiting for the hourly tick.
    void this.runFleetLicenseReResolveTick();
    return {
      ok: true,
      version: result.version,
      revokedCount: result.revokedCount,
    };
  }

  /**
   * Fleet control plane, Add-Machine slice: resolve the pure enrollment
   * headroom view AND a "was the active-node count reliably derived" signal,
   * by composing SHIPPED parts only (the existing private
   * {@link resolveFleetCap} plus the durable roster via
   * `buildFleetRoster(...)`, as {@link activateFleetLicense} already does),
   * and feeding both into the pure {@link computeFleetCapacityView}.
   *
   * `rosterCountReliable` distinguishes two different "no active count"
   * shapes that must NOT be treated the same by every caller:
   *  - `buildFleetRoster` returns normally with `available: false`
   *    (federation genuinely not provisioned on this fortress): there IS no
   *    fleet, so `active_nodes: 0` is an honest count. `rosterCountReliable`
   *    is `true` here.
   *  - `buildFleetRoster` THROWS (an unexpected derivation failure, e.g. a
   *    transient revocation-state read error) while federation IS
   *    provisioned/enabled: the real roster size is UNKNOWN, not zero.
   *    `rosterCountReliable` is `false` here, and `active_nodes: 0` in the
   *    returned view must be read as "unavailable", never as "genuinely
   *    empty".
   *
   * Never throws: `resolveFleetCap` itself is already fail-closed to the
   * community floor, and a roster derivation failure is caught and reported
   * via `rosterCountReliable`, not re-thrown.
   */
  private async computeFleetCapacityWithReliability(): Promise<{
    view: FleetCapacityView;
    rosterCountReliable: boolean;
  }> {
    const cap = await this.resolveFleetCap();
    let activeNodes = 0;
    let rosterCountReliable = true;
    try {
      const roster = buildFleetRoster(this.buildV1FederationDeps(), {
        evictionSerial: this._federationState.evictionMaxSerial,
        operatorPolicy: this._federationState.operatorPolicy,
      });
      if (roster.available) {
        activeNodes = roster.summary.admitted;
      }
    } catch {
      // Roster derivation failed while federation is (or may be) provisioned:
      // the true count is UNKNOWN, not zero. Callers that gate a mutation
      // (e.g. the enroll-token mint pre-check) must fail closed on this
      // signal rather than read active_nodes as "0 active, plenty of room".
      activeNodes = 0;
      rosterCountReliable = false;
    }
    return {
      view: computeFleetCapacityView(cap, activeNodes),
      rosterCountReliable,
    };
  }

  /**
   * Fleet control plane, Add-Machine slice: resolve the pure enrollment
   * headroom view for READ-ONLY display surfaces (`GET /api/fleet/capacity`).
   * A roster derivation failure still reports `active_nodes: 0` here (honest
   * absence for a status panel); see
   * {@link computeFleetCapacityWithReliability} for the reliability signal the
   * enroll-token MINT gate uses to fail closed instead of proceeding as if 0
   * nodes were active. Never throws.
   */
  private async computeFleetCapacity(): Promise<FleetCapacityView> {
    const { view } = await this.computeFleetCapacityWithReliability();
    return view;
  }

  /**
   * Fleet control plane, Add-Machine slice: `GET /api/fleet/capacity`. The
   * honest "enrollment headroom" read the Add-Machine UI needs before it
   * invites a node: tier, max_nodes (null = unlimited), active_nodes,
   * remaining headroom, and whether the fleet is at capacity. Read-only, no
   * bearer mutation, no key material. NEVER GATES SECURITY: advisory
   * management-capacity UX only; touches no wall / enforcement /
   * local-dashboard / policy-push / kill-safety path. Never throws.
   */
  private async handleFleetCapacity(res: ServerResponse): Promise<void> {
    try {
      const view = await this.computeFleetCapacity();
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(view));
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  }

  /**
   * Fleet control plane, Add-Machine slice: parse + FULLY validate a
   * `POST /api/fleet/enroll-token` request body into a closed, server-typed
   * result BEFORE any enrollment decision runs. Pure: no I/O, no instance
   * state, never throws (a malformed or unparseable body becomes a tagged
   * `ok: false` result carrying the exact status + JSON payload to send, not
   * an exception).
   *
   * Security note: this is INPUT VALIDATION, not a security gate. The real
   * enrollment gates (paid node-cap, federation-provisioned + issuer
   * authority, the join ceremony) all run AFTER this and are derived purely
   * from server-side state, never from the request body. `node_id` is only a
   * label bound into the minted token; `node_mode` is normalized to a closed
   * enum and never selects a capacity bucket (the cap is checked against the
   * TOTAL admitted roster count). Isolating validation here keeps the
   * attacker-controlled `node_id`/`node_mode` out of every condition that
   * dominates the mint: the handler branches only on the tagged `ok` flag, so
   * no request-body value can influence whether the mint runs. It can only
   * ever reject its own malformed request; it can never bypass a gate.
   */
  private parseFleetEnrollTokenBody(body: string): FleetEnrollTokenBodyParse {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return {
        ok: false,
        status: 400,
        payload: { error: "Invalid JSON body" },
      };
    }
    const rawNodeId = parsed.node_id;
    if (typeof rawNodeId !== "string" || rawNodeId.trim().length === 0) {
      return {
        ok: false,
        status: 400,
        payload: {
          error: "validation_error",
          message: "node_id is required and must be a non-empty string",
        },
      };
    }
    const rawNodeMode = parsed.node_mode;
    if (
      rawNodeMode !== "local" &&
      rawNodeMode !== "operator_cloud" &&
      rawNodeMode !== "sovereign_tee"
    ) {
      return {
        ok: false,
        status: 400,
        payload: {
          error: "validation_error",
          message:
            "node_mode must be one of local, operator_cloud, sovereign_tee",
        },
      };
    }
    return { ok: true, nodeId: rawNodeId, nodeMode: rawNodeMode };
  }

  /**
   * Fleet control plane, Add-Machine slice: `POST /api/fleet/enroll-token`.
   * The dashboard-side "Add a machine" button. Body: `{ node_id: string,
   * node_mode: "local" | "operator_cloud" | "sovereign_tee" }`.
   *
   * This is a THIN in-process wrapper over the SAME ceremony primitive
   * `runFederationAuthorize` drives over HTTP (`JoinCeremony.authorizeInit`,
   * the daemon-side entry the `/v1/federation/authorize/init` route
   * dispatches to). It mints the SAME bootstrap-token artifact the CLI verb
   * prints to stdout (a public signed authorization to submit a JoinRequest),
   * NOT membership and NOT a secret (AGENTS.md #6: no private key, no master,
   * no passphrase in the response).
   *
   * CAPACITY PRE-CHECK (the product point of this slice): before minting,
   * resolves the SAME capacity view as `GET /api/fleet/capacity`. If
   * `at_capacity` and the cap is finite, returns 409 `at_capacity`. This is
   * advisory MANAGEMENT-CAPACITY UX, not enforcement (the real node-count
   * enforcement is the already-shipped `applyFleetCap` on the central
   * roster). It never touches the wall/enforcement/policy-push path, and a
   * bug here can only ever over-block enrollment, never over-admit a node.
   *
   * AUTH: gated by the operator bearer token by the caller (matches
   * `/api/fleet/activate` and `/api/fleet/revocation-list`).
   *
   * Response shape:
   *   - 200 `{ ok: true, bootstrap_token }` on a successful mint.
   *   - 400 `{ error: "validation_error" }` on a missing/malformed `node_id`
   *     or `node_mode`, or `{ error: "Invalid JSON body" }` on unparseable
   *     JSON.
   *   - 409 `{ error: "at_capacity", active_nodes, max_nodes, message }` when
   *     the fleet is at its finite paid node cap (fail-closed courtesy; see
   *     above).
   *   - 503 `{ error: "capacity_unavailable", message }` when the durable
   *     roster's active-node count could not be reliably derived (e.g. a
   *     roster-derivation throw). This is the fail-closed branch for the
   *     MINT gate specifically: an unreliable count must never be read as
   *     "0 active, plenty of room" (that would be fail-open on a paid
   *     enrollment gate). `GET /api/fleet/capacity` is unaffected and may
   *     still display `active_nodes: 0` on the same underlying condition;
   *     that surface is read-only and never mints.
   *   - 409 `{ error: "federation_not_provisioned" }` when federation is not
   *     enabled/provisioned on this fortress, or this fortress cannot mint
   *     (a non-issuer context, e.g. an operator_cloud or joiner node): never
   *     a fabricated token, never a silent success (AGENTS.md #5).
   *   - 500 `{ error: "internal_error" }` on an unexpected throw (no key
   *     material leaked; no stack).
   */
  private handleFleetEnrollToken(
    req: IncomingMessage,
    res: ServerResponse,
  ): void {
    let body = "";
    let destroyed = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      // 4KB is ample for { node_id, node_mode }.
      if (body.length > 4096) {
        destroyed = true;
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        req.destroy();
      }
    });
    req.on("end", async () => {
      if (destroyed) return;
      // Parse + fully validate the request body up front into a closed,
      // server-typed result. The handler then branches ONLY on the tagged
      // `ok` flag, so no attacker-controlled body value (node_id / node_mode)
      // syntactically controls any condition that dominates the mint below.
      // This is input validation, not a security gate; the real gates
      // (capacity, federation authority, ceremony) run afterward on
      // server-derived state alone. See parseFleetEnrollTokenBody.
      const parseResult = this.parseFleetEnrollTokenBody(body);
      if (!parseResult.ok) {
        res.writeHead(parseResult.status, {
          "Content-Type": "application/json",
        });
        res.end(JSON.stringify(parseResult.payload));
        return;
      }
      const { nodeId, nodeMode } = parseResult;

      // Build the federation deps ONCE for this request (pure synchronous
      // object construction; every closure reads live `this` state, so a
      // single instance observes the same state as per-call rebuilds did).
      const federationDeps = this.buildV1FederationDeps();

      try {
        // Capacity pre-check FIRST: an operator at cap should never even
        // reach the ceremony. Advisory UX only (see doc comment above); the
        // real enforcement is applyFleetCap on the central roster, untouched.
        //
        // Fail-closed exception (MEDIUM finding fix): this MINT path, unlike
        // the read-only GET /api/fleet/capacity panel, must NOT proceed as if
        // the roster were genuinely empty when the roster count could not be
        // reliably derived (buildFleetRoster threw). Reading an unreliable
        // "0 active" as real headroom would mint a token even when the true
        // roster is at or over cap, fail-OPEN on a paid enrollment gate. So
        // when the count is unreliable, refuse to mint rather than guess.
        const { view: capacity, rosterCountReliable } =
          await this.computeFleetCapacityWithReliability();
        if (!rosterCountReliable) {
          res.writeHead(503, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(
            JSON.stringify({
              error: "capacity_unavailable",
              message:
                "Cannot determine current fleet node count; refusing to mint an enrollment token. Try again shortly.",
            }),
          );
          void federationDeps.audit({
            operation: "fleet_enroll_token_mint",
            result: "failure",
            identityId: nodeId,
            details: { reason: "capacity_unavailable" },
          });
          return;
        }
        if (capacity.at_capacity && capacity.max_nodes !== null) {
          res.writeHead(409, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(
            JSON.stringify({
              error: "at_capacity",
              active_nodes: capacity.active_nodes,
              max_nodes: capacity.max_nodes,
              message:
                `This fleet is at its paid node cap (${capacity.max_nodes}). ` +
                "Upgrade your plan or remove a node from the console to " +
                "enroll another. Every existing node keeps its Castle Wall protection.",
            }),
          );
          void federationDeps.audit({
            operation: "fleet_enroll_token_mint",
            result: "failure",
            identityId: nodeId,
            details: { reason: "at_capacity" },
          });
          return;
        }

        const ctx = this._federationContext;
        if (
          !this._federationEnabled ||
          ctx === null ||
          !federationContextHasIssuerAuthority(ctx)
        ) {
          // Federation disabled/unprovisioned, or this fortress cannot mint
          // (e.g. a non-issuer joiner/operator_cloud context): fail closed,
          // never a fabricated token.
          res.writeHead(409, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(JSON.stringify({ error: "federation_not_provisioned" }));
          void federationDeps.audit({
            operation: "fleet_enroll_token_mint",
            result: "failure",
            identityId: nodeId,
            details: { reason: "federation_not_provisioned" },
          });
          return;
        }

        let bootstrapToken: BootstrapToken;
        try {
          bootstrapToken = new JoinCeremony(ctx).authorizeInit({
            intendedNodeId: nodeId,
            intendedNodeMode: nodeMode,
          });
        } catch {
          res.writeHead(409, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(JSON.stringify({ error: "federation_not_provisioned" }));
          void federationDeps.audit({
            operation: "fleet_enroll_token_mint",
            result: "failure",
            identityId: nodeId,
            details: { reason: "mint_unavailable" },
          });
          return;
        }

        res.writeHead(200, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        res.end(JSON.stringify({ ok: true, bootstrap_token: bootstrapToken }));
        void federationDeps.audit({
          operation: "fleet_enroll_token_mint",
          result: "success",
          identityId: nodeId,
          details: { node_mode: nodeMode, nonce: bootstrapToken.nonce },
        });
      } catch {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    });
  }

  private serveLoginPage(res: ServerResponse): void {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache, no-store",
    });
    res.end(this.loginHTML);
  }

  private serveDashboard(res: ServerResponse): void {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(this.dashboardHTML);
  }

  private serveFortressView(res: ServerResponse): void {
    if (!this.fortressHTML) {
      // Fallback to standard dashboard
      this.serveDashboard(res);
      return;
    }
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(this.fortressHTML);
  }

  /**
   * Enable Fortress View (proxy mode) with the given upstream server count.
   * Once enabled, the root path `/` serves the Fortress View instead of the
   * standard dashboard. The standard dashboard remains available at `/dashboard`.
   */
  enableFortressView(upstreamServerCount: number): void {
    this.fortressHTML = generateFortressViewHTML({
      serverVersion: PKG_VERSION,
      authToken: this.authToken,
      upstreamServerCount,
    });
  }

  /**
   * Broadcast a proxy call event to connected dashboards (Fortress View feed).
   */
  broadcastProxyCall(data: {
    tool: string;
    server: string;
    decision: string;
    reason?: string;
    tier?: number;
    timestamp: string;
  }): void {
    this.broadcastSSE("proxy-call", data);
  }

  private handleSSE(req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });

    // Send initial state
    const initData: Record<string, unknown> = {};

    if (this.baseline) {
      initData.baseline = this.baseline.getProfile();
    }
    if (this.policy) {
      initData.policy = {
        tier1_always_approve: this.policy.tier1_always_approve,
        tier2_anomaly: this.policy.tier2_anomaly,
        tier3_always_allow: this.policy.tier3_always_allow,
        approval_channel: {
          type: this.policy.approval_channel.type,
          timeout_seconds: this.policy.approval_channel.timeout_seconds,
          auto_deny: true, // SEC-002: hardcoded, not configurable
        },
        approval_redirect: {
          enabled: this.policy.approval_redirect?.enabled === true,
          mode: this.policy.approval_redirect?.mode === "notify" ? "notify" : "replace",
        },
      };
    }

    // Send any current pending requests
    const pendingList = Array.from(this.pending.values()).map((p) => ({
      request_id: p.id,
      operation: p.request.operation,
      tier: p.request.tier,
      reason: p.request.reason,
      context: p.request.context,
      timestamp: p.request.timestamp,
    }));
    if (pendingList.length > 0) {
      initData.pending = pendingList;
    }

    res.write(`event: init\ndata: ${JSON.stringify(initData)}\n\n`);

    this.sseClients.add(res);

    req.on("close", () => {
      this.sseClients.delete(res);
    });
  }

  /**
   * Build the AggregatorSources bundle for getProtectionSnapshot from the
   * dependencies injected via setDependencies(). Mirrors what the
   * co-located server (dashboard/server.ts) receives at construction, so
   * /api/snapshot returns the same document shape in both modes.
   */
  private async buildAggregatorSources(): Promise<AggregatorSources> {
    // Slice R + P: resolve the pinned producer key the SAME way dispatchPosture
    // does, so the dashboard hero shield arms the wall on the identical
    // cryptographic basis as /v1 G4. `present` → re-verify producer signatures
    // (a forged marker-only entry cannot arm green); `absent` → channel basis
    // (honest macOS / pre-provision); `unreadable` → fail honestly via
    // `producerKeyExpectedButUnavailable` (the shield goes amber, never green on
    // a weaker basis than the consumer wrote with).
    await this.ensureProducerKeyLoaded();
    const load = this._producerKeyLoad;
    return {
      mode: this._standaloneMode ? "standalone" : "co-located",
      server_version: PKG_VERSION,
      ...(this.identityManager ? { identityManager: this.identityManager } : {}),
      ...(this.auditLog ? { auditLog: this.auditLog } : {}),
      ...(this.baseline ? { baseline: this.baseline } : {}),
      ...(this.policy ? { policy: this.policy } : {}),
      ...(this.clientManager ? { clientManager: this.clientManager } : {}),
      resolvePinnedProducerKey: () =>
        load?.status === "present" ? load.keyB64url : null,
      ...(load?.status === "unreadable"
        ? { producerKeyExpectedButUnavailable: true }
        : {}),
      // S5-P: hand the hero shield the SAME fail-closed exclusive-egress
      // resolver every other surface uses, so the shield's wall arm-state
      // (via the ONE canonical shaper) caps green identically.
      resolveExclusiveEgressPosture: () => this.resolveExclusiveEgressPosture(),
      pendingApprovals: Array.from(this.pending.values()).map((p) => ({
        id: p.id,
        operation: p.request.operation,
        tier: p.request.tier,
        reason: p.request.reason,
        created_at: p.created_at,
      })),
    };
  }

  /**
   * GET /api/snapshot: unified ProtectionSnapshot JSON (v1.3.3 fix,
   * F-1.3.2-N-002). Auth + rate limiting are enforced by
   * handleLegacyRequest before this is reached, matching every other
   * legacy /api/* route.
   */
  private handleSnapshot(res: ServerResponse): void {
    this.buildAggregatorSources()
      .then((sources) => getProtectionSnapshot(sources))
      .then((snapshot) => {
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        res.end(JSON.stringify(snapshot));
      })
      .catch((err) => {
        logCaughtError(
          err,
          { route: "/api/snapshot", operation: "get_snapshot" },
          { status: 500 },
        );
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "snapshot_failed",
            })
          );
        }
      });
  }

  private handleStatus(res: ServerResponse): void {
    const status: Record<string, unknown> = {
      pending_count: this.pending.size,
      connected_clients: this.sseClients.size,
      standalone_mode: this._standaloneMode,
      decision_capable: !this._standaloneMode,
    };

    if (this.baseline) {
      status.baseline = this.baseline.getProfile();
    }
    if (this.policy) {
      status.policy = {
        version: this.policy.version,
        tier1_always_approve: this.policy.tier1_always_approve,
        tier2_anomaly: this.policy.tier2_anomaly,
        tier3_always_allow: this.policy.tier3_always_allow,
        approval_channel: {
          type: this.policy.approval_channel.type,
          timeout_seconds: this.policy.approval_channel.timeout_seconds,
          auto_deny: true, // SEC-002: hardcoded, not configurable
        },
        approval_redirect: {
          enabled: this.policy.approval_redirect?.enabled === true,
          mode: this.policy.approval_redirect?.mode === "notify" ? "notify" : "replace",
        },
      };
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(status));
  }

  private handlePendingList(res: ServerResponse): void {
    const list = Array.from(this.pending.values()).map((p) => ({
      id: p.id,
      operation: p.request.operation,
      tier: p.request.tier,
      reason: p.request.reason,
      context: p.request.context,
      timestamp: p.request.timestamp,
      created_at: p.created_at,
    }));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(list));
  }

  private handleAuditLog(url: URL, res: ServerResponse): void {
    const limit = parseInt(url.searchParams.get("limit") ?? "50", 10);

    // AuditLog.query is async, but for the dashboard we return what we can
    if (this.auditLog) {
      this.auditLog.query({ limit }).then((entries) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(entries));
      }).catch(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify([]));
      });
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([]));
    }
  }

  private handleDecision(id: string, decision: "approve" | "deny", res: ServerResponse): void {
    const pending = this.pending.get(id);
    if (!pending) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Request not found or already resolved" }));
      return;
    }

    // Clear timeout
    clearTimeout(pending.timer);

    // Remove from pending
    this.pending.delete(id);

    // Create response
    const response: ApprovalResponse = {
      decision,
      decided_at: new Date().toISOString(),
      decided_by: "human",
    };

    // Broadcast resolution to all dashboards
    this.broadcastSSE("request-resolved", {
      request_id: id,
      decision,
      decided_by: "human",
    });

    // Resolve the waiting promise (unblocks the tool call)
    pending.resolve(response);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, decision }));
  }

  // ── Sovereignty Data Routes ─────────────────────────────────────────

  /**
   * GET /api/sovereignty - the legacy operator-dashboard sovereignty panel.
   *
   * HONESTY CONTRACT (the green-on-presence fix, parity with the 2026-06-17
   * `/api/posture/*` + `/v1` rollup honesty work): the per-layer LIVE pills and
   * the aggregate "sovereignty score" must reflect a real ENFORCEMENT VERDICT,
   * not config presence. The SHR is a portable CAPABILITY receipt ("this build
   * supports encryption / ZK / reputation"), so `l1.status:"active"` is a true
   * capability claim THERE; the defect this fixes is the live dashboard reusing
   * that capability receipt to paint a green "ACTIVE" live health pill + a high
   * score even on a host where Castle Wall is dead / not installed / never wired.
   *
   * The fix, per-layer:
   *
   *  - L1 (the ENFORCING layer): its live status is now driven by the canonical
   *    evidence-gated {@link buildCastleWallPosture} reader (via
   *    {@link buildStatusCastleWall}), NOT the static SHR capability. A wall that
   *    is `armed` (fresh enforcement verdict) renders green `active`; anything
   *    else (`degraded` / `unknown` / `not_installed`) renders the neutral
   *    `configured` state - capability present, live enforcement unproven - and
   *    never green. The wall arm-state is a real, visible input to the score.
   *  - L3 (Selective Disclosure / ZK): there is no live enforcement verdict for
   *    proof-system availability on this surface, so its capability `active` is
   *    RELABELLED to the neutral `configured` (capability present), never a green
   *    live "ACTIVE" pill.
   *  - L2 / L4: already carry honest degraded logic in the SHR generator; passed
   *    through unchanged.
   *
   * Because L3 can never exceed `configured` (15) here, a perfect 100 is no
   * longer reachable from capability presence alone - that is correct: a host
   * cannot honestly claim full sovereignty when ZK is only a build capability and
   * the wall has adjudicated no flow. Full green requires a fresh wall verdict.
   *
   * Never throws into the request path: any failure resolves to an honest error
   * body or an `unknown` wall posture, never a fabricated green.
   */
  private handleSovereignty(res: ServerResponse): void {
    if (!this.shrOpts) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "SHR generator not available" }));
      return;
    }

    const shr = generateSHR(undefined, this.shrOpts);
    if (typeof shr === "string") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: shr }));
      return;
    }

    const layers = shr.body.layers;
    const federationPosture = this.buildFederationPostureSummary();

    // Read the LIVE Castle Wall arm-state from the canonical evidence-gated
    // shaper (never the SHR capability), then assemble the honest payload. The
    // shaper is async, so the handler completes on the promise - mirroring
    // handleSnapshot - and always answers (an honest `unknown` posture on any
    // failure, never a thrown 500 that paints green by omission).
    this.buildStatusCastleWall()
      .then((wall) => {
        // L1 LIVE status: green `active` ONLY on a fresh enforcement verdict
        // (`armed`); every other arm-state is the neutral `configured`
        // (capability present, live enforcement unproven), never green.
        const l1LiveStatus = wall.arm_state === "armed" ? "active" : "configured";
        // L3 LIVE status: capability present, no live verdict on this surface →
        // neutral `configured`, never a green live pill (relabel of the SHR
        // capability `active`).
        const l3LiveStatus = "configured";

        // Score: the enforcing layer (L1) earns its points from the wall arm
        // VERDICT, not config presence. `configured` is a non-green PARTIAL - the
        // encryption-at-rest capability is real, but live enforcement is unproven,
        // so it can never reach the full-green 25. L3 likewise caps at the
        // `configured` partial. L2/L4 keep the SHR's honest active/degraded scale.
        const layerPoints = (status: string): number =>
          status === "active" ? 25
            : status === "degraded" ? 15
              : status === "configured" ? 10
                : 0; // inactive
        const l1Points =
          wall.arm_state === "armed" ? 25
            : wall.arm_state === "degraded" ? 10
              : 5; // unknown / not_installed: capability real, enforcement unproven
        const score =
          l1Points +
          layerPoints(layers.l2.status) +
          layerPoints(l3LiveStatus) +
          layerPoints(layers.l4.status);

        // `full` now requires a fresh wall verdict (l1=25) AND non-degraded
        // L2/L4; a capability-only host tops out below `full`, honestly.
        const overallLevel =
          wall.arm_state === "armed" && score >= 90 ? "full"
            : score >= 65 ? "degraded"
              : score >= 25 ? "minimal"
                : "unverified";

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          score,
          overall_level: overallLevel,
          layers: {
            // L1 live status comes from the wall verdict; the SHR capability is
            // preserved under `capability_status` so a consumer can still tell
            // "build supports this" from "it is live-enforcing now".
            l1: {
              status: l1LiveStatus,
              capability_status: layers.l1.status,
              detail: layers.l1.encryption,
              key_custody: layers.l1.key_custody,
            },
            l2: { status: layers.l2.status, detail: layers.l2.isolation_type, attestation: layers.l2.attestation_available },
            l3: {
              status: l3LiveStatus,
              capability_status: layers.l3.status,
              detail: layers.l3.proof_system,
              selective_disclosure: layers.l3.selective_disclosure,
            },
            l4: { status: layers.l4.status, detail: layers.l4.attestation_format, reputation_portable: layers.l4.reputation_portable },
          },
          // The real enforcement signal behind the L1 pill + score, surfaced so
          // the operator can see WHY green was or was not earned (never a leak of
          // rule internals - the same honest enum the /api/posture surface uses).
          live_enforcement: {
            castle_wall_arm_state: wall.arm_state,
            evidence_basis: wall.evidence_basis,
            last_enforcement_evidence_at: wall.last_enforcement_evidence_at,
            audit_integrity_ok: wall.audit_integrity_ok,
          },
          degradations: shr.body.degradations,
          capabilities: shr.body.capabilities,
          federation: {
            operator_cloud_nodes: federationPosture.operator_cloud_nodes,
            provider_in_trust_boundary: federationPosture.provider_in_trust_boundary,
            tee_attested: federationPosture.tee_attested,
            trust_boundary: federationPosture,
          },
          config_loaded: this._sanctuaryConfig != null,
        }));
      })
      .catch((err) => {
        logCaughtError(
          err,
          { route: "/api/sovereignty", operation: "get_sovereignty" },
          { status: 500 },
        );
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "sovereignty_failed" }));
        }
      });
  }

  private handleIdentity(res: ServerResponse): void {
    if (!this.identityManager) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ identities: [], count: 0 }));
      return;
    }

    const identities = this.identityManager.listWithRotationCount();

    const primary = this.identityManager.getDefault();

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      identities,
      count: identities.length,
      primary_id: primary?.identity_id ?? null,
    }));
  }

  private handleHandshakes(res: ServerResponse): void {
    if (!this.handshakeResults) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ handshakes: [], count: 0 }));
      return;
    }

    const handshakes = Array.from(this.handshakeResults.values()).map(h => ({
      counterparty_id: h.counterparty_id,
      verified: h.verified,
      sovereignty_level: h.sovereignty_level,
      trust_tier: h.trust_tier,
      completed_at: h.completed_at,
      expires_at: h.expires_at,
      errors: h.errors,
    }));

    // Sort by completed_at descending (most recent first)
    handshakes.sort((a, b) => new Date(b.completed_at).getTime() - new Date(a.completed_at).getTime());

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      handshakes,
      count: handshakes.length,
      tier_distribution: {
        verified_sovereign: handshakes.filter(h => h.trust_tier === "verified-sovereign").length,
        verified_degraded: handshakes.filter(h => h.trust_tier === "verified-degraded").length,
        unverified: handshakes.filter(h => h.trust_tier === "unverified").length,
      },
    }));
  }

  private handleSHR(res: ServerResponse): void {
    if (!this.shrOpts) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "SHR generator not available" }));
      return;
    }

    const shr = generateSHR(undefined, this.shrOpts);
    if (typeof shr === "string") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: shr }));
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(shr));
  }

  // ── Sovereignty Profile API ─────────────────────────────────────────

  private handleSovereigntyProfileGet(res: ServerResponse): void {
    if (!this.profileStore) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Sovereignty Profile not available" }));
      return;
    }

    try {
      const profile = this.profileStore.get();
      const prompt = generateSystemPrompt(profile);
      const federationPosture = this.buildFederationPostureSummary();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        profile,
        system_prompt: prompt,
        deployment_posture: {
          operator_cloud_nodes: federationPosture.operator_cloud_nodes,
          provider_in_trust_boundary: federationPosture.provider_in_trust_boundary,
          tee_attested: federationPosture.tee_attested,
          trust_boundary: federationPosture,
        },
      }));
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to read sovereignty profile" }));
    }
  }

  private handleSovereigntyProfileUpdate(req: IncomingMessage, res: ServerResponse): void {
    if (!this.profileStore) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Sovereignty Profile not available" }));
      return;
    }

    let body = "";
    let destroyed = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      // Size limit: 16KB for profile updates
      if (body.length > 16384) {
        destroyed = true;
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        req.destroy();
      }
    });
    req.on("end", async () => {
      if (destroyed) return;
      try {
        const updates: SovereigntyProfileUpdate = JSON.parse(body);
        const updated = await this.profileStore!.update(updates);
        const prompt = generateSystemPrompt(updated);
        const federationPosture = this.buildFederationPostureSummary();
        const deploymentPosture = {
          operator_cloud_nodes: federationPosture.operator_cloud_nodes,
          provider_in_trust_boundary: federationPosture.provider_in_trust_boundary,
          tee_attested: federationPosture.tee_attested,
          trust_boundary: federationPosture,
        };

        // Audit log the dashboard-initiated change
        if (this.auditLog) {
          try {
            await this.auditLog.appendCritical({
              layer: "l2",
              operation: "sovereignty_profile_update_dashboard",
              identity_id: "dashboard",
              result: "success",
              details: {
                changes: updates,
                features_enabled: Object.entries(updated.features)
                  .filter(([, v]) => v.enabled)
                  .map(([k]) => k),
              },
            });
          } catch {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              error: "Audit persistence failed",
              profile_updated: true,
              audit_failed: true,
              profile: updated,
              system_prompt: prompt,
              deployment_posture: deploymentPosture,
            }));
            return;
          }
        }

        // Broadcast to SSE clients
        this.broadcastSSE("sovereignty-profile-update", {
          profile: updated,
          system_prompt: prompt,
          deployment_posture: deploymentPosture,
        });

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          profile: updated,
          system_prompt: prompt,
          deployment_posture: deploymentPosture,
        }));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON body" }));
      }
    });
  }

  // ── Proxy Server Handlers ───────────────────────────────────────────

  /**
   * GET /api/proxy/servers - list upstream proxy servers and their status.
   */
  private handleProxyServers(res: ServerResponse): void {
    const profile = this.profileStore?.get();
    const upstreamServers = profile?.upstream_servers ?? [];
    const clientStatus = this.clientManager?.getStatus() ?? [];

    // Merge config with live status
    const servers = upstreamServers.map(server => {
      const status = clientStatus.find(s => s.name === server.name);
      return {
        name: server.name,
        transport_type: server.transport.type,
        enabled: server.enabled,
        default_tier: server.default_tier,
        state: status?.state ?? "disconnected",
        tool_count: status?.tool_count ?? 0,
        error: status?.error,
        tool_overrides: server.tool_overrides ?? {},
      };
    });

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ servers }));
  }

  /**
   * POST /api/proxy/servers - update upstream server configuration.
   * This is a dashboard action (human-initiated), so it's allowed with audit logging
   * rather than requiring Tier 1 approval.
   */
  private handleProxyServersUpdate(req: IncomingMessage, res: ServerResponse): void {
    if (!this.profileStore) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Profile store not available" }));
      return;
    }

    let body = "";
    let destroyed = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      if (body.length > 16384) {
        destroyed = true;
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        req.destroy();
      }
    });
    req.on("end", async () => {
      if (destroyed) return;
      try {
        const { upstream_servers } = JSON.parse(body) as { upstream_servers: UpstreamServer[] };

        // Update profile with new server config
        const updated = await this.profileStore!.update({ upstream_servers });

        // Audit log the dashboard-initiated change
        if (this.auditLog) {
          try {
            await this.auditLog.appendCritical({
              layer: "l2",
              operation: "proxy_servers_update_dashboard",
              identity_id: "dashboard",
              result: "success",
              details: {
                server_count: upstream_servers.length,
                servers: upstream_servers.map(s => ({
                  name: s.name,
                  type: s.transport.type,
                  enabled: s.enabled,
                  tier: s.default_tier,
                })),
              },
            });
          } catch {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              error: "Audit persistence failed",
              profile_updated: true,
              audit_failed: true,
              servers: updated.upstream_servers ?? [],
            }));
            return;
          }
        }

        // Reconfigure client manager if available
        if (this.clientManager && updated.upstream_servers) {
          this.clientManager.configure(updated.upstream_servers).catch(() => {
            // Connection errors handled by client manager
          });
        }

        // Broadcast to SSE clients
        this.broadcastSSE("proxy-servers-update", {
          servers: updated.upstream_servers ?? [],
          timestamp: new Date().toISOString(),
        });

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ upstream_servers: updated.upstream_servers ?? [] }));
      } catch (err) {
        // The surrounding try covers JSON.parse(body), profileStore.update(),
        // and broadcastSSE, so `err` can be a raw library/internal error
        // (SyntaxError carrying request fragments, a profile-store failure
        // carrying filesystem detail). Return a fixed safe message and keep
        // the real, redacted detail server-side for operators.
        logCaughtError(
          err,
          { route: "/api/proxy/servers", operation: "update_proxy_servers" },
          { status: 400 },
        );
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid request" }));
      }
    });
  }

  // ── Fleet Switcher (C1) ─────────────────────────────────────────────

  /**
   * C1: Serve the fleet switcher page. Client-side localStorage manages
   * the saved list of machine endpoints; no server-side state.
   */
  private serveFleetSwitcher(res: ServerResponse): void {
    const protocol = this.useTLS ? "https" : "http";
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    });
    res.end(generateFleetSwitcherHTML({
      serverVersion: PKG_VERSION,
      protocol,
      currentHost: this.config.host,
      currentPort: this.config.port,
    }));
  }

  // ── SSE Broadcasting ────────────────────────────────────────────────

  broadcastSSE(event: string, data: unknown): void {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(message);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  /**
   * Broadcast an audit entry to connected dashboards.
   * Called externally when audit events happen.
   */
  broadcastAuditEntry(entry: {
    timestamp: string;
    layer: string;
    operation: string;
    identity_id: string;
  }): void {
    this.broadcastSSE("audit-entry", entry);
  }

  /**
   * Broadcast a baseline update to connected dashboards.
   * Called externally after baseline changes.
   */
  broadcastBaselineUpdate(): void {
    if (this.baseline) {
      this.broadcastSSE("baseline-update", this.baseline.getProfile());
    }
  }

  /**
   * Broadcast a tool call event to connected dashboards.
   * Called from the gate or router when a tool is invoked.
   */
  broadcastToolCall(data: {
    tool: string;
    tier: number;
    allowed: boolean;
    timestamp: string;
  }): void {
    this.broadcastSSE("tool-call", data);
  }

  /**
   * Broadcast a context gate decision to connected dashboards.
   */
  broadcastContextGateDecision(data: {
    tool: string;
    fields_filtered: number;
    fields_total: number;
    action: string;
    timestamp: string;
  }): void {
    this.broadcastSSE("context-gate-decision", data);
  }

  /**
   * Broadcast current protection status to connected dashboards.
   */
  broadcastProtectionStatus(data: Record<string, unknown>): void {
    this.broadcastSSE("protection-status", data);
  }

  // ── Mesh-health surface (WP-MVP-3 Follow-up #3) ─────────────────────
  //
  // The federation FailureModeDetector pushes per-tick health snapshots and
  // per-detection alerts here; the existing /events SSE channel transports
  // them to the browser. No new transport.
  //
  // Spec §8 + §9. Spawn-prompt acceptance criterion 7: "Mesh Health dashboard
  // panel renders via existing SSE /events channel - no new transport. Every
  // state transition produces an observable SSE event."

  /** Push a Mesh Health snapshot (full re-render trigger on the client). */
  broadcastMeshHealth(snapshot: Record<string, unknown>): void {
    this.broadcastSSE("mesh-health", snapshot);
  }

  /** Push a single failure-mode alert (incremental client update). */
  broadcastMeshFailureModeAlert(alert: Record<string, unknown>): void {
    this.broadcastSSE("mesh-failure-mode-alert", alert);
  }

  /** Push a post-recovery prompt update (master rotation hygiene flow). */
  broadcastMeshPostRecoveryPrompt(prompt: Record<string, unknown>): void {
    this.broadcastSSE("mesh-post-recovery-prompt", prompt);
  }

  /**
   * Open a URL in the system's default browser.
   * Cross-platform: macOS (open), Linux (xdg-open), Windows (start).
   * Fails silently - dashboard still works via terminal URL.
   */
  private openInBrowser(url: string): void {
    const os = platform();
    let cmd: string;
    if (os === "darwin") {
      cmd = `open "${url}"`;
    } else if (os === "win32") {
      cmd = `start "" "${url}"`;
    } else {
      cmd = `xdg-open "${url}"`;
    }
    exec(cmd, (err) => {
      if (err) {
        process.stderr.write(
          `  (Could not auto-open browser. Open the URL above manually.)\n\n`
        );
      }
    });
  }

  /**
   * Create a pre-authenticated URL for the dashboard.
   * Used by the sanctuary_dashboard_open tool and at startup.
   */
  createSessionUrl(): string {
    const sessionId = this.createSession();
    const protocol = this.useTLS ? "https" : "http";
    return `${protocol}://${this.config.host}:${this.config.port}/?session=${sessionId}`;
  }

  /**
   * Get the base URL for the dashboard.
   */
  getBaseUrl(): string {
    const protocol = this.useTLS ? "https" : "http";
    return `${protocol}://${this.config.host}:${this.config.port}`;
  }

  /** Get the number of pending requests */
  get pendingCount(): number {
    return this.pending.size;
  }

  /** Get the number of connected SSE clients */
  get clientCount(): number {
    return this.sseClients.size;
  }
}
