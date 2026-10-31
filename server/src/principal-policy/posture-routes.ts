/**
 * Sovereignty Posture Dashboard - Phase 1 route layer.
 *
 * Mounts the four gap endpoints (G1, G2, G4, G5) and the posture-home HTML
 * under `/api/posture/*` and `/posture`. The route layer is the IMPURE seam:
 * it gathers live dependencies (the audit log, the hub agent registry, a
 * config-file scan for installed harnesses, and the Castle Wall allowlist) and
 * delegates the actual shaping to the pure functions in `posture.ts`.
 *
 * Auth: every route here is dispatched only AFTER the dashboard's own
 * `checkAuth` gate has passed - the same gate `/api/audit-log` uses (binding
 * amendment: "do not invent a weaker gate"). The dashboard owns that check;
 * this module assumes the caller is authenticated.
 *
 * Endpoints:
 *   GET /api/posture/home        - one composed payload for the home screen.
 *   GET /api/posture/castle-wall - G4 (enforcement-evidenced arm state).
 *   GET /api/posture/digest      - G2 (today's audit story).
 *   GET /api/posture/unwrapped   - G1 (detected-but-unwrapped roster).
 *   GET /api/posture/reach/:id   - G5 (per-agent effective reach).
 *   GET /api/posture/stream      - SSE live-refresh: pushes the SAME `buildHome`
 *                                  payload as `/home` on a cadence + heartbeat
 *                                  (additive, behind the same checkAuth +
 *                                  audit-null guards; concurrency-capped).
 *   GET /api/posture/custody-exit - Slice 3 (Custody + Exit panel).
 *   GET /api/posture/composition - Recognition precursor: the composition render
 *                                  gate flag (config, NOT evidence-gated). Carries
 *                                  NO Concordia/Verascore data - only the flag and
 *                                  origin_machine. Behind the SAME checkAuth gate.
 *   GET /api/posture/recognition - Recognition + portability panel (P5). GATED on
 *                                  composition-enabled (404 when off, so the panel
 *                                  is ABSENT not greyed). LOCAL-evidence only:
 *                                  bridge receipt counts + local reputation
 *                                  EVIDENCE (counts, never a score) + the portable-
 *                                  identity export capability. No score-fetch path;
 *                                  counterparty verification is local bridge crypto.
 *   GET /api/posture/evidence    - Phase 2 Evidence View (design section 2.5):
 *                                  filterable audit-entry table with chain
 *                                  integrity_findings surfaced ON-VIEW. Operator-
 *                                  gated (same checkAuth as all other posture JSON
 *                                  routes); never unauthenticated. Filters: agent,
 *                                  since, operation_type, layer, result, limit.
 *                                  Reuses AuditLog.query() verbatim; adds NO new
 *                                  backend query logic.
 *   GET /posture                 - the posture home HTML.
 *   GET /posture/agent/:id       - the per-agent drill-down HTML (Slice 4).
 *   GET /posture/evidence        - the Phase 2 Evidence View HTML shell.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import {
  respondWithBoundedDashboardRead,
  type DashboardReadFlightMap,
} from "../dashboard/read-response.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import { detectAgentConfigWithDiagnostics, getPlatformPaths } from "../wrap/config-reader.js";
import type { AgentPlatform } from "../wrap/config-reader.js";
import { resolveCuratedRules } from "../castle-wall/runtime/curated-allowlist.js";
import {
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
  DEFAULT_DIGEST_WINDOW_MS,
  buildCastleWallPosture,
  buildAuditDigest,
  buildUnwrappedRoster,
  buildAgentReach,
  buildPostureAgentRows,
  buildCustodyExitPanel,
  buildRecognitionPanel,
  PLATFORM_TO_HARNESS,
  type DetectedHarness,
  type ReachRule,
  type CastleWallPosture,
  type AuditDigest,
  type UnwrappedRoster,
  type AgentEffectiveReach,
  type CustodyExitPanel,
  type RecognitionPanel,
  type RecognitionReputationEvidence,
  failedExclusiveEgressStatus,
  type ExclusiveEgressStatus,
} from "./posture.js";
import {
  SLICE1_FEATURE_REGISTRY,
  buildFeatureHealthPanel,
  type FeatureHealthPanel,
} from "./feature-health.js";
import {
  buildQueryPrivacySection,
  TIER_B_FEATURE_ID,
  type QueryPrivacySection,
} from "./posture-query-privacy.js";
import {
  computeQueryAnonymityStats,
  handleQueryAnonymityStatsRequest,
  QUERY_ANONYMITY_API_PREFIX,
} from "../query-anonymity/query-anonymity-routes.js";
import { renderPostureAgentHTML } from "./posture-agent-html.js";
import { renderPostureEvidenceHTML } from "./posture-evidence-html.js";
import type { FleetRoster } from "./fleet-roster.js";
import {
  handlePostureStream,
  type PostureStreamRegistry,
} from "./posture-stream.js";
// `PostureHome` lives in a neutral type module so `posture-stream.ts` can import
// the payload shape without closing a `posture-routes` <-> `posture-stream`
// cycle (this module imports the stream handler above).
import type { PostureHome } from "./posture-home-types.js";
import {
  DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS,
  type ResolvedEnforcementAvailability,
} from "../castle-wall/runtime/enforcement-availability.js";

import { type ProducerKeyObservation, NO_PANEL_INPUTS, capStalePanel, type PosturePanelStore, type PosturePanelStatus, type PanelSnapshot } from "./panel-producer.js";

export type { ProducerKeyObservation } from "./panel-producer.js";
type ProducerKeys = Pick<PostureRouteDeps, "resolvePinnedProducerKey" | "resolveBrokerPinnedProducerKey" | "producerKeyObservation" | "brokerProducerKeyObservation">;

/** Only a positively absent key permits the ordinary channel-basis path. */
export function observeInjectedProducerKey(resolve: (() => string | null) | undefined, expected = false): ProducerKeyObservation {
  try {
    return resolve?.() ? "present" : expected ? "unreadable" : resolve ? "absent" : "unknown";
  } catch {
    // A resolver exception cannot establish absence or reject the whole composition.
    return expected ? "unreadable" : "unknown";
  }
}
function keyRestricted(observation: ProducerKeyObservation | undefined): boolean {
  // Missing observations are unknown; absence must be positively established by the loader.
  return observation !== "present" && observation !== "absent";
}

export const POSTURE_API_PREFIX = "/api/posture";
export const POSTURE_HOME_PATH = "/posture";
/**
 * SSE live-refresh stream path (additive, Phase 2): `/api/posture/stream`.
 * Pushes the SAME `buildHome` payload as `/api/posture/home` on a cadence plus
 * a heartbeat. Mounted behind the SAME checkAuth gate + audit-null 503 guard as
 * the rest of the posture API. Exported so the dashboard can classify it as a
 * long-lived view route (rate-limit exempt), mirroring the v1.0 `/events` stream.
 */
export const POSTURE_STREAM_PATH = `${POSTURE_API_PREFIX}/stream`;
/**
 * Per-agent drill-down HTML page prefix (Slice 4): `/posture/agent/:id`. The
 * page is a static shell that fetches `/api/posture/reach/:id` (G5) and
 * `/api/posture/home` client-side behind the same auth gate; the id is parsed
 * from the path in the browser, so the route only matches the prefix here.
 */
export const POSTURE_AGENT_PATH_PREFIX = "/posture/agent/";
/**
 * Evidence View HTML page (Phase 2, design section 2.5): `/posture/evidence`.
 * A filterable audit-entry table with chain integrity_findings surfaced on-view.
 * Served behind the SAME checkAuth gate as `/posture/agent/:id` and the posture
 * JSON endpoints. The data comes from `/api/posture/evidence` (JSON, same gate).
 */
export const POSTURE_EVIDENCE_PATH = "/posture/evidence";

/**
 * Dependencies the route layer needs from the dashboard. All are resolved
 * lazily per request (via closures) so post-unlock wiring is always observed -
 * mirrors the `buildV1AgentsDeps` pattern.
 */
export interface PostureRouteDeps {
  /** Encrypted audit log (already unlocked). */
  auditLog: AuditLog | null;
  /** Origin-machine attribution for `/v1`-compatible shapes. */
  originMachine: string;
  /** Owning dashboard instance's bounded-read flights (one map per running dashboard server). */
  // Required: each dashboard instance owns its flight map (must match the required
  // `readFlights` option in src/dashboard/read-response.ts).
  readFlightMap: DashboardReadFlightMap;
  /** Required per-instance admission shared by HTTP and SSE. */
  panelStore: PosturePanelStore;
  /** Raw key-load prelude, budgeted by the same store as the home producers. */
  prepareProducerKeys?: () => Promise<ProducerKeys>;
  producerKeysStatus?: PosturePanelStatus;
  /** Rebuild daemon dependencies inside each admitted stream frame so observations are current. */
  refreshStreamDeps?: () => Promise<PostureRouteDeps>;
  /**
   * Recognition precursor: the resolved `composition_enabled` flag (default-off
   * via `resolveCompositionConfig()`). This is CONFIG, not evidence: it is the
   * render gate the Recognition panel will key on so the panel is absent (never
   * implies a Concordia/Verascore dependency) when composition is off. Resolved
   * by the dashboard and passed through verbatim; the route exposes ONLY the
   * boolean + origin_machine, never any Concordia/Verascore data. Optional;
   * absent is treated as `false` (honest default-off).
   */
  compositionEnabled?: boolean;
  /**
   * Recognition panel (P5): count of persisted Concordia-bridge commitments
   * (`storage.list("_bridge")`). Supplied by the dashboard, which holds the
   * storage backend; resolved lazily per request so post-unlock wiring is
   * observed. Optional - when absent, OR when it resolves to `undefined` (no
   * storage backend wired, so the count is unknowable), the recognition shaper
   * falls back to the count of `bridge_commit` audit events (an honest lower
   * bound, never a fabricated count). A resolved `0` is a real "zero persisted
   * commitments" fact and is used as-is. Carries NO Concordia/Verascore data
   * beyond a local count.
   */
  countBridgeCommitments?: () => Promise<number | undefined>;
  /**
   * Recognition panel (P5): pre-gathered LOCAL reputation EVIDENCE (counts only)
   * for the primary identity - NOT a score and NOT a fetched Verascore value.
   * Supplied by the dashboard, which holds the identity + master key needed to
   * read the local attestation store. Resolved lazily per request. Returns
   * `null` when no reputation store is wired / readable, which renders the
   * reputation row amber ("no evidence yet"), never green-from-absence. There is
   * NO score-fetch path anywhere in this flow; this is the only reputation input
   * the panel ever sees.
   */
  gatherRecognitionReputation?: () => Promise<RecognitionReputationEvidence | null>;
  /**
   * Does THIS fortress carry the persisted `not_yet_walled` claim
   * (`castle-wall/provision-state.ts`)? Supplied by the dashboard, which holds
   * the fortress storage path; resolved lazily per request so a vault created
   * after the server started is observed.
   *
   * ABSENT = no claim is rendered, which is what every fortress that predates
   * the state gets. It is NOT a claim of protection: this route can observe
   * neither half of the `walled` pair on its own, so the additive field it
   * renders can only ever say `not_yet_walled` (deliberate under-claiming,
   * AGENTS.md rule 1).
   */
  resolveVaultProvisionClaimed?: () => Promise<boolean>;
  /** Live wrapped-agent roster from the hub registry. */
  listAgents: () => LocalAgentRecord[];
  /**
   * Fleet Console Slice 1: build the federation-backed fleet roster on demand.
   * Supplied by the dashboard, which holds the live federation deps; the route
   * is a thin presenter over it (the dashboard runs `buildFleetRoster` against
   * the SAME `V1FederationDeps` and revocation projection the `/v1` endpoints
   * use, so trust is the federation layer's verdict, never re-derived here).
   * Resolved lazily per request so post-provision wiring is observed. When
   * ABSENT, the fleet route is disabled (404 within the namespace); additive,
   * so an unwired dashboard simply has no fleet panel rather than a broken one.
   *
   * MAY be async: the standalone daemon path resolves it synchronously from live
   * in-memory federation deps, but the wrap ("Protect") dashboard resolves it by
   * reading the at-rest fortress records (it runs no live federation daemon), so
   * the route awaits whatever the closure returns.
   */
  fleetRoster?: () => FleetRoster | Promise<FleetRoster>;
  /**
   * Castle Wall reach rules visible for the fortress. Phase 1 sources these
   * from the curated allowlist (the structured destination set the dashboard
   * can read without the daemon); a daemon-sourced live manifest can replace
   * this later without changing the shape. Optional override for tests.
   */
  listReachRules?: () => ReachRule[];
  /**
   * The curated rule ids the operator has ACTUALLY enabled on disk (#641). The
   * default `curatedReachRules()` shaper sources reach lines from these ids via
   * `resolveCuratedRules`, instead of mapping the entire curated catalog, so a
   * never-configured fortress reports NO wall rules (an honest red gap) rather
   * than a fabricated default-deny over the full curated set. When this returns
   * `null` / an empty list, or when it is absent (no enabled manifest readable),
   * the reach view shows the honest "No Castle Wall ruleset applies" gap.
   * Resolved lazily per request so post-provision wiring is observed. Ignored
   * when `listReachRules` is supplied (the explicit override wins, e.g. tests).
   */
  listEnabledCuratedRuleIds?: () => readonly string[] | null;
  /**
   * Scan for installed harnesses by config-file presence. Optional override so
   * tests inject a deterministic detection set instead of touching the real
   * home directory. The default performs the real config scan and audit-logs
   * it.
   */
  detectInstalledHarnesses?: () => Promise<DetectedHarness[]>;
  /** Node platform, for the wall posture's platform field + tests. */
  platform?: NodeJS.Platform;
  /** Injectable clock for tests. */
  now?: () => number;
  /**
   * The reader's pinned producer public key (base64url-no-pad), loaded from the
   * SAME source the audit consumer uses (`<policy_dir>/audit-producer.pub`).
   * Resolved lazily per request so post-provision wiring is observed. When it
   * returns null (macOS today / pre-provision), the readers fall back to the
   * honest channel-authenticated basis - never claimed as per-producer
   * authenticated. The dashboard MUST supply the same key the consumer wrote
   * with, never a weaker basis (Slice R, R-4).
   */
  resolvePinnedProducerKey?: () => string | null;
  /** macOS v3 level-triggered enforcement availability source. */
  resolveEnforcementAvailability?: () =>
    | Promise<ResolvedEnforcementAvailability>
    | ResolvedEnforcementAvailability;
  /** Named pinned-key observation: only positive absence permits channel-basis evidence. */
  producerKeyObservation?: ProducerKeyObservation;
  /** Derived, do not set: compatibility for shaper callers; true for unresolved or unreadable observations. */
  readonly producerKeyExpectedButUnavailable?: boolean;
  /** Pinned public key for the broker daemon liveness producer. */
  resolveBrokerPinnedProducerKey?: () => string | null;
  /** Named broker-key observation, using the same unknown/absent distinction as the pinned key. */
  brokerProducerKeyObservation?: ProducerKeyObservation;
  /** Derived, do not set: compatibility for shaper callers. */
  readonly brokerProducerKeyExpectedButUnavailable?: boolean;
  /**
   * Canonical confined-agent subject (`fortress/uid-N`) for protection claims.
   * When provided, Castle Wall green evidence must bind to this subject across
   * posture and feature-health readers.
   */
  resolveProtectionClaimSubject?: () => string | null | Promise<string | null>;
  /**
   * Shared active-stream registry for the SSE live-refresh endpoint
   * (`/api/posture/stream`). Supplied by the dashboard so the concurrency cap is
   * enforced across all open streams on the server. When ABSENT, the stream
   * endpoint is disabled (404 within the namespace) and the page falls back to
   * its poll loop - the endpoint is purely additive, so an unwired dashboard
   * simply has no live stream rather than a broken one.
   */
  streamRegistry?: PostureStreamRegistry;
  /** Override the SSE push cadence (ms). Tests inject a deterministic value. */
  streamIntervalMs?: number;
  /** Override the SSE heartbeat cadence (ms). Tests inject a deterministic value. */
  streamHeartbeatMs?: number;
  /** Override the concurrent-stream cap. Tests inject a small value to exercise it. */
  streamMaxConcurrent?: number;
  /** Injectable timer hooks so tests can drive the stream cadence synchronously. */
  streamSetInterval?: (handler: () => void, ms: number) => NodeJS.Timeout;
  streamClearInterval?: (handle: NodeJS.Timeout) => void;
  /**
   * Exclusive-egress posture provider (Unified Protect Slice 5 S5-P). Resolved
   * lazily per request so post-provision wiring is observed. Return semantics
   * (fail-closed contract):
   *   - provider ABSENT (field undefined): no producer is wired => no
   *     fine-grained agent has ever been provisioned; every surface behaves as
   *     today (no cap).
   *   - provider returns `null`: "affirmatively scanned; no fine-grained agent
   *     declared right now" => same as absent (no cap). A `null` return is a
   *     POSITIVE no-fine-grained-agent answer, NOT an error channel.
   *   - provider returns a status: threaded into the wall posture and
   *     feature-health builders, which apply the ONE aggregate-green capping
   *     rule (`armed` -> distinct non-green `coarse_only` when a fine-grained
   *     agent's exclusive stack is not live).
   *   - provider THROWS: the routes substitute `failedExclusiveEgressStatus`
   *     (which caps green) - a failed posture read must never render the
   *     stronger claim. A provider that cannot DETERMINE state must throw or
   *     return `failedExclusiveEgressStatus`, never a bare empty summary
   *     (see the producer contract on `summarizeExclusiveEgressStatus`).
   */
  exclusiveEgressPosture?: () =>
    | Promise<ExclusiveEgressStatus | null>
    | ExclusiveEgressStatus
    | null;
}

export function buildLockedAuditPostureUnavailableBody(originMachine: string): {
  error: "posture_unavailable";
  reason: "audit log not unlocked; posture cannot be evidenced";
  origin_machine: string;
} {
  return {
    error: "posture_unavailable",
    reason: "audit log not unlocked; posture cannot be evidenced",
    origin_machine: originMachine,
  };
}

/**
 * Resolve the optional exclusive-egress posture provider fail-closed: absent
 * provider -> null (no fine-grained agent; no cap); provider THROWS ->
 * `failedExclusiveEgressStatus` (caps green). Shared by the wall-posture and
 * feature-health builders so both surfaces resolve identically.
 */
async function resolveExclusiveEgress(
  deps: PostureRouteDeps,
): Promise<ExclusiveEgressStatus | null> {
  if (!deps.exclusiveEgressPosture) return null;
  try {
    return await deps.exclusiveEgressPosture();
  } catch (err) {
    return failedExclusiveEgressStatus(
      err instanceof Error ? err.message : String(err),
    );
  }
}

async function resolveEnforcementAvailability(
  deps: PostureRouteDeps,
): Promise<ResolvedEnforcementAvailability | null> {
  if (
    (deps.platform ?? process.platform) !== "darwin" &&
    !deps.resolveEnforcementAvailability
  ) {
    return null;
  }
  if (!deps.resolveEnforcementAvailability) {
    return {
      status: "undetermined",
      reason: "availability_not_queried",
      observed_at: null,
      freshness_window_ms: DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS,
      active_connection_count: 0,
    };
  }
  try {
    return await deps.resolveEnforcementAvailability();
  } catch (error) {
    return {
      status: "undetermined",
      reason: `availability_query_failed:${
        error instanceof Error ? error.message : String(error)
      }`,
      observed_at: null,
      freshness_window_ms: DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS,
      active_connection_count: 0,
    };
  }
}

async function resolveProtectionClaimSubject(
  deps: PostureRouteDeps,
): Promise<string | null> {
  if (!deps.resolveProtectionClaimSubject) return null;
  try {
    return await deps.resolveProtectionClaimSubject();
  } catch {
    return null;
  }
}

/**
 * Dispatch a posture route. Returns true when the request was served (or
 * deliberately 404'd within the posture namespace), false to fall through.
 *
 * The caller (dashboard) must have already run `checkAuth`.
 */
export async function handlePostureRoute(
  deps: PostureRouteDeps,
  _req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
): Promise<boolean> {
  deps = withDerivedKeyRestriction(deps);
  const path = url.pathname;

  // NOTE (Delta Review A3 remediation): the posture-home HTML at `/posture` is
  // NO LONGER served here. The dashboard now serves the `/posture` shell (and
  // `/`) BEFORE its auth gate, byte-for-byte the same unauthenticated static
  // shell, so `/` and `/posture` are genuinely one surface under the same auth
  // contract (see `DashboardApprovalChannel.dispatchRootPosture`). This branch
  // would be unreachable for `GET /posture`; the data routes below are
  // unchanged and still run behind `checkAuth`. `POSTURE_HOME_PATH` is still
  // exported for the dashboard's routing/view-route classification.

  // Per-agent drill-down HTML (Slice 4). The page is a static shell; it parses
  // the :id from the path and fetches `/api/posture/reach/:id` + `/api/posture/
  // home` client-side behind this same auth gate. An unknown id renders an
  // honest not-found state (driven by the reach endpoint's 404), so the HTML
  // shell is served for any non-empty id and the data layer owns existence.
  if (method === "GET" && path.startsWith(POSTURE_AGENT_PATH_PREFIX)) {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(renderPostureAgentHTML());
    return true;
  }

  // Evidence View HTML shell (Phase 2, design section 2.5). A static shell that
  // fetches `/api/posture/evidence` client-side behind this same auth gate. The
  // page filters are applied client-side via URL params passed to the JSON API.
  // Operator-gated: served only AFTER checkAuth (same gate as the JSON routes).
  if (method === "GET" && path === POSTURE_EVIDENCE_PATH) {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(renderPostureEvidenceHTML());
    return true;
  }

  // Query-privacy stats (Phase 2): mount the previously-orphaned
  // `/api/query-anonymity/stats` endpoint behind the SAME checkAuth gate as the
  // rest of the posture surface (the caller ran it before dispatch). It
  // aggregates 24h `query_anonymity_headers_stripped` audit evidence (Tier A
  // header-metadata strip). Read-only. Served here so the dashboard can light up
  // the Query-privacy section without inventing a second, weaker auth path.
  if (
    method === "GET" &&
    path === `${QUERY_ANONYMITY_API_PREFIX}/stats`
  ) {
    if (deps.auditLog === null) {
      writeJSON(res, 503, {
        error: "query_privacy_unavailable",
        reason: "audit log not unlocked; query-privacy stats cannot be evidenced",
        origin_machine: deps.originMachine,
      });
      return true;
    }
    try {
      const result = await handleQueryAnonymityStatsRequest({
        auditLog: deps.auditLog,
      });
      writeJSON(res, result.status, result.body);
    } catch {
      writeJSON(res, 500, {
        error: "internal_error",
        origin_machine: deps.originMachine,
      });
    }
    return true;
  }

  if (!path.startsWith(`${POSTURE_API_PREFIX}/`) && path !== POSTURE_API_PREFIX) {
    return false;
  }

  // Every error payload carries origin_machine too, so the `/v1`-compatible
  // shape constraint ("every payload") holds on the unhappy paths as well.
  const om = deps.originMachine;

  // Composition gate flag (Recognition precursor). This is CONFIG, not evidence:
  // the Recognition panel keys its render on this flag so the panel is ABSENT
  // (never implies a Concordia/Verascore dependency) when composition is off.
  // Deliberately served BEFORE the audit-log unlock gate below: it carries no
  // audit-derived evidence, so an honest config flag must not 503 just because
  // the audit log is locked. The payload is ONLY `{ composition_enabled,
  // origin_machine }` - no Concordia/Verascore data, no score, no fetch. Honest:
  // `false` when off (the default), which is config, not absence-of-evidence.
  if (method === "GET" && path === `${POSTURE_API_PREFIX}/composition`) {
    writeJSON(res, 200, {
      composition_enabled: deps.compositionEnabled === true,
      origin_machine: om,
    });
    return true;
  }

  // Every JSON posture route needs the audit log to be unlocked. Without it we
  // cannot prove enforcement or count operations - fail closed to a 503 that
  // says so honestly (never an empty-but-green payload).
  if (deps.auditLog === null) {
    writeJSON(res, 503, buildLockedAuditPostureUnavailableBody(om));
    return true;
  }

  // SSE live-refresh stream (additive, Phase 2). Reaches here only AFTER the
  // audit-null 503 guard above, so the stream is never opened against a locked
  // audit log (it would otherwise have to fabricate a green-or-empty payload).
  // It pushes the SAME `buildHome` payload as `/home` on a cadence plus a
  // heartbeat, with a concurrency cap + per-connection cleanup in the stream
  // handler. Disabled (404 within the namespace) when no registry is wired, so
  // the page falls back to polling. NOTE: this branch is deliberately OUTSIDE the
  // try/catch below - the handler owns its own try/catch and, once the SSE head
  // is written, an error must not also try to write a JSON 500 onto the same
  // already-sent response.
  if (method === "GET" && path === POSTURE_STREAM_PATH) {
    if (!deps.streamRegistry) {
      writeJSON(res, 404, { error: "not_found", origin_machine: om });
      return true;
    }
    await handlePostureStream(res, {
      // SSE admits and registers cleanup before refreshing each frame; it never joins the HTTP flight.
      buildHome: async () => buildHome(deps.refreshStreamDeps ? await deps.refreshStreamDeps() : deps),
      registry: deps.streamRegistry,
      ...(deps.streamIntervalMs !== undefined
        ? { intervalMs: deps.streamIntervalMs }
        : {}),
      ...(deps.streamHeartbeatMs !== undefined
        ? { heartbeatMs: deps.streamHeartbeatMs }
        : {}),
      ...(deps.streamMaxConcurrent !== undefined
        ? { maxConcurrent: deps.streamMaxConcurrent }
        : {}),
      ...(deps.streamSetInterval !== undefined
        ? { setIntervalFn: deps.streamSetInterval }
        : {}),
      ...(deps.streamClearInterval !== undefined
        ? { clearIntervalFn: deps.streamClearInterval }
        : {}),
    });
    return true;
  }

  try {
    if (method === "GET" && path === `${POSTURE_API_PREFIX}/castle-wall`) {
      const posture = await buildWallPosture(deps);
      writeJSON(res, 200, posture);
      return true;
    }

    if (method === "GET" && path === `${POSTURE_API_PREFIX}/digest`) {
      const digest = await buildDigest(deps);
      writeJSON(res, 200, digest);
      return true;
    }

    if (method === "GET" && path === `${POSTURE_API_PREFIX}/feature-health`) {
      const panel = await buildFeatureHealth(deps);
      writeJSON(res, 200, panel);
      return true;
    }

    if (method === "GET" && path === `${POSTURE_API_PREFIX}/custody-exit`) {
      const panel = await buildCustodyExit(deps);
      writeJSON(res, 200, panel);
      return true;
    }

    // Evidence View JSON endpoint (Phase 2, design section 2.5). Filterable
    // audit-entry table with integrity_findings surfaced ON-VIEW.  Reuses
    // AuditLog.query() verbatim; adds NO new backend query logic.
    //
    // HONESTY: integrity_findings are returned as-is from the query result and
    // must be surfaced by the client.  A chain with findings must NEVER render
    // green on the client side.  The operator audit is their own data, but it is
    // ALWAYS operator-gated (this route is behind checkAuth, unreachable to any
    // unauthenticated caller or non-operator, and cross-tenant is structurally
    // impossible because each fortress runs a separate AuditLog instance keyed
    // to its own encrypted storage namespace).
    //
    // Supported query params (all optional, all map to existing AuditLog.query()
    // options; any unrecognised param is silently ignored):
    //   ?agent=<identity_id>         filter by session identity or save attribution
    //   ?since=<ISO-string>          filter entries at or after this timestamp
    //   ?operation_type=<string>     filter by operation name
    //   ?layer=<l1|l2|l3|l4>        filter by layer
    //   ?result=<success|failure>    filter by result
    //   ?limit=<number>              max entries to return (default 50, cap 500)
    if (method === "GET" && path === `${POSTURE_API_PREFIX}/evidence`) {
      const result = await buildEvidence(deps, url);
      writeJSON(res, 200, result);
      return true;
    }

    // Recognition + portability panel (P5). GATED on composition-enabled: when
    // composition is OFF the panel is ABSENT entirely (404 within the namespace,
    // NOT a greyed/empty payload), so its mere existence never implies a
    // Concordia/Verascore dependency. When ON it returns LOCAL-evidence-only
    // receipt counts + local reputation evidence (counts, NOT a score) + the
    // portable-identity export capability. It reaches here only after the
    // audit-null 503 guard above, so it is never built against a locked log.
    // IMPARTIALITY: there is no score-fetch path; counterparty verification is
    // labeled local bridge crypto; rows are amber unless evidence is present.
    if (method === "GET" && path === `${POSTURE_API_PREFIX}/recognition`) {
      if (deps.compositionEnabled !== true) {
        // Honest absence: composition off => the Recognition panel does not
        // exist on this fortress. 404 (not an empty 200) so the page omits the
        // panel rather than rendering a greyed/implied-dependency shell.
        writeJSON(res, 404, {
          error: "recognition_unavailable",
          reason: "composition is disabled; the recognition panel is absent",
          origin_machine: om,
        });
        return true;
      }
      const panel = await buildRecognition(deps);
      writeJSON(res, 200, panel);
      return true;
    }

    if (method === "GET" && path === `${POSTURE_API_PREFIX}/unwrapped`) {
      const roster = await buildUnwrapped(deps, deps.listAgents());
      writeJSON(res, 200, roster);
      return true;
    }

    // Fleet Console Slice 1: the federation-backed fleet roster (the operator's
    // own admitted machines, each with its fail-closed trust verdict + a reach
    // indicator). LOOPBACK-ONLY read; SEE/MONITOR only (no trust mutation here).
    //
    // ABSENCE: when the dashboard does not supply `fleetRoster` (federation not
    // wired in this build path), the route 404s within the namespace so the page
    // simply omits the fleet panel; additive, never a broken/empty-green shell.
    //
    // TRUST: the roster's per-node verdict comes from `buildFleetRoster` reading
    // the federation layer's own `isNodeRevoked` projection (the SAME one every
    // sync path routes through), fail-closed: an unevaluable node renders
    // `untrusted`, never amber, never silently admitted. The presenter never
    // re-derives trust from a `/v1/nodes` response field. No key material is on
    // the roster shape.
    if (method === "GET" && path === `${POSTURE_API_PREFIX}/fleet`) {
      if (!deps.fleetRoster) {
        writeJSON(res, 404, {
          error: "fleet_unavailable",
          reason: "federation is not wired on this dashboard; the fleet panel is absent",
          origin_machine: om,
        });
        return true;
      }
      const roster = await buildFleet(deps);
      writeJSON(res, 200, roster);
      return true;
    }

    if (method === "GET" && path.startsWith(`${POSTURE_API_PREFIX}/reach/`)) {
      // Decode in its own guard: a malformed percent-encoding throws from
      // decodeURIComponent and must surface as a 400 client error, not a 500.
      let agentId: string;
      try {
        agentId = decodeURIComponent(
          path.slice(`${POSTURE_API_PREFIX}/reach/`.length),
        );
      } catch {
        writeJSON(res, 400, { error: "invalid_agent_id", origin_machine: om });
        return true;
      }
      if (!agentId) {
        writeJSON(res, 400, { error: "missing_agent_id", origin_machine: om });
        return true;
      }
      const reach = buildReach(deps, agentId);
      if (reach === null) {
        writeJSON(res, 404, {
          error: "agent_not_found",
          agent_id: agentId,
          origin_machine: om,
        });
        return true;
      }
      writeJSON(res, 200, reach);
      return true;
    }

    if (method === "GET" && path === `${POSTURE_API_PREFIX}/home`) {
      return respondWithBoundedDashboardRead({
        route: "posture_home",
        req: _req,
        res,
        operation: "get_posture_home",
        readFlights: deps.readFlightMap,
        originMachine: om,
        reconciliation: { arrivalSequence: deps.auditLog!.currentInMemorySequence(), reconcile: reconcilePostureHomeJoiner },
        produce: async () => ({
          status: 200,
          body: await buildHome(deps),
        }),
      });
    }

    // Within the posture namespace but no match - 404 here (do not fall
    // through to legacy routing for an unknown /api/posture path).
    writeJSON(res, 404, { error: "not_found", origin_machine: om });
    return true;
  } catch {
    writeJSON(res, 500, { error: "internal_error", origin_machine: om });
    return true;
  }
}

// ── Composition helpers ──────────────────────────────────────────────

// Eager reads preserve immediate local-append visibility. An out-of-band byte
// change in any entry is caught on the first eager read after one pass interval.
// The agent-facing evidence route retains full per-request verification.
async function buildWallPosture(
  deps: PostureRouteDeps,
  /**
   * S5-P: a pre-resolved exclusive-egress snapshot. `buildHome` resolves the
   * provider ONCE and threads the SAME snapshot into both the wall posture and
   * the feature-health panel, so an intermittent provider can never cap one
   * home surface while the other renders green (codex BLOCKER). Undefined =>
   * resolve here (the single-builder `/api/posture/castle-wall` route path,
   * where a single resolve per request is correct).
   */
  preResolvedExclusiveEgress?: ExclusiveEgressStatus | null,
  preResolvedProtectionClaimSubject?: string | null,
  preResolvedEnforcementAvailability?: ResolvedEnforcementAvailability | null,
): Promise<CastleWallPosture> {
  // S5-P: resolve the exclusive-egress posture BEFORE the eager read scope so
  // the provider (which may read its own state surfaces) never nests inside the
  // audit log's read scope. Fail-closed on provider throw.
  const exclusiveEgress =
    preResolvedExclusiveEgress !== undefined
      ? preResolvedExclusiveEgress
      : await resolveExclusiveEgress(deps);
  const protectionClaimSubject =
    preResolvedProtectionClaimSubject !== undefined
      ? preResolvedProtectionClaimSubject
      : await resolveProtectionClaimSubject(deps);
  const enforcementAvailability =
    preResolvedEnforcementAvailability !== undefined
      ? preResolvedEnforcementAvailability
      : await resolveEnforcementAvailability(deps);
  // Resolved BEFORE the eager read scope, like every other provider here, so a
  // filesystem read never nests inside the audit log's read scope. A throwing
  // provider is a claim-read FAILURE, not an absence of a claim, and must fail
  // closed: claimed=true renders the honest not-walled reading (the posture
  // read itself still succeeds; only the vault-claim half degrades honestly).
  // Falling back to `false` here was the "a throwing resolver also produces
  // green" fail-open Codex lens A round 2 found on 2026-09-10.
  let vaultProvisionClaimed = false;
  if (deps.resolveVaultProvisionClaimed) {
    try {
      vaultProvisionClaimed = await deps.resolveVaultProvisionClaimed();
    } catch {
      vaultProvisionClaimed = true;
    }
  }
  return (deps.auditLog as AuditLog).runEagerReads(() =>
    buildCastleWallPosture({
      auditLog: deps.auditLog as AuditLog,
      originMachine: deps.originMachine,
      ...(vaultProvisionClaimed ? { vaultProvisionClaimed: true } : {}),
      ...(deps.platform !== undefined ? { platform: deps.platform } : {}),
      ...(deps.now ? { now: deps.now() } : {}),
      pinnedProducerKeyB64url: deps.resolvePinnedProducerKey
        ? deps.resolvePinnedProducerKey()
        : null,
      // Unknown and unreadable observations cannot admit unsigned channel-basis evidence.
      ...(deps.producerKeyExpectedButUnavailable || deps.brokerProducerKeyExpectedButUnavailable
        ? { producerKeyExpectedButUnavailable: true }
        : {}),
      ...(exclusiveEgress !== null ? { exclusiveEgress } : {}),
      ...(enforcementAvailability !== null ? { enforcementAvailability } : {}),
      protectionClaimSubject,
    }),
  );
}

async function buildDigest(
  deps: PostureRouteDeps,
  preResolvedProtectionClaimSubject?: string | null,
): Promise<AuditDigest> {
  const protectionClaimSubject =
    preResolvedProtectionClaimSubject !== undefined
      ? preResolvedProtectionClaimSubject
      : await resolveProtectionClaimSubject(deps);
  return (deps.auditLog as AuditLog).runEagerReads(() =>
    buildAuditDigest({
      auditLog: deps.auditLog as AuditLog,
      originMachine: deps.originMachine,
      protectionClaimSubject,
      ...(deps.now ? { now: deps.now() } : {}),
      pinnedProducerKeyB64url: deps.resolvePinnedProducerKey
        ? deps.resolvePinnedProducerKey()
        : null,
      // Unknown and unreadable observations cannot admit unsigned channel-basis evidence.
      ...(deps.producerKeyExpectedButUnavailable || deps.brokerProducerKeyExpectedButUnavailable
        ? { producerKeyExpectedButUnavailable: true }
        : {}),
    }),
  );
}

/** Feature health uses the verified eager view: an out-of-band byte change in
 * any entry is caught on the first eager read after one pass interval. */
async function buildFeatureHealth(
  deps: PostureRouteDeps,
  /**
   * S5-P: a pre-resolved exclusive-egress snapshot (see `buildWallPosture`).
   * `buildHome` passes the SAME snapshot it gave the wall posture so the
   * `castle_wall_egress` row and the banner cap green from ONE verdict.
   * Undefined => resolve here (the single-builder `/api/posture/feature-health`
   * route path).
   */
  preResolvedExclusiveEgress?: ExclusiveEgressStatus | null,
  preResolvedProtectionClaimSubject?: string | null,
  preResolvedEnforcementAvailability?: ResolvedEnforcementAvailability | null,
): Promise<FeatureHealthPanel> {
  // S5-P: same fail-closed resolve as the wall posture, so the
  // `castle_wall_egress` row and the banner cap green identically.
  const exclusiveEgress =
    preResolvedExclusiveEgress !== undefined
      ? preResolvedExclusiveEgress
      : await resolveExclusiveEgress(deps);
  const protectionClaimSubject =
    preResolvedProtectionClaimSubject !== undefined
      ? preResolvedProtectionClaimSubject
      : await resolveProtectionClaimSubject(deps);
  const enforcementAvailability =
    preResolvedEnforcementAvailability !== undefined
      ? preResolvedEnforcementAvailability
      : await resolveEnforcementAvailability(deps);
  return (deps.auditLog as AuditLog).runEagerReads(() =>
    buildFeatureHealthPanel({
      auditLog: deps.auditLog as AuditLog,
      originMachine: deps.originMachine,
      // Surface the per-plugin attribution rows on the operator posture surface.
      // Read-only projection over the same audit read; never enforcement-bearing.
      includePluginRows: true,
      ...(exclusiveEgress !== null ? { exclusiveEgress } : {}),
      protectionClaimSubject,
      ...(deps.platform !== undefined ? { platform: deps.platform } : {}),
      ...(enforcementAvailability !== null ? { enforcementAvailability } : {}),
      ...(deps.now ? { now: deps.now() } : {}),
      pinnedProducerKeyB64url: deps.resolvePinnedProducerKey
        ? deps.resolvePinnedProducerKey()
        : null,
      brokerPinnedProducerKeyB64url: deps.resolveBrokerPinnedProducerKey
        ? deps.resolveBrokerPinnedProducerKey()
        : null,
      // Unknown and unreadable observations cannot admit unsigned channel-basis evidence.
      ...(deps.producerKeyExpectedButUnavailable
        ? { producerKeyExpectedButUnavailable: true }
        : {}),
      ...(deps.brokerProducerKeyExpectedButUnavailable
        ? { brokerProducerKeyExpectedButUnavailable: true }
        : {}),
    }),
  );
}

/**
 * Query-privacy section (Phase 2). Reads the Tier A 24h header-strip stats from
 * the same audit chain (a failed read passes null, which the shaper renders as
 * `unconfirmed`, never green) and carries the Tier B PII-rewrite feature-health
 * row through verbatim. The shaper hard-asserts header stripping is metadata
 * hygiene, not anonymity.
 */
async function buildQueryPrivacy(
  deps: PostureRouteDeps,
  featureHealth: FeatureHealthPanel,
): Promise<QueryPrivacySection> {
  let stats: { total_outbound_calls: number; total_headers_stripped: number; window: "24h" } | null;
  try {
    // An out-of-band byte change is caught on the first eager read after one pass interval.
    const computed = await (deps.auditLog as AuditLog).runEagerReads(() =>
      computeQueryAnonymityStats({
        auditLog: deps.auditLog as AuditLog,
        ...(deps.now ? { now: () => new Date(deps.now!()) } : {}),
      }),
    );
    stats = {
      window: computed.window,
      total_outbound_calls: computed.total_outbound_calls,
      total_headers_stripped: computed.total_headers_stripped,
    };
  } catch {
    // A failed stats read is NOT evidence of health: leave stats null so the
    // Tier-A row renders `unconfirmed` (amber), never green.
    stats = null;
  }
  const tierBRow =
    featureHealth.rows.find((r) => r.feature_id === TIER_B_FEATURE_ID) ?? null;
  return buildQueryPrivacySection({
    originMachine: deps.originMachine,
    headerStripStats: stats,
    tierBRow,
  });
}

/**
 * Custody & Exit panel (Slice 3). Read-only over the audit chain the dashboard
 * already reads: it surfaces NEGATIVE custody evidence (pin-custody mismatch /
 * suspected-rollback freeze) and custody-establishment provenance, plus the
 * honest CLI-gated exit-export capability. It never re-derives custody HEALTH
 * (that lives under the transient master at boot), so the custody tile is never
 * green - amber unconfirmed or red damaged only.
 */
async function buildCustodyExit(
  deps: PostureRouteDeps,
): Promise<CustodyExitPanel> {
  return (deps.auditLog as AuditLog).runEagerReads(() =>
    buildCustodyExitPanel({
      auditLog: deps.auditLog as AuditLog,
      originMachine: deps.originMachine,
      ...(deps.now ? { now: deps.now() } : {}),
    }),
  );
}

/**
 * Evidence View JSON endpoint (Phase 2, design section 2.5). Reads the audit
 * chain via `AuditLog.query()` with the operator-supplied filter params and
 * returns entries + integrity_findings.  Adds NO new backend query logic; it is
 * a thin URL-param-to-query-options adapter over the existing query API.
 *
 * Supported URL params (all optional; unrecognised params are ignored):
 *   ?agent=<string>            - maps to query.evidence_agent before pagination
 *   ?since=<ISO-string>        - maps to query.since
 *   ?operation_type=<string>   - maps to query.operation_type
 *   ?layer=<l1|l2|l3|l4>      - maps to query.layer
 *   ?result=<success|failure>  - applied as post-filter (query has no result
 *                                field; we filter after the query returns)
 *   ?limit=<number>            - capped at 500; defaults to 50
 */
async function buildEvidence(
  deps: PostureRouteDeps,
  url: URL,
): Promise<{
  origin_machine: string;
  entries: import("../operational/audit-log.js").AuditEntry[];
  total: number;
  integrity_findings: import("../operational/audit-log.js").AuditIntegrityFinding[];
  chain_verdict: import("../operational/audit-log.js").AuditChainVerdictStatus;
  sealed_region: import("../operational/audit-log.js").SealedRegionVerdict;
}> {
  const auditLog = deps.auditLog as AuditLog;

  // Parse filter params defensively: invalid values are silently ignored so the
  // endpoint degrades gracefully (a bad param gives unfiltered results, not 500).
  const agentParam = url.searchParams.get("agent") ?? undefined;
  const sinceParam = url.searchParams.get("since") ?? undefined;
  const opParam = url.searchParams.get("operation_type") ?? undefined;
  const resultParam = url.searchParams.get("result") ?? undefined;

  const layerRaw = url.searchParams.get("layer");
  const validLayers = ["l1", "l2", "l3", "l4"] as const;
  type Layer = (typeof validLayers)[number];
  const layerParam: Layer | undefined =
    validLayers.includes(layerRaw as Layer) ? (layerRaw as Layer) : undefined;

  const limitRaw = Number(url.searchParams.get("limit") ?? "50");
  const limitParam = Number.isFinite(limitRaw) && limitRaw > 0
    ? Math.min(Math.floor(limitRaw), 500)
    : 50;

  const queryResult = await auditLog.query({
    since: sinceParam,
    layer: layerParam,
    operation_type: opParam,
    // Must match AuditLog.query evidence_agent in operational/audit-log.ts; display filtering never substitutes for session authorization.
    evidence_agent: agentParam,
    limit: limitParam,
  });

  // Result filter is applied as a post-filter (AuditLog.query has no result
  // param).  We re-derive total to reflect post-filter count.
  let entries = queryResult.entries;
  const total = queryResult.total;
  if (resultParam === "success" || resultParam === "failure") {
    entries = entries.filter((e) => e.result === resultParam);
    // total is queryResult.total: the in-window count BEFORE the result
    // post-filter (and before the limit slice).  It is NOT the count of matched
    // entries; the client can compare entries.length against total to detect
    // truncation at the query level, but cannot infer how many in-window entries
    // matched the result filter.  This is the honest reading of the number.
  }

  // BLOCKER-1 (round 3): `integrity_findings` is the ROUTINE finding set, which
  // skips the sealed legacy region. Surface the shared audit-chain verdict so a
  // client cannot read empty `integrity_findings` as "the whole chain is clean"
  // over an in-place-corrupted sealed entry.
  const chainVerdict = await auditLog.getAuditChainVerdict();
  return {
    origin_machine: deps.originMachine,
    entries,
    total,
    integrity_findings: queryResult.integrity_findings,
    chain_verdict: chainVerdict.status,
    sealed_region: chainVerdict.sealed_region,
  };
}

/**
 * Recognition + portability panel (P5). The route already enforced the
 * composition-enabled render gate and the audit-unlock 503 before we reach here,
 * so this helper only shapes evidence. It resolves the two optional impure
 * sources defensively: a failed bridge-commitment list or a failed reputation
 * gather degrades to the honest fallback (audit-event lower bound / `null` amber
 * row) rather than throwing, so a partial-evidence fortress still renders an
 * honest panel instead of a 500. There is NO score fetch on any of these paths.
 */
async function buildRecognition(deps: PostureRouteDeps): Promise<RecognitionPanel> {
  let committedReceiptCount: number | undefined;
  if (deps.countBridgeCommitments) {
    try {
      committedReceiptCount = await deps.countBridgeCommitments();
    } catch {
      // A failed `_bridge` list is not evidence of zero receipts: leave it
      // undefined so the shaper falls back to the audit-event lower bound.
      committedReceiptCount = undefined;
    }
  }

  let reputationEvidence: RecognitionReputationEvidence | null = null;
  if (deps.gatherRecognitionReputation) {
    try {
      reputationEvidence = await deps.gatherRecognitionReputation();
    } catch {
      // A failed reputation read is NOT evidence of health: null renders the
      // reputation row amber ("no evidence yet"), never green.
      reputationEvidence = null;
    }
  }

  return (deps.auditLog as AuditLog).runEagerReads(() =>
    buildRecognitionPanel({
      auditLog: deps.auditLog as AuditLog,
      originMachine: deps.originMachine,
      ...(deps.now ? { now: deps.now() } : {}),
      ...(committedReceiptCount !== undefined ? { committedReceiptCount } : {}),
      reputationEvidence,
    }),
  );
}

async function buildUnwrapped(deps: PostureRouteDeps, records: LocalAgentRecord[]): Promise<UnwrappedRoster> {
  const detected = deps.detectInstalledHarnesses
    ? await deps.detectInstalledHarnesses()
    : await scanInstalledHarnesses(deps.auditLog as AuditLog, deps.originMachine);
  return buildUnwrappedRoster({
    originMachine: deps.originMachine,
    wrappedAgents: records,
    detectedHarnesses: detected,
  });
}

/**
 * Fleet Console Slice 1: resolve the federation-backed fleet roster.
 *
 * The roster is built by the dashboard-supplied `fleetRoster` closure, which
 * runs `buildFleetRoster` against the live `V1FederationDeps`. We wrap the read
 * in `runEagerReads` so it shares the same maintained-view read scope as the
 * other always-on posture panels and the cross-machine fan-out stays cheap. The
 * caller has already guarded `deps.fleetRoster` non-null (404 otherwise).
 */
async function buildFleet(deps: PostureRouteDeps): Promise<FleetRoster> {
  const resolve = deps.fleetRoster as () => FleetRoster | Promise<FleetRoster>;
  return (deps.auditLog as AuditLog).runEagerReads(async () => resolve());
}

function buildReach(
  deps: PostureRouteDeps,
  agentId: string,
): AgentEffectiveReach | null {
  const agent = deps.listAgents().find((a) => a.agent_id === agentId);
  if (!agent) return null;
  const rules = deps.listReachRules
    ? deps.listReachRules()
    : curatedReachRules(
        deps.listEnabledCuratedRuleIds
          ? deps.listEnabledCuratedRuleIds()
          : null,
      );
  // #641 honesty gate: derive enforcement_confirmed from the SAME per-agent
  // signal the agent pill uses, via the canonical row shaper (single source of
  // truth: never re-implement the policy-vs-enforcement split). Today this is
  // always false (no per-agent live enforcement signal exists), so the reach
  // view renders rules as configured, not as confirmed OS enforcement. Routing
  // it through `buildPostureAgentRows` means any future per-agent enforcement
  // probe lights up the pill AND the reach view together, with no second path.
  const [row] = buildPostureAgentRows({
    originMachine: deps.originMachine,
    records: [agent],
  });
  const enforcementConfirmed = row?.enforcement_active === "active";
  return buildAgentReach({
    originMachine: deps.originMachine,
    agentId,
    harness: agent.harness,
    rules,
    enforcementConfirmed,
  });
}

// `PostureHome` is defined in `./posture-home-types.js` (imported above) so the
// SSE stream handler can share the payload shape without a `posture-routes` <->
// `posture-stream` cycle. Re-exported here to preserve the historical import
// site (`import type { PostureHome } from "./posture-routes.js"`).
export type { PostureHome };

/** Load the key pair under the producer budget before composing any dependent panels. */
export async function loadPostureProducerKeys(deps: PostureRouteDeps): Promise<PostureRouteDeps> {
  const producer = deps.producerKeyObservation ?? observeInjectedProducerKey(deps.resolvePinnedProducerKey);
  const broker = deps.brokerProducerKeyObservation ?? observeInjectedProducerKey(deps.resolveBrokerPinnedProducerKey);
  // Negative observations are transient: retaining one must never delay a repaired key's first request.
  if (keyRestricted(producer) || keyRestricted(broker)) deps.panelStore.invalidate("producer_keys");
  // Must match the inputKey check in panel-producer.ts: both named observation states invalidate reuse on transition.
  const producerKeysInputKey = JSON.stringify([producer, broker]);
  const readKeys = () => deps.panelStore.read("producer_keys", deps.auditLog?.currentInMemorySequence() ?? 0,
    () => deps.prepareProducerKeys ? deps.prepareProducerKeys() : Promise.resolve({
      resolvePinnedProducerKey: deps.resolvePinnedProducerKey,
      resolveBrokerPinnedProducerKey: deps.resolveBrokerPinnedProducerKey,
      producerKeyObservation: producer, brokerProducerKeyObservation: broker,
    }), producerKeysInputKey);
  const retainedKeys = deps.panelStore.snapshot<ProducerKeys>("producer_keys").value;
  let keys = await readKeys();
  if (keys.status.state === "fresh" && keys.value === retainedKeys &&
      !keyRestricted(producer) && !keyRestricted(broker) && keys.value &&
      (keyRestricted(keys.value.producerKeyObservation) || keyRestricted(keys.value.brokerProducerKeyObservation))) {
    // Only a reused completed negative gets one retry; a timed-out or newly completed read cannot spend a second budget.
    deps.panelStore.invalidate("producer_keys");
    keys = await readKeys();
  }
  // A timed-out first load cannot establish absence, even if no key has ever been cached.
  const ready = { ...deps, ...(keys.status.state === "fresh" ? keys.value : {}), producerKeysStatus: keys.status };
  ready.producerKeyObservation = keys.status.state === "fresh" ? keys.value?.producerKeyObservation ?? producer : producer === "present" ? producer : "unknown";
  ready.brokerProducerKeyObservation = keys.status.state === "fresh" ? keys.value?.brokerProducerKeyObservation ?? broker : broker === "present" ? broker : "unknown";
  const observations = [ready.producerKeyObservation, ready.brokerProducerKeyObservation];
  if (observations.some(keyRestricted)) {
    // Unknown and unreadable are unavailable observations, never a successfully established no-key state.
    ready.producerKeysStatus = { ...keys.status, state: "unavailable", completed_at: null, age_ms: null,
      reason: keys.status.reason ?? (observations.includes("unreadable") ? "producer_failed" : "never_completed") };
  }
  return ready;
}

/** Apply the post-load observations; the loader runs before this shaping boundary. */
export async function withPostureProducerKeys(initial: PostureRouteDeps): Promise<PostureRouteDeps> {
  const deps = initial.producerKeysStatus ? initial : await loadPostureProducerKeys(initial);
  return withDerivedKeyRestriction(deps);
}

function withDerivedKeyRestriction(deps: PostureRouteDeps): PostureRouteDeps {
  return { ...deps,
    // Every root derives these flags here; a caller cannot omit the named observation's restriction.
    // Derived, do not set: absence alone admits channel-basis evidence at each shaper below.
    get producerKeyExpectedButUnavailable() { return keyRestricted(deps.producerKeyObservation ?? observeInjectedProducerKey(deps.resolvePinnedProducerKey)); },
    get brokerProducerKeyExpectedButUnavailable() { return keyRestricted(deps.brokerProducerKeyObservation ?? observeInjectedProducerKey(deps.resolveBrokerPinnedProducerKey)); },
  };
}

// Must match the audit readers in buildHome's producer table below; query_privacy reads header-strip evidence and federation enters runEagerReads through buildFleet.
export const AUDIT_READING_HOME_PANELS = ["castle_wall", "digest", "feature_health", "query_privacy", "custody_exit", "federation"] as const;

/** Reconcile a route-flight follower against the audit state at its own arrival. */
export function reconcilePostureHomeJoiner(home: PostureHome, admissionSequence: number, arrivalSequence: number): PostureHome {
  if (arrivalSequence <= admissionSequence || !home.panels) return home;
  const result = { ...home, panels: { ...home.panels } };
  // A flight proves its admission sequence only; a newer caller gets a private capped copy.
  for (const id of AUDIT_READING_HOME_PANELS) {
    Object.assign(result, { [id]: capStalePanel(id, home[id]) });
    result.panels[id] = { ...home.panels[id], state: home.panels[id].state === "unavailable" ? "unavailable" : "stale",
      reason: home.panels[id].reason ?? "observation_superseded" };
  }
  return result;
}

/** Existing fail-closed wire shapes, assembled synchronously with no producer work. */
function unavailableHomeValues(deps: PostureRouteDeps): Pick<PostureHome, "castle_wall" | "digest" | "feature_health" | "custody_exit" | "unwrapped" | "federation" | "query_privacy"> {
  const origin_machine = deps.originMachine;
  const now = deps.now?.() ?? Date.now();
  const window_start = new Date(now - DEFAULT_DIGEST_WINDOW_MS).toISOString();
  const window_end = new Date(now).toISOString();
  const castle_wall: CastleWallPosture = {
    origin_machine, arm_state: "unknown", evidence_basis: "no_evidence",
    platform: (deps.platform ?? process.platform) === "darwin" ? "macos" : (deps.platform ?? process.platform) === "linux" ? "linux" : "other",
    last_enforcement_evidence_at: null, freshness_window_ms: DEFAULT_ENFORCEMENT_FRESHNESS_MS,
    verdict_counts: { allowed: 0, blocked: 0, operator_decisions: 0 }, audit_integrity_ok: false,
    sealed_region_unverified_at_privilege: false, producer_authenticity: "not_applicable",
  };
  const digest: AuditDigest = {
    origin_machine, window_start, window_end, window_complete: false, window_incomplete_reason: "coverage_unknown",
    kernel_allow_overrides: 0, blocked_destinations: [], blocked_destination_count: 0,
    total_operations: 0, failures: 0, kernel_blocks: 0, kernel_allows: 0, approvals_granted: 0,
    approvals_denied: 0, by_agent: [], chain_verified: false, chain_verdict: "findings", integrity_finding_count: 0,
  };
  const feature_health: FeatureHealthPanel = {
    origin_machine, window_start, window_end, audit_integrity_ok: false, sealed_region_unverified_at_privilege: false,
    rows: SLICE1_FEATURE_REGISTRY.map(feature => ({ origin_machine, feature_id: feature.id, label: feature.label,
      liveness: feature.liveness, status: "unknown", basis: "stale_evidence", invocation_count: 0,
      last_evidence_at: null, broken_zero_detectable: feature.brokenZeroDetectable,
      expectation_floor: null, trailing_window_volume: null, audit_integrity_ok: false,
      freshness_window_ms: DEFAULT_ENFORCEMENT_FRESHNESS_MS })),
    plugin_rows: [], disclosure: { broken_zero_undetectable_for_event_driven: true,
      castle_wall_silent_death_is_unknown_not_green: true, silent_death_distinguished_from_intentional_stop: false,
      broker_daemon_silent_death_detectable: false },
  };
  const custody_exit: CustodyExitPanel = {
    origin_machine, custody_state: "unconfirmed", custody_basis: "no_negative_evidence_unconfirmed",
    rollback_freeze_suspected: false, pin_custody_mismatch: false, establishment: null, last_damage_evidence_at: null,
    freshness_window_ms: DEFAULT_ENFORCEMENT_FRESHNESS_MS, audit_integrity_ok: false,
    exit_state: "export_available", exit_command: "sanctuary exit export", clean_exit_guaranteed: false,
  };
  return { castle_wall, digest, feature_health, custody_exit,
    unwrapped: buildUnwrappedRoster({ originMachine: origin_machine, wrappedAgents: [], detectedHarnesses: [] }),
    federation: { available: false, enabled: false, fleet_node_count: 0 },
    query_privacy: buildQueryPrivacySection({ originMachine: origin_machine, headerStripStats: null, tierBRow: null }),
  };
}

export async function buildHome(initialDeps: PostureRouteDeps): Promise<PostureHome> {
  const deps = await withPostureProducerKeys(initialDeps);
  const store = deps.panelStore;
  const sequence = () => deps.auditLog!.currentInMemorySequence();
  const fallback = unavailableHomeValues(deps);
  // Either unresolved key keeps dependent claims restrictive; only positive absence permits the no-key path.
  const keysRestricted = keyRestricted(deps.producerKeyObservation) || keyRestricted(deps.brokerProducerKeyObservation);
  // S5-P: one fresh-or-capped snapshot is shared by wall and feature health.
  const [roster, exclusive, subject, availability, provision] = await Promise.all([
    store.read("agents_roster", sequence(), () => deps.listAgents(), NO_PANEL_INPUTS), // Roster has no shared resolver inputs.
    store.read("exclusive_egress", sequence(), () => deps.exclusiveEgressPosture?.() ?? null, NO_PANEL_INPUTS), // Egress is an independent resolver.
    store.read("protection_subject", sequence(), () => deps.resolveProtectionClaimSubject?.() ?? null, NO_PANEL_INPUTS), // Subject is an independent resolver.
    store.read("enforcement_availability", sequence(), () => deps.resolveEnforcementAvailability
      ? deps.resolveEnforcementAvailability() : resolveEnforcementAvailability(deps), NO_PANEL_INPUTS), // Availability has no shared inputs.
    store.read("vault_provision_claim", sequence(), () => deps.resolveVaultProvisionClaimed?.() ?? false, NO_PANEL_INPUTS), // Provision is an independent resolver.
  ]);
  // Missed exclusive-egress observations cannot mean no fine-grained agent exists.
  const exclusiveValue = exclusive.status.state === "fresh" ? exclusive.value! : failedExclusiveEgressStatus("budget_exceeded");
  // Availability absence cannot prove current enforcement, even if old evidence was green.
  const availabilityValue = availability.status.state === "fresh" ? availability.value! : {
    status: "undetermined" as const, reason: "availability_budget_exceeded", observed_at: null,
    freshness_window_ms: DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS, active_connection_count: 0,
  };
  // An unread claim must retain the not-yet-walled restriction.
  const provisionValue = provision.status.state === "fresh" ? provision.value! : true;
  // A previous identity binding is reusable; no binding observation means no dependent green.
  const subjectMissing = subject.status.state !== "fresh" && subject.value === undefined;
  const subjectValue = subject.value ?? null;
  const records = roster.value ?? [];
  const snapshotDeps = { ...deps, resolveVaultProvisionClaimed: async () => provisionValue };
  // Must match the inputKey reuse check in panel-producer.ts: resolver values can change without an append.
  // observed_at is part of this key, so live resolver timestamps usually prevent dependent reuse; this is fail-safe.
  const evidenceInputKey = JSON.stringify([exclusiveValue, subjectValue, availabilityValue, provisionValue,
    deps.producerKeyObservation, deps.brokerProducerKeyObservation]);
  // Audit-reading producers must match AUDIT_READING_HOME_PANELS above.
  const [wall, digest, unwrapped, health, custody, federation] = await Promise.all([
    subjectMissing ? Promise.resolve(store.snapshot<CastleWallPosture>("castle_wall", "upstream_unavailable")) :
      store.read("castle_wall", sequence(), () => buildWallPosture(snapshotDeps, exclusiveValue, subjectValue, availabilityValue), evidenceInputKey),
    store.read("digest", sequence(), () => buildDigest(deps, subjectValue), JSON.stringify([subjectValue, deps.producerKeyObservation, deps.brokerProducerKeyObservation])),
    store.read("unwrapped", sequence(), () => buildUnwrapped(deps, records), JSON.stringify(records)),
    subjectMissing ? Promise.resolve(store.snapshot<FeatureHealthPanel>("feature_health", "upstream_unavailable")) :
      store.read("feature_health", sequence(), () => buildFeatureHealth(deps, exclusiveValue, subjectValue, availabilityValue), evidenceInputKey),
    store.read("custody_exit", sequence(), () => buildCustodyExit(deps), NO_PANEL_INPUTS), // Custody depends on the audit sequence alone.
    store.read("federation", sequence(), () => buildFederationSummary(deps), NO_PANEL_INPUTS), // Federation has no shared resolver inputs.
  ]);
  function value<K extends keyof typeof fallback>(id: K, result: PanelSnapshot<PostureHome[K]>): PostureHome[K] {
    // An unavailable panel has no complete observation; stale observations must lose green.
    return result.value === undefined ? fallback[id] as PostureHome[K] : result.status.state === "fresh" ? result.value : capStalePanel(id, result.value) as PostureHome[K];
  }
  function lowerForUpstream(result: PanelSnapshot<unknown>): void {
    // Upstream caps cannot hide the panel's own timeout or failure reason.
    result.status = { ...result.status, state: result.value === undefined ? "unavailable" : "stale",
      reason: result.status.reason ?? "upstream_unavailable" };
  }
  let castleWall = value("castle_wall", wall);
  let featureHealth = value("feature_health", health);
  // Even a reused completed panel must respect this payload's shared resolver snapshot.
  if (exclusive.status.state !== "fresh" || availability.status.state !== "fresh" || subjectMissing ||
      keysRestricted || provision.status.state !== "fresh") {
    // A body capped for a missed upstream cannot advertise a fresh panel status.
    for (const result of [wall, health]) {
      lowerForUpstream(result);
    }
    castleWall = capStalePanel("castle_wall", castleWall);
    featureHealth = capStalePanel("feature_health", featureHealth);
  }
  const query = await store.read("query_privacy", sequence(), () => buildQueryPrivacy(deps, featureHealth), JSON.stringify(featureHealth));
  let queryPrivacy = value("query_privacy", query);
  if (health.status.state !== "fresh" || !featureHealth.audit_integrity_ok) {
    // The query body and its freshness status describe the same restricted observation.
    queryPrivacy = capStalePanel("query_privacy", queryPrivacy);
    lowerForUpstream(query);
  }
  if (keysRestricted) {
    // The zero fallback is no completed observation, so it cannot carry the discarded digest's age.
    digest.status = { ...digest.status, state: "unavailable", completed_at: null, age_ms: null,
      reason: digest.status.reason ?? "upstream_unavailable" };
  }
  const agentsRaw = buildPostureAgentRows({ originMachine: deps.originMachine, records });
  const agents = roster.status.state === "fresh" ? agentsRaw : capStalePanel("agents", agentsRaw);
  const unwrappedValue = value("unwrapped", unwrapped);
  return {
    origin_machine: deps.originMachine, stream_available: deps.streamRegistry !== undefined,
    producer_keys: { producer: deps.producerKeyObservation!, broker: deps.brokerProducerKeyObservation!,
      message: [deps.producerKeyObservation, deps.brokerProducerKeyObservation].includes("unknown")
        ? "Producer key state is not yet determined."
        : [deps.producerKeyObservation, deps.brokerProducerKeyObservation].includes("unreadable")
          ? "A producer key is expected and unavailable." : null },
    panels: { producer_keys: deps.producerKeysStatus!, agents_roster: roster.status,
      exclusive_egress: exclusive.status, protection_subject: subject.status, enforcement_availability: availability.status,
      vault_provision_claim: provision.status, castle_wall: wall.status, digest: digest.status, unwrapped: unwrapped.status,
      feature_health: health.status, custody_exit: custody.status, federation: federation.status, query_privacy: query.status },
    audit_verification: deps.auditLog!.verificationCacheStats(),
    castle_wall: castleWall, digest: keysRestricted ? fallback.digest : value("digest", digest),
    unwrapped: unwrappedValue, feature_health: featureHealth, custody_exit: value("custody_exit", custody),
    federation: value("federation", federation), query_privacy: queryPrivacy, agents,
    protection_requested_count: agents.filter(a => a.policy_protected).length,
    protection_detected_count: records.length + unwrappedValue.unwrapped.length,
    enforcement_confirmed_count: agents.filter(a => a.enforcement_active === "active").length,
  };
}

async function buildFederationSummary(
  deps: PostureRouteDeps,
): Promise<PostureHome["federation"]> {
  if (!deps.fleetRoster) {
    return { available: false, enabled: false, fleet_node_count: 0 };
  }
  const roster = await buildFleet(deps);
  return {
    available: roster.available,
    enabled: roster.enabled,
    fleet_node_count: roster.summary.total,
  };
}

// ── Real-data sourcing ───────────────────────────────────────────────

/**
 * Scan for installed harnesses by config-file presence (review finding M1:
 * config detection of installed products, NOT live process inspection). Each
 * detected harness is recorded against the platform paths the config-reader
 * already knows. The scan itself is audit-logged (open question 5: the scan is
 * a local-machine read worth recording).
 */
async function scanInstalledHarnesses(
  auditLog: AuditLog,
  originMachine: string,
): Promise<DetectedHarness[]> {
  const detected: DetectedHarness[] = [];
  const platforms = Object.keys(getPlatformPaths()) as AgentPlatform[];
  for (const platform of platforms) {
    if (platform === "generic") continue; // generic has no canonical paths
    const result = await detectAgentConfigWithDiagnostics(platform);
    if (result.config) {
      detected.push({
        platform,
        harness: PLATFORM_TO_HARNESS[platform],
        config_path: result.config.configPath,
      });
    }
  }

  // Audit-log the scan (best-effort; never block the response on the write).
  try {
    await auditLog.append(
      "l2",
      "posture_unwrapped_scan",
      originMachine,
      {
        detected_harnesses: detected.map((d) => d.harness),
        detection_method: "config_file_presence",
      },
      "success",
    );
  } catch {
    // A failed audit write must not deny the operator the roster.
  }

  return detected;
}

/**
 * Reach rules from the curated allowlist, scoped to the rules the operator has
 * ACTUALLY enabled (#641). Phase 1 read-only source for the dashboard (no daemon
 * dependency). Curated entries are `default_enabled: false` and are NOT
 * auto-applied at install; mapping the entire catalog would have shown
 * never-enabled rules as an operator-enabled, kernel-enforced default-deny: the
 * fabricated posture #641 fixes. Instead we source via `resolveCuratedRules`
 * over the operator's enabled rule ids: an empty / null id set yields NO rules,
 * so the reach view reports `has_wall_policy=false` and surfaces the honest red
 * "No Castle Wall ruleset applies to this agent" gap rather than a fabricated
 * default-deny. The `castle_wall` enforcing layer is a CONFIGURATION fact (these
 * rules target the wall); whether the OS is actually enforcing them is gated
 * separately by `enforcement_confirmed` on the payload.
 */
function curatedReachRules(
  enabledRuleIds: readonly string[] | null,
): ReachRule[] {
  if (!enabledRuleIds || enabledRuleIds.length === 0) return [];
  return resolveCuratedRules(enabledRuleIds).map((allowRule) => {
    const rule: ReachRule = {
      rule_id: allowRule.id,
      disposition: allowRule.disposition,
      enforcing_layer: "castle_wall",
    };
    const match = allowRule.match;
    if (match.host !== undefined) rule.host = match.host;
    if (match.host_pattern !== undefined) rule.host_pattern = match.host_pattern;
    if (match.ip !== undefined) rule.ip = match.ip;
    if (match.cidr !== undefined) rule.cidr = match.cidr;
    if (allowRule.scope?.agent_ids !== undefined) {
      rule.agent_ids = allowRule.scope.agent_ids;
    }
    return rule;
  });
}

function writeJSON(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(body));
}
