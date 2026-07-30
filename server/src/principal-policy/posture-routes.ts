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
import type { AuditLog } from "../operational/audit-log.js";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import { detectAgentConfigWithDiagnostics, getPlatformPaths } from "../wrap/config-reader.js";
import type { AgentPlatform } from "../wrap/config-reader.js";
import { resolveCuratedRules } from "../castle-wall/runtime/curated-allowlist.js";
import {
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
import type { EnforcementAvailabilityStatusFile } from "../castle-wall/runtime/enforcement-availability-status.js";
// `PostureHome` lives in a neutral type module so `posture-stream.ts` can import
// the payload shape without closing a `posture-routes` <-> `posture-stream`
// cycle (this module imports the stream handler above).
import type { PostureHome } from "./posture-home-types.js";

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
  /**
   * Slice P fail-honest signal: a producer key is EXPECTED for this fortress (the
   * daemon published one) but the dashboard could NOT load it (present but
   * unreadable / malformed). When true, the readers refuse to render green on the
   * channel basis - the wall posture forces `degraded`, the digest reports an
   * unverified chain, and feature-health rows render `unknown`. Mutually
   * exclusive with a non-null `resolvePinnedProducerKey()`.
   */
  producerKeyExpectedButUnavailable?: boolean;
  /** Pinned public key for the broker daemon liveness producer. */
  resolveBrokerPinnedProducerKey?: () => string | null;
  /** Broker liveness producer key exists or is expected but could not be read. */
  brokerProducerKeyExpectedButUnavailable?: boolean;
  /**
   * Canonical confined-agent subject (`fortress/uid-N`) for protection claims.
   * When provided, Castle Wall green evidence must bind to this subject across
   * posture and feature-health readers.
   */
  resolveProtectionClaimSubject?: () => string | null | Promise<string | null>;
  /**
   * Fresh local extension diagnostic fallback. This lets safe-mode diagnostics
   * written before master-key unlock degrade/fault every status surface after
   * login without treating the local file as green evidence.
   */
  resolveEnforcementAvailabilityStatus?: () =>
    | EnforcementAvailabilityStatusFile
    | null
    | Promise<EnforcementAvailabilityStatusFile | null>;
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

async function resolveEnforcementAvailabilityStatus(
  deps: PostureRouteDeps,
): Promise<EnforcementAvailabilityStatusFile | null> {
  if (!deps.resolveEnforcementAvailabilityStatus) return null;
  try {
    return await deps.resolveEnforcementAvailabilityStatus();
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
    writeJSON(res, 503, {
      error: "posture_unavailable",
      reason: "audit log not unlocked; posture cannot be evidenced",
      origin_machine: om,
    });
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
      buildHome: () => buildHome(deps),
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
    //   ?agent=<identity_id>         filter by identity_id
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
      const roster = await buildUnwrapped(deps);
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
      const home = await buildHome(deps);
      writeJSON(res, 200, home);
      return true;
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

// The always-on posture surface (home board + per-panel endpoints + SSE push)
// composes several full-window audit reads per paint. Each helper below wraps its
// build in `AuditLog.runEagerReads` so those reads serve from the eagerly-
// maintained verified view with an EVENT-DRIVEN out-of-band fingerprint sentinel
// plus a throttled backstop re-verify, instead of a full chain re-scan per request.
// On a real 10k-entry / 40MB chain the old path
// was 11-30s and pegged the event loop, and the SSE cadence made an open board
// recompute it continuously and wedge the server (the #714 drill). HONESTY is
// preserved: the eager view reflects every server-written entry with NO lag (the
// server is the sole appender and verifies each entry as it appends), and the
// strict integrity-findings contract is unchanged, so `chain_verified` /
// `integrity_finding_count` / feature-health can never serve stale-green. The
// agent-facing `/api/posture/evidence` read (`buildEvidence`) deliberately stays
// on the full per-request re-verify path, keeping per-request on-disk tamper
// detection on the inspectable audit surface.
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
  preResolvedEnforcementAvailabilityStatus?: EnforcementAvailabilityStatusFile | null,
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
  const enforcementAvailabilityStatus =
    preResolvedEnforcementAvailabilityStatus !== undefined
      ? preResolvedEnforcementAvailabilityStatus
      : await resolveEnforcementAvailabilityStatus(deps);
  return (deps.auditLog as AuditLog).runEagerReads(() =>
    buildCastleWallPosture({
      auditLog: deps.auditLog as AuditLog,
      originMachine: deps.originMachine,
      ...(deps.platform !== undefined ? { platform: deps.platform } : {}),
      ...(deps.now ? { now: deps.now() } : {}),
      pinnedProducerKeyB64url: deps.resolvePinnedProducerKey
        ? deps.resolvePinnedProducerKey()
        : null,
      ...(deps.producerKeyExpectedButUnavailable
        ? { producerKeyExpectedButUnavailable: true }
        : {}),
      ...(exclusiveEgress !== null ? { exclusiveEgress } : {}),
      protectionClaimSubject,
      ...(enforcementAvailabilityStatus !== null
        ? { enforcementAvailabilityStatus }
        : {}),
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
      ...(deps.producerKeyExpectedButUnavailable
        ? { producerKeyExpectedButUnavailable: true }
        : {}),
    }),
  );
}

/**
 * Feature-usage health panel. NEVER-STALE-GREEN rule (the new honesty argument,
 * superseding the prior "uncached by design" note): the panel reads the audit
 * chain through `buildFeatureHealthPanel`, which goes via the AuditLog's EAGER
 * read path here (wrapped in `runEagerReads`). The eager view is maintained on
 * EVERY append (the server is the sole appender and verifies each new entry as it
 * records it), so the panel always reflects the current chain head with NO lag.
 * A post-fault refresh can never show stale green. This is NOT a lazily-cached
 * value that could fall behind an append: it is the eagerly-maintained verified
 * state, and a detected integrity finding (at load, on the next eager read via the
 * fingerprint sentinel, or on the throttled backstop out-of-band re-verify) forces
 * every row to `unknown`/non-green via the existing `audit_integrity_ok=false`
 * lever. What the eager path changes versus the old code is ONLY the cadence of the
 * OUT-OF-BAND on-disk re-scan (a direct file edit that bypasses the server): a
 * fingerprint-changing edit (count / newest key / per-entry size or mtime) is
 * caught EVENT-DRIVEN on the next eager read, and only the residual same-length,
 * mtime-preserved edit waits for the throttled backstop re-verify, instead of
 * re-verifying the whole chain on every paint (the #714 wedge).
 */
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
  preResolvedEnforcementAvailabilityStatus?: EnforcementAvailabilityStatusFile | null,
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
  const enforcementAvailabilityStatus =
    preResolvedEnforcementAvailabilityStatus !== undefined
      ? preResolvedEnforcementAvailabilityStatus
      : await resolveEnforcementAvailabilityStatus(deps);
  return (deps.auditLog as AuditLog).runEagerReads(() =>
    buildFeatureHealthPanel({
      auditLog: deps.auditLog as AuditLog,
      originMachine: deps.originMachine,
      // Surface the per-plugin attribution rows on the operator posture surface.
      // Read-only projection over the same audit read; never enforcement-bearing.
      includePluginRows: true,
      ...(exclusiveEgress !== null ? { exclusiveEgress } : {}),
      protectionClaimSubject,
      ...(enforcementAvailabilityStatus !== null
        ? { enforcementAvailabilityStatus }
        : {}),
      ...(deps.now ? { now: deps.now() } : {}),
      pinnedProducerKeyB64url: deps.resolvePinnedProducerKey
        ? deps.resolvePinnedProducerKey()
        : null,
      brokerPinnedProducerKeyB64url: deps.resolveBrokerPinnedProducerKey
        ? deps.resolveBrokerPinnedProducerKey()
        : null,
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
    // Eager read (posture surface): bounded-cost, throttled out-of-band re-verify.
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
 *   ?agent=<string>            - maps to query.identity_id
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
    identity_id: agentParam,
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

async function buildUnwrapped(deps: PostureRouteDeps): Promise<UnwrappedRoster> {
  const detected = deps.detectInstalledHarnesses
    ? await deps.detectInstalledHarnesses()
    : await scanInstalledHarnesses(deps.auditLog as AuditLog, deps.originMachine);
  return buildUnwrappedRoster({
    originMachine: deps.originMachine,
    wrappedAgents: deps.listAgents(),
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

async function buildHome(deps: PostureRouteDeps): Promise<PostureHome> {
  // S5-P (codex BLOCKER fix): resolve the exclusive-egress provider EXACTLY
  // ONCE for the whole home payload, then thread the SAME snapshot into both
  // the wall posture and the feature-health panel. Resolving per-builder would
  // let an intermittent provider cap one surface (wall pill) while the other
  // (feature-health row) still rendered green from a second, luckier read.
  const exclusiveEgress = await resolveExclusiveEgress(deps);
  const protectionClaimSubject = await resolveProtectionClaimSubject(deps);
  const enforcementAvailabilityStatus =
    await resolveEnforcementAvailabilityStatus(deps);
  const [castleWall, digest, unwrapped, featureHealth, custodyExit, federation] =
    await Promise.all([
      buildWallPosture(
        deps,
        exclusiveEgress,
        protectionClaimSubject,
        enforcementAvailabilityStatus,
      ),
      buildDigest(deps, protectionClaimSubject),
      buildUnwrapped(deps),
      buildFeatureHealth(
        deps,
        exclusiveEgress,
        protectionClaimSubject,
        enforcementAvailabilityStatus,
      ),
      buildCustodyExit(deps),
      buildFederationSummary(deps),
    ]);
  // Derive the honest agent rows from the roster ALONE. Deliberately not passed
  // the wall posture: there is no path by which the machine-level arm-state can
  // leak into a per-agent enforcement claim (the #634 fake-green).
  const agents = buildPostureAgentRows({
    originMachine: deps.originMachine,
    records: deps.listAgents(),
  });
  const protectionRequestedCount = agents.filter(
    (a) => a.policy_protected,
  ).length;
  const enforcementConfirmedCount = agents.filter(
    (a) => a.enforcement_active === "active",
  ).length;
  // Query-privacy depends on the feature-health panel (it carries the Tier B
  // `privacy_strips` row through verbatim), so it is computed after the parallel
  // block rather than inside it.
  const queryPrivacy = await buildQueryPrivacy(deps, featureHealth);
  return {
    origin_machine: deps.originMachine,
    federation,
    stream_available: deps.streamRegistry !== undefined,
    castle_wall: castleWall,
    digest,
    unwrapped,
    feature_health: featureHealth,
    custody_exit: custodyExit,
    query_privacy: queryPrivacy,
    protection_requested_count: protectionRequestedCount,
    enforcement_confirmed_count: enforcementConfirmedCount,
    agents,
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
