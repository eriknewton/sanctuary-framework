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
 *   GET /posture                 - the posture home HTML.
 *   GET /posture/agent/:id       - the per-agent drill-down HTML (Slice 4).
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
  PLATFORM_TO_HARNESS,
  type DetectedHarness,
  type ReachRule,
  type CastleWallPosture,
  type AuditDigest,
  type UnwrappedRoster,
  type AgentEffectiveReach,
  type CustodyExitPanel,
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
import { renderPostureHomeHTML } from "./posture-home-html.js";
import { renderPostureAgentHTML } from "./posture-agent-html.js";
import {
  handlePostureStream,
  type PostureStreamRegistry,
} from "./posture-stream.js";
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
  /** Live wrapped-agent roster from the hub registry. */
  listAgents: () => LocalAgentRecord[];
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

  // Posture home HTML.
  if (method === "GET" && path === POSTURE_HOME_PATH) {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(renderPostureHomeHTML());
    return true;
  }

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

    if (method === "GET" && path === `${POSTURE_API_PREFIX}/unwrapped`) {
      const roster = await buildUnwrapped(deps);
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

async function buildWallPosture(deps: PostureRouteDeps): Promise<CastleWallPosture> {
  return buildCastleWallPosture({
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
  });
}

async function buildDigest(deps: PostureRouteDeps): Promise<AuditDigest> {
  return buildAuditDigest({
    auditLog: deps.auditLog as AuditLog,
    originMachine: deps.originMachine,
    ...(deps.now ? { now: deps.now() } : {}),
    pinnedProducerKeyB64url: deps.resolvePinnedProducerKey
      ? deps.resolvePinnedProducerKey()
      : null,
    ...(deps.producerKeyExpectedButUnavailable
      ? { producerKeyExpectedButUnavailable: true }
      : {}),
  });
}

/**
 * Feature-usage health panel. Cache-invalidation rule (review must-fix #4): the
 * panel is recomputed from the audit chain on every request via
 * `buildFeatureHealthPanel`, which reads `AuditLog.query` fresh and re-scans for
 * integrity findings each call. Because each response reflects the current
 * chain head, a post-fault refresh can never show stale green - there is no
 * cross-request cache to invalidate at this layer.
 */
async function buildFeatureHealth(
  deps: PostureRouteDeps,
): Promise<FeatureHealthPanel> {
  return buildFeatureHealthPanel({
    auditLog: deps.auditLog as AuditLog,
    originMachine: deps.originMachine,
    ...(deps.now ? { now: deps.now() } : {}),
    pinnedProducerKeyB64url: deps.resolvePinnedProducerKey
      ? deps.resolvePinnedProducerKey()
      : null,
    ...(deps.producerKeyExpectedButUnavailable
      ? { producerKeyExpectedButUnavailable: true }
      : {}),
  });
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
    const computed = await computeQueryAnonymityStats({
      auditLog: deps.auditLog as AuditLog,
      ...(deps.now ? { now: () => new Date(deps.now!()) } : {}),
    });
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
  return buildCustodyExitPanel({
    auditLog: deps.auditLog as AuditLog,
    originMachine: deps.originMachine,
    ...(deps.now ? { now: deps.now() } : {}),
  });
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
  const [castleWall, digest, unwrapped, featureHealth, custodyExit] =
    await Promise.all([
      buildWallPosture(deps),
      buildDigest(deps),
      buildUnwrapped(deps),
      buildFeatureHealth(deps),
      buildCustodyExit(deps),
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
