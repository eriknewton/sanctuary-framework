/**
 * Sovereignty Posture Dashboard — Phase 1 route layer.
 *
 * Mounts the four gap endpoints (G1, G2, G4, G5) and the posture-home HTML
 * under `/api/posture/*` and `/posture`. The route layer is the IMPURE seam:
 * it gathers live dependencies (the audit log, the hub agent registry, a
 * config-file scan for installed harnesses, and the Castle Wall allowlist) and
 * delegates the actual shaping to the pure functions in `posture.ts`.
 *
 * Auth: every route here is dispatched only AFTER the dashboard's own
 * `checkAuth` gate has passed — the same gate `/api/audit-log` uses (binding
 * amendment: "do not invent a weaker gate"). The dashboard owns that check;
 * this module assumes the caller is authenticated.
 *
 * Endpoints:
 *   GET /api/posture/home        — one composed payload for the home screen.
 *   GET /api/posture/castle-wall — G4 (enforcement-evidenced arm state).
 *   GET /api/posture/digest      — G2 (today's audit story).
 *   GET /api/posture/unwrapped   — G1 (detected-but-unwrapped roster).
 *   GET /api/posture/reach/:id   — G5 (per-agent effective reach).
 *   GET /api/posture/custody-exit — Slice 3 (Custody + Exit panel).
 *   GET /posture                 — the posture home HTML.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { AuditLog } from "../operational/audit-log.js";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import { detectAgentConfigWithDiagnostics, getPlatformPaths } from "../wrap/config-reader.js";
import type { AgentPlatform } from "../wrap/config-reader.js";
import { CURATED_ALLOWLIST } from "../castle-wall/runtime/curated-allowlist.js";
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
  type PostureAgentRow,
  type CustodyExitPanel,
} from "./posture.js";
import {
  buildFeatureHealthPanel,
  type FeatureHealthPanel,
} from "./feature-health.js";
import { renderPostureHomeHTML } from "./posture-home-html.js";

export const POSTURE_API_PREFIX = "/api/posture";
export const POSTURE_HOME_PATH = "/posture";

/**
 * Dependencies the route layer needs from the dashboard. All are resolved
 * lazily per request (via closures) so post-unlock wiring is always observed —
 * mirrors the `buildV1AgentsDeps` pattern.
 */
export interface PostureRouteDeps {
  /** Encrypted audit log (already unlocked). */
  auditLog: AuditLog | null;
  /** Origin-machine attribution for `/v1`-compatible shapes. */
  originMachine: string;
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
   * honest channel-authenticated basis — never claimed as per-producer
   * authenticated. The dashboard MUST supply the same key the consumer wrote
   * with, never a weaker basis (Slice R, R-4).
   */
  resolvePinnedProducerKey?: () => string | null;
  /**
   * Slice P fail-honest signal: a producer key is EXPECTED for this fortress (the
   * daemon published one) but the dashboard could NOT load it (present but
   * unreadable / malformed). When true, the readers refuse to render green on the
   * channel basis — the wall posture forces `degraded`, the digest reports an
   * unverified chain, and feature-health rows render `unknown`. Mutually
   * exclusive with a non-null `resolvePinnedProducerKey()`.
   */
  producerKeyExpectedButUnavailable?: boolean;
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

  if (!path.startsWith(`${POSTURE_API_PREFIX}/`) && path !== POSTURE_API_PREFIX) {
    return false;
  }

  // Every error payload carries origin_machine too, so the `/v1`-compatible
  // shape constraint ("every payload") holds on the unhappy paths as well.
  const om = deps.originMachine;

  // Every JSON posture route needs the audit log to be unlocked. Without it we
  // cannot prove enforcement or count operations — fail closed to a 503 that
  // says so honestly (never an empty-but-green payload).
  if (deps.auditLog === null) {
    writeJSON(res, 503, {
      error: "posture_unavailable",
      reason: "audit log not unlocked; posture cannot be evidenced",
      origin_machine: om,
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

    // Within the posture namespace but no match — 404 here (do not fall
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
 * chain head, a post-fault refresh can never show stale green — there is no
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
 * Custody & Exit panel (Slice 3). Read-only over the audit chain the dashboard
 * already reads: it surfaces NEGATIVE custody evidence (pin-custody mismatch /
 * suspected-rollback freeze) and custody-establishment provenance, plus the
 * honest CLI-gated exit-export capability. It never re-derives custody HEALTH
 * (that lives under the transient master at boot), so the custody tile is never
 * green — amber unconfirmed or red damaged only.
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
    : curatedReachRules();
  return buildAgentReach({
    originMachine: deps.originMachine,
    agentId,
    harness: agent.harness,
    rules,
  });
}

export interface PostureHome {
  origin_machine: string;
  castle_wall: CastleWallPosture;
  digest: AuditDigest;
  unwrapped: UnwrappedRoster;
  /** Per-feature usage health (evidence-based; unknown when unconfirmed). */
  feature_health: FeatureHealthPanel;
  /**
   * Custody & Exit posture (Slice 3). Custody is never green (amber unconfirmed
   * or red damaged); exit is the honest CLI-gated export capability without a
   * clean-exit guarantee.
   */
  custody_exit: CustodyExitPanel;
  /**
   * Count of agents the operator has REQUESTED protection for (policy intent).
   * This is the honest banner number: it counts policy_protected, NOT confirmed
   * enforcement. Renamed in intent from the old flat "protected" count, which
   * implied enforcement it could not prove (#634 fake-green fix).
   */
  protection_requested_count: number;
  /**
   * Count of agents with CONFIRMED live enforcement (`enforcement_active ===
   * "active"`). `0` today: no per-agent enforcement signal exists yet, so the
   * banner never overstates confirmed enforcement.
   */
  enforcement_confirmed_count: number;
  /**
   * Derived agent rows carrying the honest policy-vs-enforcement split (#634).
   * Replaces the raw `LocalAgentRecord[]`: the UI must render green only on
   * confirmed enforcement, amber on policy-only protection.
   */
  agents: PostureAgentRow[];
}

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
  return {
    origin_machine: deps.originMachine,
    castle_wall: castleWall,
    digest,
    unwrapped,
    feature_health: featureHealth,
    custody_exit: custodyExit,
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
 * Phase 1 reach rules from the curated allowlist. Every curated entry is a
 * Castle Wall (kernel-enforced) rule. When a daemon-sourced live manifest
 * becomes readable from the dashboard, this becomes the live ruleset with the
 * same shape.
 */
function curatedReachRules(): ReachRule[] {
  return CURATED_ALLOWLIST.map((entry) => {
    const rule: ReachRule = {
      rule_id: entry.rule.id,
      disposition: entry.rule.disposition,
      enforcing_layer: "castle_wall",
    };
    const match = entry.rule.match;
    if (match.host !== undefined) rule.host = match.host;
    if (match.host_pattern !== undefined) rule.host_pattern = match.host_pattern;
    if (match.ip !== undefined) rule.ip = match.ip;
    if (match.cidr !== undefined) rule.cidr = match.cidr;
    if (entry.rule.scope?.agent_ids !== undefined) {
      rule.agent_ids = entry.rule.scope.agent_ids;
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
