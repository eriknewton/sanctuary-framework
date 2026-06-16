/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-3 Anomaly Detection HTTP routes.
 *
 * Mounted under `/api/anomaly/*`. Mirrors the Phi-1 sentinel-routes
 * pattern: every route runs through the existing `authMiddleware`
 * so loopback auto-auth + bearer-token gating come from one shared
 * implementation. No new auth path.
 *
 * Routes shipped in Chi-3:
 *
 *   GET    /api/anomaly/detectors
 *       Catalog of available detector + classifier combinations.
 *
 *   GET    /api/anomaly/subscribed
 *       Detector IDs the fortress has subscribed.
 *
 *   POST   /api/anomaly/:detector_id/subscribe?classifier=<id>
 *       Subscribe a catalog entry.
 *
 *   DELETE /api/anomaly/:detector_id/subscribe?classifier=<id>
 *       Unsubscribe.
 *
 *   GET    /api/anomaly/findings?since=...&severity=...&detector_id=...
 *       Read anomaly findings. Filters down to sentinel_id starting
 *       with the ANOMALY_SENTINEL_ID_PREFIX (so the rule-based Phi-1
 *       findings stay in the Sentinels view; anomaly findings stay
 *       in this view).
 *
 *   GET    /api/anomaly/findings/:finding_id
 *       Full detail of a single finding (drift-inspector payload:
 *       per-feature contributions, observed vs baseline mean / stddev,
 *       z-scores). Also emits the
 *       `operator_anomaly_finding_drilled` audit event.
 *
 *   GET    /api/anomaly/classifier-state?detector_id=...&classifier_id=...
 *       Per-agent classifier state snapshot (training count, last
 *       saved-at, baseline freshness). Powers the training-state view.
 *
 * The Chi-3 spawn prompt also called for an SSE
 * `/api/anomaly/findings/stream` route. That ships in a follow-up
 * once the SPA hooks up a panel that consumes it; the dispatcher
 * already exposes `onEvent` for the listener-side, so plumbing
 * through HTTP-SSE is mechanical when the SPA is ready. Documented
 * in the PR drift flags.
 *
 * Castle-walking: no new outbound surface; read-only against finding
 * store + dispatcher registry + classifier state store. Audit
 * emission via existing pipeline.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type { SentinelSeverity } from "../sentinel/types.js";
import type { AnomalyPipelineDispatcher } from "./anomaly-pipeline.js";
import {
  ANOMALY_CATALOG,
  findCatalogEntry,
  type AnomalyCatalogEntry,
} from "./anomaly-catalog.js";
import { ANOMALY_SENTINEL_ID_PREFIX } from "./types.js";
import { ClassifierStateStore } from "./classifier-state-store.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import { sendCaughtError } from "../http/error-envelope.js";

export const ANOMALY_API_PREFIX = "/api/anomaly";

export const ANOMALY_UX_AUDIT_OPS = {
  VIEW_OPENED: "operator_anomaly_view_opened",
  FINDING_DRILLED: "operator_anomaly_finding_drilled",
} as const;

export type AnomalyUxAuditOp =
  (typeof ANOMALY_UX_AUDIT_OPS)[keyof typeof ANOMALY_UX_AUDIT_OPS];

export interface AnomalyRouterDeps {
  authConfig: AuthConfig;
  dispatcher: AnomalyPipelineDispatcher;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  identityId: string;
  /** Storage backend + master key for classifier-state lookups. */
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
}

const FINDINGS_DEFAULT_LIMIT = 100;
const FINDINGS_MAX_LIMIT = 500;

function writeJSON(
  res: ServerResponse,
  status: number,
  payload: unknown,
): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function isSeverity(value: string): value is SentinelSeverity {
  return value === "info" || value === "warn" || value === "alert";
}

function parseLimit(
  raw: string | null,
  defaultValue: number,
  max: number,
): number {
  if (raw === null || raw === "") return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) return defaultValue;
  return Math.min(parsed, max);
}

function matchSubscribeRoute(path: string): { detectorId: string } | null {
  const prefix = `${ANOMALY_API_PREFIX}/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/subscribe")) return null;
  const detectorId = rest.slice(0, rest.length - "/subscribe".length);
  if (detectorId.length === 0) return null;
  if (detectorId.includes("/")) return null;
  return { detectorId: decodeURIComponent(detectorId) };
}

function matchFindingDetailRoute(
  path: string,
): { findingId: string } | null {
  const prefix = `${ANOMALY_API_PREFIX}/findings/`;
  if (!path.startsWith(prefix)) return null;
  const findingId = path.slice(prefix.length);
  if (findingId.length === 0) return null;
  if (findingId === "stream") return null;
  if (findingId.includes("/")) return null;
  return { findingId: decodeURIComponent(findingId) };
}

function catalogView(entry: AnomalyCatalogEntry): {
  detector_id: string;
  classifier_id: string;
  description: string;
} {
  return {
    detector_id: entry.detectorId,
    classifier_id: entry.classifierId,
    description: entry.description,
  };
}

/**
 * Handle a request against the anomaly surface. Returns true when
 * served (including 4xx/5xx); returns false to let the caller
 * continue routing.
 */
export async function handleAnomalyRoute(
  deps: AnomalyRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== ANOMALY_API_PREFIX &&
    !path.startsWith(`${ANOMALY_API_PREFIX}/`)
  ) {
    return false;
  }

  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  const now = (deps.now ?? (() => new Date()))();

  try {
    if (method === "GET" && path === `${ANOMALY_API_PREFIX}/detectors`) {
      void deps.auditLog.append(
        "l2",
        ANOMALY_UX_AUDIT_OPS.VIEW_OPENED,
        deps.identityId,
        { fortress_id: deps.fortressId, opened_at: now.toISOString() },
      );
      const catalog = ANOMALY_CATALOG.map(catalogView);
      writeJSON(res, 200, { ok: true, data: { catalog } });
      return true;
    }

    if (method === "GET" && path === `${ANOMALY_API_PREFIX}/subscribed`) {
      const subscribed = deps.dispatcher.listDetectors();
      const tuples = subscribed.flatMap((detectorId) =>
        deps.dispatcher.listDetectorClassifiers(detectorId).map((classifierId) => ({
          detector_id: detectorId,
          classifier_id: classifierId,
        })),
      );
      writeJSON(res, 200, { ok: true, data: { subscribed, tuples } });
      return true;
    }

    if (method === "GET" && path === `${ANOMALY_API_PREFIX}/findings`) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        FINDINGS_DEFAULT_LIMIT,
        FINDINGS_MAX_LIMIT,
      );
      const since = url.searchParams.get("since") ?? undefined;
      const severityRaw = url.searchParams.get("severity") ?? undefined;
      const detectorIdFilter =
        url.searchParams.get("detector_id") ?? undefined;
      const agentIdFilter = url.searchParams.get("agent_id") ?? undefined;
      const severity =
        severityRaw && isSeverity(severityRaw) ? severityRaw : undefined;
      const sentinelIdFilter =
        detectorIdFilter !== undefined
          ? `${ANOMALY_SENTINEL_ID_PREFIX}${detectorIdFilter}`
          : undefined;
      const findings = await deps.findingStore.listFindings({
        limit,
        ...(since !== undefined ? { since } : {}),
        ...(severity !== undefined ? { severity } : {}),
        ...(sentinelIdFilter !== undefined
          ? { sentinelId: sentinelIdFilter }
          : {}),
        ...(agentIdFilter !== undefined ? { agentId: agentIdFilter } : {}),
      });
      // When no detector filter is supplied, narrow to anomaly:* prefix
      // so this view does not surface rule-based Phi-1 sentinel findings.
      const filtered =
        sentinelIdFilter !== undefined
          ? findings
          : findings.filter((f) =>
              f.sentinel_id.startsWith(ANOMALY_SENTINEL_ID_PREFIX),
            );
      writeJSON(res, 200, { ok: true, data: { findings: filtered } });
      return true;
    }

    if (method === "GET" && path === `${ANOMALY_API_PREFIX}/classifier-state`) {
      const detectorId = url.searchParams.get("detector_id") ?? "";
      const classifierId = url.searchParams.get("classifier_id") ?? "";
      if (!detectorId || !classifierId) {
        writeJSON(res, 400, {
          ok: false,
          error: "missing_query_param",
          detail: "detector_id and classifier_id are required",
        });
        return true;
      }
      const entry = findCatalogEntry(detectorId, classifierId);
      if (!entry) {
        writeJSON(res, 404, { ok: false, error: "unknown_detector_classifier" });
        return true;
      }
      const stateStore = new ClassifierStateStore({
        storage: deps.storage,
        masterKey: deps.masterKey,
        fortressId: deps.fortressId,
        ...(deps.now !== undefined ? { now: deps.now } : {}),
      });
      const agentIds = await stateStore.listAgents(classifierId);
      const states: Array<{
        agent_id: string;
        sample_count: number | null;
      }> = [];
      for (const agentId of agentIds) {
        try {
          const raw = await stateStore.loadState<{
            sample_count?: number;
          }>(classifierId, agentId);
          if (raw !== null) {
            states.push({
              agent_id: agentId,
              sample_count:
                typeof raw.sample_count === "number" ? raw.sample_count : null,
            });
          }
        } catch {
          states.push({ agent_id: agentId, sample_count: null });
        }
      }
      writeJSON(res, 200, {
        ok: true,
        data: {
          detector_id: detectorId,
          classifier_id: classifierId,
          agent_count: states.length,
          per_agent: states,
        },
      });
      return true;
    }

    const detailMatch = matchFindingDetailRoute(path);
    if (detailMatch && method === "GET") {
      const finding = await deps.findingStore.loadFinding(
        detailMatch.findingId,
      );
      if (!finding) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      if (!finding.sentinel_id.startsWith(ANOMALY_SENTINEL_ID_PREFIX)) {
        // Belongs to the Phi-1 sentinel surface; refuse to drill from
        // the anomaly view so the Sentinels-view + Anomaly-view stay
        // operator-distinct.
        writeJSON(res, 404, {
          ok: false,
          error: "not_an_anomaly_finding",
        });
        return true;
      }
      void deps.auditLog.append(
        "l2",
        ANOMALY_UX_AUDIT_OPS.FINDING_DRILLED,
        deps.identityId,
        {
          finding_id: finding.finding_id,
          detector_id:
            (finding.details["detector_id"] as string | undefined) ?? null,
          classifier_id:
            (finding.details["classifier_id"] as string | undefined) ?? null,
          severity: finding.severity,
          fortress_id: deps.fortressId,
        },
      );
      writeJSON(res, 200, { ok: true, data: { finding } });
      return true;
    }

    const subscribeMatch = matchSubscribeRoute(path);
    if (subscribeMatch) {
      const classifierIdQuery =
        url.searchParams.get("classifier") ??
        url.searchParams.get("classifier_id");
      if (!classifierIdQuery) {
        writeJSON(res, 400, {
          ok: false,
          error: "missing_query_param",
          detail: "classifier query param is required",
        });
        return true;
      }
      const entry = findCatalogEntry(subscribeMatch.detectorId, classifierIdQuery);
      if (!entry) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      if (method === "POST") {
        try {
          let classifierIds = deps.dispatcher.listDetectorClassifiers(entry.detectorId);
          if (classifierIds.length === 0) {
            await deps.dispatcher.registerDetector(entry.factory());
            classifierIds = deps.dispatcher.listDetectorClassifiers(entry.detectorId);
          }
          if (!classifierIds.includes(entry.classifierId)) {
            if (!entry.classifierFactory) {
              writeJSON(res, 409, {
                ok: false,
                error: "classifier_not_attachable",
              });
              return true;
            }
            await deps.dispatcher.addClassifierToDetector(
              entry.detectorId,
              entry.classifierFactory,
            );
            classifierIds = deps.dispatcher.listDetectorClassifiers(entry.detectorId);
          }
          writeJSON(res, 200, {
            ok: true,
            data: {
              detector_id: entry.detectorId,
              classifier_id: entry.classifierId,
              subscribed: true,
              subscribed_classifiers: classifierIds,
            },
          });
        } catch (err) {
          sendCaughtError(res, 500, "internal_error", err, {
            route: "anomaly",
            operation: "subscribe",
          });
        }
        return true;
      }
      if (method === "DELETE") {
        const classifierIds = deps.dispatcher.listDetectorClassifiers(entry.detectorId);
        let removed = false;
        if (classifierIds.includes(entry.classifierId)) {
          const primaryClassifierId = classifierIds[0];
          if (entry.classifierId === primaryClassifierId) {
            if (classifierIds.length > 1) {
              writeJSON(res, 409, {
                ok: false,
                error: "primary_classifier_has_dependents",
              });
              return true;
            }
            removed = await deps.dispatcher.unregisterDetector(entry.detectorId);
          } else {
            removed = await deps.dispatcher.removeClassifierFromDetector(
              entry.detectorId,
              entry.classifierId,
            );
          }
        }
        writeJSON(res, 200, {
          ok: true,
          data: {
            detector_id: entry.detectorId,
            classifier_id: entry.classifierId,
            subscribed: deps.dispatcher
              .listDetectorClassifiers(entry.detectorId)
              .includes(entry.classifierId),
            removed,
          },
        });
        return true;
      }
    }

    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    sendCaughtError(res, 500, "internal_error", err, {
      route: "anomaly",
      operation: `${method} ${path}`,
    });
    return true;
  }
}
