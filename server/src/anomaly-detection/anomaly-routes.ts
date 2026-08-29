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
import type { AnomalyClassifier, AnomalyContext } from "./types.js";
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

  // DEFAULT-DENY on mutation (invariant 7, co-resident-agent threat): any
  // non-GET method requires the operator bearer (`requireToken: true`), which
  // suppresses the loopback auto-auth shortcut so a co-resident agent sharing
  // loopback cannot register/remove detector subscriptions by network position
  // alone. The only non-GET routes here are `POST`/`DELETE
  // /api/anomaly/:detector_id/subscribe`, which mutate the live dispatcher
  // (registerDetector / addClassifierToDetector / unregisterDetector /
  // removeClassifierFromDetector) — both are genuine mutations, so there is no
  // read-style exemption. This mirrors the per-router default-deny the other
  // v1.1 routers use (`intelligence-api-router.ts`, the PII Tier-B router),
  // replacing the prior flat `authMiddleware(authConfig)` that let loopback
  // auto-auth release the subscribe/unsubscribe mutations.
  const requiresOperatorBearer = method !== "GET";
  const checkAuth = authMiddleware(
    deps.authConfig,
    requiresOperatorBearer ? { requireToken: true } : undefined,
  );
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
        // Refusal invariant: a refused or failed subscribe leaves the
        // dispatcher's detector list exactly as it was. Enforced by
        // ordering, not compensation: every input read and classifier
        // construction that can refuse or throw completes BEFORE the
        // first dispatcher mutation, so there is never partial state to
        // undo (register id: ic-sweep-auto-trigger-thresholds-consumed).
        try {
          // The already-live decision reads through the dispatcher's
          // settled-state chokepoint: it joins the detector's mutation
          // chain, so an in-flight teardown or attach completes before
          // this snapshot is taken and `subscribed: true` is never
          // reported from a mid-mutation registry state (register id:
          // ic-sweep-auto-trigger-thresholds-consumed).
          const preSubscribeClassifierIds =
            await deps.dispatcher.getSettledDetectorClassifiers(
              entry.detectorId,
            );
          if (preSubscribeClassifierIds.includes(entry.classifierId)) {
            // Idempotent re-subscribe: already live, nothing to mutate.
            writeJSON(res, 200, {
              ok: true,
              data: {
                detector_id: entry.detectorId,
                classifier_id: entry.classifierId,
                subscribed: true,
                subscribed_classifiers: preSubscribeClassifierIds,
              },
            });
            return true;
          }
          const detectorLive = preSubscribeClassifierIds.length > 0;
          if (detectorLive && !entry.classifierFactory) {
            // A live detector can gain the requested classifier only
            // through the entry's classifierFactory; without one the
            // subscribe is refused before any mutation.
            writeJSON(res, 409, {
              ok: false,
              error: "classifier_not_attachable",
            });
            return true;
          }
          // Construct the requested classifier before registering
          // anything: the catalog's classifierFactory is the fallible
          // step (it reads the operator's persisted threshold overrides
          // and refuses an unsupported or unreadable row), so a throw
          // here reaches the catch below with the detector list
          // untouched.
          let prevalidatedClassifier: AnomalyClassifier | undefined;
          if (entry.classifierFactory) {
            const context: AnomalyContext = {
              fortressId: deps.fortressId,
              auditLog: deps.auditLog,
              storage: deps.storage,
              masterKey: deps.masterKey,
              now: deps.now ?? (() => new Date()),
            };
            prevalidatedClassifier = await entry.classifierFactory(context);
          }
          // Every fallible input read and construction has succeeded;
          // mutations start here. An entry without a classifierFactory
          // names its detector's own primary classifier (catalog
          // contract), so the fresh registration below attaches the
          // requested classifier itself. registerDetector is idempotent,
          // so a concurrent subscribe racing this one keeps the winner's
          // live registration.
          if (!detectorLive) {
            await deps.dispatcher.registerDetector(entry.factory());
          }
          if (prevalidatedClassifier !== undefined) {
            // The factory handed to the dispatcher returns the instance
            // validated above, so the attach step itself has no remaining
            // input read that can throw.
            const classifierInstance = prevalidatedClassifier;
            const attached = await deps.dispatcher.addClassifierToDetector(
              entry.detectorId,
              () => classifierInstance,
            );
            if (!attached) {
              // `subscribed: true` is only reported for a classifier that
              // is verifiably live on the detector, so a declined attach
              // is resolved against settled dispatcher state instead of
              // being assumed successful (register id:
              // ic-sweep-auto-trigger-thresholds-consumed).
              const liveClassifierIds =
                await deps.dispatcher.getSettledDetectorClassifiers(
                  entry.detectorId,
                );
              if (liveClassifierIds.includes(entry.classifierId)) {
                // The requested classifier is live (a concurrent subscribe
                // attached it): the same idempotent-200 shape as the
                // pre-mutation already-live path above.
                writeJSON(res, 200, {
                  ok: true,
                  data: {
                    detector_id: entry.detectorId,
                    classifier_id: entry.classifierId,
                    subscribed: true,
                    subscribed_classifiers: liveClassifierIds,
                  },
                });
                return true;
              }
              // Not live and not attached. Every registered detector
              // carries at least its primary classifier, so an empty list
              // means the detector holds no live registration (e.g. a
              // concurrent unsubscribe removed it); a non-empty list means
              // the live detector declined the attach. Both are live-state
              // conflicts, refused with this route's 409 convention.
              writeJSON(res, 409, {
                ok: false,
                error:
                  liveClassifierIds.length === 0
                    ? "detector_not_subscribed"
                    : "classifier_not_attachable",
              });
              return true;
            }
          }
          const classifierIds = deps.dispatcher.listDetectorClassifiers(
            entry.detectorId,
          );
          writeJSON(res, 200, {
            ok: true,
            data: {
              detector_id: entry.detectorId,
              classifier_id: entry.classifierId,
              subscribed: classifierIds.includes(entry.classifierId),
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
        // Decision and mutation are ONE atomic dispatcher operation:
        // the primary/dependents policy fires on the same registry
        // state the selected mutation applies to, including state
        // committed by operations queued ahead of this one (register
        // id: ic-sweep-auto-trigger-thresholds-consumed). This route
        // only translates the outcome into its response shapes.
        const detachOutcome =
          await deps.dispatcher.removeClassifierOrUnregisterDetector(
            entry.detectorId,
            entry.classifierId,
          );
        if (detachOutcome.outcome === "primary_has_dependents") {
          writeJSON(res, 409, {
            ok: false,
            error: "primary_classifier_has_dependents",
          });
          return true;
        }
        const removed =
          detachOutcome.outcome === "not_subscribed"
            ? false
            : detachOutcome.removed;
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
