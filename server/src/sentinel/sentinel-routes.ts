/**
 * Sanctuary v1.3 WP-V1.3-1 Sentinel HTTP routes.
 *
 * Mounted under `/api/sentinels/*`. Every route runs through the
 * existing `authMiddleware` from `server/src/console/auth-middleware.ts`
 * so loopback auto-auth + bearer-token gating come from one shared
 * implementation. No new auth path is introduced.
 *
 * Routes:
 *   GET    /api/sentinels                        (catalog of available sentinels)
 *   GET    /api/sentinels/subscribed             (this fortress's subscriptions)
 *   POST   /api/sentinels/:sentinel_id/subscribe
 *   DELETE /api/sentinels/:sentinel_id/subscribe
 *   GET    /api/sentinels/findings               (read findings stream)
 *
 * No outbound network surface. Read-only against findings store +
 * registry; writes go through the dispatcher's audited subscribe
 * paths.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import type { SentinelDispatcher } from "./sentinel-dispatcher.js";
import type { SentinelSeverity } from "./types.js";

export const SENTINEL_API_PREFIX = "/api/sentinels";

export interface SentinelRouterDeps {
  authConfig: AuthConfig;
  dispatcher: SentinelDispatcher;
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

function matchSubscribeRoute(path: string): { sentinelId: string } | null {
  const prefix = `${SENTINEL_API_PREFIX}/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/subscribe")) return null;
  const sentinelId = rest.slice(0, rest.length - "/subscribe".length);
  if (sentinelId.length === 0) return null;
  return { sentinelId: decodeURIComponent(sentinelId) };
}

/**
 * Handle a request against the sentinel surface. Returns true when
 * served (including 4xx/5xx); returns false to let the caller
 * continue routing.
 */
export async function handleSentinelRoute(
  deps: SentinelRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== SENTINEL_API_PREFIX &&
    !path.startsWith(`${SENTINEL_API_PREFIX}/`)
  ) {
    return false;
  }

  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  const dispatcher = deps.dispatcher;
  const registry = dispatcher.getRegistry();
  const findingStore = dispatcher.getFindingStore();

  try {
    if (method === "GET" && path === SENTINEL_API_PREFIX) {
      const catalog = registry.listCatalog();
      writeJSON(res, 200, { ok: true, data: { catalog } });
      return true;
    }

    if (
      method === "GET" &&
      path === `${SENTINEL_API_PREFIX}/subscribed`
    ) {
      const subscribed = registry.listSubscribed();
      writeJSON(res, 200, { ok: true, data: { subscribed } });
      return true;
    }

    if (method === "GET" && path === `${SENTINEL_API_PREFIX}/findings`) {
      const limit = parseLimit(
        url.searchParams.get("limit"),
        FINDINGS_DEFAULT_LIMIT,
        FINDINGS_MAX_LIMIT,
      );
      const since = url.searchParams.get("since") ?? undefined;
      const severityRaw = url.searchParams.get("severity") ?? undefined;
      const sentinelIdFilter = url.searchParams.get("sentinel_id") ?? undefined;
      const agentIdFilter = url.searchParams.get("agent_id") ?? undefined;
      const severity =
        severityRaw && isSeverity(severityRaw) ? severityRaw : undefined;
      const findings = await findingStore.listFindings({
        limit,
        ...(since !== undefined ? { since } : {}),
        ...(severity !== undefined ? { severity } : {}),
        ...(sentinelIdFilter !== undefined
          ? { sentinelId: sentinelIdFilter }
          : {}),
        ...(agentIdFilter !== undefined ? { agentId: agentIdFilter } : {}),
      });
      writeJSON(res, 200, { ok: true, data: { findings } });
      return true;
    }

    const subscribeMatch = matchSubscribeRoute(path);
    if (subscribeMatch) {
      if (method === "POST") {
        try {
          await dispatcher.subscribeSentinel(subscribeMatch.sentinelId);
          writeJSON(res, 200, {
            ok: true,
            data: { sentinel_id: subscribeMatch.sentinelId, subscribed: true },
          });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (msg.startsWith("sentinel-registry: unknown sentinel")) {
            writeJSON(res, 404, { ok: false, error: "not_found" });
          } else {
            writeJSON(res, 500, { ok: false, error: "internal", detail: msg });
          }
        }
        return true;
      }
      if (method === "DELETE") {
        const removed = await dispatcher.unsubscribeSentinel(
          subscribeMatch.sentinelId,
        );
        writeJSON(res, 200, {
          ok: true,
          data: { sentinel_id: subscribeMatch.sentinelId, subscribed: false, removed },
        });
        return true;
      }
    }

    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    writeJSON(res, 500, { ok: false, error: "internal", detail: msg });
    return true;
  }
}
