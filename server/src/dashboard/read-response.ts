import type { IncomingMessage, ServerResponse } from "node:http";

export type DashboardBoundedReadRoute =
  | "unified_inbox_prefs"
  | "posture_home"
  | "sovereignty";

interface DashboardReadResponse<T> {
  status: number;
  body: T;
}

interface DashboardBoundedReadOptions<T> {
  route: DashboardBoundedReadRoute;
  req: IncomingMessage;
  res: ServerResponse;
  operation: string;
  produce: (signal: AbortSignal) => Promise<DashboardReadResponse<T>>;
}

const MILLISECONDS_PER_SECOND = 1000;
const DASHBOARD_CLIENT_READ_DEADLINE_SECONDS = 5;
// Must match DASHBOARD_READ_DEADLINE_MS in server/src/dashboard/v1_1/client.ts.
export const DASHBOARD_CLIENT_READ_DEADLINE_MS =
  DASHBOARD_CLIENT_READ_DEADLINE_SECONDS * MILLISECONDS_PER_SECOND;
const DASHBOARD_RESPONSE_FLUSH_HEADROOM_SECONDS = 1;
// One second remains for the browser to receive the explicit 503 before its own read abort fires.
const DASHBOARD_RESPONSE_FLUSH_HEADROOM_MS =
  DASHBOARD_RESPONSE_FLUSH_HEADROOM_SECONDS * MILLISECONDS_PER_SECOND;
export const DASHBOARD_READ_RESPONSE_DEADLINE_MS =
  DASHBOARD_CLIENT_READ_DEADLINE_MS - DASHBOARD_RESPONSE_FLUSH_HEADROOM_MS;
const HTTP_SERVICE_UNAVAILABLE = 503;
const DASHBOARD_READ_ROUTE_IN_FLIGHT_CAP = 1;
const DASHBOARD_RETRY_AFTER_SECONDS = 1;
const inFlightByRoute = new Map<DashboardBoundedReadRoute, number>();

function unavailableBody(route: DashboardBoundedReadRoute, reason: string): {
  ok: false;
  error: "dashboard_read_unavailable";
  route: DashboardBoundedReadRoute;
  reason: string;
} {
  return {
    ok: false,
    error: "dashboard_read_unavailable",
    route,
    reason,
  };
}

function writeJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    Connection: "close",
  });
  res.end(JSON.stringify(payload));
}

function incrementInFlight(route: DashboardBoundedReadRoute): boolean {
  const current = inFlightByRoute.get(route) ?? 0;
  if (current >= DASHBOARD_READ_ROUTE_IN_FLIGHT_CAP) return false;
  inFlightByRoute.set(route, current + 1);
  return true;
}

function decrementInFlight(route: DashboardBoundedReadRoute): void {
  const current = inFlightByRoute.get(route) ?? 0;
  if (current <= DASHBOARD_READ_ROUTE_IN_FLIGHT_CAP) {
    inFlightByRoute.delete(route);
    return;
  }
  inFlightByRoute.set(route, current - 1);
}

export function getDashboardReadInFlightCount(
  route: DashboardBoundedReadRoute,
): number {
  return inFlightByRoute.get(route) ?? 0;
}

export function resetDashboardReadInFlightForTests(): void {
  inFlightByRoute.clear();
}

/**
 * Bound dashboard read routes that compose storage, audit, producer-key, or
 * posture evidence reads. The wrapper owns the HTTP response: success returns
 * the route's normal payload, while timeout/cap pressure returns explicit
 * unavailable so the client marks the source FAILED rather than rendering
 * fabricated empty or healthy data.
 */
export function respondWithBoundedDashboardRead<T>(
  options: DashboardBoundedReadOptions<T>,
): Promise<boolean> {
  const { route, req, res, produce } = options;
  if (!incrementInFlight(route)) {
    res.setHeader("Retry-After", String(DASHBOARD_RETRY_AFTER_SECONDS));
    // Invariant: over-cap means there is already a live read whose truth is unknown; refusal is safer than zero rows or green posture.
    writeJson(res, HTTP_SERVICE_UNAVAILABLE, unavailableBody(route, "in_flight_limit"));
    return Promise.resolve(true);
  }

  const controller = new AbortController();
  let responseSettled = false;
  let producerSettled = false;
  let timeout: ReturnType<typeof setTimeout> | null = null;
  let resolveHandled: (handled: boolean) => void = () => undefined;
  const handled = new Promise<boolean>((resolve) => {
    resolveHandled = resolve;
  });

  const cleanupResponseListeners = (): void => {
    req.off?.("aborted", abortForClosedRequest);
    res.off?.("close", abortForClosedRequest);
  };
  const settleResponse = (status: number, body: unknown): void => {
    if (responseSettled) return;
    responseSettled = true;
    if (timeout) clearTimeout(timeout);
    cleanupResponseListeners();
    if (!res.headersSent && !res.writableEnded) {
      writeJson(res, status, body);
    }
    resolveHandled(true);
  };
  const abortForClosedRequest = (): void => {
    if (!producerSettled) controller.abort();
  };

  req.once?.("aborted", abortForClosedRequest);
  res.once?.("close", abortForClosedRequest);
  timeout = setTimeout(() => {
    controller.abort();
    // Invariant: an overdue evidence read has unknown truth; unavailable is the only honest payload the SPA will fail closed on.
    settleResponse(HTTP_SERVICE_UNAVAILABLE, unavailableBody(route, "deadline_exceeded"));
  }, DASHBOARD_READ_RESPONSE_DEADLINE_MS);

  void produce(controller.signal)
    .then(({ status, body }) => {
      settleResponse(status, body);
    })
    .catch(() => {
      // Invariant: a failed composition cannot be converted to an empty dashboard shape, because empty can mean healthy to the operator.
      settleResponse(HTTP_SERVICE_UNAVAILABLE, unavailableBody(route, "composition_failed"));
    })
    .finally(() => {
      producerSettled = true;
      decrementInFlight(route);
    });

  return handled;
}
