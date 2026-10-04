import type { IncomingMessage, ServerResponse } from "node:http";

import { logCaughtError } from "../http/error-envelope.js";

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
  readFlights?: DashboardReadFlightMap;
  originMachine?: string;
}

export interface DashboardReadFlight<T> {
  promise: Promise<DashboardReadResponse<T>>;
  deadlineAtMs: number;
}

export type DashboardReadFlightMap = Map<
  DashboardBoundedReadRoute,
  DashboardReadFlight<unknown>
>;

// Definition: JavaScript timers and Date.now() use milliseconds, while HTTP Retry-After uses seconds.
export const DASHBOARD_MILLISECONDS_PER_SECOND = 1000;
export const DASHBOARD_CLIENT_READ_DEADLINE_SECONDS = 5;
// Must match DASHBOARD_READ_DEADLINE_MS in server/src/dashboard/v1_1/client.ts.
export const DASHBOARD_CLIENT_READ_DEADLINE_MS =
  DASHBOARD_CLIENT_READ_DEADLINE_SECONDS * DASHBOARD_MILLISECONDS_PER_SECOND;
const DASHBOARD_RESPONSE_FLUSH_HEADROOM_SECONDS = 1;
// One second remains for the browser to receive the explicit 503 before its own read abort fires.
const DASHBOARD_RESPONSE_FLUSH_HEADROOM_MS =
  DASHBOARD_RESPONSE_FLUSH_HEADROOM_SECONDS * DASHBOARD_MILLISECONDS_PER_SECOND;
export const DASHBOARD_READ_RESPONSE_DEADLINE_MS =
  DASHBOARD_CLIENT_READ_DEADLINE_MS - DASHBOARD_RESPONSE_FLUSH_HEADROOM_MS;
const HTTP_SERVICE_UNAVAILABLE = 503;
// Rule 12 admission: one producer per route is the complete cap; followers join that producer until it is overdue.
export const DASHBOARD_READ_ROUTE_SINGLE_FLIGHT_CAP = 1;
// Retry-After equals the reserved response-flush headroom, rounded to the HTTP header's integer seconds.
export const DASHBOARD_RETRY_AFTER_SECONDS = Math.ceil(
  DASHBOARD_RESPONSE_FLUSH_HEADROOM_MS / DASHBOARD_MILLISECONDS_PER_SECOND,
);
const inFlightByRoute = createDashboardReadFlightMap();

export function createDashboardReadFlightMap(): DashboardReadFlightMap {
  return new Map<DashboardBoundedReadRoute, DashboardReadFlight<unknown>>();
}

function unavailableBody(route: DashboardBoundedReadRoute, reason: string): {
  ok: false;
  error: "dashboard_read_unavailable";
  route: DashboardBoundedReadRoute;
  reason: string;
} & { origin_machine?: string } {
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
  });
  res.end(JSON.stringify(payload));
}

function logDashboardReadFailure(
  route: DashboardBoundedReadRoute,
  operation: string,
  reason: "deadline_exceeded" | "composition_failed",
): void {
  logCaughtError(new Error(reason), { route, operation }, {
    status: HTTP_SERVICE_UNAVAILABLE,
    publicCode: "service_unavailable",
  });
}

export function getDashboardReadInFlightCount(
  route: DashboardBoundedReadRoute,
  readFlights: DashboardReadFlightMap = inFlightByRoute,
): number {
  return readFlights.has(route) ? DASHBOARD_READ_ROUTE_SINGLE_FLIGHT_CAP : 0;
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
 *
 * No current producer honors the AbortSignal: storage, audit, custody, posture,
 * and sovereignty reads keep running after a caller deadline or disconnect.
 * The signal is a future handoff only; aborting here stops that caller's
 * response path, not the shared read, so the route slot is released only when
 * the producer settles.
 */
export function respondWithBoundedDashboardRead<T>(
  options: DashboardBoundedReadOptions<T>,
): Promise<boolean> {
  const { route, req, res, operation, produce, originMachine } = options;
  const readFlights = options.readFlights ?? inFlightByRoute;
  const existing = readFlights.get(route) as DashboardReadFlight<T> | undefined;
  const flight = existing ?? startReadFlight(readFlights, route, produce);

  if (existing && Date.now() >= existing.deadlineAtMs) {
    res.setHeader("Retry-After", String(DASHBOARD_RETRY_AFTER_SECONDS));
    // Invariant: over-cap means there is already a live read whose truth is unknown; refusal is safer than zero rows or green posture.
    writeJson(res, HTTP_SERVICE_UNAVAILABLE, {
      ...unavailableBody(route, "in_flight_limit"),
      ...(originMachine !== undefined ? { origin_machine: originMachine } : {}),
    });
    return Promise.resolve(true);
  }

  let responseSettled = false;
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
  const settleClosedCaller = (): void => {
    if (responseSettled) return;
    responseSettled = true;
    if (timeout) clearTimeout(timeout);
    cleanupResponseListeners();
    resolveHandled(true);
  };
  const abortForClosedRequest = (): void => {
    settleClosedCaller();
  };

  req.once?.("aborted", abortForClosedRequest);
  res.once?.("close", abortForClosedRequest);
  timeout = setTimeout(() => {
    // Invariant: an overdue evidence read has unknown truth; unavailable is the only honest payload the SPA will fail closed on.
    logDashboardReadFailure(route, operation, "deadline_exceeded");
    settleResponse(HTTP_SERVICE_UNAVAILABLE, {
      ...unavailableBody(route, "deadline_exceeded"),
      ...(originMachine !== undefined ? { origin_machine: originMachine } : {}),
    });
  }, DASHBOARD_READ_RESPONSE_DEADLINE_MS);

  void flight.promise
    .then(({ status, body }) => {
      settleResponse(status, body);
    })
    .catch(() => {
      // Invariant: a failed composition cannot be converted to an empty dashboard shape, because empty can mean healthy to the operator.
      if (!responseSettled) {
        logDashboardReadFailure(route, operation, "composition_failed");
      }
      settleResponse(HTTP_SERVICE_UNAVAILABLE, unavailableBody(route, "composition_failed"));
    });

  return handled;
}

function startReadFlight<T>(
  readFlights: DashboardReadFlightMap,
  route: DashboardBoundedReadRoute,
  produce: (signal: AbortSignal) => Promise<DashboardReadResponse<T>>,
): DashboardReadFlight<T> {
  const controller = new AbortController();
  let flight!: DashboardReadFlight<T>;
  const promise = Promise.resolve()
    .then(() => produce(controller.signal))
    .finally(() => {
      // Invariant: the single-flight slot stays held through caller timeouts and releases only when the producer settles, blocking rule-12 timeout-then-release waves.
      if (readFlights.get(route) === flight) {
        readFlights.delete(route);
      }
    });
  flight = {
    promise,
    deadlineAtMs: Date.now() + DASHBOARD_READ_RESPONSE_DEADLINE_MS,
  };
  // Invariant: these route payloads are operator-wide, read-only views with no per-caller redaction or privilege-dependent fields; if that changes, key the flight by caller class, not just route.
  readFlights.set(route, flight as DashboardReadFlight<unknown>);
  return flight;
}
