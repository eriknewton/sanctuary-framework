/**
 * Sovereignty Posture Dashboard - SSE live-refresh stream (additive, Phase 2).
 *
 * `GET /api/posture/stream` is a Server-Sent Events endpoint that pushes the
 * SAME honest home payload as `GET /api/posture/home` (it REUSES `buildHome`,
 * introducing no new data and no new green paths) on a modest cadence plus a
 * periodic heartbeat comment. It is mounted behind the SAME `checkAuth` gate as
 * the rest of `/api/posture/*` (the dashboard runs the check before dispatch)
 * AND behind the same audit-null 503 guard (the route layer enforces it before
 * calling this handler), so the stream can never serve an empty-but-green
 * payload when the audit log is locked.
 *
 * Progressive enhancement: this endpoint is purely additive. The static
 * `/posture` page and the existing `/api/posture/*` JSON endpoints are
 * untouched; if a client never connects (EventSource unsupported, or the stream
 * 503s), the page keeps working exactly as before via its poll fallback.
 *
 * Resource safety (mandatory):
 *  - Concurrent streams are capped (`MAX_CONCURRENT_STREAMS`). At the cap the
 *    handler responds 503 with `Retry-After` rather than opening an unbounded
 *    number of long-lived sockets (a connection-exhaustion DoS surface).
 *  - A heartbeat comment is sent on a fixed interval so a dead peer is detected
 *    and intermediaries do not buffer the connection closed.
 *  - EVERY timer and the active-stream counter are cleaned up on `close` /
 *    `error`, exactly once, so a disconnecting client leaks neither a timer nor
 *    a counted slot.
 *
 * Honesty contract (#617): the stream NEVER fabricates state. Each frame is a
 * fresh `buildHome` read; a failed read emits an explicit `error` event (not a
 * stale-but-green payload), and the CLIENT is responsible for showing a
 * "reconnecting" + "last updated" indicator on any drop/staleness so a stale
 * view can never be mistaken for a live green-all-well.
 */

import type { ServerResponse } from "node:http";
// Import the payload shape from the neutral type module, NOT from
// `posture-routes.js`: `posture-routes` imports this stream handler, so
// importing back from it would close a `posture-routes` <-> `posture-stream`
// cycle. The neutral module sits strictly lower in the dependency DAG.
import type { PostureHome } from "./posture-home-types.js";

/** Default cadence for pushing a fresh home payload (5s). */
export const DEFAULT_STREAM_INTERVAL_MS = 5_000;

/** Default heartbeat-comment cadence (15s). Keeps the socket + proxies alive. */
export const DEFAULT_STREAM_HEARTBEAT_MS = 15_000;

/**
 * Default cap on concurrent posture streams. A single operator dashboard opens
 * one stream; the cap exists to bound a misbehaving client or a scripted
 * connection-exhaustion attempt, not to limit legitimate use. Generous enough
 * for a handful of operator tabs, small enough that it cannot exhaust sockets.
 */
export const DEFAULT_MAX_CONCURRENT_STREAMS = 16;

/**
 * Options for {@link handlePostureStream}. All timing + cap knobs are injectable
 * so tests can drive the cadence deterministically and exercise the cap without
 * waiting on wall-clock intervals.
 */
export interface PostureStreamOptions {
  /** Produce the current honest home payload (the SAME shaper as `/home`). */
  buildHome: () => Promise<PostureHome>;
  /** Push cadence (ms). Defaults to {@link DEFAULT_STREAM_INTERVAL_MS}. */
  intervalMs?: number;
  /** Heartbeat cadence (ms). Defaults to {@link DEFAULT_STREAM_HEARTBEAT_MS}. */
  heartbeatMs?: number;
  /** Shared mutable registry tracking active streams (for the concurrency cap). */
  registry: PostureStreamRegistry;
  /** Concurrency cap. Defaults to {@link DEFAULT_MAX_CONCURRENT_STREAMS}. */
  maxConcurrent?: number;
  /**
   * Injectable timer hooks for deterministic tests. Default to the global
   * `setInterval`/`clearInterval`. Tests pass fakes so a single tick can be
   * fired synchronously without real time passing.
   */
  setIntervalFn?: (handler: () => void, ms: number) => NodeJS.Timeout;
  clearIntervalFn?: (handle: NodeJS.Timeout) => void;
}

/**
 * Shared active-stream accounting. A single instance is held by the dashboard
 * and passed to every stream so the cap is enforced across all connections.
 * Kept as a tiny mutable object (not module-global state) so tests get an
 * isolated counter and the dashboard owns the lifecycle.
 */
export interface PostureStreamRegistry {
  /** Number of currently-open streams. */
  active: number;
}

/** Create a fresh stream registry (active = 0). */
export function createPostureStreamRegistry(): PostureStreamRegistry {
  return { active: 0 };
}

/**
 * Serve a posture SSE stream on `res`. The caller has already run `checkAuth`
 * and the audit-null 503 guard. Returns once the response head + initial frame
 * are written (the stream itself lives until the client disconnects).
 *
 * At the concurrency cap, responds 503 (with `Retry-After`) and opens no
 * stream; the active count is unchanged.
 */
export async function handlePostureStream(
  res: ServerResponse,
  options: PostureStreamOptions,
): Promise<void> {
  const intervalMs = options.intervalMs ?? DEFAULT_STREAM_INTERVAL_MS;
  const heartbeatMs = options.heartbeatMs ?? DEFAULT_STREAM_HEARTBEAT_MS;
  const maxConcurrent = options.maxConcurrent ?? DEFAULT_MAX_CONCURRENT_STREAMS;
  const setIntervalFn = options.setIntervalFn ?? setInterval;
  const clearIntervalFn = options.clearIntervalFn ?? clearInterval;
  const registry = options.registry;

  // Concurrency cap: refuse to open an unbounded number of long-lived sockets.
  // This is a JSON 503 (not an SSE frame) because the stream never opened.
  if (registry.active >= maxConcurrent) {
    res.writeHead(503, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Retry-After": "5",
    });
    res.end(JSON.stringify({ error: "too_many_streams" }));
    return;
  }

  // Count this slot BEFORE any await so a burst of concurrent opens cannot race
  // past the cap between the check above and the increment.
  registry.active += 1;

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    // Defeat proxy buffering so frames are delivered promptly (mirrors the v1.0
    // dashboard stream).
    "X-Accel-Buffering": "no",
  });

  // ── Single-shot cleanup ──────────────────────────────────────────────
  // Runs exactly once on the first of close/error. Clears BOTH timers and
  // releases the counted slot so neither a timer nor a stream slot can leak.
  let cleanedUp = false;
  let pushTimer: NodeJS.Timeout | null = null;
  let heartbeatTimer: NodeJS.Timeout | null = null;
  const cleanup = (): void => {
    if (cleanedUp) return;
    cleanedUp = true;
    if (pushTimer !== null) clearIntervalFn(pushTimer);
    if (heartbeatTimer !== null) clearIntervalFn(heartbeatTimer);
    pushTimer = null;
    heartbeatTimer = null;
    registry.active -= 1;
  };

  // Write a `home` event with the current honest payload, or an explicit
  // `error` event if the read fails. NEVER fabricates a green payload on error:
  // the client treats an `error` event (and any silence) as "go reconnecting,
  // keep the last-updated timestamp", never as fresh green.
  const pushHome = async (): Promise<void> => {
    if (cleanedUp) return;
    let frame: string;
    try {
      const home = await options.buildHome();
      // A late completion after the client vanished must not write to a dead
      // socket: re-check the cleanup flag after the await.
      if (cleanedUp) return;
      frame = `event: home\ndata: ${JSON.stringify(home)}\n\n`;
    } catch {
      if (cleanedUp) return;
      // Honest failure frame: tell the client the read failed so it shows the
      // reconnecting/stale state, never the prior data as fresh.
      frame = `event: error\ndata: ${JSON.stringify({ error: "posture_read_failed" })}\n\n`;
    }
    try {
      res.write(frame);
    } catch {
      // Socket gone between the read and the write: tear down now rather than
      // waiting on the next tick.
      cleanup();
    }
  };

  res.on("close", cleanup);
  res.on("error", cleanup);

  // Initial frame so the client renders immediately on connect (no waiting for
  // the first interval tick).
  await pushHome();
  if (cleanedUp) return;

  // Periodic fresh push. Each tick is a NEW buildHome read, so the stream can
  // never replay a stale payload as if it were current.
  pushTimer = setIntervalFn(() => {
    void pushHome();
  }, intervalMs);

  // Heartbeat comment. SSE comment lines (`:`) are ignored by EventSource but
  // keep the socket + any intermediary from treating the connection as idle,
  // and surface a dead peer to the server promptly.
  heartbeatTimer = setIntervalFn(() => {
    if (cleanedUp) return;
    try {
      res.write(": heartbeat\n\n");
    } catch {
      cleanup();
    }
  }, heartbeatMs);
}
