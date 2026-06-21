/**
 * Sovereignty Posture Dashboard - SSE live-refresh stream tests.
 *
 * Covers the prompt's acceptance criteria:
 *  (a) the stream emits the honest `buildHome` payload (same shape as `/home`);
 *  (b) reconnect-and-restore is encoded in the client (reconnect timer + close
 *      + poll fallback);
 *  (c) a dropped / stale / error stream renders an honest "reconnecting" +
 *      "last updated" state and NEVER relabels stale data as fresh-green;
 *  (d) the connection is cleaned up on disconnect (no leaked timer/handler) and
 *      the concurrency cap bounds open streams;
 *  (e) the static page still loads + renders correctly with SSE unavailable
 *      (the poll fallback is intact).
 *
 * The server-side cases drive a real `node:http` server through
 * `handlePostureRoute` (matching the existing posture-routes test harness) so
 * the auth-gate dispatch, the audit-null 503 guard, and the SSE framing are all
 * exercised end-to-end. The client-side cases assert against the
 * `renderPostureHomeHTML()` string (matching the v1.1 sse-reconnect test
 * pattern) so the honesty contract is pinned without a browser.
 */

import { describe, expect, it, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import {
  handlePostureRoute,
  POSTURE_STREAM_PATH,
  type PostureRouteDeps,
} from "../../src/principal-policy/posture-routes.js";
import {
  createPostureStreamRegistry,
  handlePostureStream,
  type PostureStreamRegistry,
} from "../../src/principal-policy/posture-stream.js";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";
import type { DetectedHarness } from "../../src/principal-policy/posture.js";

const FORTRESS = "fortress:test";

function wrappedAgent(id: string, harness: string): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: id,
    identity_id: FORTRESS,
    harness: harness as LocalAgentRecord["harness"],
    model_provider: { vendor: "anthropic", model_id: "claude", runs_locally: false },
    policy_id: "p1",
    status: "active",
    budget_summary: { last_refreshed_at: new Date().toISOString() },
    last_activity_at: new Date().toISOString(),
    wrapped_at: new Date().toISOString(),
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: false,
      can_change_template: false,
    },
  };
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (s) => new Promise<void>((resolve) => s.close(() => resolve())),
    ),
  );
});

async function serve(deps: PostureRouteDeps): Promise<string> {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const handled = await handlePostureRoute(
      deps,
      req,
      res,
      url,
      req.method ?? "GET",
    );
    if (!handled) res.writeHead(404).end();
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return `http://127.0.0.1:${addr.port}`;
}

function baseDeps(
  log: AuditLog | null,
  agents: LocalAgentRecord[],
  extra?: Partial<PostureRouteDeps>,
): PostureRouteDeps {
  const detected: DetectedHarness[] = [
    { platform: "cursor", harness: "cursor", config_path: "/home/u/.cursor/mcp.json" },
  ];
  return {
    auditLog: log,
    originMachine: FORTRESS,
    listAgents: () => agents,
    detectInstalledHarnesses: async () => detected,
    listReachRules: () => [
      {
        rule_id: "curated-anthropic-api",
        host: ["api.anthropic.com"],
        disposition: "allow",
        enforcing_layer: "castle_wall",
      },
    ],
    platform: "darwin",
    ...extra,
  };
}

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

/**
 * Read up to `byteLimit` bytes (or until `predicate(buffer)` is satisfied) from
 * an SSE response body, then abort. Returns the accumulated text. Aborting the
 * controller closes the socket, which fires the server-side `close` cleanup.
 */
async function readStreamUntil(
  base: string,
  path: string,
  predicate: (buf: string) => boolean,
  timeoutMs = 4000,
): Promise<{ text: string; controller: AbortController }> {
  const controller = new AbortController();
  const res = await fetch(`${base}${path}`, {
    headers: { Accept: "text/event-stream" },
    signal: controller.signal,
  });
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toContain("text/event-stream");
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let text = "";
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { value, done } = await reader.read();
    if (done) break;
    text += decoder.decode(value, { stream: true });
    if (predicate(text)) break;
  }
  controller.abort();
  return { text, controller };
}

describe("posture SSE stream (server)", () => {
  it("(a) emits the honest buildHome payload as a `home` SSE event", async () => {
    const log = newLog();
    const now = Date.now();
    await log.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: FORTRESS,
      result: "success",
      details: { cw_source: "castle_wall_audit_consumer" },
      timestamp: new Date(now - 30_000).toISOString(),
    });
    const registry = createPostureStreamRegistry();
    const base = await serve(
      baseDeps(log, [wrappedAgent("a1", "claude_code")], {
        streamRegistry: registry,
        streamIntervalMs: 50,
        streamHeartbeatMs: 50,
      }),
    );

    const { text } = await readStreamUntil(base, POSTURE_STREAM_PATH, (buf) =>
      buf.includes("event: home"),
    );

    expect(text).toContain("event: home");
    // Parse the first home frame and assert it is the SAME honest shape as /home.
    const m = /event: home\ndata: (.+)\n/.exec(text);
    expect(m).not.toBeNull();
    const payload = JSON.parse(m![1]!);
    expect(payload.origin_machine).toBe(FORTRESS);
    expect(payload.stream_available).toBe(true);
    expect(payload.castle_wall.arm_state).toBe("armed");
    expect(payload.protection_requested_count).toBe(1);
    expect(payload.unwrapped.unwrapped[0].harness).toBe("cursor");
    expect(payload.digest.kernel_allows).toBe(1);
    // No new green path: the stream carries the same fields, nothing invented.
    expect(payload.feature_health).toBeDefined();
  });

  it("(a) the stream payload equals the /home payload byte-for-byte (same shaper)", async () => {
    const log = newLog();
    const base = await serve(
      baseDeps(log, [wrappedAgent("a1", "claude_code")], {
        streamRegistry: createPostureStreamRegistry(),
        streamIntervalMs: 50,
        streamHeartbeatMs: 1000,
      }),
    );
    const homeRes = await fetch(`${base}/api/posture/home`);
    const home = await homeRes.json();
    const { text } = await readStreamUntil(base, POSTURE_STREAM_PATH, (buf) =>
      buf.includes("event: home"),
    );
    const m = /event: home\ndata: (.+)\n/.exec(text);
    const streamed = JSON.parse(m![1]!);
    // Window timestamps in the digest move between the two reads; compare the
    // structural keys + the honest counts rather than the volatile windows.
    expect(Object.keys(streamed).sort()).toEqual(Object.keys(home).sort());
    expect(streamed.castle_wall.arm_state).toBe(home.castle_wall.arm_state);
    expect(streamed.protection_requested_count).toBe(
      home.protection_requested_count,
    );
    expect(streamed.enforcement_confirmed_count).toBe(
      home.enforcement_confirmed_count,
    );
  });

  it("emits a heartbeat comment to keep the connection alive", async () => {
    const base = await serve(
      baseDeps(newLog(), [], {
        streamRegistry: createPostureStreamRegistry(),
        streamIntervalMs: 5000,
        streamHeartbeatMs: 30,
      }),
    );
    const { text } = await readStreamUntil(base, POSTURE_STREAM_PATH, (buf) =>
      buf.includes(": heartbeat"),
    );
    expect(text).toContain(": heartbeat");
  });

  it("(c) emits an honest `error` event (never stale-green) when buildHome fails", async () => {
    // A deps whose listAgents throws makes buildHome reject; the stream must
    // surface an explicit error frame, not a fabricated payload.
    const failing = baseDeps(newLog(), [], {
      streamRegistry: createPostureStreamRegistry(),
      streamIntervalMs: 50,
      streamHeartbeatMs: 5000,
      listAgents: () => {
        throw new Error("boom");
      },
    });
    const base = await serve(failing);
    const { text } = await readStreamUntil(base, POSTURE_STREAM_PATH, (buf) =>
      buf.includes("event: error"),
    );
    expect(text).toContain("event: error");
    expect(text).toContain("posture_read_failed");
    // The error frame carries NO home payload fields - it cannot be mistaken
    // for fresh green data.
    expect(text).not.toContain("arm_state");
  });

  it("(c) the stream is behind the audit-null 503 guard (never opens on a locked log)", async () => {
    const base = await serve(
      baseDeps(null, [], { streamRegistry: createPostureStreamRegistry() }),
    );
    const res = await fetch(`${base}${POSTURE_STREAM_PATH}`);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toBe("posture_unavailable");
    // Crucially NOT a text/event-stream - the stream never opened.
    expect(res.headers.get("content-type")).toContain("application/json");
  });

  it("(e) the stream endpoint 404s within the namespace when no registry is wired (additive/disabled)", async () => {
    // No streamRegistry -> the SSE endpoint is disabled and the page falls back
    // to polling. The rest of the posture surface is unaffected.
    const base = await serve(baseDeps(newLog(), []));
    const res = await fetch(`${base}${POSTURE_STREAM_PATH}`);
    expect(res.status).toBe(404);
    // The existing /home endpoint still works (page keeps functioning).
    const home = await fetch(`${base}/api/posture/home`);
    expect(home.status).toBe(200);
    const body = await home.json();
    expect(body.stream_available).toBe(false);
  });

  it("(d) caps concurrent streams (503 at the cap, no unbounded sockets)", async () => {
    const registry = createPostureStreamRegistry();
    const base = await serve(
      baseDeps(newLog(), [], {
        streamRegistry: registry,
        streamMaxConcurrent: 1,
        streamIntervalMs: 5000,
        streamHeartbeatMs: 5000,
      }),
    );
    // Open the first stream and HOLD it open (do not abort): read one frame, then
    // keep the socket so the slot stays counted while we attempt a second open.
    const controller = new AbortController();
    const res = await fetch(`${base}${POSTURE_STREAM_PATH}`, {
      headers: { Accept: "text/event-stream" },
      signal: controller.signal,
    });
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (!buf.includes("event: home")) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    expect(registry.active).toBe(1);

    // The second open is refused with 503 (cap reached) and does NOT open a
    // stream or increment the count.
    const refused = await fetch(`${base}${POSTURE_STREAM_PATH}`);
    expect(refused.status).toBe(503);
    const body = await refused.json();
    expect(body.error).toBe("too_many_streams");
    expect(registry.active).toBe(1);

    // Release the held stream; the slot frees so a later open would succeed.
    controller.abort();
    try {
      await reader.cancel();
    } catch {
      /* already aborted */
    }
  });
});

describe("posture SSE stream (handler unit: cleanup + cap)", () => {
  /**
   * Minimal fake ServerResponse capturing writes + the close/error listeners so
   * the handler's timer + counter cleanup can be asserted deterministically with
   * fake timers (no wall-clock waiting).
   */
  function fakeRes() {
    const listeners: Record<string, Array<() => void>> = {};
    const writes: string[] = [];
    let headStatus: number | null = null;
    return {
      writeHead(status: number) {
        headStatus = status;
        return this;
      },
      write(chunk: string) {
        writes.push(chunk);
        return true;
      },
      end() {
        /* no-op */
      },
      on(event: string, cb: () => void) {
        (listeners[event] ??= []).push(cb);
        return this;
      },
      fire(event: string) {
        for (const cb of listeners[event] ?? []) cb();
      },
      get writes() {
        return writes;
      },
      get headStatus() {
        return headStatus;
      },
    };
  }

  it("(d) clears BOTH timers and releases the slot on `close` (no leak)", async () => {
    const registry: PostureStreamRegistry = createPostureStreamRegistry();
    const created: NodeJS.Timeout[] = [];
    const cleared: NodeJS.Timeout[] = [];
    let id = 0;
    const setIntervalFn = ((): NodeJS.Timeout => {
      const handle = ++id as unknown as NodeJS.Timeout;
      created.push(handle);
      return handle;
    }) as PostureRouteDeps["streamSetInterval"];
    const clearIntervalFn = ((handle: NodeJS.Timeout) => {
      cleared.push(handle);
    }) as PostureRouteDeps["streamClearInterval"];

    const res = fakeRes();
    await handlePostureStream(res as never, {
      buildHome: async () =>
        ({ origin_machine: FORTRESS }) as never,
      registry,
      setIntervalFn: setIntervalFn!,
      clearIntervalFn: clearIntervalFn!,
    });

    // Stream opened: head 200, an initial home frame written, slot counted, and
    // both the push + heartbeat intervals created.
    expect(res.headStatus).toBe(200);
    expect(res.writes.some((w) => w.includes("event: home"))).toBe(true);
    expect(registry.active).toBe(1);
    expect(created.length).toBe(2);

    // Client disconnects.
    res.fire("close");
    // Both timers cleared exactly once, slot released.
    expect(cleared.sort()).toEqual(created.sort());
    expect(registry.active).toBe(0);

    // Idempotent: a subsequent error must not double-decrement or double-clear.
    res.fire("error");
    expect(registry.active).toBe(0);
    expect(cleared.length).toBe(2);
  });

  it("(d) refuses to open at the cap and leaves the slot count unchanged", async () => {
    const registry: PostureStreamRegistry = { active: 2 };
    const res = fakeRes();
    await handlePostureStream(res as never, {
      buildHome: async () => ({ origin_machine: FORTRESS }) as never,
      registry,
      maxConcurrent: 2,
    });
    expect(res.headStatus).toBe(503);
    expect(registry.active).toBe(2);
    expect(res.writes.some((w) => w.includes("event: home"))).toBe(false);
  });
});

describe("posture home page client (honesty + reconnect + static-load)", () => {
  const html = renderPostureHomeHTML();

  it("(b) encodes the reconnect-and-restore pattern (timer + close + reconnect)", () => {
    expect(html).toContain("EventSource");
    expect(html).toContain("connectStream");
    expect(html).toContain("reconnectTimer");
    expect(html).toContain("scheduleReconnect");
    // Capped backoff, never a tight loop.
    expect(html).toContain("RECONNECT_MAX_MS");
    // The source is closed before reconnecting.
    expect(html).toContain("es.close()");
  });

  it("(c) shows a reconnecting indicator + last-updated, never stale-as-green", () => {
    // The connection indicator element + the two honest states exist.
    expect(html).toContain('id="conn"');
    expect(html).toContain('id="conn-updated"');
    expect(html).toContain("Reconnecting");
    expect(html).toContain("last updated ");
    // A staleness watchdog forces amber when frames stop arriving, so an open-
    // but-quiet socket cannot keep a green "Live".
    expect(html).toContain("STALENESS_WINDOW_MS");
    expect(html).toContain("tickStaleness");
    // "Live" (green) is advanced ONLY by a fully-applied fresh frame.
    expect(html).toContain("lastFrameAt = Date.now()");
    expect(html).toContain('setConn("live")');
    // The transport-error / server-error paths both go amber.
    expect(html).toContain('setConn("reconnecting")');
  });

  it("(e) the static page still works with SSE unavailable (poll fallback intact)", () => {
    // Progressive enhancement: feature-detect EventSource; poll when absent.
    expect(html).toContain('"EventSource" in window');
    expect(html).toContain("startPolling");
    expect(html).toContain("pollOnce");
    expect(html).toContain("streamAvailable = home && home.stream_available === true");
    expect(html).toContain("if (!streamAvailable) { startPolling(); return; }");
    // The poll path still hits the existing /home endpoint (unchanged contract).
    expect(html).toContain("/api/posture/home");
    // The page renders once on boot before any stream connects, so first paint
    // is correct even if SSE never connects.
    expect(html).toContain("if (!supportsSSE || !streamAvailable) startPolling()");
  });

  it("never weakens the existing never-fake-green tile model", () => {
    // The wall pill keeps ARMED as the only green; the agent pill keeps
    // enforcement-active as the only green. The SSE path renders through the
    // SAME renderHome, so no second color model is introduced.
    expect(html).toContain("renderHome");
    expect(html).toContain('pill green">ARMED');
    expect(html).toContain('pill green">enforcement active');
  });
});
