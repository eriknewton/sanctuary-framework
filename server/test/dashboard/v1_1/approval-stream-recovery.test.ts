/** Real client recovery with a fake transport and clock: three-minute outage, repeated opens, and bounded probing. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

const SECOND_MS = 1000;
const MINUTE_MS = 60 * SECOND_MS;
const INTERVAL_MS = MINUTE_MS; // At most one automatic read per panel per minute.
const REPEATED_WAVES = 5; // Five failures reach the existing backoff ceiling.
const emptyData = { data: { configured: false, surfaces: [], agents: [], items: [], traps: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] } };
const response = (body: unknown = emptyData) => ({
  ok: true, status: 200, json: async () => body, // HTTP OK fixture.
  body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(JSON.stringify(body))); controller.close(); } }),
});
function deferred() {
  let resolve!: (value: ReturnType<typeof response>) => void;
  const promise = new Promise<ReturnType<typeof response>>((done) => { resolve = done; });
  return { promise, resolve };
}
// Same real-script VM, minimal DOM, fake stream and fetch pattern as boot-hydration.test.ts.
// sse-reconnect.test.ts itself only checks the generated script's source.
function harness(options: { deferDeadlines?: boolean } = {}) {
  let deferCurrentReadDeadline = false;
  const calls: Array<{ path: string; signal?: AbortSignal | null }> = [];
  const overrides: Record<string, () => unknown> = {};
  const streams: FakeEventSource[] = [];
  const listeners: Record<string, () => void> = {};
  const main = { innerHTML: "", querySelector: () => null, querySelectorAll: () => [] };
  const fortress = { innerHTML: "" };
  class FakeEventSource {
    static OPEN = 1; // Browser OPEN state.
    readyState = 0; // Browser CONNECTING state.
    onopen?: () => void;
    onerror?: () => void;
    listeners: Record<string, (event: { data: string }) => void> = {};
    constructor() { streams.push(this); }
    open() { this.readyState = FakeEventSource.OPEN; this.onopen?.(); }
    close() { this.readyState = 2; } // Browser CLOSED state.
    error() { this.onerror?.(); }
    frame(name: string, data: unknown) { this.listeners[name]?.({ data: JSON.stringify(data) }); }
    addEventListener(name: string, listener: (event: { data: string }) => void) { this.listeners[name] = listener; }
  }
  const document = {
    visibilityState: "visible",
    getElementById: (id: string) => id === "main" ? main : id === "fortress" ? fortress : null,
    addEventListener: (event: string, listener: () => void) => { listeners[event] = listener; },
    querySelectorAll: () => [], documentElement: { setAttribute() {}, removeAttribute() {} },
  };
  const context = createContext({
    document, window: { addEventListener: (event: string, listener: () => void) => { listeners[event] = listener; } }, location: { hash: "", search: "", origin: "http://fixture" },
    sessionStorage: { getItem: () => null }, URLSearchParams, URL, AbortController, TextDecoder, Date,
    // Defer deadline delivery beyond two more steady ticks while transport remains pending.
    setTimeout: (callback: () => void, delay: number) => setTimeout(callback,
      options.deferDeadlines && deferCurrentReadDeadline && callback.name === "dashboardReadDeadline" ? INTERVAL_MS * 3 : delay),
    clearTimeout, setInterval: () => 0, clearInterval() {}, EventSource: FakeEventSource,
    fetch: (url: string, init?: RequestInit) => {
      const parsed = new URL(url, "http://fixture"); parsed.searchParams.delete("_t");
      const path = parsed.pathname + parsed.search;
      calls.push({ path, signal: init?.signal });
      if (overrides[path]) return overrides[path]();
      return Promise.resolve(response(path === "/api/posture/home" ? {
        origin_machine: "fixture", agents: [], castle_wall: { arm_state: "unknown" }, digest: {},
        protection_requested_count: 0, enforcement_confirmed_count: 0,
      } : emptyData));
    },
  });
  runInContext(getClientScript(), context);
  const originalReadResponse = context.readResponse;
  context.readResponse = function (...args: unknown[]) {
    deferCurrentReadDeadline = args[0] === "/auth/session";
    try { return originalReadResponse(...args); }
    finally { deferCurrentReadDeadline = false; }
  };
  const read = (expression: string) => runInContext(expression, context);
  return { calls, overrides, streams, main, fortress, read, pagehide: () => listeners.pagehide(),
    count: (path: string) => calls.filter(call => call.path === path).length,
    visibility: (value: string) => { document.visibilityState = value; listeners.visibilitychange(); },
  };
}
// Finite boot and panel promise drain, with no observer or wall-clock wait.
async function settle() { const MICROTASK_DRAIN_LIMIT = 100; for (let i = 0; i < MICROTASK_DRAIN_LIMIT; i++) await Promise.resolve(); }
async function connected(options: Parameters<typeof harness>[0] = {}) {
  const h = harness(options); await settle(); h.streams[0].open(); h.streams[0].frame("snapshot", { server_boot_id: "a".repeat(32) }); return h;
}
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-24T12:00:00Z")); });
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

it("recovers after three minutes down without a click and shows one restart banner", async () => {
  const h = await connected();
  h.read('TOKEN = "fixture"');
  h.overrides["/auth/session"] = () => Promise.reject(new Error("offline"));
  h.streams[0].error();
  await vi.advanceTimersByTimeAsync(SECOND_MS);
  expect(h.read("pollingStarted"), "session network failures stay on stream backoff").toBe(false);
  await vi.advanceTimersByTimeAsync(3 * MINUTE_MS - SECOND_MS);
  expect(h.streams).toHaveLength(1);
  const before = h.count("/auth/session");
  h.overrides["/auth/session"] = () => Promise.resolve(response({ session_id: "restored" }));
  await vi.advanceTimersByTimeAsync(30 * SECOND_MS);
  expect(h.streams).toHaveLength(2);
  h.streams[1].open();
  h.streams[1].frame("snapshot", { server_boot_id: "b".repeat(32) });
  await settle();
  expect(h.read("liveUpdatesStopped")).toBe(false);
  expect(h.main.innerHTML.match(/data-stream-recovery-banner/g)).toHaveLength(1);
  expect(h.main.innerHTML).toContain("The server restarted. Requests that were waiting before the restart were denied.");
  expect(h.count("/auth/session") - before).toBeLessThanOrEqual(2);
  // A received frame resets the budget; later same-process reconnects clear the stale restart banner.
  for (let i = 0; i < REPEATED_WAVES + 1; i++) {
    const count = h.streams.length;
    h.streams.at(-1)!.error();
    await vi.advanceTimersByTimeAsync(SECOND_MS);
    expect(h.streams).toHaveLength(count + 1);
    h.streams.at(-1)!.open();
    h.streams.at(-1)!.frame("snapshot", { server_boot_id: "b".repeat(32) });
  }
  expect(h.main.innerHTML).not.toContain("data-stream-recovery-banner");
});

it("admits only one slow probe while its fetch is outstanding", async () => {
  const h = await connected({ deferDeadlines: true }); h.read('TOKEN = "fixture"');
  h.overrides["/auth/session"] = () => Promise.reject(new Error("offline"));
  h.streams[0].error();
  await vi.advanceTimersByTimeAsync(MINUTE_MS);
  const slow = deferred(); h.overrides["/auth/session"] = () => slow.promise;
  const before = h.count("/auth/session");
  await vi.advanceTimersByTimeAsync(30 * SECOND_MS);
  expect(h.count("/auth/session") - before).toBe(1);
  await vi.advanceTimersByTimeAsync(2 * MINUTE_MS);
  expect(h.count("/auth/session") - before).toBe(1);
  slow.resolve(response({ session_id: "up" })); await settle();
});


it("same-process reconnects show no restart banner and clear a stale banner", async () => {
  const h = await connected();
  h.streams[0].error(); await vi.advanceTimersByTimeAsync(SECOND_MS);
  h.streams[1].open(); h.streams[1].frame("snapshot", { server_boot_id: "a".repeat(32) });
  expect(h.main.innerHTML).not.toContain("data-stream-recovery-banner");
  h.streams[1].error(); await vi.advanceTimersByTimeAsync(SECOND_MS);
  h.streams[2].open(); h.streams[2].frame("snapshot", { server_boot_id: "b".repeat(32) });
  expect(h.main.innerHTML.match(/data-stream-recovery-banner/g)).toHaveLength(1);
  h.streams[2].error(); await vi.advanceTimersByTimeAsync(SECOND_MS);
  h.streams[3].open(); h.streams[3].frame("snapshot", { server_boot_id: "b".repeat(32) });
  expect(h.main.innerHTML).not.toContain("data-stream-recovery-banner");
});

it("connect-then-drop spends the backoff budget and reaches the single-flight probe", async () => {
  const h = harness(); await settle();
  for (const delay of [1, 2, 4, 8, 16]) {
    h.streams.at(-1)!.open(); h.streams.at(-1)!.error();
    const count = h.streams.length;
    await vi.advanceTimersByTimeAsync(delay * SECOND_MS - 1);
    expect(h.streams).toHaveLength(count);
    await vi.advanceTimersByTimeAsync(1);
    expect(h.streams).toHaveLength(count + 1);
  }
  h.streams.at(-1)!.open(); h.streams.at(-1)!.error();
  expect(h.read("liveUpdatesStopped")).toBe(true);
  const count = h.streams.length;
  await vi.advanceTimersByTimeAsync(30 * SECOND_MS - 1);
  expect(h.streams).toHaveLength(count);
  await vi.advanceTimersByTimeAsync(1);
  expect(h.streams).toHaveLength(count + 1);
});

it.each([-6, 6])("uses server time with a %i minute browser skew and waits for a confirmed denial", async minutes => {
  const serverStart = Date.now(), skew = minutes * MINUTE_MS;
  vi.setSystemTime(new Date(serverStart + skew));
  const h = await connected();
  const item = { item_id: "charter.approval.skew", kind: "approval_pending", tier: "tier1", operation_category: "other", operation: "memory_insert", created_at: new Date(serverStart).toISOString(), expires_at: new Date(serverStart + 10 * SECOND_MS).toISOString(), resolved: false };
  const payload = () => ({ items: [{ ...item }], server_now: new Date(Date.now() - skew).toISOString() });
  h.overrides["/api/hub/inbox"] = () => Promise.resolve(response({ data: payload() }));
  h.read('applyInboxPayload(' + JSON.stringify(payload()) + '); state.approvals.selectedId = "charter.approval.skew"; scheduleApprovalDeadlineTick()');
  expect(h.read('approvalExpired(state.inbox[0])')).toBe(false);
  expect(h.read('approvalDecisionDisabled(state.inbox[0])')).toBe("");
  expect(h.read('approvalCountdownHtml(state.inbox[0])')).toContain("Expires in 0:10");
  const before = h.count("/api/hub/inbox");
  await vi.advanceTimersByTimeAsync(10 * SECOND_MS);
  expect(h.read('approvalExpired(state.inbox[0])')).toBe(true);
  expect(h.read('approvalCountdownHtml(state.inbox[0])')).toContain("This request reached its time limit.");
  await vi.advanceTimersByTimeAsync(25 * SECOND_MS);
  expect(h.count("/api/hub/inbox") - before).toBeLessThanOrEqual(2);
  h.streams.at(-1)!.frame("approval", { id: "skew", resolved: true, decision: "deny", decided_by: "timeout" });
  expect(h.read('approvalCountdownHtml(state.inbox[0])')).toContain("was denied automatically. The agent was told no.");
  h.read('applyInboxPayload(' + JSON.stringify(payload()) + ')');
  expect(h.read('approvalCountdownHtml(state.inbox[0])')).toContain("was denied automatically. The agent was told no.");
  // A confirmed timeout can precede the locally estimated deadline when the clock sample arrived late.
  item.item_id = "charter.approval.early";
  item.expires_at = new Date(Date.now() - skew + 10 * SECOND_MS).toISOString();
  h.read('applyInboxPayload(' + JSON.stringify(payload()) + ')');
  const earlyReads = h.count("/api/hub/inbox");
  h.streams.at(-1)!.frame("approval", { id: "early", resolved: true, decision: "deny", decided_by: "timeout" });
  expect(h.read('approvalCountdownHtml(state.inbox[0])')).toContain("was denied automatically.");
  await vi.advanceTimersByTimeAsync(20 * SECOND_MS);
  // The stream itself invalidates once; deadline processing admits at most one read and one retry.
  expect(h.count("/api/hub/inbox") - earlyReads).toBeLessThanOrEqual(3);
});

it.each([
  { decision: "approve", decided_by: "human" },
  { decision: "deny", decided_by: "human" },
  { decision: "deny" },
  { decision: "deny", decided_by: "untrusted" },
])("does not infer a timeout from close metadata %j", async close => {
  const h = await connected();
  const item = { item_id: "charter.approval.human", resolved: false, created_at: new Date(Date.now() - SECOND_MS).toISOString(), expires_at: new Date().toISOString() };
  h.read('applyInboxPayload(' + JSON.stringify({ items: [item], server_now: new Date().toISOString() }) + ')');
  h.streams[0].frame("approval", { id: "human", resolved: true, ...close });
  expect(h.read('state.inbox[0].timeoutConfirmed')).toBeUndefined();
  expect(h.read('approvalCountdownHtml(state.inbox[0])')).not.toContain("denied automatically");
  expect(h.read('expiredApprovalSelection')).toBeNull();
});

it("pagehide clears the retained closed card before back-forward restoration", async () => {
  const h = await connected();
  const item = { item_id: "charter.approval.hidden", resolved: false, created_at: new Date(Date.now() - SECOND_MS).toISOString(), expires_at: new Date().toISOString() };
  h.read('applyInboxPayload(' + JSON.stringify({ items: [item], server_now: new Date().toISOString() }) + '); state.approvals.selectedId = "charter.approval.hidden"');
  h.streams[0].frame("approval", { id: "hidden", resolved: true, decision: "deny", decided_by: "timeout" });
  expect(h.read('expiredApprovalSelection.timeoutConfirmed')).toBe(true);
  h.read('applyInboxPayload({ items: [] })');
  h.pagehide();
  expect(h.read('expiredApprovalSelection')).toBeNull();
  expect(h.read('renderApprovalsScreen()')).not.toContain("denied automatically");
});
