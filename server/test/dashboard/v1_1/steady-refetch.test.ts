/**
 * Connected dashboards refresh inbox and agents with bounded work,
 * visible read failures, and teardown across stream and page transitions.
 * D7
 */
// fail-before-exempt: regression guard for behaviour that already shipped; these late-fulfil cases pass on both revisions by design and pin the refusal of a superseded steady response.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

const SECOND_MS = 1000;
const MINUTE_MS = 60 * SECOND_MS;
const INTERVAL_MS = MINUTE_MS; // At most one automatic read per panel per minute.
const DEADLINE_MS = 5 * SECOND_MS; // Existing dashboard read budget.
const EDGE_MS = 1; // Adjacent fake-clock tick before a timer is due.
const REPEATED_WAVES = 5; // Five failures reach the existing backoff ceiling.
const TARGETS = ["/api/hub/inbox", "/api/hub/agents"];
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
    addEventListener(name: string, listener: (event: { data: string }) => void) { this.listeners[name] = listener; }
  }
  const document = {
    visibilityState: "visible",
    getElementById: (id: string) => id === "main" ? main : id === "fortress" ? fortress : null,
    addEventListener: (event: string, listener: () => void) => { listeners[event] = listener; },
    querySelectorAll: () => [], documentElement: { setAttribute() {}, removeAttribute() {} },
  };
  const context = createContext({
    document, window: { addEventListener() {} }, location: { hash: "", search: "", origin: "http://fixture" },
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
    deferCurrentReadDeadline = args[4] === true;
    try { return originalReadResponse(...args); }
    finally { deferCurrentReadDeadline = false; }
  };
  const read = (expression: string) => runInContext(expression, context);
  return { calls, overrides, streams, main, fortress, read,
    count: (path: string) => calls.filter(call => call.path === path).length,
    visibility: (value: string) => { document.visibilityState = value; listeners.visibilitychange(); },
  };
}
// Finite boot and panel promise drain, with no observer or wall-clock wait.
async function settle() { const MICROTASK_DRAIN_LIMIT = 100; for (let i = 0; i < MICROTASK_DRAIN_LIMIT; i++) await Promise.resolve(); }
async function connected(options: Parameters<typeof harness>[0] = {}) {
  const h = harness(options); await settle(); h.streams[0].open(); return h;
}
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-24T12:00:00Z")); });
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

describe("connected dashboard bounded hub refetch", () => {
  it("waits one minute, then refreshes only inbox and agents on each healthy interval", async () => {
    const h = await connected(); const before = h.calls.length;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS - EDGE_MS);
    expect(h.calls).toHaveLength(before);
    await vi.advanceTimersByTimeAsync(EDGE_MS);
    expect(h.calls.slice(before).map(call => call.path).sort()).toEqual([...TARGETS].sort());
    expect(h.read("DASHBOARD_STEADY_REFETCH_INTERVAL_MS")).toBe(INTERVAL_MS);
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    TARGETS.forEach(path => expect(h.count(path)).toBe(3)); // Boot and two steady waves.
  });
  it("does not start periodic reads until the stream opens", async () => {
    const h = harness(); await settle(); const before = h.calls.length;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS * REPEATED_WAVES);
    expect(h.calls).toHaveLength(before);
    h.streams[0].open(); await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    TARGETS.forEach(path => expect(h.count(path)).toBe(2)); // Boot and one connected wave.
  });
  it("keeps one wave in flight across later intervals with delayed deadline delivery", async () => {
    const h = await connected({ deferDeadlines: true }); const slow = deferred();
    h.overrides[TARGETS[0]] = () => slow.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS); const before = h.calls.length;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS * 2); // Two further ticks before the delayed deadline.
    expect(h.calls).toHaveLength(before);
    slow.resolve(response()); await settle();
    await vi.advanceTimersByTimeAsync(INTERVAL_MS - EDGE_MS);
    expect(h.calls).toHaveLength(before);
    await vi.advanceTimersByTimeAsync(EDGE_MS);
    TARGETS.forEach(path => expect(h.count(path)).toBe(3)); // One new wave after completion.
  });
  it.each(["mutation", "reconnect"])("serializes a %s wave arriving during a steady read", async (kind) => {
    const h = await connected(); const slow = deferred();
    h.overrides[TARGETS[0]] = () => slow.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS); const before = h.calls.length;
    let wave: Promise<unknown> | undefined;
    if (kind === "mutation") wave = h.read("fetchAll(true)");
    else { h.streams[0].error(); await vi.advanceTimersByTimeAsync(SECOND_MS); }
    await settle(); expect(h.calls).toHaveLength(before);
    slow.resolve(response()); await settle(); await wave;
    expect(h.calls.length).toBeGreaterThan(before);
    TARGETS.forEach(path => expect(h.count(path)).toBe(3)); // Boot, steady, then queued wave.
  });
  it("does not let unrelated activity defer steady reads across repeated waves", async () => {
    const h = await connected();
    for (let wave = 1; wave <= REPEATED_WAVES; wave++) {
      await vi.advanceTimersByTimeAsync(INTERVAL_MS - EDGE_MS);
      const slow = deferred(); h.overrides["/api/hub/activity"] = () => slow.promise;
      const activity = h.read('fetchAll(true, jobsForPaths(["/api/hub/activity"]))'); await settle();
      await vi.advanceTimersByTimeAsync(EDGE_MS);
      TARGETS.forEach(path => expect(h.count(path)).toBe(wave + 1));
      slow.resolve(response()); await activity;
    }
  });
  it("retries competing admission after one read budget instead of another minute", async () => {
    const h = await connected(); const slow = deferred();
    await vi.advanceTimersByTimeAsync(INTERVAL_MS - EDGE_MS);
    h.overrides[TARGETS[0]] = () => slow.promise;
    const mutation = h.read('fetchAll(true, jobsForPaths(["/api/hub/inbox"]))'); await settle();
    await vi.advanceTimersByTimeAsync(EDGE_MS);
    expect(h.count(TARGETS[1])).toBe(1); // The competing inbox owns the wave admission.
    slow.resolve(response()); await mutation;
    await vi.advanceTimersByTimeAsync(DEADLINE_MS - EDGE_MS);
    expect(h.count(TARGETS[1])).toBe(1);
    await vi.advanceTimersByTimeAsync(EDGE_MS);
    expect(h.count(TARGETS[1])).toBe(2);
    expect(h.read("DASHBOARD_STEADY_REFETCH_RETRY_MS")).toBe(DEADLINE_MS);
    const before = h.calls.length;
    await h.read('fetchAll(true, jobsForPaths(["/api/hub/inbox", "/api/hub/agents"]))');
    expect(h.calls.slice(before).map(call => call.path).sort()).toEqual([...TARGETS].sort());
  });
  it("gives coalesced mutation reads priority across repeated steady waves", async () => {
    const h = await connected({ deferDeadlines: true });
    for (let wave = 0; wave < REPEATED_WAVES; wave++) {
      const steady = deferred(); const mutation = deferred();
      h.overrides[TARGETS[0]] = () => steady.promise;
      await vi.advanceTimersByTimeAsync(INTERVAL_MS);
      const before = h.count(TARGETS[0]);
      const queued = h.read('fetchAll(true, jobsForPaths(["/api/hub/inbox"]))');
      const coalesced = h.read('fetchAll(true, jobsForPaths(["/api/hub/inbox"]))');
      await settle();
      expect(h.count(TARGETS[0])).toBe(before);
      expect(h.read("trailingPanels.size")).toBe(1); // One queued panel for both invalidations.
      h.overrides[TARGETS[0]] = () => mutation.promise;
      const completedAt = Date.now(); steady.resolve(response()); await settle();
      expect(Date.now()).toBe(completedAt);
      expect(h.count(TARGETS[0])).toBe(before + 1); // Mutation starts before the next steady timer.
      const duringMutation = h.calls.length;
      await vi.advanceTimersByTimeAsync(DEADLINE_MS - EDGE_MS);
      expect(h.calls).toHaveLength(duringMutation); // The mutation owns its read budget without overlap.
      mutation.resolve(response()); await queued; await coalesced;
      expect(h.read("trailingPanels.size")).toBe(0);
      expect(h.read("pendingPanels.size")).toBe(0);
    }
  });
  it.each(["close", "stop", "flag", "hidden"])("ends periodic reads on %s", async (transition) => {
    const h = await connected(); await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    TARGETS.forEach(path => expect(h.count(path)).toBe(2)); // Witness a real wave before teardown.
    if (transition === "close") h.streams[0].close();
    if (transition === "stop") { h.overrides["/api/health"] = () => Promise.reject(new Error("offline")); h.read("stopLiveUpdates()"); }
    if (transition === "flag") h.read("liveUpdatesStopped = true");
    if (transition === "hidden") h.visibility("hidden");
    if (transition === "close" || transition === "stop") {
      expect(h.read("steadyRefetchTimer")).toBeNull();
      expect(h.read("connectedStream")).toBeNull();
    }
    const before = h.calls.length;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS * REPEATED_WAVES);
    expect(h.calls.filter(call => call.path !== "/api/health")).toHaveLength(before);
    if (transition === "hidden") {
      h.visibility("visible"); h.visibility("visible");
      await vi.advanceTimersByTimeAsync(INTERVAL_MS);
      TARGETS.forEach(path => expect(h.count(path)).toBe(3)); // Repeated visibility delivery admits one wave.
    }
  });
  it("does not rearm after stopping an in-flight refetch", async () => {
    const h = await connected(); const slow = deferred();
    h.overrides[TARGETS[0]] = () => slow.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(2);
    h.overrides["/api/health"] = () => Promise.reject(new Error("offline"));
    h.read("stopLiveUpdates()");
    expect(h.read("steadyRefetchTimer")).toBeNull();
    expect(h.read("connectedStream")).toBeNull();
    const before = h.calls.length;
    slow.resolve(response()); await settle();
    await vi.advanceTimersByTimeAsync(INTERVAL_MS * REPEATED_WAVES);
    expect(h.calls.filter(call => call.path !== "/api/health")).toHaveLength(before);
    expect(h.read('sourceLoaded("/api/hub/inbox")')).toBe(false);
  });
  it("clears the old timer on error and rearms once on the replacement stream", async () => {
    const h = await connected();
    await vi.advanceTimersByTimeAsync(INTERVAL_MS - EDGE_MS); h.streams[0].error();
    await vi.advanceTimersByTimeAsync(SECOND_MS); // First reconnect delay.
    const before = h.calls.length; expect(h.streams).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(INTERVAL_MS * REPEATED_WAVES);
    expect(h.calls).toHaveLength(before);
    h.streams[1].open(); h.streams[1].open();
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.calls.length - before).toBe(TARGETS.length);
  });
  it("hands refresh ownership to the fallback poller", async () => {
    const h = await connected();
    await vi.advanceTimersByTimeAsync(INTERVAL_MS - DEADLINE_MS);
    h.read("schedulePolling()"); const before = h.calls.length;
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    const wave = h.calls.slice(before); expect(wave.length).toBeGreaterThan(TARGETS.length);
    TARGETS.forEach(path => expect(wave.filter(call => call.path === path)).toHaveLength(1));
    expect(h.read("steadyRefetchTimer")).toBeNull();
  });
  it.each(["reject", "timeout"])("shows existing read failure and backoff after %s, refusing late bytes", async (failure) => {
    const h = await connected(); const late = deferred();
    TARGETS.forEach(path => { h.overrides[path] = () => failure === "reject" ? Promise.reject(new Error("Fixture read unavailable")) : late.promise; });
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    if (failure === "timeout") await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    const message = failure === "timeout" ? "Read timed out. The latest result is unavailable." : "Fixture read unavailable";
    TARGETS.forEach(path => {
      expect(h.read('sourceRead(' + JSON.stringify(path) + ').state')).toBe("state_FAILED");
      expect(h.read('sourceRead(' + JSON.stringify(path) + ').failures')).toBe(1);
      expect(h.read('sourceRead(' + JSON.stringify(path) + ').nextReadAt')).toBe(Date.now() + DEADLINE_MS);
    });
    h.read('state.route = "agents"; rerender()');
    expect(h.main.innerHTML).toContain("Agent roster Unknown");
    expect(h.main.innerHTML).toContain("agent roster did not answer: " + message);
    expect(h.main.innerHTML).toContain(">Retry</button>");
    expect(h.fortress.innerHTML).toContain("Retry Decisions");
    const before = h.calls.length;
    await h.read('fetchAll(false, jobsForPaths(["/api/hub/inbox", "/api/hub/agents"]))');
    expect(h.calls).toHaveLength(before);
    if (failure === "timeout") {
      expect(h.calls.filter(call => TARGETS.includes(call.path)).slice(-TARGETS.length).every(call => call.signal?.aborted)).toBe(true);
      late.resolve(response()); await settle();
      TARGETS.forEach(path => expect(h.read('sourceRead(' + JSON.stringify(path) + ').state')).toBe("state_FAILED"));
    }
    TARGETS.forEach(path => { delete h.overrides[path]; });
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    TARGETS.forEach(path => expect(h.read('sourceRead(' + JSON.stringify(path) + ').failures')).toBe(0));
  });
  it("keeps approval decision controls and the Evidence batch toolbar stable through a loaded refresh", async () => {
    const h = await connected(); const slow = deferred();
    const item = { item_id: "held-fixture", kind: "approval_pending", tier: "tier2", resolved: false,
      created_at: new Date().toISOString(), agent_id: "agent-fixture", display_template_id: "approval_pending.tier2.tool",
      display_template_args: ["agent-fixture", "read"], operation_category: "tool" };
    h.read('state.inbox = ' + JSON.stringify([item]) + '; state.inboxOps.selected = { "held-fixture": true }; state.route = "approvals"; rerender()');
    const controls = () => {
      h.read('rerender()');
      // These shipped controls use inbox-* actions; batch controls live on Evidence, not Approvals.
      const drawer = h.main.innerHTML.match(/<aside class="card approval-drawer"[\s\S]*?<\/aside>/)?.[0];
      expect(drawer).toContain('data-action="inbox-approve"');
      expect(drawer).toContain('data-action="inbox-deny"');
      const evidence = h.read("renderEvidenceOperationsSection()") as string;
      const toolbar = evidence.match(/<div class="toolbar" style="margin-bottom:8px;">[\s\S]*?<\/div>/)?.[0];
      expect(toolbar).toContain('data-action="inbox-batch-archive"');
      return { drawer, toolbar };
    };
    const before = controls();
    h.overrides[TARGETS[0]] = () => slow.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.read('sourceRead("/api/hub/inbox").refreshing')).toBe(true);
    expect(h.read('sourceLoaded("/api/hub/inbox")')).toBe(true);
    expect(controls()).toEqual(before);
    slow.resolve(response({ data: { items: [item] } })); await settle();
    expect(h.read('sourceRead("/api/hub/inbox").refreshing')).toBe(false);
    expect(controls()).toEqual(before);
  });
  it.each(["reject", "timeout"])("recovers queued mutation and reconnect reads after a steady %s", async (failure) => {
    const h = await connected(); const slow = deferred();
    h.overrides[TARGETS[0]] = () => slow.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(2);
    const mutation = h.read('fetchAll(true, jobsForPaths(["/api/hub/inbox"]))');
    h.streams[0].error(); await vi.advanceTimersByTimeAsync(SECOND_MS);
    const before = h.calls.length;
    expect(h.read("trailingPanels.size")).toBeGreaterThan(0);
    delete h.overrides[TARGETS[0]];
    if (failure === "reject") {
      // Force loadPanel.finally to reject once, after the queued reads already captured both promises.
      h.read('const fixtureRender = rerender; rerender = function () { rerender = fixtureRender; throw new Error("Fixture render rejection"); }');
      slow.resolve(response()); await settle();
    } else await vi.advanceTimersByTimeAsync(DEADLINE_MS - SECOND_MS);
    await mutation; await settle();
    expect(h.calls.length).toBeGreaterThan(before);
    TARGETS.forEach(path => expect(h.count(path)).toBe(3));
    expect(h.read("trailingPanels.size")).toBe(0);
    expect(h.read("pendingPanels.size")).toBe(0);
    expect(h.streams).toHaveLength(2);
    h.streams[1].open(); await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    TARGETS.forEach(path => expect(h.count(path)).toBe(4));
    if (failure === "timeout") { slow.resolve(response()); await settle(); }
  });
  it("does not charge a superseded steady response against the trailing read's backoff", async () => {
    const h = await connected(); const slow = deferred();
    h.overrides[TARGETS[0]] = () => slow.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(2);
    h.streams[0].listeners.approval({ data: "{}" }); await settle();
    h.overrides[TARGETS[0]] = () => Promise.reject(new Error("Trailing fixture failure"));
    slow.resolve(response()); await settle();
    expect(h.read('sourceRead("/api/hub/inbox").failures')).toBe(1);
    expect(h.read('sourceRead("/api/hub/inbox").nextReadAt')).toBe(Date.now() + DEADLINE_MS);
  });
  it("waits for an in-flight steady wave before the fallback poller loads", async () => {
    const h = await connected({ deferDeadlines: true }); const slow = deferred();
    h.overrides[TARGETS[0]] = () => slow.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(2);
    const before = h.calls.length; h.read("schedulePolling()");
    expect(h.read("steadyRefetchTimer")).toBeNull();
    expect(h.read("connectedStream")).toBeNull();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.calls).toHaveLength(before);
    delete h.overrides[TARGETS[0]]; slow.resolve(response()); await settle();
    TARGETS.forEach(path => expect(h.count(path)).toBe(3));
    expect(h.read("steadyRefetchTimer")).toBeNull();
  });
  it("clears a silently closed stream when the timer observes its readyState", async () => {
    const h = await connected();
    expect(h.read("steadyRefetchTimer")).not.toBeNull();
    h.streams[0].readyState = 2; // Browser CLOSED state without calling close or onerror.
    const before = h.calls.length; await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.read("steadyRefetchTimer")).toBeNull();
    expect(h.read("connectedStream")).toBeNull();
    expect(h.calls).toHaveLength(before);
  });
  it("keeps empty steady jobs empty and skips not-served sources without starving due siblings", async () => {
    const h = await connected();
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    TARGETS.forEach(path => expect(h.count(path)).toBe(2));
    h.read('markSourceNotServed("/api/hub/inbox"); sourceRead("/api/hub/agents").nextReadAt = Date.now() + ' + INTERVAL_MS * 2);
    const before = h.calls.length;
    await h.read("fetchAll(false, [])");
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.calls).toHaveLength(before);
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.calls.slice(before).map(call => call.path)).toEqual([TARGETS[1]]);
    expect(h.read('sourceRead("/api/hub/inbox").state')).toBe("state_NOT_SERVED");
  });
  it("caps exponential failure backoff and honors an outstanding retry deadline", async () => {
    const h = await connected();
    TARGETS.forEach(path => { h.overrides[path] = () => Promise.reject(new Error("Fixture read unavailable")); });
    for (let wave = 1; wave <= REPEATED_WAVES; wave++) {
      await vi.advanceTimersByTimeAsync(INTERVAL_MS);
      TARGETS.forEach(path => {
        expect(h.read('sourceRead(' + JSON.stringify(path) + ').failures')).toBe(wave);
        expect(h.read('sourceRead(' + JSON.stringify(path) + ').nextReadAt') - Date.now()).toBe(Math.min(MINUTE_MS, DEADLINE_MS * 2 ** (wave - 1)));
      });
    }
    // A later source retry deadline must survive the automatic admission check.
    h.read('sourceRead("/api/hub/inbox").nextReadAt = Date.now() + ' + (INTERVAL_MS * 2));
    const agentsBefore = h.count(TARGETS[1]);
    const before = h.count(TARGETS[0]); await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(before);
    expect(h.count(TARGETS[1])).toBe(agentsBefore + 1);
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(before + 1);
  });
});

// Regression guard added after the steady-refetch change shipped: a steady response admitted under one revision is
// refused once stopLiveUpdates or a queued mutation moves the revision, and the control case proves the fixture payload
// is otherwise accepted. Witnessed first as an uncommitted box run during the gate on 2026-10-25.
const LATE_INBOX = { data: { configured: false, surfaces: [], agents: [], items: [{ id: "LATE-ITEM", severity: "high", source: "fixture", status: "pending" }], traps: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] } };
const LATE_AGENTS = { data: { configured: false, surfaces: [], agents: [{ agent_id: "LATE-AGENT", label: "late" }], items: [], traps: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] } };
describe("regression guard: a steady GET that fulfils after the revision moved is refused", () => {
  it("control: with no ownership move, the late payload IS applied", async () => {
    const h = await connected(); const slowInbox = deferred(); const slowAgents = deferred();
    h.overrides[TARGETS[0]] = () => slowInbox.promise; h.overrides[TARGETS[1]] = () => slowAgents.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(2); expect(h.count(TARGETS[1])).toBe(2);
    slowInbox.resolve(response(LATE_INBOX)); slowAgents.resolve(response(LATE_AGENTS)); await settle();
    expect(h.read("JSON.stringify(state.inbox)")).toContain("LATE-ITEM");
    expect(h.read("JSON.stringify(state.agents)")).toContain("LATE-AGENT");
  });
  it("stop: a steady GET that fulfils after stopLiveUpdates does not publish inbox or agents bytes", async () => {
    const h = await connected(); const slowInbox = deferred(); const slowAgents = deferred();
    h.overrides[TARGETS[0]] = () => slowInbox.promise; h.overrides[TARGETS[1]] = () => slowAgents.promise;
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(2); expect(h.count(TARGETS[1])).toBe(2);
    h.read("stopLiveUpdates()");
    slowInbox.resolve(response(LATE_INBOX)); slowAgents.resolve(response(LATE_AGENTS)); await settle();
    await vi.advanceTimersByTimeAsync(SECOND_MS); await settle();
    expect(h.read("JSON.stringify(state.inbox)")).not.toContain("LATE-ITEM");
    expect(h.read("JSON.stringify(state.agents)")).not.toContain("LATE-AGENT");
  });
  it("mutation: a steady GET that fulfils after queuePanel bumped the revision never publishes, before or after the trailing read", async () => {
    const h = await connected(); const slowInbox = deferred(); const trailing = deferred(); let inboxReads = 0;
    h.overrides[TARGETS[0]] = () => (inboxReads++ === 0 ? slowInbox.promise : trailing.promise);
    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(h.count(TARGETS[0])).toBe(2);
    const wave = h.read("fetchAll(true)") as Promise<unknown>;
    slowInbox.resolve(response(LATE_INBOX)); await settle();
    expect(h.read("JSON.stringify(state.inbox)")).not.toContain("LATE-ITEM");
    expect(h.count(TARGETS[0])).toBe(3); // The trailing read has started.
    trailing.resolve(response()); await settle(); await wave;
    expect(h.read("JSON.stringify(state.inbox)")).not.toContain("LATE-ITEM");
  });
});
