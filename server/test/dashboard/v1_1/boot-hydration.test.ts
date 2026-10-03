/** Dashboard reads settle independently and missing evidence stays unknown. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
const DEADLINE_MS = 5 * 1000; // UI responsiveness budget, not evidence freshness.
const home = { origin_machine: "fixture-mac", agents: [], castle_wall: { arm_state: "unknown" }, digest: {}, protection_requested_count: 0, enforcement_confirmed_count: 0 };
const response = (body: unknown, status = 200) => ({ ok: status === 200, status, json: async () => body });
const pending = () => new Promise<never>(() => {});
function harness(overrides: Record<string, () => unknown> = {}) {
  const calls: string[] = [];
  const main = { innerHTML: "", querySelector: () => null, querySelectorAll: () => [] };
  const listeners: Record<string, (event: unknown) => void> = {};
  class Element {
    parentElement = null;
    getAttribute(name: string) { return name === "data-action" ? "retry-panel" : name === "data-read" ? "/api/posture/home" : null; }
    closest() { return null; }
  }
  const context = createContext({
    document: { getElementById: (id: string) => id === "main" ? main : null, addEventListener: (event: string, listener: (event: unknown) => void) => { listeners[event] = listener; }, querySelectorAll: () => [], documentElement: { setAttribute() {}, removeAttribute() {} } },
    window: { addEventListener() {} }, location: { hash: "", search: "", origin: "http://fixture" },
    sessionStorage: { getItem: () => null }, URLSearchParams, URL, AbortController, Element, Date,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {}, EventSource: class { addEventListener() {} },
    fetch: (url: string) => {
      const path = url.replace(/([?&])_t=[^&]*&?/, "$1").replace(/[?&]$/, ""); calls.push(path);
      if (overrides[path]) return overrides[path]();
      return Promise.resolve(response(path === "/api/posture/home" ? home : { data: { agents: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] } }));
    },
  });
  runInContext(getClientScript(), context);
  return { calls, main, context, retry: () => listeners.click({ target: new Element() }) };
}
async function settle() { for (let i = 0; i < 100; i++) await Promise.resolve(); } // Finite boot microtask drain.
afterEach(() => vi.useRealTimers());
describe("dashboard bounded independent hydration", () => {
  it.each(["/api/inbox/unified/prefs", "/api/hub/agents"])("renders Posture while %s never settles", async (path) => {
    vi.useFakeTimers(); const h = harness({ [path]: pending }); await settle();
    expect(h.calls).toContain("/api/posture/home"); expect(h.main.innerHTML).toContain("fixture-mac");
  });
  it("replaces loading with unavailable and Retry at the deadline, keeping Unknown", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/posture/home": pending, "/api/sovereignty": pending });
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.main.innerHTML).toContain("Protection status unavailable"); expect(h.main.innerHTML).toContain(">Retry</button>");
    expect(h.main.innerHTML).not.toContain("Loading posture detail"); expect(runInContext("deriveSeal().word", h.context)).toBe("Unknown");
  });
  it("bounds response-body consumption too", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/posture/home": () => Promise.resolve({ ok: true, status: 200, json: pending }) });
    await vi.advanceTimersByTimeAsync(DEADLINE_MS); expect(h.main.innerHTML).toContain("Protection status unavailable");
  });
  it("publishes home without waiting for anomaly findings", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/anomaly/findings": pending }); await settle();
    expect(h.main.innerHTML).toContain("fixture-mac"); expect(h.main.innerHTML).toContain("not a confirmation of zero findings");
    await vi.advanceTimersByTimeAsync(DEADLINE_MS); expect(h.main.innerHTML).toContain(">Retry</button>");
  });
  it.each([401, 403, 500])("shows an honest HTTP %s failure", async (status) => {
    vi.useFakeTimers(); const h = harness({ "/api/posture/home": () => Promise.resolve(response({ error: "no" }, status)) }); await settle();
    expect(h.main.innerHTML).toContain("Protection status unavailable"); expect(h.main.innerHTML).toContain("HTTP " + status);
  });
  it("rejects invalid JSON without showing healthy evidence", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/posture/home": () => Promise.resolve({ ok: true, status: 200, json: async () => { throw new Error("Invalid JSON"); } }) }); await settle();
    expect(h.main.innerHTML).toContain("Protection status unavailable");
  });
  it("retries only the selected panel, single-flight, and ignores a late old response", async () => {
    vi.useFakeTimers(); let release!: (value: unknown) => void; let attempts = 0;
    const h = harness({ "/api/posture/home": () => ++attempts === 1 ? new Promise(resolve => { release = resolve; }) : Promise.resolve(response(home)) });
    await vi.advanceTimersByTimeAsync(DEADLINE_MS); const callsBefore = h.calls.length; h.retry(); h.retry(); await settle();
    expect(h.calls.length - callsBefore).toBe(1); expect(h.main.innerHTML).toContain("fixture-mac");
    release(response({ ...home, origin_machine: "obsolete" })); await settle();
    expect(h.main.innerHTML).not.toContain("obsolete"); expect(h.main.innerHTML).not.toContain("Protection status unavailable");
  });
  it("reports a preferences timeout and uses default filters", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/inbox/unified/prefs": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.main.innerHTML).toContain("Read timed out"); expect(runInContext("state.inboxOps.filters.search", h.context)).toBe(""); expect(h.main.innerHTML).toContain("fixture-mac");
  });
  it("keeps unavailable approvals distinct from zero", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/hub/inbox": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.main.innerHTML).toContain("Unknown"); expect(h.main.innerHTML).toContain("Approvals waiting");
  });
  it("keeps a valid empty roster honest", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    expect(h.main.innerHTML).toContain("No agents protected yet");
    expect(runInContext("deriveSeal().word", h.context)).toBe("Unknown");
  });
  it("never promotes stale enforcement evidence to Protected", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/sovereignty": () => Promise.resolve(response({ live_enforcement: { castle_wall_arm_state: "armed", evidence_basis: "fresh_enforcement_evidence", last_enforcement_evidence_at: "2000-01-01T00:00:00Z", freshness_window_ms: 60 * 1000 } })) });
    await settle(); expect(runInContext("deriveSeal().word", h.context)).not.toBe("Protected");
  });
  it("shares one panel deadline across dependent intelligence reads", async () => {
    vi.useFakeTimers(); const h = harness({
      "/api/hub/intelligence/status": () => new Promise(resolve => setTimeout(() => resolve(response({ data: {} })), DEADLINE_MS - 1000)),
      "/api/hub/intelligence/config": pending,
    });
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.calls).toContain("/api/hub/intelligence/config");
    expect(h.main.innerHTML).toContain("Intelligence: Read timed out");
  });
  it("does not overwrite a newly edited filter when preferences arrive late", async () => {
    vi.useFakeTimers(); let release!: (value: unknown) => void;
    const h = harness({ "/api/inbox/unified/prefs": () => new Promise(resolve => { release = resolve; }) });
    await settle(); runInContext('state.inboxOps.filters.search = "new edit"', h.context);
    release(response({ data: { filters: { search: "old saved value" } } })); await settle();
    expect(runInContext("state.inboxOps.filters.search", h.context)).toBe("new edit");
  });

  it("bounds retained failures across many distinct failed detail reads", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    runInContext('fetch = async function () { throw new Error("Unavailable"); }', h.context);
    const limit = runInContext("MAX_RETAINED_READ_FAILURES", h.context) as number;
    for (let i = 0; i < limit * 3; i++) await runInContext('api("/agents/detail-' + i + '").catch(function () {})', h.context);
    expect(runInContext("readFailures.size", h.context)).toBe(limit);
    expect(runInContext('readFailures.has("/api/hub/agents/detail-0")', h.context)).toBe(false);
  });

  it("shows unavailable rather than an empty agent list after timeout", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/hub/agents": pending });
    runInContext('state.route = "agents"', h.context);
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.main.innerHTML).toContain("Current panel data is unavailable");
    expect(h.main.innerHTML).toContain(">Retry</button>");
    expect(h.main.innerHTML).not.toContain("No agents");
  });

});
