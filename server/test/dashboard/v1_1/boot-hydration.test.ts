/** Dashboard reads settle independently and missing evidence stays unknown. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
const DEADLINE_MS = 5 * 1000; // UI responsiveness budget, not evidence freshness.
const home = { origin_machine: "fixture-mac", agents: [], castle_wall: { arm_state: "unknown" }, digest: {}, protection_requested_count: 0, enforcement_confirmed_count: 0 };
const response = (body: unknown, status = 200) => ({ ok: status === 200, status, json: async () => body });
const pending = () => new Promise<never>(() => {});
function harness(overrides: Record<string, () => unknown> = {}, hub = "/api/hub") {
  const calls: string[] = [];
  const urls: string[] = [];
  const fortress = { innerHTML: "" };
  const streams: { onerror?: () => void; close: () => void; listeners: Record<string, (event: { data: string }) => void> }[] = [];
  const main = { innerHTML: "", querySelector: () => null, querySelectorAll: () => [] };
  const listeners: Record<string, (event: unknown) => void> = {};
  class Element {
    parentElement = null;
    getAttribute(name: string) { return name === "data-action" ? "retry-panel" : name === "data-read" ? "/api/posture/home" : null; }
    closest() { return null; }
  }
  const context = createContext({
    document: { getElementById: (id: string) => id === "main" ? main : id === "fortress" ? fortress : id === "dashboard-config" ? { textContent: JSON.stringify({ hubApiBase: hub }) } : null, addEventListener: (event: string, listener: (event: unknown) => void) => { listeners[event] = listener; }, querySelectorAll: () => [], documentElement: { setAttribute() {}, removeAttribute() {} } },
    window: { addEventListener() {} }, location: { hash: "", search: "", origin: "http://fixture" },
    sessionStorage: { getItem: () => null }, URLSearchParams, URL, AbortController, Element, Date,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {}, EventSource: class { listeners: Record<string, (event: { data: string }) => void> = {}; constructor() { streams.push(this); } close() {} addEventListener(name: string, listener: (event: { data: string }) => void) { this.listeners[name] = listener; } },
    fetch: (url: string) => {
      urls.push(url);
      const path = url.replace(/([?&])_t=[^&]*&?/, "$1").replace(/[?&]$/, ""); calls.push(path);
      if (overrides[path]) return overrides[path]();
      return Promise.resolve(response(path === "/api/posture/home" ? home : { data: { configured: false, surfaces: [], agents: [], items: [], traps: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] } }));
    },
  });
  runInContext(getClientScript(), context);
  return { calls, urls, main, fortress, streams, context, click: (target: unknown) => listeners.click({ target }), retry: () => listeners.click({ target: new Element() }) };
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
    expect(h.main.innerHTML).not.toContain("Read timed out");
    expect(h.main.innerHTML).not.toContain("Panel unavailable");
  });
  it("reports a preferences timeout and uses default filters", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/inbox/unified/prefs": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.main.innerHTML).not.toContain("Saved inbox filters");
    runInContext('state.route = "activity"; rerender()', h.context);
    expect(h.main.innerHTML).toContain("Read timed out"); expect(runInContext("state.inboxOps.filters.search", h.context)).toBe(""); expect(h.main.innerHTML).toContain("Activity");
  });
  it("keeps unavailable approvals distinct from zero", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/hub/inbox": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.main.innerHTML).toMatch(/pm-v[^>]*>Unknown<.*?pm-l[^>]*>Approvals waiting/s);
    expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you");
    expect(h.fortress.innerHTML).toContain("Retry Decisions");
  });
  it("keeps a loaded empty roster unknown while a refresh is pending", async () => {
    vi.useFakeTimers(); let refreshing = false;
    const h = harness({ "/api/hub/agents": () => refreshing ? pending() : response({ data: { agents: [] } }) }); await settle(); refreshing = true;
    runInContext('state.route = "agents"; void fetchAll()', h.context); await settle();
    expect(h.main.innerHTML).not.toContain("No protected agents yet");
    expect(h.main.innerHTML).toContain("Unknown");
    expect(h.main.innerHTML).toContain("Retry Agents");
  });
  it("never renders protective home or agent statuses with stale or invalid evidence", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-02T12:00:00Z"));
    const iso = new Date().toISOString();
    const msPerMinute = 60 * 1000;
    // Match the receiver's local clock so permissive parsing would treat this as fresh.
    const localIso = new Date(Date.now() - new Date().getTimezoneOffset() * msPerMinute).toISOString().slice(0, -1);
    for (const timestamp of ["2000-01-01T00:00:00Z", localIso, iso.replace("T", " "), "2026-02-30T12:00:00Z", "invalid"]) {
      const evidence = { last_enforcement_evidence_at: timestamp, freshness_window_ms: msPerMinute };
      const h = harness({
        "/api/hub/agents": () => response({ data: { agents: [{ agent_id: "fixture", status: "active" }] } }),
        "/api/posture/home": () => response({ ...home, castle_wall: { arm_state: "armed", ...evidence }, agents: [{ agent_id: "fixture", enforcement_active: "active", ...evidence }] }),
      });
      await settle();
      expect.soft(h.main.innerHTML, timestamp).not.toContain(">Enforcing</span>");
      expect.soft(runInContext("homeFreshnessTimer", h.context), timestamp).toBeNull();
      runInContext('state.route = "agents"; rerender()', h.context);
      expect.soft(h.main.innerHTML, timestamp).not.toMatch(/protected|state-dot live|att-agent verified|tone-verified/i);
    }
  });
  it("shares one panel deadline across dependent intelligence reads", async () => {
    vi.useFakeTimers(); const h = harness({
      "/api/hub/intelligence/status": () => new Promise(resolve => setTimeout(() => resolve(response({ data: { surfaces: [] } })), DEADLINE_MS - 1000)),
      "/api/hub/intelligence/config": pending,
    });
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.calls).toContain("/api/hub/intelligence/config");
    runInContext('state.route = "intelligence"; rerender()', h.context);
    expect(h.main.innerHTML).toContain("Read timed out");
  });
  it("does not overwrite a newly edited filter when preferences arrive late", async () => {
    vi.useFakeTimers(); let release!: (value: unknown) => void;
    const h = harness({ "/api/inbox/unified/prefs": () => new Promise(resolve => { release = resolve; }) });
    await settle(); runInContext('state.inboxOps.filters.search = "new edit"', h.context);
    release(response({ data: { filters: { search: "old saved value" } } })); await settle();
    expect(runInContext("state.inboxOps.filters.search", h.context)).toBe("new edit");
  });

  it("cannot evict an inbox failure with dynamic detail failures", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    runInContext('const originalFetch = fetch; fetch = async function (url) { if (url.includes("/posture/home")) return originalFetch(url); throw new Error("Unavailable"); }', h.context);
    await runInContext('fetchAll()', h.context);
    for (let i = 0; i < 96; i++) await runInContext('api("/agents/detail-' + i + '").catch(function () {})', h.context);
    runInContext('rerender()', h.context);
    expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you");
    expect(h.main.innerHTML).toMatch(/pm-v[^>]*>Unknown<.*?pm-l[^>]*>Approvals waiting/s);
    expect(runInContext("sourceReads.size", h.context)).toBe(20); // The fixed source inventory has twenty entries.
  });

  it("shows unavailable rather than an empty agent list after timeout", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/hub/agents": pending });
    runInContext('state.route = "agents"', h.context);
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.main.innerHTML).toContain("Unknown");
    expect(h.main.innerHTML).toContain(">Retry</button>");
    expect(h.main.innerHTML).not.toContain("No agents");
  });
  it("keeps every unread and loading rail count unknown", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/hub/agents": pending, "/api/hub/inbox": pending }); await settle();
    expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you");
    expect(h.fortress.innerHTML).not.toMatch(/>0<\/span><span class="l">(Wrapped|Waiting)/);
    expect(h.fortress.innerHTML).toContain("Retry Decisions");
  });
  it("Health and agent timeline distinguish failed reads from zero", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/hub/agents": pending, "/api/hub/activity": pending });
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    runInContext('state.route = "health"; rerender()', h.context);
    expect(h.main.innerHTML).not.toContain("<dd>0</dd>"); expect(h.main.innerHTML).toContain("Retry Activity");
    runInContext('state.agents = [{ agent_id: "fixture", status: "active" }]; state.selectedAgentId = "fixture"; state.route = "agent-detail"; rerender()', h.context);
    expect(h.main.innerHTML).not.toContain("No activity yet");
  });
  it("missing sovereignty cannot claim configured, Off, or still watching", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/sovereignty": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(runInContext('postureLayerLines().find(function (l) { return l.k === "Heralds (reputation)"; }).v', h.context)).toBe("Unknown");
    expect(h.fortress.innerHTML).not.toContain('>Off</span>'); expect(h.fortress.innerHTML).not.toContain("Sentinels still watch");
  });
  it.each(["/api/hub/intelligence/status", "/api/hub/recognition/did-web", "/api/hub/agents"])("settled malformed %s gets unavailable and Retry", async path => {
    vi.useFakeTimers(); const h = harness({ [path]: () => response({}) }); await settle();
    runInContext('state.route = "' + (path.includes("intelligence") ? "intelligence" : path.includes("recognition") ? "policy" : "agents") + '"; rerender()', h.context);
    const html = path.includes("recognition") ? runInContext('renderRecognitionHealthCard()', h.context) : h.main.innerHTML;
    expect(html).toContain("Retry"); expect(html).not.toMatch(/Loading (substrate|Recognition)/);
    expect(html).toContain("unavailable");
  });
  it("cache busts each anomaly fetch", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    expect(h.urls.find(url => url.includes("/api/anomaly/findings"))).toMatch(/[?&]_t=/);
  });
  it.each([503, 401])("Intelligence HTTP %s stays local and preserves guidance", async status => {
    vi.useFakeTimers(); const h = harness({ "/api/hub/intelligence/status": () => ({ ok: false, status, json: async () => { throw new Error("proxy html"); } }) }); await settle();
    expect(h.main.innerHTML).not.toContain("Intelligence:");
    runInContext('state.route = "intelligence"; rerender()', h.context);
    expect(h.main.innerHTML).toMatch(status === 503 ? /Pick a model/i : /authentication required/i);
    expect(h.main.innerHTML).not.toContain("proxy html"); expect(h.main.innerHTML).toContain("Retry Intelligence");
  });
  it.each([404, 422])("chat HTTP %s keeps history and errors inside the chat panel", async status => {
    vi.useFakeTimers(); let failed = false;
    const h = harness({ "/api/hub/chat/concierge/history": () => response(failed ? {} : { data: { messages: [{ role: "operator", content: "keep this" }] } }, failed ? status : 200) }); await settle(); failed = true;
    await runInContext('fetchAll()', h.context);
    expect(runInContext('state.chat.concierge.messages.length', h.context)).toBe(1);
    expect(h.main.innerHTML).not.toContain("Conversation history");
    runInContext('state.route = "dashboard"; rerender()', h.context);
    expect(h.main.innerHTML).toContain("Retry Conversation history");
  });
  it("recommendations failure preserves independently loaded rules", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/auto-trigger/rules": () => response({ data: { rules: [{ rule_id: "fixture-rule" }] } }), "/api/auto-trigger/recommendations": () => response({}, 503), "/api/auto-trigger/rules/fixture-rule": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    runInContext('state.route = "auto-trigger"; rerender()', h.context);
    expect(h.main.innerHTML).toContain("fixture-rule"); expect(h.main.innerHTML).toContain("Retry Recommendations");
    expect(h.main.innerHTML).not.toContain("No recent action attempts");
  });
  it.each([401,403,503])("policy HTTP %s preserves panel explanation", async status => {
    vi.useFakeTimers(); const h = harness({ "/api/policy/current": () => response({}, status) }); await settle();
    await runInContext('state.route = "policy"; loadPolicyView()', h.context);
    expect(h.main.innerHTML).toMatch(status === 503 ? /Policy engine is not configured/ : /Operator token required/);
    expect(h.main.innerHTML).toContain("Retry Operator policy");
  });
  it("absolute hub base keeps unavailable counts and a working Retry", async () => {
    vi.useFakeTimers(); let fail = true; const hub = "https://remote.invalid/api/hub";
    const h = harness({ [hub + "/inbox"]: () => fail ? response({}, 500) : response({ data: { items: [] } }) }, hub); await settle();
    expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you"); fail = false;
    await runInContext('retryPanel(HUB + "/inbox")', h.context);
    expect(h.fortress.innerHTML).toContain("Nothing waiting on you");
  });
  it("post-mutation refresh performs a trailing read after an older in-flight read", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    runInContext('let releaseOld; let reads = 0; fetch = async function (url) { if (url.includes("/inbox")) { reads++; if (reads === 1) return new Promise(function (resolve) { releaseOld = resolve; }); } return { ok: true, status: 200, json: async function () { return { data: { items: [], agents: [], entries: [], policies: [] } }; } }; }; void fetchAll()', h.context); await settle();
    runInContext('void onInboxAction("x", "approve")', h.context); await settle();
    runInContext('releaseOld({ ok: true, status: 200, json: async function () { return { data: { items: [{item_id: "obsolete"}] } }; } })', h.context); await settle();
    expect(runInContext('state.inbox', h.context)).toEqual([]);
  });
  it("backs off failed automatic reads while manual Retry bypasses the delay", async () => {
    vi.useFakeTimers(); let n = 0; const h = harness({ "/api/posture/home": () => { n++; return response({}, 500); } }); await settle();
    await runInContext('fetchAll()', h.context); expect(n).toBe(1);
    await runInContext('retryPanel("/api/posture/home")', h.context); expect(n).toBe(2);
    await vi.advanceTimersByTimeAsync(DEADLINE_MS); await runInContext('fetchAll()', h.context); expect(n).toBe(2);
  });
  it("caps stream reconnect attempts with increasing delays", async () => {
    vi.useFakeTimers(); const h = harness(); await settle(); const first = h.streams.length;
    runInContext('fetch = async function () { throw new Error("offline"); }', h.context);
    h.streams.at(-1)?.onerror?.(); await vi.advanceTimersByTimeAsync(1000); expect(h.streams.length).toBe(first + 1);
    h.streams.at(-1)?.onerror?.(); await vi.advanceTimersByTimeAsync(1000); expect(h.streams.length).toBe(first + 1);
    await vi.advanceTimersByTimeAsync(1000);
    for (let i = 0; i < 10; i++) { h.streams.at(-1)?.onerror?.(); await vi.advanceTimersByTimeAsync(60_000); }
    expect(h.streams.length).toBeLessThanOrEqual(first + 5);
  });
  it("gives Retry a panel-specific accessible name", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/posture/home": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    expect(h.main.innerHTML).toContain('aria-label="Retry Protection status"');
  });
  it("announces error text without placing the control in its live region", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/posture/home": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    const regions = [...h.main.innerHTML.matchAll(/<([a-z]+)[^>]*role="(?:status|alert)"[^>]*>([\s\S]*?)<\/\1>/g)];
    expect(regions.length).toBeGreaterThan(0);
    for (const region of regions) expect(region[2]).not.toContain("<button");
  });
  it("does not capture Retry buttons during main content replacement", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/posture/home": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    runInContext('let focused = false; document.activeElement = { tagName: "BUTTON", getAttribute: function (key) { return key === "data-action" ? "retry-panel" : key === "data-read" ? "/api/posture/home" : null; } }; document.getElementById("main").querySelector = function (selector) { return selector.includes("retry-panel") && selector.includes("data-read") ? { focus: function () { focused = true; } } : null; }; state.posture.homeError = "new error"; rerender()', h.context);
    expect(runInContext('focused', h.context)).toBe(false);
  });
  it("fresh home evidence expires without a refresh and unread evidence never becomes Enforcing", async () => {
    vi.useFakeTimers(); const timestamp = new Date().toISOString(); let hang = false;
    const h = harness({ "/api/posture/home": () => hang ? pending() : response({ ...home, castle_wall: { arm_state: "armed", last_enforcement_evidence_at: timestamp, freshness_window_ms: 1000 } }) }); await settle();
    expect(h.main.innerHTML).toContain(">Enforcing</span>");
    await vi.advanceTimersByTimeAsync(1001); expect(h.main.innerHTML).not.toContain(">Enforcing</span>");
    hang = true; runInContext('void fetchAll()', h.context); await settle();
    expect(h.main.innerHTML).not.toContain(">Enforcing</span>");
  });
  it("a fresh loaded seal becomes Unknown while its refresh is pending", async () => {
    vi.useFakeTimers(); let hang = false;
    const h = harness({ "/api/sovereignty": () => hang ? pending() : response({ live_enforcement: { castle_wall_arm_state: "armed", last_enforcement_evidence_at: new Date().toISOString(), freshness_window_ms: 60_000 } }) }); await settle();
    expect(runInContext('deriveSeal().word', h.context)).toBe("Protected"); hang = true;
    runInContext('void fetchAll()', h.context); await settle();
    expect(runInContext('deriveSeal().word', h.context)).toBe("Unknown");
  });
  it("missing per-agent freshness cannot borrow the machine timestamp", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/posture/home": () => response({ ...home, castle_wall: { arm_state: "armed", last_enforcement_evidence_at: new Date().toISOString(), freshness_window_ms: 60_000 }, agents: [{ agent_id: "fixture", enforcement_active: "active" }] }) }); await settle();
    const html = runInContext('renderPostureAgentRows(state.posture.home)', h.context);
    expect(html).not.toContain(">Enforcing</span>");
  });
  it("anomaly 503 stays local and cannot render a checked empty detector", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/anomaly/findings": () => response({}, 503) }); await settle();
    expect(h.main.innerHTML).toContain("fixture-mac"); expect(h.main.innerHTML).not.toContain("detector answered");
    expect(h.main.innerHTML).toContain("Retry Anomaly findings");
    runInContext('state.route = "agents"; rerender()', h.context); expect(h.main.innerHTML).not.toContain("Anomaly findings");
  });
  it("a hung stream session exchange starts bounded fallback at its deadline", async () => {
    vi.useFakeTimers(); const h = harness({ "/auth/session": pending }); await settle();
    const before = h.calls.filter(path => path === "/api/posture/home").length;
    runInContext('TOKEN = "fixture"; connectStream()', h.context);
    await vi.advanceTimersByTimeAsync(DEADLINE_MS * 2);
    expect(h.calls.filter(path => path === "/api/posture/home").length).toBe(before + 1);
  });
  it("stream-triggered rule failure is contained by the panel loader", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    runInContext('fetch = async function () { throw new Error("offline"); }', h.context);
    h.streams.at(-1)!.listeners.activity({ data: JSON.stringify({ entry_id: "rule-event", display_template_id: "auto_trigger.changed" }) });
    await settle();
    runInContext('state.route = "auto-trigger"; rerender()', h.context);
    expect(h.main.innerHTML).toContain("Retry Auto-trigger");
  });
  it("keeps later rule details unavailable when the shared deadline runs out", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/auto-trigger/rules": () => response({ data: { rules: [{ rule_id: "first" }, { rule_id: "later" }] } }), "/api/auto-trigger/rules/first": pending });
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    runInContext('state.route = "auto-trigger"; rerender()', h.context);
    expect(h.calls).not.toContain("/api/auto-trigger/rules/later");
    expect(h.main.innerHTML).toContain("later"); expect(h.main.innerHTML).not.toContain("No recent action attempts");
    expect(h.main.innerHTML).toContain("Retry Rule details");
  });
  it("starts home and sovereignty before optional panel reads", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    expect(h.calls.indexOf("/api/posture/home")).toBeLessThan(h.calls.indexOf("/api/hub/agents"));
    expect(h.calls.indexOf("/api/sovereignty")).toBeLessThan(h.calls.indexOf("/api/hub/agents"));
  });

  it("policy activation does not reuse a pre-activation policy read", async () => {
    vi.useFakeTimers(); let release!: (value: unknown) => void; let reads = 0;
    const h = harness({
      "/api/policy/current": () => ++reads === 1 ? new Promise(resolve => { release = resolve; }) : response({ data: { view: { lines: [], marker: "new" } } }),
      "/api/policy/drafts/fixture/activate": () => response({ data: { status: "activated" } }),
    }); await settle();
    runInContext('state.route = "policy"; void loadPolicyView()', h.context); await settle();
    runInContext('void activateStandingRule("fixture", "fixture-op", false)', h.context); await settle();
    release(response({ data: { view: { lines: [], marker: "old" } } })); await settle();
    expect(runInContext('state.policyView.view.marker', h.context)).toBe("new"); expect(reads).toBe(2);
  });
  it("recognition mutation cannot be overwritten by a pre-mutation health read", async () => {
    vi.useFakeTimers(); let release!: (value: unknown) => void; let reads = 0;
    const h = harness({
      "/api/hub/recognition/did-web": () => ++reads === 1 ? new Promise(resolve => { release = resolve; }) : response({ data: { configured: false, marker: "new" } }),
      "/api/hub/recognition/did-web/rotate-compromised": () => response({ data: { health: { configured: false, marker: "new" } } }),
    }); await settle();
    runInContext('void onDidWebCompromisedRotation()', h.context); await settle();
    release(response({ data: { configured: false, marker: "old" } })); await settle();
    expect(runInContext('state.recognition.health.marker', h.context)).toBe("new"); expect(reads).toBe(2);
  });

  it("a settled sovereignty timeout has an unavailable popover with Retry", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/sovereignty": pending }); await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    runInContext('const sealEls = {}; ["posture-seal", "posture-seal-word", "posture-seal-freshness", "posture-seal-pop"].forEach(function (id) { sealEls[id] = { innerHTML: "", textContent: "", classList: { add: function () {}, remove: function () {} }, setAttribute: function () {} }; }); const originalGet = document.getElementById; document.getElementById = function (id) { return sealEls[id] || originalGet(id); }; state.posture.sealOpen = true; renderPostureSeal()', h.context);
    const popover = runInContext('sealEls["posture-seal-pop"].innerHTML', h.context);
    expect(popover).not.toContain("Posture is being checked");
    expect(popover).toContain("Retry Protection evidence");
  });
  it("a loaded roster lifecycle flag cannot claim Protected without agent evidence", async () => {
    vi.useFakeTimers(); const h = harness({ "/api/hub/agents": () => response({ data: { agents: [{ agent_id: "fixture", status: "active" }] } }) }); await settle();
    runInContext('state.route = "agents"; rerender()', h.context);
    expect(h.main.innerHTML).not.toMatch(/agent-state[^]*?Protected/);
    expect(h.main.innerHTML).toContain("Unknown");
  });

});


/** D5: decisions, focus, evidence and live refresh keep their read-state contract. */
describe("D5 closure", () => {
  it.each(["approve", "deny"])("keeps the queue visible while %s is pending or rejected", async action => {
    vi.useFakeTimers(); let reject!: (reason: Error) => void;
    const h = harness({ ["/api/hub/inbox/fixture/" + action]: () => new Promise((_, r) => { reject = r; }) }); await settle();
    runInContext(`
      let hidden = false;
      const count = { textContent: "1", classList: { add() {} } };
      const get = document.getElementById;
      document.getElementById = id => id === "queue-count" ? count : get(id);
      const tile = { classList: { add() { hidden = true; } } };
      const button = new Element();
      button.getAttribute = key => key === "data-action" ? "inbox-${action}" : key === "data-item-id" ? "fixture" : null;
      button.closest = selector => selector === ".approval-tile" ? tile : null;
    `, h.context);
    h.click(runInContext('button', h.context)); await settle();
    expect(runInContext('count.textContent', h.context)).toBe("1"); expect(runInContext('hidden', h.context)).toBe(false);
    reject(new Error("fixture rejection")); await settle();
    expect(runInContext('count.textContent', h.context)).toBe("1"); expect(runInContext('hidden', h.context)).toBe(false);
  });
  it.each(["BUTTON", "INPUT"])("never restores a decision %s onto another inbox row", async tag => {
    vi.useFakeTimers(); const h = harness(); await settle();
    runInContext(`
      let focusedItem = null;
      state.route = "activity";
      state.inbox = [{ item_id: "first", status: "pending" }, { item_id: "second", status: "pending" }];
      document.activeElement = { tagName: "${tag}", type: "checkbox", getAttribute: key => key === "data-action" ? "inbox-deny" : key === "data-item-id" ? "second" : null };
      document.getElementById("main").querySelector = () => ({ focus() { focusedItem = "first"; } });
      rerender();
    `, h.context);
    expect(runInContext('focusedItem', h.context)).toBeNull();
  });
  it("requires loaded matching posture evidence for all protective agent chrome", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    runInContext(`
      state.agents = [{ agent_id: "fixture", status: "active", last_enforcement_evidence_at: new Date().toISOString(), freshness_window_ms: 60000 }];
      state.selectedAgentId = "fixture";
      state.chat.inspect.panelByAgentId.fixture = { recent_activity: [], pending_approvals: [] };
      state.route = "agents"; rerender();
    `, h.context);
    const rendered = () => h.main.innerHTML + runInContext('renderAgentInspectPanel(state.agents[0])', h.context);
    expect(rendered()).not.toMatch(/protected|state-dot live|att-agent verified|tone-verified/i);
    runInContext(`state.posture.home.agents = [{ agent_id: "other", enforcement_active: "active", last_enforcement_evidence_at: new Date().toISOString(), freshness_window_ms: 60000 }]; rerender()`, h.context);
    expect(rendered()).not.toMatch(/protected|state-dot live|att-agent verified|tone-verified/i);
    runInContext('state.posture.home.agents[0].agent_id = "fixture"; rerender()', h.context);
    expect(rendered()).toContain('state-dot live'); expect(rendered()).toMatch(/protected/i);
    runInContext('sourceRead("/api/posture/home").state = "state_LOADING"; rerender()', h.context);
    expect(rendered()).not.toMatch(/protected|state-dot live|att-agent verified|tone-verified/i);
    runInContext('sourceRead("/api/posture/home").state = "state_LOADED"; state.posture.home.agents[0].last_enforcement_evidence_at = "2000-01-01T00:00:00Z"; rerender()', h.context);
    expect(rendered()).not.toMatch(/protected|state-dot live|att-agent verified|tone-verified/i);
  });
  it.each(["stream", "polling"])("shows stopped %s updates on every route until Retry", async mode => {
    vi.useFakeTimers(); const h = harness(); await settle();
    runInContext('fetch = async function () { throw new Error("offline"); }', h.context);
    if (mode === "stream") {
      for (let i = 0; i < 6; i++) { h.streams.at(-1)!.onerror!(); await vi.advanceTimersByTimeAsync(60_000); }
    } else { runInContext('schedulePolling()', h.context); await vi.advanceTimersByTimeAsync(180_000); }
    for (const route of ["dashboard", "activity", "posture", "agents", "agent-detail", "policy", "auto-trigger", "intelligence", "attestation", "honeypot", "privacy", "coordination", "health", "exit-drill"]) {
      runInContext('state.route = "' + route + '"; rerender()', h.context);
      expect(h.main.innerHTML).toContain("Live updates stopped"); expect(h.main.innerHTML).toContain(">Retry</button>");
      expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you");
      expect(runInContext('sourceLoaded(HUB + "/inbox")', h.context)).toBe(false);
    }
    runInContext('fetch = async function (url) { const path = String(url).replace(/([?&])_t=[^&]*&?/, "$1").replace(/[?&]$/, ""); return { ok: true, status: 200, json: async function () { return path === "/api/posture/home" ? { origin_machine: "fixture-mac", agents: [], castle_wall: { arm_state: "unknown" }, digest: {}, protection_requested_count: 0, enforcement_confirmed_count: 0 } : { data: { configured: false, surfaces: [], agents: [], items: [], traps: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] }, live_enforcement: { castle_wall_arm_state: "unknown" } }; } }; }', h.context);
    const before = h.streams.length; h.retry(); await settle();
    expect(h.streams.length).toBe(before + 1); expect(h.main.innerHTML).not.toContain("Live updates stopped");
    expect(h.fortress.innerHTML).toContain("Nothing waiting on you");
  });
  it.each(["approval", "inbox", "reconnect", "polling"])("%s queues a fresh read behind an older read", async trigger => {
    vi.useFakeTimers(); let reads = 0; let pollingBoot = trigger === "polling"; let old!: (value: unknown) => void; let fresh!: (value: unknown) => void;
    const h = harness({ "/api/hub/inbox": () => pollingBoot ? response({ data: { items: [] } }) : ++reads === 1 ? new Promise(r => { old = r; }) : new Promise(r => { fresh = r; }) }); await settle();
    if (trigger === "reconnect") { h.streams.at(-1)!.onerror!(); await vi.advanceTimersByTimeAsync(1000); }
    else if (trigger === "polling") { runInContext('schedulePolling()', h.context); await vi.advanceTimersByTimeAsync(1000); pollingBoot = false; runInContext('void fetchAll()', h.context); await settle(); await vi.advanceTimersByTimeAsync(DEADLINE_MS - 1000); }
    else h.streams.at(-1)!.listeners[trigger]({ data: JSON.stringify({ item_id: "new", entry_id: "new", status: "pending" }) });
    await settle(); old(response({ data: { items: [] } })); await settle();
    expect(reads).toBe(2); expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you");
    expect(runInContext('sourceLoaded(HUB + "/inbox")', h.context)).toBe(false);
    fresh(response({ data: { items: [{ item_id: "new", status: "pending" }] } })); await settle();
    expect(runInContext('state.inbox.map(item => item.item_id)', h.context)).toEqual(["new"]);
    expect(runInContext('sourceLoaded(HUB + "/inbox")', h.context)).toBe(true);
  });
  it("expires agent badges without borrowing the wall freshness timer", async () => {
    vi.useFakeTimers();
    const h = harness({
      "/api/hub/agents": () => response({ data: { agents: [{ agent_id: "fixture", status: "active" }] } }),
      "/api/posture/home": () => response({ ...home, agents: [{ agent_id: "fixture", enforcement_active: "active", last_enforcement_evidence_at: new Date().toISOString().replace("Z", "+00:00"), freshness_window_ms: 1000 }] }),
    }); await settle(); runInContext('state.route = "agents"; rerender()', h.context);
    expect(h.main.innerHTML).toContain('state-dot live');
    await vi.advanceTimersByTimeAsync(1001);
    expect(h.main.innerHTML).not.toMatch(/protected|state-dot live|att-agent verified/i);
  });
  it("coalesces event bursts and invalidates the next read when a later event arrives", async () => {
    vi.useFakeTimers(); const releases: ((value: unknown) => void)[] = [];
    const h = harness({ "/api/hub/inbox": () => new Promise(r => releases.push(r)) }); await settle();
    const event = () => h.streams.at(-1)!.listeners.approval({ data: "{}" });
    for (let i = 0; i < 20; i++) event();
    await settle(); expect(releases).toHaveLength(1);
    releases[0](response({ data: { items: [] } })); await settle(); expect(releases).toHaveLength(2);
    event(); releases[1](response({ data: { items: [] } })); await settle();
    expect(releases).toHaveLength(3); expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you");
    releases[2](response({ data: { items: [{ item_id: "latest", status: "pending" }] } })); await settle();
    expect(runInContext('state.inbox[0].item_id', h.context)).toBe("latest");
  });
  it("does not publish an old clear while the trailing read fails", async () => {
    vi.useFakeTimers(); let reads = 0; let release!: (value: unknown) => void;
    const h = harness({ "/api/hub/inbox": () => ++reads === 1 ? new Promise(r => { release = r; }) : response({}, 500) }); await settle();
    h.streams.at(-1)!.listeners.approval({ data: "{}" }); release(response({ data: { items: [] } })); await settle();
    expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you"); expect(h.fortress.innerHTML).toContain("Retry Decisions");
    expect(runInContext('sourceRead(HUB + "/inbox").state', h.context)).toBe("state_FAILED");
  });
  it("event bursts do not demote loaded posture or discard a slow posture read", async () => {
    vi.useFakeTimers(); let releaseHome!: (value: unknown) => void; let inboxReads = 0;
    const h = harness({
      "/api/posture/home": () => new Promise(resolve => { releaseHome = resolve; }),
      "/api/hub/inbox": () => ++inboxReads === 1 ? response({ data: { items: [] } }) : pending(),
      "/api/sovereignty": () => response({ live_enforcement: { castle_wall_arm_state: "armed", last_enforcement_evidence_at: new Date().toISOString(), freshness_window_ms: 60_000 } }),
    }); await settle();
    expect(runInContext('sourceLoaded("/api/sovereignty")', h.context)).toBe(true);
    expect(h.fortress.innerHTML).toContain("Nothing waiting on you");
    for (let i = 0; i < 20; i++) h.streams.at(-1)!.listeners.inbox({ data: JSON.stringify({ item_id: "burst-" + i }) });
    await settle();
    expect(runInContext('sourceLoaded("/api/sovereignty")', h.context)).toBe(true);
    expect(h.fortress.innerHTML).not.toContain("Nothing waiting on you");
    releaseHome(response({ ...home, origin_machine: "slow-home-loaded" })); await settle();
    expect(runInContext('sourceLoaded("/api/posture/home")', h.context)).toBe(true);
    expect(h.main.innerHTML).toContain("slow-home-loaded");
  });
  it("separated stream outages keep reconnecting after loaded recovery refreshes", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    for (let i = 0; i < 6; i++) {
      const before = h.streams.length;
      h.streams.at(-1)!.onerror!();
      await vi.advanceTimersByTimeAsync(1000);
      await settle();
      expect(h.streams.length).toBe(before + 1);
      expect(h.main.innerHTML).not.toContain("Live updates stopped");
    }
  });
  it("healthy polling waves do not spend the stopped-live-update budget", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    runInContext('schedulePolling()', h.context);
    for (let i = 0; i < 6; i++) {
      await vi.advanceTimersByTimeAsync(DEADLINE_MS);
      await settle();
      expect(h.main.innerHTML).not.toContain("Live updates stopped");
    }
  });
  it("Retry clears stopped-update text from saved filters and policy views", async () => {
    vi.useFakeTimers(); const h = harness(); await settle();
    for (let i = 0; i < 6; i++) { h.streams.at(-1)!.onerror!(); await vi.advanceTimersByTimeAsync(60_000); }
    h.retry(); await settle();
    for (const route of ["activity", "policy"]) {
      runInContext('state.route = "' + route + '"; rerender()', h.context);
      expect(h.main.innerHTML).not.toContain("Live updates stopped");
    }
  });
  it("uses demo-safe wording for agents and posture rows", async () => {
    vi.useFakeTimers(); const h = harness({
      "/api/hub/agents": () => response({ data: { agents: [{ agent_id: "fixture", status: "active", harness: "codex", model_provider: { vendor: "OpenAI", model_id: "gpt" }, policy_id: "default" }] } }),
      "/api/posture/home": () => response({ ...home, agents: [{ agent_id: "fixture", status: "active", harness: "codex", policy_protected: false, enforcement_active: "unknown" }] }),
    }); await settle();
    runInContext('state.route = "health"; rerender()', h.context);
    expect(h.main.innerHTML).toContain("<dt>Wrapped agents</dt>");
    expect(h.main.innerHTML).not.toContain("<dt>Protected agents</dt>");
    runInContext('state.route = "agents"; rerender()', h.context);
    expect(h.main.innerHTML).toContain("1 agent. Click one");
    expect(h.main.innerHTML).not.toContain("1 agents.");
    runInContext('state.route = "posture"; rerender()', h.context);
    expect(h.main.innerHTML).toContain("Not protected");
    expect(h.main.innerHTML).not.toContain("status active");
  });
  it("agent_status events re-read the roster instead of mutating it locally", async () => {
    vi.useFakeTimers(); let reads = 0; let release!: (value: unknown) => void;
    const h = harness({ "/api/hub/agents": () => ++reads === 1 ? response({ data: { agents: [{ agent_id: "fixture", status: "active" }] } }) : new Promise(resolve => { release = resolve; }) }); await settle();
    h.streams.at(-1)!.listeners.agent_status({ data: JSON.stringify({ agent_id: "fixture", status: "locked_down", last_activity_at: "now" }) });
    await settle();
    expect(reads).toBe(2);
    expect(runInContext('state.agents[0].status', h.context)).toBe("active");
    release(response({ data: { agents: [{ agent_id: "fixture", status: "locked_down" }] } })); await settle();
    expect(runInContext('state.agents[0].status', h.context)).toBe("locked_down");
  });

});
