/**
 * Console first-run polish: wired witnesses for four operator-visible behaviours of the v1.1 console.
 *
 * Each test boots the real client script in a minimal DOM, lets its reads settle against fixture responses and
 * drives the real listeners:
 *  - a read the server refuses for want of an operator token shows a Paste operator token control in the feedback
 *    row; saving a pasted token stores it in session storage, empties the field and reloads, and the token never
 *    appears in the page, a URL, a request path or the console; an empty entry stores nothing and says so;
 *  - the Overview's open-findings tile and Findings card never read 0 while the Findings screen lists Sentinel
 *    findings whose lifecycle is not served;
 *  - a hash route change opens the new screen at the top of #main, while a redraw or a filter change on the same
 *    screen keeps the reader's place;
 *  - the approval drawer says "Always allow is unavailable" once, not twice.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

const response = (body: unknown, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  redirected: false,
  type: "basic",
  json: async () => body,
  body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(JSON.stringify(body))); controller.close(); } }),
});
const home = () => ({
  origin_machine: "fixture-mac", agents: [], castle_wall: { arm_state: "unknown" }, digest: {},
  protection_requested_count: 0, enforcement_confirmed_count: 0,
});
const emptyData = { data: { configured: false, surfaces: [], agents: [], items: [], traps: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] } };
const evidence = { origin_machine: "fixture-mac", entries: [], total: 0, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } };
const agents = { data: { agents: [{ agent_id: "fixture-agent", status: "active", harness: "fixture", identity_id: "operator-fixture" }] } };
// A token-shaped value distinctive enough that any echo of it anywhere is unambiguous.
const PASTED_TOKEN = "pasted-operator-token-7f3c9a";

function escapeHtml(raw: string) {
  return raw.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
class FakeElement {
  attrs: Record<string, string>;
  parentElement: FakeElement | null = null;
  tagName: string;
  private html = "";
  private text = "";
  hidden = false;
  disabled = false;
  checked = false;
  value = "";
  open = false;
  scrollTop = 0;
  focused = 0;
  modalOpens = 0;
  style: Record<string, string> = {};
  private classes = new Set<string>();
  private listeners: Record<string, Array<() => void>> = {};
  constructor(attrs: Record<string, string> = {}, tagName = "DIV") { this.attrs = { ...attrs }; this.tagName = tagName.toUpperCase(); }
  get innerHTML() { return this.html; }
  set innerHTML(value: string) { this.html = String(value); }
  get textContent() { return this.text; }
  set textContent(value: string) { this.text = String(value); this.html = escapeHtml(String(value)); }
  classList = {
    add: (...n: string[]) => n.forEach((c) => this.classes.add(c)),
    remove: (...n: string[]) => n.forEach((c) => this.classes.delete(c)),
    contains: (c: string) => this.classes.has(c),
  };
  getAttribute(name: string) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name]! : null; }
  setAttribute(name: string, value: string) { this.attrs[name] = String(value); }
  removeAttribute(name: string) { delete this.attrs[name]; }
  closest() { return null; }
  querySelector(): FakeElement | null { return null; }
  querySelectorAll(): FakeElement[] { return []; }
  contains(target: unknown) { return target === this; }
  appendChild(child: FakeElement) { return child; }
  insertBefore(child: FakeElement) { return child; }
  addEventListener(name: string, fn: () => void) { (this.listeners[name] ||= []).push(fn); }
  dispatch(name: string) { (this.listeners[name] || []).forEach((fn) => fn()); }
  focus() { this.focused++; }
  showModal() { this.open = true; this.modalOpens++; }
  close() { this.open = false; this.dispatch("close"); }
  click() {}
  remove() {}
}
class FakeInput extends FakeElement {}
class FakeForm extends FakeElement {}

const SHELL_IDS = [
  "app", "main", "fortress", "feedback", "sidebar-pills", "btn-lockdown", "posture-seal", "posture-seal-word",
  "posture-seal-freshness", "posture-seal-pop", "rail-approvals-count", "btn-notifications", "notify-count",
  "time-range", "btn-talk", "talk-panel", "talk-panel-body", "search-results",
  "machines-summary", "machines-age", "machines-list", "toast-host", "decision-announcement", "decision-feedback-result",
  // The token notice host and dialog parts: must match the operator-token-* ids in html.ts.
  "operator-token-entry", "operator-token-dialog", "operator-token-error",
];

type Override = (init?: RequestInit, url?: string) => unknown;
function boot(overrides: Record<string, Override> = {}, storage: Map<string, string> = new Map(), opts: { browserHeaders?: boolean } = {}) {
  const el: Record<string, FakeElement> = {};
  for (const id of SHELL_IDS) el[id] = new FakeElement({ id });
  el["global-search"] = new FakeInput({ "data-action": "global-search" });
  el["operator-token-input"] = new FakeInput({ id: "operator-token-input", type: "password" }, "INPUT");
  el["operator-token-form"] = new FakeForm({ id: "operator-token-form", "data-action": "operator-token-submit" }, "FORM");
  el["rail-approvals-count"]!.parentElement = new FakeElement();
  const docListeners: Record<string, (ev: unknown) => void> = {};
  const winListeners: Record<string, () => void> = {};
  let locationHash = "";
  let reloads = 0;
  const location = {
    get hash() { return locationHash; },
    set hash(value: string) {
      const next = String(value).startsWith("#") ? String(value) : "#" + String(value);
      const changed = next !== locationHash;
      locationHash = next;
      if (changed && winListeners.hashchange) winListeners.hashchange();
    },
    search: "", origin: "http://fixture", href: "http://fixture/v1.1",
    reload() { reloads++; },
  };
  const consoleCalls: string[] = [];
  const record = (...args: unknown[]) => { consoleCalls.push(args.map((a) => String(a)).join(" ")); };
  const prompts: string[] = [];
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const context = createContext({
    document: {
      getElementById: (id: string) => el[id] || (id === "dashboard-config" ? { textContent: JSON.stringify({ hubApiBase: "/api/hub" }) } : null),
      addEventListener: (name: string, fn: (ev: unknown) => void) => { docListeners[name] = fn; },
      createElement: (tagName: string) => new FakeElement({}, tagName),
      createDocumentFragment: () => new FakeElement({}, "FRAGMENT"),
      createTextNode: (text: string) => new FakeElement({}, "TEXT"),
      querySelectorAll: () => [],
      querySelector: () => null,
      activeElement: null,
      body: new FakeElement({}, "BODY"),
      documentElement: { setAttribute() {}, removeAttribute() {}, getAttribute: () => null },
    },
    window: { addEventListener: (name: string, fn: () => void) => { winListeners[name] = fn; }, prompt: (message: string) => { prompts.push(message); return null; } },
    location,
    sessionStorage: {
      getItem: (key: string) => (storage.has(key) ? storage.get(key)! : null),
      setItem: (key: string, value: string) => { storage.set(key, String(value)); },
    },
    console: { log: record, info: record, warn: record, error: record, debug: record },
    URLSearchParams, URL, AbortController, TextDecoder, Date, Element: FakeElement, HTMLInputElement: FakeInput, HTMLFormElement: FakeForm, Blob, Headers,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    EventSource: class { addEventListener() {} close() {} },
    fetch: (url: string, init?: RequestInit) => {
      // A browser builds the request headers before anything is sent, and rejects a value outside Latin-1 there.
      if (opts.browserHeaders && init && init.headers) {
        try { new Headers(init.headers); } catch (error) { return Promise.reject(error); }
      }
      const path = url.replace(/([?&])_t=[^&]*&?/, "$1").replace(/[?&]$/, "");
      requests.push({ url, init });
      const bare = path.split("?")[0]!;
      if (overrides["*"]) { const answer = overrides["*"]!(init, path); if (answer !== undefined) return answer; }
      if (overrides[path]) return overrides[path]!(init, path);
      if (overrides[bare]) return overrides[bare]!(init, path);
      if (path === "/api/policy/current") return Promise.resolve(response({ data: { view: { lines: [] } } }));
      if (path === "/api/posture/evidence") return Promise.resolve(response(evidence));
      if (path === "/api/hub/agents") return Promise.resolve(response(agents));
      return Promise.resolve(response(path === "/api/posture/home" ? home() : emptyData));
    },
  });
  runInContext(getClientScript(), context);
  const navigate = (route: string) => { location.hash = "#" + route; };
  const click = (attrs: Record<string, string>) => { docListeners.click!({ target: new FakeElement(attrs, "BUTTON") }); };
  const submit = (form: FakeElement) => { let prevented = false; docListeners.submit!({ target: form, preventDefault() { prevented = true; } }); return prevented; };
  const read = (expression: string) => runInContext(expression, context);
  return { el, context, location, navigate, click, submit, read, requests, storage, consoleCalls, prompts, reloads: () => reloads };
}
// Boot's longest read chain (fetch, body, panel publish, rerender, trailing read) settles in a few dozen microtask
// turns; 100 is that bound with margin, the same finite drain settle() uses in approval-decision-result.test.ts.
const MICROTASK_DRAIN_TURNS = 100;
async function settle() { for (let i = 0; i < MICROTASK_DRAIN_TURNS; i++) await Promise.resolve(); }
// Must match DASHBOARD_READ_DEADLINE_MS in client.ts: a read still pending at this age fails Unknown.
const READ_DEADLINE_MS = 5 * 1000;
afterEach(() => { vi.useRealTimers(); });

// Every read the console makes is refused unless it carries the stored bearer, as a fortress that requires the
// operator token answers a tab that holds none.
function tokenGate(token: string): Override {
  return (init?: RequestInit) => {
    const headers = (init && init.headers ? init.headers : {}) as Record<string, string>;
    return headers.Authorization === "Bearer " + token ? undefined : Promise.resolve(response({ error: "unauthorized" }, 401));
  };
}

describe("operator token entry for refused reads", () => {
  it("a refused read shows a Paste operator token control in the feedback row, and opens the token dialog", async () => {
    vi.useFakeTimers();
    const h = boot({ "*": tokenGate(PASTED_TOKEN) });
    await settle();
    const notice = h.el["operator-token-entry"]!.innerHTML;
    expect(notice).toContain('data-action="operator-token-open"');
    expect(notice).toContain(">Paste operator token</button>");
    expect(notice).toContain("No operator token is held in this tab");
    // A refused read never falls back to the mutation prompt.
    expect(h.prompts).toEqual([]);
    h.click({ "data-action": "operator-token-open" });
    expect(h.el["operator-token-dialog"]!.open).toBe(true);
    expect(h.el["operator-token-input"]!.focused).toBeGreaterThan(0);
    // Cancel closes the dialog and leaves nothing typed behind.
    h.el["operator-token-input"]!.value = PASTED_TOKEN;
    h.click({ "data-action": "operator-token-cancel" });
    expect(h.el["operator-token-dialog"]!.open).toBe(false);
    expect(h.el["operator-token-input"]!.value).toBe("");
    expect(h.storage.has("authToken")).toBe(false);
  });

  it("saving a pasted token stores it for this tab, empties the field and reloads, without echoing it anywhere", async () => {
    vi.useFakeTimers();
    const h = boot({ "*": tokenGate(PASTED_TOKEN) });
    await settle();
    h.click({ "data-action": "operator-token-open" });
    h.el["operator-token-input"]!.value = "  " + PASTED_TOKEN + "\n";
    expect(h.submit(h.el["operator-token-form"]!), "the native dialog submit is replaced").toBe(true);
    expect(h.storage.get("authToken")).toBe(PASTED_TOKEN);
    expect(h.el["operator-token-input"]!.value).toBe("");
    expect(h.el["operator-token-dialog"]!.open).toBe(false);
    expect(h.reloads()).toBe(1);
    await settle();
    for (const [id, node] of Object.entries(h.el)) {
      expect(node.innerHTML, id).not.toContain(PASTED_TOKEN);
      expect(JSON.stringify(node.attrs), id).not.toContain(PASTED_TOKEN);
    }
    expect(h.location.hash + h.location.search + h.location.href).not.toContain(PASTED_TOKEN);
    expect(h.requests.map((r) => r.url).join("\n")).not.toContain(PASTED_TOKEN);
    expect(h.consoleCalls.join("\n")).not.toContain(PASTED_TOKEN);

    // The reload boots with the stored token: reads carry the bearer, load, and the notice is gone.
    const next = boot({ "*": tokenGate(PASTED_TOKEN) }, h.storage);
    await settle();
    expect(next.el["operator-token-entry"]!.innerHTML).toBe("");
    expect(next.el.main!.innerHTML).toContain("fixture-mac");
    expect(next.requests.map((r) => r.url).join("\n")).not.toContain(PASTED_TOKEN);
  });

  it("an empty entry stores nothing, does not reload and says what is missing", async () => {
    vi.useFakeTimers();
    const h = boot({ "*": tokenGate(PASTED_TOKEN) });
    await settle();
    h.click({ "data-action": "operator-token-open" });
    h.el["operator-token-input"]!.value = "   ";
    expect(h.submit(h.el["operator-token-form"]!)).toBe(true);
    expect(h.storage.has("authToken")).toBe(false);
    expect(h.reloads()).toBe(0);
    expect(h.el["operator-token-error"]!.hidden).toBe(false);
    expect(h.el["operator-token-error"]!.textContent).toBe("Paste the operator token first.");
    expect(h.el["operator-token-dialog"]!.open).toBe(true);
  });

  it("a malformed paste is refused before storage: the held token stays, the dialog stays open and says why", async () => {
    vi.useFakeTimers();
    const held = "held-token-from-the-token-file";
    const h = boot({ "*": tokenGate(held) }, new Map([["authToken", held]]));
    await settle();
    h.click({ "data-action": "operator-token-open" });
    // An em-dash typo (outside Latin-1) and an inner space are both outside the token shape.
    for (const pasted of ["operator-token\u2014typo", "two words"]) {
      h.el["operator-token-input"]!.value = pasted;
      expect(h.submit(h.el["operator-token-form"]!)).toBe(true);
      expect(h.storage.get("authToken"), pasted).toBe(held);
      expect(h.reloads(), pasted).toBe(0);
      expect(h.el["operator-token-dialog"]!.open, pasted).toBe(true);
      expect(h.el["operator-token-error"]!.hidden, pasted).toBe(false);
      expect(h.el["operator-token-error"]!.textContent, pasted).toContain("That is not an operator token");
      expect(h.el["operator-token-error"]!.textContent, pasted).not.toContain(pasted);
      expect(h.el["operator-token-input"]!.value, pasted).toBe("");
    }
    // The dialog stays usable: a well-formed token after the refusal is stored and reloads.
    h.el["operator-token-input"]!.value = PASTED_TOKEN;
    h.submit(h.el["operator-token-form"]!);
    expect(h.storage.get("authToken")).toBe(PASTED_TOKEN);
    expect(h.reloads()).toBe(1);
  });

  it("a held token whose header cannot be built reads as refused, so the replacement notice still appears", async () => {
    vi.useFakeTimers();
    // A token stored before shape checking existed (or set through the mutation prompt) with an em-dash typo.
    const h = boot({}, new Map([["authToken", "operator-token\u2014typo"]]), { browserHeaders: true });
    await settle();
    const notice = h.el["operator-token-entry"]!.innerHTML;
    expect(notice).toContain(">Paste operator token</button>");
    expect(notice).toContain("contains characters that cannot be sent");
    expect(h.el.main!.innerHTML).toContain("the operator token held in this tab cannot be sent");
    expect(h.read('sourceRead("/api/posture/home").tokenUnsendable')).toBe(true);
  });

  it("a held token the server does not accept is named as refused, and the notice offers a replacement", async () => {
    vi.useFakeTimers();
    const h = boot({ "*": tokenGate(PASTED_TOKEN) }, new Map([["authToken", "stale-token-from-an-earlier-reset"]]));
    await settle();
    const notice = h.el["operator-token-entry"]!.innerHTML;
    expect(notice).toContain("did not accept the operator token held in this tab");
    expect(notice).toContain(">Paste operator token</button>");
    expect(notice).not.toContain("stale-token-from-an-earlier-reset");
  });
});

describe("Overview findings agree with the Findings screen", () => {
  const sentinelFinding = { finding_id: "finding-1", summary: "Fixture sentinel flagged a burst.", severity: "warn", sentinel_id: "sentinel-1", agent_id: null, observed_at: "2026-10-21T12:00:00.000Z" };

  it("an empty anomaly answer beside a listed Sentinel finding reads as 1 finding with status unknown, never 0 open", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/sentinels/findings": () => Promise.resolve(response({ data: { findings: [sentinelFinding] } })) });
    await settle();
    const overview = h.el.main!.innerHTML;
    expect(overview).not.toMatch(/Open Sentinel findings<\/a><span class="ot-value">0</);
    expect(overview).toMatch(/Open Sentinel findings<\/a><span class="ot-value"><span class="state-chip unknown overview-chip"><span class="overview-chip-head"><i aria-hidden="true"><\/i>1 FINDING<\/span><span class="overview-chip-detail">status unknown<\/span>/);
    expect(overview).not.toContain("No open Sentinel findings");
    expect(overview).not.toContain("0 of 0 open findings");
    expect(overview).toContain("<h3>1 finding, status unknown</h3>");
    // The Findings screen lists the same served finding with its lifecycle Unknown.
    h.navigate("findings");
    expect(h.el.main!.innerHTML).toContain("Fixture sentinel flagged a burst.");

    // With no Sentinel finding listed, a checked-empty anomaly answer still reads as 0 open.
    const quiet = boot();
    await settle();
    expect(quiet.el.main!.innerHTML).toMatch(/Open Sentinel findings<\/a><span class="ot-value">0</);
    expect(quiet.el.main!.innerHTML).toContain("No open Sentinel findings");
  });
});

describe("an unread Sentinel feed is never a zero", () => {
  const sentinelFinding = { finding_id: "finding-1", summary: "Fixture sentinel flagged a burst.", severity: "warn", sentinel_id: "sentinel-1", agent_id: null, observed_at: "2026-10-21T12:00:00.000Z" };
  const never = () => new Promise<never>(() => {});
  const zeroTile = /Open Sentinel findings<\/a><span class="ot-value">0</;
  const unknownTile = /Open Sentinel findings<\/a><span class="ot-value"><span class="state-chip unknown overview-chip"><span class="overview-chip-head"><i aria-hidden="true"><\/i>Not evaluated</;
  function expectUnknown(html: string, when: string) {
    expect(html, when).not.toMatch(zeroTile);
    expect(html, when).toMatch(unknownTile);
    expect(html, when).not.toContain("No open Sentinel findings");
    expect(html, when).not.toContain("0 of 0 open findings");
    expect(html, when).toContain("Sentinel findings Unknown");
    expect(html, when).toContain('data-read="/api/sentinels/findings">Retry Sentinel findings</button>');
  }

  it("a feed that has not answered beside an empty anomaly answer reads Not evaluated, before and after its deadline", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/sentinels/findings": never });
    await settle();
    expectUnknown(h.el.main!.innerHTML, "pending at boot");
    await vi.advanceTimersByTimeAsync(READ_DEADLINE_MS);
    expectUnknown(h.el.main!.innerHTML, "timed out");
  });

  it("a pending refresh after one listed finding never flips the Overview to 0 of 0", async () => {
    vi.useFakeTimers();
    let mode: "listed" | "pending" = "listed";
    const h = boot({ "/api/sentinels/findings": () => mode === "listed" ? Promise.resolve(response({ data: { findings: [sentinelFinding] } })) : never() });
    await settle();
    expect(h.el.main!.innerHTML).toContain("<h3>1 finding, status unknown</h3>");
    mode = "pending";
    h.read('void queueStreamRefresh(["/api/sentinels/findings"])');
    // The refresh is in flight: no settle, so this is the window the redraw paints while the read is pending.
    expectUnknown(h.el.main!.innerHTML, "refresh in flight");
    await settle();
    expectUnknown(h.el.main!.innerHTML, "refresh still pending");
    await vi.advanceTimersByTimeAsync(READ_DEADLINE_MS);
    expectUnknown(h.el.main!.innerHTML, "refresh timed out");
  });

  it("a failed refresh after one listed finding reads Unknown, and a later empty answer reads 0 open", async () => {
    vi.useFakeTimers();
    let mode: "listed" | "failed" | "empty" = "listed";
    const h = boot({ "/api/sentinels/findings": () => mode === "listed" ? Promise.resolve(response({ data: { findings: [sentinelFinding] } }))
      : mode === "failed" ? Promise.resolve(response({ error: "unavailable" }, 503)) : Promise.resolve(response({ data: { findings: [] } })) });
    await settle();
    expect(h.el.main!.innerHTML).toContain("1 FINDING");
    mode = "failed";
    h.read('void queueStreamRefresh(["/api/sentinels/findings"])');
    expectUnknown(h.el.main!.innerHTML, "refresh in flight");
    await settle();
    expectUnknown(h.el.main!.innerHTML, "refresh answered 503");
    expect(h.el.main!.innerHTML).toContain("Sentinel findings did not answer: Read failed (HTTP 503)");
    // Only a feed that loads empty earns the zero.
    mode = "empty";
    h.read('void retryPanel("/api/sentinels/findings")');
    await settle();
    expect(h.el.main!.innerHTML).toMatch(zeroTile);
    expect(h.el.main!.innerHTML).toContain("No open Sentinel findings");
  });
});

describe("each findings surface names the feed it counts", () => {
  const sentinelFinding = { finding_id: "finding-1", summary: "Fixture sentinel flagged a burst.", severity: "warn", sentinel_id: "sentinel-1", agent_id: null, observed_at: "2026-10-21T12:00:00.000Z" };
  const READ_GAP_MS = 3 * 60 * 1000;

  it("an empty anomaly answer beside one listed Sentinel finding: the tile names the queue, the anomaly card names its detector and points at the queue", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/sentinels/findings": () => Promise.resolve(response({ data: { findings: [sentinelFinding] } })) });
    await settle();
    const overview = h.el.main!.innerHTML;
    expect(overview).toContain("Sentinel queue returned 1 finding; lifecycle is not served");
    expect(overview).toContain("The Sentinel queue returned 1 finding.");
    h.navigate("findings");
    const findings = h.el.main!.innerHTML;
    const card = findings.split("data-anomaly-findings")[1] || "";
    expect(card, "the anomaly card says whose zero it is").toContain("0 open in the anomaly detector");
    expect(card, "no unlabeled zero").not.toMatch(/>0 open(?! in the anomaly detector)/);
    expect(card, "and that the queue above lists a finding it does not count").toContain(
      "This card counts only the anomaly detector. The Sentinel queue above lists 1 finding whose status is not served.");

    // With the queue loaded empty, the card carries no queue note and still names its detector.
    const quiet = boot();
    await settle();
    quiet.navigate("findings");
    const quietCard = quiet.el.main!.innerHTML.split("data-anomaly-findings")[1] || "";
    expect(quietCard).toContain("0 open in the anomaly detector");
    expect(quietCard).not.toContain("data-anomaly-queue-note");
  });

  it("a listed anomaly beside more Sentinel queue findings: the Overview panel names the anomaly feed in its count and rows", async () => {
    vi.useFakeTimers();
    const anomaly = { finding_id: "anomaly-1", severity: "high", detector_id: "detector-1", summary: "Fixture anomaly.", created_at: "2026-10-21T12:00:00.000Z" };
    const h = boot({
      "/api/anomaly/findings": () => Promise.resolve(response({ data: { findings: [anomaly] } })),
      "/api/sentinels/findings": () => Promise.resolve(response({ data: { findings: [sentinelFinding, { ...sentinelFinding, finding_id: "finding-2" }] } })),
    });
    await settle();
    const overview = h.el.main!.innerHTML;
    expect(overview, "the panel count says which feed it shows").toContain("showing 1 of 1 anomaly findings");
    expect(overview, "rows name the anomaly detector, not the Sentinel queue").toContain("Anomaly detector: detector-1");
    expect(overview).not.toContain("Sentinel: detector-1");

    // An anomaly with nothing to title it by is still named as an anomaly, never as a Sentinel finding.
    const bare = boot({ "/api/anomaly/findings": () => Promise.resolve(response({ data: { findings: [{ severity: "high" }] } })) });
    await settle();
    expect(bare.el.main!.innerHTML).toContain(">Anomaly finding<");
    expect(bare.el.main!.innerHTML).not.toContain(">Sentinel finding<");
  });

  it("an earned 0 open is aged by the older of its two reads, so a fresh anomaly read cannot freshen an old Sentinel zero", async () => {
    vi.useFakeTimers();
    let sentinelReads = 0;
    const h = boot({ "/api/sentinels/findings": () => { sentinelReads++; return Promise.resolve(response({ data: { findings: [] } })); } });
    await settle();
    expect(h.el.main!.innerHTML).toContain("No open Sentinel findings");
    const sentinelReadsAtBoot = sentinelReads;
    await vi.advanceTimersByTimeAsync(READ_GAP_MS);
    h.read('void queueStreamRefresh(["/api/anomaly/findings"])');
    await settle();
    expect(sentinelReads, "only the anomaly detector was reread").toBe(sentinelReadsAtBoot);
    const gap = h.read("durationLabelFromMs(" + READ_GAP_MS + ")") as string;
    const fresh = h.read('sourceReadAge("/api/anomaly/findings")') as string;
    expect(fresh, "the anomaly read is fresh").not.toBe(gap + " ago");
    const overview = h.el.main!.innerHTML;
    expect(overview).toContain("The anomaly detector and the Sentinel queue both answered empty; oldest read " + gap + " ago.");
    expect(overview).toContain("anomaly detector and Sentinel queue answered empty; oldest read " + gap + " ago");
    expect(overview).not.toContain("oldest read " + fresh);
  });
});

describe("screen scroll on route change", () => {
  it("a new hash route opens at the top of main; a redraw or same-screen filter change keeps the place", async () => {
    vi.useFakeTimers();
    const h = boot();
    await settle();
    h.navigate("approvals");
    await settle();
    const main = h.el.main!;
    main.scrollTop = 792;
    h.navigate("enforcement");
    expect(main.scrollTop, "a route change resets the workspace scroller").toBe(0);
    main.scrollTop = 300;
    h.read("rerender()");
    expect(main.scrollTop, "a redraw of the same route keeps the reader's place").toBe(300);
    h.click({ "data-action": "set-route", "data-route": "enforcement" });
    expect(main.scrollTop, "re-entering the screen already showing keeps the place").toBe(300);
    h.navigate("activity");
    expect(main.scrollTop).toBe(0);
    main.scrollTop = 120;
    h.navigate("activity?layer=l3");
    expect(main.scrollTop, "a filter change on the same screen keeps the place").toBe(120);
  });
});

describe("approval drawer standing-rule copy", () => {
  it("an operation that cannot become a standing rule says Always allow is unavailable once", async () => {
    vi.useFakeTimers();
    const item = {
      item_id: "hold-1", kind: "approval_pending", tier: "tier2", agent_id: "fixture-agent",
      display_template_id: "approval_pending.tier2.other", display_template_args: [{ kind: "agent_id", value: "fixture-agent" }],
      resolved: false, created_at: "2026-10-21T12:00:00.000Z", identity_id: "operator-fixture", operation_category: "other",
    };
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [item] } })) });
    await settle();
    h.navigate("approvals");
    await settle();
    h.click({ "data-action": "approval-select", "data-item-id": "hold-1" });
    const drawer = h.el.main!.innerHTML.split('<aside class="card approval-drawer"')[1] || "";
    expect(drawer).toContain('data-action="approval-always-allow"');
    expect(drawer.split("Always allow is unavailable").length - 1).toBe(1);
    expect(drawer).toContain("Always allow is unavailable for this operation.");
  });
});
