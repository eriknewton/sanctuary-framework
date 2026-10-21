/**
 * Approval decision result: wired witnesses for the one retained outcome that every inbox decision settles into.
 *
 * Each test boots the real client script in a minimal DOM, lets its reads settle against fixture responses,
 * drives a decision through the real click listeners and asserts what the operator sees: a decision the
 * server acknowledged reads as taken even when the queue cannot be re-read afterwards (the re-read is named
 * in plain English and never turns into a refusal); a 2xx that does not confirm the admitted item, a 5xx or no
 * answer at all reads as unconfirmed, never as taken; a 4xx reads as refused with the server's reason; a
 * unified batch the server refused keeps the operator's selection instead of looking done; a batch dismiss
 * keeps each item's outcome; one lock pauses every decision control on every screen with its reason, a
 * second click sends nothing and the result names the first request only; consent survives a decision on
 * another row and resets for the decided one; the result survives a route change and clears only through
 * its own control; Allow always reports a refused or unconfirmed standing rule in words on an acknowledged
 * approval, and an activation answer that cannot be read is unconfirmed, never refused; a decision is sent only
 * against a loaded queue that still holds every admitted request, otherwise nothing is sent and the result says
 * so; the row the operator decided from echoes the outcome; a partly refused batch says so in its headline; an
 * unconfirmed result has no Clear control and stays until a sent decision replaces it, a later click that sends
 * nothing being noted on it instead; a local non-admission
 * is its own "not sent" outcome, never a refusal; the row Snooze menu and the selection pause while a batch holds
 * the lock; a batch summary is confirmed only when every count and missing id is accounted for; the result block
 * remains beside the stopped-updates panel too; a decision keeps every control paused for the release hold after
 * its last layout change, restarts the hold when a repaint lands in it (a bounded number of times), still releases
 * when a repaint throws, and releases with a repaint that changes only the paused attributes. The decision-result witness for D5-approval; this header carries the bare
 * id only.
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
const held = (itemId: string, extra: Record<string, unknown> = {}) => ({
  item_id: itemId, kind: "approval_pending", tier: "tier2", agent_id: "fixture-agent",
  display_template_id: "approval_pending.tier2.other", display_template_args: [{ kind: "agent_id", value: "fixture-agent" }],
  resolved: false, created_at: "2026-10-17T16:45:00.000Z", identity_id: "operator-fixture", operation_category: "state_export", ...extra,
});
const withoutResolved = (item: Record<string, unknown>) => { const copy = { ...item }; delete copy.resolved; return copy; };
const resolvedBody = (itemId: string) => ({ ok: true, data: { item: { ...held(itemId), resolved: true, resolved_at: "2026-10-17T16:46:00.000Z" } } });
const BUSY = 'disabled title="Another decision is being sent."';
const REREAD = "The queue could not be re-read after this decision, so this list may be out of date.";
const REREAD_BUSY = 'disabled title="The queue is being re-read after a decision."';
const UNCONFIRMED_ADVICE = "The decision may or may not have been applied. Check the queue before deciding again.";
const CHECK_RULE = " Check the policy before relying on it.";
const UNCONFIRMED_STAYS = "This result stays on screen until your next decision replaces it.";
const NOT_SENT_STALE = "the request is no longer waiting in the loaded queue, so nothing was sent.";
const NOT_SENT_UNREAD = "the queue has not been read since it last changed, so nothing was sent. Re-read the queue first.";

function escapeHtml(raw: string) {
  return raw.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
let fakeActiveElement: unknown = null;
class FakeElement {
  attrs: Record<string, string>;
  parentElement: FakeElement | null = null;
  tagName: string;
  private children: Array<FakeElement | FakeText> = [];
  private html = "";
  private text = "";
  className = "";
  hidden = false;
  disabled = false;
  checked = false;
  value = "";
  style: Record<string, string> = {};
  inside: string[] = [];
  private classes = new Set<string>();
  constructor(attrs: Record<string, string> = {}, tagName = "DIV") { this.attrs = { ...attrs }; this.tagName = tagName.toUpperCase(); }
  get innerHTML() { return this.children.length ? this.children.map((c) => c.outerHTML).join("") : this.html; }
  set innerHTML(value: string) { this.html = String(value); this.children = []; }
  get textContent() { return this.children.length ? this.children.map((c) => c.textContent).join("") : this.text; }
  set textContent(value: string) { this.text = String(value); this.html = escapeHtml(String(value)); this.children = []; }
  get outerHTML() {
    const merged = this.className ? { ...this.attrs, class: this.className } : this.attrs;
    const attrs = Object.entries(merged).map(([k, v]) => ` ${k}="${escapeHtml(v)}"`).join("");
    return `<${this.tagName.toLowerCase()}${attrs}>${this.innerHTML}</${this.tagName.toLowerCase()}>`;
  }
  classList = {
    add: (...n: string[]) => n.forEach((c) => this.classes.add(c)),
    remove: (...n: string[]) => n.forEach((c) => this.classes.delete(c)),
    contains: (c: string) => this.classes.has(c),
  };
  getAttribute(name: string) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name]! : null; }
  setAttribute(name: string, value: string) { this.attrs[name] = String(value); }
  removeAttribute(name: string) { delete this.attrs[name]; }
  get title() { return this.attrs.title ?? ""; }
  set title(value: string) { this.attrs.title = String(value); }
  closest(selector: string) { return this.inside.includes(selector) ? this : null; }
  querySelector(): FakeElement | null { return null; }
  querySelectorAll(): FakeElement[] { return []; }
  contains(target: unknown): boolean { return target === this || this.children.some((c) => c instanceof FakeElement && c.contains(target)); }
  appendChild(child: FakeElement | FakeText) { if (child instanceof FakeElement) child.parentElement = this; this.children.push(child); return child; }
  focus() { fakeActiveElement = this; }
  click() {}
  remove() {}
}
class FakeText {
  textContent: string;
  constructor(value: string) { this.textContent = String(value); }
  get outerHTML() { return escapeHtml(this.textContent); }
}
class FakeInput extends FakeElement {}

const SHELL_IDS = [
  "app", "main", "fortress", "sidebar-pills", "btn-lockdown", "posture-seal", "posture-seal-word",
  "posture-seal-freshness", "posture-seal-pop", "rail-approvals-count", "btn-notifications", "notify-count",
  "time-range", "btn-talk", "talk-panel", "talk-panel-body", "search-results",
  "machines-summary", "machines-age", "machines-list", "toast-host", "decision-announcement", "decision-feedback-result",
];

type Override = (init?: RequestInit, url?: string) => unknown;
function boot(overrides: Record<string, Override> = {}) {
  fakeActiveElement = null;
  const el: Record<string, FakeElement> = {};
  for (const id of SHELL_IDS) el[id] = new FakeElement({ id });
  el["global-search"] = new FakeInput({ "data-action": "global-search" });
  el["rail-approvals-count"]!.parentElement = new FakeElement();
  const docListeners: Record<string, (ev: unknown) => void> = {};
  const winListeners: Record<string, () => void> = {};
  let locationHash = "";
  const location = {
    get hash() { return locationHash; },
    set hash(value: string) {
      const next = String(value).startsWith("#") ? String(value) : "#" + String(value);
      const changed = next !== locationHash;
      locationHash = next;
      if (changed && winListeners.hashchange) winListeners.hashchange();
    },
    search: "", origin: "http://fixture",
  };
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const context = createContext({
    document: {
      getElementById: (id: string) => el[id] || (id === "dashboard-config" ? { textContent: JSON.stringify({ hubApiBase: "/api/hub" }) } : null),
      addEventListener: (name: string, fn: (ev: unknown) => void) => { docListeners[name] = fn; },
      createElement: (tagName: string) => new FakeElement({}, tagName),
      createDocumentFragment: () => new FakeElement({}, "FRAGMENT"),
      createTextNode: (text: string) => new FakeText(text),
      querySelectorAll: () => [],
      querySelector: () => null,
      get activeElement() { return fakeActiveElement; },
      body: new FakeElement({}, "BODY"),
      documentElement: { setAttribute() {}, removeAttribute() {}, getAttribute: () => null },
    },
    window: { addEventListener: (name: string, fn: () => void) => { winListeners[name] = fn; } },
    location, sessionStorage: { getItem: () => null, setItem() {} },
    URLSearchParams, URL, AbortController, TextDecoder, Date, Element: FakeElement, HTMLInputElement: FakeInput, Blob,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    EventSource: class { addEventListener() {} close() {} },
    fetch: (url: string, init?: RequestInit) => {
      const path = url.replace(/([?&])_t=[^&]*&?/, "$1").replace(/[?&]$/, "");
      requests.push({ url: path, init });
      const bare = path.split("?")[0]!;
      if (overrides[path]) return overrides[path]!(init, path);
      if (overrides[bare]) return overrides[bare]!(init, path);
      // "*" answers every path without an override of its own; returning undefined falls through to the defaults.
      if (overrides["*"]) { const answer = overrides["*"]!(init, path); if (answer !== undefined) return answer; }
      if (path === "/api/policy/current") return Promise.resolve(response({ data: { view: { lines: [] } } }));
      if (path === "/api/posture/evidence") return Promise.resolve(response(evidence));
      if (path === "/api/hub/agents") return Promise.resolve(response({ data: { agents: [{ agent_id: "fixture-agent", status: "active", harness: "fixture", identity_id: "operator-fixture" }] } }));
      return Promise.resolve(response(path === "/api/posture/home" ? home() : emptyData));
    },
  });
  runInContext(getClientScript(), context);
  const navigate = (route: string) => { location.hash = "#" + route; };
  const click = (attrs: Record<string, string>, checked = false) => {
    const target = new FakeElement(attrs, "BUTTON");
    target.checked = checked;
    docListeners.click!({ target });
  };
  const posts = () => requests.filter((r) => r.init?.method === "POST").map((r) => r.url);
  const main = () => el.main!.innerHTML;
  // The result block only, so the panels' own error text cannot satisfy or defeat an assertion about it.
  const result = () => (el["decision-feedback-result"]!.innerHTML.split('class="decision-result"')[1] ?? "").split("</section>")[0]!;
  const read = (expression: string) => runInContext(expression, context);
  return { el, context, navigate, click, requests, posts, main, result, read };
}
// Must match DECISION_RELEASE_HOLD_MS in src/dashboard/v1_1/client.ts: a decision keeps its lock through this
// hold after its last layout change, so a drain under fake timers advances past it.
const RELEASE_HOLD_MS = 300;
async function settle() {
  for (let i = 0; i < 100; i++) await Promise.resolve();
  if (!vi.isFakeTimers()) return;
  await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS);
  for (let i = 0; i < 100; i++) await Promise.resolve();
}
function gate<T>() { let release!: (value: T) => void; const promise = new Promise<T>((resolve) => { release = resolve; }); return { promise, release }; }
afterEach(() => { vi.useRealTimers(); });

describe("one retained decision result", () => {
  for (const failing of ["the inbox read", "every read"]) {
    it(`an acknowledged decision whose refresh cannot load ${failing} reads as taken with the re-read note, never as refused`, async () => {
      vi.useFakeTimers();
      let decided = false;
      const h = boot({
        "/api/hub/inbox": () => Promise.resolve(decided ? response({ error: "read failed" }, 500) : response({ data: { items: [held("wait-1")] } })),
        "/api/hub/inbox/wait-1/approve": () => { decided = true; return Promise.resolve(response(resolvedBody("wait-1"))); },
        // After the decision every other read the refresh issues fails too, not only the inbox and the home read.
        "*": () => decided && failing === "every read" ? Promise.resolve(response({ error: "read failed" }, 500)) : undefined,
      });
      await settle();
      h.navigate("approvals");
      const requestsBeforeDecision = h.requests.length;
      h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
      await settle();
      expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/approve"]);
      expect(h.result()).toContain('data-decision-status="acknowledged"');
      expect(h.result()).toContain("Allowed once: state export by fixture-agent (request wait-1). Marked decided in this inbox. " + REREAD);
      expect(h.result()).not.toMatch(/refused|failed/);
      // Only the reads the refresh issued after the decision count, so boot traffic cannot satisfy this.
      if (failing === "every read") expect(h.requests.slice(requestsBeforeDecision).filter((r) => r.init?.method !== "POST" && r.url.startsWith("/api/") && !r.url.startsWith("/api/hub/inbox")).length, "the refresh issued reads beyond the inbox, and every one failed").toBeGreaterThan(1);
      expect(h.el["decision-announcement"]!.textContent).toBe("Decision taken. Allowed once: state export by fixture-agent (request wait-1). Marked decided in this inbox. " + REREAD);
      expect(h.el["toast-host"]!.innerHTML).toBe("");
      expect(h.read("state.approvals.lock")).toBeNull();
      expect(h.read("state.approvals.result.refresh")).toBe("unavailable");
    });
  }

  it("an acknowledged deny whose refresh repaint throws reads as taken with the re-read note and releases the lock", async () => {
    vi.useFakeTimers();
    let decided = false;
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
      "/api/hub/inbox/wait-1/deny": () => { decided = true; return Promise.resolve(response(resolvedBody("wait-1"))); },
    });
    await settle();
    const main = h.el.main!;
    let throwOnce = false;
    let threw = false;
    Object.defineProperty(h.el, "main", {
      configurable: true,
      get() { if (throwOnce) { throwOnce = false; threw = true; throw new Error("fixture repaint failure"); } return main; },
    });
    // The inbox panel's final repaint after the decision throws: the client clears the panel's pending entry
    // right before that repaint, so arming there hits the repaint whose failure rejects the whole refresh.
    h.context.armRepaintThrow = () => { if (decided) throwOnce = true; };
    h.read('const clearPanel = pendingPanels.delete.bind(pendingPanels); pendingPanels.delete = function (job) { if (job.paths.indexOf(HUB + "/inbox") >= 0) armRepaintThrow(); return clearPanel(job); };');
    h.navigate("approvals");
    h.click({ "data-action": "inbox-deny", "data-item-id": "wait-1" });
    await settle();
    expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/deny"]);
    expect(threw, "the armed repaint threw").toBe(true);
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.result()).toContain("Denied: state export by fixture-agent (request wait-1). Marked decided in this inbox. " + REREAD);
    expect(h.result()).not.toMatch(/refused|failed|repaint/);
    expect(h.read("state.approvals.lock")).toBeNull();
    expect(h.read("state.approvals.result.refresh")).toBe("unavailable");
  });

  for (const [label, body] of [
    ["names another item", { ok: true, data: { item: { ...held("other"), resolved: true } } }],
    ["lacks resolved", { ok: true, data: { item: withoutResolved(held("wait-1")) } }],
    ["carries no item", { ok: true, data: {} }],
    ["is not an object", null],
  ] as const) {
    it(`a 2xx answer that ${label} reads as unconfirmed, never as taken`, async () => {
      vi.useFakeTimers();
      const h = boot({
        "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
        "/api/hub/inbox/wait-1/approve": () => Promise.resolve(response(body)),
      });
      await settle();
      h.navigate("approvals");
      h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
      await settle();
      expect(h.result()).toContain('data-decision-status="uncertain"');
      expect(h.result()).toContain("did not confirm Allow once for state export by fixture-agent (request wait-1). " + UNCONFIRMED_ADVICE);
      expect(h.result()).not.toContain("Allowed once");
      expect(h.result(), "an unconfirmed result has no Clear control").not.toContain("decision-result-clear");
      expect(h.result()).toContain(UNCONFIRMED_STAYS);
      h.click({ "data-action": "decision-result-clear" });
      expect(h.read("state.approvals.result.status"), "a stray clear click leaves the warning").toBe("uncertain");
      expect(h.main()).toContain("WAITING");
    });
  }

  it("a later click that sends nothing is noted on an unconfirmed result and leaves it unclearable", async () => {
    vi.useFakeTimers();
    let reads = 0;
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(++reads === 1 ? response({ data: { items: [held("wait-1")] } }) : response({ error: "read failed" }, 500)),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/inbox/unified/batch": () => Promise.resolve(response({ error: "storage unavailable" }, 500)),
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true; state.inboxOps.snoozeDialog = true; rerender();');
    h.click({ "data-action": "inbox-batch-snooze", "data-snooze-ms": "3600000" });
    await settle();
    expect(h.posts()).toEqual(["/api/inbox/unified/batch"]);
    expect(h.result()).toContain('data-decision-status="uncertain"');
    expect(h.read("state.approvals.result.refresh")).toBe("unavailable");
    expect(h.read("state.approvals.lock")).toBeNull();
    // The queue could not be re-read, so the retry is not admitted: it must not replace the unconfirmed result.
    h.click({ "data-action": "inbox-batch-snooze", "data-snooze-ms": "3600000" });
    await settle();
    expect(h.posts()).toEqual(["/api/inbox/unified/batch"]);
    expect(h.result()).toContain('data-decision-status="uncertain"');
    expect(h.result()).not.toContain("decision-result-clear");
    expect(h.result()).toContain("did not confirm Snooze for 1 selected item (storage unavailable (HTTP 500)). " + UNCONFIRMED_ADVICE + " " + REREAD + " " + UNCONFIRMED_STAYS + " Your next Snooze was not sent for 1 selected item: " + NOT_SENT_UNREAD);
    expect(h.el["decision-announcement"]!.textContent).toContain("Decision unconfirmed. ");
    expect(h.el["decision-announcement"]!.textContent).toContain(" Your next Snooze was not sent for 1 selected item: " + NOT_SENT_UNREAD);
    h.click({ "data-action": "inbox-batch-snooze", "data-snooze-ms": "3600000" });
    await settle();
    expect(h.result().split("Your next Snooze was not sent").length - 1, "one note, however many clicks").toBe(1);
    expect(h.main()).toContain('<p class="decision-inline" data-decision-status="uncertain">Unconfirmed.</p>');
  });

  it("an unconfirmed result is replaced only by the next decision", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/inbox/wait-1/approve": () => Promise.resolve(response({ error: "storage unavailable" }, 500)),
      "/api/hub/inbox/wait-2/deny": () => Promise.resolve(response(resolvedBody("wait-2"))),
    });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.result()).toContain('data-decision-status="uncertain"');
    expect(h.result()).not.toContain("decision-result-clear");
    h.navigate("posture");
    expect(h.result()).toContain('data-decision-status="uncertain"');
    h.click({ "data-action": "inbox-deny", "data-item-id": "wait-2" });
    await settle();
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.result()).toContain("Denied: state export by fixture-agent (request wait-2).");
    expect(h.result()).toContain('data-action="decision-result-clear">Clear</button>');
  });

  for (const [label, answer, status, text] of [
    ["a 500", () => Promise.resolve(response({ error: "storage unavailable" }, 500)), "uncertain", "did not confirm Allow once for state export by fixture-agent (request wait-1) (storage unavailable (HTTP 500))."],
    ["no answer", () => Promise.reject(new Error("network down")), "uncertain", "(network down). The decision may or may not have been applied."],
    ["a 401", () => Promise.resolve(response({ error: "operator session required" }, 401)), "refused", "Allow once was refused for state export by fixture-agent (request wait-1): operator session required (HTTP 401). The decision was not applied."],
  ] as const) {
    it(`${label} reads as ${status} with the reason`, async () => {
      vi.useFakeTimers();
      const h = boot({
        "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
        "/api/hub/inbox/wait-1/approve": answer,
      });
      await settle();
      h.navigate("approvals");
      h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
      await settle();
      expect(h.result()).toContain(`data-decision-status="${status}"`);
      expect(h.result()).toContain(text);
      expect(h.result()).not.toContain("Allowed once");
      expect(h.el["toast-host"]!.innerHTML).toBe("");
    });
  }

  it("a 409 on a Tier 2 dismiss keeps the server's reason instead of the Tier 1 sentence", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
      "/api/hub/inbox/wait-1/dismiss": () => Promise.resolve(response({ error: "already resolved" }, 409)),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
    });
    await settle();
    h.navigate("activity");
    h.click({ "data-action": "inbox-dismiss", "data-item-id": "wait-1" });
    await settle();
    expect(h.result()).toContain('data-decision-status="refused"');
    expect(h.result()).toContain("Dismiss was refused for state export by fixture-agent (request wait-1): already resolved (HTTP 409). The decision was not applied.");
    expect(h.result()).not.toContain("Tier 1");
  });

  it("a Tier 1 dismiss the server refuses with 409 names the next step instead of the code", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("tier1-1", { tier: "tier1" })] } })),
      "/api/hub/inbox/tier1-1/dismiss": () => Promise.resolve(response({ error: "conflict" }, 409)),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
    });
    await settle();
    h.navigate("activity");
    h.click({ "data-action": "inbox-dismiss", "data-item-id": "tier1-1" });
    await settle();
    expect(h.result()).toContain('data-decision-status="refused"');
    expect(h.result()).toContain("Dismiss was refused for state export by fixture-agent (request tier1-1): Tier 1 items cannot be dismissed. Approve or deny instead. The decision was not applied.");
  });

  it("a unified batch the server refuses keeps the selection and never reads as done", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/inbox/unified/batch": () => Promise.resolve(response({ ok: false, error: "delete_confirmation_required" }, 400)),
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true; state.inboxOps.selected["wait-2"] = true; rerender();');
    expect(h.main()).toContain("2 selected");
    h.click({ "data-action": "inbox-batch-delete" });
    await settle();
    expect(h.posts()).toEqual(["/api/inbox/unified/batch"]);
    expect(h.result()).toContain('data-decision-status="refused"');
    expect(h.result()).toContain("Delete was refused for 2 selected items: delete_confirmation_required (HTTP 400).");
    expect(h.result()).not.toContain("Deleted");
    expect(h.main()).toContain('<p class="decision-inline" data-decision-status="refused">Refused.</p>');
    expect(h.main()).toContain("2 selected");
    expect(h.read('state.inboxOps.selected["wait-1"] === true && state.inboxOps.selected["wait-2"] === true')).toBe(true);
  });

  it("a unified batch the server acknowledged reports affected and missing counts and clears the selection", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/inbox/unified/batch": () => Promise.resolve(response({ ok: true, data: { result: { batch_correlation_id: "fixture", requested: 2, affected: 1, missing: ["wait-2"] } } })),
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true; state.inboxOps.selected["wait-2"] = true; rerender();');
    h.click({ "data-action": "inbox-batch-archive" });
    await settle();
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.result()).toContain("Archived 1 of 2 items. 1 was not found: wait-2.");
    expect(h.main()).toContain('<p class="decision-inline" data-decision-status="acknowledged">Archived 1 of 2 items.</p>');
    expect(h.read("Object.keys(state.inboxOps.selected).length")).toBe(0);
  });

  for (const [label, sent, body] of [
    ["carries no summary", 1, { ok: true }],
    ["counts more requests than were sent", 1, { ok: true, data: { result: { batch_correlation_id: "fixture", requested: 2, affected: 1, missing: [] } } }],
    ["counts that do not add up", 1, { ok: true, data: { result: { batch_correlation_id: "fixture", requested: 1, affected: 1, missing: ["wait-9"] } } }],
    ["carries a negative count that adds up", 1, { ok: true, data: { result: { batch_correlation_id: "fixture", requested: 1, affected: -1, missing: ["wait-1", "wait-2"] } } }],
    ["names a missing id this batch did not send", 1, { ok: true, data: { result: { batch_correlation_id: "fixture", requested: 1, affected: 0, missing: ["wait-9"] } } }],
    ["names a missing entry that is not an id", 1, { ok: true, data: { result: { batch_correlation_id: "fixture", requested: 1, affected: 0, missing: [{ foreign: "wait-1" }] } } }],
    ["names the same missing id twice", 2, { ok: true, data: { result: { batch_correlation_id: "fixture", requested: 2, affected: 0, missing: ["wait-1", "wait-1"] } } }],
  ] as const) it(`a unified batch whose answer ${label} reads as unconfirmed and keeps the selection`, async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/inbox/unified/batch": () => Promise.resolve(response(body)),
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true;' + (sent === 2 ? ' state.inboxOps.selected["wait-2"] = true;' : "") + ' rerender();');
    h.click({ "data-action": "inbox-batch-archive" });
    await settle();
    expect(h.result()).toContain('data-decision-status="uncertain"');
    expect(h.result()).toContain("did not confirm Archive for " + sent + " selected item" + (sent === 1 ? "." : "s."));
    expect(h.result()).not.toContain("Archived");
    expect(h.result()).not.toContain("[object");
    expect(h.read('state.inboxOps.selected["wait-1"]')).toBe(true);
  });

  it("a batch dismiss keeps each item's outcome and counts the refused ones", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("tier1-1", { tier: "tier1" })] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/hub/inbox/wait-1/dismiss": () => Promise.resolve(response(resolvedBody("wait-1"))),
      "/api/hub/inbox/tier1-1/dismiss": () => Promise.resolve(response({ error: "conflict" }, 409)),
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true; state.inboxOps.selected["tier1-1"] = true; rerender();');
    h.click({ "data-action": "inbox-batch-dismiss" });
    await settle();
    expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/dismiss", "/api/hub/inbox/tier1-1/dismiss"]);
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.result()).toContain("<strong>Decision partly taken</strong>");
    expect(h.el["decision-announcement"]!.textContent).toContain("Decision partly taken. Dismissed 1 of 2 items. 1 was refused.");
    expect(h.result()).toContain("Dismissed 1 of 2 items. 1 was refused.");
    expect(h.main(), "the toolbar echo keeps the partial refusal").toContain('<p class="decision-inline" data-decision-status="acknowledged">Dismissed 1 of 2 items. 1 was refused.</p>');
    expect(h.result()).toContain("<li>Dismissed: state export by fixture-agent (request wait-1).</li>");
    expect(h.result()).toContain("<li>Dismiss was refused for state export by fixture-agent (request tier1-1): Tier 1 items cannot be dismissed. Approve or deny instead. The decision was not applied.</li>");
  });

  it("one lock pauses every decision control on every screen, a second click sends nothing and the result names the first request", async () => {
    vi.useFakeTimers();
    const answer = gate<unknown>();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2"), held("tier1-1", { tier: "tier1" })] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/hub/inbox/wait-1/approve": () => answer.promise,
      "/api/hub/inbox/tier1-1/approve": () => Promise.resolve(response(resolvedBody("tier1-1"))),
      "/api/hub/inbox/wait-2/approve": () => Promise.resolve(response(resolvedBody("wait-2"))),
      "/api/inbox/unified/batch": () => Promise.resolve(response({ ok: true, data: { result: { batch_correlation_id: "fixture", requested: 1, affected: 1, missing: [] } } })),
    });
    await settle();
    h.navigate("approvals");
    await settle();
    // The Tier 1 request is selected and armed before the lock, so Confirm is on screen while the lock holds.
    h.click({ "data-action": "approval-select", "data-item-id": "tier1-1" });
    h.click({ "data-action": "approval-start-tier1-allow", "data-item-id": "tier1-1" });
    expect(h.main()).toContain('data-action="approval-confirm-tier1-allow" data-item-id="tier1-1">Confirm');
    expect(h.main()).not.toContain(BUSY);
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.result()).toContain('data-decision-status="pending"');
    expect(h.result()).toContain("Sending Allow once for state export by fixture-agent (request wait-1). Other decision controls are paused until the server answers.");
    expect(h.main()).toContain('data-action="inbox-approve" data-item-id="wait-2" ' + BUSY);
    expect(h.main()).toContain('data-action="inbox-deny" data-item-id="wait-2" ' + BUSY);
    expect(h.main()).toContain('data-action="approval-confirm-tier1-allow" data-item-id="tier1-1" ' + BUSY);
    expect(h.main()).toContain('data-action="approval-cancel-tier1-allow" data-item-id="tier1-1" ' + BUSY);
    expect(h.main()).toContain('data-action="inbox-deny" data-item-id="tier1-1" ' + BUSY);
    expect(h.main(), "the queue row echoes its own decision while the drawer shows another request").toContain('</div><p class="decision-inline" data-decision-status="pending">Sending Allow once.</p></td></tr><tr class="" data-approval-row="wait-2">');
    h.click({ "data-action": "approval-select", "data-item-id": "wait-1" });
    expect(h.main(), "the drawer echoes the selected request's decision").toContain('<p class="decision-inline" data-decision-status="pending">Sending Allow once.</p>');
    h.navigate("posture");
    expect(h.main()).toContain('data-action="inbox-approve" data-item-id="wait-2" ' + BUSY);
    expect(h.main(), "the Overview row echoes its own decision").toContain('data-item-id="wait-1" ' + BUSY + '>Deny</button></div><p class="decision-inline" data-decision-status="pending">Sending Allow once.</p>');
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-2"] = true; state.inboxOps.snoozeDialog = true; rerender();');
    for (const control of ["inbox-batch-archive", "inbox-batch-dismiss", "inbox-batch-snooze-open", "inbox-batch-delete", "inbox-batch-snooze-custom"]) expect(h.main()).toContain(`data-action="${control}" ` + BUSY);
    expect(h.main().match(/data-action="inbox-batch-snooze" data-snooze-ms="\d+" disabled title=/g)?.length, "every snooze duration is paused").toBe(4);
    expect(h.main(), "the row Snooze menu is paused").toContain('data-action="inbox-snooze-menu" data-item-id="wait-2" ' + BUSY + '>...</button>');
    expect(h.main(), "an item decision leaves the selection live").toContain('data-action="inbox-select" data-item-id="wait-2" checked>');
    h.click({ "data-action": "inbox-snooze-menu", "data-item-id": "wait-1" });
    expect(h.read('state.inboxOps.selected["wait-2"] === true && state.inboxOps.selected["wait-1"] !== true'), "the row menu under the lock changes nothing").toBe(true);
    expect(h.main(), "the Evidence row echoes its own decision").toContain('</div><p class="decision-inline" data-decision-status="pending">Sending Allow once.</p>');
    expect(h.main().split('class="decision-inline"').length - 1, "only the decided row echoes").toBe(1);
    expect(h.main()).toContain('data-action="inbox-approve" data-item-id="wait-2" ' + BUSY);
    h.read('state.selectedAgentId = "fixture-agent";');
    h.navigate("agent-detail");
    expect(h.main()).toContain('data-action="inbox-approve" data-item-id="wait-2" ' + BUSY);
    expect(h.main(), "the agent row echoes its own decision").toContain('data-item-id="wait-1" ' + BUSY + '>Allow once</button><p class="decision-inline" data-decision-status="pending">Sending Allow once.</p>');
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-2" });
    h.click({ "data-action": "inbox-batch-archive" });
    h.click({ "data-action": "inbox-batch-snooze", "data-snooze-ms": "3600000" });
    h.click({ "data-action": "inbox-batch-snooze-custom" });
    h.click({ "data-action": "approval-confirm-tier1-allow", "data-item-id": "tier1-1" });
    await settle();
    expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/approve"]);
    expect(h.read("state.approvals.result.itemId")).toBe("wait-1");
    answer.release(response(resolvedBody("wait-1")));
    await settle();
    expect(h.read("state.approvals.lock")).toBeNull();
    expect(h.read("state.approvals.result.itemId")).toBe("wait-1");
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.main()).not.toContain(BUSY);
    h.navigate("activity");
    expect(h.main(), "the decided row echoes the outcome").toContain('<p class="decision-inline" data-decision-status="acknowledged">Allowed once.</p>');
  });

  it("a batch in flight keeps its selection against the row Snooze menu and the checkboxes until it settles", async () => {
    vi.useFakeTimers();
    const answer = gate<unknown>();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/inbox/unified/batch": () => answer.promise,
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true; rerender();');
    h.click({ "data-action": "inbox-batch-archive" });
    await settle();
    expect(h.result()).toContain('data-decision-status="pending"');
    expect(h.main()).toContain('data-action="inbox-select" data-item-id="wait-2" ' + BUSY + '>');
    expect(h.main()).toContain('data-action="inbox-snooze-menu" data-item-id="wait-2" ' + BUSY + '>...</button>');
    h.click({ "data-action": "inbox-snooze-menu", "data-item-id": "wait-2" });
    h.click({ "data-action": "inbox-select", "data-item-id": "wait-2" }, true);
    h.click({ "data-action": "inbox-select", "data-item-id": "wait-1" }, false);
    expect(h.read("JSON.stringify(state.inboxOps.selected)")).toBe('{"wait-1":true}');
    expect(h.read("state.inboxOps.snoozeDialog")).toBeFalsy();
    answer.release(response({ ok: false, error: "delete_confirmation_required" }, 400));
    await settle();
    expect(h.result()).toContain('data-decision-status="refused"');
    expect(h.read("JSON.stringify(state.inboxOps.selected)"), "the refused batch keeps the selection it sent").toBe('{"wait-1":true}');
    expect(h.main()).not.toContain(BUSY);
    h.click({ "data-action": "inbox-snooze-menu", "data-item-id": "wait-2" });
    expect(h.read("JSON.stringify(state.inboxOps.selected)"), "after release the row menu works again").toBe('{"wait-2":true}');
  });

  it("the result block remains beside the stopped-updates panel too", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
      "/api/hub/inbox/wait-1/approve": () => Promise.resolve(response(resolvedBody("wait-1"))),
    });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    h.read("liveUpdatesStopped = true; rerender();");
    expect(h.main()).toContain("Live updates stopped");
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.result()).toContain("Allowed once: state export by fixture-agent (request wait-1).");
    expect(h.main()).not.toContain('class="decision-result"');
  });

  it("controls stay paused with the re-read reason until the queue re-read settles", async () => {
    vi.useFakeTimers();
    const reread = gate<unknown>();
    let decided = false;
    const h = boot({
      "/api/hub/inbox": () => decided ? reread.promise : Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/inbox/wait-1/approve": () => { decided = true; return Promise.resolve(response(resolvedBody("wait-1"))); },
    });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.result()).toContain("Re-reading the queue.");
    // While the queue is re-read the rows are not on screen; Clear is the control that carries the paused reason.
    expect(h.result()).toContain('data-action="decision-result-clear" ' + REREAD_BUSY + '>Clear</button>');
    expect(h.main()).not.toContain(BUSY);
    h.click({ "data-action": "decision-result-clear" });
    expect(h.read("state.approvals.result"), "Clear waits for the release").not.toBeNull();
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-2" });
    await settle();
    expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/approve"]);
    reread.release(response({ data: { items: [held("wait-2")] } }));
    await settle();
    expect(h.read("state.approvals.lock")).toBeNull();
    expect(h.main()).not.toContain(REREAD_BUSY);
    expect(h.result()).not.toContain("Re-reading the queue.");
  });

  it("a decision on a request the loaded queue no longer holds sends nothing and says so", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), { ...held("done-1"), resolved: true }] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
    });
    await settle();
    h.navigate("posture");
    h.click({ "data-action": "inbox-approve", "data-item-id": "gone-1" });
    await settle();
    expect(h.posts()).toEqual([]);
    expect(h.read("state.approvals.lock")).toBeNull();
    expect(h.result()).toContain('data-decision-status="not_sent"');
    expect(h.result()).not.toContain('data-decision-status="refused"');
    expect(h.result()).toContain("<strong>Decision not sent</strong>");
    expect(h.result()).toContain("Allow once was not sent for (request gone-1): " + NOT_SENT_STALE);
    expect(h.result()).toContain('data-action="decision-result-clear">Clear</button>');
    expect(h.el["decision-announcement"]!.textContent).toBe("Decision not sent. Allow once was not sent for (request gone-1): " + NOT_SENT_STALE);
    expect(h.main()).not.toContain(BUSY);
    h.click({ "data-action": "inbox-deny", "data-item-id": "done-1" });
    await settle();
    expect(h.posts()).toEqual([]);
    expect(h.result()).toContain("Deny was not sent for state export by fixture-agent (request done-1): " + NOT_SENT_STALE);
    expect(h.main(), "the decided row echoes the not-sent outcome").not.toContain('data-decision-status="refused"');
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true; state.inboxOps.selected["done-1"] = true; state.inboxOps.snoozeDialog = true; rerender();');
    h.click({ "data-action": "inbox-batch-snooze", "data-snooze-ms": "3600000" });
    await settle();
    expect(h.posts()).toEqual([]);
    expect(h.result()).toContain("Snooze was not sent for 2 selected items: 1 of the 2 selected items is no longer waiting in the loaded queue, so nothing was sent.");
    expect(h.main()).toContain('<p class="decision-inline" data-decision-status="not_sent">Not sent.</p>');
    expect(h.read('state.inboxOps.selected["wait-1"] === true && state.inboxOps.selected["done-1"] === true')).toBe(true);
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.posts(), "a held request still decides").toEqual(["/api/hub/inbox/wait-1/approve"]);
  });

  it("a decision while the queue read is not current sends nothing and asks for a re-read", async () => {
    vi.useFakeTimers();
    let reads = 0;
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(++reads === 1 ? response({ data: { items: [held("wait-1"), held("wait-2")] } }) : response({ error: "read failed" }, 500)),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/hub/inbox/wait-1/approve": () => Promise.resolve(response(resolvedBody("wait-1"))),
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-2"] = true; state.inboxOps.snoozeDialog = true; rerender();');
    expect(h.main()).toContain('data-action="inbox-batch-snooze-custom"');
    // The second inbox read fails: the rows the operator still sees come from a read that is no longer current.
    await h.read("fetchAll(true)");
    await settle();
    expect(reads).toBe(2);
    h.click({ "data-action": "inbox-batch-snooze", "data-snooze-ms": "3600000" });
    await settle();
    expect(h.posts()).toEqual([]);
    expect(h.result()).toContain('data-decision-status="not_sent"');
    expect(h.result()).toContain("Snooze was not sent for 1 selected item: " + NOT_SENT_UNREAD);
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.posts()).toEqual([]);
    expect(h.result()).toContain("Allow once was not sent for state export by fixture-agent (request wait-1): " + NOT_SENT_UNREAD);
    expect(h.read("state.approvals.lock")).toBeNull();
  });

  it("consent survives a decision on another row and resets for the decided request", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/inbox/wait-2/deny": () => Promise.resolve(response(resolvedBody("wait-2"))),
      "/api/hub/inbox/wait-1/deny": () => Promise.resolve(response(resolvedBody("wait-1"))),
    });
    await settle();
    h.navigate("approvals");
    await settle();
    h.click({ "data-action": "approval-select", "data-item-id": "wait-1" });
    h.click({ "data-action": "approval-always-allow" }, true);
    expect(h.main()).toContain('data-approval-primary="wait-1" data-action="inbox-promote"');
    h.click({ "data-action": "inbox-deny", "data-item-id": "wait-2" });
    await settle();
    expect(h.posts()).toEqual(["/api/hub/inbox/wait-2/deny"]);
    expect(h.read("state.approvals.alwaysAllow")).toBe(true);
    expect(h.read("state.approvals.selectedId")).toBe("wait-1");
    expect(h.main()).toContain('data-approval-primary="wait-1" data-action="inbox-promote"');
    h.click({ "data-action": "inbox-deny", "data-item-id": "wait-1" });
    await settle();
    expect(h.read("state.approvals.alwaysAllow")).toBe(false);
  });

  // Records every renderMain call (whether or not it rewrote #main) with the fake-clock time, whether the decision
  // lock was held, and the #main markup it left.
  type Paint = { time: number; locked: boolean; html: string };
  function recordPaints(h: ReturnType<typeof boot>) {
    const paints: Paint[] = [];
    (h.context as Record<string, unknown>).__paintLog = (locked: boolean) => paints.push({ time: Date.now(), locked, html: h.main() });
    h.read("const __renderMainUnderTest = renderMain; renderMain = function () { __renderMainUnderTest(); __paintLog(!!state.approvals.lock); };");
    return paints;
  }
  // The release paint may change only the attributes the lock adds: a lock reason title with its disabled flag,
  // the bare disabled flag on the Always allow checkbox, and the row Snooze menu's own title when it is live.
  // Only those tags are normalized, so a changed sentence, label, other control's state or tooltip still fails.
  const LOCK_REASONS = [BUSY, REREAD_BUSY].map((pair) => " " + pair);
  const withoutLockAttributes = (html: string) => html.replace(/<[^>]*>/g, (tag) => {
    let out = tag;
    for (const reason of LOCK_REASONS) out = out.split(reason).join("");
    if (out.includes('data-action="approval-always-allow"')) out = out.replace(/(?<="| checked) disabled(?=[ >])/, "");
    if (out.includes('data-action="inbox-snooze-menu"')) out = out.replace(' title="Snooze"', "");
    return out;
  });
  function expectAttributeOnlyRelease(paints: Paint[]) {
    const release = paints.findIndex((p, i) => i > 0 && !p.locked && paints[i - 1]!.locked);
    expect(release, "a repaint released the lock").toBeGreaterThan(0);
    const released = paints[release]!;
    expect(released.html).not.toContain(BUSY);
    expect(released.html).not.toContain(REREAD_BUSY);
    expect(withoutLockAttributes(released.html)).toBe(withoutLockAttributes(paints[release - 1]!.html));
    // The last held paint that changed #main stayed on screen, controls paused, for the whole hold.
    let lastChange = -1;
    for (let i = 1; i < release; i++) if (paints[i]!.html !== paints[i - 1]!.html) lastChange = i;
    expect(lastChange, "the decision changed #main under the lock").toBeGreaterThan(0);
    expect(released.time - paints[lastChange]!.time, "held after its last change").toBeGreaterThanOrEqual(RELEASE_HOLD_MS);
  }

  for (const [label, items, decided, answer, pre] of [
    ["Allow always refused on the selected request", [held("wait-1"), held("wait-2")], "/api/hub/inbox/wait-1/approve", () => Promise.resolve(response({ error: "refused" }, 403)),
      (h: ReturnType<typeof boot>) => { h.click({ "data-action": "approval-select", "data-item-id": "wait-1" }); h.click({ "data-action": "approval-always-allow" }, true); h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" }); }],
    ["Allow always unconfirmed on the selected request", [held("wait-1"), held("wait-2")], "/api/hub/inbox/wait-1/approve", () => Promise.reject(new Error("network down")),
      (h: ReturnType<typeof boot>) => { h.click({ "data-action": "approval-select", "data-item-id": "wait-1" }); h.click({ "data-action": "approval-always-allow" }, true); h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" }); }],
    ["a Tier 1 Confirm refused on the selected request", [held("wait-1", { tier: "tier1" }), held("wait-2")], "/api/hub/inbox/wait-1/approve", () => Promise.resolve(response({ error: "refused" }, 403)),
      (h: ReturnType<typeof boot>) => { h.click({ "data-action": "approval-select", "data-item-id": "wait-1" }); h.click({ "data-action": "approval-start-tier1-allow", "data-item-id": "wait-1" }); h.click({ "data-action": "approval-confirm-tier1-allow", "data-item-id": "wait-1" }); }],
    ["a deny on another row while Allow always stays chosen", [held("wait-1"), held("wait-2")], "/api/hub/inbox/wait-2/deny", () => Promise.resolve(response(resolvedBody("wait-2"))),
      (h: ReturnType<typeof boot>) => { h.click({ "data-action": "approval-select", "data-item-id": "wait-1" }); h.click({ "data-action": "approval-always-allow" }, true); h.click({ "data-action": "inbox-deny", "data-item-id": "wait-2" }); }],
  ] as const) {
    it(`releasing the lock after ${label} changes only the paused attributes`, async () => {
      vi.useFakeTimers();
      const h = boot({
        "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
        [decided]: answer,
      });
      await settle();
      h.navigate("approvals");
      await settle();
      const paints = recordPaints(h);
      pre(h);
      await settle();
      await settle();
      expect(h.posts()).toEqual([decided]);
      expect(h.read("state.approvals.lock")).toBeNull();
      expectAttributeOnlyRelease(paints);
    });
  }

  it("releasing the lock after a decision whose re-read fails changes only the paused attributes", async () => {
    vi.useFakeTimers();
    let decided = false;
    const h = boot({
      "/api/hub/inbox": () => decided ? Promise.resolve(response({ error: "down" }, 503)) : Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/inbox/wait-1/approve": () => { decided = true; return Promise.resolve(response({ error: "refused" }, 403)); },
    });
    await settle();
    h.navigate("approvals");
    await settle();
    const paints = recordPaints(h);
    h.click({ "data-action": "approval-select", "data-item-id": "wait-1" });
    h.click({ "data-action": "approval-always-allow" }, true);
    h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" });
    await settle();
    await settle();
    expect(h.read("state.approvals.result.refresh")).toBe("unavailable");
    expect(h.read("state.approvals.lock")).toBeNull();
    expectAttributeOnlyRelease(paints);
  });

  it("releasing the lock after a refused batch changes only the paused attributes", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/inbox/unified/batch": () => Promise.resolve(response({ ok: false, error: "delete_confirmation_required" }, 400)),
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true; state.inboxOps.selected["wait-2"] = true; rerender();');
    const paints = recordPaints(h);
    h.click({ "data-action": "inbox-batch-delete" });
    await settle();
    expect(h.posts()).toEqual(["/api/inbox/unified/batch"]);
    expectAttributeOnlyRelease(paints);
  });

  it("the release hold matches the client constant", () => {
    const h = boot();
    expect(h.read("DECISION_RELEASE_HOLD_MS")).toBe(RELEASE_HOLD_MS);
  });

  // Boots the Approvals screen with Allow always chosen on wait-1 and a refused approval, the path whose consent
  // reset rewrites the drawer copy above Allow once.
  async function refusedAllowAlways() {
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/inbox/wait-1/approve": () => Promise.resolve(response({ error: "refused" }, 403)),
    });
    await settle();
    h.navigate("approvals");
    await settle();
    h.click({ "data-action": "approval-select", "data-item-id": "wait-1" });
    h.click({ "data-action": "approval-always-allow" }, true);
    return h;
  }
  async function drain() { for (let i = 0; i < 100; i++) await Promise.resolve(); }

  it("the decision's layout is painted under the lock and held for the full hold before the controls enable", async () => {
    vi.useFakeTimers();
    const h = await refusedAllowAlways();
    h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" });
    await drain();
    // The refusal, the re-read and the consent reset are all on screen, every decision control still paused.
    expect(h.result()).toContain('data-decision-status="refused"');
    expect(h.read("state.approvals.alwaysAllow")).toBe(false);
    expect(h.main()).toContain('data-approval-primary="wait-1" data-action="inbox-approve" data-item-id="wait-1" ' + REREAD_BUSY + '>Allow once</button>');
    await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS - 1);
    expect(h.read("state.approvals.lock"), "still held one millisecond before the hold ends").not.toBeNull();
    await vi.advanceTimersByTimeAsync(1);
    await drain();
    expect(h.read("state.approvals.lock")).toBeNull();
    expect(h.main()).toContain('data-approval-primary="wait-1" data-action="inbox-approve" data-item-id="wait-1">Allow once</button>');
  });

  it("a background repaint during the hold restarts it", async () => {
    vi.useFakeTimers();
    const h = await refusedAllowAlways();
    h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" });
    await drain();
    await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS / 2);
    // A background read lands mid-hold and adds a row above nothing the operator chose; #main is rewritten.
    h.read('state.inbox.push(Object.assign({}, state.inbox[0], { item_id: "wait-3" })); rerender();');
    await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS / 2);
    await drain();
    expect(h.read("state.approvals.lock"), "the first hold saw a rewrite, so it does not release").not.toBeNull();
    await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS);
    await drain();
    expect(h.read("state.approvals.lock")).toBeNull();
  });

  it("a screen that keeps changing keeps decisions paused until it has been quiet for a full hold", async () => {
    vi.useFakeTimers();
    const h = await refusedAllowAlways();
    h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" });
    await drain();
    // Fifteen holds, each rewritten mid-hold: none may release onto a layout the operator has not seen.
    for (let hold = 0; hold < 15; hold++) {
      await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS / 2);
      h.read('state.inbox.push(Object.assign({}, state.inbox[0], { item_id: "churn-' + hold + '" })); rerender();');
      await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS / 2);
      await drain();
      expect(h.read("state.approvals.lock"), "held through hold " + hold).not.toBeNull();
    }
    await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS);
    await drain();
    expect(h.read("state.approvals.lock")).toBeNull();
  });

  it("a repaint that throws during the hold still releases the lock", async () => {
    vi.useFakeTimers();
    const h = await refusedAllowAlways();
    const main = h.el.main!;
    let throwOnce = false;
    let threw = false;
    Object.defineProperty(h.el, "main", {
      configurable: true,
      get() { if (throwOnce) { throwOnce = false; threw = true; throw new Error("fixture repaint failure"); } return main; },
    });
    h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" });
    await drain();
    expect(h.read("state.approvals.lock")).not.toBeNull();
    throwOnce = true;
    await vi.advanceTimersByTimeAsync(RELEASE_HOLD_MS);
    await drain();
    expect(threw, "the hold's repaint threw").toBe(true);
    expect(h.read("state.approvals.lock")).toBeNull();
    expect(h.main()).toContain('data-approval-primary="wait-1" data-action="inbox-approve" data-item-id="wait-1">Allow once</button>');
  });

  it("the result survives a route change and clears only through its own control", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
      "/api/hub/inbox/wait-1/approve": () => Promise.resolve(response(resolvedBody("wait-1"))),
    });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    h.navigate("posture");
    expect(h.result()).toContain("Allowed once: state export by fixture-agent (request wait-1).");
    h.navigate("approvals");
    expect(h.result()).toContain("Allowed once: state export by fixture-agent (request wait-1).");
    expect(h.result()).toContain('data-action="decision-result-clear"');
    const mainBeforeClear = h.main();
    const requestsBeforeClear = h.requests.length;
    h.click({ "data-action": "decision-result-clear" });
    expect(h.result()).toBe("");
    expect(h.main()).toBe(mainBeforeClear);
    expect(h.requests).toHaveLength(requestsBeforeClear);
    expect(h.read("state.approvals.result.cleared")).toBe(true);
    h.read("rerender()");
    expect(h.result()).toBe("");
    expect(h.main()).toBe(mainBeforeClear);
  });

  for (const [label, activate, rule, text] of [
    ["refused", () => Promise.resolve(response({ error: "not configured" }, 503)), "refused", "The standing rule was not added: Policy engine is not configured on this fortress."],
    ["refused by an explicit status", () => Promise.resolve(response({ ok: true, data: { status: "rejected" } })), "refused", "The standing rule was not added: Rule not activated (rejected)."],
    ["unconfirmed", () => Promise.reject(new Error("network down")), "uncertain", "The standing rule may not have been added: network down." + CHECK_RULE],
    ["unconfirmed by an answer without a status", () => Promise.resolve(response({ ok: true, data: {} })), "uncertain", "The standing rule may not have been added: the activation answer could not be read." + CHECK_RULE],
    ["unconfirmed by an unreadable answer", () => Promise.resolve(response(null)), "uncertain", "The standing rule may not have been added: the activation answer could not be read." + CHECK_RULE],
  ] as const) {
    it(`Allow always reports a ${label} standing rule in words on an acknowledged approval`, async () => {
      vi.useFakeTimers();
      const h = boot({
        "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
        "/api/hub/inbox/wait-1/approve": () => Promise.resolve(response(resolvedBody("wait-1"))),
        "/api/policy/compile": () => Promise.resolve(response({ data: { draft: { draft_id: "rule" } } })),
        "/api/policy/drafts/rule/activate": activate,
      });
      await settle();
      h.navigate("approvals");
      await settle();
      h.click({ "data-action": "approval-always-allow" }, true);
      h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" });
      await settle();
      await settle();
      expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/approve", "/api/policy/compile", "/api/policy/drafts/rule/activate"]);
      expect(h.result()).toContain('data-decision-status="acknowledged"');
      expect(h.result()).toContain("Allowed once: state export by fixture-agent (request wait-1). Marked decided in this inbox. " + text);
      expect(h.read("state.approvals.result.rule")).toBe(rule);
      expect(h.el["toast-host"]!.innerHTML).toBe("");
    });
  }

  it("a refused approval under Allow always requests no standing rule", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
      "/api/hub/inbox/wait-1/approve": () => Promise.resolve(response({ error: "refused" }, 403)),
    });
    await settle();
    h.navigate("approvals");
    await settle();
    h.click({ "data-action": "approval-always-allow" }, true);
    h.click({ "data-action": "inbox-promote", "data-item-id": "wait-1" });
    await settle();
    await settle();
    expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/approve"]);
    expect(h.result()).toContain('data-decision-status="refused"');
    expect(h.result()).toContain("No standing rule was requested.");
    expect(h.read("state.approvals.result.rule")).toBe("refused");
  });
});
