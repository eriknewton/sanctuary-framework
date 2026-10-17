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
 * approval. The decision-result witness for defect D5-approval; no reproduction of a live defect is given.
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
const resolvedBody = (itemId: string) => ({ ok: true, data: { item: { ...held(itemId), resolved: true, resolved_at: "2026-10-17T16:46:00.000Z" } } });
const BUSY = 'disabled title="Another decision is being sent."';
const REREAD = "The queue could not be re-read after this decision, so this list may be out of date.";

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
  "machines-summary", "machines-age", "machines-list", "toast-host", "decision-announcement",
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
  const result = () => (main().split('class="decision-result"')[1] ?? "").split("</section>")[0]!;
  const read = (expression: string) => runInContext(expression, context);
  return { el, context, navigate, click, requests, posts, main, result, read };
}
async function settle() { for (let i = 0; i < 100; i++) await Promise.resolve(); }
function gate<T>() { let release!: (value: T) => void; const promise = new Promise<T>((resolve) => { release = resolve; }); return { promise, release }; }
afterEach(() => { vi.useRealTimers(); });

describe("one retained decision result", () => {
  for (const failing of ["the inbox read", "every read"]) {
    it(`an acknowledged decision whose refresh cannot load ${failing} reads as taken with the re-read note, never as refused`, async () => {
      vi.useFakeTimers();
      let decided = false;
      const h = boot({
        "/api/hub/inbox": () => Promise.resolve(decided ? response({ error: "read failed" }, 500) : response({ data: { items: [held("wait-1")] } })),
        "/api/posture/home": () => Promise.resolve(decided && failing === "every read" ? response({ error: "read failed" }, 500) : response(home())),
        "/api/hub/inbox/wait-1/approve": () => { decided = true; return Promise.resolve(response(resolvedBody("wait-1"))); },
      });
      await settle();
      h.navigate("approvals");
      h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
      await settle();
      expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/approve"]);
      expect(h.result()).toContain('data-decision-status="acknowledged"');
      expect(h.result()).toContain("Allowed once: state_export by fixture-agent (request wait-1). Marked decided in this inbox. " + REREAD);
      expect(h.result()).not.toMatch(/refused|failed/);
      expect(h.el["decision-announcement"]!.textContent).toContain("Decision taken. Allowed once: state_export by fixture-agent (request wait-1).");
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
    Object.defineProperty(h.el, "main", {
      configurable: true,
      get() { if (throwOnce) { throwOnce = false; throw new Error("fixture repaint failure"); } return main; },
    });
    // The inbox panel's final repaint after the decision throws: the client clears the panel's pending entry
    // right before that repaint, so arming there hits the repaint whose failure rejects the whole refresh.
    h.context.armRepaintThrow = () => { if (decided) throwOnce = true; };
    h.read('const clearPanel = pendingPanels.delete.bind(pendingPanels); pendingPanels.delete = function (job) { if (job.paths.indexOf(HUB + "/inbox") >= 0) armRepaintThrow(); return clearPanel(job); };');
    h.navigate("approvals");
    h.click({ "data-action": "inbox-deny", "data-item-id": "wait-1" });
    await settle();
    expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/deny"]);
    expect(throwOnce, "the armed repaint threw").toBe(false);
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.result()).toContain("Denied: state_export by fixture-agent (request wait-1). Marked decided in this inbox. " + REREAD);
    expect(h.result()).not.toMatch(/refused|failed|repaint/);
    expect(h.read("state.approvals.lock")).toBeNull();
    expect(h.read("state.approvals.result.refresh")).toBe("unavailable");
  });

  for (const [label, body] of [
    ["names another item", { ok: true, data: { item: { ...held("other"), resolved: true } } }],
    ["lacks resolved", { ok: true, data: { item: held("wait-1") } }],
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
      expect(h.result()).toContain("did not confirm Allow once for state_export by fixture-agent (request wait-1). The decision may or may not have been applied. Check the queue before deciding again.");
      expect(h.result()).not.toContain("Allowed once");
      expect(h.main()).toContain("WAITING");
    });
  }

  for (const [label, answer, status, text] of [
    ["a 500", () => Promise.resolve(response({ error: "storage unavailable" }, 500)), "uncertain", "did not confirm Allow once for state_export by fixture-agent (request wait-1) (storage unavailable (HTTP 500))."],
    ["no answer", () => Promise.reject(new Error("network down")), "uncertain", "(network down). The decision may or may not have been applied."],
    ["a 401", () => Promise.resolve(response({ error: "operator session required" }, 401)), "refused", "Allow once was refused for state_export by fixture-agent (request wait-1): operator session required (HTTP 401). The request is still waiting."],
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
    expect(h.result()).toContain("Dismiss was refused for state_export by fixture-agent (request tier1-1): Tier 1 items cannot be dismissed. Approve or deny instead. The request is still waiting.");
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
    expect(h.main()).toContain('<p class="decision-inline" data-decision-status="refused">Refused. See the decision result at the top of this screen.</p>');
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

  it("a unified batch answered without consistent counts reads as unconfirmed and keeps the selection", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1")] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/inbox/unified/batch": () => Promise.resolve(response({ ok: true })),
    });
    await settle();
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-1"] = true; rerender();');
    h.click({ "data-action": "inbox-batch-archive" });
    await settle();
    expect(h.result()).toContain('data-decision-status="uncertain"');
    expect(h.result()).toContain("did not confirm Archive for 1 selected item.");
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
    expect(h.result()).toContain("Dismissed 1 of 2 items. 1 was refused.");
    expect(h.result()).toContain("<li>Dismissed: state_export by fixture-agent (request wait-1).</li>");
    expect(h.result()).toContain("<li>Dismiss was refused for state_export by fixture-agent (request tier1-1): Tier 1 items cannot be dismissed. Approve or deny instead. The request is still waiting.</li>");
  });

  it("one lock pauses every decision control on every screen, a second click sends nothing and the result names the first request", async () => {
    vi.useFakeTimers();
    const answer = gate<unknown>();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [held("wait-1"), held("wait-2")] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/hub/inbox/wait-1/approve": () => answer.promise,
      "/api/hub/inbox/wait-2/approve": () => Promise.resolve(response(resolvedBody("wait-2"))),
      "/api/inbox/unified/batch": () => Promise.resolve(response({ ok: true, data: { result: { batch_correlation_id: "fixture", requested: 1, affected: 1, missing: [] } } })),
    });
    await settle();
    h.navigate("approvals");
    expect(h.main()).not.toContain(BUSY);
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.result()).toContain('data-decision-status="pending"');
    expect(h.result()).toContain("Sending Allow once for state_export by fixture-agent (request wait-1). Other decision controls are paused until the server answers.");
    expect(h.main()).toContain('data-action="inbox-approve" data-item-id="wait-2" ' + BUSY);
    expect(h.main()).toContain('data-action="inbox-deny" data-item-id="wait-2" ' + BUSY);
    expect(h.main()).toContain('<p class="decision-inline" data-decision-status="pending">Sending Allow once.</p>');
    h.navigate("posture");
    expect(h.main()).toContain('data-action="inbox-approve" data-item-id="wait-2" ' + BUSY);
    h.navigate("activity");
    h.read('state.inboxOps.selected["wait-2"] = true; rerender();');
    for (const control of ["inbox-batch-archive", "inbox-batch-dismiss", "inbox-batch-snooze-open", "inbox-batch-delete"]) expect(h.main()).toContain(`data-action="${control}" ` + BUSY);
    expect(h.main(), "an item decision leaves no batch echo").not.toContain('class="decision-inline"');
    expect(h.main()).toContain('data-action="inbox-approve" data-item-id="wait-2" ' + BUSY);
    h.read('state.selectedAgentId = "fixture-agent";');
    h.navigate("agent-detail");
    expect(h.main()).toContain('data-action="inbox-approve" data-item-id="wait-2" ' + BUSY);
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-2" });
    h.click({ "data-action": "inbox-batch-archive" });
    await settle();
    expect(h.posts()).toEqual(["/api/hub/inbox/wait-1/approve"]);
    expect(h.read("state.approvals.result.itemId")).toBe("wait-1");
    answer.release(response(resolvedBody("wait-1")));
    await settle();
    expect(h.read("state.approvals.lock")).toBeNull();
    expect(h.read("state.approvals.result.itemId")).toBe("wait-1");
    expect(h.result()).toContain('data-decision-status="acknowledged"');
    expect(h.main()).not.toContain(BUSY);
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
    expect(h.result()).toContain("Allowed once: state_export by fixture-agent (request wait-1).");
    h.navigate("approvals");
    expect(h.result()).toContain("Allowed once: state_export by fixture-agent (request wait-1).");
    expect(h.result()).toContain('data-action="decision-result-clear"');
    h.click({ "data-action": "decision-result-clear" });
    expect(h.main()).not.toContain("decision-result");
    expect(h.read("state.approvals.result")).toBeNull();
  });

  for (const [label, activate, rule, text] of [
    ["refused", () => Promise.resolve(response({ error: "not configured" }, 503)), "refused", "The standing rule was not added: Policy engine is not configured on this fortress."],
    ["unconfirmed", () => Promise.reject(new Error("network down")), "uncertain", "The standing rule may not have been added: network down Check the policy before relying on it."],
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
      expect(h.result()).toContain("Allowed once: state_export by fixture-agent (request wait-1). Marked decided in this inbox. " + text);
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
