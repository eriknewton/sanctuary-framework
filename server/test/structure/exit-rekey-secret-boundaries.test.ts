/** Export disclosure is bounded to one deciding view and cleared across its lifecycle. IC-07. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";

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
  "exit-rekey-view", "machines-summary", "machines-age", "machines-list", "toast-host", "decision-announcement", "decision-feedback-result",
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
  const streamListeners: Record<string, (event: { data: string }) => void> = {};
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
  const storageSpy = vi.fn();
  const context = createContext({
    document: {
      hidden: false,
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
    location, sessionStorage: { getItem: () => null, setItem: storageSpy }, localStorage: { getItem: () => null, setItem: storageSpy }, console: { log: storageSpy, error: storageSpy }, navigator: { clipboard: { writeText: storageSpy } },
    URLSearchParams, URL, AbortController, TextDecoder, Date, Element: FakeElement, HTMLInputElement: FakeInput, Blob,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    EventSource: class { addEventListener(name: string, fn: (event: { data: string }) => void) { streamListeners[name] = fn; } close() {} },
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
  return { el, context, navigate, click, requests, posts, main, result, read, docListeners, winListeners, streamListeners, storageSpy };
}
async function settle() { for (let i = 0; i < 100; i++) await Promise.resolve(); }
function gate<T>() { let release!: (value: T) => void; const promise = new Promise<T>((resolve) => { release = resolve; }); return { promise, release }; }
afterEach(() => { vi.useRealTimers(); });

const REKEY = Buffer.from("synthetic-export-key-for-tests!!").toString("base64url");
const safePayload = { bundle_dir: "/tmp/exit-bundles/fixture", manifest_hash: "a".repeat(64), artifact_count: 7, state_entry_count: 1 };
const exportItem = (id = "export-1") => held(id, { operation_category: "exit_bundle_export", tier: "tier1", agent_id: undefined });
function deliveryBody(id = "export-1") {
  return { data: { item: { ...exportItem(id), resolved: true, resolution_payload: { ...safePayload } }, one_time_export: { state_rekey_key: REKEY, bundle_dir: safePayload.bundle_dir, manifest_hash: safePayload.manifest_hash } } };
}
async function deciding() {
  const body = deliveryBody();
  const h = boot({
    "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [exportItem(), held("next")] } })),
    "/api/hub/inbox/export-1/approve": () => Promise.resolve(response(body)),
  });
  await settle(); h.navigate("approvals"); await settle();
  h.click({ "data-action": "inbox-approve", "data-item-id": "export-1" }); await settle();
  expect(h.el["exit-rekey-view"]!.textContent).toContain(REKEY);
  return { h, body };
}
function noSharedSecret(h: ReturnType<typeof boot>) {
  expect(h.read("JSON.stringify(state)")).not.toContain(REKEY);
  expect(h.result()).not.toContain(REKEY);
  expect(h.el["decision-announcement"]!.textContent).not.toContain(REKEY);
  expect(h.el["toast-host"]!.innerHTML).not.toContain(REKEY);
  expect(JSON.stringify(h.storageSpy.mock.calls)).not.toContain(REKEY);
}

describe("one-time browser delivery", () => {
  it("approver-without-wizard-shows-key-once", async () => {
    vi.useFakeTimers();
    const { h, body } = await deciding();
    expect(h.read("state.exitDrill.inboxItemId")).toBeNull();
    h.read('state.exitDrill.inboxItemId = "older-export"; state.exitDrill.bundleResult = { state_entry_count: 1 };');
    expect(h.read("renderExitDrill()")).not.toContain("Re-key key available for this export.");
    expect(body.data.one_time_export).toBeUndefined();
    expect(h.el["exit-rekey-view"]!.textContent).toContain("Bundle created. Save this re-key key separately from the bundle. You will need it to import the encrypted state on another machine.");
    noSharedSecret(h);
    const other = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [body.data.item] } })) });
    await settle();
    expect(other.el["exit-rekey-view"]!.textContent).not.toContain(REKEY);
    expect(other.posts()).toEqual([]);
  });

  it("key-view-survives-rerender-but-clears-on-lifecycle", async () => {
    vi.useFakeTimers();
    for (const clear of ["acknowledgement", "expiry", "navigation", "pagehide", "hidden"]) {
      const { h } = await deciding();
      h.read("rerender()"); await h.read("fetchAll(true)"); await settle();
      expect(h.el["exit-rekey-view"]!.textContent).toContain(REKEY);
      if (clear === "acknowledgement") h.click({ "data-action": "exit-rekey-clear" });
      if (clear === "expiry") { vi.advanceTimersByTime(5 * 60 * 1000 - 1); expect(h.el["exit-rekey-view"]!.textContent).toContain(REKEY); vi.advanceTimersByTime(1); }
      if (clear === "navigation") h.navigate("activity");
      if (clear === "pagehide") h.winListeners.pagehide!();
      if (clear === "hidden") { h.read("document.hidden = true"); h.docListeners.visibilitychange!({}); }
      expect(h.el["exit-rekey-view"]!.textContent).toBe("");
      expect(h.streamListeners.inbox).toBeTypeOf("function");
      h.streamListeners.inbox!({ data: JSON.stringify({ ...exportItem(), resolved: true, resolution_payload: safePayload }) });
      h.read("rerender()"); expect(h.el["exit-rekey-view"]!.textContent).toBe(""); noSharedSecret(h);
    }
    // Navigation while the POST is pending also invalidates presentation of a late answer.
    const pending = gate<unknown>(); const body = deliveryBody();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [exportItem()] } })), "/api/hub/inbox/export-1/approve": () => pending.promise });
    await settle(); h.click({ "data-action": "inbox-approve", "data-item-id": "export-1" }); await settle();
    h.navigate("activity"); pending.release(response(body)); await settle();
    expect(h.el["exit-rekey-view"]!.textContent).toBe(""); expect(body.data.one_time_export).toBeUndefined();
  });

  it("batch-pauses-at-key-disclosure", async () => {
    vi.useFakeTimers(); const { h } = await deciding();
    const before = h.posts();
    h.read('state.inboxOps.selected["next"] = true');
    await h.read('onInboxBatchAction("dismiss")');
    h.click({ "data-action": "inbox-approve", "data-item-id": "next" }); await settle();
    expect(h.posts()).toEqual(before); expect(h.el["exit-rekey-view"]!.textContent).toContain(REKEY);
    expect(h.read("state.approvals.result.records")).toEqual([]); noSharedSecret(h);
    h.click({ "data-action": "exit-rekey-clear" });
    await h.read('onInboxBatchAction("dismiss")'); await settle();
    expect(h.posts()).toContain("/api/hub/inbox/next/dismiss");
  });

  it("browser-never-retains-key-in-shared-state-or-storage", async () => {
    vi.useFakeTimers(); const { h } = await deciding();
    noSharedSecret(h);
    h.click({ "data-action": "exit-rekey-clear" });
    for (const node of Object.values(h.el)) expect(node.innerHTML).not.toContain(REKEY);
    noSharedSecret(h);
    // A malformed/empty response, an unavailable host, and a throwing renderer discard the parsed key.
    for (const mode of ["empty", "fractional", "wrong-item", "hidden", "missing-host", "render-error"]) {
      const body = deliveryBody();
      const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [exportItem()] } })), "/api/hub/inbox/export-1/approve": () => Promise.resolve(response(body)) });
      await settle();
      if (mode === "empty") body.data.item.resolution_payload.state_entry_count = 0;
      if (mode === "fractional") body.data.item.resolution_payload.state_entry_count = 0.5;
      if (mode === "wrong-item") body.data.item.item_id = "another";
      if (mode === "hidden") h.read("document.hidden = true");
      if (mode === "missing-host") delete h.el["exit-rekey-view"];
      if (mode === "render-error") h.read('document.createElement = function () { throw new Error("render unavailable"); }');
      h.click({ "data-action": "inbox-approve", "data-item-id": "export-1" }); await settle();
      expect(body.data.one_time_export).toBeUndefined(); noSharedSecret(h);
      expect(h.el["exit-rekey-view"]?.textContent || "").not.toContain(REKEY);
      if (mode === "empty") expect(h.result()).toContain("This bundle contains no encrypted state. No re-key key was created.");
    }
  });

  it("decision-wire-and-display-contract-diff-is-intentional", async () => {
    const { readFile } = await import("node:fs/promises");
    const client = getClientScript();
    const source = (path: string) => readFile(new URL("../../src/" + path, import.meta.url), "utf8");
    const [types, router, store, service, wiring, html] = await Promise.all(["hub/types.ts", "hub/api-router.ts", "hub/inbox-store.ts", "hub/hub-service.ts", "dashboard/v1_1/wiring.ts", "dashboard/v1_1/html.ts"].map(source));
    expect(types).toContain("export interface HubOneTimeExport");
    const safeType = types!.split("export interface HubFortressExportResult")[1]!.split("\n}")[0]!;
    expect(safeType).not.toContain("state_rekey_key");
    expect(router).toContain("one_time_export: slot");
    expect(store!.split("async resolve(")[1]!.split("pruneResolvedOlderThan")[0]).not.toContain("upsertFromSource");
    expect(store).toContain("projectHubExportResult(handlerResult.resolution_payload");
    expect(service).toContain("await this.deps.activitySources.auditLog.appendCritical");
    expect(wiring).toContain("delete exported.state_rekey_key");
    expect(html).toContain('id="exit-rekey-view" hidden');
    expect(client).not.toContain("Re-key complete.");
    for (const sentence of [
      "This export includes a re-key key when it contains encrypted state. The key will be shown only in the dashboard that approves this export.",
      "Bundle created. Save this re-key key separately from the bundle. You will need it to import the encrypted state on another machine.",
      "This key is shown once and is not saved by Sanctuary. It disappears when you close this view or after five minutes.",
      "I saved it", "The re-key key is no longer available here. If you did not save it, create a new export from the source fortress.",
      "The export may have completed, but this dashboard did not receive its re-key key. Check the export result and create a new export if you did not save the key.",
      "This bundle contains no encrypted state. No re-key key was created.",
      "Import on the destination fortress using the re-key key saved with this export. Sanctuary has not verified the import from this dashboard.",
      "Re-key key available for this export.",
    ]) expect(client).toContain(sentence);
    const storeSource = store!;
    expect(storeSource).not.toMatch(/from ["'](?:node:fs|.*storage|.*keychain)/);
    for (const source of [wiring!, service!, store!]) expect(source).not.toMatch(/(?:publishInbox|broadcastSSE)\(/);
  });
});
