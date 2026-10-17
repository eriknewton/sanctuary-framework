/**
 * Slice 2 shell: wired-consumer tests for the top bar and the rail.
 *
 * Each test boots the real client script in a minimal DOM that carries the
 * shell's elements, lets its reads settle against fixture responses, and
 * asserts what the operator would see: the waiting count on the rail pill and
 * the bell is Unknown until the queue read loads and "n of N" with the read's
 * age after; the seal wears its own unknown tone before any evidence; the
 * time range is live only on Evidence and says why when it is not; Talk mounts
 * the concierge in its panel; search answers from loaded groups and marks the
 * rest Unknown. A capability with no consumer reaching it is not shipped, so
 * these drive the boot path and the event listeners rather than a renderer in
 * isolation.
 *
 * Slice 2b adds: Machines inside the shell (the saved fleet with its
 * denominator and check age, an unanswered machine Unknown and never counted
 * online, no credential on a probe, no non-web address linked); the Sentinels
 * layer line Unknown without a Sentinel report; the agent controls and every
 * other rendered screen free of the retired wrap vocabulary; the Policies
 * subtitle saying only what the edit path does; agent state marks that keep
 * Unknown apart from a working state; the Evidence filter form as labelled
 * fields; activity rows without a verdict wearing no pass mark; and the
 * auto-trigger trend naming each bar shape in words.
 */
import { mfpScenario } from "./fixtures/mfp-scenarios.js";
import { agentsScenario } from "./fixtures/agents-scenarios.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { HUB_AGENT_STATUSES } from "../../../src/contracts/v1.1/constants.js";
import { renderDashboardV11Html } from "../../../src/dashboard/v1_1/html.js";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import { HUB_INBOX_KINDS } from "../../../src/contracts/v1.1/constants.js";
import { STATUS_MAPPING, TIER1_BUTTON_COPY } from "../../../src/dashboard/v1_1/status-mapping.js";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { TypeAliasDeclaration, UnionTypeNode, LiteralTypeNode, StringLiteral, TypeLiteralNode, PropertySignature, Identifier } from "typescript";
const ts = createRequire(import.meta.url)("typescript") as typeof import("typescript");
import type { AuditChainVerdictStatus } from "../../../src/operational/audit-log.js";

// Read the source union at runtime: vitest does not typecheck test files.
function unionValues(name: string) {
  const source = ts.createSourceFile("audit-log.ts", readFileSync(new URL("../../../src/operational/audit-log.ts", import.meta.url), "utf8"), ts.ScriptTarget.Latest, true);
  const alias = source.statements.find((node): node is TypeAliasDeclaration => ts.isTypeAliasDeclaration(node) && node.name.text === name)!;
  return (alias.type as UnionTypeNode).types.map((node) => ((node as LiteralTypeNode).literal as StringLiteral).text).sort();
}

// The `status` literal of each member of an object-type union such as SealedRegionVerdict.
function unionStatusValues(name: string) {
  const source = ts.createSourceFile("audit-log.ts", readFileSync(new URL("../../../src/operational/audit-log.ts", import.meta.url), "utf8"), ts.ScriptTarget.Latest, true);
  const alias = source.statements.find((node): node is TypeAliasDeclaration => ts.isTypeAliasDeclaration(node) && node.name.text === name)!;
  return (alias.type as UnionTypeNode).types.map((node) => {
    const member = (node as TypeLiteralNode).members.find((m) => m.name && (m.name as Identifier).text === "status") as PropertySignature;
    return ((member.type as LiteralTypeNode).literal as StringLiteral).text;
  }).sort();
}

const response = (body: unknown, status = 200, init: Record<string, unknown> = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  redirected: false,
  type: "basic",
  json: async () => body,
  body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(JSON.stringify(body))); controller.close(); } }),
  ...init,
});
const never = () => new Promise<never>(() => {});
const home = (digest: Record<string, unknown> = {}) => ({
  origin_machine: "fixture-mac", agents: [], castle_wall: { arm_state: "unknown" }, digest,
  protection_requested_count: 0, enforcement_confirmed_count: 0,
});
const heldItem = {
  item_id: "item-1", kind: "approval_pending", tier: "tier1", agent_id: "fixture-agent",
  display_template_id: "approval_pending.tier1.lockdown", display_template_args: [{ kind: "agent_id", value: "fixture-agent" }], resolved: false,
  created_at: "2026-10-14T16:45:00.000Z", identity_id: "operator-fixture", operation_category: "lockdown",
};
const emptyData = { data: { configured: false, surfaces: [], agents: [], items: [], traps: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] } };

let fakeActiveElement: unknown = null;
let setAttributeThrowFor: { name: string; value: string; persistent?: boolean } | null = null;

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
  replaceCount = 0;
  style: Record<string, string> = {};
  private classes = new Set<string>();
  constructor(attrs: Record<string, string> = {}, tagName = "DIV") { this.attrs = { ...attrs }; this.tagName = tagName.toUpperCase(); }
  get innerHTML() { return this.children.length ? this.children.map((c) => c.outerHTML).join("") : this.html; }
  set innerHTML(value: string) { this.html = String(value); this.children = []; }
  get textContent() { return this.children.length ? this.children.map((c) => c.textContent).join("") : this.text; }
  set textContent(value: string) { this.text = String(value); this.html = escapeHtml(String(value)); this.children = []; }
  get outerHTML() {
    if (this.tagName === "FRAGMENT") return this.innerHTML;
    const merged = this.className ? { ...this.attrs, class: this.className } : this.attrs;
    const attrs = Object.entries(merged).map(([k, v]) => ` ${k}="${escapeHtml(v)}"`).join("");
    return `<${this.tagName.toLowerCase()}${attrs}>${this.innerHTML}</${this.tagName.toLowerCase()}>`;
  }
  classList = {
    add: (...n: string[]) => n.forEach((c) => this.classes.add(c)),
    remove: (...n: string[]) => n.forEach((c) => this.classes.delete(c)),
    contains: (c: string) => this.classes.has(c),
    has: (c: string) => this.classes.has(c),
  };
  getAttribute(name: string) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name]! : null; }
  get title() { return this.attrs.title ?? ""; }
  set title(value: string) { this.attrs.title = String(value); }
  get lastChild(): FakeElement | FakeText | null { return this.children.at(-1) ?? null; }
  setAttribute(name: string, value: string) {
    if (setAttributeThrowFor && setAttributeThrowFor.name === name && setAttributeThrowFor.value === String(value)) {
      if (!setAttributeThrowFor.persistent) setAttributeThrowFor = null;
      throw new Error("fixture row build failed");
    }
    this.attrs[name] = String(value);
  }
  removeAttribute(name: string) { delete this.attrs[name]; }
  inside: string[] = [];
  closest(selector: string) { return this.inside.includes(selector) ? this : null; }
  private matches(selector: string) {
    if (/^\.[\w-]+$/.test(selector)) return this.className.split(/\s+/).includes(selector.slice(1));
    const tag = selector.match(/^[a-z]+/i)?.[0]?.toUpperCase();
    if (tag && this.tagName !== tag) return false;
    const attrs = [...selector.matchAll(/\[([^=\]]+)="([^"]*)"\]/g)];
    if (!attrs.length) return false;
    return attrs.every((m) => this.attrs[m[1]!] === m[2]);
  }
  querySelector(selector: string): FakeElement | null {
    if (/[\f\n\r]/.test(selector)) throw new SyntaxError("invalid selector");
    if (this.matches(selector)) return this;
    for (const child of this.children) {
      if (child instanceof FakeElement) {
        const found: FakeElement | null = child.querySelector(selector);
        if (found) return found;
      }
    }
    // Parse only rendered button and heading attributes for focus assertions; the fake does not lay out HTML.
    // Headings are included because the Approvals drawer moves focus to its heading, not to a decision control.
    for (const match of this.html.matchAll(/<(button|h3)\b([^>]*)>/g)) {
      const attrs = Object.fromEntries([...match[2]!.matchAll(/([\w-]+)="([^"]*)"/g)].map((m) => [m[1]!, m[2]!]));
      const element = new FakeElement(attrs, match[1]!);
      if (element.matches(selector)) return element;
    }
    return null;
  }
  querySelectorAll(selector: string): FakeElement[] {
    if (/[\f\n\r]/.test(selector)) throw new SyntaxError("invalid selector");
    const found: FakeElement[] = [];
    if (this.matches(selector)) found.push(this);
    for (const child of this.children) {
      if (child instanceof FakeElement) found.push(...child.querySelectorAll(selector));
    }
    return found;
  }
  contains(target: unknown): boolean {
    if (target === this) return true;
    return this.children.some((child) => child instanceof FakeElement && child.contains(target));
  }
  appendChild(child: FakeElement | FakeText) {
    if (child instanceof FakeElement) child.parentElement = this;
    this.children.push(child);
    return child;
  }
  removeChild(child: FakeElement | FakeText) {
    const index = this.children.indexOf(child);
    if (index >= 0) this.children.splice(index, 1);
    if (child instanceof FakeElement) child.parentElement = null;
    return child;
  }
  append(...children: Array<FakeElement | FakeText | string>) {
    children.forEach((child) => this.appendChild(typeof child === "string" ? new FakeText(child) : child));
  }
  replaceChildren(...children: Array<FakeElement | FakeText | string>) {
    this.replaceCount++;
    this.children = [];
    this.html = "";
    this.text = "";
    this.append(...children);
  }
  focus() { fakeActiveElement = this; }
  click() {}
  remove() {}
  replaceWith(next: FakeElement | FakeText) {
    if (!this.parentElement) return;
    const index = this.parentElement.children.indexOf(this);
    if (index < 0) return;
    if (next instanceof FakeElement) next.parentElement = this.parentElement;
    this.parentElement.children[index] = next;
    this.parentElement = null;
  }
}
class FakeText {
  textContent: string;
  constructor(value: string) { this.textContent = String(value); }
  get outerHTML() { return escapeHtml(this.textContent); }
}
class FakeInput extends FakeElement {}

function escapeHtml(raw: string) {
  return raw.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const SHELL_IDS = [
  "app", "main", "fortress", "sidebar-pills", "btn-lockdown", "posture-seal", "posture-seal-word",
  "posture-seal-freshness", "posture-seal-pop", "rail-approvals-count", "btn-notifications", "notify-count",
  "time-range", "btn-talk", "talk-panel", "talk-panel-body", "search-results",
  "machines-summary", "machines-age", "machines-list", "toast-host",
];

function boot(overrides: Record<string, (init?: RequestInit, url?: string) => unknown> = {}, extraGlobals: Record<string, unknown> = {}, options: { deferredHashchange?: boolean; templateContent?: boolean } = {}) {
  fakeActiveElement = null;
  const el: Record<string, FakeElement> = {};
  for (const id of SHELL_IDS) el[id] = new FakeElement({ id });
  el["global-search"] = new FakeInput({ "data-action": "global-search" });
  const body = new FakeElement({}, "BODY");
  const downloads: FakeElement[] = [];
  // The rail pill sits inside its rail link, which carries the sentence.
  const railLink = new FakeElement();
  el["rail-approvals-count"]!.parentElement = railLink;
  const docListeners: Record<string, (ev: unknown) => void> = {};
  const winListeners: Record<string, () => void> = {};
  let locationHash = "";
  const location = {
    get hash() { return locationHash; },
    set hash(value: string) {
      const next = String(value).startsWith("#") ? String(value) : "#" + String(value);
      const changed = next !== locationHash;
      locationHash = next;
      if (changed && winListeners.hashchange) {
        // Browser navigation dispatches after the click task and its microtasks have finished.
        if (options.deferredHashchange) setTimeout(() => winListeners.hashchange!(), 0);
        else winListeners.hashchange();
      }
    },
    search: "",
    origin: "http://fixture",
  };
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const context = createContext({
    document: {
      getElementById: (id: string) => el[id] || (id === "dashboard-config" ? { textContent: JSON.stringify({ hubApiBase: "/api/hub" }) } : null),
      addEventListener: (name: string, fn: (ev: unknown) => void) => { docListeners[name] = fn; },
      createElement: (tagName: string) => {
        const node = new FakeElement({}, tagName);
        if (tagName === "a") node.click = () => { downloads.push(node); };
        // Opt-in native template content, for the Talk owner feature check only.
        if (tagName === "template" && options.templateContent) Object.assign(node, { content: new FakeElement({}, "FRAGMENT") });
        return node;
      },
      createDocumentFragment: () => new FakeElement({}, "FRAGMENT"),
      createTextNode: (text: string) => new FakeText(text),
      querySelectorAll: () => [],
      get activeElement() { return fakeActiveElement; },
      set activeElement(value: unknown) { fakeActiveElement = value; },
      body,
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
      if (overrides[path]) return overrides[path]!(init, path);
      const bare = path.split("?")[0]!;
      if (overrides[bare]) return overrides[bare]!(init, path);
      // Standing-rule tests require a valid policy view; malformed policy data now fails the whole read.
      if (path === "/api/policy/current") return Promise.resolve(response({ data: { view: { lines: [] } } }));
      return Promise.resolve(response(path === "/api/posture/home" ? home() : emptyData));
    },
    ...extraGlobals,
  });
  runInContext(getClientScript(), context);
  const navigate = (route: string) => { location.hash = "#" + route; };
  const click = (attrs: Record<string, string>, inside: string[] = [], checked = false, event: { stopPropagation?: () => void } = {}) => {
    const target = new FakeElement(attrs);
    target.inside = inside;
    // Both forms stay: slice 5's tests pass `checked: "true"` in attrs, slice 4's pass the third argument.
    target.checked = checked || attrs.checked === "true";
    docListeners.click!({ target, ...event });
  };
  const clickRenderedButton = (action: string) => {
    const markup = [...el.main!.innerHTML.matchAll(/<button\b([^>]*)>/g)].find(m => m[1]!.includes(`data-action="${action}"`));
    expect(markup, `rendered ${action} button`).toBeDefined();
    expect(markup![1]).not.toMatch(/\bdisabled\b/);
    const attrs = Object.fromEntries([...markup![1]!.matchAll(/([\w-]+)="([^"]*)"/g)].map(m => [m[1]!, m[2]!]));
    const target = new FakeElement(attrs, "BUTTON");
    docListeners.click!({ target });
  };
  const keydown = (attrs: Record<string, string>, key: string) => {
    const preventDefault = vi.fn();
    docListeners.keydown!({ target: new FakeElement(attrs), key, preventDefault });
    return preventDefault;
  };
  const type = (text: string) => { el["global-search"]!.value = text; docListeners.input!({ target: el["global-search"] }); };
  const change = (target: FakeElement) => docListeners.change!({ target });
  const input = (action: string, value: string) => { const target = new FakeInput({ "data-action": action }); target.value = value; docListeners.input!({ target }); };
  return { el, railLink, context, navigate, click, clickRenderedButton, keydown, type, change, input, requests, downloads };
}
async function settle() { for (let i = 0; i < 100; i++) await Promise.resolve(); } // Finite boot microtask drain.
afterEach(() => {
  setAttributeThrowFor = null;
  vi.useRealTimers();
});

describe("slice 2 shell wired consumers", () => {
  it("the rail pill and the bell read Unknown before the queue loads, never a zero", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": never });
    await settle();
    expect(h.el["rail-approvals-count"]!.textContent).toBe("Unknown");
    expect(h.el["rail-approvals-count"]!.className).toContain("unknown");
    expect(h.railLink.getAttribute("title")).toContain("Unknown until the approval queue loads");
    expect(h.el["notify-count"]!.innerHTML).toContain("Unknown");
    expect(h.el["notify-count"]!.hidden).toBe(false);
    expect(h.el["notify-count"]!.className).toContain("unknown");
    expect(h.el["btn-notifications"]!.getAttribute("title")).toContain("Unknown until the approval queue loads");
  });

  it("after the queue loads, the rail pill and the bell carry n of N and the title carries the read age", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })) });
    await settle();
    expect(h.el["rail-approvals-count"]!.textContent).toBe("1 of 1");
    expect(h.el["rail-approvals-count"]!.className).toContain("hot");
    expect(h.railLink.getAttribute("title")).toMatch(/^1 of 1 held operation waits on you · queue read \d+s ago\.$/);
    expect(h.el["notify-count"]!.innerHTML).toContain("1 of 1");
    expect(h.el["notify-count"]!.className).not.toContain("unknown");
    expect(h.el["btn-notifications"]!.getAttribute("aria-label")).toMatch(/1 of 1 held operation waits on you · queue read \d+s ago/);
  });

  it("the seal wears the unknown tone before any enforcement evidence", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/posture/home": never, "/api/sovereignty": never });
    await settle();
    expect(h.el["posture-seal"]!.classList.contains("tone-unknown")).toBe(true);
    expect(h.el["posture-seal"]!.classList.contains("tone-protected")).toBe(false);
    expect(h.el["posture-seal-word"]!.textContent).toBe("Unknown");
  });

  it("the time range is disabled with its reason off Evidence and enabled on Evidence", async () => {
    vi.useFakeTimers();
    // A held item keeps the queue populated while this fixture checks the independent time-range control.
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })) });
    await settle();
    const range = h.el["time-range"]!;
    expect(range.disabled).toBe(true);
    expect(range.getAttribute("title")).toBe("This screen shows current state and has no time window. The time range applies to the Evidence list.");
    h.navigate("activity");
    expect(range.disabled).toBe(false);
    expect(range.getAttribute("title")).toBe("Time range for the Evidence list: all time.");
    h.navigate("enforcement");
    expect(range.disabled).toBe(true);
  });

  it("the Talk button mounts the concierge renderer in the panel beside the current screen", async () => {
    vi.useFakeTimers();
    const h = boot();
    await settle();
    expect(h.el["talk-panel"]!.hidden).toBe(true);
    h.click({ "data-action": "talk-toggle" });
    expect(h.el["talk-panel"]!.hidden).toBe(false);
    expect(h.el["btn-talk"]!.getAttribute("aria-expanded")).toBe("true");
    const concierge = runInContext("renderDashboardConcierge()", h.context) as string;
    expect(concierge.length).toBeGreaterThan(0);
    expect(h.el["talk-panel-body"]!.innerHTML).toBe(concierge);
    // The screen underneath is still the one the operator was on.
    expect(runInContext("state.route", h.context)).toBe("posture");
    h.click({ "data-action": "talk-close" });
    expect(h.el["talk-panel"]!.hidden).toBe(true);
    expect(h.el["talk-panel-body"]!.innerHTML).toBe("");
  });

  it("global search answers from loaded groups and marks an unloaded group Unknown", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [{ agent_id: "fixture-agent", status: "active" }] } })),
      "/api/hub/activity": never,
    });
    await settle();
    h.type("fixture");
    const panel = h.el["search-results"]!;
    expect(panel.hidden).toBe(false);
    expect(panel.innerHTML).toContain("Agents (1 of 1 matches)");
    expect(panel.innerHTML).toContain('data-agent-id="fixture-agent"');
    expect(panel.innerHTML).toMatch(/Recent evidence<\/div><div class="sr-empty">Unknown: not loaded yet, so a match cannot be ruled out\./);
    expect(panel.innerHTML).toContain("recent evidence not loaded");
  });

  it("a redacted queue's search group says the approvals are hidden, not unloaded", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { pending_approvals_redacted: true, pending_approvals_count: 2 } })) });
    await settle();
    h.type("anything");
    const html = h.el["search-results"]!.innerHTML;
    expect(html).toMatch(/Waiting approvals<\/div><div class="sr-empty">Unknown: hidden until you paste the operator token/);
    expect(html).not.toMatch(/Waiting approvals<\/div><div class="sr-empty">Unknown: not loaded yet/);
    expect(html).toContain("waiting approvals hidden");
  });

  it("the approval queue's element id lives only on the Approvals screen", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })) });
    await settle();
    h.navigate("approvals");
    const doc = h.el.main!.innerHTML + h.el.fortress!.innerHTML;
    expect(doc.match(/id="approval-queue"/g) ?? []).toHaveLength(1);
    expect(h.el.main!.innerHTML).toContain('id="approval-queue"');
    // The right rail links to Approvals and no longer duplicates the queue controls.
    h.navigate("dashboard");
    expect(h.el.fortress!.innerHTML).not.toContain('id="approval-queue"');
    expect(h.el.fortress!.innerHTML).toContain("Open Approvals");
  });

  it("the Enforcement egress line shows an absent kernel count as Unknown, never 0", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/posture/home": () => Promise.resolve(response(home({ kernel_blocks: 4 }))) });
    await settle();
    h.navigate("enforcement");
    const main = h.el.main!.innerHTML;
    // Both counts need the common positive gate; an unverified read is not a measured zero.
    expect(main).toContain("Not evaluated");
    // This home fixture serves no chain_verdict, so the chain gate withholds its counts.
    expect(main).toContain("chain not verified");
    expect(main).not.toContain("<strong>0</strong>");
    expect(main).not.toMatch(/\b0 allowed/);
    expect(main).not.toMatch(/of 4 observed/);
  });

  it("the Enforcement egress card renders separate verified kernel counts", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/posture/home": () => Promise.resolve(response(home({ kernel_blocks: 4, kernel_allows: 2, chain_verified: true, chain_verdict: "verified", window_complete: true, kernel_allow_overrides: 0, window_start: new Date(Date.now() - 1000).toISOString(), window_end: new Date().toISOString() }))) });
    await settle();
    h.navigate("enforcement");
    // The fixture serves the clean flag and verdict together; counts remain independent served values.
    expect(h.el.main!.innerHTML).toContain("Blocked <strong>4</strong>");
    expect(h.el.main!.innerHTML).toContain("Allowed <strong>2</strong>");
    expect(h.el.main!.innerHTML).not.toContain("of 6");
  });

  it("the Approvals and seal copy claim only what the paths do", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })) });
    await settle();
    h.navigate("approvals");
    const main = h.el.main!.innerHTML;
    // Ordinary hub inbox decisions resolve in the inbox store; only Charter
    // holds go through the operator audit queue.
    expect(main).not.toContain("operator key");
    expect(main).not.toContain("Every decision is signed");
    expect(main).toContain("marked decided in this inbox");
    expect(main).toContain('href="#activity">Evidence</a>');
    // Lockdown revokes network access for confined agents; agents keep running.
    runInContext('state.posture.sealOpen = true; state.tier1.lockdown.state = "engaged"; renderTopbar();', h.context);
    const pop = h.el["posture-seal-pop"]!.innerHTML;
    expect(pop).not.toContain("holds every agent");
    expect(pop).toContain("Lockdown revokes network access for every confined agent; agents keep running and keep local access.");
  });

  it("the lockdown top-bar button renders the Tier 1 copy table exactly for every top-bar state", async () => {
    vi.useFakeTimers();
    const h = boot();
    await settle();
    for (const stateName of ["idle", "pending", "partial", "engaged"] as const) {
      runInContext(`state.tier1.lockdown.state = ${JSON.stringify(stateName)}; renderTopbar();`, h.context);
      expect(h.el["btn-lockdown"]!.textContent, stateName).toBe(TIER1_BUTTON_COPY.lockdown[stateName]);
    }
  });

  it("agent-row Tier 1 controls render approved labels and removal failures toast with the removal label", async () => {
    vi.useFakeTimers();
    const failures = [
      { status: 422, body: { error: "unsupported request refused" } },
      { status: 500, body: { error: "controller unavailable" } },
    ];
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({
        data: {
          agents: [{
            agent_id: "agent-alpha",
            status: "active",
            capabilities: { can_lockdown: true, can_unwrap: true },
          }],
        },
      })),
      "/api/hub/agents/agent-alpha/unwrap": () => {
        const next = failures.shift()!;
        return Promise.resolve(response(next.body, next.status));
      },
    });
    await settle();
    const labelsByAction = runInContext(`
      const html = renderFortressAgentsCard();
      Object.fromEntries(
        Array.from(html.matchAll(/data-action="agent-([^"]+)"[^>]*>([^<]*)<\\/button>/g))
          .map(function (match) { return [match[1], match[2]]; })
      );
    `, h.context) as Record<string, string>;

    expect(labelsByAction.lockdown).toBe(TIER1_BUTTON_COPY.lockdown.idle);
    expect(labelsByAction.unwrap).toBe(TIER1_BUTTON_COPY.unwrap.idle);

    runInContext("var capturedToasts = []; toast = function (message, kind) { capturedToasts.push({ message, kind }); };", h.context);
    await runInContext('onAgentControl("agent-alpha", "unwrap")', h.context);
    await runInContext('onAgentControl("agent-alpha", "unwrap")', h.context);

    const messages = runInContext("capturedToasts.map(function (toast) { return toast.message; })", h.context) as string[];
    expect(messages).toHaveLength(2);
    expect(messages[0]).toContain('Sanctuary cannot apply "Remove protection" for this agent.');
    expect(messages[1]).toContain('"Remove protection" failed. Try again.');
    for (const message of messages) {
      expect(message).toContain("Remove protection");
      expect(message).not.toMatch(/wrap/i);
    }
  });

  it("a layer line whose word is Unknown never wears the pass dot, in Enforcement or the seal popover", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": never,
      // A sovereignty read that loads but carries no Heralds layer.
      "/api/sovereignty": () => Promise.resolve(response({ live_enforcement: {}, layers: {} })),
    });
    await settle();
    h.navigate("enforcement");
    runInContext("state.posture.sealOpen = true; renderTopbar();", h.context);
    for (const [where, html] of [["enforcement", h.el.main!.innerHTML], ["popover", h.el["posture-seal-pop"]!.innerHTML]]) {
      const lines = [...html.matchAll(/<span class="(pp-dot[^"]*)"><\/span><span class="pp-k">([^<]*)<\/span><span class="pp-v">([^<]*)<\/span>/g)];
      expect(lines.length, where).toBeGreaterThan(0);
      const unknown = lines.filter((m) => /^unknown$/i.test(m[3]!));
      // The Charter line (inbox unloaded) and the Heralds line (no l4) are among them.
      expect(unknown.map((m) => m[2]), where).toEqual(expect.arrayContaining(["Charter approvals", "Heralds (reputation)"]));
      for (const m of unknown) expect(m[1], `${where}: ${m[2]}`).toBe("pp-dot unknown");
    }
  });

  it("a Heralds layer that is configured but not signing does not wear the pass dot", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/sovereignty": () => Promise.resolve(response({ live_enforcement: {}, layers: { l4: { status: "inactive" } } })) });
    await settle();
    h.navigate("enforcement");
    const m = h.el.main!.innerHTML.match(/<span class="(pp-dot[^"]*)"><\/span><span class="pp-k">Heralds \(reputation\)<\/span><span class="pp-v">configured<\/span>/);
    expect(m).toBeTruthy();
    expect(m![1]).not.toBe("pp-dot");
  });

  it("Evidence names the rows outside the time range instead of saying nothing is pending", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-10T12:00:00Z"));
    const old = { ...heldItem, item_id: "old-1", kind: "blocked_egress", tier: undefined, created_at: "2026-03-05T12:00:00Z" };
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [old, { ...old, item_id: "old-2" }] } })) });
    await settle();
    const select = new FakeElement({ "data-action": "time-range" }) as FakeElement & { tagName: string };
    select.tagName = "SELECT";
    select.value = "24h";
    h.navigate("activity");
    // The operator picks the 24 hours range in the top bar.
    h.change(select);
    const main = h.el.main!.innerHTML;
    expect(main).toContain("Inbox (0 of 2)");
    expect(main).not.toContain("Nothing pending.");
    expect(main).toContain("No open items in this view: 2 older items are outside the last 24 hours.");
  });

  it("Evidence says Nothing pending only when no item is open", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [] } })) });
    await settle();
    h.navigate("activity");
    expect(h.el.main!.innerHTML).toContain("Nothing pending.");
  });

  it("Evidence says entries are Unknown when the verification read has not answered", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-10T12:00:00Z"));
    const h = boot({ "/api/posture/evidence": () => Promise.reject(new Error("verification offline.")) });
    await settle();
    const select = new FakeElement({ "data-action": "time-range" }) as FakeElement & { tagName: string };
    select.tagName = "SELECT";
    select.value = "24h";
    h.navigate("activity");
    // The operator picks the 24 hours range in the top bar.
    h.change(select);
    const main = h.el.main!.innerHTML;
    expect(main).toContain("Entries Unknown");
    expect(main).toContain("Chain verification Unknown");
    expect(main).not.toContain("CHAIN VERIFIED");
  });

  it("Evidence says no entries match only after the server evidence read loads", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/posture/evidence": () => Promise.resolve(response({ origin_machine: "fixture", entries: [], total: 0, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } })),
    });
    await settle();
    h.navigate("activity");
    expect(h.el.main!.innerHTML).toContain("No audit entries in this view");
  });

  it("the Approvals subtitle says where each decision is recorded", async () => {
    vi.useFakeTimers();
    const h = boot();
    await settle();
    h.navigate("approvals");
    const main = h.el.main!.innerHTML;
    expect(main).not.toContain("signed policy");
    expect(main).not.toContain("Allow always writes");
    expect(main).toContain("A decision on a Charter hold is recorded in your audit log; a decision on any other held item is marked decided in this inbox.");
  });

  it("Approvals names Charter and hub decision records without inferring an operator outcome", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-14T17:00:00.000Z"));
    const items = [
      { ...heldItem, item_id: "charter.approval.wait", tier: "tier2", agent_id: "agent-c", operation_category: "state_export", resolved: false, created_at: "2026-10-14T16:30:00.000Z" },
      { ...heldItem, item_id: "hub-wait", tier: "tier2", agent_id: "agent-h", operation_category: "state_import", resolved: false, created_at: "2026-10-14T16:40:00.000Z" },
      { ...heldItem, item_id: "charter.approval.decided", tier: "tier2", agent_id: "agent-c", operation_category: "state_delete", resolved: true, resolved_at: "2026-10-14T16:45:00.000Z", resolution_payload: { outcome: "engaged" } },
      { ...heldItem, item_id: "hub-decided", tier: "tier2", agent_id: "agent-h", operation_category: "state_delete", resolved: true, resolved_at: "2026-10-14T16:46:00.000Z", resolution_payload: { outcome: "engaged" } },
    ];
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })) });
    await settle();
    h.navigate("approvals");
    let main = h.el.main!.innerHTML;
    expect(main).toContain("A decision on a Charter hold is recorded in your audit log; a decision on any other held item is marked decided in this inbox.");
    expect(main).toContain("Waiting on you · 2 of 2");
    expect(main).toMatch(/data-approval-row="charter\.approval\.wait"[\s\S]*?recorded in your audit log/);
    expect(main).toMatch(/data-approval-row="hub-wait"[\s\S]*?marked decided in this inbox/);
    expect(main).toMatch(/data-approval-row="charter\.approval\.decided"[\s\S]*?DECIDED[\s\S]*?outcome in your audit log[\s\S]*?href="#activity">Evidence<\/a>/);
    expect(main).toMatch(/data-approval-row="hub-decided"[\s\S]*?DECIDED[\s\S]*?outcome not reported by the inbox/);
    expect(main).not.toMatch(/ALLOWED ONCE|DENIED|ALWAYS ALLOW/);
    h.click({ "data-action": "approval-select", "data-item-id": "hub-wait" });
    main = h.el.main!.innerHTML;
    expect(main).toMatch(/If you decide[\s\S]*?marked decided in this inbox[\s\S]*?Decision marked decided in this inbox/);
  });

  it("Approvals uses plain operator copy for always allow and never renders route paths", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [{ ...heldItem, item_id: "wait-1", tier: "tier2", operation_category: "state_export" }] } })),
      // Policy fixtures serve the view's real lines field; a malformed policy view now fails the whole read.
      "/api/policy/current": () => Promise.resolve(response({ data: { view: { lines: [] } } })),
    });
    await settle();
    h.navigate("approvals");
    await settle();
    runInContext("state.approvals.alwaysAllow = true; rerender();", h.context);
    const main = h.el.main!.innerHTML;
    expect(main).not.toContain("/api/");
    expect(main).toContain("Always allow this operation for every agent on this fortress.");
    // The rule is added to the fortress policy and this console cannot remove it, so the note claims neither a
    // signature nor a revocation path.
    // The screen escapes the apostrophe as &#039; (escHtml), so the rendered markup carries that entity.
    expect(main).toContain("Adds a standing rule to this fortress&#039;s policy. The console has no control to remove a standing rule yet.");
    expect(main).not.toContain("signed policy");
    expect(main).not.toContain("revocable");
    expect(main).toContain("Allow always first allows this request, then asks the policy engine to compile a standing rule for state_export and activate it with your operator token.");
    expect(main).toMatch(/approval-effects[\s\S]*?<strong>Allow always<\/strong>/);
    expect(main).toContain("Either step can be refused; your policy changes only if both succeed.");
    expect(main).toContain("Later matching operations stop asking only if the policy engine accepts both steps.");
  });

  it("Approvals renders grouped waiting and decided rows with served fields only", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-14T17:00:00.000Z"));
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [
      { ...heldItem, item_id: "wait-1", operation_category: "state_export", created_at: "2026-10-14T16:30:00.000Z" },
      { ...heldItem, item_id: "decided-1", operation_category: "state_import", created_at: "2026-10-14T15:30:00.000Z", resolved: true, resolved_at: "2026-10-14T15:35:00.000Z" },
    ] } })) });
    await settle();
    h.navigate("approvals");
    const main = h.el.main!.innerHTML;
    expect(main).toContain("State");
    expect(main).toContain("Agent");
    expect(main).toContain("Tier");
    expect(main).toContain("Category");
    expect(main).toContain("Waiting on you");
    expect(main).toContain("oldest wait");
    expect(main).toContain("Decided");
    expect(main).toContain("showing 2 of 2");
    expect(main).toContain("Selected approval");
    expect(main).toContain("What it wants to do");
    expect(main).toContain("Why it is held");
    expect(main).toContain("If you decide");
    expect(main).toContain("marked decided in this inbox");
    expect(main).toContain("outcome not reported by the inbox");
    expect(main).toContain("Decided at");
    expect(main).not.toContain("Context the agent gave");
    expect(main).not.toContain("Note for the audit record");
    expect(main).not.toContain("server reported this hold");
  });

  it("Approvals renders hostile served typed args as literal text", async () => {
    vi.useFakeTimers();
    const hostile = '<img src=x onerror="alert(1)">';
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [
      { ...heldItem, item_id: "wait-1", agent_id: hostile, display_template_args: [{ kind: "agent_id", value: hostile }] },
    ] } })) });
    await settle();
    h.navigate("approvals");
    const main = h.el.main!.innerHTML;
    expect(main).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(main).not.toContain(hostile);
    expect(main).not.toContain("Agent-supplied text");
  });

  it("Approvals disables the standing-rule checkbox when policy activation is unavailable", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [{ ...heldItem, tier: "tier2", operation_category: "state_export" }] } })),
      "/api/policy/current": () => Promise.resolve(response({}, 503)),
    });
    await settle();
    h.navigate("approvals");
    await settle();
    const main = h.el.main!.innerHTML;
    expect(main).toContain("Always allow is unavailable");
    expect(main).toContain("Policy engine is not configured on this fortress.");
    expect(main).toContain('data-action="approval-always-allow" disabled');
    expect(main).not.toContain('data-action="inbox-promote"');
  });

  it("Tier 1 approvals require drawer confirmation while Tier 2 keeps inline decisions", async () => {
    vi.useFakeTimers();
    const calls: string[] = [];
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [
        { ...heldItem, item_id: "tier1-1", tier: "tier1", operation_category: "state_export" },
        { ...heldItem, item_id: "tier2-1", tier: "tier2", operation_category: "state_delete" },
      ] } })),
      "/api/hub/inbox/tier1-1/approve": () => { calls.push("/api/hub/inbox/tier1-1/approve"); return Promise.resolve(response({ data: { item: { ...heldItem, item_id: "tier1-1", resolved: true } } })); },
      "/api/hub/inbox/tier2-1/approve": () => { calls.push("/api/hub/inbox/tier2-1/approve"); return Promise.resolve(response({ data: { item: { ...heldItem, item_id: "tier2-1", resolved: true } } })); },
    });
    await settle();
    h.navigate("approvals");
    let html = h.el.main!.innerHTML;
    expect(html).not.toContain('data-action="inbox-approve" data-item-id="tier1-1"');
    expect(html).toContain('data-action="inbox-approve" data-item-id="tier2-1"');
    h.click({ "data-action": "approval-start-tier1-allow", "data-item-id": "tier1-1" });
    await settle();
    expect(calls).toEqual([]);
    html = h.el.main!.innerHTML;
    expect(html).toContain('data-action="approval-confirm-tier1-allow" data-item-id="tier1-1"');
    expect(html).toContain("Confirm state_export");
    h.click({ "data-action": "approval-confirm-tier1-allow", "data-item-id": "tier1-1" });
    await settle();
    expect(calls).toEqual(["/api/hub/inbox/tier1-1/approve"]);
  });

  it("Approvals drawer buttons still use the existing inbox decision path with empty bodies", async () => {
    vi.useFakeTimers();
    const calls: Array<{ url: string; body: unknown }> = [];
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [{ ...heldItem, item_id: "wait-1", tier: "tier2", operation_category: "state_export" }] } })),
      "/api/hub/inbox/wait-1/approve": (init) => { calls.push({ url: "/api/hub/inbox/wait-1/approve", body: init && init.body }); return Promise.resolve(response({ data: { item: { ...heldItem, item_id: "wait-1", resolved: true } } })); },
      "/api/hub/inbox/wait-1/deny": (init) => { calls.push({ url: "/api/hub/inbox/wait-1/deny", body: init && init.body }); return Promise.resolve(response({ data: { item: { ...heldItem, item_id: "wait-1", resolved: true } } })); },
    });
    await settle();
    h.navigate("approvals");
    expect(h.el.main!.innerHTML).toContain('data-approval-primary="wait-1" data-action="inbox-approve"');
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    h.click({ "data-action": "inbox-deny", "data-item-id": "wait-1" });
    await settle();
    expect(calls).toEqual([
      { url: "/api/hub/inbox/wait-1/approve", body: "{}" },
      { url: "/api/hub/inbox/wait-1/deny", body: "{}" },
    ]);
  });

  it("Approvals filters narrow rows and counts after the left rail agent scope", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [
      { ...heldItem, item_id: "a-wait", tier: "tier1", agent_id: "agent-a", operation_category: "state_export", resolved: false },
      { ...heldItem, item_id: "b-wait", tier: "tier2", agent_id: "agent-b", operation_category: "state_delete", resolved: false },
      { ...heldItem, item_id: "a-decided", tier: "tier2", agent_id: "agent-a", operation_category: "state_import", resolved: true, resolved_at: "2026-10-14T16:50:00.000Z" },
    ] } })) });
    await settle();
    h.navigate("approvals");
    expect(h.el.main!.innerHTML).toContain("showing 3 of 3");
    const stateSelect = new FakeElement({ "data-action": "approval-filter-state" }, "select");
    stateSelect.value = "waiting";
    h.change(stateSelect);
    expect(h.el.main!.innerHTML).toContain("showing 2 of 3");
    const tierSelect = new FakeElement({ "data-action": "approval-filter-tier" }, "select");
    tierSelect.value = "tier2";
    h.change(tierSelect);
    expect(h.el.main!.innerHTML).toContain("showing 1 of 3");
    const categorySelect = new FakeElement({ "data-action": "approval-filter-category" }, "select");
    categorySelect.value = "state_export";
    h.change(categorySelect);
    expect(h.el.main!.innerHTML).toContain("No held operation matches these filters");
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "agent-a" });
    // Retargeted from the old scope hint text: the scope now applies before the filters, so the queue counts the
    // scoped rows and the other agent's option and row are gone.
    expect(h.el.main!.innerHTML).toContain("showing 0 of 2");
    expect(h.el.main!.innerHTML).not.toContain('<option value="agent-b"');
    expect(h.el.main!.innerHTML).not.toContain('data-approval-row="b-wait"');
  });

  it("Approvals cap reports showing M of N past the loaded inbox page cap", async () => {
    vi.useFakeTimers();
    const items = Array.from({ length: 101 }, (_, index) => ({
      ...heldItem,
      item_id: `item-${index}`,
      tier: "tier2",
      agent_id: `agent-${index}`,
      operation_category: "state_export",
      resolved: false,
    }));
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })) });
    await settle();
    h.navigate("approvals");
    expect(h.el.main!.innerHTML).toContain("showing 100 of 101");
    expect(h.el.main!.innerHTML).toContain("cap 100");
  });

  it("Approvals says a full inbox page may hide more held operations, and says nothing when the page is not full", async () => {
    vi.useFakeTimers();
    // One inbox read returns at most 100 items of every kind and no total (HUB_INBOX_DEFAULT_LIMIT).
    const page = (approvals: number, others: number) => [
      ...Array.from({ length: approvals }, (_, index) => ({ ...heldItem, item_id: `held-${index}`, tier: "tier2", operation_category: "state_export", resolved: false })),
      ...Array.from({ length: others }, (_, index) => ({ item_id: `egress-${index}`, kind: "blocked_egress", agent_id: "agent-a", created_at: "2026-10-14T16:00:00.000Z", resolved: false, destination_category: "paste-site", display_template_id: "blocked_egress.egress_policy_deny", display_template_args: [] })),
    ];
    const full = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: page(60, 40) } })) });
    await settle();
    full.navigate("approvals");
    expect(full.el.main!.innerHTML).toContain("showing 60 of 60");
    expect(full.el.main!.innerHTML).toContain('data-inbox-page-full="1"');
    expect(full.el.main!.innerHTML).toContain("The inbox read returned a full page of 100 items; held operations beyond it are not shown here.");
    const partial = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: page(60, 39) } })) });
    await settle();
    partial.navigate("approvals");
    expect(partial.el.main!.innerHTML).toContain("showing 60 of 60");
    expect(partial.el.main!.innerHTML).not.toContain('data-inbox-page-full="1"');
  });

  it("refused decisions show the refusal and repaint from server state", async () => {
    vi.useFakeTimers();
    const inboxItems: Array<Record<string, unknown>> = [{ ...heldItem, item_id: "wait-1", tier: "tier2", operation_category: "state_export", resolved: false }];
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: inboxItems } })),
      "/api/hub/inbox/wait-1/approve": () => {
        return Promise.resolve(response({ error: "operator session required" }, 401));
      },
    });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    // The refusal is the retained decision result, not a toast; the server's reason is quoted in it.
    expect(h.el.main!.innerHTML).toContain('data-decision-status="refused"');
    expect(h.el.main!.innerHTML).toContain("Allow once was refused for state_export by fixture-agent (request wait-1): operator session required (HTTP 401). The request is still waiting.");
    // Retargeted from "Decided at": a refused decision leaves the row waiting with its controls, repainted from the server.
    expect(h.el.main!.innerHTML).toContain("WAITING");
    expect(h.el.main!.innerHTML).toContain('data-action="inbox-approve" data-item-id="wait-1"');
    expect(h.el.main!.innerHTML).not.toContain("Decided at");
  });

  it("search says nothing searchable has loaded, not no match, when no group has loaded", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/agents": never, "/api/hub/inbox": never, "/api/hub/activity": never });
    await settle();
    h.type("zzz");
    const html = h.el["search-results"]!.innerHTML;
    expect(html).toContain('data-search-nothing-loaded="1"');
    expect(html).toContain("Nothing searchable has loaded yet, so no result is known.");
    expect(html).not.toContain("No match in what this page has loaded");
  });

  it("search says no match only when a group loaded and none matched", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [{ agent_id: "fixture-agent", status: "active" }] } })),
      "/api/hub/inbox": never, "/api/hub/activity": never,
    });
    await settle();
    h.type("zzz");
    const html = h.el["search-results"]!.innerHTML;
    expect(html).toContain('data-search-no-match="1"');
    expect(html).toContain("No match in what this page has loaded.");
    expect(html).not.toContain("Nothing searchable has loaded yet");
  });

  it("a search hit that links to the route already showing closes the results", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })) });
    await settle();
    h.navigate("approvals");
    h.type("fixture-agent");
    expect(h.el["search-results"]!.innerHTML).toContain('<a href="#approvals">');
    expect(h.el["search-results"]!.hidden).toBe(false);
    // A plain link to #approvals while on #approvals: the hash does not
    // change, so no hashchange fires; the click itself must close the panel.
    h.click({ href: "#approvals" }, ["[data-search]", "#search-results a"]);
    expect(h.el["search-results"]!.hidden).toBe(true);
    expect(runInContext("state.search.open", h.context)).toBe(false);
  });

  it("a click inside the search box that is not on a result leaves the results open", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })) });
    await settle();
    h.type("fixture-agent");
    h.click({}, ["[data-search]"]);
    expect(h.el["search-results"]!.hidden).toBe(false);
  });

  it("choosing an agent scope repaints the Approvals screen, the rail pill and the bell with the scoped count", async () => {
    vi.useFakeTimers();
    const items = [
      { ...heldItem, item_id: "held-a", agent_id: "fixture-agent-a" },
      { ...heldItem, item_id: "held-b", agent_id: "fixture-agent-b" },
    ];
    // Both agents are served, so the scope names an agent on the roster. The
    // scope menu's reconciliation (which resets a scope naming an unknown
    // agent) does not run here: this fake page has no #agent-switcher-label
    // or #agent-switcher-menu, so renderAgentSwitcher returns before it. The
    // scope holds because the click sets it, which is what this test pins.
    const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
    const agents = [{ agent_id: "fixture-agent-a", status: "active", model_provider }, { agent_id: "fixture-agent-b", status: "active", model_provider }];
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })),
    });
    await settle();
    h.navigate("approvals");
    expect(h.el["rail-approvals-count"]!.textContent).toBe("2 of 2");
    expect(h.el.main!.innerHTML).toContain('data-item-id="held-b"');
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "fixture-agent-a" });
    // The numerator is scoped to the chosen agent; the denominator stays the
    // fortress-wide queue.
    expect(h.el["rail-approvals-count"]!.textContent).toBe("1 of 2");
    expect(h.el["notify-count"]!.innerHTML).toContain("1 of 2");
    expect(h.el.main!.innerHTML).toContain('data-item-id="held-a"');
    expect(h.el.main!.innerHTML).not.toContain('data-item-id="held-b"');
  });

  it("a scoped zero while other agents' holds wait keeps the bell badge and earns no green check", async () => {
    vi.useFakeTimers();
    const items = [
      { ...heldItem, item_id: "held-a", agent_id: "fixture-agent-a" },
      { ...heldItem, item_id: "held-b", agent_id: "fixture-agent-b" },
    ];
    const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
    const agents = ["fixture-agent-a", "fixture-agent-b", "fixture-agent-c"].map((agent_id) => ({ agent_id, status: "active", model_provider }));
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })),
    });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "fixture-agent-c" });
    expect(h.el["rail-approvals-count"]!.textContent).toBe("0 of 2");
    expect(h.el["notify-count"]!.hidden).toBe(false);
    expect(h.el["notify-count"]!.innerHTML).toContain("0 of 2");
    const main = h.el.main!.innerHTML;
    expect(main).toContain('data-scoped-empty="1"');
    expect(main).toContain("No recognized held operation for fixture-agent-c is waiting in this read. 2 held operations wait outside this agent scope");
    expect(main).not.toContain("qe-check");
    expect(main).not.toContain("Nothing waiting on you.");
  });

  it("the empty Approvals drawer states what still waits behind a filter or the agent scope, never a calm zero", async () => {
    vi.useFakeTimers();
    const items = [
      { ...heldItem, item_id: "held-a", tier: "tier2", agent_id: "fixture-agent-a", operation_category: "state_export", resolved: false },
      { ...heldItem, item_id: "held-b", tier: "tier2", agent_id: "fixture-agent-b", operation_category: "state_delete", resolved: false },
    ];
    const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
    const agents = ["fixture-agent-a", "fixture-agent-b", "fixture-agent-c"].map((agent_id) => ({ agent_id, status: "active", model_provider }));
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })),
    });
    await settle();
    h.navigate("approvals");
    // The drawer is the last block of the layout, so everything from its class on is the drawer.
    const drawer = () => { const html = h.el.main!.innerHTML; return html.slice(html.indexOf("card approval-drawer")); };
    const categorySelect = new FakeElement({ "data-action": "approval-filter-category" }, "select");
    categorySelect.value = "state_import";
    h.change(categorySelect);
    expect(h.el.main!.innerHTML).toContain("No held operation matches these filters");
    expect(drawer()).not.toContain("No approvals waiting");
    expect(drawer()).not.toContain("0 of 0 held operations");
    // The count is the waiting holds in scope, with no denominator that would also count decided items.
    expect(drawer()).toContain("No held operation matches these filters. 2 held operations in this scope are waiting on you.");
    categorySelect.value = "";
    h.change(categorySelect);
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "fixture-agent-c" });
    expect(drawer()).not.toContain("No approvals waiting");
    expect(drawer()).not.toContain("0 of 0 held operations");
    expect(drawer()).toContain("No recognized held operation for fixture-agent-c is waiting in this read. 2 held operations wait outside this agent scope");
  });

  it("the bell badge goes and the green check is earned only when nothing waits fortress-wide", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [] } })) });
    await settle();
    h.navigate("approvals");
    expect(h.el["notify-count"]!.hidden).toBe(true);
    expect(h.el.main!.innerHTML).toContain('<span class="qe-check"></span>Nothing waiting on you.');
  });

  it("a search hit for another agent from the agent detail opens that agent and closes the results", async () => {
    vi.useFakeTimers();
    const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
    const agents = [{ agent_id: "fixture-agent-a", status: "active", model_provider }, { agent_id: "fixture-agent-b", status: "active", model_provider }];
    const h = boot({ "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })) });
    await settle();
    h.click({ "data-action": "open-agent", "data-agent-id": "fixture-agent-a" });
    h.navigate("agent-detail");
    expect(h.el.main!.innerHTML).toContain("fixture-agent-a");
    h.type("fixture-agent-b");
    expect(h.el["search-results"]!.hidden).toBe(false);
    // The hit's hash is the current one, so no hashchange will fire.
    h.click({ "data-action": "open-agent", "data-agent-id": "fixture-agent-b" }, ["[data-search]"]);
    expect(runInContext("state.selectedAgentId", h.context)).toBe("fixture-agent-b");
    expect(h.el.main!.innerHTML).toContain("fixture-agent-b");
    expect(h.el.main!.innerHTML).not.toContain("fixture-agent-a");
    expect(h.el["search-results"]!.hidden).toBe(true);
  });
});

describe("slice 2b shell wired consumers", () => {
  const FLEET_KEY = "sanctuary_fleet_machines";
  const storage = (saved: unknown) => ({
    localStorage: {
      getItem: (k: string) => (k === FLEET_KEY ? JSON.stringify(saved) : null),
      setItem: () => { throw new Error("the shell must never write localStorage"); },
      removeItem: () => { throw new Error("the shell must never write localStorage"); },
    },
  });
  const textOf = (html: string) => html.replace(/<[^>]*>/g, " ").replace(/&[a-z#0-9]+;/gi, " ");
  const attrsOf = (html: string) => [...html.matchAll(/\s(?:title|aria-label|placeholder)="([^"]*)"/g)].map((m) => m[1]!);
  const machinesHtml = (h: ReturnType<typeof boot>) =>
    h.el["machines-summary"]!.innerHTML + h.el["machines-list"]!.innerHTML;
  const escapedAttr = (value: string) => escapeHtml(value);
  const rowSlice = (html: string, rowOpen: string, marker: string) => {
    const markerIndex = html.indexOf(marker);
    expect(markerIndex, marker).toBeGreaterThanOrEqual(0);
    const start = html.lastIndexOf(rowOpen, markerIndex);
    expect(start, rowOpen).toBeGreaterThanOrEqual(0);
    const next = html.indexOf(rowOpen, markerIndex + marker.length);
    return html.slice(start, next < 0 ? html.length : next);
  };
  const machineRowHtml = (html: string, url: string) => {
    const marker = `data-machine-url="${escapedAttr(url)}"`;
    const markerIndex = html.indexOf(marker);
    expect(markerIndex, marker).toBeGreaterThanOrEqual(0);
    const start = html.lastIndexOf("<div ", markerIndex);
    expect(start, "machine row start").toBeGreaterThanOrEqual(0);
    const next = html.indexOf("<div data-machine-index=", markerIndex + marker.length);
    return html.slice(start, next < 0 ? html.length : next);
  };
  const agentListRowHtml = (html: string, id: string) =>
    rowSlice(html, '<tr>', `data-agent-id="${escapedAttr(id)}"`);
  const fortressAgentRowHtml = (html: string, id: string) =>
    rowSlice(html, '<div class="row agent-row"', `data-agent-row="${escapedAttr(id)}"`);

  it("Machines renders the saved fleet with its denominator and check age, and an unanswered machine is Unknown, never online", async () => {
    vi.useFakeTimers();
    const probes: Array<{ url: string; init?: RequestInit }> = [];
    const abortable = (init?: RequestInit) => new Promise((_, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
    });
    const h = boot({
      "http://fixture/api/health": (init) => { probes.push({ url: "http://fixture", init }); return Promise.resolve(response({ ok: true })); },
      "http://build-1.fixture:3501/api/health": (init) => { probes.push({ url: "build-1", init }); return Promise.resolve(response({ ok: false })); },
      "http://mba.fixture:3501/api/health": (init) => { probes.push({ url: "mba", init }); return abortable(init); },
    }, storage([
      { name: "build-1", url: "http://build-1.fixture:3501" },
      { name: "erik-mba", url: "http://mba.fixture:3501" },
      { name: "not-a-web-address", url: "javascript:alert(1)" },
    ]));
    await settle();
    h.navigate("machines");
    await settle();
    let html = machinesHtml(h);
    // This machine joins the three saved ones: four in the denominator.
    expect(html).toContain("1 of 4 machines online · 1 checking · 1 not healthy · 1 Unknown");
    // Retargeted (slice 2b): the summary used to include a cap-only
    // "showing" clause; all rows are now listed, so that copy would lie.
    expect(html).not.toContain("showing");
    expect(html).toMatch(/checked \d+s ago/);
    vi.advanceTimersByTime(3000);
    await settle();
    html = machinesHtml(h);
    // Once the probe deadline passes, no row can keep claiming an in-flight check.
    expect(html).toContain("1 of 4 machines online · 1 not healthy · 2 Unknown · <span id=\"machines-age\">checked 3s ago</span>");
    expect(html.match(/state-chip good/g) ?? []).toHaveLength(1);
    expect(html.match(/state-chip unknown/g) ?? []).toHaveLength(2);
    const mbaRow = machineRowHtml(html, "http://mba.fixture:3501");
    // The saved display name must stay above the saved address in its row;
    // otherwise the row can look like an origin-only fallback.
    expect(mbaRow).toMatch(/<strong>erik-mba<\/strong><small class="mono">http:\/\/mba\.fixture:3501<\/small>/);
    // This binds the unanswered mba row to its own Unknown chip; aggregate
    // chip counts alone would miss a row-to-state swap.
    expect(html).toMatch(/data-machine-url="http:\/\/mba\.fixture:3501"[^>]*><span [^>]*class="state-chip unknown"/);
    // No non-web address reaches an href or a probe, and no probe carries a
    // credential to another machine.
    expect(html).not.toMatch(/href="javascript:/i);
    expect(probes.map((p) => p.url).sort()).toEqual(["build-1", "http://fixture", "mba"]);
    for (const p of probes) {
      expect(p.init?.credentials, p.url).toBe("omit");
      expect(JSON.stringify(p.init?.headers ?? {}), p.url).not.toMatch(/authorization/i);
    }
    // The rail item lights for the screen, and /fleet stays one click away.
    expect(runInContext("ROUTE_RAIL_PARENT.machines", h.context)).toBe("machines");
    expect(h.el.main!.innerHTML).toContain('href="/fleet"');
  });

  it.each([
    ["2xx ok true", response({ ok: true }), "Online", "state-chip good"],
    ["2xx ok false", response({ ok: false }), "Not healthy", "state-chip bad"],
    ["503 ok true", response({ ok: true }, 503), "Unknown", "state-chip unknown"],
    ["500 ok false", response({ ok: false }, 500), "Unknown", "state-chip unknown"],
    ["missing ok", response({}), "Unknown", "state-chip unknown"],
    ["non-boolean ok", response({ ok: "yes" }), "Unknown", "state-chip unknown"],
    ["redirect", response({ ok: true }, 200, { redirected: true }), "Unknown", "state-chip unknown"],
    ["opaque redirect", response({ ok: true }, 0, { type: "opaqueredirect" }), "Unknown", "state-chip unknown"],
    ["malformed json", { ok: true, status: 200, redirected: false, type: "basic", json: async () => { throw new Error("bad json"); } }, "Unknown", "state-chip unknown"],
  ])("probe outcome table maps %s to %s", async (_label, health, word, cls) => {
    vi.useFakeTimers();
    const h = boot({ "http://fixture/api/health": () => Promise.resolve(health) }, storage([]));
    await settle();
    h.navigate("machines");
    await settle();
    const html = machinesHtml(h);
    expect(html).toContain(word);
    expect(html).toContain(cls);
    if (word === "Unknown") expect(html).toContain("0 of 1 machine online · 1 Unknown");
  });

  it("Check again aborts the previous probe wave and a slow answer from the old round never repaints a machine", async () => {
    vi.useFakeTimers();
    let release: (v: unknown) => void = () => {};
    let calls = 0;
    let aborts = 0;
    const h = boot({
      "http://fixture/api/health": (init) => {
        calls++;
        init?.signal?.addEventListener("abort", () => { aborts++; });
        if (calls === 1) return new Promise((r) => { release = r; });
        return Promise.reject(new Error("refused"));
      },
    }, storage([]));
    await settle();
    h.navigate("machines");
    await settle();
    expect(machinesHtml(h)).toContain("0 of 1 machine online · 1 checking");
    h.click({ "data-action": "machines-recheck" });
    await settle();
    expect(aborts).toBeGreaterThan(0);
    expect(machinesHtml(h)).toContain("0 of 1 machine online · 1 Unknown");
    release(response({ ok: true }));
    await settle();
    expect(machinesHtml(h)).toContain("0 of 1 machine online · 1 Unknown");
    expect(machinesHtml(h)).not.toContain("state-chip good");
  });

  it("Machines treats saved entries with script-like text as text and never probes or links non-web addresses", async () => {
    vi.useFakeTimers();
    const fetched: string[] = [];
    const h = boot({}, {
      ...storage([
        { name: '<img src=x onerror=alert(1)>', url: 'http://safe.fixture:3501/console?name="><script>alert(1)</script>' },
        { name: '"><script>alert(1)</script>', url: "javascript:alert(1)" },
        { name: "data payload", url: "data:text/html,<script>alert(1)</script>" },
        { name: "mixed scheme", url: "JaVaScRiPt:alert(1)" },
      ]),
      fetch: (url: string, init?: RequestInit) => {
        fetched.push(url);
        if (url === "http://fixture/api/health" || url === "http://safe.fixture:3501/api/health") return Promise.resolve(response({ ok: true }));
        return Promise.resolve(response(emptyData, 200, { init }));
      },
    });
    await settle();
    h.navigate("machines");
    await settle();
    const html = machinesHtml(h);
    expect(h.el["machines-list"]!.textContent).toContain('<img src=x onerror=alert(1)>');
    expect(h.el["machines-list"]!.textContent).toContain('"><script>alert(1)</script>');
    expect(html).not.toMatch(/<(?:img|script)\b/i);
    expect(html).not.toMatch(/\sonerror="/i);
    // The only href keeps the parsed web address; non-web entries
    // remain text, and the saved path is not silently retargeted to root.
    expect([...html.matchAll(/\shref="([^"]*)"/g)].map((m) => m[1])).toEqual(["http://safe.fixture:3501/console?name=%22%3E%3Cscript%3Ealert(1)%3C/script%3E"]);
    expect(fetched.filter((url) => url.endsWith("/api/health")).sort()).toEqual(["http://fixture/api/health", "http://safe.fixture:3501/api/health"]);
    expect(html.match(/Not a web address/g) ?? []).toHaveLength(3);
  });

  it("a long saved list is listed but only the named cap is probed", async () => {
    vi.useFakeTimers();
    const saved = Array.from({ length: 2500 }, (_, i) => ({ name: `build-${i}`, url: `http://build-${i}.fixture:3501` }));
    const fetched: string[] = [];
    const h = boot({}, {
      ...storage(saved),
      fetch: (url: string) => {
        fetched.push(url);
        return Promise.resolve(response({ ok: true }));
      },
    });
    await settle();
    h.navigate("machines");
    await settle();
    const limit = Number(runInContext("FLEET_PROBED_MACHINE_LIMIT", h.context));
    expect(fetched.filter((url) => url.endsWith("/api/health"))).toHaveLength(limit);
    // The capped-round summary is past tense only after every in-cap probe
    // answered, and must not restore the old second count for capped rows.
    expect(machinesHtml(h)).toContain(`checked ${limit} of 2501 machines with a web address; the rest are listed unchecked`);
    expect(machinesHtml(h)).not.toContain("unprobed");
    expect(h.el["machines-list"]!.textContent).toContain("build-2499");
    // The row chip uses the same word as the summary; "Unprobed" was an
    // internal state name and is not operator copy.
    expect(h.el["machines-list"]!.textContent).toContain("Unchecked");
    expect(attrsOf(machinesHtml(h)).some((value) => value.startsWith("Unchecked"))).toBe(true);
    expect(h.el["machines-list"]!.replaceCount).toBe(1);
  });

  it("a capped round with the named limit still in flight does not double-count checking rows", async () => {
    vi.useFakeTimers();
    const limitProbe = boot();
    const limit = Number(runInContext("FLEET_PROBED_MACHINE_LIMIT", limitProbe.context));
    const h = boot({}, {
      ...storage(Array.from({ length: limit + 1 }, (_, i) => ({ name: `peer-${i}`, url: `http://peer-${i}.fixture:3501` }))),
      fetch: () => new Promise(() => {}),
    });
    await settle();
    h.navigate("machines");
    await settle();
    const html = machinesHtml(h);
    expect(html).toContain(`checking ${limit} of ${limit + 2} machines with a web address; the rest are listed unchecked`);
    expect(html).not.toContain(`${limit} checking`);
    expect(html).not.toContain("unprobed");
  });

  it("the cap phrase uses the named web-address count at the 25 and 26 row boundaries", async () => {
    vi.useFakeTimers();
    const limitProbe = boot();
    const limit = Number(runInContext("FLEET_PROBED_MACHINE_LIMIT", limitProbe.context));
    const atLimit = boot({}, {
      ...storage(Array.from({ length: limit - 1 }, (_, i) => ({ name: `peer-${i}`, url: `http://peer-${i}.fixture:3501` }))),
      fetch: () => Promise.resolve(response({ ok: true })),
    });
    await settle();
    atLimit.navigate("machines");
    await settle();
    expect(Number(runInContext("FLEET_PROBED_MACHINE_LIMIT", atLimit.context))).toBe(limit);
    expect(machinesHtml(atLimit)).toContain(`${limit} of ${limit} machines online`);
    expect(machinesHtml(atLimit)).not.toContain("the rest are listed unchecked");

    const overLimit = boot({}, {
      ...storage([
        ...Array.from({ length: limit }, (_, i) => ({ name: `peer-${i}`, url: `http://peer-${i}.fixture:3501` })),
        { name: "plain text", url: "not-a-web-address" },
      ]),
      fetch: () => Promise.resolve(response({ ok: true })),
    });
    await settle();
    overLimit.navigate("machines");
    await settle();
    expect(machinesHtml(overLimit)).toContain(`checked ${limit} of ${limit + 1} machines with a web address; the rest are listed unchecked`);
    expect(machinesHtml(overLimit)).toContain("1 Unknown");
    // The cap denominator counts web addresses only; this catches a non-web
    // saved row being swept into "the rest are listed unchecked".
    expect(machinesHtml(overLimit)).not.toContain(`checked ${limit} of ${limit + 2} machines with a web address; the rest are listed unchecked`);
  });

  it("an empty saved list has no cap clause", async () => {
    vi.useFakeTimers();
    const h = boot({}, {
      ...storage([]),
      fetch: () => Promise.resolve(response({ ok: true })),
    });
    await settle();
    h.navigate("machines");
    await settle();
    expect(machinesHtml(h)).toContain("1 of 1 machine online");
    expect(machinesHtml(h)).not.toContain("the rest are listed unchecked");
  });

  it("this machine stays inside the probe cap even when saved after twenty-five peers", async () => {
    vi.useFakeTimers();
    const saved = Array.from({ length: 25 }, (_, i) => ({ name: `peer-${i}`, url: `http://peer-${i}.fixture:3501` }));
    saved.push({ name: "self saved late", url: "http://fixture/path" });
    const fetched: string[] = [];
    const h = boot({}, {
      ...storage(saved),
      fetch: (url: string) => { fetched.push(url); return Promise.resolve(response({ ok: true })); },
    });
    await settle();
    h.navigate("machines");
    await settle();
    expect(fetched.filter((url) => url === "http://fixture/api/health")).toHaveLength(1);
    expect(machinesHtml(h)).toMatch(/data-machine-url="http:\/\/fixture\/path"[^>]*><span [^>]*class="state-chip good"/);
  });

  it("duplicate host-port entries share one probed row and path addresses are described as host checks", async () => {
    vi.useFakeTimers();
    const fetched: string[] = [];
    const h = boot({}, {
      ...storage([
        { name: "with path", url: "http://build.fixture:3501/tenant/a" },
        { name: "duplicate path", url: "http://build.fixture:3501/tenant/b" },
      ]),
      fetch: (url: string) => { fetched.push(url); return Promise.resolve(response({ ok: true })); },
    });
    await settle();
    h.navigate("machines");
    await settle();
    expect(fetched.filter((url) => url === "http://build.fixture:3501/api/health")).toHaveLength(1);
    expect(machinesHtml(h)).toContain("2 of 2 machines online");
    expect(h.el["machines-list"]!.textContent).toContain("host health check");
    expect(machinesHtml(h)).toContain('href="http://build.fixture:3501/tenant/a"');
  });

  it("Open console uses the parsed machine address", async () => {
    vi.useFakeTimers();
    const h = boot({}, {
      ...storage([{ name: "peer", url: "http:peer:3501" }]),
      fetch: () => Promise.resolve(response({ ok: true })),
    });
    await settle();
    h.navigate("machines");
    await settle();
    expect(machinesHtml(h)).toContain('href="http://peer:3501/"');
  });

  it("a row repaint keeps focus on its Open console link", async () => {
    vi.useFakeTimers();
    let releasePeer: (value: unknown) => void = () => {};
    const h = boot({
      "http://peer.fixture:3501/api/health": () => new Promise((resolve) => { releasePeer = resolve; }),
      "http://fixture/api/health": () => Promise.resolve(response({ ok: true })),
    }, storage([{ name: "peer", url: "http://peer.fixture:3501/" }]));
    await settle();
    h.navigate("machines");
    await settle();
    const link = h.el["machines-list"]!.querySelector('[href="http://peer.fixture:3501/"]');
    expect(link).toBeTruthy();
    link!.focus();
    releasePeer(response({ ok: true }));
    await settle();
    const newLink = h.el["machines-list"]!.querySelector('[href="http://peer.fixture:3501/"]');
    expect(newLink).toBeTruthy();
    expect(newLink).not.toBe(link);
    expect(h.el["machines-list"]!.contains(link)).toBe(false);
    expect((runInContext("document.activeElement && document.activeElement.getAttribute('href')", h.context))).toBe("http://peer.fixture:3501/");
    expect(fakeActiveElement).toBe(newLink);
    expect(runInContext("document.getElementById('machines-list').contains(document.activeElement)", h.context)).toBe(true);
  });

  it("a saved address with control characters does not stop the rest of the paint batch", async () => {
    vi.useFakeTimers();
    let releaseControlAddress: (value: unknown) => void = () => {};
    let releaseNormal: (value: unknown) => void = () => {};
    const controlAddress = "http://bad.fixture:3501/\fline\nbreak";
    const h = boot({
      "http://bad.fixture:3501/api/health": () => new Promise((resolve) => { releaseControlAddress = resolve; }),
      "http://normal.fixture:3501/api/health": () => new Promise((resolve) => { releaseNormal = resolve; }),
      "http://fixture/api/health": () => Promise.resolve(response({ ok: true })),
    }, storage([{ name: "control chars", url: controlAddress }, { name: "normal", url: "http://normal.fixture:3501/" }]));
    await settle();
    h.navigate("machines");
    await settle();
    releaseControlAddress(response({ ok: true }));
    releaseNormal(response({ ok: false }));
    await settle();
    const html = machinesHtml(h);
    expect(html).toContain('data-machine-url="' + controlAddress + '"');
    expect(html).toContain('data-machine-url="http://normal.fixture:3501/"');
    expect(html).toContain("Online");
    expect(html).toContain("Not healthy");
    expect(html).not.toContain("Checking");
  });

  it("each painted row carries its generated index and repaint lookup uses it", async () => {
    vi.useFakeTimers();
    let releasePeer: (value: unknown) => void = () => {};
    const h = boot({
      "http://peer.fixture:3501/api/health": () => new Promise((resolve) => { releasePeer = resolve; }),
      "http://fixture/api/health": () => Promise.resolve(response({ ok: true })),
    }, storage([{ name: "peer", url: "http://peer.fixture:3501/" }]));
    await settle();
    h.navigate("machines");
    await settle();
    expect([...machinesHtml(h).matchAll(/data-machine-index="(\d+)"/g)].map((m) => Number(m[1]))).toEqual([0, 1]);
    const peerRow = h.el["machines-list"]!.querySelector('[data-machine-url="http://peer.fixture:3501/"]');
    expect(peerRow?.getAttribute("data-machine-index")).toBe("1");
    peerRow!.removeAttribute("data-machine-index");
    releasePeer(response({ ok: true }));
    await settle();
    const row = machineRowHtml(machinesHtml(h), "http://peer.fixture:3501/");
    expect(row).toContain('class="state-chip unknown"');
    expect(row).toContain('title="Unknown: this row could not be updated; use Check again."');
    expect(row).not.toContain("Checking");
    expect(machinesHtml(h)).not.toMatch(/data-machine-url="http:\/\/peer\.fixture:3501\/"[^>]*><span [^>]*class="state-chip good"/);
  });

  it("a persistent row build failure marks the existing chip and restores focus after another row repaints", async () => {
    vi.useFakeTimers();
    let releaseBroken: (value: unknown) => void = () => {};
    let releaseNormal: (value: unknown) => void = () => {};
    const brokenUrl = "http://broken.fixture:3501/";
    const normalUrl = "http://normal.fixture:3501/";
    const h = boot({
      "http://broken.fixture:3501/api/health": () => new Promise((resolve) => { releaseBroken = resolve; }),
      "http://normal.fixture:3501/api/health": () => new Promise((resolve) => { releaseNormal = resolve; }),
      "http://fixture/api/health": () => Promise.resolve(response({ ok: true })),
    }, storage([{ name: "broken", url: brokenUrl }, { name: "normal", url: normalUrl }]));
    await settle();
    h.navigate("machines");
    await settle();
    const normalLink = h.el["machines-list"]!.querySelector('[href="http://normal.fixture:3501/"]');
    expect(normalLink).toBeTruthy();
    normalLink!.focus();
    const oldRow = h.el["machines-list"]!.querySelector('[data-machine-url="http://broken.fixture:3501/"]')!;
    const oldChip = oldRow.querySelector(".state-chip")!;
    const chipAttributeWrite = vi.spyOn(oldChip, "setAttribute");
    const rowSwap = vi.spyOn(oldRow, "replaceWith");
    setAttributeThrowFor = { name: "data-machine-url", value: brokenUrl, persistent: true };
    releaseBroken(response({ ok: true }));
    releaseNormal(response({ ok: false }));
    await settle();
    const newNormalLink = h.el["machines-list"]!.querySelector('[href="http://normal.fixture:3501/"]');
    expect(newNormalLink).toBeTruthy();
    expect(newNormalLink).not.toBe(normalLink);
    expect(fakeActiveElement).toBe(newNormalLink);
    const brokenRow = machineRowHtml(machinesHtml(h), brokenUrl);
    expect(brokenRow).toContain('class="state-chip unknown"');
    expect(brokenRow).toContain('title="Unknown: this row could not be updated; use Check again."');
    expect(brokenRow).not.toContain("Checking");
    expect(h.el["machines-list"]!.querySelector('[data-machine-url="http://broken.fixture:3501/"]')).toBe(oldRow);
    expect(oldRow.querySelector(".state-chip")).toBe(oldChip);
    expect(chipAttributeWrite).not.toHaveBeenCalled();
    expect(rowSwap).not.toHaveBeenCalled();
    expect(h.el["machines-summary"]!.textContent).toContain("2 of 3 machines online");
    expect(h.el["machines-summary"]!.textContent).not.toContain("checking");
    expect(machinesHtml(h)).toMatch(/data-machine-url="http:\/\/normal\.fixture:3501\/"[^>]*><span [^>]*class="state-chip bad"/);
  });

  it("a failed row build on first visit leaves the rest of the machine list rendered", async () => {
    vi.useFakeTimers();
    const brokenUrl = "http://broken.fixture:3501/";
    const normalUrl = "http://normal.fixture:3501/";
    setAttributeThrowFor = { name: "data-machine-url", value: brokenUrl };
    const h = boot({
      "http://broken.fixture:3501/api/health": () => Promise.resolve(response({ ok: true })),
      "http://normal.fixture:3501/api/health": () => Promise.resolve(response({ ok: true })),
      "http://fixture/api/health": () => Promise.resolve(response({ ok: true })),
    }, storage([{ name: "broken saved name", url: brokenUrl }, { name: "normal", url: normalUrl }]));
    await settle();
    h.navigate("machines");
    await settle();
    const html = machinesHtml(h);
    const brokenRow = machineRowHtml(html, brokenUrl);
    expect(brokenRow).toContain("broken saved name");
    expect(brokenRow).toContain('class="state-chip unknown"');
    expect(brokenRow).toContain('title="Unknown: this row could not be updated; use Check again."');
    expect(machineRowHtml(html, normalUrl)).toContain('class="state-chip good"');
    expect(h.el["machines-summary"]!.textContent).toContain("machines online");
  });

  it("persistent first-visit failures draw a fixed-text placeholder row and still render the other rows and restore focus", async () => {
    vi.useFakeTimers();
    const brokenUrl = "http://broken.fixture:3501/";
    const normalUrl = "http://normal.fixture:3501/";
    const returnedRow = vi.fn();
    const h = boot({
      "http://broken.fixture:3501/api/health": () => Promise.resolve(response({ ok: true })),
      "http://normal.fixture:3501/api/health": () => Promise.resolve(response({ ok: true })),
      "http://fixture/api/health": () => Promise.resolve(response({ ok: true })),
    }, { ...storage([{ name: "broken", url: brokenUrl }, { name: "normal", url: normalUrl }]), returnedRow });
    await settle();
    runInContext(`const originalGuardedRow = guardedMachineRow;
      guardedMachineRow = function (machine, index) {
        const row = originalGuardedRow(machine, index);
        returnedRow(machine.url, row);
        return row;
      };`, h.context);
    // The fake does not parse main.innerHTML; delegate its restored-link lookup
    // to the hydrated list, as the real main element does through its children.
    const priorLink = new FakeElement({ href: normalUrl }, "a");
    h.el.main!.appendChild(priorLink);
    h.el.main!.querySelectorAll = (selector) => h.el["machines-list"]!.querySelectorAll(selector);
    priorLink.focus();
    setAttributeThrowFor = { name: "data-machine-url", value: brokenUrl, persistent: true };
    expect(() => h.navigate("machines")).not.toThrow();
    const fallback = returnedRow.mock.calls.find(([url]) => url === brokenUrl)?.[1];
    // If both constructors fail, the guard returns a placeholder row of fixed
    // text, so the list still shows one entry per counted machine.
    expect(fallback).toBeInstanceOf(FakeElement);
    expect(fallback.className).toBe("machine-row");
    expect(fallback.textContent).toBe("One machine could not be shown; use Check again.");
    expect(fallback.textContent).not.toContain("broken");
    expect(machinesHtml(h)).toContain("One machine could not be shown; use Check again.");
    const normalLink = h.el["machines-list"]!.querySelector('[href="http://normal.fixture:3501/"]');
    expect(normalLink).toBeTruthy();
    expect(fakeActiveElement).toBe(normalLink);
    expect(h.el["machines-list"]!.replaceCount).toBe(1);
    expect(h.el["machines-summary"]!.textContent).toContain("3 checking");
    await settle();
    expect(machineRowHtml(machinesHtml(h), normalUrl)).toContain('class="state-chip good"');
    expect(machineRowHtml(machinesHtml(h), "http://fixture")).toContain('class="state-chip good"');
    expect(h.el["machines-summary"]!.textContent).toContain("3 of 3 machines online");
    expect(fakeActiveElement).toBe(h.el["machines-list"]!.querySelector('[href="http://normal.fixture:3501/"]'));
  });

  it.each(["missing index", "throwing index lookup"])("paint rebuilds once after %s and restores focus to the new link", async (trigger) => {
    vi.useFakeTimers();
    let releaseControl: (value: unknown) => void = () => {};
    let releaseNormal: (value: unknown) => void = () => {};
    const controlUrl = "http://control.fixture:3501/\fpath";
    const normalUrl = "http://normal.fixture:3501/";
    const h = boot({
      "http://control.fixture:3501/api/health": () => new Promise((resolve) => { releaseControl = resolve; }),
      "http://normal.fixture:3501/api/health": () => new Promise((resolve) => { releaseNormal = resolve; }),
      "http://fixture/api/health": () => Promise.resolve(response({ ok: true })),
    }, storage([{ name: "control", url: controlUrl }, { name: "normal", url: normalUrl }]));
    await settle();
    h.navigate("machines");
    await settle();
    const list = h.el["machines-list"]!;
    const oldRow = list.querySelector('[data-machine-index="1"]')!;
    expect(oldRow.textContent).toContain("Checking");
    oldRow.removeAttribute("data-machine-index");
    if (trigger === "throwing index lookup") {
      // A DOM lookup exception reaches the outer catch's distinct rebuild.
      vi.spyOn(list, "querySelector").mockImplementationOnce(() => { throw new Error("fixture lookup failed"); });
    }
    const oldLink = list.querySelectorAll('[href="http://normal.fixture:3501/"]')[0]!;
    oldLink.focus();
    const buildsBefore = list.replaceCount;
    releaseControl(response({ ok: true }));
    releaseNormal(response({ ok: false }));
    await settle();
    const newRow = list.querySelector('[data-machine-index="1"]')!;
    expect(newRow).toBeTruthy();
    expect(newRow).not.toBe(oldRow);
    expect(newRow.getAttribute("data-machine-url")).toBe(controlUrl);
    expect(newRow.querySelector(".state-chip")!.className).toBe("state-chip good");
    expect(newRow.textContent).toContain("Online");
    expect(list.textContent).not.toContain("Checking");
    expect(list.replaceCount - buildsBefore).toBe(1);
    expect(machineRowHtml(machinesHtml(h), normalUrl)).toContain('class="state-chip bad"');
    const newLink = list.querySelector('[href="http://normal.fixture:3501/"]');
    expect(newLink).toBeTruthy();
    expect(newLink).not.toBe(oldLink);
    expect(fakeActiveElement).toBe(newLink);
    expect(list.contains(fakeActiveElement)).toBe(true);
  });

  it("a Fleet link click changes route once and starts one probe wave", async () => {
    vi.useFakeTimers();
    const fetched: string[] = [];
    const h = boot({}, {
      ...storage([{ name: "build", url: "http://build.fixture:3501" }]),
      fetch: (url: string) => { fetched.push(url); return Promise.resolve(response({ ok: true })); },
    });
    await settle();
    h.click({ "data-action": "set-route", "data-route": "machines" });
    await settle();
    expect(runInContext("state.route", h.context)).toBe("machines");
    expect(fetched.filter((url) => url.endsWith("/api/health")).sort()).toEqual([
      "http://build.fixture:3501/api/health",
      "http://fixture/api/health",
    ]);
  });

  it("the Sentinels line is Unknown without a Sentinel report, however many agents are on the roster", async () => {
    vi.useFakeTimers();
    const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [{ agent_id: "a1", status: "active", model_provider }, { agent_id: "a2", status: "active", model_provider }] } })),
    });
    await settle();
    h.navigate("enforcement");
    const m = h.el.main!.innerHTML.match(/<span class="(pp-dot[^"]*)"><\/span><span class="pp-k">Sentinels watching agents<\/span><span class="pp-v">([^<]*)<\/span>/);
    expect(m, "Sentinels line").toBeTruthy();
    expect(m![1]).toBe("pp-dot unknown");
    expect(m![2]).toBe("Unknown");
  });

  it("the exercised shell screens avoid retired wrap vocabulary, and the agent controls say Lock down and Remove protection", async () => {
    vi.useFakeTimers();
    const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
    const capabilities = { can_pause: true, can_resume: true, can_restart: true, can_lockdown: true, can_unwrap: false };
    const agents = [
      { agent_id: "a1", status: "active", harness: "fixture-harness", model_provider, capabilities },
      { agent_id: "a2", status: "paused", harness: "fixture-harness", model_provider, capabilities: { ...capabilities, can_unwrap: true } },
    ];
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })),
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })),
    });
    await settle();
    const routes = ["posture", "approvals", "agents", "machines", "enforcement", "findings", "activity", "policy", "integrations", "settings",
      "dashboard", "attestation", "health", "auto-trigger", "intelligence", "privacy", "honeypot", "coordination", "exit-drill"];
    const retired = /\b(un)?wrap(s|ped|ping)?\b/i;
    for (const route of routes) {
      h.navigate(route);
      await settle();
      const html = h.el.main!.innerHTML;
      expect(textOf(html) + h.el["toast-host"]!.textContent, route).not.toMatch(retired);
      for (const a of attrsOf(html)) expect(a, route).not.toMatch(retired);
    }
    h.navigate("activity");
    await settle();
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-action="agent-unwrap" data-agent-id="a1" disabled title="Removing protection from the dashboard is not available yet; an unsupported request is refused before any approval is queued.">Remove protection</button>');
    expect(html).toContain('data-action="agent-lockdown" data-agent-id="a1" title="Tier 1: requires inbox approval.">Lock down</button>');
  });

  it("the Policies subtitle says only what the edit path does", async () => {
    vi.useFakeTimers();
    const h = boot();
    await settle();
    h.navigate("policy");
    const html = h.el.main!.innerHTML;
    expect(html).toContain("A template change waits for your approval; approving it records the new template on the agent, and your decision either way is written to your audit log.");
    expect(html).not.toMatch(/signed receipt|tool-call cycle/);
  });

  // One glyph-to-mark table for both agent mark tests below, so the dot and tone they expect cannot drift apart.
  const GLYPH_TO_MARK: Record<string, { dot: string; tone: string }> = {
    online: { dot: "live", tone: "tone-verified" }, idle: { dot: "idle", tone: "tone-degraded" },
    offline: { dot: "locked", tone: "tone-locked" }, away: { dot: "off", tone: "tone-unverified" },
    unknown: { dot: "unknown", tone: "tone-unknown" },
  };

  it("an agent without current evidence wears the Unknown mark, never a working state's mark", async () => {
    vi.useFakeTimers();
    const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [
        { agent_id: "no-evidence", status: "active", harness: "h", model_provider },
        { agent_id: "paused-one", status: "paused", harness: "h", model_provider },
        { agent_id: "unwrapping-one", status: "unwrapping", harness: "h", model_provider },
        { agent_id: "locked-one", status: "locked_down", harness: "h", model_provider },
        { agent_id: "off-enum", status: "mystery", harness: "h", model_provider },
      ] } })),
    });
    await settle();
    h.navigate("agents");
    const html = h.el.main!.innerHTML;
    const chip = (id: string) => agentListRowHtml(html, id);
    const unwrappingLabel = runInContext("STATUS_MAP.unwrapping.label", h.context) as string;
    const unwrappingGlyph = STATUS_MAPPING.unwrapping.glyph;
    const { dot: unwrappingDot, tone: unwrappingTone } = GLYPH_TO_MARK[unwrappingGlyph]!;
    expect(chip("no-evidence")).toContain('state-chip unknown');
    expect(chip("no-evidence")).toContain("UNKNOWN");
    expect(chip("paused-one")).toContain("PAUSED");
    expect(chip("unwrapping-one")).toContain(unwrappingLabel.toUpperCase());
    expect(chip("locked-one")).toContain('state-chip locked');
    expect(chip("off-enum")).toContain('state-chip unknown');
    // The inspect pane's pill wears the same Unknown tone as its dot, and
    // an activity row without a verdict wears the neutral mark, not a pass.
    runInContext(`state.chat.inspect.panelByAgentId["no-evidence"] = { recent_activity: [{ emitted_at: "2026-10-13T00:00:00.000Z", display_template_id: "activity.egress", display_template_args: [] }], pending_approvals: [], policy_summary: null, opened_at: "2026-10-13T00:00:00.000Z" };`, h.context);
    const pane = runInContext(`renderAgentInspectPanel(state.agents[0])`, h.context) as string;
    expect(pane).toContain('<span class="pill tone-unknown"><span class="state-dot unknown"');
    expect(pane).toContain('<div class="timeline-item"><div class="ts">');
    expect(pane).not.toContain("timeline-item ok");
    runInContext(`state.chat.inspect.panelByAgentId["unwrapping-one"] = { recent_activity: [], pending_approvals: [], policy_summary: null, opened_at: "2026-10-13T00:00:00.000Z" }; state.selectedAgentId = "unwrapping-one";`, h.context);
    const unwrappingPane = runInContext(`renderAgentInspectPanel(state.agents.find(function (a) { return a.agent_id === "unwrapping-one"; }))`, h.context) as string;
    const unwrappingDetail = runInContext("renderAgentDetail()", h.context) as string;
    const fortressCard = runInContext("renderFortressAgentsCard()", h.context) as string;
    expect(unwrappingPane).toContain(`<span class="pill ${unwrappingTone}"><span class="state-dot ${unwrappingDot}"`);
    expect(unwrappingDetail).toContain(`<dt>Status</dt><dd><span class="glyph ${unwrappingGlyph}"></span> ${unwrappingLabel}</dd>`);
    expect(fortressAgentRowHtml(fortressCard, "unwrapping-one")).toContain(`<span class="glyph ${unwrappingGlyph}"`);
  });

  it("every wire agent status agrees with the status table mark in each agent view", async () => {
    vi.useFakeTimers();
    const now = new Date().toISOString();
    const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
    const agents = HUB_AGENT_STATUSES.map((status) => ({ agent_id: `agent-${status}`, status, harness: "h", model_provider }));
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })),
      "/api/posture/home": () => Promise.resolve(response({
        ...home(),
        agents: [{ agent_id: "agent-active", enforcement_active: "active", last_enforcement_evidence_at: now, freshness_window_ms: 60000 }],
      })),
    });
    await settle();
    h.navigate("agents");
    const tableStatuses = Object.keys(STATUS_MAPPING).sort();
    expect([...HUB_AGENT_STATUSES].sort()).toEqual(tableStatuses);
    for (const status of HUB_AGENT_STATUSES) {
      const id = `agent-${status}`;
      const expectedGlyph = STATUS_MAPPING[status].glyph;
      const expectedDot = GLYPH_TO_MARK[expectedGlyph]!.dot;
      (h.context as Record<string, unknown>).__agentStatus = status;
      (h.context as Record<string, unknown>).__agentId = id;
      expect(runInContext("STATUS_MAP[__agentStatus].glyph", h.context), status).toBe(expectedGlyph);
      expect(runInContext("agentStateClass(__agentStatus)", h.context), status).toBe(expectedDot);
      const listHtml = h.el.main!.innerHTML;
      expect(agentListRowHtml(listHtml, id), status).toContain(status === "active" ? "RUNNING" : STATUS_MAPPING[status].label.toUpperCase());
      runInContext("state.chat.inspect.panelByAgentId[__agentId] = { recent_activity: [], pending_approvals: [], policy_summary: null, opened_at: '2026-10-14T00:00:00.000Z' }; state.selectedAgentId = __agentId;", h.context);
      const pane = runInContext("renderAgentInspectPanel(state.agents.find(function (a) { return a.agent_id === __agentId; }))", h.context) as string;
      const detail = runInContext("renderAgentDetail()", h.context) as string;
      const fortress = runInContext("renderFortressAgentsCard()", h.context) as string;
      expect(pane, status).toContain(`<span class="state-dot ${expectedDot}"`);
      expect(detail, status).toContain(`<span class="glyph ${expectedGlyph}"></span>`);
      expect(fortressAgentRowHtml(fortress, id), status).toContain(`<span class="glyph ${expectedGlyph}"`);
    }
  });

  it("the Evidence filter form renders each filter as a labelled field", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/posture/evidence": () => Promise.resolve(response({ origin_machine: "fixture", entries: [], total: 0, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } })),
    });
    await settle();
    h.navigate("activity");
    const html = h.el.main!.innerHTML;
    const bar = html.match(/<div class="filter-bar" role="group" aria-label="Filter evidence entries">([\s\S]*?)<\/div>/);
    expect(bar, "filter bar").toBeTruthy();
    const labels = [...bar![1]!.matchAll(/<label class="field"><span class="field-label">([^<]+)<\/span><(input|select) class="input"/g)].map((m) => m[1]);
    // The activity route's first filter bar is now the Evidence query bar; the kept inbox bar's six labels are
    // pinned in "keeps the old Activity inbox, agent, Recognition and batch controls on Evidence".
    expect(labels).toEqual(["Layer", "Agent", "Event", "Result", "From"]);
    expect(bar![1]).toContain("Query");
    expect(bar![1]).not.toContain("<br>");
  });

  it("the auto-trigger trend names each bar shape with its count", async () => {
    vi.useFakeTimers();
    const h = boot();
    await settle();
    const out = runInContext(`renderAutoTriggerTrend([
      { outcome: "auto_proceeded", observed_at: "2026-10-13T00:00:00.000Z" },
      { outcome: "operator_approved", observed_at: "2026-10-13T00:01:00.000Z" },
      { outcome: "operator_canceled", observed_at: "2026-10-13T00:02:00.000Z" },
      { outcome: "awaiting_operator", observed_at: "2026-10-13T00:03:00.000Z" }
    ])`, h.context) as string;
    expect(out.match(/<span class="trend-bar (good|warn|pending)"/g)).toHaveLength(4);
    expect(textOf(out).replace(/\s+/g, " ").trim()).toBe("2 went ahead 1 stopped 1 other");
  });
});

describe("slice 5 Evidence wired consumers", () => {
  const now = "2026-10-14T17:00:00.000Z";
  const evidencePayload = (overrides: Record<string, unknown> = {}) => ({
    origin_machine: "fixture-mac",
    // Served oldest first, as AuditLog.query returns its most recent page; the table lists it newest first.
    entries: [
      {
        timestamp: "2026-10-14T16:57:00.000Z",
        layer: "l2",
        identity_id: "sentinel-agent",
        operation: "sentinel_finding",
        result: "success",
        details: { summary: "Finding opened" },
      },
      {
        timestamp: "2026-10-14T16:58:00.000Z",
        layer: "l1",
        identity_id: "research-agent",
        operation: "egress",
        result: "failure",
        details: {
          destination: "198.51.100.23:8080",
          rule_id: "policy-v41/rule-2",
          agent_saw: "<script>alert(1)</script>",
          event_text: "<img src=x onerror=alert(1)>",
        },
      },
    ],
    total: 2,
    integrity_findings: [],
    chain_verdict: "verified",
    sealed_region: { status: "not_present" },
    ...overrides,
  });
  const bootEvidence = async (
    evidence: Record<string, unknown> = evidencePayload(),
    overrides: Record<string, (init?: RequestInit, url?: string) => unknown> = {},
    extraGlobals: Record<string, unknown> = {},
  ) => {
    const h = boot({
      "/api/posture/evidence": () => Promise.resolve(response(evidence)),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      ...overrides,
    }, extraGlobals);
    await settle();
    h.navigate("activity");
    await settle();
    return h;
  };

  it("renders every audit-chain verdict in its own words, plus failed and missing reads", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));

    const cases: Record<AuditChainVerdictStatus, { body: Record<string, unknown>; text: string }> = {
      verified: { body: evidencePayload(), text: "CHAIN VERIFIED" },
      verified_suffix_only: { body: evidencePayload({ chain_verdict: "verified_suffix_only", sealed_region: { status: "unreadable", note: "operator privilege cannot read sealed region" } }), text: "RECENT ENTRIES VERIFIED" },
      findings: { body: evidencePayload({ chain_verdict: "findings", integrity_findings: [{ kind: "entry_hash_mismatch", message: "entry mismatch" }] }), text: "INTEGRITY FINDINGS" },
      key_unavailable: { body: evidencePayload({ chain_verdict: "key_unavailable" }), text: "NOT VERIFIED" },
    };
    expect(Object.keys(cases).sort()).toEqual(unionValues("AuditChainVerdictStatus"));
    for (const status of Object.keys(cases) as AuditChainVerdictStatus[]) {
      const h = await bootEvidence(cases[status].body);
      const html = h.el.main!.innerHTML;
      expect(html, status).toContain(cases[status].text);
      if (status !== "verified") expect(html).not.toContain("CHAIN VERIFIED");
      expect(html, status).toContain("sealed region:");
      // The read's age is stated on every verdict, never as a verification time.
      expect(html, status).toContain("age of this read:");
      expect(html, status).not.toContain("last verified");
      expect(html, status).not.toContain("signer");
      expect(html, status).not.toContain("head <span");
    }
    const failed = await bootEvidence(evidencePayload(), {
      "/api/posture/evidence": () => Promise.reject(new Error("verification offline.")),
    });
    expect(failed.el.main!.innerHTML).toContain("Chain verification Unknown");
    expect(failed.el.main!.innerHTML).toContain("verification offline");
    const missing = await bootEvidence(evidencePayload(), { "/api/posture/evidence": never });
    expect(missing.el.main!.innerHTML).toContain("Chain verification Unknown");
    expect(missing.el.main!.innerHTML).not.toContain("CHAIN VERIFIED");
  });

  it("a served finding reads as INTEGRITY FINDINGS under any served verdict, and the findings line covers the whole chain", async () => {
    for (const status of ["verified", "verified_suffix_only", "key_unavailable"] as const) {
      const h = await bootEvidence(evidencePayload({ chain_verdict: status, integrity_findings: [{ kind: "entry_hash_mismatch", message: "entry mismatch" }] }));
      const html = h.el.main!.innerHTML;
      expect(html, status).toContain("INTEGRITY FINDINGS");
      expect(html, status).not.toContain("CHAIN VERIFIED");
      expect(html, status).not.toContain("RECENT ENTRIES VERIFIED");
    }
    const clean = await bootEvidence(evidencePayload());
    expect(clean.el.main!.innerHTML).toContain("integrity findings reported for the whole chain");
    expect(clean.el.main!.innerHTML).not.toContain("findings in window");
  });

  it("words every served sealed region status, over the full SealedRegionVerdict union", async () => {
    const statuses = unionStatusValues("SealedRegionVerdict");
    expect(statuses.length).toBeGreaterThan(0);
    for (const status of statuses) {
      const h = await bootEvidence(evidencePayload({ sealed_region: { status, entries_verified: 3, note: "fixture note", expected_tip: 9, highest_present: 7, sequence: 4 } }));
      const html = h.el.main!.innerHTML;
      expect(html, status).toContain("sealed region: ");
      expect(html, status).not.toContain("sealed region: Unknown");
    }
    const unknown = await bootEvidence(evidencePayload({ sealed_region: { status: "not_a_served_status" } }));
    expect(unknown.el.main!.innerHTML).toContain("sealed region: Unknown");
  });

  it("renders only served entry fields and result words, never chain verdict words as entry results", async () => {
    const h = await bootEvidence({
      ...evidencePayload(),
      entries: [
        {
          timestamp: "2026-10-14T16:58:00.000Z",
          layer: "l3",
          operation: "proof_commitment",
          identity_id: "",
          result: "success",
          details: { summary: "served field only" },
        },
      ],
      total: 1,
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("agent not named");
    expect(html).toContain("proof_commitment");
    expect(html).toContain("Success");
    const table = html.match(/<table class="overview-table evidence-table">([\s\S]*?)<\/table>/)![1]!;
    expect(table).not.toMatch(/VERIFIED|BROKEN|Verdict/);
    expect(table).toContain("<th>Result</th>");
    expect(html).not.toContain("<td><span class=\"row\">fortress</span></td>");
    expect(html).not.toContain("<th>Seq</th>");
    expect(html).not.toContain("<th>Seal</th>");
  });

  it("the Evidence subtitle names the audit log and claims neither completeness nor tamper evidence", async () => {
    const h = await bootEvidence(evidencePayload());
    const sub = h.el.main!.innerHTML.match(/<p class="eyebrow">Evidence<\/p>[\s\S]*?<p class="sub">([^<]*)<\/p>/)?.[1] ?? "";
    expect(sub).toContain("audit log");
    // Integrity is the strip's to state from the served verdict, and inbox decisions are not in this log.
    expect(sub).not.toMatch(/tamper|everything/i);
  });

  it("maps layer names to frozen tokens and sends every server filter as the route param", async () => {
    const h = await bootEvidence({
      ...evidencePayload(),
      entries: ["l1", "l2", "l3", "l4"].map((layer) => ({
        timestamp: "2026-10-14T16:58:00.000Z",
        layer,
        identity_id: "agent-" + layer,
        operation: "event-" + layer,
        result: "success",
        details: {},
      })),
      total: 4,
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("Castle Wall");
    expect(html).toContain("Sentinels");
    expect(html).toContain("Charter");
    expect(html).toContain("Heralds");
    const layers = { l1: "Castle Wall", l2: "Sentinels", l3: "Charter", l4: "Heralds" };
    const routeSource = readFileSync(new URL("../../../src/principal-policy/posture-routes.ts", import.meta.url), "utf8");
    const servedLayers = JSON.parse("[" + routeSource.match(/const validLayers = \[([^\]]+)\]/)![1] + "]");
    expect(Object.keys(layers).sort()).toEqual(servedLayers.sort());
    for (const [token, name] of Object.entries(layers)) {
      h.navigate("activity?layer=" + token);
      await settle();
      expect(h.el.main!.innerHTML).toContain('value="' + token + '" selected>' + name);
      expect(h.requests.at(-1)!.url).toContain("layer=" + token);
      const select = new FakeElement({ "data-action": "evidence-filter-layer" }, "SELECT");
      select.value = ""; h.change(select); await settle();
      select.value = token; h.change(select); await settle();
      expect(runInContext("location.hash", h.context)).toContain("layer=" + token);
      expect(h.requests.at(-1)!.url).toContain("layer=" + token);
    }
    h.input("evidence-filter-agent", "agent-alpha");
    h.input("evidence-filter-event", "egress");
    const result = new FakeElement({ "data-action": "evidence-filter-result" }, "SELECT");
    result.value = "failure"; h.change(result);
    h.input("evidence-filter-from", "2026-10-14");
    await settle();
    const request = new URL(h.requests.at(-1)!.url, "http://fixture");
    // The From date is the operator's calendar date, so it is sent as that date's local midnight.
    expect(Object.fromEntries(request.searchParams)).toEqual({ layer: "l4", agent: "agent-alpha", operation_type: "egress", result: "failure", since: new Date(2026, 9, 14).toISOString(), limit: "50" });
    h.navigate("activity"); await settle();
    expect(h.requests.at(-1)!.url).toBe("/api/posture/evidence?limit=50");
  });

  it("the top-bar time range narrows the entries read, and the later of it and the From date starts the window", async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-14T17:00:30.000Z"));
    const h = await bootEvidence(evidencePayload());
    expect(h.el.main!.innerHTML).toContain("Time range: all time");
    const range = new FakeElement({ "data-action": "time-range" }, "SELECT");
    range.value = "24h"; h.change(range);
    await settle();
    // The range start is rounded down to the minute.
    const rangeStart = "2026-10-13T17:00:00.000Z";
    expect(new URL(h.requests.at(-1)!.url, "http://fixture").searchParams.get("since")).toBe(rangeStart);
    expect(h.el.main!.innerHTML).toContain("Time range: the last 24 hours");
    h.input("evidence-filter-from", "2026-10-14");
    await settle();
    const later = new Date(Math.max(new Date(2026, 9, 14).getTime(), Date.parse(rangeStart))).toISOString();
    expect(new URL(h.requests.at(-1)!.url, "http://fixture").searchParams.get("since")).toBe(later);
    h.input("evidence-filter-from", "");
    range.value = "all"; h.change(range);
    await settle();
    expect(new URL(h.requests.at(-1)!.url, "http://fixture").searchParams.has("since")).toBe(false);
  });

  it("drops a From value that is not a real calendar date instead of sending a window that matches nothing", async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date(now));
    const h = await bootEvidence(evidencePayload());
    for (const bad of ["garbage", "2026-02-30", "2026-1-5"]) {
      h.navigate("activity?from=" + encodeURIComponent(bad));
      await settle();
      expect(new URL(h.requests.at(-1)!.url, "http://fixture").searchParams.has("since"), bad).toBe(false);
      expect(h.el.main!.innerHTML, bad).toContain("From: Any");
      expect(h.el.main!.innerHTML, bad).not.toContain("From: " + bad);
    }
  });

  it("narrows free-text search only over the loaded page and keeps total as the served window count", async () => {
    const h = await bootEvidence({
      ...evidencePayload(),
      entries: [
        { timestamp: "2026-10-14T16:57:00.000Z", layer: "l2", identity_id: "two", operation: "other_event", result: "failure", details: { summary: "hay" } },
        { timestamp: "2026-10-14T16:58:00.000Z", layer: "l1", identity_id: "one", operation: "matched_event", result: "success", details: { summary: "needle" } },
      ],
      total: 99,
    });
    const before = h.requests.length;
    h.input("evidence-filter-query", "needle");
    await settle();
    const html = h.el.main!.innerHTML;
    expect(h.requests.length).toBe(before);
    expect(html).toContain("showing 1 of 99");
    expect(html).toContain("searching the 2 entries loaded");
    expect(html).toContain("matched_event");
    expect(html).not.toContain("other_event");
    expect(html).toContain("entries in the served window before page limit and result filter");
  });

  it("renders hostile details as text and makes no per-entry seal claim when seal fields are absent", async () => {
    const h = await bootEvidence();
    const html = h.el.main!.innerHTML;
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("Per-entry seal data is not served by this read");
    expect(html).not.toContain("link ok");
    expect(html).not.toContain("authenticity verified");
    expect(html).not.toContain("broken");
  });

  it("exports JSON through api with the operator token and keeps unavailable exports disabled with reasons", async () => {
    const blobs: Blob[] = [];
    const exportedEntry = { timestamp: now, layer: "l1", operation: "egress", identity_id: "research-agent", result: "failure" };
    const servedBody = { entries: [exportedEntry], total: 1, integrity_findings: [] };
    const h = await bootEvidence(evidencePayload(), {
      "/api/audit-log": (init) => {
        expect(init?.headers).toMatchObject({ Authorization: "Bearer operator-token" });
        // Must match the served shape pinned in test/principal-policy/dashboard-audit-log-route-shape.test.ts:
        // with an audit log wired, handleAuditLog answers with the AuditLog.query result object.
        return Promise.resolve(response(servedBody));
      },
    }, {
      sessionStorage: { getItem: (key: string) => key === "authToken" ? "operator-token" : null, setItem() {} },
      URL: class extends URL { static createObjectURL(blob: Blob) { blobs.push(blob); return "blob:fixture"; } static revokeObjectURL() {} },
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-action="evidence-export-json"');
    expect(html).toContain("CEF export is available from the audit_export_siem tool");
    expect(html).toContain("Compliance bundle export is Tier 1");
    expect(html).toContain('href="#exit-drill"');
    expect(html).toContain('href="/posture/evidence"');
    h.click({ "data-action": "evidence-export-json" });
    await settle();
    expect(h.requests.some((r) => r.url.startsWith("/api/audit-log"))).toBe(true);
    expect(h.downloads).toHaveLength(1);
    expect((h.downloads[0] as unknown as { download: string }).download).toBe("sanctuary-audit-log.json");
    expect(JSON.parse(await blobs[0]!.text())).toEqual(servedBody);
    expect(h.el["toast-host"]!.innerHTML).toContain("Downloaded the latest 1 audit entry as JSON");
  });

  it("the JSON export reports a served result object with no entries as no entries, never as a downloaded log", async () => {
    const h = await bootEvidence(evidencePayload(), {
      "/api/audit-log": () => Promise.resolve(response({ entries: [], total: 0, integrity_findings: [] })),
    }, {
      sessionStorage: { getItem: (key: string) => key === "authToken" ? "operator-token" : null, setItem() {} },
      URL: class extends URL { static createObjectURL() { return "blob:fixture"; } static revokeObjectURL() {} },
    });
    h.click({ "data-action": "evidence-export-json" });
    await settle();
    expect(h.downloads).toHaveLength(0);
    expect(h.el["toast-host"]!.innerHTML).toContain("No audit entries were returned, so nothing was exported.");
    expect(h.el["toast-host"]!.innerHTML).not.toContain("export failed");
  });

  it("the JSON export names its bound and reports an empty audit log read instead of downloading a file", async () => {
    const h = await bootEvidence(evidencePayload(), {
      "/api/audit-log": () => Promise.resolve(response([])),
    }, {
      sessionStorage: { getItem: (key: string) => key === "authToken" ? "operator-token" : null, setItem() {} },
      URL: class extends URL { static createObjectURL() { return "blob:fixture"; } static revokeObjectURL() {} },
    });
    expect(h.el.main!.innerHTML).toContain("JSON: latest 50 audit entries");
    h.click({ "data-action": "evidence-export-json" });
    await settle();
    expect(h.requests.some((r) => r.url.startsWith("/api/audit-log"))).toBe(true);
    // The label's bound is the audit log route's own default limit, read from its source.
    const dashboardSource = readFileSync(new URL("../../../src/principal-policy/dashboard.ts", import.meta.url), "utf8");
    const routeDefault = dashboardSource.match(/private handleAuditLog\(url: URL[^]*?searchParams\.get\("limit"\) \?\? "(\d+)"/)![1];
    expect(h.el.main!.innerHTML).toContain("JSON: latest " + routeDefault + " audit entries");
    expect(h.downloads).toHaveLength(0);
    expect(h.el["toast-host"]!.innerHTML).toContain("No audit entries were returned, so nothing was exported.");
    expect(h.el["toast-host"]!.innerHTML).not.toContain("downloaded");
  });

  it("a result filter says it checks only the most recent page while the count covers every result", async () => {
    const h = await bootEvidence(evidencePayload({ total: 120 }));
    expect(h.el.main!.innerHTML).not.toContain("data-evidence-result-scope");
    const result = new FakeElement({ "data-action": "evidence-filter-result" }, "SELECT");
    result.value = "failure"; h.change(result);
    await settle();
    const html = h.el.main!.innerHTML;
    expect(h.requests.at(-1)!.url).toContain("result=failure");
    expect(html).toContain("showing 2 of 120");
    expect(html).toContain("The result filter checks the 50 most recent entries in the window; 120 counts entries of every result.");
  });

  it("the Evidence inbox decides only Tier 2 approvals inline and sends Tier 1 and unknown tiers to Approvals", async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date(now));
    const inboxItems = [
      { ...heldItem, item_id: "t1", tier: "tier1", created_at: "2026-10-14T16:50:00.000Z" },
      { ...heldItem, item_id: "t2", tier: "tier2", created_at: "2026-10-14T16:51:00.000Z" },
      { ...heldItem, item_id: "tx", tier: undefined, created_at: "2026-10-14T16:52:00.000Z" },
    ];
    const h = await bootEvidence(evidencePayload(), {
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: inboxItems } })),
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-action="inbox-approve" data-item-id="t2"');
    expect(html).toContain('data-action="inbox-deny" data-item-id="t2"');
    // The one-time decision reads the same as on the Overview and the Approvals screen.
    expect(html).toContain('data-action="inbox-approve" data-item-id="t2">Allow once</button>');
    expect(html).not.toContain(">Approve</button>");
    for (const id of ["t1", "tx"]) {
      expect(html).not.toContain('data-action="inbox-approve" data-item-id="' + id + '"');
      expect(html).not.toContain('data-action="inbox-deny" data-item-id="' + id + '"');
      expect(html).toContain('href="#approvals" data-evidence-review="' + id + '">Review in Approvals</a>');
    }
  });

  it("keeps the old Activity inbox, agent, Recognition and batch controls on Evidence", async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date(now));
    const inboxItems = [
      { ...heldItem, item_id: "t1", tier: "tier1", created_at: "2026-10-14T16:50:00.000Z" },
      { ...heldItem, item_id: "t2", tier: "tier2", created_at: "2026-10-14T16:51:00.000Z" },
      { item_id: "privacy-1", kind: "privacy_event", display_template_id: "privacy_event.filtered", display_template_args: { agent_id: "agent-alpha" }, resolved: false, created_at: "2026-10-14T16:52:00.000Z" },
    ];
    const h = await bootEvidence(evidencePayload(), {
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: inboxItems } })),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [{ agent_id: "agent-alpha", status: "active", capabilities: { can_pause: true, can_resume: true, can_restart: true, can_lockdown: true } }] } })),
      "/api/hub/recognition/did-web": () => Promise.resolve(response({ data: { configured: true, identifier: "did:web:example.com", days_until_recommended_rotation: 7, key_history: [] } })),
      "/api/inbox/unified/batch": (init) => {
        expect(init?.method).toBe("POST");
        return Promise.resolve(response({ ok: true }));
      },
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("This fortress");
    expect(html).toContain("Inbox");
    expect(html).toContain("Tier 1 approvals");
    expect(html).toContain("Tier 2 approvals");
    expect(html).toContain('class="inbox-group-head">Other</h4>');
    expect(html).toContain("Inbox (3 of 3)");
    expect(html).toContain("Agents (1)");
    const bar = html.match(/aria-label="Filter the inbox">([\s\S]*?)<\/div>/)![1]!;
    expect([...bar.matchAll(/field-label">([^<]+)/g)].map(m => m[1])).toEqual(["Search", "Source", "Severity", "Agent", "From", "To"]);
    expect(html).toContain('data-action="agent-lockdown"');
    expect(html).toContain("Recognition Layer health");
    runInContext(`state.inboxOps.selected = { "privacy-1": true }; rerender();`, h.context);
    const selectedHtml = h.el.main!.innerHTML;
    expect(selectedHtml).toContain('data-action="inbox-batch-archive"');
    expect(selectedHtml).toContain('data-action="inbox-batch-dismiss"');
    expect(selectedHtml).toContain('data-action="inbox-batch-snooze-open"');
    expect(selectedHtml).toContain('data-action="inbox-batch-delete"');
    h.click({ "data-action": "inbox-batch-archive" });
    await settle();
    expect(h.requests.some((r) => r.url === "/api/inbox/unified/batch")).toBe(true);
  });
  it("keeps unknown statuses unknown and bounds findings, details, contributors and raw text", async () => {
    const unknown = await bootEvidence(evidencePayload({ chain_verdict: "future_status" }));
    expect(unknown.el.main!.innerHTML).toContain("status was not recognized");
    expect(unknown.el.main!.innerHTML).not.toContain("CHAIN VERIFIED");
    const findings = Array.from({ length: 7 }, (_, i) => ({ kind: "entry_hash_mismatch", message: "finding-" + i + "<script>" + "x".repeat(300) }));
    const h = await bootEvidence(evidencePayload({ chain_verdict: "verified", integrity_findings: findings }));
    expect(h.el.main!.innerHTML).toContain("INTEGRITY FINDINGS");
    expect(h.el.main!.innerHTML).toContain("showing 5 of 7 findings");
    expect(h.el.main!.innerHTML).toContain("entry_hash_mismatch: finding-0&lt;script&gt;");
    expect(h.el.main!.innerHTML).not.toContain("finding-5");
    expect(h.el.main!.innerHTML).not.toContain("CHAIN VERIFIED");
    const bounded = await bootEvidence(evidencePayload({ entries: [{ timestamp: now, layer: "l1", operation: "large_record", result: "failure", identity_id: "a", details: { huge: "z".repeat(7000) }, contributors: [{ plugin_id: "fixture-plugin" }] }] }));
    const pane = bounded.el.main!.innerHTML.match(/<aside class="panel evidence-detail"[\s\S]*?<\/aside>/)![0];
    expect(pane).toContain("truncated at 240 chars");
    expect(pane).toContain("truncated at 6000 chars");
    expect(pane).toContain("contributors</dt>");
    expect(pane).not.toContain("z".repeat(6001));
  });

  it("lists the served page newest first and opens the newest entry in the record pane", async () => {
    const h = await bootEvidence();
    const html = h.el.main!.innerHTML;
    const table = html.match(/<table class="overview-table evidence-table">([\s\S]*?)<\/table>/)![1]!;
    expect(table.indexOf("egress")).toBeGreaterThan(-1);
    expect(table.indexOf("egress")).toBeLessThan(table.indexOf("sentinel_finding"));
    expect(html).toMatch(/<aside class="panel evidence-detail"[\s\S]*?198\.51\.100\.23:8080/);
  });

  it("selects each served record through its rendered control", async () => {
    const h = await bootEvidence();
    const controls = [...h.el.main!.innerHTML.matchAll(/data-action="evidence-select" data-evidence-index="(\d+)"/g)];
    expect(controls).toHaveLength(2);
    h.click({ "data-action": "evidence-select", "data-evidence-index": controls[1]![1]! });
    expect(h.el.main!.innerHTML).toMatch(/<aside class="panel evidence-detail"[\s\S]*?sentinel_finding/);
    expect(h.el.main!.innerHTML).toMatch(/<tr class="sel"[^>]*data-evidence-row="1"/);
  });

  it("distinguishes a server filter with no match from an empty log", async () => {
    const h = await bootEvidence(evidencePayload({ entries: [], total: 17 }));
    h.navigate("activity?result=failure"); await settle();
    expect(h.el.main!.innerHTML).toContain("No entries match this view");
    expect(h.el.main!.innerHTML).toContain("showing 0 of 17");
    const empty = await bootEvidence(evidencePayload({ entries: [], total: 0 }));
    expect(empty.el.main!.innerHTML).toContain("No audit entries in this view");
    empty.navigate("activity?agent=absent"); await settle();
    expect(empty.el.main!.innerHTML).toContain("No entries match this view");
  });

  it("reads a time range that matches nothing as a filtered view, not an empty log", async () => {
    const h = await bootEvidence(evidencePayload({ entries: [], total: 0 }));
    expect(h.el.main!.innerHTML).toContain("No audit entries in this view");
    const range = new FakeElement({ "data-action": "time-range" }, "SELECT");
    range.value = "24h"; h.change(range);
    await settle();
    expect(h.el.main!.innerHTML).toContain("No entries match this view");
    expect(h.el.main!.innerHTML).toContain("0 entries were loaded for the last 24 hours.");
    expect(h.el.main!.innerHTML).toContain("Change the time range in the top bar.");
    expect(h.el.main!.innerHTML).not.toContain('>Clear filters</a>');
    expect(h.el.main!.innerHTML).not.toContain("No audit entries in this view");
  });

  it("keeps obsolete filter responses hidden until the latest filtered read completes", async () => {
    vi.useFakeTimers();
    let release!: (value: unknown) => void;
    let filtered = false;
    const h = await bootEvidence(evidencePayload(), {
      "/api/posture/evidence": (_init, url) => {
        if (url?.includes("agent=second")) { filtered = true; return new Promise(resolve => { release = resolve; }); }
        return Promise.resolve(response(evidencePayload()));
      },
    });
    h.input("evidence-filter-agent", "second"); await settle();
    expect(filtered).toBe(true);
    expect(h.el.main!.innerHTML).toContain("Entries Unknown");
    expect(h.el.main!.innerHTML).not.toContain('aria-label="Selected entry"');
    release(response(evidencePayload({ entries: [], total: 0 }))); await settle();
    expect(h.el.main!.innerHTML).toContain("No entries match this view");
  });

  it("an older filter's response that settles after the filter changed never publishes its rows", async () => {
    vi.useFakeTimers();
    const held: Record<string, (value: unknown) => void> = {};
    const requested: string[] = [];
    const h = await bootEvidence(evidencePayload(), {
      "/api/posture/evidence": (_init, url) => {
        const agent = new URL(url!, "http://fixture").searchParams.get("agent");
        if (agent === "first" || agent === "second") { requested.push(agent); return new Promise(resolve => { held[agent] = resolve; }); }
        return Promise.resolve(response(evidencePayload()));
      },
    });
    const only = (operation: string) => evidencePayload({ entries: [{ timestamp: "2026-10-14T16:59:00.000Z", layer: "l1", identity_id: "agent-x", operation, result: "success", details: {} }], total: 1 });
    h.input("evidence-filter-agent", "first"); await settle();
    h.input("evidence-filter-agent", "second"); await settle();
    expect(requested).toEqual(["first"]);
    // The first read settles after the filter moved on: its rows must not appear under the second filter. The
    // trailing read already marks the source loading, so the screen alone cannot tell; the revision check in
    // readResponse is what keeps the stale answer out of the view state, so the test reads that state too.
    held.first!(response(only("first_filter_operation"))); await settle();
    expect(h.el.main!.innerHTML).not.toContain("first_filter_operation");
    expect(runInContext("JSON.stringify(state.evidence.view)", h.context)).not.toContain("first_filter_operation");
    expect(requested).toEqual(["first", "second"]);
    held.second!(response(only("second_filter_operation"))); await settle();
    expect(h.el.main!.innerHTML).toContain("second_filter_operation");
    expect(h.el.main!.innerHTML).not.toContain("first_filter_operation");
  });

  it("restores Inbox unknown and redacted states and the served fortress identity", async () => {
    vi.useFakeTimers();
    const h = await bootEvidence(evidencePayload(), { "/api/hub/inbox": never });
    expect(h.el.main!.innerHTML).toContain("Inbox (Unknown)");
    expect(h.el.main!.innerHTML).not.toContain("Nothing pending.");
    runInContext('config.tenantName = "Fixture tenant"; config.fortressId = "fixture-fortress"; config.identityId = "fixture-operator"; rerender();', h.context);
    expect(h.el.main!.innerHTML).toContain("fixture-operator");
    expect(h.el.main!.innerHTML).toContain("Fixture tenant");
    const redacted = await bootEvidence(evidencePayload(), { "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [], pending_approvals_redacted: true, pending_approvals_count: 3 } })) });
    expect(redacted.el.main!.innerHTML).toContain("Approvals are hidden, not empty");
  });

  it("restores all Inbox kinds and drives every batch handler from its control", async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date(now));
    const kinds = [...HUB_INBOX_KINDS];
    const items = [...kinds.map(kind => ({ ...heldItem, kind, item_id: kind, created_at: now })), { ...heldItem, item_id: "decided-1", resolved: true, resolved_at: now, created_at: now }];
    const h = await bootEvidence(evidencePayload(), {
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
      "/api/inbox/unified/batch": () => Promise.resolve(response({ ok: true })),
      "/api/hub/inbox/privacy_event/dismiss": () => Promise.resolve(response({ data: {} })),
    });
    for (const kind of kinds) expect(h.el.main!.innerHTML).toContain('data-inbox-kind="' + kind + '"');
    expect(h.el.main!.innerHTML).toContain("Decided approvals");
    const decided = h.el.main!.innerHTML.match(/data-decided-approval="decided-1"([\s\S]*?)<\/section>/)![1]!;
    expect(decided).toContain("Resolved");
    expect(decided).not.toMatch(/data-action="inbox-(approve|deny)/);
    for (const action of ["archive", "dismiss", "snooze", "delete"]) {
      expect(h.el.main!.innerHTML).toContain('data-action="inbox-select" data-item-id="privacy_event"');
      h.click({ "data-action": "inbox-select", "data-item-id": "privacy_event", checked: "true" });
      const button = "inbox-batch-" + (action === "snooze" ? "snooze-open" : action);
      expect(h.el.main!.innerHTML).toContain('data-action="' + button + '"');
      h.click({ "data-action": button });
      if (action === "snooze") {
        for (const control of ["inbox-batch-snooze", "inbox-snooze-custom", "inbox-batch-snooze-custom", "inbox-batch-snooze-close"]) expect(h.el.main!.innerHTML).toContain('data-action="' + control + '"');
        h.click({ "data-action": "inbox-batch-snooze", "data-snooze-ms": "3600000" });
      }
      await settle();
      if (action === "dismiss") expect(h.requests.some(r => r.url === "/api/hub/inbox/privacy_event/dismiss" && r.init?.method === "POST")).toBe(true);
      else expect(h.requests.some(r => r.url === "/api/inbox/unified/batch" && JSON.parse(String(r.init?.body)).action === action)).toBe(true);
    }
  });

});

describe("slice 3 Overview wired consumers", () => {
  const now = "2026-10-14T17:00:00.000Z";
  const evidence = { last_enforcement_evidence_at: "2026-10-14T16:59:20.000Z", freshness_window_ms: 10 * 60 * 1000 };
  const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model", runs_locally: false };
  const unwrapped = { origin_machine: "fixture-mac", detection_method: "config_file_presence", unwrapped: [] };
  const textOnly = (html: string) => html.replace(/<[^>]*>/g, " ").replace(/&[a-z#0-9]+;/gi, " ").replace(/\s+/g, " ").trim();
  const overviewLimit = (name: string) => {
    const match = getClientScript().match(new RegExp(`const ${name} = (\\d+);`));
    if (!match) throw new Error(`Missing ${name}`);
    return Number(match[1]);
  };
  const agent = (agent_id: string, overrides: Record<string, unknown> = {}) => ({
    version: "1.1", agent_id, identity_id: "operator-1", harness: "claude_code",
    model_provider, policy_id: "policy-v41", channel_template_id: "request-approve-act",
    status: "active", budget_summary: { daily: { unit: "usd", cap: 10, used: 4.2 }, last_refreshed_at: now },
    last_activity_at: "2026-10-14T16:58:00.000Z", wrapped_at: "2026-10-14T15:00:00.000Z",
    capabilities: { can_pause: true, can_resume: true, can_restart: true, can_unwrap: true, can_lockdown: true, can_chat: true, can_change_template: true },
    ...overrides,
  });
  const pending = (item_id: string, tier: string | undefined, agent_id: string | undefined, operation_category = "state_export") => ({
    ...heldItem,
    item_id, tier, agent_id, operation_category,
    created_at: tier === "tier1" ? "2026-10-14T16:45:00.000Z" : "2026-10-14T16:55:00.000Z",
    display_template_id: `approval_pending.${tier || "unknown"}.state_export`,
    display_template_args: [{ kind: "agent_id", value: agent_id }],
  });
  const overviewHome = (overrides: Record<string, unknown> = {}, digest: Record<string, unknown> = {}) => ({
    // A verified fixture serves both the verdict and its legacy clean flag.
    ...home({ kernel_blocks: 3, kernel_allows: 7, chain_verdict: "verified", chain_verified: true, window_start: "2026-10-14T16:00:00.000Z", window_end: "2026-10-14T17:00:00.000Z", entry_count: 1284, ...digest }),
    castle_wall: { arm_state: "armed", platform: "macOS kernel", ...evidence },
    agents: [{ agent_id: "research-agent", status: "active", harness: "claude_code", enforcement_active: "active", policy_protected: true, ...evidence }],
    unwrapped,
    protection_requested_count: 1,
    enforcement_confirmed_count: 1,
    ...overrides,
  });
  const bootOverview = async (overrides: Record<string, (init?: RequestInit) => unknown> = {}, homeBody: Record<string, unknown> = overviewHome()) => {
    const h = boot({
      "/api/posture/home": () => Promise.resolve(response(homeBody)),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [agent("research-agent")] } })),
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [] } })),
      "/api/anomaly/findings": () => Promise.resolve(response({ data: { findings: [] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [] } })),
      "/api/hub/policies": () => Promise.resolve(response({ data: { policies: [{ policy_id: "policy-v41", display_label: "Request approve act", bound_at: now, agent_count: 1, channel_template_id: "request-approve-act" }] } })),
      ...overrides,
    });
    await settle();
    return h;
  };

  it("renders the remaining source-backed tiles, the queue, findings panel and agents table from served sources", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = boot({
      "/api/posture/home": () => Promise.resolve(response({
        ...overviewHome({}, { window_end: "2026-10-14T16:59:00.000Z" }),
        castle_wall: { arm_state: "armed", platform: "macOS kernel", ...evidence },
        agents: [
          { agent_id: "research-agent", status: "active", harness: "claude_code", enforcement_active: "active", policy_protected: true, ...evidence },
          { agent_id: "doc-reviewer", status: "active", harness: "claude_code", enforcement_active: "active", policy_protected: true, ...evidence },
        ],
        unwrapped,
        protection_requested_count: 2,
        enforcement_confirmed_count: 2,
      })),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [agent("research-agent"), agent("doc-reviewer")] } })),
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [
        pending("tier1-1", "tier1", "research-agent"),
        pending("tier2-1", "tier2", "doc-reviewer"),
        { ...heldItem, item_id: "block-1", kind: "blocked_egress", agent_id: "research-agent", destination_category: "frontier_model_api", created_at: "2026-10-14T16:50:00.000Z", resolved: false },
      ] } })),
      "/api/anomaly/findings": () => Promise.resolve(response({ data: { findings: [
        { finding_id: "finding-1", severity: "medium", detector_id: "egress-volume", summary: "Unusual outbound volume", created_at: "2026-10-14T16:46:00.000Z" },
      ] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [
        { entry_id: "a1", emitted_at: "2026-10-14T16:55:00.000Z", category: "egress", agent_id: "research-agent", display_template_id: "activity.egress.allowed", display_template_args: [{ kind: "destination_category", value: "allowed_api" }] },
      ] } })),
      "/api/hub/policies": () => Promise.resolve(response({ data: { policies: [{ policy_id: "policy-v41", display_label: "Request approve act", bound_at: now, agent_count: 2, channel_template_id: "request-approve-act" }] } })),
    });
    await settle();
    const html = h.el.main!.innerHTML;
    expect(html).toContain("What needs attention now. Unknown means a source has not answered or has not proven the value.");
    expect(html).not.toContain("Each tile names the served source it reads");
    for (const label of ["Castle Wall", "Approvals waiting", "Open Sentinel findings", "Audit chain"]) {
      expect(html).toContain(label);
    }
    expect(html).toContain('class="state-chip good overview-chip"><span class="overview-chip-head"><i aria-hidden="true"></i>VERIFIED');
    expect(html).not.toContain("Protected agents");
    expect(html).not.toContain("Enforcement confirmed");
    expect(html).not.toContain('<a class="overview-tile"');
    expect(html).toContain("Needs your decision");
    expect(html).toContain('data-overview-review="tier1-1"');
    expect(html).toContain('data-action="inbox-approve" data-item-id="tier2-1"');
    expect(html).not.toContain("Egress enforcement");
    expect(html).not.toContain("frontier_model_api");
    expect(html).not.toContain("allowed_api");
    expect(html).not.toContain("last 24h");
    expect(html).toContain("Agents <span class=\"n\">showing 2 of 2");
    expect(html).toContain("Reach (allowed of requested)");
    expect(html).toContain("policy-v41");
  });

  it("keeps missing and stale Overview sources Unknown or Not evaluated, never green or zero", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const stale = { last_enforcement_evidence_at: "2026-10-14T16:00:00.000Z", freshness_window_ms: 10 * 60 * 1000 };
    const h = boot({
      "/api/posture/home": () => Promise.resolve(response({
        origin_machine: "fixture-mac",
        agents: [{ agent_id: "stale-agent", enforcement_active: "active", ...stale }],
        castle_wall: { arm_state: "armed", ...stale },
        digest: {},
        unwrapped,
        protection_requested_count: 1,
        enforcement_confirmed_count: 1,
      })),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [agent("stale-agent")] } })),
      "/api/hub/inbox": () => Promise.reject(new Error("no queue")),
      "/api/anomaly/findings": () => Promise.reject(new Error("no sentinels")),
      "/api/hub/activity": () => Promise.reject(new Error("no activity")),
    });
    await settle();
    const html = h.el.main!.innerHTML;
    expect(html).toContain("UNKNOWN");
    expect(html).toContain("Not evaluated");
    expect(html).toContain("approval queue did not answer");
    expect(html).toContain("Sentinels did not answer");
    expect(html).not.toContain("0 approvals waiting");
    expect(html).not.toContain("0 open findings");
    expect(html).not.toContain("ENFORCING");
  });

  it("renders no protection summary tiles when the unprotected harness list is not served", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({}, { ...overviewHome(), unwrapped: undefined });
    expect(h.el.main!.innerHTML).toContain("Castle Wall");
    expect(h.el.main!.innerHTML).not.toContain("Protected agents");
    expect(h.el.main!.innerHTML).not.toContain("Enforcement confirmed");
    expect(textOnly(h.el.main!.innerHTML)).not.toContain("of 1 detected");
  });

  it("keeps stale per-agent enforcement out of the agent chips", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const stale = { last_enforcement_evidence_at: "2026-10-14T15:00:00.000Z", freshness_window_ms: 10 * 60 * 1000 };
    const h = await bootOverview({}, {
      ...overviewHome({ protection_requested_count: 1, enforcement_confirmed_count: 1 }),
      agents: [{ agent_id: "research-agent", status: "active", enforcement_active: "active", ...stale }],
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("Castle Wall");
    expect(html).not.toContain("Enforcement confirmed");
    expect(html).toMatch(/data-agent-id="research-agent"[\s\S]*?<span class="state-chip unknown overview-chip"><span class="overview-chip-head"><i aria-hidden="true"><\/i>UNKNOWN<\/span>/);
    expect(html).not.toContain("server reports 1");
  });

  it("does not render requested-count fallback copy when requested count is not served", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const body = overviewHome();
    delete (body as Record<string, unknown>).protection_requested_count;
    const h = await bootOverview({}, body);
    expect(h.el.main!.innerHTML).toContain("Castle Wall");
    expect(h.el.main!.innerHTML).not.toContain("requested count not served");
    expect(h.el.main!.innerHTML).not.toContain("Enforcement confirmed");
    expect(h.el.main!.innerHTML).not.toContain("of 1 requested");
  });

  it("does not render server confirmed-count disagreement copy", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({}, overviewHome({ protection_requested_count: 0 }));
    expect(h.el.main!.innerHTML).toContain("Castle Wall");
    expect(h.el.main!.innerHTML).not.toContain("Enforcement confirmed");
    expect(h.el.main!.innerHTML).not.toContain("counts disagree");
    expect(h.el.main!.innerHTML).not.toContain("server reports");
  });

  it("Castle Wall and audit chain never go green without parseable fresh evidence", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({}, overviewHome({
      castle_wall: { arm_state: "armed", platform: "macOS kernel", last_enforcement_evidence_at: "invalid", freshness_window_ms: 10 * 60 * 1000 },
    }, { chain_verified: true, window_end: "not-a-date" }));
    const html = h.el.main!.innerHTML;
    expect(html).toContain("UNKNOWN");
    // A claimed verification with an invalid check time is explicitly Unknown.
    expect(html).toContain("last verified Unknown");
    expect(html).toContain("last check Not evaluated");
    expect(html).not.toContain('class="state-chip good overview-chip"><span class="overview-chip-head"><i aria-hidden="true"></i>VERIFIED');
  });

  it("Overview state chips cover non-green wall and chain verdicts", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const notInstalled = await bootOverview({}, overviewHome({ castle_wall: { arm_state: "not_installed", platform: "macOS kernel", ...evidence } }));
    expect(notInstalled.el.main!.innerHTML).toContain("NOT INSTALLED");
    const degraded = await bootOverview({}, overviewHome({ castle_wall: { arm_state: "degraded", platform: "macOS kernel", ...evidence } }));
    expect(degraded.el.main!.innerHTML).toContain("DEGRADED");
    const locked = await bootOverview({}, overviewHome({ castle_wall: { arm_state: "locked_down", platform: "macOS kernel", ...evidence } }));
    expect(locked.el.main!.innerHTML).toContain("LOCKED DOWN");
    const suffixOnly = await bootOverview({}, overviewHome({}, { chain_verified: false, chain_verdict: "verified_suffix_only", window_end: "2026-10-14T16:59:00.000Z" }));
    expect(suffixOnly.el.main!.innerHTML).toContain("SUFFIX ONLY");
    expect(suffixOnly.el.main!.innerHTML).toContain("digest from 1m ago, not verified");
    const keyUnavailable = await bootOverview({}, overviewHome({}, { chain_verified: false, chain_verdict: "key_unavailable", window_end: "2026-10-14T16:59:00.000Z" }));
    expect(keyUnavailable.el.main!.innerHTML).toContain("NOT YET VERIFIED");
    expect(keyUnavailable.el.main!.innerHTML).toContain("digest from 1m ago, not verified");
  });

  it("Approvals waiting is hidden rather than zero when the queue is redacted", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { pending_approvals_redacted: true, pending_approvals_count: 5 } })),
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("approval queue hidden; pending count 5");
    expect(html).toContain("Approvals hidden");
    expect(html).not.toContain('data-action="inbox-approve"');
  });

  it("Overview caps queue, findings and agent rows from the named constants", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const decisionLimit = overviewLimit("OVERVIEW_DECISION_LIMIT");
    const findingLimit = overviewLimit("OVERVIEW_FINDING_LIMIT");
    const agentLimit = overviewLimit("OVERVIEW_AGENT_LIMIT");
    const h = await bootOverview({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: Array.from({ length: agentLimit + 1 }, (_, i) => agent(`agent-${i + 1}`)) } })),
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: Array.from({ length: decisionLimit + 2 }, (_, i) => pending(`tier2-${i + 1}`, "tier2", "research-agent")) } })),
      "/api/anomaly/findings": () => Promise.resolve(response({ data: { findings: Array.from({ length: findingLimit + 1 }, (_, i) => ({
        finding_id: `finding-${i + 1}`,
        severity: "medium",
        detector_id: "egress-volume",
        summary: `Finding ${i + 1}`,
        created_at: "2026-10-14T16:46:00.000Z",
      })) } })),
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain(`showing ${decisionLimit} of ${decisionLimit + 2}`);
    expect(html).toContain(`showing ${findingLimit} of ${findingLimit + 1}`);
    expect(html).toContain(`showing ${agentLimit} of ${agentLimit + 1}`);
  });

  it("Open Sentinel findings is Not evaluated when the findings read fails", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({ "/api/anomaly/findings": () => Promise.reject(new Error("no sentinels.")) });
    expect(h.el.main!.innerHTML).toContain("Sentinels did not answer: no sentinels");
    expect(h.el.main!.innerHTML).toContain("Not evaluated");
  });

  it("Audit chain findings verdict renders FAILED with finding count", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({}, overviewHome({}, { chain_verified: false, chain_verdict: "findings", integrity_finding_count: 2 }));
    expect(h.el.main!.innerHTML).toContain("FAILED");
    // A positive window count remains displayable even though the verdict covers the whole chain.
    expect(h.el.main!.innerHTML).toContain("2 findings");
    expect(h.el.main!.innerHTML).toContain("digest from 0s ago, not verified");
  });

  it("shows the first-run empty state for a fortress with no agents instead of a wall of zeros", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = boot({
      "/api/posture/home": () => Promise.resolve(response({
        ...home({ chain_verified: true, window_start: "2026-10-14T16:00:00.000Z", window_end: now }),
        unwrapped: { origin_machine: "fixture-mac", detection_method: "config_file_presence", unwrapped: [
          { origin_machine: "fixture-mac", harness: "Claude Code", platform: "macos", config_path: "/tmp/claude.json", protected: false, detection_method: "config_file_presence" },
          { origin_machine: "fixture-mac", harness: "Codex CLI", platform: "macos", config_path: "/tmp/codex.json", protected: false, detection_method: "config_file_presence" },
        ] },
      })),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [] } })),
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [pending("wide-1", "tier1", undefined)] } })),
      "/api/anomaly/findings": () => Promise.resolve(response({ data: { findings: [{ finding_id: "finding-wide", severity: "high", detector_id: "fortress", summary: "Fortress-wide finding", created_at: "2026-10-14T16:50:00.000Z" }] } })),
    });
    await settle();
    const html = h.el.main!.innerHTML;
    expect(html).toContain("No agents protected yet");
    expect(html).toContain("2 agent harnesses detected, none protected");
    expect(html).toContain("Claude Code, Codex CLI");
    expect(html).toContain("Protect an agent");
    expect(html).toContain("Needs your decision");
    expect(html).toContain("agent not named");
    expect(html).toContain("<td><span>agent not named</span></td>");
    expect(html).not.toContain("fortress-wide");
    expect(html).toContain("Fortress-wide finding");
    expect(html).not.toContain("Protected agents");
  });

  it("first-run copy distinguishes unserved and empty unprotected-harness lists", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const firstRunHome = {
      ...home({ chain_verified: true, window_start: "2026-10-14T16:00:00.000Z", window_end: now }),
      agents: [],
      castle_wall: { arm_state: "unknown" },
      digest: {},
    };
    const unserved = await bootOverview({ "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [] } })) }, firstRunHome);
    expect(unserved.el.main!.innerHTML).toContain("Unprotected-harness list was not served");
    expect(unserved.el.main!.innerHTML).not.toContain("No harness was detected");
    const servedEmpty = await bootOverview({ "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [] } })) }, {
      ...firstRunHome,
      unwrapped,
    });
    expect(servedEmpty.el.main!.innerHTML).toContain("No harness was detected");
  });

  it("first-run still shows a redacted non-empty decision queue", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [] } })),
      "/api/hub/inbox": () => Promise.resolve(response({ data: { pending_approvals_redacted: true, pending_approvals_count: 3 } })),
    }, {
      ...home({ chain_verified: true, window_start: "2026-10-14T16:00:00.000Z", window_end: now }),
      agents: [],
      unwrapped,
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("No agents protected yet");
    expect(html).toContain("Approvals hidden");
    expect(html).toContain("Pending count: 3");
  });

  it("inline Overview decisions use the existing inbox path and Tier 1 rows link instead of deciding inline", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [agent("research-agent"), agent("doc-reviewer")] } })),
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [
        pending("tier1-1", "tier1", "research-agent"),
        pending("tier2-1", "tier2", "doc-reviewer"),
        pending("missing-tier", undefined, "doc-reviewer"),
        pending("misspelled-tier", "teir2", "doc-reviewer"),
      ] } })),
      "/api/hub/inbox/tier2-1/approve": (init) => { calls.push({ url: "/api/hub/inbox/tier2-1/approve", init }); return Promise.resolve(response({ data: { item: { ...pending("tier2-1", "tier2", "doc-reviewer"), resolved: true } } })); },
    });
    await settle();
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-overview-review="tier1-1"');
    expect(html).not.toContain('data-action="inbox-approve" data-item-id="tier1-1"');
    expect(html).not.toContain("Tier unknown");
    expect(html).not.toContain("Tier teir2");
    expect(h.el["rail-approvals-count"]!.textContent).toBe("2 of 2");
    expect(html).toMatch(/Approvals waiting<\/a><span class="ot-value">2<\/span>/);
    expect(html).not.toContain('data-overview-review="missing-tier"');
    expect(html).not.toContain('data-overview-review="misspelled-tier"');
    expect(html).not.toContain('data-action="inbox-approve" data-item-id="missing-tier"');
    expect(html).not.toContain('data-action="inbox-approve" data-item-id="misspelled-tier"');
    h.click({ "data-action": "inbox-approve", "data-item-id": "tier2-1" });
    await settle();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("/api/hub/inbox/tier2-1/approve");
  });

  it("inline Overview Deny dispatches through the same Approvals inbox path", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const calls: string[] = [];
    const h = await bootOverview({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [pending("tier2-1", "tier2", "research-agent")] } })),
      "/api/hub/inbox/tier2-1/deny": () => { calls.push("/api/hub/inbox/tier2-1/deny"); return Promise.resolve(response({ data: { item: { ...pending("tier2-1", "tier2", "research-agent"), resolved: true } } })); },
    });
    h.click({ "data-action": "inbox-deny", "data-item-id": "tier2-1" });
    await settle();
    expect(calls).toEqual(["/api/hub/inbox/tier2-1/deny"]);
  });

  it("renders no egress panel even when blocked egress inbox items are present", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [
        { ...heldItem, item_id: "block-1", kind: "blocked_egress", agent_id: "a", destination_category: "dest-one", created_at: "2026-10-14T16:10:00.000Z", resolved: false },
        { ...heldItem, item_id: "block-2", kind: "blocked_egress", agent_id: "b", destination_category: "dest-one", created_at: "2026-10-14T16:20:00.000Z", resolved: true },
        { ...heldItem, item_id: "block-3", kind: "blocked_egress", agent_id: "a", destination_category: "dest-two", created_at: "2026-10-14T16:30:00.000Z", resolved: false },
        { ...heldItem, item_id: "block-4", kind: "blocked_egress", agent_id: "a", destination_category: "dest-three", created_at: "2026-10-14T16:40:00.000Z", resolved: false },
        { ...heldItem, item_id: "block-5", kind: "blocked_egress", agent_id: "a", destination_category: "dest-four", created_at: "2026-10-14T16:50:00.000Z", resolved: false },
        { ...heldItem, item_id: "old", kind: "blocked_egress", agent_id: "a", destination_category: "old-dest", created_at: "2026-10-14T15:59:59.000Z", resolved: false },
      ] } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [{ entry_id: "allowed", emitted_at: "2026-10-14T16:20:00.000Z", category: "egress", agent_id: "a", display_template_id: "activity.egress.allowed", display_template_args: [{ kind: "destination_category", value: "allowed-api" }] }] } })),
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("Castle Wall");
    expect(html).not.toContain("Egress enforcement");
    expect(html).not.toContain("dest-one");
    expect(html).not.toContain("2 agents");
    expect(html).not.toContain("old-dest");
    expect(html).not.toContain("allowed-api");
    expect(html).not.toContain("blocked destinations");
    expect(html).not.toContain("last 24h");
  });

  it("renders no egress empty or failed states from the Overview", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const unanswered = await bootOverview({ "/api/hub/inbox": () => Promise.reject(new Error("queue down.")) });
    expect(unanswered.el.main!.innerHTML).toContain("Castle Wall");
    expect(unanswered.el.main!.innerHTML).not.toContain("blocked egress inbox did not answer");
    expect(unanswered.el.main!.innerHTML).not.toContain("Egress enforcement");
    const empty = await bootOverview();
    expect(empty.el.main!.innerHTML).toContain("Castle Wall");
    expect(empty.el.main!.innerHTML).not.toContain("No blocked destinations in this window");
    expect(empty.el.main!.innerHTML).not.toContain("Egress enforcement");
  });

  it("structurally renders no nested anchors in Overview HTML", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview();
    let open = 0;
    for (const tag of h.el.main!.innerHTML.match(/<\/?a\b[^>]*>/g) || []) {
      if (tag.startsWith("</")) open -= 1;
      else {
        expect(open).toBe(0);
        open += 1;
      }
      expect(open).toBeGreaterThanOrEqual(0);
    }
    expect(open).toBe(0);
  });

  it("agent chips use the agent's own evidence age and show paused plus absent activity honestly", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    const h = await bootOverview({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [agent("research-agent"), agent("paused-agent", { status: "paused", last_activity_at: undefined })] } })),
    }, {
      ...overviewHome({ protection_requested_count: 2, enforcement_confirmed_count: 1 }),
      agents: [
        { agent_id: "research-agent", status: "active", enforcement_active: "active", ...evidence },
        { agent_id: "paused-agent", status: "paused", enforcement_active: "active", ...evidence },
      ],
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("CONFIRMED");
    expect(html).toContain("40s ago");
    expect(html).toContain("PAUSED");
    expect(html).toContain("no activity reported");
    expect(html).not.toContain("CONFIRMED · <span>0s ago");
  });
});


describe("slice 6a Agents wired consumers", () => {
  const start = async (name = "protected", overrides: Record<string, (init?: RequestInit) => unknown> = {}, deferredHashchange = false) => {
    vi.useFakeTimers();
    const sc = agentsScenario(name);
    const h = boot({
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: sc.agents } })),
      "/api/posture/home": () => Promise.resolve(response(sc.home)),
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: sc.inbox } })),
      "/api/hub/activity": () => Promise.resolve(response({ data: { entries: sc.activity } })),
      "/api/hub/policies": () => Promise.resolve(response({ data: { policies: sc.policies } })),
      "/api/posture/reach/research-agent": () => Promise.resolve(response(sc.reach)),
      ...overrides,
    }, {}, { deferredHashchange });
    await settle();
    h.navigate("agents");
    if (deferredHashchange) await vi.advanceTimersByTimeAsync(0);
    return { h, sc };
  };
  const detail = (h: Awaited<ReturnType<typeof start>>["h"]) => h.click({ "data-action": "open-agent", "data-agent-id": "research-agent" });

  it("6a inventory reuses the Overview table and shows evidence-bearing tiles", async () => {
    const { h } = await start();
    const html = h.el.main!.innerHTML;
    expect(html).toContain('class="overview-table overview-table-agents"');
    for (const label of ["Total", "Protected of detected", "Ownerless", "At risk", "Policy template", "Reach (allowed of requested)"]) expect(html).toContain(label);
    expect(html).toContain("1 of 1");
    expect(html).toContain("Not evaluated");
    expect(html).toContain("roster read");
    const inventory = html.match(/<tbody>([\s\S]*?)<\/tbody>/)![1];
    h.navigate("posture");
    expect(h.el.main!.innerHTML).toContain(inventory);
    const protectedAgent = await start("evidenced-protected");
    const protectedTile = protectedAgent.h.el.main!.innerHTML.match(/<div class="overview-tile">(?:(?!<div class="overview-tile">)[\s\S])*?Protected of detected[\s\S]*?<\/div>/)![0];
    expect(protectedTile).toContain('<span class="ot-value">1 of 1</span>');
    detail(protectedAgent.h); await settle();
    for (const region of [
      protectedAgent.h.el.main!.innerHTML.match(/<header class="agent-entity-header">([\s\S]*?)<\/header>/)![1]!,
      protectedAgent.h.el.main!.innerHTML.match(/<section class="card" aria-label="Standing">([\s\S]*?)<\/section>/)![1]!,
    ]) {
      expect(region).toContain('state-chip good');
      expect(region).toContain("CONFIRMED");
    }
  });

  it("6a inventory filters, sorts and pages the shared table with a bounded page", async () => {
    const sc = agentsScenario();
    const agents = Array.from({ length: 53 }, (_, i) => ({ ...sc.agents[0]!, agent_id: `agent-${String(i).padStart(2, "0")}`, harness: i % 2 ? "hermes" : "claude_code", status: i % 2 ? "paused" : "active" }));
    const { h } = await start("protected", { "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })) });
    expect(h.el.main!.innerHTML).toContain("showing 25 of 53");
    h.click({ "data-action": "agents-page", "data-page": "1" });
    expect(h.el.main!.innerHTML).toContain("agent-25");
    expect(h.el.main!.innerHTML).not.toContain('data-agent-id="agent-00"');
    const change = (action: string, value: string) => { const el = new FakeElement({ "data-action": action }, "SELECT"); el.value = value; h.change(el); };
    change("agents-harness", "hermes");
    change("agents-state", "paused");
    expect(h.el.main!.innerHTML).toContain("showing 25 of 26");
    change("agents-sort", "name-desc");
    const rows = h.el.main!.innerHTML;
    expect(rows.indexOf('data-agent-id="agent-51"')).toBeLessThan(rows.indexOf('data-agent-id="agent-49"'));
    expect(rows).not.toContain('data-agent-id="agent-00"');
  });

  it("6a missing sources keep all inventory counts Unknown and stale protection is never green", async () => {
    const { h } = await start("unknown");
    expect(h.el.main!.innerHTML).toContain("Protected of detected");
    expect(h.el.main!.innerHTML).not.toContain('state-chip good');
    detail(h);
    expect(h.el.main!.innerHTML).toContain('aria-label="Standing"');
    const unknownHeader = h.el.main!.innerHTML.match(/<header class="agent-entity-header">([\s\S]*?)<\/header>/)![1]!;
    const unknownStanding = h.el.main!.innerHTML.match(/<section class="card" aria-label="Standing">([\s\S]*?)<\/section>/)![1]!;
    for (const region of [unknownHeader, unknownStanding]) {
      expect(region).toContain("UNKNOWN");
      expect(region).not.toContain('state-chip good');
    }
    runInContext('state.posture.home.agents[0].policy_protected = false; rerender()', h.context);
    expect(h.el.main!.innerHTML).toContain("No · roster intent; posture read");
    runInContext('state.posture.home.agents = []; rerender()', h.context);
    expect(h.el.main!.innerHTML).toContain("Unknown · no agent policy evidence served");
    const missing = await start("unknown", { "/api/hub/agents": () => Promise.reject(new Error("offline")) });
    expect(missing.h.el.main!.innerHTML).toContain("Total");
    expect(missing.h.el.main!.innerHTML).not.toContain("0 of 0");
    const sc = agentsScenario();
    const evidence = { ...sc.home.agents![0]!, enforcement_active: "active", last_enforcement_evidence_at: new Date().toISOString(), freshness_window_ms: 1000 };
    const fresh = await start("protected", { "/api/posture/home": () => Promise.resolve(response({ ...sc.home, agents: [evidence] })) });
    detail(fresh.h); await settle();
    expect(fresh.h.el.main!.innerHTML).toContain('state-chip good');
    // A one-second fixture window plus one millisecond proves autonomous header/Standing expiry.
    await vi.advanceTimersByTimeAsync(1001);
    expect(fresh.h.el.main!.innerHTML).not.toContain('state-chip good');
    expect(fresh.h.el.main!.innerHTML).toContain("UNKNOWN");
  });

  it("6a empty fortress has one first-run action and no inventory wall of zeros", async () => {
    const { h } = await start("empty");
    expect(h.el.main!.innerHTML).toContain('data-agents-first-run');
    expect(h.el.main!.innerHTML).toContain("sanctuary protect");
    expect(h.el.main!.innerHTML.match(/class="btn"/g)).toHaveLength(1);
    expect(h.el.main!.innerHTML).not.toContain('class="overview-tiles"');
  });

  it("6a entity header shares every lifecycle label and keeps unsupported controls disabled", async () => {
    const { h } = await start(); detail(h);
    const html = h.el.main!.innerHTML;
    expect(html).toContain('aria-label="Breadcrumb"');
    expect(html).toContain('aria-label="Agent sections"');
    expect(html).toContain("Lock down this agent");
    expect(html).toContain("Rotate identity");
    expect(html).toContain("Tier 1");
    expect(html).toMatch(/data-action="agent-unwrap"[^>]*disabled[^>]*>Remove protection/);
    expect(html).toMatch(/data-action="agent-pause"[^>]*disabled/);
    for (const action of ["pause", "resume", "restart", "lockdown", "unwrap"]) {
      const label = runInContext(`agentControlLabel("${action}")`, h.context) as string;
      expect(html).toContain(label);
      expect(runInContext("renderFortressAgentsCard()", h.context)).toContain(label);
    }
  });

  for (const [tab, text] of [["overview", "Standing"], ["approvals", "This agent's approvals"], ["activity", "Recent activity"], ["policy", "Effective reach"], ["identity", "Fingerprint"], ["memory", "Memory inventory unavailable"], ["evidence", "Agent evidence"]]) {
    it(`6a ${tab} tab consumes its served source or states the specific gap`, async () => {
      const { h } = await start("pending-tier1"); detail(h);
      h.click({ "data-action": "agent-tab", "data-tab": tab! });
      await settle();
      const html = h.el.main!.innerHTML;
      expect(html).toContain(`data-agent-tab="${tab}"`);
      expect(html).toContain(text);
      if (tab === "policy") {
        for (const lane of ["May reach", "Asks you first", "Never"]) expect(html).toContain(lane);
        expect(html).toContain("Research policy");
        expect(html).toContain("version Unknown");
      }
      // Custody has no served evidence, matching the other unknown identity fields.
      if (tab === "identity") expect(html).toContain("Unknown · custody evidence not served");
      if (tab === "activity" || tab === "evidence") {
        // Denial categories do not identify which layer made the decision.
        expect(html).toContain("Layer not served");
        expect(html).toContain('state-chip bad');
        expect(html).toContain("entry-1");
        expect(html).toContain("showing 1 of 1");
      }
    });
  }

  it("6a agent approvals and inspect allow only Tier 2 inline and use the existing decision path", async () => {
    const sc = agentsScenario("pending-tier1");
    const items = [sc.approval, { ...sc.approval, item_id: "missing", tier: undefined }, { ...sc.approval, item_id: "tier2", tier: "tier2" }];
    const calls: string[] = [];
    const { h } = await start("pending-tier1", {
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
      "/api/hub/inbox/tier2/approve": () => { calls.push("approve"); return Promise.resolve(response({ data: {} })); },
      "/api/hub/inbox/tier2/deny": () => { calls.push("deny"); return Promise.resolve(response({ data: {} })); },
    });
    (h.context as Record<string, unknown>).__items = items;
    runInContext('state.chat.inspect.panelByAgentId["research-agent"] = { pending_approvals: __items, recent_activity: [], opened_at: new Date().toISOString() }', h.context);
    detail(h); h.click({ "data-action": "agent-tab", "data-tab": "approvals" });
    const inspect = runInContext("renderAgentInspectPanel(state.agents[0])", h.context) as string;
    runInContext('delete state.chat.inspect.panelByAgentId["research-agent"]', h.context);
    const inspectCta = runInContext("renderAgentInspectPanel(state.agents[0])", h.context) as string;
    expect(inspectCta).toContain("pending approvals");
    expect(inspectCta).not.toContain("pending Tier 1 approvals");
    for (const html of [h.el.main!.innerHTML, inspect]) {
      for (const id of ["held-agent", "missing"]) expect(html).not.toMatch(new RegExp(`data-action="inbox-(approve|deny)" data-item-id="${id}"`));
      expect(html.match(/href="#approvals">Review in Approvals/g)).toHaveLength(2);
      expect(html).toContain('data-action="inbox-approve" data-item-id="tier2">Allow once');
      expect(html).toContain('data-action="inbox-deny" data-item-id="tier2">Deny');
    }
    for (const action of ["approve", "deny"]) { h.click({ "data-action": `inbox-${action}`, "data-item-id": "tier2" }); await settle(); }
    expect(calls).toEqual(["approve", "deny"]);
  });

  it("6a controls preserve frozen routes and Tier 1 remains pending until Approvals", async () => {
    const sc = agentsScenario();
    const calls: string[] = [];
    const routes: Record<string, () => unknown> = {};
    for (const action of ["pause", "resume", "restart", "lockdown", "unwrap"]) routes[`/api/hub/agents/research-agent/${action}`] = () => { calls.push(action); return Promise.resolve(response({ data: { status: action === "lockdown" || action === "unwrap" ? "approval_pending" : "active" } })); };
    const all = { ...sc.agents[0]!, capabilities: Object.fromEntries(Object.keys(sc.agents[0]!.capabilities).map(k => [k, true])) };
    const { h } = await start("protected", { ...routes, "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [all] } })) });
    detail(h);
    expect(h.el.main!.innerHTML).toContain('class="agent-entity-actions"');
    for (const action of ["pause", "resume", "restart", "lockdown", "unwrap"]) { h.clickRenderedButton(`agent-${action}`); await settle(); }
    expect(calls).toEqual(["pause", "resume", "restart", "lockdown", "unwrap"]);
    expect(h.el["toast-host"]!.textContent).toContain("Approval pending");
  });

  for (const status of [422, 500]) it(`6a ${status} control failure toast uses only the operator label`, async () => {
    const { h } = await start("protected", {
      "/api/hub/agents/research-agent/unwrap": () => Promise.resolve(response({ ok: false, error: "HubCapabilityError", detail: "capability not supported: agent_control_unwrap_unsupported_operator_decision_pending" }, status)),
    });
    h.click({ "data-action": "agent-unwrap", "data-agent-id": "research-agent" }); await settle();
    const toast = h.el["toast-host"]!.textContent;
    expect(toast).toContain("Remove protection");
    expect(toast).not.toMatch(/wrap|HubCapabilityError|capability not supported/i);
  });

  it("6a hostile labels stay text and identity never enumerates secret fields", async () => {
    const sc = agentsScenario();
    const hostile = '<img src=x onerror="hostile()">';
    const agent = { ...sc.agents[0]!, agent_id: hostile, private_key: "SECRET-MATERIAL", fingerprint: "SECRET-FINGERPRINT" };
    const { h } = await start("protected", { "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [agent] } })) });
    h.click({ "data-action": "open-agent", "data-agent-id": hostile });
    h.click({ "data-action": "agent-tab", "data-tab": "identity" });
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-agent-tab="identity"');
    expect(html).toContain("&lt;img");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("SECRET-");
    expect(html).not.toContain("private_key");
  });
  it("6a reach retains one bounded projection and rejects oversized destination input", async () => {
    const sc = agentsScenario();
    let payload = { ...sc.reach, unrelated: "DO-NOT-RETAIN" };
    const { h } = await start("protected", { "/api/posture/reach/research-agent": () => Promise.resolve(response(payload)) });
    detail(h); await settle();
    expect(runInContext("JSON.stringify(state.agentReach)", h.context)).not.toContain("DO-NOT-RETAIN");
    // 257 exceeds the 256 configured-destination budget for one detail read.
    payload = { ...payload, destinations: Array.from({ length: 257 }, () => sc.reach.destinations[0]!) };
    h.click({ "data-action": "agent-reach-refresh", "data-agent-id": "research-agent" }); await settle();
    // Failed reads name the read failure instead of borrowing unread copy.
    expect(h.el.main!.innerHTML).toContain("Reach read failed");
    expect(runInContext("state.agentReach.data", h.context)).toBeNull();
    // 2049 exceeds the 2048-character destination/rule budget.
    payload = { ...payload, destinations: [{ ...sc.reach.destinations[0]!, destination: "x".repeat(2049) }] };
    h.click({ "data-action": "agent-reach-refresh", "data-agent-id": "research-agent" }); await settle();
    expect(runInContext("state.agentReach.data", h.context)).toBeNull();
    // More than two MiB must be rejected even when the destination list itself is small.
    payload = { ...payload, destinations: sc.reach.destinations, unrelated: "x".repeat(2 * 1024 * 1024 + 1) };
    h.click({ "data-action": "agent-reach-refresh", "data-agent-id": "research-agent" }); await settle();
    expect(runInContext("state.agentReach.data", h.context)).toBeNull();
  });

  it("6a reach admission stays bounded through timeout waves and ignores late completion", async () => {
    const sc = agentsScenario();
    let finish!: (value: unknown) => void;
    let calls = 0;
    const { h } = await start("protected", { "/api/posture/reach/research-agent": () => { calls++; return new Promise(resolve => { finish = resolve; }); } });
    detail(h); await settle();
    // Three waves of twenty clicks cross the five-second deadline with fetch ignoring abort.
    for (let wave = 0; wave < 3; wave++) {
      await vi.advanceTimersByTimeAsync(5001);
      for (let click = 0; click < 20; click++) h.click({ "data-action": "agent-reach-refresh", "data-agent-id": "research-agent" });
      await settle();
    }
    expect(calls).toBe(1);
    finish(response(sc.reach)); await settle();
    expect(runInContext("state.agentReach.data", h.context)).toBeNull();
    h.click({ "data-action": "agent-reach-refresh", "data-agent-id": "research-agent" }); await settle();
    expect(calls).toBe(2);
    finish(response(sc.reach)); await settle();
    expect(h.el.main!.innerHTML).toContain("docs.example.test");
  });

  it("6a reach expires without interaction and does not retain old policy destinations", async () => {
    const { h } = await start(); detail(h); await settle();
    expect(h.el.main!.innerHTML).toContain("docs.example.test");
    // One minute plus one millisecond crosses the configured-read freshness window.
    await vi.advanceTimersByTimeAsync(60 * 1000 + 1);
    // Expiry records that a previous read aged out, not that it failed.
    expect(h.el.main!.innerHTML).toContain("Reach read expired after one minute without interaction.");
    expect(h.el.main!.innerHTML).not.toContain("docs.example.test");
    expect(runInContext("state.agentReach.data", h.context)).toBeNull();
  });

  it("6a failed detail sources clear prior reach and label each unavailable source", async () => {
    let failed = false;
    const sc = agentsScenario();
    const { h } = await start("protected", {
      "/api/posture/reach/research-agent": () => Promise.resolve(response(failed ? { error: "offline" } : sc.reach, failed ? 503 : 200)),
      "/api/hub/inbox": () => Promise.reject(new Error("offline")),
      "/api/hub/activity": () => Promise.reject(new Error("offline")),
      "/api/hub/policies": () => Promise.reject(new Error("offline")),
      "/api/posture/home": () => Promise.reject(new Error("offline")),
    });
    detail(h); await settle();
    expect(h.el.main!.innerHTML).toContain("docs.example.test");
    failed = true;
    h.click({ "data-action": "agent-reach-refresh", "data-agent-id": "research-agent" }); await settle();
    const html = h.el.main!.innerHTML;
    // Failed reach and absent independent sources retain their distinct labels.
    for (const label of ["Reach read failed", "Approvals Unknown", "Activity Unknown", "Policy summary Unknown", "UNKNOWN"]) expect(html).toContain(label);
    expect(html).not.toContain("docs.example.test");
    expect(html).not.toContain('state-chip good');
    expect(html).toContain("Reach read failed");
  });

  it("6a reach reads configured destinations, caps each lane, escapes names and rejects a different subject", async () => {
    const sc = agentsScenario();
    const hostile = '<img src=x onerror="tool()">';
    const reach = { ...sc.reach, destinations: Array.from({ length: 55 }, (_, i) => ({ destination: hostile + i, disposition: "allow", enforcing_layer: "castle_wall", rule_id: `r${i}` })) };
    const { h } = await start("protected", { "/api/posture/reach/research-agent": () => Promise.resolve(response(reach)) });
    detail(h); await settle(); h.click({ "data-action": "agent-tab", "data-tab": "policy" });
    expect(h.el.main!.innerHTML).toContain("&lt;img");
    expect(h.el.main!.innerHTML).not.toContain("<img");
    expect(h.el.main!.innerHTML).toContain("showing 20 of 55");
    expect(h.el.main!.innerHTML).toContain("Configured; enforcement not confirmed");
    expect(h.el.main!.innerHTML).toContain("requested hosts Unknown");
    expect(h.el.main!.innerHTML).not.toContain('state-chip good');
    reach.agent_id = "other-agent";
    h.click({ "data-action": "agent-reach-refresh", "data-agent-id": "research-agent" }); await settle();
    // Failed reads name the read failure instead of borrowing unread copy.
    expect(h.el.main!.innerHTML).toContain("Reach read failed");
    expect(h.el.main!.innerHTML).not.toContain("&lt;img");
  });

  it("6a a second agent opened while a reach read holds admission waits as loading, then reads once admission frees", async () => {
    const sc = agentsScenario();
    const second = { ...sc.agents[0]!, agent_id: "second-agent" };
    let finishFirst!: (value: unknown) => void;
    const calls: string[] = [];
    const { h } = await start("protected", {
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [sc.agents[0]!, second] } })),
      "/api/posture/reach/research-agent": () => { calls.push("research-agent"); return new Promise(resolve => { finishFirst = resolve; }); },
      "/api/posture/reach/second-agent": () => { calls.push("second-agent"); return Promise.resolve(response({ ...sc.reach, agent_id: "second-agent" })); },
    });
    detail(h); await settle();
    h.click({ "data-action": "open-agent", "data-agent-id": "second-agent" }); await settle();
    expect(calls).toEqual(["research-agent"]);
    expect(h.el.main!.innerHTML).not.toContain("Reach read failed");
    finishFirst(response(sc.reach)); await settle();
    expect(calls).toEqual(["research-agent", "second-agent"]);
    expect(h.el.main!.innerHTML).toContain("docs.example.test");
    expect(h.el.main!.innerHTML).not.toContain("Reach read failed");
  });

  it("6a an approval-category entry is recorded, never marked approved, since that category also holds denied decisions", async () => {
    const sc = agentsScenario();
    const entry = { ...sc.activity[0]!, entry_id: "entry-approval", category: "approval" };
    const { h } = await start("protected", { "/api/hub/activity": () => Promise.resolve(response({ data: { entries: [entry] } })) });
    detail(h); await settle();
    h.click({ "data-action": "agent-tab", "data-tab": "activity" });
    const html = h.el.main!.innerHTML;
    expect(html).toContain("Entry entry-approval");
    expect(html).toContain("RECORDED");
    expect(html).not.toContain("APPROVED");
    entry.category = "egress";
    await runInContext("fetchAll()", h.context); await settle();
    expect(h.el.main!.innerHTML).toContain("Layer not served");
    expect(h.el.main!.innerHTML).not.toContain("Castle Wall");
  });

  const reachSentences = {
    state_UNREAD: "Reach not read yet.",
    state_LOADING: "Reading this agent's reach.",
    state_EXPIRED: "Reach read expired after one minute without interaction.",
    state_FAILED: "Reach read failed",
    state_LOADED: "The reach source answered without a record for this agent.",
  };
  for (const [readState, sentence] of Object.entries(reachSentences)) {
    it(`6a r2 ${readState} names only its own reach state`, async () => {
      const { h } = await start();
      runInContext(`state.selectedAgentId = "research-agent"; state.agentReach = { state: "${readState}", agentId: "research-agent", data: null, readAt: Date.now() };`, h.context);
      h.navigate("agent-detail");
      const html = h.el.main!.innerHTML.match(/<section class="card" aria-label="Effective reach">([\s\S]*?)<\/section>/)![1]!;
      // The production escape helper encodes the apostrophe in loading copy.
      expect(html).toContain(escapeHtml(sentence).replaceAll("'", "&#039;"));
      for (const other of Object.values(reachSentences).filter(value => value !== sentence)) expect(html).not.toContain(escapeHtml(other).replaceAll("'", "&#039;"));
      expect(html).not.toContain("The agent reach source has not answered");
      if (["state_UNREAD", "state_EXPIRED"].includes(readState)) expect(html).toContain('data-action="agent-reach-refresh"');
    });
  }

  it("6a r2 a loaded reach read past its one-minute age reads expired", async () => {
    const { h } = await start();
    // Two one-minute reach windows make this read two minutes old without firing the expiry timer.
    runInContext('state.selectedAgentId = "research-agent"; state.agentReach = { state: "state_LOADED", agentId: "research-agent", data: { enforcement_confirmed: false, has_wall_policy: true, destinations: [] }, readAt: Date.now() - 2 * AGENT_REACH_MAX_AGE_MS };', h.context);
    h.navigate("agent-detail");
    const html = h.el.main!.innerHTML.match(/<section class="card" aria-label="Effective reach">([\s\S]*?)<\/section>/)![1]!;
    expect(html).toContain("Reach read expired after one minute without interaction.");
    expect(html).not.toContain("The reach source answered without a record for this agent.");
    expect(html).not.toContain('class="agent-reach-lane"');
    expect(html).not.toContain("Enforcement confirmed");
  });

  for (const [name, setup, sentence] of [
    ["stopped", "liveUpdatesStopped = true", "Live updates stopped. Retry to resume."],
    // Five one-minute reach windows date the read five minutes ahead without moving the test clock.
    ["future", "state.agentReach.readAt += 5 * AGENT_REACH_MAX_AGE_MS", "Reach read time is ahead of this device's clock, so it is not current."],
  ]) it(`A1 ${name} reach read names its reason and hides lanes`, async () => {
    const { h } = await start("evidenced-protected");
    detail(h); await settle();
    // The page's stopped-source gate hides the whole detail view, so inspect its reach card with the loaded subject.
    const html = runInContext(setup + '; renderAgentReach(state.agents.find(a => a.agent_id === "research-agent"))', h.context) as string;
    expect(html).toContain(escapeHtml(sentence!).replaceAll("'", "&#039;"));
    expect(html).not.toContain("Reach read expired after one minute without interaction.");
    expect(html).not.toContain('class="agent-reach-lane"');
    expect(html).not.toContain("docs.example.test");
    expect(html).not.toContain("Enforcement confirmed");
  });

  // Numeric text and a symbol are not numbers, so neither may be compared or dated as one.
  for (const [name, readAt] of [["missing", "undefined"], ["not-a-number", "NaN"], ["text", '"soon"'], ["numeric-text", '"9999999999999999"'], ["symbol", 'Symbol("t")']]) it(`A1 a loaded reach read with a ${name} read time is withheld as undated`, async () => {
    const { h } = await start("evidenced-protected");
    detail(h); await settle();
    // Every case fails at the round 1 head 46a1dd4a, before the undated arm in renderAgentReach (A1 round 2 fail-before
    // evidence); the symbol case also fails at f894e599, before the numeric read time in the A1 closure.
    const html = runInContext(`state.agentReach.readAt = ${readAt}; renderAgentReach(state.agents.find(a => a.agent_id === "research-agent"))`, h.context) as string;
    expect(html).toContain("Reach read time is unknown, so it is not current.");
    expect(html).not.toContain("The reach source answered without a record for this agent.");
    expect(html).not.toContain("Reach read expired after one minute without interaction.");
    expect(html).not.toContain('class="agent-reach-lane"');
    expect(html).not.toContain("docs.example.test");
    expect(html).not.toContain("Enforcement confirmed");
  });

  it("A1 a loaded reach read dated past the clock's range reads ahead of this device's clock", async () => {
    const { h } = await start("evidenced-protected");
    detail(h); await settle();
    // Fails before the read age is computed once in renderAgentReach (A1 round 2 fail-before evidence).
    // 8.64e15 ms is the largest time a Date can hold, so one more millisecond has no ISO form.
    const html = runInContext('state.agentReach.readAt = 8.64e15 + 1; renderAgentReach(state.agents.find(a => a.agent_id === "research-agent"))', h.context) as string;
    expect(html).toContain(escapeHtml("Reach read time is ahead of this device's clock, so it is not current.").replaceAll("'", "&#039;"));
    expect(html).not.toContain('class="agent-reach-lane"');
    expect(html).not.toContain("docs.example.test");
    expect(html).not.toContain("Enforcement confirmed");
  });

  it("A1 a loaded reach read with no record and a symbol read time renders the no-record sentence", async () => {
    const { h } = await start("evidenced-protected");
    detail(h); await settle();
    // Fails before the numeric read time in renderAgentReach (A1 closure fail-before evidence).
    const html = runInContext('state.agentReach.data = null; state.agentReach.readAt = Symbol("t"); renderAgentReach(state.agents.find(a => a.agent_id === "research-agent"))', h.context) as string;
    expect(html).toContain("The reach source answered without a record for this agent.");
    expect(html).not.toContain("docs.example.test");
    expect(html).not.toContain("Enforcement confirmed");
  });

  it("A1 a loaded reach read exactly one minute old reads expired and one millisecond younger stays current", async () => {
    const { h } = await start("evidenced-protected");
    detail(h); await settle();
    // fail-before-exempt: pins the existing one-minute boundary; a planted change from >= to > in renderAgentReach turns it red.
    // start() runs under fake timers, so the clock does not move between setting each read time and rendering it.
    const render = (age: string) => runInContext(`state.agentReach.readAt = Date.now() - (${age}); renderAgentReach(state.agents.find(a => a.agent_id === "research-agent"))`, h.context) as string;
    const atLimit = render("AGENT_REACH_MAX_AGE_MS");
    expect(atLimit).toContain("Reach read expired after one minute without interaction.");
    expect(atLimit).not.toContain('class="agent-reach-lane"');
    expect(atLimit).not.toContain("docs.example.test");
    const justYounger = render("AGENT_REACH_MAX_AGE_MS - 1");
    expect(justYounger).not.toContain("Reach read expired after one minute without interaction.");
    expect(justYounger).toContain('class="agent-reach-lane"');
    expect(justYounger).toContain("docs.example.test");
  });

  for (const key of ["Enter", " "]) it(`A1 row inspect ${JSON.stringify(key)} resets the tab and reads reach once`, async () => {
    const { h } = await start();
    runInContext('state.agentTab = "evidence"', h.context);
    const prevented = h.keydown({ "data-action": "agent-row-inspect-open", "data-agent-id": "research-agent" }, key);
    await settle();
    expect(prevented).toHaveBeenCalledOnce();
    expect(runInContext("state.agentTab", h.context)).toBe("overview");
    expect(runInContext("state.selectedAgentId", h.context)).toBe("research-agent");
    expect(runInContext("state.route", h.context)).toBe("agent-detail");
    expect(h.requests.filter(r => r.url === "/api/posture/reach/research-agent")).toHaveLength(1);
    expect(h.requests.filter(r => r.url === "/api/hub/agents/research-agent/inspect/open")).toHaveLength(1);
  });

  it("6a r2 unknown hash state selects All states and keeps the roster", async () => {
    const { h } = await start();
    h.navigate("agents?state=nope");
    expect(h.el.main!.innerHTML).toContain('<option value="" selected>All states</option>');
    expect(h.el.main!.innerHTML).toContain("showing 1 of 1");
    expect(h.el.main!.innerHTML).toContain('data-agent-id="research-agent"');
  });

  it("6a r2 leaving detail clears the pending reach subject before admission frees", async () => {
    const sc = agentsScenario();
    let finish!: (value: unknown) => void;
    const calls: string[] = [];
    const { h } = await start("protected", {
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [sc.agents[0], { ...sc.agents[0], agent_id: "second-agent" }] } })),
      "/api/posture/reach/research-agent": () => { calls.push("research-agent"); return new Promise(resolve => { finish = resolve; }); },
      "/api/posture/reach/second-agent": () => { calls.push("second-agent"); return Promise.resolve(response({ ...sc.reach, agent_id: "second-agent" })); },
    });
    detail(h); await settle();
    h.click({ "data-action": "open-agent", "data-agent-id": "second-agent" }); await settle();
    h.navigate("overview");
    finish(response(sc.reach)); await settle();
    expect(calls).toEqual(["research-agent"]);
    expect(runInContext("agentReachPendingId", h.context)).toBeNull();
  });

  // fail-before-exempt: existing queue behavior; plants remove open-agent loadAgentReach or restore route-guard-back.
  it("6a r2 an agent opened from another route while a read holds admission is read next", async () => {
    const sc = agentsScenario();
    let finish!: (value: unknown) => void;
    const calls: string[] = [];
    const { h } = await start("protected", {
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [sc.agents[0], { ...sc.agents[0], agent_id: "second-agent" }] } })),
      "/api/posture/reach/research-agent": () => { calls.push("research-agent"); return new Promise(resolve => { finish = resolve; }); },
      "/api/posture/reach/second-agent": () => { calls.push("second-agent"); return Promise.resolve(response({ ...sc.reach, agent_id: "second-agent" })); },
    }, true);
    // Establish the first read through row inspection so the open-agent plant targets only the second open.
    h.click({ "data-action": "agent-row-inspect-open", "data-agent-id": "research-agent" }); await settle();
    await vi.advanceTimersByTimeAsync(0);
    h.navigate("agents");
    await vi.advanceTimersByTimeAsync(0);
    expect(runInContext("state.route", h.context)).toBe("agents");
    h.click({ "data-action": "open-agent", "data-agent-id": "second-agent" });
    // Keep hashchange queued while the previous transport releases admission in its microtasks.
    expect(runInContext("state.route", h.context)).toBe("agents");
    finish(response(sc.reach)); await settle();
    expect(calls).toEqual(["research-agent", "second-agent"]);
    await vi.advanceTimersByTimeAsync(0);
    expect(runInContext("state.route", h.context)).toBe("agent-detail");
    const html = h.el.main!.innerHTML.match(/<section class="card" aria-label="Effective reach">([\s\S]*?)<\/section>/)![1]!;
    expect(html).not.toContain(escapeHtml("Reading this agent's reach.").replaceAll("'", "&#039;"));
    expect(html).toContain('<div class="mono">docs.example.test');
  });

  it("6a r2 leaving detail with a queued subject returns its placeholder to unread", async () => {
    const sc = agentsScenario();
    let finish!: (value: unknown) => void;
    const { h } = await start("protected", {
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: [sc.agents[0], { ...sc.agents[0], agent_id: "second-agent" }] } })),
      "/api/posture/reach/research-agent": () => new Promise(resolve => { finish = resolve; }),
    });
    detail(h); await settle();
    h.click({ "data-action": "open-agent", "data-agent-id": "second-agent" }); await settle();
    h.navigate("overview");
    finish(response(sc.reach)); await settle();
    h.navigate("agent-detail"); await settle();
    const html = h.el.main!.innerHTML.match(/<section class="card" aria-label="Effective reach">([\s\S]*?)<\/section>/)![1]!;
    expect(html).toContain("Reach not read yet.");
    expect(html).not.toContain(escapeHtml("Reading this agent's reach.").replaceAll("'", "&#039;"));
  });
});

// These scenarios are also imported by the untracked lane capture script.
import { overviewScenarios, OVERVIEW_FRESHNESS_MS } from "./fixtures/overview-scenarios.js";
async function bootOverview3b(change?: (home: Record<string, any>) => void, scenario = "healthy") {
  vi.useFakeTimers();
  const scenarios = await overviewScenarios(Date.now());
  const sc = scenarios.find(row => row.name === scenario)!;
  change?.(sc.home);
  const wall = sc.home.castle_wall;
  // The same served wall evidence feeds the top bar, including adversarial expiry cases.
  const live = { ...sc.sovereignty.live_enforcement, castle_wall_arm_state: wall.arm_state,
    evidence_basis: wall.evidence_basis, last_enforcement_evidence_at: wall.last_enforcement_evidence_at,
    freshness_window_ms: wall.freshness_window_ms };
  let homeReads = 0;
  const h = boot({
    "/api/posture/home": () => { homeReads++; return Promise.resolve(response(sc.home)); },
    "/api/sovereignty": () => Promise.resolve(response({ live_enforcement: live })),
    "/api/hub/agents": () => Promise.resolve(response({ data: { agents: sc.agents } })),
  });
  await settle(); return Object.assign(h, { homeReads: () => homeReads });
}
function outboundHtml(h: ReturnType<typeof boot>) {
  return h.el.main!.innerHTML.match(/<section class="card outbound-card">[\s\S]*?<\/section>/)?.[0] ?? "";
}
function auditTile(h: ReturnType<typeof boot>) {
  return h.el.main!.innerHTML.match(/<div class="overview-tile"><a[^>]*>Audit chain<\/a>[\s\S]*?<\/div>/)?.[0] ?? "";
}
function protectionTile(h: ReturnType<typeof boot>) {
  return h.el.main!.innerHTML.match(/<div class="overview-tile"><a[^>]*>Protection requested<\/a>[\s\S]*?<\/div>/)?.[0] ?? "";
}
describe("Overview 3b served evidence", () => {
  it("A1 mismatched verified flag names chain not verified in both counts", async () => {
    const h = await bootOverview3b(home => home.digest.chain_verified = false);
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route);
      const html = outboundHtml(h);
      for (const label of ["Blocked", "Allowed"]) {
        const cell = html.match(new RegExp('<div>' + label + ' ([^]*?)</div>'))![1]!;
        expect(cell).toContain('class="state-chip unknown overview-chip"');
        expect(cell).toContain("Not evaluated");
        expect(cell).toContain("chain not verified");
      }
      expect(html).not.toContain("audit check not current");
      expect(html).not.toContain("last verified");
      expect(html).not.toMatch(/<strong>\d+<\/strong>/);
    }
  });

  // fail-before-exempt: existing stale-check copy; plant replaces the audit check not current reason.
  it("A1 eleven-minute verified check retains its age reason", async () => {
    const h = await bootOverview3b(undefined, "stale-verified");
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route);
      expect(outboundHtml(h)).toContain("audit check not current");
      expect(outboundHtml(h)).toContain("last verified 11m ago");
      expect(outboundHtml(h)).not.toMatch(/<strong>\d+<\/strong>/);
    }
  });

  it("A1 fail-honest Audit chain chip has no invented zero findings", async () => {
    const h = await bootOverview3b(undefined, "fail-honest");
    const tile = auditTile(h);
    expect(tile).toContain('class="state-chip bad overview-chip"');
    expect(tile).toContain("FAILED");
    expect(tile).toContain("chain not verified");
    expect(tile).not.toContain("0 findings");
    expect(tile).toContain("not verified");
  });

  it("A1 Audit chain chip uses the singular for one finding", async () => {
    const h = await bootOverview3b(home => Object.assign(home.digest, { chain_verdict: "findings", chain_verified: false, integrity_finding_count: 1 }));
    expect(auditTile(h)).toContain("1 finding");
    expect(auditTile(h)).not.toContain("1 findings");
    expect(auditTile(h)).toContain("FAILED");
  });

  it("A1 Audit chain chip withholds every invalid finding count", async () => {
    // Exercise absent, nonnumeric, negative, fractional, nonfinite, and unsafe integer counts.
    for (const count of [undefined, null, "2", -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      const h = await bootOverview3b(home => Object.assign(home.digest, { chain_verdict: "findings", chain_verified: false, integrity_finding_count: count }));
      expect.soft(auditTile(h), String(count)).toContain("chain not verified");
      expect.soft(auditTile(h), String(count)).not.toContain(" findings");
      expect.soft(auditTile(h), String(count)).toContain('class="state-chip bad overview-chip"');
      expect.soft(auditTile(h), String(count)).toContain("FAILED");
    }
  });

  for (const [name, mutate, reason] of [
    ["findings zeros", (d: any) => Object.assign(d, { chain_verdict: "findings", kernel_blocks: 0, kernel_allows: 0 }), "chain not verified"],
    ["key unavailable", (d: any) => Object.assign(d, { chain_verdict: "key_unavailable", kernel_blocks: 0, kernel_allows: 0 }), "chain not verified"],
    ["incomplete", (d: any) => d.window_complete = false, "window coverage not established"],
    ["missing completeness", (d: any) => delete d.window_complete, "window completeness not served"],
    ["bad window", (d: any) => d.window_end = "bad date", "window not stated"],
    ["missing count", (d: any) => delete d.kernel_blocks, "count not served"],
    ["negative count", (d: any) => d.kernel_allows = -1, "count not served"],
    ["unsafe count", (d: any) => d.kernel_blocks = Number.MAX_SAFE_INTEGER + 1, "count not served"],
  ] as const) it(`withholds both counts for ${name} on both screens`, async () => {
    const h = await bootOverview3b(home => mutate(home.digest));
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); const html = outboundHtml(h);
      expect(html).toContain("Not evaluated"); expect(html).toContain(reason);
      expect(html).not.toMatch(/<strong>\d+<\/strong>/);
    }
  });
  it("shows separate served counts with both window dates", async () => {
    const h = await bootOverview3b(home => Object.assign(home.digest, { kernel_blocks: 4, kernel_allows: 2, blocked_destinations: [], blocked_destination_count: 0 }));
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); const html = outboundHtml(h);
      expect(html).toContain('Blocked <strong>4</strong>'); expect(html).toContain('Allowed <strong>2</strong>');
      expect(html).toContain("window "); expect(html).toContain(" to ");
      expect(html).toContain(runInContext("shortTime(new Date(Date.now()).toISOString())", h.context));
      expect(html).toContain(runInContext("shortTime(new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())", h.context));
      expect(html).not.toContain("of 6");
    }
  });
  for (const override of [1, undefined]) it(`withholds Allowed alone for overrides=${override}`, async () => {
    const h = await bootOverview3b(home => home.digest.kernel_allow_overrides = override);
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); const html = outboundHtml(h);
      expect(html).toContain("Blocked <strong>16</strong>"); expect(html).toContain("Allowed");
      // A missing override count is absence of evidence, not evidence of an override.
      expect(html).toContain(override === 1 ? "1 allowed verdict was overridden after it was recorded" : "override count not served");
    }
  });
  it("caps destination rows separately on both screens and preserves the null bucket", async () => {
    const h = await bootOverview3b();
    expect(outboundHtml(h)).toContain("showing 3 of 12");
    expect(outboundHtml(h)).toContain("destination not recorded");
    expect(outboundHtml(h)).toContain('href="#enforcement"');
    h.navigate("enforcement"); expect(outboundHtml(h)).toContain("showing 10 of 12");
    // Enforcement keeps the canonical Evidence link for every row count.
    expect(outboundHtml(h)).toContain('href="/posture/evidence"');
  });
  for (const [name, change, reason] of [
    ["absent", (d: any) => delete d.blocked_destinations, "Blocked destinations are not served"],
    ["not an array", (d: any) => d.blocked_destinations = {}, "Blocked destinations are not served"],
    ["sum", (d: any) => d.kernel_blocks = 1, "served destination values disagree"],
    ["distinct count", (d: any) => d.blocked_destination_count = 1, "served destination values disagree"],
    ["invalid row", (d: any) => d.blocked_destinations[0].blocks = -1, "served destination values disagree"],
  ] as const) it(`withholds destinations for ${name}`, async () => {
    const h = await bootOverview3b(home => change(home.digest));
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); expect(outboundHtml(h)).toContain(reason); expect(outboundHtml(h)).not.toContain("<table");
    }
  });
  it("escapes hostile destinations as text", async () => {
    const h = await bootOverview3b(home => home.digest.blocked_destinations[0].destination = '<img src=x onerror="alert(1)">');
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); expect(outboundHtml(h)).toContain("&lt;img"); expect(outboundHtml(h)).not.toContain("<img");
    }
  });
  it("states an answered zero only after the gate", async () => {
    const h = await bootOverview3b(home => Object.assign(home.digest, { kernel_blocks: 0, blocked_destinations: [], blocked_destination_count: 0 }));
    for (const route of ["posture", "enforcement"]) { h.navigate(route); expect(outboundHtml(h)).toContain("No blocked connections in this window"); }
  });
  for (const [name, change] of [
    ["absent", (home: any) => delete home.protection_detected_count],
    ["fractional", (home: any) => home.protection_requested_count = 1.5],
    ["contradicting", (home: any) => home.protection_requested_count = 100],
    ["negative", (home: any) => home.protection_requested_count = -1],
  ] as const) it(`keeps protection unknown for ${name} counts`, async () => {
    const h = await bootOverview3b(change);
    expect(protectionTile(h)).toContain("UNKNOWN"); expect(protectionTile(h)).not.toContain("good");
  });
  it("renders policy intent as 1 of 3 with its evidence and no enforcement-count consumer", async () => {
    const h = await bootOverview3b(home => { home.protection_requested_count = 1; home.protection_detected_count = 3; });
    expect(protectionTile(h)).toContain("1 of 3"); expect(protectionTile(h)).toContain("registered agents plus unprotected harnesses");
    expect(protectionTile(h)).not.toContain("good"); expect(getClientScript()).not.toContain("enforcement_confirmed_count");
  });
  it("shows an unknown protection tile while the home has not answered", async () => {
    vi.useFakeTimers(); const h = boot({ "/api/posture/home": never }); await settle();
    expect(protectionTile(h)).toContain("UNKNOWN"); expect(protectionTile(h)).not.toContain("0 of 0");
  });
  for (const [label, age, green] of [["inside", OVERVIEW_FRESHNESS_MS - 1, true], ["expired", OVERVIEW_FRESHNESS_MS + 1, false], ["future", -1, false]] as const) {
    it(`ages the chain badge at ${label}`, async () => {
      const h = await bootOverview3b(home => home.digest.window_end = new Date(Date.now() - age).toISOString());
      const html = h.el.main!.innerHTML;
      expect(html.includes('class="overview-chip-head"><i aria-hidden="true"></i>VERIFIED')).toBe(green);
      if (!green) { expect(html).toContain("last verified"); expect(html).toContain(", not current"); }
    });
  }
  it("expires the audit chip and rereads at the boundary", async () => {
    const h = await bootOverview3b(home => home.digest.window_end = new Date(Date.now() - OVERVIEW_FRESHNESS_MS + 1).toISOString());
    expect(h.el.main!.innerHTML).toContain('></i>VERIFIED');
    const reads = h.homeReads();
    await vi.advanceTimersByTimeAsync(2); await settle();
    expect(h.el.main!.innerHTML).not.toContain('></i>VERIFIED');
    expect(h.el.main!.innerHTML).toContain("not current");
    // The existing read-rate floor may defer the network read, never the visual expiry.
    const rereadFloor = runInContext("DASHBOARD_SEAL_REREAD_MIN_INTERVAL_MS", h.context) as number;
    await vi.advanceTimersByTimeAsync(rereadFloor + 1000); await settle();
    expect(h.homeReads()).toBeGreaterThan(reads);
  });
  for (const [label, age] of [["fresh", 1000], ["stale", OVERVIEW_FRESHNESS_MS + 1], ["absent", null]] as const) {
    it(`keeps the seal and wall in agreement with ${label} evidence`, async () => {
      const h = await bootOverview3b(home => home.castle_wall.last_enforcement_evidence_at = age === null ? null : new Date(Date.now() - age).toISOString());
      expect(h.el["posture-seal-word"]!.textContent).toBe(label === "fresh" ? "Protected" : "Attention");
      expect(h.el.main!.innerHTML.includes('></i>ENFORCING')).toBe(label === "fresh");
      expect(h.el.main!.innerHTML).toContain("showing 3 of 12");
    });
  }
  it("keeps chip heads together and separates their wrapping evidence detail", async () => {
    const h = await bootOverview3b();
    expect(h.el.main!.innerHTML).toContain('class="overview-chip-head"><i aria-hidden="true"></i>ENFORCING</span>');
    expect(h.el.main!.innerHTML).toContain('class="overview-chip-detail"');
    const chip = runInContext('makeMachineRow({ name: "fixture", url: "http://fixture/", probe: { state: "state_UNKNOWN" } }, 0).outerHTML', h.context) as string;
    // Captured from main 546180fa; this shared chip must survive Overview-only styling.
    expect(chip.match(/<span[^>]*class="state-chip[^>]*>[\s\S]*?<\/span>/)?.[0]).toBe('<span title="Unknown: this saved address is not a web address, so it was not linked or checked." class="state-chip unknown"><i aria-hidden="true"></i>Unknown</span>');
    expect(getClientScript()).not.toContain("\u2014");
  });
});

describe("round 2 outbound and tile honesty", () => {
  for (const verdict of ["verified", "verified_suffix_only"] as const) it(`requires a current ${verdict} check beside covered counts`, async () => {
    const h = await bootOverview3b(home => Object.assign(home.digest, {
      chain_verdict: verdict, chain_verified: verdict === "verified", window_complete: true,
      window_end: new Date(Date.now() - OVERVIEW_FRESHNESS_MS + 1).toISOString(),
    }));
    expect(outboundHtml(h)).toContain("Blocked <strong>16</strong>");
    expect(h.el.main!.innerHTML).toContain(verdict === "verified" ? "></i>VERIFIED" : "></i>SUFFIX ONLY");
    await vi.advanceTimersByTimeAsync(2); await settle();
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route);
      expect(outboundHtml(h)).toContain("audit check not current");
      expect(outboundHtml(h)).toContain("last verified 10m ago");
      expect(outboundHtml(h)).not.toMatch(/<strong>\d+<\/strong>/);
      if (route === "posture") expect(h.el.main!.innerHTML).not.toContain("></i>SUFFIX ONLY");
    }
  });
  for (const [value, reason] of [
    [undefined, "override count not served"], [null, "override count not served"], [-1, "override count not served"],
    [1.5, "override count not served"], [Number.MAX_SAFE_INTEGER + 1, "override count not served"],
    [1, "1 allowed verdict was overridden after it was recorded"], [2, "2 allowed verdicts were overridden after they were recorded"],
  ] as const) it(`states the served override reason for ${value}`, async () => {
    const h = await bootOverview3b(home => home.digest.kernel_allow_overrides = value);
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); expect(outboundHtml(h)).toContain(reason);
      expect(outboundHtml(h)).toContain("Blocked <strong>16</strong>");
    }
  });
  for (const [complete, value, reason] of [
    [undefined, undefined, "window completeness not served"], [null, null, "window completeness not served"],
    [-1, null, "window completeness not served"], [false, "read_limit", "window larger than one read"],
    [false, "sealed_region", "sealed audit region coverage not established"],
    // The coverage reason does not establish whether pruning, a legacy prefix, or a racing append caused it.
    [false, "retention", "the check could not reach the oldest audit entry, so this window is not fully covered"],
    [false, "coverage_unknown", "window coverage not established"],
    [false, "unexpected", "window coverage not established"], [false, undefined, "window coverage not established"],
  ] as const) it(`states completeness=${complete} reason=${value}`, async () => {
    const h = await bootOverview3b(home => Object.assign(home.digest, { window_complete: complete, window_incomplete_reason: value }));
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); expect(outboundHtml(h)).toContain(reason);
      expect(h.el.main!.innerHTML).not.toContain("retention removed older entries");
      expect(outboundHtml(h)).toContain('class="outbound-reason muted"');
      expect(outboundHtml(h)).not.toMatch(/<strong>\d+<\/strong>/);
    }
  });
  for (const shape of ["no rows", "zero destinations", "all rows undercount"] as const) it(`rejects destination disagreement: ${shape}`, async () => {
    const h = await bootOverview3b(home => Object.assign(home.digest, {
      blocked_destinations: shape !== "all rows undercount" ? [] : [{ destination: "one", blocks: 1, last_blocked_at: null }],
      blocked_destination_count: shape === "zero destinations" ? 0 : 1,
    }));
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); expect(outboundHtml(h)).toContain("served destination values disagree");
      expect(outboundHtml(h)).not.toContain("<table");
    }
  });
  for (const count of [0, 1, 10]) it(`keeps the Enforcement age and Evidence link with ${count} destinations`, async () => {
    const h = await bootOverview3b(home => Object.assign(home.digest, {
      kernel_blocks: count, blocked_destination_count: count,
      blocked_destinations: Array.from({ length: count }, (_, i) => ({ destination: `host-${i}`, blocks: 1, last_blocked_at: null })),
    }));
    h.navigate("enforcement");
    expect(outboundHtml(h)).toContain("window closed");
    expect(outboundHtml(h)).toContain('href="/posture/evidence"');
  });
  it("gives all three withheld cells an Unknown glyph and a separate reason line", async () => {
    const h = await bootOverview3b(home => home.digest.chain_verdict = "findings");
    for (const route of ["posture", "enforcement"]) {
      h.navigate(route); const html = outboundHtml(h);
      expect(html.match(/class="state-chip unknown overview-chip"/g)).toHaveLength(3);
      expect(html.match(/<i aria-hidden="true"><\/i>Not evaluated/g)).toHaveLength(3);
      expect(html.match(/<span class="outbound-reason muted">chain not verified<\/span>/g)).toHaveLength(3);
    }
  });
  for (const scenario of ["first-run-unprotected", "unloaded"]) it(`puts the ${scenario} protection tile inside the grid`, async () => {
    vi.useFakeTimers();
    const h = scenario === "unloaded" ? boot({ "/api/posture/home": never }) : await bootOverview3b(undefined, scenario);
    await settle();
    expect(h.el.main!.innerHTML).toMatch(/<div class="overview-tiles"[^>]*><div class="overview-tile"><a[^>]*>Protection requested/);
  });
  it("starts chip detail on its own block without a leading separator", async () => {
    const h = await bootOverview3b();
    expect(h.el.main!.innerHTML).toMatch(/class="overview-chip-detail">[^ ·]/);
    expect(h.el.main!.innerHTML).not.toContain('class="overview-chip-detail"> ·');
    expect(renderDashboardV11Html()).toContain('.overview-chip-detail { display: block;');
  });
  it("uses container widths for five tiles or three plus two", () => {
    const html = renderDashboardV11Html();
    expect(html).toContain('container-type: inline-size');
    expect(html).toContain('grid-template-columns: repeat(3, minmax(0, 1fr))');
    expect(html).toMatch(/@container overview \(min-width: \d+px\)/);
    expect(html).toContain('grid-template-columns: repeat(5, minmax(0, 1fr))');
    expect(html).not.toContain('repeat(auto-fit, minmax(min(100%, var(--overview-tile-min))');
    expect(html).toContain('.outbound-reason { display: block;');
  });
});

describe("Approvals round-one decision and evidence states", () => {
  const cap = 100; // Must match HUB_INBOX_DEFAULT_LIMIT: one inbox page.
  const tier2 = { ...heldItem, tier: "tier2", operation_category: "state_export" };
  const drawer = (h: ReturnType<typeof boot>) => h.el.main!.innerHTML.split('<aside class="card approval-drawer"')[1] || "";
  const checkbox = (h: ReturnType<typeof boot>) => h.click({ "data-action": "approval-always-allow" }, [], true);
  const changeFilter = (h: ReturnType<typeof boot>, field: string, value: string) => {
    const select = new FakeElement({ "data-action": `approval-filter-${field}` }, "select");
    select.value = value;
    h.change(select);
  };
  const inbox = (items: unknown[]) => () => Promise.resolve(response({ data: { items } }));
  const pageOthers = (count: number) => Array.from({ length: count }, (_, index) => ({ ...heldItem, kind: "blocked_egress", item_id: `other-${index}` }));

  it("a full page without holds earns no empty claim on the queue, drawer or fortress", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox(pageOthers(cap)) });
    await settle();
    h.navigate("approvals");
    const sentence = `None of the first ${cap} inbox items is a held operation. The inbox has at least ${cap} items and this read shows only the first ${cap}, so a held operation may be waiting past them.`;
    for (const html of [h.el.main!.innerHTML.split("<aside")[0]!, drawer(h), h.el.fortress!.innerHTML]) {
      expect(html).toContain(sentence);
      expect(html).not.toMatch(/qe-check|Nothing waiting on you\.|No approvals waiting|0 of 0 held operations/);
    }
  });

  it("a full page fortress summary states at least the loaded hold count", async () => {
    vi.useFakeTimers();
    const holdCount = 3; // Three visible holds amid the rest of a full page.
    const h = boot({ "/api/hub/inbox": inbox([...Array.from({ length: holdCount }, (_, i) => ({ ...heldItem, item_id: `hold-${i}` })), ...pageOthers(cap - holdCount)]) });
    await settle();
    expect(h.el.fortress!.innerHTML).toContain(`At least ${holdCount} held operations waiting (from the first ${cap} inbox items).`);
  });

  it("unrecognized tiers remain visible as an uncertainty on every approval surface", async () => {
    vi.useFakeTimers();
    const items = [{ ...heldItem, tier: "tier9" }];
    const h = boot({ "/api/hub/inbox": inbox(items) });
    await settle();
    h.navigate("approvals");
    const line = "1 held item carries a tier this console does not recognize. It is not shown here and cannot be decided from this screen.";
    for (const html of [h.el.main!.innerHTML, drawer(h), h.el.fortress!.innerHTML]) {
      expect(html).toContain(line);
      expect(html).not.toMatch(/qe-check|Nothing waiting on you\.|No approvals waiting|0 of 0 held operations/);
    }
    items.push({ ...heldItem, item_id: "known", tier: "tier2" });
    await runInContext("fetchAll(true);", h.context);
    expect(h.el.main!.innerHTML).toContain(line);
    expect(h.el.fortress!.innerHTML).toContain(line);
  });

  it("the fortress names holds outside an empty agent scope including Charter holds", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox([{ ...heldItem, item_id: "charter.approval.one", agent_id: undefined }]) });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "agent-empty" });
    const line = "No recognized held operation for agent-empty is waiting in this read. 1 held operation waits outside this agent scope; choose All agents in the scope menu to see them.";
    for (const html of [h.el.main!.innerHTML, drawer(h), h.el.fortress!.innerHTML]) {
      expect(html).toContain(line);
      expect(html).not.toContain("qe-check");
    }
  });

  for (const failure of ["none", "approve", "compile", "activate", "missing draft", "refused status", "downgrade cancelled", "downgrade confirmed", "override refused"]) {
    it(`Always allow orders approve, compile, activate and reports ${failure} refusal honestly`, async () => {
      vi.useFakeTimers();
      const calls: string[] = [];
      const requestId = failure === "none" ? "charter.approval.one" : "item-1";
      let items = [{ ...tier2, item_id: requestId }];
      const h = boot({
        "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
        [`/api/hub/inbox/${requestId}/approve`]: (init) => {
          calls.push("approve");
          expect(init?.body).toBe("{}");
          if (failure === "approve") return Promise.resolve(response({ error: "refused" }, 401));
          const resolved = { ...tier2, item_id: requestId, resolved: true };
          // Charter holds disappear from the served projection immediately after a decision.
          items = failure === "none" ? [] : [resolved];
          return Promise.resolve(response({ data: { item: resolved } }));
        },
        "/api/policy/compile": (init) => {
          calls.push("compile");
          expect(JSON.parse(String(init?.body))).toEqual({ english_text: "auto-allow state_export" });
          return Promise.resolve(failure === "compile" ? response({ error: "compile refused" }, 422) : response({ data: { draft: failure === "missing draft" ? null : { draft_id: "rule" } } }));
        },
        "/api/policy/drafts/rule/activate": (init) => {
          calls.push("activate");
          expect(init?.body).toBe("{}");
          if (failure.startsWith("downgrade") || failure === "override refused") return Promise.resolve(response({ error: "downgrade" }, 409));
          return Promise.resolve(failure === "activate" ? response({ error: "activate refused" }, 503) : response({ data: { status: failure === "refused status" ? "refused" : "activated" } }));
        },
        "/api/policy/drafts/rule/activate?override_downgrade=true": () => {
          calls.push("override");
          return Promise.resolve(failure === "override refused" ? response({ error: "override refused" }, 409) : response({ data: { status: "activated" } }));
        },
      });
      runInContext(`window.confirm = function () { return ${failure !== "downgrade cancelled"}; };`, h.context);
      await settle();
      h.navigate("approvals");
      await settle();
      checkbox(h);
      expect(drawer(h)).toContain('data-action="inbox-promote"');
      h.click({ "data-action": "inbox-promote", "data-item-id": requestId });
      // Approval, promotion and the final repaint each drain a bounded refresh wave.
      await settle();
      await settle();
      const expected = failure === "approve" ? ["approve"] : failure === "compile" || failure === "missing draft" ? ["approve", "compile"] : ["approve", "compile", "activate"];
      if (failure === "downgrade confirmed" || failure === "override refused") expected.push("override");
      expect(calls).toEqual(expected);
      // Every outcome is the retained decision result on the screen; no toast reports a decision.
      const result = h.el.main!.innerHTML.split('class="decision-result"')[1] ?? "";
      expect(h.el["toast-host"]!.innerHTML).toBe("");
      if (failure === "approve") {
        expect(result).toContain('data-decision-status="refused"');
        expect(result).toContain("Allow once was refused for");
        expect(result).not.toContain("Allowed once");
        expect(drawer(h)).toContain("WAITING");
      } else {
        expect(drawer(h)).toContain(failure === "none" ? "No approvals waiting" : "DECIDED");
        expect(result).toContain('data-decision-status="acknowledged"');
        expect(result).toContain("Allowed once: state_export by fixture-agent (request " + requestId + ").");
        if (failure !== "none" && failure !== "downgrade confirmed") expect(result).toContain("The standing rule was not added:");
        else expect(result).toContain("Standing rule added: agents may state_export without asking.");
        // A declined downgrade reads as one sentence, not a second "no standing rule added" after the first.
        if (failure === "downgrade cancelled") {
          expect(result).toContain("The standing rule was not added: you chose to keep your protection.");
          expect(result).not.toContain("no standing rule added");
        }
      }
      expect(runInContext("state.approvals.alwaysAllow", h.context)).toBe(false);
    });
  }

  it("Always allow resets when fallback selection or scope changes the drawer", async () => {
    vi.useFakeTimers();
    let items = [{ ...tier2, agent_id: "agent-a" }, { ...tier2, item_id: "item-2", agent_id: "agent-b" }];
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })) });
    await settle();
    h.navigate("approvals");
    await settle();
    checkbox(h);
    items = items.slice(1);
    await runInContext("fetchAll(true)", h.context);
    expect(drawer(h)).toContain('data-item-id="item-2"');
    expect(drawer(h)).not.toContain('data-action="approval-always-allow" checked');
    checkbox(h);
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "agent-b" });
    expect(drawer(h)).not.toContain('data-action="approval-always-allow" checked');
  });

  for (const mode of ["loading", "not served", "401", "503", "tier1", "other"]) {
    it(`Always allow is disabled with a reason for ${mode}`, async () => {
      vi.useFakeTimers();
      const h = boot({
        "/api/hub/inbox": inbox([{ ...tier2, ...(mode === "tier1" ? { tier: "tier1" } : mode === "other" ? { operation_category: "other" } : {}) }]),
        // Policy fixtures serve the view's real lines field; a malformed policy view now fails the whole read.
        "/api/policy/current": mode === "loading" ? never : () => Promise.resolve(response({ data: { view: { lines: [] } } }, mode === "401" ? 401 : mode === "503" ? 503 : 200)),
      });
      await settle();
      h.navigate("approvals");
      await settle();
      if (mode === "not served") runInContext('markSourceNotServed(POLICY + "/current"); rerender();', h.context);
      const reasons: Record<string, string> = {
        loading: "Checking the policy-change path.", "not served": "Not available in this dashboard mode.", "401": "Operator token required", "503": "Policy engine is not configured", tier1: "Tier 1 approvals cannot become standing rules", other: "Always allow is unavailable for this operation.",
      };
      expect(drawer(h)).toContain('data-action="approval-always-allow" disabled');
      expect(drawer(h).toLowerCase()).toContain(reasons[mode]!.toLowerCase());
      checkbox(h);
      expect(drawer(h)).not.toContain('data-action="inbox-promote"');
    });
  }

  it("Review in drawer moves focus to the drawer heading, never to a decision control", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox([heldItem, { ...heldItem, item_id: "item-2", tier: "tier2" }]) });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "approval-select", "data-item-id": "item-1" });
    const focused = fakeActiveElement as FakeElement;
    expect(focused.getAttribute("data-approval-drawer-focus")).toBe("1");
    expect(focused.getAttribute("data-action")).toBeNull();
    expect(drawer(h)).toContain('<h3 tabindex="-1" data-approval-drawer-focus="1">Selected approval</h3>');
  });

  it("a Tier 1 drawer says Allow once arms the request and only Confirm sends it", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox([heldItem]) });
    await settle();
    h.navigate("approvals");
    const html = drawer(h);
    expect(html).toContain("Allow once arms this request, and Confirm ");
    expect(html).not.toContain("Allow once sends this approval");
  });

  it("Tier 1 double-click disarms in the original slot and keeps focus on Cancel", async () => {
    vi.useFakeTimers();
    const calls: string[] = [];
    const h = boot({ "/api/hub/inbox": inbox([heldItem]), "/api/hub/inbox/item-1/approve": () => { calls.push("approve"); return never(); } });
    await settle();
    h.navigate("approvals");
    const clickFirstSlot = () => {
      const toolbar = drawer(h).match(/<div class="toolbar">([\s\S]*?)<\/div>/)![1]!;
      const button = toolbar.match(/<button\b([^>]*)>/)![1]!;
      h.click(Object.fromEntries([...button.matchAll(/([\w-]+)="([^"]*)"/g)].map((m) => [m[1]!, m[2]!])));
    };
    clickFirstSlot();
    const armed = drawer(h);
    expect(armed).toContain('data-action="approval-cancel-tier1-allow"');
    expect(armed).toMatch(/<\/div><div class="approval-confirm-row">.*data-action="approval-confirm-tier1-allow"/);
    expect((fakeActiveElement as FakeElement).getAttribute("data-action")).toBe("approval-cancel-tier1-allow");
    clickFirstSlot();
    h.click({ "data-action": "approval-confirm-tier1-allow", "data-item-id": "item-1" });
    await settle();
    expect(calls).toEqual([]);
    expect(drawer(h)).toContain("WAITING");
    expect(drawer(h)).not.toContain('data-action="approval-confirm-tier1-allow"');
    expect((fakeActiveElement as FakeElement).getAttribute("data-action")).toBe("approval-cancel-tier1-allow");
    expect(drawer(h)).toContain("Only Confirm sends the approval.");
  });

  for (const mode of ["once", "always", "tier1"]) {
  it(`pending ${mode} decisions disable the item's controls and ignore repeat clicks`, async () => {
    vi.useFakeTimers();
    const calls: string[] = [];
    let finish!: (value: unknown) => void;
    const h = boot({ "/api/hub/inbox": inbox([mode === "tier1" ? heldItem : tier2]), "/api/hub/inbox/item-1/approve": () => { calls.push("approve"); return new Promise((resolve) => { finish = resolve; }); }, "/api/hub/inbox/item-1/deny": () => { calls.push("deny"); return never(); } });
    await settle();
    h.navigate("approvals");
    await settle();
    if (mode === "always") checkbox(h);
    if (mode === "tier1") h.click({ "data-action": "approval-start-tier1-allow", "data-item-id": "item-1" });
    const action = mode === "always" ? "inbox-promote" : mode === "tier1" ? "approval-confirm-tier1-allow" : "inbox-approve";
    h.click({ "data-action": action, "data-item-id": "item-1" });
    expect(drawer(h)).toContain(`data-action="${action}" data-item-id="item-1" disabled`);
    for (const button of h.el.main!.innerHTML.matchAll(/<button\b[^>]*data-action="(?:inbox-approve|inbox-deny|inbox-promote|approval-confirm-tier1-allow)"[^>]*>/g)) expect(button[0]).toContain(" disabled");
    h.click({ "data-action": "inbox-approve", "data-item-id": "item-1" });
    h.click({ "data-action": "inbox-deny", "data-item-id": "item-1" });
    expect(calls).toEqual(["approve"]);
    finish(response({ data: { item: tier2 } }));
    await settle();
    await settle();
    expect(drawer(h)).not.toMatch(/data-item-id="item-1" disabled/);
  });
  }

  it("stale agent and category filters stay selected and agent scope clears the agent filter", async () => {
    vi.useFakeTimers();
    let items = [tier2];
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })) });
    await settle();
    h.navigate("approvals");
    changeFilter(h, "agent", "fixture-agent");
    changeFilter(h, "category", "state_export");
    items = [{ ...tier2, agent_id: "new-agent", operation_category: "state_delete" }];
    await runInContext("fetchAll(true)", h.context);
    expect(h.el.main!.innerHTML).toContain('<option value="fixture-agent" selected>fixture-agent (none loaded)</option>');
    expect(h.el.main!.innerHTML).toContain('<option value="state_export" selected>state_export (none loaded)</option>');
    changeFilter(h, "category", "");
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "new-agent" });
    expect(runInContext("state.approvals.filters.agent", h.context)).toBe("");
    expect(h.el.main!.innerHTML).toContain("showing 1 of 1");
  });

  it("waiting rows precede the cap even when decided history comes first", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox([...Array.from({ length: cap }, (_, i) => ({ ...tier2, item_id: `decided-${i}`, resolved: true })), { ...tier2, item_id: "waiting-last" }]) });
    await settle();
    h.navigate("approvals");
    expect(h.el.main!.innerHTML).toContain('data-action="inbox-approve" data-item-id="waiting-last"');
    expect(h.el.main!.innerHTML).toContain("Waiting on you · 1 of 1");
    expect(h.el.main!.innerHTML).toContain(`showing ${cap} of ${cap + 1}`);
  });

  for (const mode of ["redacted", "failed"]) {
    it(`Approvals ${mode} reads render no rows or calm zero`, async () => {
      vi.useFakeTimers();
      const h = boot({ "/api/hub/inbox": () => Promise.resolve(mode === "failed" ? response({}, 500) : response({ data: { items: [], pending_approvals_redacted: true, pending_approvals_count: 2 } })) });
      await settle();
      h.navigate("approvals");
      expect(h.el.main!.innerHTML).toContain(mode === "failed" ? "Unknown" : "Approvals are hidden, not empty");
      expect(h.el.main!.innerHTML).not.toMatch(/data-approval-row|qe-check|No approvals waiting|0 of 0/);
    });
  }

  it("hub controls and other categories state the hold without inventing a policy reason", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox([heldItem, { ...tier2, item_id: "other", operation_category: "other" }, { ...heldItem, item_id: "export", operation_category: "exit_bundle_export" }]) });
    await settle();
    h.navigate("approvals");
    expect(drawer(h)).toContain("Held for your decision (lockdown, Tier 1).");
    h.click({ "data-action": "approval-select", "data-item-id": "other" });
    expect(drawer(h)).toContain("Held for your decision (other, Tier 2).");
    h.click({ "data-action": "approval-select", "data-item-id": "export" });
    expect(drawer(h)).toContain("Held for your decision (exit_bundle_export, Tier 1).");
  });

  it("an unrecognized-tier count names only waiting items, and alone it says no recognized hold waits", async () => {
    vi.useFakeTimers();
    // A decided item is no longer held, so it must not inflate the waiting count; with no recognized hold
    // waiting the queue still says so in words rather than leaving an empty notice.
    const h = boot({ "/api/hub/inbox": inbox([{ ...heldItem, item_id: "decided", tier: "tier9", resolved: true }, { ...heldItem, item_id: "waiting", tier: "tier9" }]) });
    await settle();
    h.navigate("approvals");
    for (const html of [h.el.main!.innerHTML, drawer(h), h.el.fortress!.innerHTML]) {
      expect(html).toContain("1 held item carries a tier this console does not recognize.");
      expect(html).not.toContain("2 held items carry");
      expect(html).not.toContain("1 held items");
    }
    for (const html of [drawer(h), h.el.fortress!.innerHTML]) expect(html).toContain("No recognized held operation is waiting.");
    expect(h.el.fortress!.innerHTML).not.toContain('<div class="queue-empty"></div>');
  });

  it("a scoped empty on a full page states a lower bound, never an exact count", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox([{ ...heldItem, item_id: "charter.approval.one", agent_id: undefined }, ...pageOthers(cap - 1)]) });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "agent-empty" });
    for (const html of [h.el.main!.innerHTML, drawer(h), h.el.fortress!.innerHTML]) {
      expect(html).toContain(`No recognized held operation for agent-empty is waiting in this read. At least 1 held operation waits outside this agent scope; choose All agents in the scope menu to see them. The inbox has at least ${cap} items and this read shows only the first ${cap}, so a held operation may be waiting past them.`);
      expect(html).not.toContain("1 of 1 held operation");
    }
  });

  it("the fortress count badge is a lower bound on a full page and separates unrecognized holds", async () => {
    vi.useFakeTimers();
    const holdCount = 3; // Three visible holds amid the rest of a full page.
    const full = boot({ "/api/hub/inbox": inbox([...Array.from({ length: holdCount }, (_, i) => ({ ...heldItem, item_id: `hold-${i}` })), ...pageOthers(cap - holdCount)]) });
    await settle();
    expect(full.el.fortress!.innerHTML).toContain(`<span class="count" id="queue-count">${holdCount}+ of ${holdCount}+</span>`);
    const unrecognized = boot({ "/api/hub/inbox": inbox([{ ...heldItem, tier: "tier9" }]) });
    await settle();
    expect(unrecognized.el.fortress!.innerHTML).toContain('<span class="count" id="queue-count">0</span>');
    expect(unrecognized.el.fortress!.innerHTML).toContain("1 held item carries a tier");
    const earned = boot({ "/api/hub/inbox": inbox([]) });
    await settle();
    expect(earned.el.fortress!.innerHTML).toContain('<span class="count zero" id="queue-count">0</span>');
  });
});


describe("slice 6b Machines Findings Policies wired consumers", () => {
  async function mfpBoot(route: string, change?: (s: ReturnType<typeof mfpScenario>) => void, overrides = {}) {
    vi.useFakeTimers();
    const s = mfpScenario();
    change?.(s);
    const h = boot({
      "/api/fleet/roster": () => Promise.resolve(response(s.roster)),
      "/api/sentinels/findings": () => Promise.resolve(response({ data: { findings: s.findings } })),
      "/api/policy/current": () => Promise.resolve(response({ data: { view: s.policy } })),
      "/api/hub/agents": () => Promise.resolve(response({ data: { agents: s.agents } })),
      ...overrides,
    });
    await settle(); h.navigate(route); await settle();
    return h;
  }
  it("reads the authenticated roster separately from browser-saved machines", async () => {
    const h = await mfpBoot("machines");
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-mfp-roster');
    expect(html).toContain('Build box');
    expect(html).toContain('ADMITTED');
    expect(html).toContain('Saved in this browser');
    expect(html).toContain('Showing 1 of 1');
    expect(html).toContain('Enrollment status is not served');
    expect(html).toContain('Last check');
  });
  it("never derives roster trust or drift from attestation or reach", async () => {
    const h = await mfpBoot("machines", s => {
      Object.assign(s.roster.nodes[0]!, { trust_state: undefined, policy: undefined, attestation_status: 'verified', reach: 'recent' });
    });
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-mfp-roster');
    expect(html).not.toContain('ADMITTED');
    expect(html).not.toContain('IN SYNC');
    expect(html.match(/state-chip unknown/g)!.length).toBeGreaterThanOrEqual(3);
  });
  it("shows a roster read failure as Unknown without old rows or a zero", async () => {
    const h = await mfpBoot("machines", undefined, { '/api/fleet/roster': () => Promise.reject(new Error('unavailable')) });
    expect(h.el.main!.innerHTML).toContain('Fleet roster Unknown');
    expect(h.el.main!.innerHTML).not.toContain('Showing 0 of 0');
    expect(h.el.main!.innerHTML).toContain('data-read="/api/fleet/roster"');
  });
  it("paginates the roster with a bounded page and an exact denominator", async () => {
    const h = await mfpBoot("machines", s => { s.roster.nodes = Array.from({ length: 51 }, (_, i) => ({ ...s.roster.nodes[0]!, node_id: 'node-' + i, label: 'Machine ' + i })); });
    expect(h.el.main!.innerHTML).toContain('Showing 25 of 51');
    expect(h.el.main!.innerHTML).not.toContain('Machine 25<');
    h.click({ 'data-action': 'mfp-page', 'data-list': 'roster', 'data-step': '1' });
    expect(h.el.main!.innerHTML).toContain('Machine 25<');
  });
  it("ranks the served Sentinel vocabulary and declares its five-level display scale", async () => {
    const h = await mfpBoot("findings");
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-mfp-findings');
    for (const level of ['critical', 'high', 'medium', 'low', 'info']) expect(html).toContain('mfp-severity ' + level);
    expect(html.indexOf('alert outbound observation')).toBeLessThan(html.indexOf('warn outbound observation'));
    expect(html.indexOf('warn outbound observation')).toBeLessThan(html.indexOf('info outbound observation'));
    expect(html).toContain('egress-volume');
    expect(html).toContain('Read-only');
    expect(html).toContain('Lifecycle is not served');
    expect(html).not.toMatch(/data-action="finding-(resolve|dismiss|acknowledge)"/);
  });
  it("opens finding evidence in a drawer and escapes hostile text throughout", async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const h = await mfpBoot("findings", s => { s.findings[1]!.summary = hostile; s.findings[1]!.details = { evidence: hostile }; });
    h.click({ 'data-action': 'mfp-finding', 'data-finding-id': 'finding-alert' });
    const html = h.el.main!.innerHTML;
    expect(html).toContain('aria-label="Finding evidence"');
    expect(html).toContain('baseline');
    expect(html).toContain('&lt;img');
    expect(html).not.toContain(hostile);
    expect(html).toContain('egress_blocked');
    expect(html).toContain('data-action="mfp-finding-close"');
  });
  it("keeps findings Unknown when the Sentinel source fails", async () => {
    const h = await mfpBoot("findings", undefined, { '/api/sentinels/findings': () => Promise.reject(new Error('offline')) });
    expect(h.el.main!.innerHTML).toContain('Sentinel findings Unknown');
    expect(h.el.main!.innerHTML).not.toContain('No findings returned');
  });
  it("bounds the findings queue and clears a selected record when its source fails", async () => {
    let failed = false;
    const s = mfpScenario();
    s.findings = Array.from({ length: 51 }, (_, i) => ({ ...s.findings[0]!, finding_id: 'f-' + i }));
    const h = await mfpBoot("findings", undefined, { '/api/sentinels/findings': () => failed ? Promise.reject(new Error('offline')) : Promise.resolve(response({ data: { findings: s.findings } })) });
    expect(h.el.main!.innerHTML).toContain('Showing 25 of 51');
    h.click({ 'data-action': 'mfp-finding', 'data-finding-id': 'f-0' });
    expect(h.el.main!.innerHTML).toContain('aria-label="Finding evidence"');
    failed = true;
    h.click({ 'data-action': 'retry-panel', 'data-read': '/api/sentinels/findings' }); await settle();
    expect(h.el.main!.innerHTML).not.toContain('aria-label="Finding evidence"');
  });
  it("renders policy groups beside the served rule table with truthful metadata", async () => {
    const h = await mfpBoot("policy");
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-mfp-policy');
    // The approval group takes its heading from POLICY_SECTION_TITLES, the same name the rule table uses.
    for (const label of ['What agents may reach', 'Always asks you first', 'What is never allowed', 'Rule table', 'Version 7', 'Signature state is not served']) expect(html).toContain(label);
    expect(html).toContain('export your saved state off the machine');
    expect(html).toContain('data-action="template-picker-open"');
    expect(html).not.toContain('state-chip good');
  });
  it("does not retain policy metadata or rules after a failed read", async () => {
    const h = await mfpBoot("policy", undefined, { '/api/policy/current': () => Promise.reject(new Error('offline')) });
    expect(h.el.main!.innerHTML).toContain('Policy Unknown');
    expect(h.el.main!.innerHTML).not.toContain('Version 7');
    expect(h.el.main!.innerHTML).not.toContain('export your saved state off the machine');
  });
  it("bounds served policy lines and escapes their text", async () => {
    const h = await mfpBoot("policy", s => { s.policy.lines = Array.from({ length: 51 }, () => ({ section: 'approval', text: '<script>bad()</script>' })); });
    expect(h.el.main!.innerHTML).toContain('Showing 25 of 51');
    expect(h.el.main!.innerHTML).toContain('&lt;script&gt;');
    expect(h.el.main!.innerHTML).not.toContain('<script>bad()');
  });
  it("shows evidenced empty states for all three screens", async () => {
    const h = await mfpBoot("machines", s => { s.roster.nodes = []; s.findings = []; s.policy.lines = []; });
    expect(h.el.main!.innerHTML).toContain('No machines in the roster');
    h.navigate('findings'); await settle();
    expect(h.el.main!.innerHTML).toContain('No findings returned');
    h.navigate('policy'); await settle();
    expect(h.el.main!.innerHTML).toContain('No policy lines returned');
  });
  it("rejects malformed roster entries without claiming a checked empty fleet", async () => {
    const h = await mfpBoot("machines", s => { s.roster.nodes = [null as never]; });
    expect(h.el.main!.innerHTML).toContain('Fleet roster Unknown');
  });
  it("rejects malformed findings without a lifecycle or empty claim", async () => {
    const h = await mfpBoot("findings", s => { s.findings = [null as never]; });
    expect(h.el.main!.innerHTML).toContain('Sentinel findings Unknown');
  });
  it("refuses an oversized roster response within its read budget", async () => {
    const h = await mfpBoot("machines", s => { s.roster.nodes[0]!.label = 'x'.repeat(2 * 1024 * 1024); });
    expect(h.el.main!.innerHTML).toContain('Fleet roster Unknown');
  });
  it("bounds repeated snapshots and exposes records beyond the preview cap", async () => {
    const h = await mfpBoot("findings", s => { s.findings = Array.from({ length: 501 }, (_, i) => ({ ...s.findings[0]!, finding_id: 'f-' + i })); });
    expect(h.el.main!.innerHTML).toContain('Showing 25 of 501');
    expect(h.el.main!.innerHTML).toContain('Only the first 500');
    for (let i = 0; i < 22; i++) h.click({ 'data-action': 'mfp-page', 'data-list': 'findings', 'data-step': '1' });
    expect(h.el.main!.innerHTML).toContain('Page 20 of 20');
    expect(h.el.main!.innerHTML).not.toContain('data-finding-id="f-500"');
    for (let i = 0; i < 3; i++) { h.click({ 'data-action': 'retry-panel', 'data-read': '/api/sentinels/findings' }); await settle(); }
    expect(h.el.main!.innerHTML).toContain('Showing 25 of 501');
  });
  it("folds Auto-trigger and Honeypots into both Findings and Policies", async () => {
    const h = await mfpBoot("findings");
    expect(h.el.main!.innerHTML).toContain('data-folded-route="auto-trigger"');
    expect(h.el.main!.innerHTML).toContain('data-folded-route="honeypot"');
    h.navigate('policy'); await settle();
    expect(h.el.main!.innerHTML).toContain('data-folded-route="auto-trigger"');
    expect(h.el.main!.innerHTML).toContain('data-folded-route="honeypot"');
  });
  it("6b the roster, findings and policy lists render no link into a raw read", async () => {
    // Read URLs carry the launch session only inside fetch calls (credentialedReadUrl), never in a rendered link.
    for (const route of ["machines", "findings", "policy"]) {
      const h = await mfpBoot(route);
      expect(h.el.main!.innerHTML).toContain('returned records');
      expect(h.el.main!.innerHTML).not.toMatch(/href="\/api\//);
    }
  });
  it("6b the Findings screen keeps the anomaly findings the Overview tile counts and links to", async () => {
    const h = await mfpBoot("findings", undefined, { "/api/anomaly/findings": () => Promise.resolve(response({ data: { findings: [
      { finding_id: "anomaly-1", severity: "medium", detector_id: "egress-volume", summary: "Unusual outbound volume", created_at: "2026-10-14T16:46:00.000Z" },
    ] } })) });
    const html = h.el.main!.innerHTML;
    expect(html).toContain('data-anomaly-findings');
    expect(html).toContain('1 open');
    expect(html).toContain('Unusual outbound volume');
    expect(html).toContain('data-mfp-findings');
  });
  it("6b retains at most the record cap from each roster, findings and policy snapshot", async () => {
    const h = await mfpBoot("findings", s => {
      s.findings = Array.from({ length: 501 }, (_, i) => ({ ...s.findings[0]!, finding_id: 'f-' + i }));
      s.roster.nodes = Array.from({ length: 501 }, (_, i) => ({ ...s.roster.nodes[0]!, node_id: 'node-' + i }));
      s.policy.lines = Array.from({ length: 501 }, (_, i) => ({ ...s.policy.lines[0]!, text: 'Policy line ' + i }));
    });
    h.navigate('machines'); await settle();
    h.navigate('policy'); await settle();
    // The render pages within the cap too, so only the retained state shows whether a snapshot was cut on arrival.
    expect(runInContext("state.mfp.findings.length", h.context)).toBe(500);
    expect(runInContext("state.mfp.totals.findings", h.context)).toBe(501);
    expect(runInContext("state.mfp.roster.nodes.length", h.context)).toBe(500);
    expect(runInContext("state.policyView.view.lines.length", h.context)).toBe(500);
  });
  it("6b each finding row shows the served alert as High, warn as Medium and info as Info", async () => {
    const h = await mfpBoot("findings");
    const html = h.el.main!.innerHTML;
    const row = (summary: string) => (html.match(new RegExp('<tr[^>]*>(?:(?!</tr>)[\\s\\S])*' + summary + '(?:(?!</tr>)[\\s\\S])*</tr>')) || [''])[0];
    expect(row('alert outbound observation')).toContain('mfp-severity high');
    expect(row('alert outbound observation')).toContain('>High<');
    expect(row('warn outbound observation')).toContain('mfp-severity medium');
    expect(row('info outbound observation')).toContain('mfp-severity info');
  });
  it("6b roster trust verdicts never render a green chip", async () => {
    const h = await mfpBoot("machines", s => {
      s.roster.nodes = ['admitted', 'revoked', 'untrusted'].map((trust_state, i) => ({ ...s.roster.nodes[0]!, node_id: 'node-' + i, trust_state, reach: 'recent', policy: { drift_state: 'in_sync' } })) as never;
    });
    const roster = (h.el.main!.innerHTML.match(/<section class="card" data-mfp-roster>[\s\S]*?<\/section>/) || [''])[0];
    expect(roster).toContain('ADMITTED');
    expect(roster).toContain('REVOKED');
    expect(roster).not.toContain('state-chip good');
  });
  it("6b escapes hostile roster labels and node ids", async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const h = await mfpBoot("machines", s => { s.roster.nodes[0]!.label = hostile; s.roster.nodes[0]!.node_id = hostile + '-id'; });
    const html = h.el.main!.innerHTML;
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain(hostile);
  });
  it("6b the evidence drawer previews at most the evidence character limit", async () => {
    const h = await mfpBoot("findings", s => { s.findings[1]!.details = { evidence: 'z'.repeat(20 * 1024) }; });
    h.click({ 'data-action': 'mfp-finding', 'data-finding-id': 'finding-alert' });
    const pre = (h.el.main!.innerHTML.match(/<pre>([\s\S]*?)<\/pre>/) || ['', ''])[1]!;
    const previewed = (pre.match(/z/g) || []).length;
    expect(previewed).toBeGreaterThan(0);
    expect(previewed).toBeLessThanOrEqual(16 * 1024);
    expect(h.el.main!.innerHTML).toContain('Evidence preview truncated at ' + 16 * 1024 + ' characters of');
  });
  it("6b refuses roster entries whose node id or label is not text", async () => {
    for (const change of [
      (n: Record<string, unknown>) => { n.node_id = 7; },
      (n: Record<string, unknown>) => { n.label = { text: 'Build box' }; },
    ]) {
      const h = await mfpBoot("machines", s => { change(s.roster.nodes[0] as never); });
      expect(h.el.main!.innerHTML).toContain('Fleet roster Unknown');
    }
  });

  // Round 2: public read behavior and reachable per-item controls.
  const r2Sources = [
    { route: 'machines', path: '/api/fleet/roster', key: 'roster', unknown: 'Fleet roster Unknown', old: 'Build box', read: 'fetchMfpRead("/api/fleet/roster", "roster")' },
    { route: 'findings', path: '/api/sentinels/findings', key: 'findings', unknown: 'Sentinel findings Unknown', old: 'alert outbound observation', read: 'fetchMfpRead("/api/sentinels/findings", "findings")' },
    { route: 'policy', path: '/api/policy/current', key: 'policy', unknown: 'Policy Unknown', old: 'export your saved state off the machine', read: 'readPolicyView()' },
  ];
  function r2Body(key: string, label?: string) {
    const s = mfpScenario();
    if (label) { s.roster.nodes[0]!.label = label; s.findings[0]!.summary = label; s.policy.lines[0]!.text = label; }
    return key === 'roster' ? s.roster : { data: key === 'findings' ? { findings: s.findings } : { view: s.policy } };
  }
  function r2Retry(h: Awaited<ReturnType<typeof mfpBoot>>, path: string) {
    const button = h.el.main!.querySelector('[data-action="retry-panel"][data-read="' + path + '"]');
    expect(button, 'rendered retry for ' + path).not.toBeNull();
    h.click(button!.attrs);
  }
  for (const source of r2Sources) {
    it('6b r2 retries a rejected ' + source.key + ' read exactly once', async () => {
      const read = vi.fn(() => Promise.reject(new Error('offline')));
      const h = await mfpBoot(source.route, undefined, { [source.path]: read });
      expect(h.el.main!.innerHTML).toContain(source.unknown);
      const before = read.mock.calls.length;
      r2Retry(h, source.path); await settle();
      expect(read.mock.calls.length).toBe(before + 1);
    });
    it('6b r2 rejects malformed ' + source.key + ' records with a retry control', async () => {
      const body = source.key === 'roster' ? { available: true, nodes: [null] }
        : { data: source.key === 'findings' ? { findings: [null] } : { view: { lines: [null] } } };
      const h = await mfpBoot(source.route, undefined, { [source.path]: () => Promise.resolve(response(body)) });
      expect(h.el.main!.innerHTML).toContain(source.unknown);
      expect(runInContext('sourceLoaded(' + JSON.stringify(source.path) + ')', h.context)).toBe(false);
      expect(h.el.main!.querySelector('[data-action="retry-panel"][data-read="' + source.path + '"]')).not.toBeNull();
    });
    it('6b r2 drops the ' + source.key + ' snapshot and total after refresh failure', async () => {
      let failed = false;
      const h = await mfpBoot(source.route, undefined, { [source.path]: () => failed ? Promise.reject(new Error('offline')) : Promise.resolve(response(r2Body(source.key))) });
      expect(h.el.main!.innerHTML).toContain(source.old);
      failed = true;
      h.click({ 'data-action': 'retry-panel', 'data-read': source.path }); await settle();
      expect(h.el.main!.innerHTML).toContain(source.unknown);
      expect(h.el.main!.innerHTML).not.toContain(source.old);
      expect(h.el.main!.querySelector('[data-action="retry-panel"][data-read="' + source.path + '"]')).not.toBeNull();
      expect(runInContext('state.mfp.totals.' + source.key, h.context)).toBe(0);
      expect(runInContext(source.key === 'policy' ? 'state.policyView.view' : 'state.mfp.' + source.key, h.context)).toEqual(source.key === 'findings' ? [] : null);
    });
    it('6b r2 times out the ' + source.key + ' read with a retry control', async () => {
      const h = await mfpBoot(source.route, undefined, { [source.path]: never });
      await vi.advanceTimersByTimeAsync(runInContext('DASHBOARD_READ_DEADLINE_MS + 1', h.context));
      await settle();
      expect(h.el.main!.innerHTML).toContain(source.unknown);
      expect(h.el.main!.innerHTML).toContain('Read timed out');
      expect(runInContext('sourceLoaded(' + JSON.stringify(source.path) + ')', h.context)).toBe(false);
      expect(h.el.main!.querySelector('[data-action="retry-panel"][data-read="' + source.path + '"]')).not.toBeNull();
    });
    it('6b r2 rejects an oversized ' + source.key + ' body with a retry control', async () => {
      // Padding exceeds the two MiB body budget without relying on a field-length validator.
      const body = { ...r2Body(source.key), padding: 'x'.repeat(2 * 1024 * 1024) };
      const h = await mfpBoot(source.route, undefined, { [source.path]: () => Promise.resolve(response(body)) });
      expect(h.el.main!.innerHTML).toContain(source.unknown);
      expect(h.el.main!.querySelector('[data-action="retry-panel"][data-read="' + source.path + '"]')).not.toBeNull();
    });
    for (const outcome of ['success', 'failure']) {
      it('6b r2 ignores older ' + source.key + ' ' + outcome + ' after the newer read loads', async () => {
        let wave = false;
        const pending: Array<{ resolve: (value: unknown) => void; reject: (error: Error) => void }> = [];
        const h = await mfpBoot(source.route, undefined, { [source.path]: () => wave ? new Promise((resolve, reject) => pending.push({ resolve, reject })) : Promise.resolve(response(r2Body(source.key))) });
        wave = true;
        const a = runInContext(source.read, h.context); await settle();
        const b = runInContext(source.read, h.context); await settle();
        expect(pending).toHaveLength(2);
        pending[1]!.resolve(response(r2Body(source.key, 'newer snapshot'))); await b; await settle();
        if (outcome === 'success') pending[0]!.resolve(response(r2Body(source.key, 'older snapshot')));
        else pending[0]!.reject(new Error('old failure'));
        await a; await settle();
        runInContext('rerender()', h.context);
        expect(h.el.main!.innerHTML).toContain('newer snapshot');
        expect(h.el.main!.innerHTML).not.toContain('older snapshot');
        expect(runInContext('sourceLoaded(' + JSON.stringify(source.path) + ')', h.context)).toBe(true);
      });
    }
    it('6b keeps the ' + source.key + ' snapshot for the trailing read when a queued refresh supersedes the read', async () => {
      let wave = false;
      const pending: Array<{ resolve: (value: unknown) => void; reject: (error: Error) => void }> = [];
      const h = await mfpBoot(source.route, undefined, { [source.path]: () => wave ? new Promise((resolve, reject) => pending.push({ resolve, reject })) : Promise.resolve(response(r2Body(source.key))) });
      const total = runInContext('state.mfp.totals.' + source.key, h.context);
      expect(total).toBeGreaterThan(0);
      wave = true;
      const job = source.key === 'policy' ? 'policyPanelJob' : 'panelJobs.find(function (job) { return job.paths[0] === ' + JSON.stringify(source.path) + '; })';
      // Two refreshes, as two stream events queue them: the first starts a read and the second supersedes it.
      const first = runInContext('queuePanel(' + job + ')', h.context); await settle();
      const trailing = runInContext('queuePanel(' + job + ')', h.context); await settle();
      expect(pending).toHaveLength(1);
      pending[0]!.resolve(response(r2Body(source.key, 'superseded snapshot'))); await first; await settle();
      expect(runInContext('sourceRead(' + JSON.stringify(source.path) + ').state', h.context)).not.toBe('state_FAILED');
      expect(runInContext('state.mfp.totals.' + source.key, h.context)).toBe(total);
      expect(pending).toHaveLength(2);
      pending[1]!.resolve(response(r2Body(source.key, 'trailing snapshot'))); await trailing; await settle();
      runInContext('rerender()', h.context);
      expect(h.el.main!.innerHTML).toContain('trailing snapshot');
      expect(h.el.main!.innerHTML).not.toContain('superseded snapshot');
      expect(runInContext('sourceLoaded(' + JSON.stringify(source.path) + ')', h.context)).toBe(true);
    });
    it('6b leaves the ' + source.key + ' read Unknown when an older success lands after a newer failure', async () => {
      let wave = false;
      const pending: Array<{ resolve: (value: unknown) => void; reject: (error: Error) => void }> = [];
      const h = await mfpBoot(source.route, undefined, { [source.path]: () => wave ? new Promise((resolve, reject) => pending.push({ resolve, reject })) : Promise.resolve(response(r2Body(source.key))) });
      wave = true;
      const a = runInContext(source.read, h.context); await settle();
      const b = runInContext(source.read, h.context); await settle();
      expect(pending).toHaveLength(2);
      pending[1]!.reject(new Error('newer failure')); await b; await settle();
      pending[0]!.resolve(response(r2Body(source.key, 'older snapshot'))); await a; await settle();
      runInContext('rerender()', h.context);
      expect(h.el.main!.innerHTML).toContain(source.unknown);
      expect(h.el.main!.innerHTML).not.toContain('older snapshot');
      expect(runInContext('sourceLoaded(' + JSON.stringify(source.path) + ')', h.context)).toBe(false);
    });
    it('6b keeps the ' + source.key + ' snapshot for the trailing read when a superseded read fails', async () => {
      let wave = false;
      const pending: Array<{ resolve: (value: unknown) => void; reject: (error: Error) => void }> = [];
      const h = await mfpBoot(source.route, undefined, { [source.path]: () => wave ? new Promise((resolve, reject) => pending.push({ resolve, reject })) : Promise.resolve(response(r2Body(source.key))) });
      const total = runInContext('state.mfp.totals.' + source.key, h.context);
      expect(total).toBeGreaterThan(0);
      wave = true;
      const job = source.key === 'policy' ? 'policyPanelJob' : 'panelJobs.find(function (job) { return job.paths[0] === ' + JSON.stringify(source.path) + '; })';
      const first = runInContext('queuePanel(' + job + ')', h.context); await settle();
      const trailing = runInContext('queuePanel(' + job + ')', h.context); await settle();
      expect(pending).toHaveLength(1);
      // The superseded read fails instead of succeeding; the trailing read still owns the source.
      pending[0]!.reject(new Error('superseded failure')); await first; await settle();
      expect(runInContext('sourceRead(' + JSON.stringify(source.path) + ').state', h.context)).not.toBe('state_FAILED');
      expect(runInContext('state.mfp.totals.' + source.key, h.context)).toBe(total);
      expect(pending).toHaveLength(2);
      pending[1]!.resolve(response(r2Body(source.key, 'trailing snapshot'))); await trailing; await settle();
      runInContext('rerender()', h.context);
      expect(h.el.main!.innerHTML).toContain('trailing snapshot');
      expect(runInContext('sourceLoaded(' + JSON.stringify(source.path) + ')', h.context)).toBe(true);
    });
  }
  it('6b keeps an open finding through two activity frames that supersede its read', async () => {
    let wave = false;
    const pending: Array<{ resolve: (value: unknown) => void; reject: (error: Error) => void }> = [];
    const h = await mfpBoot('findings', undefined, { '/api/sentinels/findings': () => wave ? new Promise((resolve, reject) => pending.push({ resolve, reject })) : Promise.resolve(response(r2Body('findings'))) });
    h.click({ 'data-action': 'mfp-finding', 'data-finding-id': 'finding-alert' });
    expect(h.el.main!.innerHTML).toContain('aria-label="Finding evidence"');
    wave = true;
    // The activity frame handler queues this refresh through queueStreamRefresh; two frames arrive during one read.
    const first = runInContext('queueStreamRefresh(["/api/sentinels/findings"])', h.context); await settle();
    const second = runInContext('queueStreamRefresh(["/api/sentinels/findings"])', h.context); await settle();
    expect(pending).toHaveLength(1);
    pending[0]!.resolve(response(r2Body('findings'))); await settle();
    expect(pending).toHaveLength(2);
    pending[1]!.resolve(response(r2Body('findings'))); await first; await second; await settle();
    expect(runInContext('state.mfp.findingId', h.context)).toBe('finding-alert');
    expect(h.el.main!.innerHTML).toContain('aria-label="Finding evidence"');
  });
  it('6b keeps an open finding when a read superseded by two activity frames fails', async () => {
    let wave = false;
    const pending: Array<{ resolve: (value: unknown) => void; reject: (error: Error) => void }> = [];
    const h = await mfpBoot('findings', undefined, { '/api/sentinels/findings': () => wave ? new Promise((resolve, reject) => pending.push({ resolve, reject })) : Promise.resolve(response(r2Body('findings'))) });
    h.click({ 'data-action': 'mfp-finding', 'data-finding-id': 'finding-alert' });
    expect(h.el.main!.innerHTML).toContain('aria-label="Finding evidence"');
    wave = true;
    const first = runInContext('queueStreamRefresh(["/api/sentinels/findings"])', h.context); await settle();
    const second = runInContext('queueStreamRefresh(["/api/sentinels/findings"])', h.context); await settle();
    expect(pending).toHaveLength(1);
    pending[0]!.reject(new Error('superseded failure')); await settle();
    expect(runInContext('state.mfp.findingId', h.context)).toBe('finding-alert');
    expect(pending).toHaveLength(2);
    pending[1]!.resolve(response(r2Body('findings'))); await first; await second; await settle();
    expect(runInContext('state.mfp.findingId', h.context)).toBe('finding-alert');
    expect(h.el.main!.innerHTML).toContain('aria-label="Finding evidence"');
  });
  it('6b closes the open finding when live updates stop, so a restart cannot reopen it', async () => {
    let wave = false;
    const pending: Array<{ resolve: (value: unknown) => void; reject: (error: Error) => void }> = [];
    const h = await mfpBoot('findings', undefined, { '/api/sentinels/findings': () => wave ? new Promise((resolve, reject) => pending.push({ resolve, reject })) : Promise.resolve(response(r2Body('findings'))) });
    h.click({ 'data-action': 'mfp-finding', 'data-finding-id': 'finding-alert' });
    expect(h.el.main!.innerHTML).toContain('aria-label="Finding evidence"');
    wave = true;
    // A stop lands while a findings read is in flight; that read then returns the same finding.
    const read = runInContext('queueStreamRefresh(["/api/sentinels/findings"])', h.context); await settle();
    expect(pending).toHaveLength(1);
    runInContext('stopLiveUpdates()', h.context);
    pending[0]!.resolve(response(r2Body('findings'))); await read; await settle();
    expect(runInContext('state.mfp.findingId', h.context)).toBe(null);
    wave = false;
    // The operator's Retry restarts live updates and rereads every source, the same finding included.
    await runInContext('retryPanel("/api/sentinels/findings")', h.context); await settle();
    runInContext('rerender()', h.context);
    expect(runInContext('sourceLoaded("/api/sentinels/findings")', h.context)).toBe(true);
    expect(h.el.main!.innerHTML).not.toContain('aria-label="Finding evidence"');
  });
  it('6b r2 closes a selected finding through failure and recovery', async () => {
    let failed = false;
    const h = await mfpBoot('findings', undefined, { '/api/sentinels/findings': () => failed ? Promise.reject(new Error('offline')) : Promise.resolve(response(r2Body('findings'))) });
    h.click({ 'data-action': 'mfp-finding', 'data-finding-id': 'finding-alert' });
    expect(h.el.main!.innerHTML).toContain('aria-label="Finding evidence"');
    failed = true; h.click({ 'data-action': 'retry-panel', 'data-read': '/api/sentinels/findings' }); await settle();
    failed = false; r2Retry(h, '/api/sentinels/findings'); await settle();
    expect(h.el.main!.innerHTML).not.toContain('aria-label="Finding evidence"');
    expect(runInContext('state.mfp.findingId', h.context)).toBeNull();
  });
  it('6b r2 renders only server severity values and keeps all five legend words', async () => {
    const h = await mfpBoot('findings', s => {
      s.findings = ['critical', 'low', 'high', 'medium', 'other', 'info', 'warn', 'alert'].map((severity, i) => ({ ...s.findings[0]!, severity, finding_id: 'severity-' + i, summary: 'Observation ' + i })) as never;
    });
    const html = h.el.main!.innerHTML;
    const legend = html.match(/<div class="mfp-legend"[\s\S]*?<\/div>/)![0];
    for (const word of ['Critical', 'High', 'Medium', 'Low', 'Info']) expect(legend).toContain('>' + word + '<');
    expect(html).toContain('Critical and Low are display levels not emitted');
    const rows = html.match(/<tbody>([\s\S]*?)<\/tbody>/)![1]!;
    for (let i = 0; i < 5; i++) {
      const row = rows.split('</tr>').find(row => row.includes('Observation ' + i))!;
      expect(row).toContain('UNKNOWN');
      expect(row).not.toMatch(/mfp-severity|>Critical<|>High<|>Medium<|>Low<|>Info</);
    }
    expect(rows.indexOf('Observation 5')).toBeLessThan(rows.indexOf('Observation 0'));
    expect(rows).not.toMatch(/>Critical<|>Low</);
  });
  for (const agent of [null, '', undefined]) {
    it('6b r2 leaves unserved agent scope unknown for ' + String(agent), async () => {
      const h = await mfpBoot('findings', s => { s.findings = [{ ...s.findings[0]!, agent_id: agent }] as never; });
      expect(h.el.main!.innerHTML).toContain('Unknown · agent not served');
      h.click({ 'data-action': 'mfp-finding', 'data-finding-id': 'finding-info' });
      const drawer = h.el.main!.innerHTML.match(/<aside class="mfp-drawer"[\s\S]*?<\/aside>/)![0];
      expect(drawer).toContain('Unknown · agent not served');
      expect(h.el.main!.innerHTML).not.toContain('Fortress-wide');
    });
  }
  it('6b r2 distinguishes unevaluable and proven untrusted nodes', async () => {
    const h = await mfpBoot('machines', s => { s.roster.nodes = [false, true].map((trust_evaluable, i) => ({ ...s.roster.nodes[0]!, node_id: 'node-' + i, trust_state: 'untrusted', trust_evaluable })); });
    // Main's overviewChip wraps the glyph and word in an overview-chip-head span; the chip state and word are what this pins.
    expect(h.el.main!.innerHTML).toMatch(/state-chip warn[^>]*><span class="overview-chip-head"><i[^>]*><\/i>NOT EVALUATED/);
    expect(h.el.main!.innerHTML).toContain('Trust could not be evaluated; treated as untrusted');
    expect(h.el.main!.innerHTML).toMatch(/state-chip bad[^>]*><span class="overview-chip-head"><i[^>]*><\/i>UNTRUSTED/);
    expect(h.el.main!.innerHTML).not.toContain('state-chip good');
  });
  it('6b r2 rejects a nonboolean trust evaluation flag', async () => {
    const h = await mfpBoot('machines', s => { Object.assign(s.roster.nodes[0]!, { trust_evaluable: 'false' }); });
    expect(h.el.main!.innerHTML).toContain('Fleet roster Unknown');
    expect(h.el.main!.innerHTML).not.toContain('Build box');
    expect(h.el.main!.querySelector('[data-action="retry-panel"][data-read="/api/fleet/roster"]')).not.toBeNull();
  });
  it('6b r2 uses the shared policy heading and template severities', async () => {
    const h = await mfpBoot('policy');
    expect(h.el.main!.innerHTML).toContain('<h3>Always asks you first</h3>');
    expect(h.el.main!.innerHTML).not.toContain('What asks you first');
    expect(h.el.main!.innerHTML).toContain('<span class="severity medium">MEDIUM</span>');
    expect(h.el.main!.innerHTML).toContain('<span class="severity low">LOW</span>');
  });



  it('A2 empty trap reads omit both pagers while one trap retains its pager', async () => {
    let populated = false;
    const h = await mfpBoot('honeypot', undefined, {
      '/api/honeypot/tool-traps': () => Promise.resolve(response({ data: { traps: populated ? [{ fake_tool_name: 'tool-one' }] : [] } })),
      '/api/honeypot/credential-traps': () => Promise.resolve(response({ data: { traps: populated ? [{ fake_credential_name: 'credential-one' }] : [] } })),
    });
    expect(h.el.main!.innerHTML).toContain('No tool-call traps deployed.');
    expect(h.el.main!.innerHTML).toContain('No credential traps deployed.');
    expect(h.el.main!.innerHTML).not.toContain('Showing 0 of 0');
    expect(h.el.main!.innerHTML).not.toContain('mfp-pager');
    populated = true;
    await runInContext('fetchAll(true)', h.context); await settle();
    expect(h.el.main!.innerHTML.match(/Showing 1 of 1/g)).toHaveLength(2); // One pager for each populated trap list.
  });
  it('A2 empty agents omit the Policy rules pager while a populated read retains it', async () => {
    const h = await mfpBoot('policy', s => { s.agents = []; });
    const panel = () => h.el.main!.innerHTML.split('<h2>Per-agent rules</h2>')[1]!.split('</section>')[0]!;
    expect(panel()).toContain('No protected agents yet.');
    expect(panel()).not.toContain('Showing 0 of 0');
    expect(panel()).not.toContain('mfp-pager');
    const populated = await mfpBoot('policy');
    expect(populated.el.main!.innerHTML.split('<h2>Per-agent rules</h2>')[1]).toContain('Showing 1 of 1');
  });
  it('6b r2 leaves an empty policy read without a pager', async () => {
    const h = await mfpBoot('policy', s => { s.policy.lines = []; });
    const panel = h.el.main!.innerHTML.split('data-mfp-policy')[1]!.split('Channel templates')[0]!;
    expect(panel).toContain('No policy lines returned');
    expect(panel).not.toContain('Showing 0 of 0');
    expect(panel).not.toContain('mfp-pager');
  });
  for (const list of [
    { key: 'rules', route: 'auto-trigger', path: '/api/auto-trigger/rules', field: 'rules', row: (i: number) => ({ rule_id: 'rule-' + i, history: [] }), marker: 'rule-26', controls: ['auto-trigger-threshold-save'] },
    { key: 'recommendations', route: 'auto-trigger', path: '/api/auto-trigger/recommendations', field: 'recommendations', row: (i: number) => ({ rule_id: 'recommendation-' + i }), marker: 'recommendation-26', controls: ['auto-trigger-accept', 'auto-trigger-reject'] },
    { key: 'credentialTraps', route: 'honeypot', path: '/api/honeypot/credential-traps', field: 'traps', row: (i: number) => ({ fake_credential_name: 'credential-' + i }), marker: 'credential-26', controls: [] },
    { key: 'toolTraps', route: 'honeypot', path: '/api/honeypot/tool-traps', field: 'traps', row: (i: number) => ({ fake_tool_name: 'tool-' + i }), marker: 'tool-26', controls: [] },
  ]) {
    it('6b r2 pages all ' + list.key + ' on both folded screens and the standalone route', async () => {
      const rows = Array.from({ length: 26 }, (_, i) => list.row(i + 1)); // One beyond the 25-row page.
      const h = await mfpBoot('findings', undefined, { [list.path]: () => Promise.resolve(response({ data: { [list.field]: rows } })) });
      // Rule detail hydration is serial, so drain its bounded fixture wave before paging.
      for (let i = 0; i < rows.length; i++) await settle();
      for (const route of ['findings', 'policy', list.route]) {
        runInContext('state.mfp.pages.' + list.key + ' = 0', h.context);
        h.navigate(route); await settle(); runInContext('rerender()', h.context);
        expect(h.el.main!.innerHTML).not.toContain(list.marker);
        expect(h.el.main!.querySelector('[data-action="mfp-page"][data-list="' + list.key + '"][data-step="1"]')).not.toBeNull();
        h.click({ 'data-action': 'mfp-page', 'data-list': list.key, 'data-step': '1' });
        expect(h.el.main!.innerHTML).toContain(list.marker);
        for (const action of list.controls) expect(h.el.main!.innerHTML).toContain('data-action="' + action + '" data-rule-id="' + list.marker + '"');
        runInContext('state.mfp.pages.' + list.key + ' = 999; rerender()', h.context); // Deliberately beyond the last page.
        expect(h.el.main!.innerHTML).toContain(list.marker);
        expect(runInContext('state.mfp.pages.' + list.key, h.context)).toBe(1);
      }
      // Per-item controls remain reachable beyond the main snapshot cap too.
      const extra = Array.from({ length: 501 }, (_, i) => list.row(i + 1));
      h.context.r2Rows = extra;
      const target = list.route === 'honeypot' ? 'state.honeypot.' + list.key : 'state.autoTrigger.' + list.key;
      runInContext(target + ' = r2Rows; state.mfp.pages.' + list.key + ' = 19; rerender()', h.context);
      h.click({ 'data-action': 'mfp-page', 'data-list': list.key, 'data-step': '1' });
      expect(h.el.main!.innerHTML).toContain(list.marker.replace('26', '501'));
      expect(h.el.main!.innerHTML).toContain('Page 21 of 21');
      expect(h.el.main!.innerHTML).not.toContain('Only the first 500');
    });
  }

});

describe("Read-only extraction: Approvals follow-ups", () => {
  const pageCap = 100; // One inbox page, must match HUB_INBOX_DEFAULT_LIMIT in hub/constants.ts.
  const tier2 = { ...heldItem, tier: "tier2", operation_category: "state_export" };
  const other = { ...tier2, item_id: "other", agent_id: "other-agent" };
  const inbox = (items: unknown[]) => () => Promise.resolve(response({ data: { items } }));
  const drawer = (h: ReturnType<typeof boot>) => h.el.main!.innerHTML.split('<aside class="card approval-drawer"')[1] || "";
  const badge = (h: ReturnType<typeof boot>) => h.el.fortress!.innerHTML.match(/id="queue-count">([^<]*)</)![1];
  const stat = (h: ReturnType<typeof boot>) => h.el.fortress!.innerHTML.match(/<span class="n">([^<]*)<\/span><span class="l">Waiting</)![1];
  const others = (count: number) => Array.from({ length: count }, (_, i) => ({ ...other, item_id: `notice-${i}`, kind: "blocked_egress" }));
  const scope = (h: ReturnType<typeof boot>, id: string) => h.click({ "data-action": "agent-scope-select", "data-agent-id": id });

  for (const full of [false, true]) {
    it(`shares scoped zero and recognized denominator on every waiting count, full=${full}`, async () => {
      vi.useFakeTimers();
      const outsideCount = 3; // The three holds are all outside the selected agent scope.
      const items = Array.from({ length: outsideCount }, (_, i) => ({ ...other, item_id: `held-${i}` }));
      const h = boot({ "/api/hub/inbox": inbox([...items, ...(full ? others(pageCap - outsideCount) : [])]) });
      await settle(); h.navigate("approvals"); scope(h, "empty-agent");
      const count = full ? "0+ of 3+" : "0 of 3";
      expect(badge(h)).toBe(count);
      expect(stat(h)).toBe(count);
      expect(h.el["rail-approvals-count"]!.textContent).toBe(count);
      expect(h.el["notify-count"]!.innerHTML).toContain(count);
      for (const element of [h.railLink, h.el["btn-notifications"]!]) {
        for (const attr of ["title", "aria-label"]) {
          // Full-page sentences now bound the observed counts to the served page, preserving the scoped denominator.
          expect(element.getAttribute(attr)).toContain(full ? `0 of 3 held operations in the first ${pageCap} inbox items wait on you` : "0 of 3 held operations wait on you");
          if (full) expect(element.getAttribute(attr)).toContain("a held operation may be waiting past them");
        }
      }
      h.navigate("dashboard");
      expect(badge(h)).toBe(count); expect(stat(h)).toBe(count);
    });
  }

  it("keeps unrecognized tiers separate and uses singular summaries and accessible names", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox([tier2, { ...other, tier: "tier9" }]) });
    await settle(); h.navigate("approvals"); scope(h, tier2.agent_id);
    expect(badge(h)).toBe("1"); expect(stat(h)).toBe("1");
    expect(h.el.fortress!.innerHTML).toContain("1 held operation waiting.");
    expect(h.el.fortress!.innerHTML).toContain("1 held item carries a tier");
    for (const el of [h.railLink, h.el["btn-notifications"]!]) {
      expect(el.getAttribute("aria-label")).toContain("1 of 1 held operation waits on you");
      expect(el.getAttribute("title")).toContain("1 of 1 held operation waits on you");
    }
    const filter = new FakeElement({ "data-action": "approval-filter-state" }, "SELECT");
    filter.value = "decided"; h.change(filter);
    expect(drawer(h)).toContain("1 held operation in this scope is waiting on you.");
  });

  it("puts outside holds above a scoped decided-only table", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": inbox([{ ...tier2, resolved: true }, other]) });
    await settle(); h.navigate("approvals"); scope(h, tier2.agent_id);
    const queue = h.el.main!.innerHTML.split('<aside')[0]!;
    expect(queue).toContain("1 held operation waits outside this agent scope");
    expect(queue.indexOf("outside this agent scope")).toBeLessThan(queue.indexOf('<table class="approval-table">'));
    expect(queue).toContain('data-approval-row="item-1"');
  });

  for (const kind of ["non-hold", "decided", "unrecognized"]) {
    it(`Overview reuses the lower-bound line on a full ${kind} page without a calm zero`, async () => {
      vi.useFakeTimers();
      const items = others(pageCap);
      if (kind !== "non-hold") items[0] = { ...tier2, item_id: "edge", resolved: kind === "decided", tier: kind === "unrecognized" ? "tier9" : "tier2" };
      let hasAgent = true;
      const h = boot({ "/api/hub/inbox": inbox(items), "/api/posture/home": () => Promise.resolve(response({ ...home(), agents: hasAgent ? [{ agent_id: "fixture-agent" }] : [] })) }); await settle(); h.navigate("posture");
      const card = h.el.main!.innerHTML.split('Needs your decision')[1]!.split('</section>')[0]!;
      const line = runInContext('approvalQueueEvidence().line', h.context) as string;
      expect(card).toContain(line);
      expect(card).not.toMatch(/0 of 0|No approvals waiting|Nothing waiting on you|qe-check/);
      if (kind !== "non-hold") expect(line).toContain("No recognized held operation is waiting in this page.");
      h.navigate("approvals");
      // A decided row has its own drawer; the queue still carries its full-page notice instead of an empty drawer sentence.
      expect(h.el.main!.innerHTML).toContain("held operations beyond it are not shown here.");
      if (kind !== "decided") expect(h.el.main!.innerHTML).toContain(line);
      expect(h.el.fortress!.innerHTML).toContain(line);
      hasAgent = false; await runInContext('fetchAll(true)', h.context); h.navigate("posture");
      expect(h.el.main!.innerHTML).toContain("Needs your decision");
      expect(h.el.main!.innerHTML).toContain(line);
    });
  }

  for (const active of [["range"], ["server"], ["search"], ["range", "server"], ["range", "search"], ["server", "search"], ["range", "server", "search"]]) {
    it(`Evidence no-match guidance names only active filters: ${active.join(", ")}`, async () => {
      vi.useFakeTimers();
      const h = boot({ "/api/posture/evidence": () => Promise.resolve(response({ entries: [], total: 0, integrity_findings: [] })) });
      await settle(); h.navigate("activity");
      if (active.includes("range")) {
        const range = new FakeElement({ "data-action": "time-range" }, "SELECT"); range.value = "24h"; h.change(range);
      }
      const query = active.includes("search") ? "absent" : "";
      h.navigate("activity?" + new URLSearchParams({ ...(active.includes("server") ? { agent: "absent" } : {}), ...(query ? { q: query } : {}) }).toString());
      await settle();
      const empty = h.el.main!.innerHTML.match(/<h3>No entries match this view<\/h3><p>([^<]*)<\/p>([\s\S]*?)<\/div>/)!;
      expect(empty).not.toBeNull();
      const names: string[] = active.map(a => a === "range" ? "time range" : a === "server" ? "server filters" : "page-local search");
      expect(empty[1]).toContain("Active filters: " + names.join(", ") + ". No matches on this page.");
      for (const name of ["time range", "server filters", "page-local search"].filter(n => !names.includes(n))) expect(empty[1]).not.toContain(name);
      if (active.length === 1 && active[0] === "range") {
        expect(empty[1]).toContain("Change the time range in the top bar.");
        expect(empty[2]).not.toContain('href="#activity"'); expect(empty[2]).not.toContain("Clear filters");
      } else expect(empty[2]).toContain('href="#activity">Clear filters</a>');
    });
  }
});

describe("Read-only extraction: Approvals round-two surface evidence", () => {
  const pageCap = 100; // Must match APPROVAL_QUEUE_ITEM_CAP in client.ts and HUB_INBOX_DEFAULT_LIMIT in hub/constants.ts.
  const recognized = (count: number) => Array.from({ length: count }, (_, i) => ({ ...heldItem, item_id: `recognized-${i}` }));
  const unknown = (count: number) => recognized(count).map(i => ({ ...i, tier: "tier9" }));
  const fullPage = (holds: ReturnType<typeof recognized>) => holds.concat(Array.from({ length: pageCap - holds.length }, (_, i) => ({ ...heldItem, item_id: `notice-${i}`, kind: "blocked_egress" })));
  const bootItems = async (items: unknown[]) => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
      "/api/posture/home": () => Promise.resolve(response({ ...home(), agents: [{ agent_id: heldItem.agent_id }] })),
    });
    await settle(); h.navigate("posture");
    return h;
  };
  const tile = (h: ReturnType<typeof boot>) => h.el.main!.innerHTML.split('>Approvals waiting</a>')[1]!.split('</div>')[0]!;
  const tierWarning = (count: number) => count === 1 ? "1 held item carries a tier this console does not recognize" : `${count} held items carry a tier this console does not recognize`;
  const openSeal = (h: ReturnType<typeof boot>) => {
    const stopPropagation = vi.fn();
    h.click({ "data-action": "posture-seal-toggle" }, [], false, { stopPropagation });
    expect(stopPropagation).toHaveBeenCalledOnce();
    expect(h.el["posture-seal-pop"]!.hidden).toBe(false);
  };


  for (const shape of ['unrecognized-only', 'full-page-none']) {
    it(`A2 ${shape} uses unknown count styles while earned empty and recognized holds retain their styles`, async () => {
      const h = await bootItems(shape === 'unrecognized-only' ? unknown(1) : fullPage([]));
      expect(h.el['rail-approvals-count']!.className).toBe('count unknown');
      // Retargeted in A2 round 2: an observed hold of a tier this console cannot decide keeps the waiting badge; only a
      // zero with nothing observed takes the unknown look.
      expect(h.el['notify-count']!.className).toBe(shape === 'unrecognized-only' ? 'wait' : 'wait unknown');
      expect(h.el['notify-count']!.hidden).toBe(false);
      const empty = await bootItems([]);
      expect(empty.el['rail-approvals-count']!.className).toBe('count');
      expect(empty.el['notify-count']!.className).toBe('wait');
      expect(empty.el['notify-count']!.hidden).toBe(true);
      const held = await bootItems(recognized(1));
      expect(held.el['rail-approvals-count']!.className).toBe('count hot');
      expect(held.el['notify-count']!.className).toBe('wait');
      expect(held.el['notify-count']!.hidden).toBe(false);
    });
  }
  it('A2 a scoped-empty queue with recognized holds elsewhere keeps the hot pill and the waiting badge', async () => {
    vi.useFakeTimers();
    const items = [{ ...heldItem, item_id: 'held-a', agent_id: 'fixture-agent-a' }, { ...heldItem, item_id: 'held-b', agent_id: 'fixture-agent-b' }];
    const model_provider = { vendor: 'fixture-vendor', model_id: 'fixture-model' };
    const agents = ['fixture-agent-a', 'fixture-agent-b', 'fixture-agent-c'].map(agent_id => ({ agent_id, status: 'active', model_provider }));
    const h = boot({ '/api/hub/inbox': () => Promise.resolve(response({ data: { items } })), '/api/hub/agents': () => Promise.resolve(response({ data: { agents } })) });
    await settle(); h.navigate('approvals');
    h.click({ 'data-action': 'agent-scope-select', 'data-agent-id': 'fixture-agent-c' });
    expect(h.el['rail-approvals-count']!.textContent).toBe('0 of 2');
    expect(h.el['rail-approvals-count']!.className).toBe('count hot');
    expect(h.el['notify-count']!.className).toBe('wait');
    expect(h.el['notify-count']!.hidden).toBe(false);
  });
  // fail-before-exempt: plant (!w.earned && !counted) as (w.full && !counted) in renderApprovalCounts; the redacted zero then reads calm.
  it('A2 a redacted zero takes the unknown pill and the unknown badge', async () => {
    vi.useFakeTimers();
    const h = boot({ '/api/hub/inbox': () => Promise.resolve(response({ data: { items: [], pending_approvals_redacted: true, pending_approvals_count: 0 } })) });
    await settle();
    expect(h.el['rail-approvals-count']!.className).toBe('count unknown');
    expect(h.el['notify-count']!.className).toBe('wait unknown');
    expect(Boolean(h.el['notify-count']!.hidden)).toBe(false);
  });
  it('A2 Overview decision card keeps the unknown-tier warning below recognized rows', async () => {
    const holds = recognized(2); // Two recognized rows plus one unknown hold exercise the mixed branch.
    const h = await bootItems([...holds, ...unknown(1)]);
    const card = h.el.main!.innerHTML.split('Needs your decision')[1]!.split('</section>')[0]!;
    expect(card).toContain('overview-table-decisions');
    expect(card.match(/data-overview-review=/g)).toHaveLength(holds.length);
    expect(card.split('</table>')[1]).toContain(tierWarning(1));
  });
  it('A2 rail and bell sentences end with a period for every summary branch', async () => {
    for (const items of [[], recognized(1), unknown(1), fullPage([])]) {
      const h = await bootItems(items);
      for (const el of [h.railLink, h.el['btn-notifications']!]) for (const attr of ['title', 'aria-label']) expect(el.getAttribute(attr)).toMatch(/\.$/);
    }
    for (const load of [never, () => Promise.resolve(response({ data: { items: [], pending_approvals_redacted: true, pending_approvals_count: 0 } }))]) {
      const h = boot({ '/api/hub/inbox': load }); await settle();
      for (const el of [h.railLink, h.el['btn-notifications']!]) for (const attr of ['title', 'aria-label']) expect(el.getAttribute(attr)).toMatch(/\.$/);
    }
  });
  it('A2 a full-page Waiting stat marks both observed counts as lower bounds', async () => {
    const h = await bootItems(fullPage(recognized(2))); // Two in-scope holds and no outside holds reach the omitted denominator.
    expect(h.el.fortress!.innerHTML).toContain('<span class="n">2+ of 2+</span><span class="l">Waiting</span>');
    const partial = await bootItems(recognized(2));
    expect(partial.el.fortress!.innerHTML).toContain('<span class="n">2</span><span class="l">Waiting</span>');
  });

  for (const count of [0, 2]) { // Zero and two distinguish absence from plural recognized holds.
    it(`Overview tile marks the fortress-wide full-page recognized count ${count} with its source bound`, async () => {
      const h = await bootItems(fullPage(recognized(count)));
      h.click({ "data-action": "agent-scope-select", "data-agent-id": "outside-agent" });
      expect(tile(h)).toContain(`<span class="ot-value">${count}+</span>`);
      expect(tile(h)).toContain(`from the first ${pageCap} inbox items`);
    });
  }
  for (const count of [1, 2]) { // Singular and plural unknown-tier wording are distinct product branches.
    it(`Overview tile qualifies zero with ${count} unrecognized-tier holds`, async () => {
      const h = await bootItems(unknown(count));
      expect(tile(h)).toContain(tierWarning(count) + " · ");
      expect(tile(h)).toContain('<span class="ot-value">0</span>');
    });
  }

  for (const count of [0, 1, 2]) { // Empty, singular and plural sentences each have a distinct grammar boundary.
    it(`rail and bell describe ${count} recognized holds within the full page and separate the page-edge sentence`, async () => {
      const h = await bootItems(fullPage(recognized(count)));
      for (const el of [h.railLink, h.el["btn-notifications"]!]) {
        for (const attr of ["title", "aria-label"]) {
          expect(el.getAttribute(attr)).toContain(`${count} of ${count} held ${count === 1 ? "operation" : "operations"} in the first ${pageCap} inbox items ${count === 1 ? "waits" : "wait"} on you`);
          expect(el.getAttribute(attr)).toMatch(/ · queue read [^.]+\. The inbox has at least/);
          expect(el.getAttribute(attr)).not.toContain("At least");
        }
      }
      expect(h.el["rail-approvals-count"]!.textContent).toBe(`${count}+ of ${count}+`);
      expect(h.el["notify-count"]!.innerHTML).toContain(`${count}+ of ${count}+`);
      expect(h.el["notify-count"]!.hidden).toBe(false);
    });
  }
  for (const count of [1, 2]) {
    it(`rail and bell name ${count} unrecognized-tier holds after the scope clause`, async () => {
      const h = await bootItems(unknown(count));
      h.click({ "data-action": "agent-scope-select", "data-agent-id": "outside-agent" });
      for (const el of [h.railLink, h.el["btn-notifications"]!]) {
        for (const attr of ["title", "aria-label"]) expect(el.getAttribute(attr)).toContain(`0 of 0 held operations wait on you (scoped to outside-agent); ${tierWarning(count)} · queue read `);
      }
      expect(h.el["notify-count"]!.hidden).toBe(false);
    });
  }

  // fail-before-exempt: plant earned: hidden === 0 in the redacted summary to hide the badge incorrectly.
  it("redacted zero keeps the badge visible and names the hidden queue", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [], pending_approvals_redacted: true, pending_approvals_count: 0 } })) });
    await settle();
    // Real DOM boolean properties coerce the base summary's absent earned field to false.
    expect(Boolean(h.el["notify-count"]!.hidden)).toBe(false);
    expect(h.el["btn-notifications"]!.classList.contains("waiting")).toBe(true);
    for (const el of [h.railLink, h.el["btn-notifications"]!]) {
      for (const attr of ["title", "aria-label"]) expect(el.getAttribute(attr)).toContain("hidden until you paste the operator token");
    }
  });

  it("Overview card header marks the recognized total on a full page as a lower bound", async () => {
    const holds = recognized(2); // Two holds fit in the Overview card without row truncation.
    const h = await bootItems(fullPage(holds));
    const header = h.el.main!.innerHTML.split('Needs your decision')[1]!.split('</h3>')[0]!;
    expect(header).toContain(`showing ${holds.length} of ${holds.length}+ · `);
  });

  // A positive server count deliberately disagrees with the empty served page; one entry takes the singular noun.
  for (const total of [7, 1]) it(`Evidence empty page with a total of ${total} and no filter states the server count and retries its read`, async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/posture/evidence": () => Promise.resolve(response({ origin_machine: "fixture", entries: [], total, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } })) });
    await settle();
    runInContext('state.timeRange = "all";', h.context); h.navigate("activity"); await settle();
    const entries = h.el.main!.innerHTML.split('aria-label="Entries"')[1]!.split('</section>')[0]!;
    expect(entries).toContain('<h3>No entries on this page</h3>');
    expect(entries).toContain(`The server counts ${total} ${total === 1 ? "entry" : "entries"} in this view, but this read shows none.`);
    expect(entries).not.toContain("No entries match this view");
    expect(entries).not.toContain("Clear filters");
    expect(entries).toContain('data-action="retry-panel" data-read="/api/posture/evidence"');
    const before = h.requests.filter(r => r.url.startsWith("/api/posture/evidence")).length;
    h.click({ "data-action": "retry-panel", "data-read": "/api/posture/evidence" }); await settle();
    expect(h.requests.filter(r => r.url.startsWith("/api/posture/evidence"))).toHaveLength(before + 1);
  });

  // AuditLog.query applies the range before total and paging, so a real range-only no-match read has total zero.
  for (const range of ["24h", "7d", "30d"]) it(`Evidence with the ${range} range, no rows and a zero total points to the range, not Retry`, async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/posture/evidence": () => Promise.resolve(response({ origin_machine: "fixture", entries: [], total: 0, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } })) });
    await settle();
    runInContext('state.timeRange = "' + range + '";', h.context); h.navigate("activity"); await settle();
    const entries = h.el.main!.innerHTML.split('aria-label="Entries"')[1]!.split('</section>')[0]!;
    expect(entries).toContain("No entries match this view");
    expect(entries).toContain("Active filters: time range.");
    expect(entries).toContain("Change the time range in the top bar.");
    expect(entries).not.toContain("No entries on this page");
    expect(entries).not.toContain('data-action="retry-panel"');
  });

  for (const count of [0, 1]) {
    it(`seal Charter approvals row warns about the full-page recognized count ${count}`, async () => {
      const h = await bootItems(fullPage(recognized(count)));
      h.click({ "data-action": "agent-scope-select", "data-agent-id": "outside-agent" });
      openSeal(h);
      const row = h.el["posture-seal-pop"]!.innerHTML.split('<div class="pp-line">').find(line => line.includes('Charter approvals</span>'))!;
      expect(row).toContain(`<span class="pp-v">${count}+ waiting</span>`);
      expect(row).toContain('class="pp-dot warn"');
    });
  }
  for (const count of [1, 2]) {
    it(`seal Charter approvals row separates ${count} unrecognized-tier holds from recognized waiting`, async () => {
      const h = await bootItems(unknown(count));
      openSeal(h);
      const row = h.el["posture-seal-pop"]!.innerHTML.split('Charter approvals</span>')[1]!.split('</div>')[0]!;
      expect(row).toContain(`<span class="pp-v">0 waiting; ${tierWarning(count)}</span>`);
      expect(h.el["posture-seal-pop"]!.innerHTML).toContain('class="pp-dot warn"></span><span class="pp-k">Charter approvals');
    });
  }
  // fail-before-exempt: plant the earned-empty Charter approvals value as "0 waiting" instead of "clear".
  it("seal Charter approvals is clear only with earned-empty evidence", async () => {
    const h = await bootItems([]);
    openSeal(h);
    expect(h.el["posture-seal-pop"]!.innerHTML).toContain('class="pp-dot"></span><span class="pp-k">Charter approvals</span><span class="pp-v">clear</span>');
    expect(tile(h)).toContain('<span class="ot-value">0</span>');
    expect(h.el["notify-count"]!.hidden).toBe(true);
    const waiting = await bootItems(recognized(1));
    openSeal(waiting);
    expect(waiting.el["posture-seal-pop"]!.innerHTML).toContain('class="pp-dot warn"></span><span class="pp-k">Charter approvals</span><span class="pp-v">1 waiting</span>');
    for (const mode of ["unloaded", "redacted"]) {
      const unavailable = boot({ "/api/hub/inbox": mode === "unloaded" ? never : () => Promise.resolve(response({ data: { items: [], pending_approvals_redacted: true, pending_approvals_count: 0 } })) });
      await settle(); openSeal(unavailable);
      expect(unavailable.el["posture-seal-pop"]!.innerHTML).toContain('class="pp-dot unknown"></span><span class="pp-k">Charter approvals</span><span class="pp-v">Unknown</span>');
    }
  });
});

describe("Read-only extraction mutation boundaries", () => {
  it("count, scope, Evidence retry and pager reads never submit a decision or standing rule", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem, { ...heldItem, item_id: "unknown-tier", tier: "tier9" }] } })),
      "/api/posture/home": () => Promise.resolve(response({ ...home(), agents: [{ agent_id: heldItem.agent_id }] })),
      "/api/posture/evidence": () => Promise.resolve(response({ entries: [], total: 1, integrity_findings: [] })),
      // One beyond the existing 25-row pager makes the read-only Next action reachable.
      "/api/honeypot/tool-traps": () => Promise.resolve(response({ data: { traps: Array.from({ length: 26 }, (_, i) => ({ fake_tool_name: `readonly-tool-${i + 1}` })) } })),
    });
    await settle();
    for (const route of ["approvals", "posture", "dashboard", "policy", "honeypot"]) {
      h.navigate(route); await settle();
      h.click({ "data-action": "agent-scope-select", "data-agent-id": "outside-agent" });
      expect(h.el.main!.innerHTML).not.toContain("approval-decision-feedback");
      expect(h.el.main!.innerHTML).not.toContain("approval-feedback-open");
    }
    h.navigate("honeypot"); await settle();
    expect(h.el.main!.querySelector('[data-action="mfp-page"][data-list="toolTraps"][data-step="1"]')).not.toBeNull();
    expect(h.el.main!.innerHTML).not.toContain("readonly-tool-26");
    h.click({ "data-action": "mfp-page", "data-list": "toolTraps", "data-step": "1" });
    expect(h.el.main!.innerHTML).toContain("readonly-tool-26");
    expect(runInContext('state.mfp.pages.toolTraps', h.context)).toBe(1);
    runInContext('state.timeRange = "all";', h.context);
    h.navigate("activity"); await settle();
    expect(h.el.main!.innerHTML).toContain('data-action="retry-panel" data-read="/api/posture/evidence"');
    const before = h.requests.length;
    h.click({ "data-action": "retry-panel", "data-read": "/api/posture/evidence" }); await settle();
    expect(h.requests.length).toBeGreaterThan(before);
    expect(h.requests.filter(r => r.init?.method && r.init.method !== "GET")).toEqual([]);
    expect(runInContext('state.approvals.inFlightItemId', h.context)).toBeNull();
    expect(runInContext('state.inbox.every(i => !i.resolved)', h.context)).toBe(true);
  });
});


describe("Read-only scoped notice evidence boundary", () => {
  const pageCap = 100; // One inbox page, must match HUB_INBOX_DEFAULT_LIMIT in hub/constants.ts.
  const model_provider = { vendor: "fixture-vendor", model_id: "fixture-model" };
  const agents = ["agent-a", "agent-b"].map(agent_id => ({ agent_id, status: "active", model_provider }));
  const decidedA = { ...heldItem, item_id: "decided-a", agent_id: "agent-a", tier: "tier2", resolved: true };
  const pendingB = { ...heldItem, item_id: "pending-b", agent_id: "agent-b", tier: "tier2" };
  const unknownA = { ...heldItem, item_id: "unknown-a", agent_id: "agent-a", tier: "tier9" };
  const scopeA = (h: ReturnType<typeof boot>) => h.click({ "data-action": "agent-scope-select", "data-agent-id": "agent-a" });
  for (const shape of ["unknown", "full-page"]) {
    it(`decided-history consumer qualifies observed outside holds for ${shape}`, async () => {
      vi.useFakeTimers();
      // The unknown hold belongs to selected A; the full page cannot exclude an unseen A hold.
      const items = shape === "unknown" ? [decidedA, pendingB, unknownA] : [decidedA, pendingB, ...Array.from({ length: pageCap - 2 }, (_, i) => ({ ...pendingB, item_id: `notice-${i}`, kind: "blocked_egress" }))];
      const h = boot({
        "/api/hub/inbox": () => Promise.resolve(response({ data: { items } })),
        "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })),
      });
      await settle(); h.navigate("approvals"); scopeA(h);
      const queue = h.el.main!.innerHTML.split('<aside')[0]!;
      expect(queue).toContain('data-approval-row="decided-a"');
      expect(queue).toContain("1 held operation waits outside this agent scope");
      expect(queue.indexOf("outside this agent scope")).toBeLessThan(queue.indexOf('<table class="approval-table">'));
      expect(queue).not.toContain("Nothing waiting for agent-a.");
      expect(queue).toContain("No recognized held operation for agent-a is waiting in this read.");
      expect(queue).not.toMatch(/Nothing waiting on you|qe-check/);
      if (shape === "unknown") expect(queue).toContain("1 held item carries a tier this console does not recognize");
      else expect(queue).toContain("a held operation may be waiting past them");
    });
  }
  it("defensive Evidence Retry is not masked by page-local search", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/posture/evidence": () => Promise.resolve(response({ entries: [], total: 7, integrity_findings: [] })) });
    await settle();
    runInContext('state.timeRange = "all";', h.context);
    h.navigate("activity"); await settle();
    h.input("evidence-filter-query", "absent");
    const entries = h.el.main!.innerHTML.split('aria-label="Entries"')[1]!.split('</section>')[0]!;
    expect(entries).toContain("The server counts 7 entries in this view, but this read shows none.");
    expect(entries).toContain('data-action="retry-panel" data-read="/api/posture/evidence"');
    expect(entries).not.toContain("Clear filters");
  });
  for (const selected of [false, true]) for (const mode of ["earned", "known", "unknown", "loading", "redacted"]) {
    it(`read-only evidence matrix selected=${selected} mode=${mode}`, async () => {
      vi.useFakeTimers();
      const pendingA = { ...decidedA, item_id: "pending-a", resolved: false };
      const items = mode === "known" ? [decidedA, pendingA, pendingB] : mode === "unknown" ? [decidedA, unknownA] : [decidedA];
      const h = boot({
        "/api/hub/inbox": mode === "loading" ? never : () => Promise.resolve(response({ data: { items: mode === "redacted" ? [] : items, pending_approvals_redacted: mode === "redacted", pending_approvals_count: 0 } })),
        "/api/hub/agents": () => Promise.resolve(response({ data: { agents } })),
        "/api/posture/home": () => Promise.resolve(response({ ...home(), agents })),
      });
      await settle(); h.navigate("approvals");
      if (selected) scopeA(h);
      const unknown = mode === "loading" || mode === "redacted";
      const earned = mode === "earned";
      const known = mode === "known";
      const count = mode === "loading" ? "Unknown" : known ? `${selected ? 1 : 2} of 2` : "0 of 0";
      expect(h.el["rail-approvals-count"]!.textContent).toBe(count);
      expect(h.el["rail-approvals-count"]!.className).toBe(earned ? "count" : known ? "count hot" : "count unknown");
      expect(Boolean(h.el["notify-count"]!.hidden)).toBe(earned);
      for (const el of [h.railLink, h.el["btn-notifications"]!]) {
        const label = el.getAttribute("aria-label")!;
        if (mode === "loading") expect(label).toContain("Unknown until the approval queue loads");
        else if (mode === "redacted") expect(label).toContain("hidden until you paste the operator token");
        else if (mode === "unknown") expect(label).toContain("1 held item carries a tier this console does not recognize");
        else expect(label).toContain(known ? `${selected ? 1 : 2} of 2 held operations wait on you` : "0 of 0 held operations wait on you");
      }
      if (earned) expect(h.el.fortress!.innerHTML).toContain('qe-check');
      else {
        expect(h.el.fortress!.innerHTML).not.toContain('qe-check');
        expect(h.el.main!.innerHTML).not.toContain("Nothing waiting on you.");
      }
      h.navigate("posture");
      const tile = h.el.main!.innerHTML.split('>Approvals waiting</a>')[1]!.split('</div>')[0]!;
      if (unknown) expect(tile).toContain(mode === "loading" ? "Not evaluated" : "UNKNOWN");
      else expect(tile).toContain(`<span class="ot-value">${known ? "2" : "0"}</span>`);
      if (mode === "unknown") expect(h.el.main!.innerHTML).toContain("1 held item carries a tier this console does not recognize");
      if (earned) expect(h.el.main!.innerHTML).toContain("No approvals waiting");
      else expect(h.el.main!.innerHTML).not.toContain("No approvals waiting");
      h.click({ "data-action": "posture-seal-toggle" }, [], false, { stopPropagation: vi.fn() });
      const row = h.el["posture-seal-pop"]!.innerHTML.split('<div class="pp-line">').find(line => line.includes('Charter approvals</span>'))!;
      expect(row).toContain(`class="pp-dot${unknown ? " unknown" : earned ? "" : " warn"}"`);
      expect(row).toContain(`<span class="pp-v">${unknown ? "Unknown" : earned ? "clear" : known ? "2 waiting" : "0 waiting; 1 held item carries a tier this console does not recognize"}</span>`);
    });
  }
  for (const filters of [{ query: " " }, { agent: "agent-a", query: "absent" }, { layer: "l1" }, { event: "state_write" }]) {
    it(`defensive inconsistent page keeps Retry with pre-total filters ${JSON.stringify(filters)}`, async () => {
      vi.useFakeTimers();
      const h = boot({ "/api/posture/evidence": () => Promise.resolve(response({ entries: [], total: 7, integrity_findings: [] })) });
      await settle(); h.context.testFilters = filters;
      runInContext('state.timeRange = "24h";', h.context);
      h.navigate("activity"); await settle();
      runInContext('Object.assign(state.evidence.filters, testFilters); rerender();', h.context);
      const entries = h.el.main!.innerHTML.split('aria-label="Entries"')[1]!.split('</section>')[0]!;
      expect(entries).toContain('data-action="retry-panel"');
      expect(entries).not.toContain("Clear filters");
    });
  }
  it("result post-filter may explain an empty positive-total page even with local search", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/posture/evidence": () => Promise.resolve(response({ entries: [], total: 7, integrity_findings: [] })) });
    await settle();
    runInContext('state.timeRange = "all";', h.context);
    h.navigate("activity"); await settle();
    runInContext('state.evidence.filters.result = "failure"; rerender();', h.context);
    h.input("evidence-filter-query", "absent");
    const entries = h.el.main!.innerHTML.split('aria-label="Entries"')[1]!.split('</section>')[0]!;
    expect(entries).toContain("No entries match this view");
    expect(entries).toContain("Clear filters");
    expect(entries).not.toContain('data-action="retry-panel"');
  });

});

describe("Talk split draft ownership", () => {
  it("explicit suggestion updates the live mounted draft before a refused send", async () => {
    const h = boot({ "/api/hub/chat/concierge": () => Promise.resolve(response({ error: "refused" }, 403)) });
    await settle();
    const mounted = Object.assign(new FakeInput({ "data-action": "concierge-input" }), { value: "draft A", isConnected: true });
    Object.assign(h.context, { mounted });
    runInContext('state.chat.concierge.composer="draft A"; talkOwner={input:mounted};', h.context);
    h.click({ "data-action": "concierge-suggestion", "data-suggestion-id": "summarize-hour" });
    expect(mounted.value).toBe("Summarize what happened in this fortress in the last hour.");
    await settle();
    expect(runInContext("state.chat.concierge.composer", h.context)).toBe(mounted.value);
    expect(h.requests.filter(r => r.url === "/api/hub/chat/concierge" && r.init?.method === "POST")).toHaveLength(1);
  });

  it("a host change carries an unrevoked send follow to the new host's history", async () => {
    const h = boot(); await settle();
    const makeHost = () => {
      const history = Object.assign(new FakeElement({ id: "concierge-history" }), {
        scrollTop: 0, clientHeight: 100, scrollHeight: 500,
        addEventListener() {}, removeEventListener() {}, isConnected: true,
      });
      const input = Object.assign(new FakeInput({ "data-action": "concierge-input" }), { isConnected: true });
      const host = new FakeElement();
      host.querySelector = (selector: string) => selector === "#concierge-history" ? history
        : selector === 'input[data-action="concierge-input"]' ? input
        : selector === "[data-talk-read-status]" || selector === "[data-talk-error]" ? new FakeElement() : null;
      return { host, history };
    };
    const first = makeHost(); const second = makeHost();
    Object.assign(h.context, { firstHost: first.host, secondHost: second.host });
    runInContext('attachTalkOwner(firstHost); talkFollowIntent={scrollEpoch:talkUserScrollEpoch}; disposeTalkOwner(); attachTalkOwner(secondHost);', h.context);
    expect(runInContext("!!talkFollowIntent", h.context)).toBe(true);
    expect(second.history.scrollTop).toBe(500);
  });

  it("changed legacy history restores its own mid-thread offset without outer-page scrolling", async () => {
    const h = boot(); await settle();
    const history = Object.assign(new FakeElement({ id: "concierge-history" }), {
      scrollTop: 73, clientHeight: 100, scrollHeight: 500, scrollIntoView: vi.fn(),
    });
    Object.assign(h.context, { testHistory: history });
    runInContext('var snapshot=captureTalkViewport(testHistory); testHistory.scrollTop=0; testHistory.scrollHeight=600; restoreTalkViewport(testHistory,snapshot,false);', h.context);
    expect(history.scrollTop).toBe(73);
    expect(history.scrollIntoView).not.toHaveBeenCalled();
  });

  it("a zero-motion scroll event leaves the follow epoch alone while a moved history bumps it", async () => {
    const h = boot(); await settle();
    const listeners: Record<string, (ev: unknown) => void> = {};
    const history = Object.assign(new FakeElement({ id: "concierge-history" }), {
      scrollTop: 0, clientHeight: 100, scrollHeight: 500, isConnected: true,
      addEventListener(name: string, fn: (ev: unknown) => void) { listeners[name] = fn; },
      removeEventListener() {},
    });
    const input = Object.assign(new FakeInput({ "data-action": "concierge-input" }), { isConnected: true });
    const host = new FakeElement();
    host.querySelector = (selector: string) => selector === "#concierge-history" ? history
      : selector === 'input[data-action="concierge-input"]' ? input
      : selector === "[data-talk-read-status]" || selector === "[data-talk-error]" ? new FakeElement() : null;
    Object.assign(h.context, { testHost: host });
    runInContext('attachTalkOwner(testHost); talkFollowIntent={scrollEpoch:talkUserScrollEpoch};', h.context);
    // The VM DOM has no wheel or layout; the real no-motion wheel is covered by
    // test/e2e/talk-follow-ownership.e2e.ts (d). This proves only the epoch rule.
    expect(listeners.scroll).toBeTypeOf("function");
    listeners.scroll!({ isTrusted: true });
    expect(runInContext("talkFollowIntent.scrollEpoch===talkUserScrollEpoch", h.context)).toBe(true);
    history.scrollTop = 10; listeners.scroll!({ isTrusted: true });
    expect(runInContext("talkFollowIntent.scrollEpoch===talkUserScrollEpoch", h.context)).toBe(false);
  });

  it("contains a wheel at the history's ends so the outer page never moves under the reader", () => {
    // Native Chromium chained a no-motion wheel at the bottom of the history to the page (0 to 28 px).
    const rule = /\.concierge-history \{([^}]*)\}/.exec(renderDashboardV11Html());
    expect(rule?.[1]).toMatch(/overscroll-behavior:\s*contain;/);
  });

  it("a hidden history's zero geometry never overwrites the saved reader position", async () => {
    const h = boot(); await settle();
    const history = Object.assign(new FakeElement({ id: "concierge-history" }), {
      scrollTop: 0, clientHeight: 100, scrollHeight: 500, isConnected: true,
      addEventListener() {}, removeEventListener() {},
    });
    const input = Object.assign(new FakeInput({ "data-action": "concierge-input" }), { isConnected: true });
    const host = new FakeElement();
    host.querySelector = (selector: string) => selector === "#concierge-history" ? history
      : selector === 'input[data-action="concierge-input"]' ? input
      : selector === "[data-talk-read-status]" || selector === "[data-talk-error]" ? new FakeElement() : null;
    Object.assign(h.context, { testHost: host });
    runInContext('talkViewportState={top:73,following:false}; attachTalkOwner(testHost);', h.context);
    expect(history.scrollTop).toBe(73);
    // panel.hidden = true drops the layout box: every geometry field reads 0.
    Object.assign(history, { scrollTop: 0, clientHeight: 0, scrollHeight: 0 });
    runInContext("disposeTalkOwner();", h.context);
    expect(runInContext("JSON.stringify(talkViewportState)", h.context)).toBe(JSON.stringify({ top: 73, following: false }));
  });

  it("a legacy reader who scrolls during an in-flight send is not pulled down by the reply", async () => {
    const posts: Array<(value: unknown) => void> = [];
    const h = boot({ "/api/hub/chat/concierge": () => new Promise((resolve) => posts.push(resolve)) });
    await settle();
    expect(runInContext("talkDomOwnerSupported", h.context)).toBe(false);
    const listeners: Record<string, (ev: unknown) => void> = {};
    const history = Object.assign(new FakeElement({ id: "concierge-history" }), {
      scrollTop: 0, clientHeight: 100, scrollHeight: 500, isConnected: true,
      addEventListener(name: string, fn: (ev: unknown) => void) { listeners[name] = fn; },
      removeEventListener() {},
    });
    // The VM DOM does not parse innerHTML into elements, so the written history is this one fake.
    h.el["concierge-history"] = history;
    const main = h.el.main!;
    const ownQuery = main.querySelector.bind(main);
    main.querySelector = (selector: string) => selector === "#concierge-history" ? history : ownQuery(selector);
    h.navigate("dashboard"); await settle();
    const send = async (scrollDuringFlight: boolean) => {
      runInContext('state.chat.concierge.composer="question"; void onConciergeSend();', h.context);
      await settle();
      if (scrollDuringFlight) { history.scrollTop = 200; listeners.scroll?.({ isTrusted: true }); }
      posts.shift()!(response({ data: { reply_text: "answer", served_by: "local" } }));
      await settle();
    };
    await send(false);
    expect(history.scrollTop, "an unrevoked send follows its reply").toBe(500);
    await send(true);
    expect(history.scrollTop, "a real scroll during the send revoked follow").toBe(200);
  });

  it("a legacy panel-to-full-page move restores the panel reader's current position, not its last write", async () => {
    const h = boot(); await settle();
    const makeHistory = () => Object.assign(new FakeElement({ id: "concierge-history" }), {
      scrollTop: 0, clientHeight: 100, scrollHeight: 500, isConnected: true,
      addEventListener() {}, removeEventListener() {},
    });
    const panelHistory = makeHistory(); const mainHistory = makeHistory();
    // The VM DOM does not parse innerHTML, so each host answers with its fake
    // history only once Talk markup has been written into it.
    const answer = (host: FakeElement, history: FakeElement) => {
      const ownQuery = host.querySelector.bind(host);
      host.querySelector = (selector: string) => selector === "#concierge-history"
        ? (host.innerHTML.includes('id="concierge-history"') ? history : null) : ownQuery(selector);
    };
    answer(h.el["talk-panel-body"]!, panelHistory); answer(h.el.main!, mainHistory);
    h.el["concierge-history"] = panelHistory;
    h.click({ "data-action": "talk-toggle" });
    expect(panelHistory.scrollTop, "the panel opens a long thread at its latest message").toBe(500);
    panelHistory.scrollTop = 200;
    h.click({ "data-action": "talk-open-full" });
    h.navigate("dashboard"); await settle();
    expect(mainHistory.scrollTop).toBe(200);
  });

  it("an engine missing Node.isConnected or Element.replaceChildren takes the legacy Talk path", async () => {
    const connectedNode = { prototype: { isConnected: false } };
    class NoReplaceChildren {}
    const missingNode = boot({}, {}, { templateContent: true }); await settle();
    expect(runInContext("talkDomOwnerSupported", missingNode.context)).toBe(false);
    const missingReplace = boot({}, { Node: connectedNode, Element: NoReplaceChildren }, { templateContent: true }); await settle();
    expect(runInContext("talkDomOwnerSupported", missingReplace.context)).toBe(false);
    const complete = boot({}, { Node: connectedNode }, { templateContent: true }); await settle();
    expect(runInContext("talkDomOwnerSupported", complete.context)).toBe(true);
  });

  it("a send whose first render throws still settles, so the next send posts", async () => {
    const h = boot({ "/api/hub/chat/concierge": () => Promise.resolve(response({ data: { reply_text: "ok" } })) });
    await settle();
    const main = h.el.main!;
    let throwOnce = false;
    Object.defineProperty(h.el, "main", {
      configurable: true,
      get() { if (throwOnce) { throwOnce = false; throw new Error("fixture render failure"); } return main; },
    });
    const posts = () => h.requests.filter(r => r.url === "/api/hub/chat/concierge" && r.init?.method === "POST").length;
    throwOnce = true;
    runInContext('state.chat.concierge.composer="first"; void onConciergeSend().catch(function () {});', h.context);
    await settle();
    expect(runInContext("state.chat.concierge.sending", h.context)).toBe(false);
    expect(posts(), "the failed render happened before any POST").toBe(0);
    runInContext('state.chat.concierge.composer="second"; void onConciergeSend();', h.context);
    await settle();
    expect(posts()).toBe(1);
  });
});
