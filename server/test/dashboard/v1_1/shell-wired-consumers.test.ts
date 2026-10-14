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
import { afterEach, describe, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { HUB_AGENT_STATUSES } from "../../../src/contracts/v1.1/constants.js";
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
let setAttributeThrowFor: { name: string; value: string } | null = null;

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
  setAttribute(name: string, value: string) {
    if (setAttributeThrowFor && setAttributeThrowFor.name === name && setAttributeThrowFor.value === String(value)) {
      setAttributeThrowFor = null;
      throw new Error("fixture row build failed");
    }
    this.attrs[name] = String(value);
  }
  removeAttribute(name: string) { delete this.attrs[name]; }
  inside: string[] = [];
  closest(selector: string) { return this.inside.includes(selector) ? this : null; }
  private matches(selector: string) {
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

function boot(overrides: Record<string, (init?: RequestInit, url?: string) => unknown> = {}, extraGlobals: Record<string, unknown> = {}) {
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
      const next = String(value);
      const changed = next !== locationHash;
      locationHash = next;
      if (changed && winListeners.hashchange) winListeners.hashchange();
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
    URLSearchParams, URL, AbortController, Date, Element: FakeElement, HTMLInputElement: FakeInput, Blob,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    EventSource: class { addEventListener() {} close() {} },
    fetch: (url: string, init?: RequestInit) => {
      const path = url.replace(/([?&])_t=[^&]*&?/, "$1").replace(/[?&]$/, "");
      requests.push({ url: path, init });
      if (overrides[path]) return overrides[path]!(init, path);
      const bare = path.split("?")[0]!;
      if (overrides[bare]) return overrides[bare]!(init, path);
      return Promise.resolve(response(path === "/api/posture/home" ? home() : emptyData));
    },
    ...extraGlobals,
  });
  runInContext(getClientScript(), context);
  const navigate = (route: string) => { location.hash = "#" + route; };
  const click = (attrs: Record<string, string>, inside: string[] = []) => {
    const target = new FakeElement(attrs);
    target.inside = inside;
    target.checked = attrs.checked === "true";
    docListeners.click!({ target });
  };
  const type = (text: string) => { el["global-search"]!.value = text; docListeners.input!({ target: el["global-search"] }); };
  const change = (target: FakeElement) => docListeners.change!({ target });
  const input = (action: string, value: string) => { const target = new FakeInput({ "data-action": action }); target.value = value; docListeners.input!({ target }); };
  return { el, railLink, context, navigate, click, type, change, input, requests, downloads };
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
    expect(h.railLink.getAttribute("title")).toMatch(/^1 of 1 held operations wait on you · queue read \d+s ago$/);
    expect(h.el["notify-count"]!.innerHTML).toContain("1 of 1");
    expect(h.el["notify-count"]!.className).not.toContain("unknown");
    expect(h.el["btn-notifications"]!.getAttribute("aria-label")).toMatch(/1 of 1 held operations wait on you · queue read \d+s ago/);
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
    expect(main).toContain("<strong>4</strong> outbound connections blocked at the kernel");
    expect(main).toMatch(/<strong class="unknown-value">Unknown<\/strong> allowed/);
    expect(main).not.toContain("<strong>0</strong>");
    expect(main).not.toMatch(/\b0 allowed/);
    expect(main).not.toMatch(/of 4 observed/);
  });

  it("the Enforcement egress line keeps its denominator when both kernel counts are read", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/posture/home": () => Promise.resolve(response(home({ kernel_blocks: 4, kernel_allows: 2 }))) });
    await settle();
    h.navigate("enforcement");
    expect(h.el.main!.innerHTML).toContain("<strong>4</strong> of 6 observed outbound connections blocked at the kernel; 2 allowed.");
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
    expect(main).toContain("recorded in this inbox");
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
    expect(messages[0]).toContain('Sanctuary cannot apply "Remove protection" for this agent: unsupported request refused');
    expect(messages[1]).toContain('"Remove protection" failed: controller unavailable');
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
    expect(main).toContain("A decision on a Charter hold is recorded in your audit log; a decision on any other held item is recorded in this inbox.");
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
    expect(main).toContain("A decision on a Charter hold is recorded in your audit log; a decision on any other held item is recorded in this inbox.");
    expect(main).toContain("Waiting on you · 2 of 2");
    expect(main).toMatch(/data-approval-row="charter\.approval\.wait"[\s\S]*?recorded in your audit log/);
    expect(main).toMatch(/data-approval-row="hub-wait"[\s\S]*?recorded in this inbox/);
    expect(main).toMatch(/data-approval-row="charter\.approval\.decided"[\s\S]*?DECIDED[\s\S]*?outcome in your audit log[\s\S]*?href="#activity">Evidence<\/a>/);
    expect(main).toMatch(/data-approval-row="hub-decided"[\s\S]*?DECIDED[\s\S]*?outcome not reported by the inbox/);
    expect(main).not.toMatch(/ALLOWED ONCE|DENIED|ALWAYS ALLOW/);
    h.click({ "data-action": "approval-select", "data-item-id": "hub-wait" });
    main = h.el.main!.innerHTML;
    expect(main).toMatch(/If you decide[\s\S]*?recorded in this inbox[\s\S]*?Decision recorded in this inbox/);
  });

  it("Approvals uses plain operator copy for always allow and never renders route paths", async () => {
    vi.useFakeTimers();
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [{ ...heldItem, item_id: "wait-1", tier: "tier2", operation_category: "state_export" }] } })),
      "/api/policy/current": () => Promise.resolve(response({ data: { view: { sections: [] } } })),
    });
    await settle();
    h.navigate("approvals");
    await settle();
    runInContext("state.approvals.alwaysAllow = true; rerender();", h.context);
    const main = h.el.main!.innerHTML;
    expect(main).not.toContain("/api/");
    expect(main).toContain("Allow always asks the policy engine to compile a standing rule for state_export, then activates it with your operator token.");
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
    expect(main).toContain("recorded in this inbox");
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
    expect(h.el.main!.innerHTML).toContain("Left rail agent scope applies first");
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
    let inboxItems: Array<Record<string, unknown>> = [{ ...heldItem, item_id: "wait-1", tier: "tier2", operation_category: "state_export", resolved: false }];
    const h = boot({
      "/api/hub/inbox": () => Promise.resolve(response({ data: { items: inboxItems } })),
      "/api/hub/inbox/wait-1/approve": () => {
        inboxItems = [{ ...heldItem, item_id: "wait-1", tier: "tier2", operation_category: "state_export", resolved: true, resolved_at: "2026-10-14T16:59:00.000Z" }];
        return Promise.resolve(response({ error: "operator session required" }, 401));
      },
    });
    await settle();
    h.navigate("approvals");
    h.click({ "data-action": "inbox-approve", "data-item-id": "wait-1" });
    await settle();
    expect(h.el["toast-host"]!.innerHTML).toContain("Inbox action failed: operator session required");
    expect(h.el.main!.innerHTML).toContain("Decided at");
    expect(h.el.main!.innerHTML).toContain("outcome not reported by the inbox");
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
    expect(main).toContain("Nothing waiting for fixture-agent-c. 2 of 2 held operations wait on other agents");
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
    expect(drawer()).toContain("2 of 2 held operations in this scope are waiting on you");
    categorySelect.value = "";
    h.change(categorySelect);
    h.click({ "data-action": "agent-scope-select", "data-agent-id": "fixture-agent-c" });
    expect(drawer()).not.toContain("No approvals waiting");
    expect(drawer()).not.toContain("0 of 0 held operations");
    expect(drawer()).toContain("Nothing waiting for fixture-agent-c. 2 of 2 held operations wait on other agents");
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
    rowSlice(html, '<div class="agent-row', `data-agent-id="${escapedAttr(id)}"`);
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

  it("a row build failure leaves that row visible and still restores focus after another row repaints", async () => {
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
    setAttributeThrowFor = { name: "data-machine-url", value: brokenUrl };
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
      expect(textOf(html), route).not.toMatch(retired);
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
    const dot = (id: string) => {
      const row = agentListRowHtml(html, id);
      return row.match(/<span class="state-dot ([^"]+)"><\/span>([^<]*)<\/span>/);
    };
    const unwrappingLabel = runInContext("STATUS_MAP.unwrapping.label", h.context) as string;
    (h.context as Record<string, unknown>).__agentStatus = "unwrapping";
    const unwrappingDot = runInContext("agentStateClass(__agentStatus)", h.context) as string;
    const unwrappingGlyph = runInContext("STATUS_MAP[__agentStatus].glyph", h.context) as string;
    const unwrappingTone = runInContext("AGENT_STATE_PILL_TONE[agentStateClass(__agentStatus)] || 'tone-unknown'", h.context) as string;
    expect(dot("no-evidence")![1]).toBe("unknown");
    expect(dot("no-evidence")![2]).toBe("Unknown");
    expect(dot("paused-one")![1]).toBe("idle");
    expect(dot("unwrapping-one")![1]).toBe(unwrappingDot);
    expect(dot("unwrapping-one")![2]).toBe(unwrappingLabel);
    expect(dot("locked-one")![1]).toBe("locked");
    expect(dot("off-enum")![1]).toBe("unknown");
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
    const glyphToDot: Record<string, string> = { online: "live", idle: "idle", offline: "locked", away: "off", unknown: "unknown" };
    for (const status of HUB_AGENT_STATUSES) {
      const id = `agent-${status}`;
      const expectedGlyph = STATUS_MAPPING[status].glyph;
      const expectedDot = glyphToDot[expectedGlyph];
      (h.context as Record<string, unknown>).__agentStatus = status;
      (h.context as Record<string, unknown>).__agentId = id;
      expect(runInContext("STATUS_MAP[__agentStatus].glyph", h.context), status).toBe(expectedGlyph);
      expect(runInContext("agentStateClass(__agentStatus)", h.context), status).toBe(expectedDot);
      const listHtml = h.el.main!.innerHTML;
      expect(agentListRowHtml(listHtml, id), status).toContain(`<span class="state-dot ${expectedDot}"></span>`);
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
    ...home({ kernel_blocks: 3, kernel_allows: 7, chain_verified: true, window_start: "2026-10-14T16:00:00.000Z", window_end: "2026-10-14T17:00:00.000Z", entry_count: 1284, ...digest }),
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
    expect(html).toContain('class="state-chip good"><i aria-hidden="true"></i>VERIFIED');
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
    expect(html).toMatch(/data-agent-id="research-agent"[\s\S]*?<span class="state-chip unknown"><i aria-hidden="true"><\/i>UNKNOWN<\/span>/);
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
    expect(html).toContain("NOT YET VERIFIED");
    expect(html).toContain("last check Not evaluated");
    expect(html).not.toContain('class="state-chip good"><i aria-hidden="true"></i>VERIFIED');
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
