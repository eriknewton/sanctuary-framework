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
import { STATUS_MAPPING, TIER1_BUTTON_COPY } from "../../../src/dashboard/v1_1/status-mapping.js";

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

function boot(overrides: Record<string, (init?: RequestInit) => unknown> = {}, extraGlobals: Record<string, unknown> = {}) {
  fakeActiveElement = null;
  const el: Record<string, FakeElement> = {};
  for (const id of SHELL_IDS) el[id] = new FakeElement({ id });
  el["global-search"] = new FakeInput({ "data-action": "global-search" });
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
  const context = createContext({
    document: {
      getElementById: (id: string) => el[id] || (id === "dashboard-config" ? { textContent: JSON.stringify({ hubApiBase: "/api/hub" }) } : null),
      addEventListener: (name: string, fn: (ev: unknown) => void) => { docListeners[name] = fn; },
      createElement: (tagName: string) => new FakeElement({}, tagName),
      createDocumentFragment: () => new FakeElement({}, "FRAGMENT"),
      createTextNode: (text: string) => new FakeText(text),
      querySelectorAll: () => [],
      get activeElement() { return fakeActiveElement; },
      set activeElement(value: unknown) { fakeActiveElement = value; },
      documentElement: { setAttribute() {}, removeAttribute() {}, getAttribute: () => null },
    },
    window: { addEventListener: (name: string, fn: () => void) => { winListeners[name] = fn; } },
    location, sessionStorage: { getItem: () => null, setItem() {} },
    URLSearchParams, URL, AbortController, Date, Element: FakeElement, HTMLInputElement: FakeInput,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    EventSource: class { addEventListener() {} close() {} },
    fetch: (url: string, init?: RequestInit) => {
      const path = url.replace(/([?&])_t=[^&]*&?/, "$1").replace(/[?&]$/, "");
      if (overrides[path]) return overrides[path]!(init);
      return Promise.resolve(response(path === "/api/posture/home" ? home() : emptyData));
    },
    ...extraGlobals,
  });
  runInContext(getClientScript(), context);
  const navigate = (route: string) => { location.hash = "#" + route; };
  const click = (attrs: Record<string, string>, inside: string[] = [], checked = false) => {
    const target = new FakeElement(attrs);
    target.inside = inside;
    target.checked = checked;
    docListeners.click!({ target });
  };
  const type = (text: string) => { el["global-search"]!.value = text; docListeners.input!({ target: el["global-search"] }); };
  const change = (target: FakeElement) => docListeners.change!({ target });
  return { el, railLink, context, navigate, click, type, change };
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
      "/api/policy/current": () => Promise.resolve(response({ data: { view: { sections: [] } } })),
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
    expect(h.el["toast-host"]!.innerHTML).toContain("Inbox action failed: operator session required");
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
    expect(main).toContain("Nothing waiting for fixture-agent-c. 2 held operations wait outside this agent scope");
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
    expect(drawer()).toContain("Nothing waiting for fixture-agent-c. 2 held operations wait outside this agent scope");
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
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })) });
    await settle();
    h.navigate("activity");
    const html = h.el.main!.innerHTML;
    const bar = html.match(/<div class="filter-bar" role="group" aria-label="Filter the inbox">([\s\S]*?)<\/div>/);
    expect(bar, "filter bar").toBeTruthy();
    const labels = [...bar![1]!.matchAll(/<label class="field"><span class="field-label">([^<]+)<\/span><(input|select) class="input"/g)].map((m) => m[1]);
    expect(labels).toEqual(["Search", "Source", "Severity", "Agent", "From", "To"]);
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
    const line = "Nothing waiting for agent-empty. 1 held operation waits outside this agent scope; choose All agents in the scope menu to see them.";
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
      if (failure === "approve") {
        expect(h.el["toast-host"]!.innerHTML).toContain("Inbox action failed: refused");
        expect(drawer(h)).toContain("WAITING");
      } else {
        expect(drawer(h)).toContain(failure === "none" ? "No approvals waiting" : "DECIDED");
        if (failure !== "none" && failure !== "downgrade confirmed") expect(h.el["toast-host"]!.innerHTML).toContain("Allowed once. The standing rule was not added:");
        // A declined downgrade reads as one sentence, not a second "no standing rule added" after the first.
        if (failure === "downgrade cancelled") {
          expect(h.el["toast-host"]!.innerHTML).toContain("Allowed once. The standing rule was not added: you chose to keep your protection.");
          expect(h.el["toast-host"]!.innerHTML).not.toContain("no standing rule added");
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
        "/api/policy/current": mode === "loading" ? never : () => Promise.resolve(response({ data: { view: { sections: [] } } }, mode === "401" ? 401 : mode === "503" ? 503 : 200)),
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
      expect(html).toContain(`Nothing waiting for agent-empty. At least 1 held operation waits outside this agent scope; choose All agents in the scope menu to see them. The inbox has at least ${cap} items and this read shows only the first ${cap}, so a held operation may be waiting past them.`);
      expect(html).not.toContain("1 of 1 held operation");
    }
  });

  it("the fortress count badge is a lower bound on a full page and counts unrecognized holds", async () => {
    vi.useFakeTimers();
    const holdCount = 3; // Three visible holds amid the rest of a full page.
    const full = boot({ "/api/hub/inbox": inbox([...Array.from({ length: holdCount }, (_, i) => ({ ...heldItem, item_id: `hold-${i}` })), ...pageOthers(cap - holdCount)]) });
    await settle();
    expect(full.el.fortress!.innerHTML).toContain(`<span class="count" id="queue-count">${holdCount}+</span>`);
    const unrecognized = boot({ "/api/hub/inbox": inbox([{ ...heldItem, tier: "tier9" }]) });
    await settle();
    expect(unrecognized.el.fortress!.innerHTML).toContain('<span class="count" id="queue-count">1</span>');
    const earned = boot({ "/api/hub/inbox": inbox([]) });
    await settle();
    expect(earned.el.fortress!.innerHTML).toContain('<span class="count zero" id="queue-count">0</span>');
  });
});
