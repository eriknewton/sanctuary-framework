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
import { agentsScenario } from "./fixtures/agents-scenarios.js";
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
  display_template_id: "approval_pending.tier1.lockdown", display_template_args: {}, resolved: false,
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
      const next = String(value).startsWith("#") ? String(value) : "#" + String(value);
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
    URLSearchParams, URL, AbortController, TextDecoder, Date, Element: FakeElement, HTMLInputElement: FakeInput,
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
  const click = (attrs: Record<string, string>, inside: string[] = []) => {
    const target = new FakeElement(attrs);
    target.inside = inside;
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
    const h = boot();
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

  it("the approval queue's element id exists once on the Approvals screen", async () => {
    vi.useFakeTimers();
    const h = boot({ "/api/hub/inbox": () => Promise.resolve(response({ data: { items: [heldItem] } })) });
    await settle();
    h.navigate("approvals");
    const doc = h.el.main!.innerHTML + h.el.fortress!.innerHTML;
    expect(doc.match(/id="approval-queue"/g) ?? []).toHaveLength(1);
    expect(h.el.main!.innerHTML).toContain('id="approval-queue"');
    // Beside Talk's full page the column shows, and carries the queue.
    h.navigate("dashboard");
    expect(h.el.fortress!.innerHTML).toContain('id="approval-queue"');
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
    const h = boot();
    await settle();
    h.navigate("approvals");
    const main = h.el.main!.innerHTML;
    // Charter holds are recorded in the audit log by the gate; nothing signs
    // a decision with an operator key, and other held items are not
    // audit-appended on their path.
    expect(main).not.toContain("operator key");
    expect(main).not.toContain("Every decision is signed");
    expect(main).toContain("A decision on a Charter hold is recorded in your audit log");
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

  it("the Approvals subtitle promises no signed policy and says Allow always is refused when the engine is not configured", async () => {
    vi.useFakeTimers();
    const h = boot();
    await settle();
    h.navigate("approvals");
    const main = h.el.main!.innerHTML;
    // Allow always asks the policy engine to compile and activate a standing
    // rule; where the engine is not configured it is refused and the policy
    // is unchanged. The subtitle may promise no more than that.
    expect(main).not.toContain("signed policy");
    expect(main).not.toContain("Allow always writes");
    expect(main).toContain("Allow always asks Sanctuary to add a standing rule to your policy; if the policy engine is not configured on this machine, it refuses and your policy is unchanged.");
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


describe("slice 6a Agents wired consumers", () => {
  const start = async (name = "protected", overrides: Record<string, (init?: RequestInit) => unknown> = {}) => {
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
    });
    await settle();
    h.navigate("agents");
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
    expect(h.el.main!.innerHTML).toContain("UNKNOWN");
    expect(h.el.main!.innerHTML).not.toContain('state-chip good');
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
      if (tab === "identity") expect(html).toContain("Operator-held");
      if (tab === "activity" || tab === "evidence") {
        expect(html).toContain("Castle Wall");
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
    for (const action of ["pause", "resume", "restart", "lockdown", "unwrap"]) { h.click({ "data-action": `agent-${action}`, "data-agent-id": "research-agent" }); await settle(); }
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
    expect(h.el.main!.innerHTML).toContain("Reach unavailable");
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
    expect(h.el.main!.innerHTML).toContain("Reach unavailable");
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
    for (const label of ["Reach unavailable", "Approvals Unknown", "Activity Unknown", "Policy summary Unknown", "UNKNOWN"]) expect(html).toContain(label);
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
    expect(h.el.main!.innerHTML).toContain("Reach unavailable");
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
  });

});
