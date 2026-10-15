import { describe, expect, it } from "vitest";
import { generateFleetSwitcherHTML } from "../../src/principal-policy/dashboard-html.js";

function page(): string {
  return generateFleetSwitcherHTML({
    serverVersion: "test",
    protocol: "http",
    currentHost: "127.0.0.1",
    currentPort: 3501, // The dashboard's conventional port; no socket is opened.
  });
}

class PageNode {
  className = "";
  textContent = "";
  dataset: Record<string, string> = {};
  children: PageNode[] = [];
  appendChild(node: PageNode): void { this.children.push(node); }
  replaceChildren(): void { this.children = []; }
  setAttribute(): void {}
  addEventListener(): void {}
}

type ProbeFetch = (url: string, options: { signal: AbortSignal }) => Promise<unknown>;

async function probe(fetch: ProbeFetch, abort = false): Promise<{ word: string; cls: string }> {
  const scriptMatch = page().match(/<script>\s*(const STORAGE_KEY[\s\S]*?)<\/script>/);
  if (!scriptMatch) throw new Error("Missing Fleet Switcher script anchor");
  const end = scriptMatch[1].indexOf("// Auto-add current machine");
  if (end < 0) throw new Error("Missing Fleet Switcher initialization anchor");
  const list = new PageNode();
  let finish!: (value: { word: string; cls: string }) => void;
  const completed = new Promise<{ word: string; cls: string }>((resolve) => { finish = resolve; });
  const document = {
    getElementById: () => list,
    createElement: () => {
      const node = new PageNode();
      let text = "";
      Object.defineProperty(node, "textContent", {
        get: () => text,
        set: (value: string) => {
          text = value;
          if (node.className === "status-label" && value !== "Checking") {
            const dot = list.children.flatMap((card) => card.children)
              .find((child) => child.className.startsWith("status-dot "));
            if (!dot) throw new Error("Missing rendered probe dot");
            finish({ word: value, cls: dot.className });
          }
        },
      });
      return node;
    },
    createTextNode: () => new PageNode(),
  };
  let deadline: (() => void) | undefined;
  const setTimeout = (callback: () => void, milliseconds: number) => {
    // 3000 ms = the shared three-second probe window times 1000 ms per second.
    expect(milliseconds).toBe(3000);
    deadline = callback;
    return callback;
  };
  const clearTimeout = () => { deadline = undefined; };
  const source = scriptMatch[1].slice(0, end) + "\nrender();";
  // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
  new Function("document", "localStorage", "location", "fetch", "setTimeout", "clearTimeout", "AbortController", source)(
    document,
    { getItem: () => JSON.stringify([{ name: "Saved peer", url: "https://peer.example" }]) },
    { origin: "http://127.0.0.1:3501" },
    fetch, setTimeout, clearTimeout, AbortController,
  );
  if (abort) {
    if (!deadline) throw new Error("Probe did not schedule an abort");
    deadline();
  }
  return completed;
}

function answer(body: unknown, overrides: Record<string, unknown> = {}): ProbeFetch {
  return async () => ({ ok: true, redirected: false, json: async () => body, ...overrides });
}

describe("Fleet Switcher probe status", () => {
  // fail-before-exempt: plant ONLINE_AS_OFFLINE changes the ok:true branch to return offline.
  it("an ok:true answer reads Online with the online class", async () => {
    expect(await probe(answer({ ok: true }))).toEqual({ word: "Online", cls: "status-dot online" });
  });

  it("an ok:false answer reads Not healthy with the failure class", async () => {
    expect(await probe(answer({ ok: false }))).toEqual({ word: "Not healthy", cls: "status-dot offline" });
  });

  const unknownCases: Array<{ name: string; fetch: ProbeFetch; abort?: boolean }> = [
    { name: "a rejected fetch", fetch: async () => { throw new TypeError("Network error"); } },
    {
      name: "an aborted fetch", abort: true,
      fetch: (_url, { signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
      }),
    },
    // HTTP 500 is an error response even when its JSON claims ok:true.
    { name: "a 500 answer", fetch: answer({ ok: true }, { ok: false, status: 500 }) },
    { name: "a redirected 2xx answer", fetch: answer({ ok: true }, { redirected: true }) },
    { name: "a non-JSON body", fetch: answer(null, { json: async () => { throw new SyntaxError("Not JSON"); } }) },
    { name: "a body without ok", fetch: answer({}) },
    { name: "a string true ok", fetch: answer({ ok: "true" }) },
    { name: "a string false ok", fetch: answer({ ok: "false" }) },
    { name: "a null body", fetch: answer(null) },
  ];

  it.each(unknownCases)("$name reads Unknown without a failure class", async ({ fetch, abort }) => {
    const result = await probe(fetch, abort);
    expect(result.word).toBe("Unknown");
    expect(result.cls).toBe("status-dot unknown");
    expect(result.cls).not.toContain("offline");
    expect(result.cls).not.toContain("online");
  });

  it("styles unknown distinctly from online, failure and checking", () => {
    const style = page().match(/<style>([\s\S]*?)<\/style>/)?.[1];
    if (!style) throw new Error("Missing Fleet Switcher style anchor");
    const rule = (state: string) => {
      const match = style.match(new RegExp("\\.machine-card \\.status-dot\\." + state + "\\s*\\{([^}]+)\\}"));
      expect(match, "Missing status rule: " + state).not.toBeNull();
      return match![1].trim();
    };
    const unknown = rule("unknown");
    expect(unknown).toContain("background: transparent");
    expect(unknown).toMatch(/border:.*var\(--ink-3\)/);
    for (const other of ["online", "offline", "checking"]) expect(unknown).not.toBe(rule(other));
    expect(unknown).not.toMatch(/var\(--(?:sage|rust|ochre)\)/);
  });
});
