/**
 * Sanctuary v1.1 Dashboard — Exit drill client rendering tests (defect A7).
 *
 * Covers the client-side half of A7: the exit drill wizard must render
 * state_entry_count explicitly (including 0) so "Bundle ready" cannot imply
 * state was included when none was. Warnings must be text-escaped, never
 * injected as raw HTML.
 *
 * Pattern mirrors privacy-safety.test.ts: lift renderExitDrill out of the
 * static CLIENT_SCRIPT string into a sandboxed Function so it can be called
 * against synthetic state objects without a real browser.
 */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

/**
 * Lift renderExitDrill (and the helpers it needs: escHtml, stepBlock) from
 * the client script into a sandbox. The script up to the fortress-column
 * marker contains everything renderExitDrill depends on.
 *
 * The returned render function accepts a synthetic state object and returns
 * the HTML string renderExitDrill would produce in a browser.
 */
function liftExitDrillRenderer(): { render: (state: unknown) => string } {
  const src = getClientScript();
  // Capture everything through the end of renderExitDrill, which ends just
  // before the fortress-column section. This range includes escHtml and all
  // local helpers renderExitDrill calls.
  let chunk = src.slice(0, src.indexOf("// ── Render: fortress column"));
  // Allow the test fixture to inject its own state.
  chunk = chunk.replace(/const\s+state\s*=/, "var state =");
  const wrapper = `
    var document = { getElementById: function() { return null; } };
    var window = { matchMedia: function() { return null; } };
    var sessionStorage = { getItem: function() { return null; }, setItem: function() {} };
    var location = { hash: "", host: "test" };
    ${chunk}
    return function(s) { state = s; return renderExitDrill(); };
  `;
  // eslint-disable-next-line no-new-func
  const factory = new Function(wrapper) as () => (s: unknown) => string;
  return { render: factory() };
}

function baseState(overrides: object = {}): object {
  return {
    route: "exit-drill",
    agents: [],
    inbox: [],
    activity: [],
    policies: [],
    privacyEvents: [],
    handoffEvents: [],
    topbarPills: {},
    tier1: { lockdown: { state: "idle", inboxItemId: null } },
    exitDrill: { step: 1, inboxItemId: null, bundleResult: null },
    selectedAgentId: null,
    chatActiveAgentId: null,
    seenEventIds: new Set(),
    sidebarCollapsed: false,
    ...overrides,
  };
}

/**
 * Lift onInboxAction from the client script into a test-controllable sandbox.
 *
 * All async side-effects (api, fetchAll, rerender, toast, renderTopbar,
 * onAgentInspectOpen) are replaced with minimal stubs. The function mutates
 * the state object passed in, so assertions read back from that same object.
 *
 * The slice runs from "async function onInboxAction(" to the
 * "// Tunability UX: promote" marker that immediately follows it, so the
 * extracted text is exactly the function and nothing else.
 */
function makeInboxActionSandbox(): {
  call: (state: object, itemId: string, action: string, apiReturn: object) => Promise<void>;
} {
  const src = getClientScript();
  const fnStart = src.indexOf("async function onInboxAction(");
  const fnEnd = src.indexOf("// Tunability UX: promote a pending approval", fnStart);
  const fnText = src.slice(fnStart, fnEnd).trim();

  const wrapper = `
    return async function invoke(stateObj, itemId, action, apiReturn) {
      var state = stateObj;
      var api = async function() { return apiReturn; };
      var toast = function() {};
      var fetchAll = async function() {};
      var rerender = function() {};
      var renderTopbar = function() {};
      var onAgentInspectOpen = async function() {};
      ${fnText}
      await onInboxAction(itemId, action);
    };
  `;
  // eslint-disable-next-line no-new-func
  const factory = new Function(wrapper) as () => (
    s: object,
    id: string,
    act: string,
    r: object,
  ) => Promise<void>;
  return { call: factory() };
}

describe("v1.1 dashboard exit drill onInboxAction (A7 regression)", () => {
  const { call } = makeInboxActionSandbox();

  // Minimal state for an exit-drill item. The lockdown inboxItemId is null so
  // the lockdown branch does NOT execute, which means on the buggy tree the
  // payload const is never declared and the exit-drill branch throws
  // ReferenceError when it tries to read payload.bundle_dir.
  function exitDrillState(itemId = "item-exit-1"): object {
    return {
      inbox: [],
      tier1: { lockdown: { inboxItemId: null, state: "idle" } },
      exitDrill: { step: 1, inboxItemId: itemId, bundleResult: null },
      selectedAgentId: null,
    };
  }

  function resolvedApi(pl: object, itemId = "item-exit-1"): object {
    return { data: { item: { item_id: itemId, agent_id: null, resolution_payload: pl } } };
  }

  // A7 regression: this test fails on the buggy tree because payload is
  // declared inside the lockdown if-block and is not in scope when the
  // exit-drill branch runs (ReferenceError). On the fixed tree the payload
  // is lifted to the outer scope and bundleResult is populated correctly.
  it("A7 regression: bundleResult receives all fields including state_entry_count 0 and warnings", async () => {
    const st = exitDrillState();
    await call(st, "item-exit-1", "approve", resolvedApi({
      bundle_dir: "/tmp/exit-bundles/reg",
      manifest_hash: "aabb1122",
      artifact_count: 3,
      state_entry_count: 0,
      warnings: ["No encrypted state found; bundle carries 0 state entries."],
    }));
    const br = (st as any).exitDrill.bundleResult;
    expect(br).not.toBeNull();
    expect(br.bundle_dir).toBe("/tmp/exit-bundles/reg");
    expect(br.manifest_hash).toBe("aabb1122");
    expect(br.artifact_count).toBe(3);
    // A7: zero must be preserved, not coerced to null or omitted.
    expect(br.state_entry_count).toBe(0);
    expect(Array.isArray(br.warnings)).toBe(true);
    expect(br.warnings[0]).toContain("No encrypted state found");
  });

  // Hardening: a negative count must be rejected and stored as null so the
  // renderer omits the field rather than displaying a nonsensical value.
  it("A7 hardening: negative state_entry_count is stored as null", async () => {
    const st = exitDrillState();
    await call(st, "item-exit-1", "approve", resolvedApi({
      bundle_dir: "/tmp/exit-bundles/neg",
      manifest_hash: "ff001122",
      artifact_count: 1,
      state_entry_count: -1,
    }));
    expect((st as any).exitDrill.bundleResult.state_entry_count).toBeNull();
  });

  // Hardening: a fractional count must be rejected and stored as null.
  it("A7 hardening: fractional state_entry_count is stored as null", async () => {
    const st = exitDrillState();
    await call(st, "item-exit-1", "approve", resolvedApi({
      bundle_dir: "/tmp/exit-bundles/frac",
      manifest_hash: "ff001122",
      artifact_count: 1,
      state_entry_count: 1.5,
    }));
    expect((st as any).exitDrill.bundleResult.state_entry_count).toBeNull();
  });

  // Approval path regression: when the API omits state_entry_count entirely,
  // it must be stored as null (not undefined or missing from bundleResult).
  // Other bundle fields must still populate to prove this is a wired approval path.
  it("A7 approval path: omitted state_entry_count is stored as null, other fields populate", async () => {
    const st = exitDrillState();
    await call(st, "item-exit-1", "approve", resolvedApi({
      bundle_dir: "/tmp/exit-bundles/omitted",
      manifest_hash: "cc001122",
      artifact_count: 2,
      // state_entry_count intentionally omitted
    }));
    const br = (st as any).exitDrill.bundleResult;
    expect(br).not.toBeNull();
    expect(br.bundle_dir).toBe("/tmp/exit-bundles/omitted");
    expect(br.manifest_hash).toBe("cc001122");
    expect(br.artifact_count).toBe(2);
    // Omitted field must be null, not undefined or missing.
    expect(br.state_entry_count).toBeNull();
  });

  // Hardening: non-string warning entries must be filtered out before they
  // reach escHtml so they cannot be coerced into the rendered HTML surface.
  it("A7 hardening: non-string warning entries are filtered; string entries are preserved", async () => {
    const st = exitDrillState();
    await call(st, "item-exit-1", "approve", resolvedApi({
      bundle_dir: "/tmp/exit-bundles/ws",
      manifest_hash: "ff001122",
      artifact_count: 1,
      state_entry_count: 0,
      warnings: [42, "real warning", { inject: "<script>" }, "another real warning"],
    }));
    expect((st as any).exitDrill.bundleResult.warnings).toEqual(["real warning", "another real warning"]);
  });
});

describe("v1.1 dashboard exit drill client rendering (A7)", () => {
  const { render } = liftExitDrillRenderer();

  // A7 fail-before: when bundleResult carries state_entry_count, the rendered
  // HTML must include the count so the operator sees it. On base, renderExitDrill
  // renders only bundle_dir and manifest_hash; this assertion fails.
  it("A7: renders state_entry_count explicitly in the bundle step (including 0)", () => {
    const html = render(
      baseState({
        exitDrill: {
          step: 3,
          inboxItemId: "item-1",
          bundleResult: {
            bundle_dir: "/tmp/exit-bundles/test",
            manifest_hash: "aabbccddee112233",
            artifact_count: 5,
            state_entry_count: 0,
          },
        },
      }),
    );
    // A7: the count must appear in the rendered output so "Bundle ready"
    // cannot hide that zero state entries were included.
    expect(html).toContain("0");
    // The specific label must be present so the operator knows what "0" means.
    // On base, neither "State entries" nor "state_entry_count" appears in the HTML.
    expect(html.toLowerCase()).toMatch(/state entr/);
  });

  // A7: zero count with a warning — the warning text must be visible.
  it("A7: renders the zero-state warning text when state_entry_count is 0 and warnings present", () => {
    const html = render(
      baseState({
        exitDrill: {
          step: 3,
          inboxItemId: "item-1",
          bundleResult: {
            bundle_dir: "/tmp/exit-bundles/test",
            manifest_hash: "aabbccddee112233",
            artifact_count: 1,
            state_entry_count: 0,
            warnings: ["No encrypted state found; bundle carries 0 state entries."],
          },
        },
      }),
    );
    // A7: the warning text must appear so the operator cannot mistake "Bundle
    // ready" for "state was included".
    expect(html).toContain("No encrypted state found");
  });

  // A7: when state_entry_count is null/absent despite bundleResult existing,
  // render explicit "Unavailable" so the absence is not silent.
  it("A7: renders explicit Unavailable row when state_entry_count is null", () => {
    const html = render(
      baseState({
        exitDrill: {
          step: 3,
          inboxItemId: "item-1",
          bundleResult: {
            bundle_dir: "/tmp/exit-bundles/test",
            manifest_hash: "aabbccddee112233",
            artifact_count: 5,
            state_entry_count: null,
          },
        },
      }),
    );
    // A7: must render "State entries" label so the operator sees the row.
    expect(html.toLowerCase()).toMatch(/state entr/);
    // A7: must render "Unavailable" explicitly so absence is truthful.
    expect(html).toContain("Unavailable");
  });

  // A7: when state_entry_count is undefined, behavior matches null case.
  it("A7: renders explicit Unavailable row when state_entry_count is undefined", () => {
    const html = render(
      baseState({
        exitDrill: {
          step: 3,
          inboxItemId: "item-1",
          bundleResult: {
            bundle_dir: "/tmp/exit-bundles/test",
            manifest_hash: "aabbccddee112233",
            artifact_count: 5,
            state_entry_count: undefined,
          },
        },
      }),
    );
    expect(html.toLowerCase()).toMatch(/state entr/);
    expect(html).toContain("Unavailable");
  });

  // A7: HTML injection in warning text must be escaped.
  it("A7: HTML-shaped warning text is escaped, not injected", () => {
    const MAGIC = '<script>alert("A7-XSS")</script>';
    const html = render(
      baseState({
        exitDrill: {
          step: 3,
          inboxItemId: "item-1",
          bundleResult: {
            bundle_dir: "/tmp/exit-bundles/test",
            manifest_hash: "aabbccddee112233",
            artifact_count: 1,
            state_entry_count: 0,
            warnings: [MAGIC],
          },
        },
      }),
    );
    // The raw script tag must never appear as live HTML.
    expect(html).not.toContain(MAGIC);
    // The escaped form (or the content text) must appear instead.
    expect(html).toContain("&lt;script&gt;");
  });
});
