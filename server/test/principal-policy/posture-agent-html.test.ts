import { describe, expect, it } from "vitest";
import { renderPostureAgentHTML } from "../../src/principal-policy/posture-agent-html.js";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";

/**
 * Extract the source of a named `function NAME(` ... matching-brace block from a
 * rendered page string. Used to pin the honesty-critical client functions
 * byte-for-byte across the two posture surfaces (#641). Brace-balanced so it is
 * robust to nested blocks.
 */
function extractFnSource(html: string, fnHeader: string): string {
  const start = html.indexOf(fnHeader);
  if (start === -1) throw new Error("function not found: " + fnHeader);
  const open = html.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < html.length; i++) {
    const ch = html[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return html.slice(start, i + 1);
    }
  }
  throw new Error("unbalanced braces for: " + fnHeader);
}

/**
 * Slice 4 of the unified posture dashboard: the per-agent drill-down page. These
 * tests pin the #617/#634 honesty contract on the new surface. The page reuses
 * the existing reach shaper and the Slice 1 PostureAgentRow; its only color
 * logic is the agent Standing pill, which must mirror the Home grid: GREEN only
 * on confirmed live enforcement, amber for policy-only "protection requested",
 * never green for unknown.
 */
describe("posture agent drill-down - honesty + composition", () => {
  it("renders the Standing and Effective reach sections", () => {
    const html = renderPostureAgentHTML();
    expect(html).toContain("Standing");
    expect(html).toContain("Effective reach");
  });

  it("composes existing data only - reuses the reach endpoint and the home payload", () => {
    const html = renderPostureAgentHTML();
    // No new server shaper on the surface: the page fetches the already-built
    // reach endpoint and the composed home payload client-side.
    expect(html).toContain("/api/posture/reach/");
    expect(html).toContain("/api/posture/home");
  });

  it("the agent Standing pill never maps a non-active enforcement state to green", () => {
    const html = renderPostureAgentHTML();
    const start = html.indexOf("function agentPill(row)");
    expect(start).toBeGreaterThan(-1);
    const fnSource = html.slice(start, start + 400);
    // Green is keyed strictly on confirmed enforcement.
    expect(fnSource).toContain('enforcement_active === "active"');
    expect(fnSource).toContain('pill green">enforcement active');
    // Policy-only protection is amber "protection requested", never green.
    expect(fnSource).toContain('pill amber">protection requested');
    // No green branch keyed on policy_protected alone or on unknown.
    expect(fnSource).not.toMatch(/policy_protected[^\n]*pill green/);
    expect(fnSource).not.toMatch(/unknown[^\n]*pill green/);
  });

  it("renders an honest agent-not-found state rather than a crash or a fake card", () => {
    const html = renderPostureAgentHTML();
    expect(html).toContain("function renderNotFound()");
    expect(html).toContain("Agent not found.");
    // The not-found state is driven by the reach endpoint's 404, surfaced
    // honestly (no fabricated enforcement).
    expect(html).toContain("e.status === 404");
  });

  it("surfaces the no-wall-policy reach gap honestly (red, not implied protection)", () => {
    const html = renderPostureAgentHTML();
    expect(html).toContain("has_wall_policy");
    expect(html).toContain("No Castle Wall ruleset applies to this agent");
  });

  it("contains no em-dash in the rendered page", () => {
    // The page is a user-facing string artifact; the no-em-dash rule applies to
    // the whole output, not just stripped comments.
    expect(renderPostureAgentHTML()).not.toContain("—");
  });
});

/**
 * Phase 2 distress tile (design 2026-06-19 2.4): the agent drill-down Standing
 * section gains a Distress channel tile. CISO-first: it lives in the secondary
 * drill-down, never on Home. Honesty (#617): facts only, never a green
 * "channel healthy/active"; absence of signals is "no distress signals
 * recorded", never a fabricated green all-well; the guaranteed-egress habeas
 * rule is a structural policy fact, not a welfare guarantee.
 */
describe("posture agent drill-down - distress tile honesty", () => {
  it("renders a Distress channel section fed by the already-mounted inbox endpoint", () => {
    const html = renderPostureAgentHTML();
    expect(html).toContain("Distress channel");
    expect(html).toContain('id="distress"');
    // Reuses the existing, durable inbox endpoint (no new plumbing on the surface).
    expect(html).toContain("/api/distress/inbox");
    expect(html).toContain("renderDistress(");
  });

  it("the distress renderer has no green branch and frames absence honestly", () => {
    const html = renderPostureAgentHTML();
    const start = html.indexOf("function renderDistress(inbox)");
    expect(start).toBeGreaterThan(-1);
    const end = html.indexOf("function renderReach(reach)");
    expect(end).toBeGreaterThan(start);
    const fnSource = html.slice(start, end);
    // FACTS-ONLY: no green pill anywhere in the distress tile.
    expect(fnSource).not.toContain("pill green");
    // Absence is "no distress signals recorded", never a green all-well.
    expect(fnSource).toContain("No distress signals recorded");
    // The empty-state copy explicitly disavows a green all-well reading.
    expect(fnSource).toContain('never green');
    // The most-recent line states a received signal is a fact, not a health state.
    expect(fnSource).toContain("not a health state");
  });

  it("surfaces the guaranteed-egress habeas lane as a structural policy fact, not a liveness claim", () => {
    const html = renderPostureAgentHTML();
    const start = html.indexOf("function renderDistress(inbox)");
    const end = html.indexOf("function renderReach(reach)");
    const fnSource = html.slice(start, end);
    expect(fnSource).toContain("habeas port");
    expect(fnSource).toContain("8741");
    expect(fnSource).toContain("policy cannot remove or shadow");
    // Explicitly NOT a claim the listener is bound.
    expect(fnSource).toContain("not a claim that the listener is currently bound");
  });

  it("distress fetch is best-effort: a failure renders the honest empty state", () => {
    const html = renderPostureAgentHTML();
    // The inbox fetch falls back to an empty inbox on error rather than crashing
    // or implying anything green.
    expect(html).toContain('renderDistress({ data: { entries: [], count: 0 } })');
  });
});

/**
 * #641: the reach drill-down's ENFORCEMENT presentation must be gated on the
 * SAME enforcement evidence the agent Standing pill uses. A curated rule on disk
 * is CONFIGURATION, not proof the OS is enforcing it. So when enforcement is not
 * confirmed (today: always, since no per-agent live enforcement signal exists),
 * the reach table must NOT emit a green Castle Wall pill, a green deny pill, or
 * the "only the destinations listed below are reachable" default-deny-in-effect
 * claim. Green OS-enforcement coloring + that claim are reserved for the
 * enforcement_confirmed case.
 */
describe("posture agent drill-down - reach enforcement honesty (#641)", () => {
  it("the reach renderer keys OS-enforcement coloring on enforcement_confirmed", () => {
    const html = renderPostureAgentHTML();
    const fnSource = extractFnSource(html, "function renderReach(reach)");
    // The honesty gate exists and reads the SAME evidence the pill keys on.
    expect(fnSource).toContain("reach.enforcement_confirmed === true");
  });

  it("the deny disposition pill is green ONLY under confirmed enforcement", () => {
    const html = renderPostureAgentHTML();
    const fnSource = extractFnSource(
      html,
      "function dispositionPill(d, enforcementConfirmed)",
    );
    // Green deny is gated on enforcementConfirmed; the un-confirmed branch is a
    // non-green "deny (configured)" amber pill.
    expect(fnSource).toContain("enforcementConfirmed");
    expect(fnSource).toContain('pill amber">deny (configured)');
    // The ONLY green branch must sit inside the enforcementConfirmed ternary, so
    // a green deny can never be emitted when enforcement is unconfirmed.
    expect(fnSource).toMatch(
      /enforcementConfirmed\s*\?\s*'<span class="pill green">deny<\/span>'/,
    );
  });

  it("the Castle Wall layer pill is green ONLY under confirmed enforcement", () => {
    const html = renderPostureAgentHTML();
    const fnSource = extractFnSource(
      html,
      "function layerLabel(layer, enforcementConfirmed)",
    );
    expect(fnSource).toContain("enforcementConfirmed");
    // Un-confirmed castle_wall lines render amber "Castle Wall (configured)".
    expect(fnSource).toContain('pill amber">Castle Wall (configured)');
    // The green Castle Wall pill sits strictly inside the confirmed branch.
    expect(fnSource).toMatch(
      /enforcementConfirmed\s*\?\s*'<span class="pill green">Castle Wall<\/span>'/,
    );
  });

  it("does NOT claim default-deny is in effect unless enforcement is confirmed", () => {
    const html = renderPostureAgentHTML();
    const fnSource = extractFnSource(html, "function renderReach(reach)");
    // The default-deny-in-effect copy must be gated behind the confirmed branch
    // (the else of `!enforcementConfirmed`), never emitted unconditionally.
    const defaultDenyIdx = fnSource.indexOf(
      "only the destinations listed below are reachable",
    );
    expect(defaultDenyIdx).toBeGreaterThan(-1);
    const gateIdx = fnSource.indexOf("!enforcementConfirmed");
    expect(gateIdx).toBeGreaterThan(-1);
    // The honest "configured, not confirmed enforcing" copy precedes the
    // default-deny claim and is the branch taken when enforcement is unconfirmed.
    // (The page source splits the sentence across concatenated string literals,
    // so assert a contiguous literal fragment, not the rendered concatenation.)
    expect(fnSource).toContain(
      "operating system is not confirmed to be enforcing them",
    );
    expect(fnSource).toContain(
      "not a confirmed in-effect block",
    );
  });
});

/**
 * #641 LOW: the agent Standing pill is the most-screenshotted honesty surface,
 * and it is rendered on BOTH the Home grid and the per-agent drill-down. The two
 * copies MUST be byte-identical so the "never fake green" contract cannot
 * silently drift on one surface. They now share a single source of truth
 * (posture-html-shared.ts); this test pins that they render identically.
 */
describe("posture agentPill byte-identity across surfaces (#641)", () => {
  it("the agentPill body is byte-identical on Home and on the drill-down", () => {
    const home = extractFnSource(renderPostureHomeHTML(), "function agentPill(row)");
    const agent = extractFnSource(renderPostureAgentHTML(), "function agentPill(row)");
    expect(agent).toBe(home);
    // And it still encodes the honesty contract (green only on confirmed active).
    expect(home).toContain('enforcement_active === "active"');
    expect(home).toContain('pill green">enforcement active');
    expect(home).toContain('pill amber">protection requested');
    expect(home).not.toMatch(/policy_protected[^\n]*pill green/);
  });
});
