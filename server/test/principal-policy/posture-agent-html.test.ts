import { describe, expect, it } from "vitest";
import { renderPostureAgentHTML } from "../../src/principal-policy/posture-agent-html.js";

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
