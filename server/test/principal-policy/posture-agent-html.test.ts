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
