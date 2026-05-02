/**
 * Sanctuary v1.2.x Dashboard sidebar click-to-inspect
 *
 * Mirrors the click-to-inspect behavior from the Agents view onto the
 * fortress-column agent rows in renderFortress(). Click target is the
 * agent-row-head sub-row; the action navigates to agent-detail and
 * fires the synchronous /agents/:id/inspect/open route. Lifecycle
 * buttons in agent-row-actions still take precedence (the dispatcher
 * walks up to the closest data-action ancestor; the buttons are
 * siblings, not children, of the head).
 *
 * Originally introduced as click-to-chat (PR #98 + PR #100); the
 * direct-agent chat surface was removed in the v1.2 reshape and the
 * sidebar wire-up was repurposed as click-to-inspect. Test descriptions
 * and anchors were updated to match. The data-action carried by the
 * head is `agent-row-inspect-open` (distinct from the simpler
 * `agent-inspect-open` used on the agent-detail buttons because the
 * sidebar variant must navigate AND inspect, while the button variant
 * is already on agent-detail and only inspects).
 *
 * These are server-side rendered-script / CSS-shape assertions; the
 * full route round-trip is exercised by inspect-routes coverage.
 */

import { describe, expect, it } from "vitest";
import {
  renderDashboardV11Html,
  getClientScript,
} from "../../../src/dashboard/v1_1/index.js";

describe("v1.1 dashboard sidebar click-to-inspect (fortress-column agent rows)", () => {
  it("emits the agent-row-head with the agent-row-inspect-open action wired", () => {
    const script = getClientScript();
    // The head sub-row carries data-action + data-agent-id + role +
    // tabindex so it acts as a click + keyboard target. Pin every
    // attribute so accessibility does not silently regress.
    expect(script).toContain('class="agent-row-head" data-action="agent-row-inspect-open" data-agent-id="');
    expect(script).toContain('role="button" tabindex="0"');
    expect(script).toContain('title="Open inspect panel for ');
  });

  it("dispatcher routes agent-row-inspect-open to selectedAgentId + agent-detail + onAgentInspectOpen", () => {
    const script = getClientScript();
    // The wire-up sets selectedAgentId and navigates to #agent-detail,
    // then fires the synchronous round-trip POST /agents/:id/inspect/open.
    // The optimistic openingAgentId pane renders while the response lands.
    expect(script).toContain('action === "agent-row-inspect-open" && agentId');
    expect(script).toMatch(/state\.selectedAgentId = agentId;[\s\S]*?location\.hash[\s\S]*?onAgentInspectOpen\(agentId\)/);
  });

  it("Enter and Space activate the role=button head via keydown", () => {
    const script = getClientScript();
    // Real <button> elements get keyboard activation natively; the head
    // is a div with role="button" + tabindex="0", so it needs an
    // explicit keydown handler. Pin the handler shape so accessibility
    // does not silently regress to mouse-only.
    expect(script).toContain('addEventListener("keydown"');
    expect(script).toContain('ev.key !== "Enter" && ev.key !== " "');
    expect(script).toContain('action !== "agent-row-inspect-open"');
    expect(script).toContain('ev.preventDefault();');
  });

  it("CSS pins cursor pointer + hover + focus-visible on the head click target", () => {
    const html = renderDashboardV11Html({});
    // The CSS block must contain the click-to-inspect affordance rules
    // so the row signals clickability; without these the operator has
    // no visual cue that the head is a click target.
    expect(html).toContain('.agent-row-head[data-action="agent-row-inspect-open"] { cursor: pointer;');
    expect(html).toContain('.agent-row-head[data-action="agent-row-inspect-open"]:hover { background:');
    expect(html).toContain('.agent-row-head[data-action="agent-row-inspect-open"]:focus-visible { outline:');
  });

  it("agent-row-head structural anchors from Finding DD are preserved", () => {
    // Pin that the layout fix from v1.1.7 Finding DD still holds:
    // the head + actions stay split into separate sub-rows so a wide
    // agent_id does not push action buttons onto the next line in the
    // narrow fortress column. Adding click-to-inspect must not collapse
    // this back to a single-row layout.
    const html = renderDashboardV11Html({});
    expect(html).toContain(".agent-row-head { display: flex;");
    expect(html).toContain(".agent-row-actions { display: flex; flex-wrap: wrap;");
    expect(html).toContain(".agent-row-head .grow { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis;");
  });

  it("lifecycle action buttons still carry their own data-action so the head click does not swallow them", () => {
    const script = getClientScript();
    // The dispatcher walks up to the closest data-action ancestor.
    // Lifecycle buttons (Pause / Resume / Restart / Lockdown / Unwrap)
    // are emitted with their own data-action="agent-<sub>" so a click
    // on a button finds that action first and does NOT bubble up to
    // agent-row-inspect-open on the head. Pin the agent-<sub> pattern
    // so the click hierarchy stays correct.
    expect(script).toContain("'<button class=\"btn\" data-action=\"agent-' + mi.action +");
    // And the dispatcher routes agent-<sub> through onAgentControl, so
    // a Pause click does not accidentally fire agent-row-inspect-open.
    expect(script).toMatch(/action\.indexOf\("agent-"\) === 0 && agentId/);
  });
});
