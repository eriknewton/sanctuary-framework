/**
 * Sanctuary v1.2.x Dashboard sidebar click-to-chat
 *
 * Mirrors the PR #98 click-to-chat behavior from the Agents view onto
 * the fortress-column agent rows in renderFortress(). Click target is
 * the agent-row-head sub-row; the action navigates to agent-detail and
 * fires the synchronous PR #98 /session/start route. Lifecycle buttons
 * in agent-row-actions still take precedence (the dispatcher walks up
 * to the closest data-action ancestor; the buttons are siblings, not
 * children, of the head).
 *
 * These are server-side rendered-script / CSS-shape assertions; the
 * full route round-trip is exercised by chat-routes.test.ts and the
 * curl-driven real-server drill on the build subthread.
 */

import { describe, expect, it } from "vitest";
import {
  renderDashboardV11Html,
  getClientScript,
} from "../../../src/dashboard/v1_1/index.js";

describe("v1.1 dashboard sidebar click-to-chat (fortress-column agent rows)", () => {
  it("emits the agent-row-head with the open-agent-chat action wired", () => {
    const script = getClientScript();
    // The head sub-row carries data-action + data-agent-id + role +
    // tabindex so it acts as a click + keyboard target. Pin every
    // attribute so accessibility does not silently regress.
    expect(script).toContain('class="agent-row-head" data-action="open-agent-chat" data-agent-id="');
    expect(script).toContain('role="button" tabindex="0"');
    expect(script).toContain('title="Open direct chat with ');
  });

  it("dispatcher routes open-agent-chat to selectedAgentId + agent-detail + onAgentInspectOpen", () => {
    const script = getClientScript();
    // WP-V1.2 reshape: the click-to-chat surface was repurposed as
    // click-to-inspect. The wire-up still sets selectedAgentId and
    // navigates to #agent-detail, but the synchronous round-trip is
    // now POST /agents/:id/inspect/open. The optimistic openingAgentId
    // pane renders while the response lands.
    expect(script).toContain('action === "open-agent-chat" && agentId');
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
    expect(script).toContain('action !== "open-agent-chat"');
    expect(script).toContain('ev.preventDefault();');
  });

  it("CSS pins cursor pointer + hover + focus-visible on the head click target", () => {
    const html = renderDashboardV11Html({});
    // The CSS block must contain the click-to-chat affordance rules so
    // the row signals clickability; without these the operator has no
    // visual cue that the head is a click target.
    expect(html).toContain('.agent-row-head[data-action="open-agent-chat"] { cursor: pointer;');
    expect(html).toContain('.agent-row-head[data-action="open-agent-chat"]:hover { background:');
    expect(html).toContain('.agent-row-head[data-action="open-agent-chat"]:focus-visible { outline:');
  });

  it("agent-row-head structural anchors from Finding DD are preserved", () => {
    // Pin that the layout fix from v1.1.7 Finding DD still holds:
    // the head + actions stay split into separate sub-rows so a wide
    // agent_id does not push action buttons onto the next line in the
    // narrow fortress column. Adding click-to-chat must not collapse
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
    // open-agent-chat on the head. Pin the agent-<sub> pattern so the
    // click hierarchy stays correct.
    expect(script).toContain("'<button class=\"btn\" data-action=\"agent-' + mi.action +");
    // And the dispatcher routes agent-<sub> through onAgentControl, so
    // a Pause click does not accidentally fire open-agent-chat.
    expect(script).toMatch(/action\.indexOf\("agent-"\) === 0 && agentId/);
  });
});
