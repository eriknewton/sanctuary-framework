/**
 * Sanctuary v1.1 Dashboard — Agents row layout (v1.1.7 Finding DD)
 *
 * The right-pane Agents widget renders one row per agent with: status
 * glyph, agent_id, status pill, and 5 action buttons (Pause, Resume,
 * Restart, Lockdown, Unwrap). At v1.1.6, all five children sat on a
 * single flex row, so on the structurally narrow `.fortress` sidebar the
 * agent_id text and pill visually overlapped the action buttons.
 *
 * v1.1.7 fix: stack the row into a head sub-row (glyph + agent_id +
 * pill) and an actions sub-row (the 5 buttons). The widget never tries
 * to fit all five children on one line.
 *
 * These are server-side rendered-HTML / CSS-shape assertions; visual
 * verification at multiple desktop widths is operator-side at acceptance.
 */

import { describe, expect, it } from "vitest";
import { renderDashboardV11Html, getClientScript } from "../../../src/dashboard/v1_1/index.js";

describe("v1.1 dashboard agents row layout (Finding DD)", () => {
  it("client script emits each agent row with the stacked agent-row shape", () => {
    const script = getClientScript();
    // The renderer template builds: <div class="row agent-row" ...> with
    // a head sub-row and an actions sub-row inside. Pin the structural
    // anchors so the layout doesn't silently regress to single-row.
    expect(script).toContain('class="row agent-row" data-agent-row=');
    expect(script).toContain('class="agent-row-head"');
    expect(script).toContain('class="agent-row-actions"');
  });

  it("emitted CSS stacks the agent-row vertically (column flex)", () => {
    const html = renderDashboardV11Html({});
    // The CSS block in the shell HTML must contain the stacking rule —
    // .agent-row overrides the parent .row's row-direction with column.
    expect(html).toContain(".agent-row { flex-direction: column;");
    // The head sub-row keeps a horizontal flex so glyph + id + pill
    // sit on one line; this is the same layout intent as the legacy
    // .row, just scoped to the head.
    expect(html).toContain(".agent-row-head { display: flex;");
    // The actions sub-row wraps the 5 buttons under the head.
    expect(html).toContain(".agent-row-actions { display: flex; flex-wrap: wrap;");
  });

  it("agent_id text in the head sub-row gets ellipsis truncation, not overflow", () => {
    const html = renderDashboardV11Html({});
    // .agent-row-head .grow uses overflow:hidden + text-overflow:ellipsis
    // so a long agent_id doesn't push the pill into the next column or
    // wrap onto a second line. Pin the truncation rule.
    expect(html).toContain(".agent-row-head .grow { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis;");
  });
});
