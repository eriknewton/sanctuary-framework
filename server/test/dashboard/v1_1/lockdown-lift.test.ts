/** Operator-approved per-agent network restoration copy and browser control. IC-11. */
import { describe, expect, it } from "vitest";
import { renderTemplate } from "../../../src/dashboard/v1_1/templates.js";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import { clientDeclarations } from "./client-script-extract.js";

describe("per-agent network restoration display IC-11", () => {
  it("serves the exact approval sentence with a named or absent agent", () => {
    const consequence = " network access. Castle Wall puts back the allow rules it removed at lockdown; the agent reaches off-machine destinations again once the reload is confirmed.";
    expect(renderTemplate("approval_pending.tier1.lockdown_lift", [{ kind: "agent_id", value: "alpha" }])).toBe("Restore agent alpha's" + consequence);
    expect(renderTemplate("approval_pending.tier1.lockdown_lift", [])).toBe("Restore an agent's" + consequence);
  });

  it("serves the exact restored, partial and refused lifecycle sentences", () => {
    const args = [{ kind: "agent_id" as const, value: "alpha" }];
    expect(renderTemplate("activity.lifecycle.agent_lockdown_lifted", args)).toBe("Network access restored for agent alpha.");
    expect(renderTemplate("activity.lifecycle.agent_lockdown_lift_partial", args)).toBe("Network access rules were restored on disk for agent alpha, but the live Castle Wall reload was not confirmed.");
    expect(renderTemplate("activity.lifecycle.agent_lockdown_lift_refused", args)).toBe("Network restore refused for agent alpha.");
  });

  it("the browser renderer requires both shared permission and locked status", () => {
    const { renderAgentControlButtons } = clientDeclarations<{ renderAgentControlButtons: (agent: unknown) => string }>(
      ["AGENT_CONTROL_LABELS", "agentControlLabel", "escHtml", "renderAgentControlButtons"], ["renderAgentControlButtons"],
    );
    for (const canLockdown of [true, false]) {
      for (const status of ["active", "locked_down"]) {
        const html = renderAgentControlButtons({ agent_id: "alpha", status, capabilities: { can_lockdown: canLockdown } });
        const button = html.match(/<button[^>]*data-action="agent-lockdown_lift"[^>]*>[^<]*<\/button>/)?.[0];
        expect(button).toContain("Restore network access");
        expect(button!.includes(" disabled")).toBe(!(canLockdown && status === "locked_down"));
      }
    }
  });

  it("the existing browser control handler posts lift through the shared endpoint", async () => {
    const script = getClientScript();
    const handler = script.slice(script.indexOf("async function onAgentControl("), script.indexOf("\n}", script.indexOf("async function onAgentControl(")) + "\n}".length);
    const calls: unknown[] = [];
    const invoke = new Function("api", "agentControlLabel", "toast", "fetchAll", "state", "rerender", handler + '; return onAgentControl("alpha", "lockdown_lift");');
    await invoke(async (path: string, options: unknown) => {
      calls.push({ path, options });
      return { status: 202, data: { inbox_item_id: "lift-approval", status: "approval_pending" } }; // Shared asynchronous approval response.
    }, () => "Restore network access", () => {}, async () => {}, {}, () => {});
    expect(calls).toEqual([{ path: "/agents/alpha/lockdown_lift", options: { method: "POST", body: {} } }]);
  });

  it("lift approvals cannot become standing auto-allow rules", () => {
    const { NON_PROMOTABLE_OPERATIONS } = clientDeclarations<{ NON_PROMOTABLE_OPERATIONS: Record<string, boolean> }>(["NON_PROMOTABLE_OPERATIONS"], ["NON_PROMOTABLE_OPERATIONS"]);
    expect(NON_PROMOTABLE_OPERATIONS.lockdown_lift).toBe(true);
  });
});
