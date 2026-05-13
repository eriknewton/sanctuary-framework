import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

describe("v1.1 dashboard auto-trigger ladder view", () => {
  it("renders the auto-trigger route as a sibling dashboard view", () => {
    const src = getClientScript();
    expect(src).toContain('case "auto-trigger": nextHtml = renderAutoTriggerPage();');
    expect(src).not.toContain("dashboard-auto-trigger-view");
  });

  it("hydrates rules, recommendations, and full rule history", () => {
    const src = getClientScript();
    expect(src).toContain("autoTrigger: { rules: [], recommendations: []");
    expect(src).toContain('await autoTriggerApi("/rules")');
    expect(src).toContain('await autoTriggerApi("/rules/" + encodeURIComponent(list[i].rule_id))');
    expect(src).toContain('await autoTriggerApi("/recommendations")');
  });

  it("renders threshold controls and saves through the existing API route", () => {
    const src = getClientScript();
    expect(src).toContain("renderAutoTriggerRuleRow");
    expect(src).toContain("auto-trigger-threshold-save");
    expect(src).toContain("warn_sigma");
    expect(src).toContain("alert_sigma");
    expect(src).toContain("promotion_fire_count");
    expect(src).toContain("promotion_window_days");
    expect(src).toContain("cancel_window_seconds");
    expect(src).toContain('method: "PATCH"');
  });

  it("refreshes the ladder on auto-trigger audit activity", () => {
    const src = getClientScript();
    expect(src).toContain('indexOf("auto_trigger")');
    expect(src).toContain('indexOf("auto_action")');
    expect(src).toContain("fetchAutoTriggerState().then(rerender)");
  });
});
