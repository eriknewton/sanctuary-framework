/** Render the live drawer in isolation; boot/event coverage lives in shell-wired-consumers. */
import { runInNewContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

export function renderApprovalFixture(alwaysAllow = false): string {
  const script = getClientScript();
  // The drawer now consumes the same strict timestamp parser as the booted client.
  const timestampStart = script.indexOf("function parseEvidenceTimestamp");
  const timestampParser = script.slice(timestampStart, script.indexOf("\n}\n", timestampStart) + 3);
  const declarations = script.slice(script.indexOf("const APPROVAL_QUEUE_ITEM_CAP"), script.indexOf("function renderEnforcementScreen"));
  return runInNewContext(timestampParser + "\n" + declarations + "\nrenderApprovalDrawer(item)", {
    item: { item_id: "fixture", tier: "tier2", operation_category: "state_export", agent_id: "fixture-agent", resolved: false },
    state: { approvals: { alwaysAllow }, policyView: {} },
    POLICY: "/api/policy",
    promotableOperation: () => "state_export",
    NON_PROMOTABLE_OPERATIONS: {},
    sourceRead: () => ({ state: "state_LOADED" }), sourceLoaded: () => true,
    // The decision lock and its drawer echo live beside the settlement code; this fixture renders an idle drawer.
    decisionInFlight: () => false, renderDecisionInline: () => "",
    escHtml: (v: unknown) => String(v ?? ""),
    renderTemplate: () => "fixture operation",
    renderTemplateHtml: () => "fixture operation",
  }) as string;
}
