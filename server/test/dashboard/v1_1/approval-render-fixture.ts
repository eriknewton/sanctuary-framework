/** Render the live drawer in isolation; boot/event coverage lives in shell-wired-consumers. */
import { runInNewContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

export function renderApprovalFixture(alwaysAllow = false): string {
  const script = getClientScript();
  const declarations = script.slice(script.indexOf("const APPROVAL_QUEUE_ITEM_CAP"), script.indexOf("function renderEnforcementScreen"));
  return runInNewContext(declarations + "\nrenderApprovalDrawer(item)", {
    item: { item_id: "fixture", tier: "tier2", operation_category: "state_export", agent_id: "fixture-agent", resolved: false },
    state: { approvals: { alwaysAllow }, policyView: {} },
    POLICY: "/api/policy",
    promotableOperation: () => "state_export",
    NON_PROMOTABLE_OPERATIONS: {},
    sourceRead: () => ({ state: "state_LOADED" }), sourceLoaded: () => true,
    escHtml: (v: unknown) => String(v ?? ""),
    renderTemplate: () => "fixture operation",
  }) as string;
}
