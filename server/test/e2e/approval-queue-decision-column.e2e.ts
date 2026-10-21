/**
 * Approvals queue at 1440 px with the drawer open: the Decision column stays
 * fully inside the queue's scroll box, so its header and every decision control
 * read whole ("Allow once", "Deny", "Review in drawer", the decided chip) rather
 * than clipped at the box edge ("Allow or", "DECID").
 *
 * The cards are shaped as the hub serves the demo's two Charter holds: long
 * registry agent ids and operation names with no break opportunity, and the
 * gate's own hold reason. Reads are served locally; nothing is decided.
 */
import { test, expect } from "./fixtures/dashboard.js";

// The demo presenter's desktop width; at this width the drawer sits beside the queue.
const DESKTOP = { width: 1440, height: 900 };
const FIXTURE_TIME = "2026-10-21T14:36:00.000Z";
// Sub-pixel layout rounding allowance when comparing a box edge to its container's edge.
const EDGE_EPSILON_PX = 1;

const charterCard = (id: string, tier: "tier1" | "tier2", operation: string, category: string, extra: Record<string, unknown> = {}) => ({
  item_id: `charter.approval.${id}`, kind: "approval_pending", tier,
  agent_id: tier === "tier1" ? "agent:claude_code:fortress-db82f27ee2c7e7b2" : "agent:cursor:fortress-db82f27ee2c7e7b2",
  display_template_id: `approval_pending.${tier}.${category}`,
  display_template_args: [{ kind: "identity_id", value: "operator-e2e" }, { kind: "operation", value: operation }],
  resolved: false, created_at: FIXTURE_TIME, identity_id: "operator-e2e", operation_category: category,
  ...extra,
});

test.describe("Approvals queue Decision column at 1440 with the drawer open", () => {
  test.use({ viewport: DESKTOP });

  test("the Decision header and every decision cell fit inside the queue", async ({ page, dashboard }) => {
    const items = [
      charterCard("40b62abdc8074e8d", "tier1", "state_export", "state_export", {
        hold_reason: '"state_export" is a Tier 1 operation (always requires approval)',
      }),
      charterCard("81fe29c9ce4f71ea", "tier2", "state_write", "other", {
        hold_reason: 'First access to namespace "customer-notes" (not in session baseline)',
      }),
      charterCard("decided0decided0", "tier1", "sanctuary_export_identity_bundle", "other", {
        resolved: true, resolved_at: FIXTURE_TIME, decision: "deny",
        hold_reason: '"sanctuary_export_identity_bundle" is a Tier 1 operation (always requires approval)',
      }),
    ];
    await page.route("**/api/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      // Hold the event stream open without frames, so no reconnect redraw runs mid-measure.
      if (path === "/api/stream") return;
      const data = path === "/api/hub/inbox" ? { data: { items } }
        : path === "/api/posture/home" ? { origin_machine: "fixture", agents: [], castle_wall: { arm_state: "unknown" }, digest: {} }
        : path === "/api/posture/evidence" ? { origin_machine: "fixture", entries: [], total: 0, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } }
        : path === "/api/policy/current" ? { data: { view: { lines: [] } } }
        : { data: { configured: false, agents: [], items: [], entries: [], findings: [], messages: [], policies: [], rules: [], recommendations: [] } };
      await route.fulfill({ json: data });
    });
    await page.goto(dashboard.url + "/#approvals");

    // Open the Tier 2 hold in the drawer, as the presenter does.
    await page.locator('[data-action="approval-select"][data-item-id="charter.approval.81fe29c9ce4f71ea"]').first().click();
    const drawer = page.locator("aside.approval-drawer");
    await expect(drawer).toContainText("First access to namespace");
    const wrap = page.locator("#approval-queue");
    await expect(wrap).toBeVisible();

    // The drawer is open BESIDE the queue at this width, not stacked under it.
    const wrapBox = (await wrap.boundingBox())!;
    const drawerBox = (await drawer.boundingBox())!;
    expect(drawerBox.x).toBeGreaterThanOrEqual(wrapBox.x + wrapBox.width - EDGE_EPSILON_PX);
    expect(drawerBox.y).toBeLessThan(wrapBox.y + wrapBox.height);

    // Nothing in the queue needs horizontal scrolling to be seen.
    const overflow = await wrap.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }));
    expect(overflow.scroll).toBeLessThanOrEqual(overflow.client);

    const wrapRight = wrapBox.x + wrapBox.width + EDGE_EPSILON_PX;
    const header = wrap.locator("thead th").last();
    await expect(header).toHaveText("Decision");
    const headerFit = await header.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }));
    expect(headerFit.scroll).toBeLessThanOrEqual(headerFit.client);
    const headerBox = (await header.boundingBox())!;
    expect(headerBox.x + headerBox.width).toBeLessThanOrEqual(wrapRight);

    // Every queue row's Decision cell and each control or chip in it sits wholly inside the queue.
    const cells = wrap.locator("tbody tr:not(.sect) td:last-child");
    const cellCount = await cells.count();
    expect(cellCount).toBe(items.length);
    for (let i = 0; i < cellCount; i++) {
      const cell = cells.nth(i);
      const fit = await cell.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }));
      expect(fit.scroll, `decision cell ${i}`).toBeLessThanOrEqual(fit.client);
      const cellBox = (await cell.boundingBox())!;
      expect(cellBox.x + cellBox.width, `decision cell ${i}`).toBeLessThanOrEqual(wrapRight);
      const controls = cell.locator("button, .state-chip");
      const controlCount = await controls.count();
      expect(controlCount, `decision cell ${i} controls`).toBeGreaterThan(0);
      for (let j = 0; j < controlCount; j++) {
        const control = controls.nth(j);
        const box = (await control.boundingBox())!;
        expect(box.x + box.width, `decision cell ${i} control ${j}`).toBeLessThanOrEqual(wrapRight);
        const controlFit = await control.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }));
        expect(controlFit.scroll, `decision cell ${i} control ${j}`).toBeLessThanOrEqual(controlFit.client);
      }
    }
    await expect(wrap.locator('[data-action="inbox-approve"][data-item-id="charter.approval.81fe29c9ce4f71ea"]')).toHaveText("Allow once");
    await expect(wrap.locator('[data-approval-decision="denied"]')).toHaveText("DENIED");
  });
});
