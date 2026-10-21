/**
 * Console first-run polish in a real browser engine: the operator-token entry for refused reads, the quiet empty
 * feedback row, and the scroll reset on a route change. The VM witnesses in
 * test/dashboard/v1_1/console-first-run-polish.test.ts cover the client logic; these cover what only a browser
 * can show: the native dialog and reload, computed styles, and the real workspace scroller.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures/dashboard.js";
import { FEEDBACK_VIEWPORTS, SETTLE_FRAMES_MS, prepareFeedback } from "./feedback-isolation-helpers.js";

// A token-shaped value distinctive enough that any echo of it is unambiguous.
const PASTED_TOKEN = "e2e-pasted-operator-token-41d7";

/** Every API read is refused unless it carries the pasted bearer, as a fortress that requires the operator token. */
async function gateReadsOnToken(page: Page) {
  await page.route("**/auth/session", (route) => route.fulfill({ json: { session_id: "no-auth" } }));
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    // Hold the event stream open without frames; ending it would schedule reconnect reads.
    if (path === "/api/stream") return;
    if (route.request().headers()["authorization"] !== "Bearer " + PASTED_TOKEN) {
      await route.fulfill({ status: 401, json: { error: "unauthorized" } });
      return;
    }
    const data = path === "/api/posture/home" ? { origin_machine: "fixture-mac", agents: [], castle_wall: { arm_state: "unknown" }, digest: {} }
      : path === "/api/posture/evidence" ? { origin_machine: "fixture-mac", entries: [], total: 0, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } }
      : path === "/api/policy/current" ? { data: { view: { lines: [] } } }
      : { data: { configured: false, agents: [], items: [], entries: [], findings: [], messages: [], policies: [], rules: [], recommendations: [] } };
    await route.fulfill({ json: data });
  });
}

test("a refused read offers Paste operator token; the pasted token is stored for the tab and the reads reload", async ({ page, dashboard }) => {
  const consoleText: string[] = [];
  page.on("console", (message) => consoleText.push(message.text()));
  await gateReadsOnToken(page);
  await page.goto(dashboard.url + "/#posture");
  const open = page.getByRole("button", { name: "Paste operator token" });
  await expect(open).toBeVisible();
  await expect(page.locator("#feedback #operator-token-entry")).toContainText("No operator token is held in this tab");

  await open.click();
  const dialog = page.getByRole("dialog", { name: "Paste operator token" });
  await expect(dialog).toBeVisible();
  const field = dialog.getByRole("textbox", { name: "Operator token" });
  await expect(field).toBeFocused();
  await expect(field).toHaveAttribute("type", "password");
  await field.fill(PASTED_TOKEN);
  await Promise.all([page.waitForEvent("load"), page.getByRole("button", { name: "Use token" }).click()]);

  await expect(page.locator("#main")).toContainText("fixture-mac");
  await expect(page.getByRole("button", { name: "Paste operator token" })).toHaveCount(0);
  expect(await page.evaluate(() => sessionStorage.getItem("authToken"))).toBe(PASTED_TOKEN);
  expect(page.url()).not.toContain(PASTED_TOKEN);
  expect(await page.locator("#operator-token-input").inputValue()).toBe("");
  expect(await page.evaluate<string>("document.documentElement.outerHTML")).not.toContain(PASTED_TOKEN);
  expect(consoleText.join("\n")).not.toContain(PASTED_TOKEN);
});

test("an empty feedback row is quiet and keeps its reserved box; feedback content restores the visible row", async ({ page, dashboard }) => {
  await page.setViewportSize(FEEDBACK_VIEWPORTS.D);
  await prepareFeedback(page, dashboard.url, "approvals", false);
  const feedback = page.locator("#feedback");
  const look = () => page.evaluate<{ border: string; fill: string; rect: number[] }>(`(() => {
    const el = document.getElementById('feedback');
    const css = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    return { border: css.borderTopColor, fill: css.backgroundColor, rect: [r.x, r.y, r.width, r.height] };
  })()`);
  const quiet = await look();
  expect(quiet.border, "no edge while empty").toBe("rgba(0, 0, 0, 0)");
  expect(quiet.fill, "no band while empty").toBe("rgba(0, 0, 0, 0)");
  const approve = page.locator('[data-action="inbox-approve"][data-item-id="seed"]').first();
  const before = await approve.boundingBox();

  await page.evaluate('feedbackDriver.toast("Ordinary feedback")');
  await expect(feedback).toContainText("Ordinary feedback");
  await page.clock.runFor(SETTLE_FRAMES_MS);
  const shown = await look();
  expect(shown.border, "the edge returns with content").not.toBe("rgba(0, 0, 0, 0)");
  expect(shown.rect, "the reserved box never moves or resizes").toEqual(quiet.rect);
  expect(await approve.boundingBox(), "a decision control never moves").toEqual(before);
});

test("a route change opens the new screen at the top of main", async ({ page, dashboard }) => {
  await page.setViewportSize(FEEDBACK_VIEWPORTS.N);
  await prepareFeedback(page, dashboard.url, "approvals", false);
  const main = page.locator("#main");
  await main.evaluate((el) => { el.scrollTop = el.scrollHeight; });
  expect(await main.evaluate((el) => el.scrollTop)).toBeGreaterThan(0);
  await page.evaluate('location.hash = "#activity"');
  await expect(main).toContainText("Evidence");
  expect(await main.evaluate((el) => el.scrollTop)).toBe(0);
});
