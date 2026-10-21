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

// Desktop and a narrow phone width (390 px, a current iPhone viewport) at which the drawer stacks below the queue.
const GEOMETRY_VIEWPORTS = { desktop: { width: 1440, height: 900 }, narrow: { width: 390, height: 844 } } as const;
const GEOMETRY_TIME = "2026-10-21T12:00:00.000Z";
const geometryHeld = (id: string, tier = "tier2") => ({
  item_id: id, kind: "approval_pending", tier, agent_id: "fixture-agent",
  display_template_id: `approval_pending.${tier}.other`, display_template_args: [{ kind: "agent_id", value: "fixture-agent" }],
  resolved: false, created_at: GEOMETRY_TIME, identity_id: "operator-e2e", operation_category: "state_export",
});

/**
 * Boot Approvals with decision controls on screen, then make one read the Approvals screen does not draw (the fleet
 * roster) answer 401 or succeed on demand, so the token notice appears and clears while the controls stay live.
 */
async function prepareTokenGeometry(page: Page, url: string) {
  const gate = { refuseRoster: false };
  await page.clock.install({ time: new Date(GEOMETRY_TIME) });
  await page.clock.pauseAt(new Date(GEOMETRY_TIME));
  // Expose only the shipping per-panel retry, the entry point a Retry button uses.
  await page.route(url + "/", async (route) => {
    const response = await route.fetch();
    const html = (await response.text()).replace("void loadPanel(panelJobs[0]);",
      "window.tokenDriver = { refresh: function (path) { return retryPanel(path); } }; void loadPanel(panelJobs[0]);");
    await route.fulfill({ response, body: html });
  });
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/stream") return;
    if (path === "/api/fleet/roster") {
      await route.fulfill(gate.refuseRoster ? { status: 401, json: { error: "unauthorized" } } : { json: { available: false, nodes: [] } });
      return;
    }
    const data = path === "/api/hub/inbox" ? { data: { items: [geometryHeld("seed"), geometryHeld("later"), geometryHeld("armed", "tier1")] } }
      : path === "/api/posture/home" ? { origin_machine: "fixture", agents: [], castle_wall: { arm_state: "unknown" }, digest: {} }
      : path === "/api/posture/evidence" ? { origin_machine: "fixture", entries: [], total: 0, integrity_findings: [], chain_verdict: "verified", sealed_region: { status: "not_present" } }
      : path === "/api/policy/current" ? { data: { view: { lines: [] } } }
      : { data: { configured: false, agents: [], items: [], entries: [], findings: [], messages: [], policies: [], rules: [], recommendations: [] } };
    await route.fulfill({ json: data });
  });
  await page.goto(url + "/#approvals");
  await page.locator('[data-action="approval-select"][data-item-id="later"]').first().click();
  const approve = page.locator('.approval-drawer [data-action="inbox-approve"]');
  await expect(approve).toBeEnabled();
  await approve.scrollIntoViewIfNeeded();
  await page.evaluate("document.fonts.ready");
  await page.clock.runFor(SETTLE_FRAMES_MS);
  return gate;
}

/** Every decision control's rectangle, identity and eligibility, plus the workspace and feedback scroll offsets. */
function decisionGeometry(page: Page) {
  return page.evaluate<{ controls: Array<[string, string, boolean, number[]]>; mainScroll: number; feedbackBox: number[] }>(`(() => {
    const box = el => { const r = el.getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; };
    const controls = [...document.querySelectorAll('#main [data-action^="inbox-"], #main [data-action^="approval-"]')]
      .map(el => [el.getAttribute('data-action'), el.getAttribute('data-item-id') || '', el.disabled === true, box(el)]);
    return { controls, mainScroll: document.getElementById('main').scrollTop, feedbackBox: box(document.getElementById('feedback')) };
  })()`);
}

for (const [name, viewport] of Object.entries(GEOMETRY_VIEWPORTS)) {
  test(`${name}: the token notice and dialog never move a decision control or the screen's scroll`, async ({ page, dashboard }) => {
    await page.setViewportSize(viewport);
    const gate = await prepareTokenGeometry(page, dashboard.url);
    const baseline = await decisionGeometry(page);
    expect(baseline.controls.length, "decision controls are on screen").toBeGreaterThan(0);
    // At the narrow width the drawer sits below the queue, so a held scroll offset is part of what must not move.
    if (name === "narrow") expect(baseline.mainScroll, "the screen is scrolled to the drawer").toBeGreaterThan(0);
    const unchanged = async (step: string) => {
      await page.clock.runFor(SETTLE_FRAMES_MS);
      expect(await decisionGeometry(page), step).toEqual(baseline);
    };

    gate.refuseRoster = true;
    await page.evaluate("tokenDriver.refresh('/api/fleet/roster')");
    const open = page.getByRole("button", { name: "Paste operator token" });
    await expect(open).toBeVisible();
    await unchanged("notice appears");

    await open.click();
    await expect(page.getByRole("dialog", { name: "Paste operator token" })).toBeVisible();
    await unchanged("dialog open");
    await page.keyboard.press("Escape");
    await expect(page.locator("#operator-token-dialog")).not.toHaveAttribute("open", "");
    await unchanged("dialog closed with Escape");
    await open.click();
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.locator("#operator-token-dialog")).not.toHaveAttribute("open", "");
    await unchanged("dialog closed with Cancel");

    gate.refuseRoster = false;
    await page.evaluate("tokenDriver.refresh('/api/fleet/roster')");
    await expect(open).toHaveCount(0);
    await unchanged("notice clears");
  });
}

test("a malformed paste is refused in the dialog, and a held token the browser cannot send still offers a replacement", async ({ page, dashboard }) => {
  // An em-dash typo: outside Latin-1, so the browser cannot put it in an Authorization header.
  const malformed = "operator-token\u2014typo";
  await gateReadsOnToken(page);
  await page.goto(dashboard.url + "/#posture");
  await page.getByRole("button", { name: "Paste operator token" }).click();
  const dialog = page.getByRole("dialog", { name: "Paste operator token" });
  await dialog.getByRole("textbox", { name: "Operator token" }).fill(malformed);
  await dialog.getByRole("button", { name: "Use token" }).click();
  await expect(page.locator("#operator-token-error")).toContainText("That is not an operator token");
  await expect(dialog).toBeVisible();
  expect(await page.evaluate<string | null>("sessionStorage.getItem('authToken')")).toBeNull();

  // A token already held in that shape (from before the check existed) makes the real fetch throw; it still reads as refused.
  await page.evaluate(`sessionStorage.setItem('authToken', ${JSON.stringify(malformed)})`);
  await page.reload();
  await expect(page.locator("#feedback #operator-token-entry")).toContainText("contains characters that cannot be sent");
  // The panel reason comes from the read path's own conversion of the browser's header TypeError.
  await expect(page.locator("#main")).toContainText("the operator token held in this tab cannot be sent");
  await expect(page.getByRole("button", { name: "Paste operator token" })).toBeVisible();
});
