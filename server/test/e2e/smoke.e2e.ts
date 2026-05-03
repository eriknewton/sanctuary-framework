/**
 * Playwright smoke test. Proves the harness boots the dashboard
 * end-to-end and reads a real DOM element. Introduced with the v1.2.0-rc.4
 * Playwright harness.
 */
import { test, expect } from "./fixtures/dashboard.js";

test("dashboard boots and renders the version pill", async ({ page, dashboard }) => {
  await page.goto(dashboard.url);

  // The version pill is server-rendered into the topbar. Server-rendered
  // first paint plus the client.ts renderTopbar refresh should both
  // produce `[data-pill="version"]` with the SANCTUARY_VERSION text.
  const versionPill = page.locator('[data-pill="version"]');
  await expect(versionPill).toBeVisible();
  await expect(versionPill).toContainText(/^v\d+\.\d+\.\d+/);
});

test("dashboard renders the main app shell", async ({ page, dashboard }) => {
  await page.goto(dashboard.url);
  await expect(page.locator("#app")).toBeVisible();
  await expect(page.locator("aside.sidebar")).toBeVisible();
  await expect(page.locator("header.topbar")).toBeVisible();
  await expect(page.locator("main#main")).toBeVisible();
});
