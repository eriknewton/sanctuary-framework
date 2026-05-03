/**
 * Playwright configuration for Sanctuary v1.1 dashboard SPA end-to-end
 * tests. Introduced in v1.2.0-rc.4 to close the structural gap surfaced
 * by Findings ZZ + DDD: server-side logic and HTTP-route assertions did
 * not reach bugs that lived in the SPA's render-and-refresh cycle on a
 * real browser. The Playwright suite is the new gate for any
 * operator-visible-state fix going forward.
 *
 * Chromium-only headless. The dashboard SPA targets evergreen Chromium
 * features (CSS grid, ESM modules, oklch). Cross-browser parity is not
 * a v1.x goal; we test what the operator runs.
 */
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./test/e2e",
  testMatch: /.*\.e2e\.ts/,
  // 60s test budget absorbs occasional cold-start variance (browser
  // launch + first-time TS transform). Per-action and per-expect
  // timeouts stay tight to keep individual assertions fast.
  timeout: 60_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  use: {
    headless: true,
    viewport: { width: 1280, height: 720 },
    actionTimeout: 5_000,
    navigationTimeout: 10_000,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
});
