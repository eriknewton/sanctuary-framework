/**
 * Playwright e2e for Finding ZZ (v1.2.0-rc.5): the dashboard SPA must
 * fetch /intelligence/status (and other GETs) with cache-busting so
 * WebKit/Safari does not serve a stale prior response after a substrate
 * flip. rc.4's existing e2e suite passes under both Chromium and
 * Playwright WebKit because Playwright's bundled WebKit build does not
 * reproduce real Safari's HTTP cache behavior on localhost. This test
 * verifies the fix shape directly: every GET the SPA issues to
 * /api/hub/* must carry both a `_t=<epoch>` query string AND a
 * `cache: "no-store"` request init (surfaced via the `Cache-Control`
 * request header). Either alone is insufficient — Safari has been
 * documented to ignore `no-store` on responses with ETags but no
 * Last-Modified, and a heuristic cache may reuse a URL that varies
 * only by query string when no Cache-Control is set. Belt + suspenders.
 *
 * The acceptance criterion is operator-visible: after a substrate flip,
 * subsequent /intelligence/status GETs reach the server (not the
 * cache), so the SPA's view tracks server state.
 */
import { test, expect } from "./fixtures/dashboard.js";

test.describe("Finding ZZ rc.5: GET requests carry cache-bust + no-store", () => {
  test("every /api/hub/* GET request includes _t query string + Cache-Control: no-cache header", async ({
    page,
    dashboard,
  }) => {
    const seenGets: { url: string; cacheControl: string | null }[] = [];

    page.on("request", (req) => {
      if (req.method() !== "GET") return;
      const u = req.url();
      if (u.indexOf("/api/hub/") < 0) return;
      seenGets.push({
        url: u,
        cacheControl: req.headers()["cache-control"] ?? null,
      });
    });

    await page.goto(dashboard.url);
    await page.locator("#app").waitFor();
    await page.locator('[data-pill="version"]').waitFor();

    // Wait long enough for the initial fetchAll cycle to issue its
    // /policies, /activity, /intelligence/status, and /chat/concierge
    // /history GETs.
    await page.waitForTimeout(500);

    expect(
      seenGets.length,
      "fetchAll must have issued at least one GET to /api/hub/*",
    ).toBeGreaterThan(0);

    for (const g of seenGets) {
      expect(
        g.url,
        `every GET must carry _t=<epoch>; saw: ${g.url}`,
      ).toMatch(/[?&]_t=\d+(&|$)/);
      expect(
        g.cacheControl,
        `every GET must send Cache-Control: no-cache; saw: ${g.cacheControl} for ${g.url}`,
      ).toBe("no-cache");
    }
  });

  test("after substrate flip, /intelligence/status fetch carries a fresh _t value", async ({
    page,
    dashboard,
  }) => {
    await dashboard.selector.setPerSurfaceChoice("concierge", "venice");
    dashboard.selector.recordRecentFailureForTest(
      "concierge",
      "substrate_misconfigured",
      "venice configured model not found on validation probe",
    );

    const statusGets: { tParam: string; ts: number }[] = [];
    page.on("request", (req) => {
      if (req.method() !== "GET") return;
      const u = req.url();
      if (u.indexOf("/api/hub/intelligence/status") < 0) return;
      const m = u.match(/[?&]_t=(\d+)/);
      statusGets.push({
        tParam: m ? m[1] : "",
        ts: Date.now(),
      });
    });

    await page.goto(dashboard.url);
    await page.locator("#app").waitFor();
    await page.evaluate(() => {
      window.location.hash = "intelligence";
    });

    const conciergeRow = page.locator(
      '.intel-row[data-intel-surface="concierge"]',
    );
    await conciergeRow.waitFor();

    // Capture the initial fetch _t.
    await page.waitForTimeout(250);
    const beforeFlip = statusGets.length;
    expect(
      beforeFlip,
      "initial /intelligence/status fetch must fire",
    ).toBeGreaterThan(0);
    const initialT = statusGets[beforeFlip - 1].tParam;

    // Flip substrate.
    await conciergeRow
      .locator('[data-action="intel-picker-open"]')
      .click();
    const applyToAll = page.locator(
      '[data-action="intel-picker-toggle-apply-to-all"]',
    );
    if (await applyToAll.isChecked()) {
      await applyToAll.click();
    }
    await page
      .locator(
        '[data-action="intel-picker-select-substrate"][data-intel-substrate="local"]',
      )
      .click();
    await page.locator('[data-action="intel-picker-save"]').click();

    // After save, the SPA fires another /intelligence/status fetch via
    // fetchIntelligenceState. That fetch must carry a different _t
    // (epoch advanced) so Safari/WebKit cannot serve the cached
    // pre-flip response.
    await expect
      .poll(
        () => statusGets.length,
        { timeout: 3000, message: "post-flip status fetch must fire" },
      )
      .toBeGreaterThan(beforeFlip);

    const postFlipT = statusGets[statusGets.length - 1].tParam;
    expect(
      postFlipT,
      "post-flip _t must advance past initial _t to defeat heuristic caches",
    ).not.toBe(initialT);
    expect(Number(postFlipT)).toBeGreaterThan(Number(initialT));
  });
});
