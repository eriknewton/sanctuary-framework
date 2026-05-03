/**
 * Playwright e2e for Finding ZZ (v1.2.0-rc.4): substrate flip on a
 * surface with prior recent failures must clear that surface's
 * recent-failures expansion in the operator-visible UI within ~3s.
 *
 * Two scenarios:
 *
 *   A. Per-surface flip: operator changes ONE surface (concierge:
 *      venice -> local). Expectation: concierge's "View recent
 *      failures (N)" expansion is gone (N === 0 hides the block per
 *      the renderIntelligenceCenter logic). OTHER surfaces with their
 *      own buffer entries are untouched.
 *   B. Bulk flip: operator changes ALL surfaces via the "Apply to all
 *      surfaces" toggle. Expectation: every surface's failures
 *      expansion is gone.
 *
 * The rc.3 intelligence-api-router test proved the server-side ring
 * buffer clears on flip and /status returns recentFailures: []. The
 * rc.2 + rc.3 field failures showed the SPA's view of /status did not
 * refresh in time. These tests assert the operator-visible UI state
 * after the flip, not the API response shape.
 */
import { test, expect } from "./fixtures/dashboard.js";

test.describe("Finding ZZ: substrate flip clears recent-failures expansion in SPA", () => {
  test("Scenario A: per-surface flip clears that surface's expansion", async ({
    page,
    dashboard,
  }) => {
    // Seed: configure concierge with venice substrate and record one
    // failure so the expansion renders on first paint.
    await dashboard.selector.setPerSurfaceChoice("concierge", "venice");
    dashboard.selector.recordRecentFailureForTest(
      "concierge",
      "substrate_misconfigured",
      "venice configured model not found on validation probe",
    );
    // Seed sentinel-scoring with its own failure so we can assert the
    // per-surface flip does not leak across surfaces.
    await dashboard.selector.setPerSurfaceChoice("sentinel-scoring", "venice");
    dashboard.selector.recordRecentFailureForTest(
      "sentinel-scoring",
      "substrate_auth_failed",
      "venice key rejected on sentinel call",
    );

    await page.goto(dashboard.url);
    await page.locator("#app").waitFor();

    // Navigate to the Intelligence panel.
    await page.evaluate(() => {
      window.location.hash = "intelligence";
    });

    // Wait for the concierge intel row to render with its failures
    // button visible. The button text is `View recent failures (1)`.
    const conciergeRow = page.locator('.intel-row[data-intel-surface="concierge"]');
    await conciergeRow.waitFor();
    const conciergeFailuresBtn = conciergeRow.locator(
      '[data-action="intel-failures-toggle"]',
    );
    await expect(conciergeFailuresBtn).toBeVisible();
    await expect(conciergeFailuresBtn).toContainText("recent failures (1)");

    const sentinelRow = page.locator(
      '.intel-row[data-intel-surface="sentinel-scoring"]',
    );
    const sentinelFailuresBtn = sentinelRow.locator(
      '[data-action="intel-failures-toggle"]',
    );
    await expect(sentinelFailuresBtn).toBeVisible();
    await expect(sentinelFailuresBtn).toContainText("recent failures (1)");

    // Open the picker for concierge.
    await conciergeRow
      .locator('[data-action="intel-picker-open"]')
      .click();

    // Turn off "apply to all surfaces" so this is a per-surface flip.
    const applyToAll = page.locator(
      '[data-action="intel-picker-toggle-apply-to-all"]',
    );
    if (await applyToAll.isChecked()) {
      await applyToAll.click();
    }

    // Pick "local" substrate.
    await page
      .locator(
        '[data-action="intel-picker-select-substrate"][data-intel-substrate="local"]',
      )
      .click();

    // Save.
    await page.locator('[data-action="intel-picker-save"]').click();

    // Within 3s the concierge expansion must be gone.
    await expect(
      conciergeRow.locator('[data-action="intel-failures-toggle"]'),
    ).toHaveCount(0, { timeout: 3000 });

    // Sentinel-scoring's expansion must remain (cross-surface
    // isolation).
    await expect(
      sentinelRow.locator('[data-action="intel-failures-toggle"]'),
    ).toBeVisible();
    await expect(
      sentinelRow.locator('[data-action="intel-failures-toggle"]'),
    ).toContainText("recent failures (1)");
  });

  test("Scenario B: bulk flip clears every surface's expansion", async ({
    page,
    dashboard,
  }) => {
    await dashboard.selector.setPerSurfaceChoice("concierge", "venice");
    await dashboard.selector.setPerSurfaceChoice("sentinel-scoring", "venice");
    dashboard.selector.recordRecentFailureForTest(
      "concierge",
      "substrate_misconfigured",
      "venice model not found",
    );
    dashboard.selector.recordRecentFailureForTest(
      "sentinel-scoring",
      "substrate_auth_failed",
      "venice key rejected",
    );

    await page.goto(dashboard.url);
    await page.locator("#app").waitFor();

    await page.evaluate(() => {
      window.location.hash = "intelligence";
    });

    const conciergeRow = page.locator('.intel-row[data-intel-surface="concierge"]');
    const sentinelRow = page.locator(
      '.intel-row[data-intel-surface="sentinel-scoring"]',
    );
    await expect(
      conciergeRow.locator('[data-action="intel-failures-toggle"]'),
    ).toBeVisible();
    await expect(
      sentinelRow.locator('[data-action="intel-failures-toggle"]'),
    ).toBeVisible();

    // Open the picker via concierge's Change button.
    await conciergeRow.locator('[data-action="intel-picker-open"]').click();

    // Apply-to-all defaults to checked. Confirm it's checked.
    const applyToAll = page.locator(
      '[data-action="intel-picker-toggle-apply-to-all"]',
    );
    await expect(applyToAll).toBeChecked();

    // Pick local + save.
    await page
      .locator(
        '[data-action="intel-picker-select-substrate"][data-intel-substrate="local"]',
      )
      .click();
    await page.locator('[data-action="intel-picker-save"]').click();

    // Both surfaces' expansions must be gone within 3s.
    await expect(
      conciergeRow.locator('[data-action="intel-failures-toggle"]'),
    ).toHaveCount(0, { timeout: 3000 });
    await expect(
      sentinelRow.locator('[data-action="intel-failures-toggle"]'),
    ).toHaveCount(0, { timeout: 3000 });
  });
});
