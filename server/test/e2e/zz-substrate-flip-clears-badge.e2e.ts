/**
 * Playwright e2e for Finding ZZ: substrate flip on a surface with prior
 * recent failures must clear that surface's recent-failures expansion in
 * the operator-visible UI within ~3s, AND the post-flip operator-visible
 * status payload must report `badge.status: "green"` and
 * `failureClass: null` (not just `recentFailures: []`).
 *
 * Two scenarios:
 *
 *   A. Per-surface flip: operator changes ONE surface (concierge:
 *      venice -> local). Expectation: concierge's "View recent
 *      failures (N)" expansion is gone (N === 0 hides the block per
 *      the renderIntelligenceCenter logic), AND a fresh fetch of
 *      `/api/hub/intelligence/status` returns concierge with
 *      `badge.status: "green"`, `failureClass: null`,
 *      `recentFailures.length: 0`. OTHER surfaces with their own buffer
 *      entries are untouched.
 *   B. Bulk flip: operator changes ALL surfaces via the "Apply to all
 *      surfaces" toggle. Expectation: every surface's failures
 *      expansion is gone AND every surface's `/status` row is green +
 *      `failureClass: null` + `recentFailures.length: 0`.
 *
 * History (why all three properties are asserted in rc.6):
 *   - rc.2 (244912a) cleared the recent-failures buffer on substrate
 *     change. The rc.4 version of these tests asserted only
 *     `recentFailures.length === 0`. That assertion passed under all
 *     three rc.x rounds (rc.2, rc.3, rc.4, rc.5) because it was true
 *     after the rc.2 fix landed.
 *   - rc.6 drill (Pass 6, 2026-05-03) showed that even with empty
 *     `recentFailures`, the operator-visible badge stayed yellow with
 *     `failureClass: substrate_misconfigured` because the static probe
 *     in `probeSurfaceHealth` kept returning `substrate_misconfigured`
 *     for `chosen: "local"` when Ollama's `/api/tags` returned model
 *     names with the default `:latest` suffix (e.g. `phi4-mini:latest`)
 *     while `LOCAL_MODEL_TAGS["phi-4-mini"]` was the bare `"phi4-mini"`.
 *     The rc.6 fix lands at the derivation site (probe), accepting
 *     `${expectedTag}:latest` as a match when `expectedTag` lacks a
 *     colon. These tests now assert the post-flip state at all three
 *     levels (recentFailures empty AND failureClass null AND badge
 *     green) so any future regression on either side surfaces here.
 *
 * The Ollama probe is stubbed so the local-substrate static probe can
 * return green. Without the stub, `ollamaReachable` is false and the
 * post-flip badge would be red (`substrate_unavailable`), which would
 * make the green-badge assertion impossible to satisfy in a test
 * harness with no real Ollama. The stub returns `phi4-mini:latest`
 * specifically to exercise the rc.6 tag-asymmetry fix.
 */
import { test, expect, ollamaTagsStub } from "./fixtures/dashboard.js";

test.use({
  dashboardOptions: { fetchImpl: ollamaTagsStub(["phi4-mini:latest"]) },
});

test.describe("Finding ZZ: substrate flip clears recent-failures expansion in SPA", () => {
  test("Scenario A: per-surface flip clears that surface's expansion AND turns badge green", async ({
    page,
    dashboard,
  }) => {
    // Seed: configure concierge with venice substrate and record one
    // failure so the expansion renders on first paint. Pick phi-4-mini
    // for the local target so it matches the stubbed Ollama
    // `phi4-mini:latest` (rc.6 tag-asymmetry exercise).
    await dashboard.selector.setPerSurfaceChoice("concierge", "venice");
    await dashboard.selector.setLocalModelPick("concierge", "phi-4-mini");
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

    // rc.6 structural assertion: the post-flip operator-visible status
    // payload must report concierge as fully green. Asserting against
    // the live `/status` endpoint (not just the SPA's render of it)
    // catches the bug class where the SPA renders correctly against a
    // payload that itself is wrong.
    const statusResp = await page.request.get(
      `${dashboard.url}/api/hub/intelligence/status`,
    );
    expect(statusResp.ok()).toBe(true);
    const statusJson = (await statusResp.json()) as {
      data: {
        surfaces: Array<{
          surface: string;
          badge: { status: string };
          failureClass: string | null;
          recentFailures: unknown[];
        }>;
      };
    };
    const concierge = statusJson.data.surfaces.find(
      (s) => s.surface === "concierge",
    );
    expect(concierge).toBeDefined();
    expect(concierge!.recentFailures).toHaveLength(0);
    expect(concierge!.failureClass).toBeNull();
    expect(concierge!.badge.status).toBe("green");
  });

  test("Scenario B: bulk flip clears every surface's expansion AND turns every badge green", async ({
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

    // Pick local + phi-4-mini (matches the stubbed Ollama
    // `phi4-mini:latest`) + save. The bulk-apply path forwards the
    // local model pick to every surface so all 6 land on the same
    // green-able binding.
    await page
      .locator(
        '[data-action="intel-picker-select-substrate"][data-intel-substrate="local"]',
      )
      .click();
    await page
      .locator(
        '[data-action="intel-picker-select-local-model"][data-intel-local-model="phi-4-mini"]',
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

    // rc.6 structural assertion: every surface's status row reports
    // green. The bulk-apply path is the operator-friendliest gesture
    // (apply-to-all defaults to checked); a regression on any single
    // surface here would re-open the rc.5 field-failure shape.
    const statusResp = await page.request.get(
      `${dashboard.url}/api/hub/intelligence/status`,
    );
    expect(statusResp.ok()).toBe(true);
    const statusJson = (await statusResp.json()) as {
      data: {
        surfaces: Array<{
          surface: string;
          badge: { status: string };
          failureClass: string | null;
          recentFailures: unknown[];
        }>;
      };
    };
    for (const surface of statusJson.data.surfaces) {
      expect(surface.recentFailures, `surface ${surface.surface} recentFailures`).toHaveLength(0);
      expect(surface.failureClass, `surface ${surface.surface} failureClass`).toBeNull();
      expect(surface.badge.status, `surface ${surface.surface} badge.status`).toBe("green");
    }
  });
});
