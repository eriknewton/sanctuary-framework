import { test, expect } from "./fixtures/dashboard.js";
import {
  FEEDBACK_VIEWPORTS, TOAST_LIFETIME_MS, prepareFeedback,
  recordFeedbackBaseline, assertFeedbackIsolation,
} from "./feedback-isolation-helpers.js";

// Slice 1 owns feedback-only transitions. Admission, release, reconstruction,
// consent and background geometry are deliberately outside these witnesses.
test.describe.configure({ retries: 0 });

// The recorder independently walks every shell/main element, including these
// surface predecessors; inserted or replaced children also fail its observer.
const predecessorManifest = {
  A: "shell/main, heading, filters, scope/source/warnings, queue/header/groups, preceding rows/cells/echoes, drawer heading/details/standing/actions",
  E: "shell/main, heading, integrity/query/chips/source/entries/detail/raw/export/fortress, preferences/filter/batch/groups, preceding inbox rows",
};
const configurations = [
  { surface: "A", width: "D", target: "later" },
  { surface: "A", width: "D", target: "armed" },
  { surface: "A", width: "S", target: "later" },
  { surface: "A", width: "S", target: "armed" },
  { surface: "E", width: "N", target: "later" },
] as const;

for (const config of configurations) {
  test.describe(`${config.surface} ${config.width} ${config.target}`, () => {
    test.use({ viewport: FEEDBACK_VIEWPORTS[config.width] });
    for (const witness of ["F-feedback", "G-clear", "G-toast-expire"] as const) {
      test(witness, async ({ page, dashboard }) => {
        test.info().annotations.push({ type: "predecessor-manifest", description: predecessorManifest[config.surface] });
        const requests = await prepareFeedback(page, dashboard.url, config.surface === "A" ? "approvals" : "activity");
        let selector: string;
        if (config.surface === "A") {
          await page.locator(`[data-action="approval-select"][data-item-id="${config.target}"]`).first().click();
          if (config.target === "armed") {
            await page.locator('[data-action="approval-start-tier1-allow"]').click();
            selector = '[data-action="approval-confirm-tier1-allow"]';
          } else selector = '.approval-drawer [data-action="inbox-approve"]';
        } else selector = '[data-action="inbox-select"][data-item-id="later"]';
        await expect(page.locator(selector)).toBeEnabled();
        if (witness === "G-toast-expire") {
          // One hundred sentences overflow F. The product entry point schedules its real expiry.
          await page.evaluate('feedbackDriver.toast("Toast expiry feedback. ".repeat(100), "error")');
          await expect(page.locator('#feedback .toast')).toBeVisible();
        }
        await recordFeedbackBaseline(page, selector, config.surface === "A");
        const requestCount = requests.length;
        if (witness === "F-feedback") {
          await page.evaluate('feedbackDriver.varyResult(); feedbackDriver.toast("Ordinary feedback")');
          await expect(page.locator('#feedback')).toContainText("Ordinary feedback");
        } else if (witness === "G-clear") {
          await page.locator('[data-action="decision-result-clear"]').click();
          await expect(page.locator('#decision-feedback-result')).toBeEmpty();
        } else {
          await page.clock.runFor(TOAST_LIFETIME_MS);
          await expect(page.locator('#feedback .toast')).toHaveCount(0);
        }
        await assertFeedbackIsolation(page, witness);
        expect(requests.length, witness + ': no read or decision request').toBe(requestCount);
        // Liveness: the same surviving control still accepts a fresh action.
        if (config.surface === "E") {
          await page.locator(selector).click();
          await expect(page.locator(selector)).toBeChecked();
        } else {
          await page.locator(selector).click();
          // One fixture decision plus this fresh decision.
          await expect.poll(() => requests.filter(r => r.startsWith("POST ")).length).toBe(2);
        }
        if (config.surface === "A" && config.width === "D" && config.target === "later" && witness === "F-feedback") {
          await page.locator('#btn-talk').click();
          const feedback = await page.locator('#feedback').boundingBox();
          const panel = await page.locator('#talk-panel').boundingBox();
          expect(panel!.y + panel!.height, "Talk panel ends above F").toBeLessThanOrEqual(feedback!.y + 1);
          await page.locator('[data-action="talk-open-full"]').click();
          await expect(page.locator('#feedback')).toContainText("Fixture refusal");
          const input = await page.locator('[data-action="concierge-input"]').boundingBox();
          expect(input!.y + input!.height, "full-page Talk composer ends above F").toBeLessThanOrEqual(feedback!.y + 1);
        }
      });
    }
  });
}
