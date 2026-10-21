import { test, expect } from "./fixtures/dashboard.js";
import { FEEDBACK_VIEWPORTS, DECISION_RELEASE_HOLD_MS, prepareFeedback } from "./feedback-isolation-helpers.js";

// Release witness for the decision lock: a refused Allow always on the selected request resets consent, which
// rewrites the drawer copy above the primary button and moves it. The witness samples the button once per
// animation frame and requires that every frame in which it is enabled shows it where the previous frames,
// for at least the release hold, showed it disabled. A release in the same frame as the move fails.
test.describe.configure({ retries: 0 });
const FRAME_MS = Math.ceil(1000 / 60);
// The hold spans at least this many whole frames; one frame of slack absorbs where sampling starts.
const HOLD_FRAMES = Math.floor(DECISION_RELEASE_HOLD_MS / FRAME_MS) - 1;

for (const width of ["D", "N"] as const) {
  test.describe(`release hold ${width}`, () => {
    test.use({ viewport: FEEDBACK_VIEWPORTS[width] });
    test("a refused Allow always moves the drawer button only while it stays paused", async ({ page, dashboard }) => {
      await prepareFeedback(page, dashboard.url, "approvals", false);
      await page.locator('[data-action="approval-select"][data-item-id="seed"]').first().click();
      await page.locator('[data-action="approval-always-allow"]').check();
      const primary = '[data-approval-primary="seed"]';
      await expect(page.locator(primary)).toHaveAttribute("data-action", "inbox-promote");
      await page.locator(primary).scrollIntoViewIfNeeded();
      await page.evaluate(`(() => {
        const frames = [];
        const sample = () => {
          const b = document.querySelector(${JSON.stringify(primary)});
          if (b) {
            const r = b.getBoundingClientRect();
            frames.push({ x: r.x, y: r.y, w: r.width, h: r.height, disabled: b.disabled, action: b.getAttribute("data-action") });
          }
          requestAnimationFrame(sample);
        };
        window.releaseFrames = frames;
        requestAnimationFrame(sample);
      })()`);
      await page.clock.runFor(2 * FRAME_MS);
      const before = await page.evaluate<{ y: number; h: number }>("window.releaseFrames[window.releaseFrames.length - 1]");
      await page.locator(primary).click();
      await expect(page.locator('#feedback [data-decision-status="refused"]')).toContainText("Fixture refusal");
      for (let t = 0; t < DECISION_RELEASE_HOLD_MS + 4 * FRAME_MS; t += FRAME_MS) await page.clock.runFor(FRAME_MS);
      const frames = await page.evaluate<Array<{ x: number; y: number; w: number; h: number; disabled: boolean; action: string }>>("window.releaseFrames.slice()");
      const after = frames[frames.length - 1]!;
      expect(after.disabled, "the controls enable after the hold").toBe(false);
      expect(after.action, "consent was reset to Allow once").toBe("inbox-approve");
      expect(Math.abs(after.y - before.y) + Math.abs(after.h - before.h), "the reset moved the button, so the witness is not vacuous").toBeGreaterThan(1);
      const same = (a: { x: number; y: number; w: number; h: number }, b: { x: number; y: number; w: number; h: number }) =>
        Math.abs(a.x - b.x) <= 1 && Math.abs(a.y - b.y) <= 1 && Math.abs(a.w - b.w) <= 1 && Math.abs(a.h - b.h) <= 1;
      const firstEnabled = frames.findIndex((f, i) => i > 0 && !f.disabled && frames[i - 1]!.disabled);
      expect(firstEnabled, "a disabled frame precedes the first enabled one").toBeGreaterThan(0);
      for (let i = firstEnabled; i < frames.length; i++) expect(same(frames[i]!, frames[firstEnabled]!), "frame " + i + " stays put once enabled").toBe(true);
      let held = 0;
      for (let i = firstEnabled - 1; i >= 0 && frames[i]!.disabled && same(frames[i]!, frames[firstEnabled]!); i--) held++;
      expect(held, "disabled frames at the final position before enabling").toBeGreaterThanOrEqual(HOLD_FRAMES);
    });
  });
}
