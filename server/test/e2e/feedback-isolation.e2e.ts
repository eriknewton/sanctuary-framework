import { test, expect } from "./fixtures/dashboard.js";
import {
  FEEDBACK_VIEWPORTS, TOAST_LIFETIME_MS, prepareFeedback,
  recordFeedbackBaseline, assertFeedbackIsolation, SETTLE_FRAMES_MS,
} from "./feedback-isolation-helpers.js";

// Slice 1 owns feedback-only transitions. Admission, release, reconstruction,
// consent and unrelated background geometry are outside these witnesses. G-clear
// includes the next timer redraw with unchanged source data.
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
  { surface: "A", width: "N", target: "later" },
  { surface: "E", width: "N", target: "later" },
] as const;

for (const config of configurations) {
  test.describe(`${config.surface} ${config.width} ${config.target}`, () => {
    test.use({ viewport: FEEDBACK_VIEWPORTS[config.width] });
    for (const witness of ["F-feedback", "G-clear keyboard", "G-clear pointer", "G-toast-expire"] as const) {
      test(witness, async ({ page, dashboard }) => {
        const clear = witness.startsWith("G-clear");
        const keyboardClear = witness === "G-clear keyboard";
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
        if (keyboardClear) {
          await page.locator('[data-action="decision-result-clear"]').focus();
        }
        await recordFeedbackBaseline(page, selector, config.surface === "A");
        const requestCount = requests.length;
        if (witness === "F-feedback") {
          test.info().annotations.push({ type: "driver-bound", description: "Message variation exercises the shipping F patcher, not decision settlement." });
          await page.evaluate('feedbackDriver.varyResult(); feedbackDriver.toast("Ordinary feedback")');
          await expect(page.locator('#feedback')).toContainText("Ordinary feedback");
          await expect(page.locator('#decision-feedback-result')).toContainText("Retained feedback.");
        } else if (clear) {
          if (keyboardClear) await page.keyboard.press('Enter');
          else await page.locator('[data-action="decision-result-clear"]').click();
          await expect(page.locator('#decision-feedback-result')).toBeEmpty();
          if (keyboardClear) await expect(page.locator('#feedback')).toBeFocused();
          else expect(await page.evaluate('document.getElementById("main").contains(document.activeElement)'),
            'pointer Clear does not move focus into main').toBe(false);
          await expect(page.locator('#main .decision-inline').first()).toHaveText("Refused.");
        } else {
          await page.clock.runFor(TOAST_LIFETIME_MS);
          await expect(page.locator('#feedback .toast')).toHaveCount(0);
        }
        await assertFeedbackIsolation(page, witness);
        if (clear) {
          // The continuing path has its own baseline after Clear. All main nodes,
          // controls and predecessors plus shell boxes must survive the redraw.
          await recordFeedbackBaseline(page, selector, config.surface === "A", true);
          await page.evaluate('feedbackDriver.backgroundRedraw()');
          await page.clock.runFor(SETTLE_FRAMES_MS);
          expect(await page.evaluate('feedbackDriver.redraws')).toBe(1);
          await assertFeedbackIsolation(page, "G-clear continuing timer redraw", false);
          await expect(page.locator('#decision-feedback-result')).toBeEmpty();
        }
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
        if (config.target === "later" && witness === "F-feedback") {
          if (config.surface === "A") {
            // The liveness decision replaces the earlier variation; vary its settled result before navigation.
            await expect(page.locator('#decision-feedback-result')).toContainText("Fixture refusal");
            await expect(page.locator('[data-action="decision-result-clear"]')).toBeEnabled();
            await page.evaluate('feedbackDriver.varyResult()');
          }
          await expect(page.locator('#decision-feedback-result')).toContainText("Retained feedback.");
          await page.locator('#btn-talk').click();
          const feedback = await page.locator('#feedback').boundingBox();
          const panel = await page.locator('#talk-panel').boundingBox();
          expect(panel!.y + panel!.height, "Talk panel ends above F").toBeLessThanOrEqual(feedback!.y + 1);
          await page.locator('[data-action="talk-open-full"]').click();
          await expect(page.locator('#decision-feedback-result')).toContainText("Retained feedback.");
          // Retained feedback already exists while hash navigation is still mounting Talk.
          // A dormant composer outside main must not compete with the visible full-page composer.
          await page.evaluate(`(() => {
            const dormant = document.createElement("input");
            dormant.dataset.action = "concierge-input";
            dormant.hidden = true;
            document.body.appendChild(dormant);
          })()`);
          const composer = page.locator('#main [data-action="concierge-input"]');
          await expect(composer).toBeVisible();
          const input = await composer.boundingBox();
          expect(input!.y + input!.height, "full-page Talk composer ends above F").toBeLessThanOrEqual(feedback!.y + 1);
        }
      });
    }
  });
}

// Keep base navigation at both widths called out by the reviews.
for (const width of [375, 759]) {
  test(`narrow rail ${width}`, async ({ page, dashboard }) => {
    await page.setViewportSize({ width, height: FEEDBACK_VIEWPORTS.N.height });
    await prepareFeedback(page, dashboard.url, "activity");
    const links = page.locator('#sidebar-nav a');
    await expect(links).toHaveCount(10);
    for (const link of await links.all()) await expect(link).toBeInViewport({ ratio: 1 });
    expect((await page.locator('.sidebar').boundingBox())!.width).toBe(56);
    const feedback = (await page.locator('#feedback').boundingBox())!;
    expect(feedback.x).toBe(0);
    expect(feedback.width).toBe(width);
  });
}

test('narrow toast is visible with retained result and scrolled F', async ({ page, dashboard }) => {
  await page.setViewportSize(FEEDBACK_VIEWPORTS.N);
  await prepareFeedback(page, dashboard.url, "activity");
  await page.evaluate('feedbackDriver.varyResult(); document.getElementById("feedback").scrollTop = document.getElementById("feedback").scrollHeight');
  const mainScroll = await page.locator('#main').evaluate(el => el.scrollTop);
  await page.evaluate('feedbackDriver.toast("New error feedback", "error")');
  const visible = await page.evaluate<boolean>(`(() => {
    const el = document.querySelector('#feedback .toast');
    const f = document.getElementById('feedback');
    const box = f.getBoundingClientRect(), toast = el.getBoundingClientRect();
    return toast.top >= box.top + f.clientTop && toast.bottom <= box.top + f.clientTop + f.clientHeight &&
      toast.left >= box.left && toast.right <= box.right &&
      document.elementFromPoint(toast.x + toast.width / 2, toast.y + toast.height / 2) === el;
  })()`);
  expect(visible, 'new toast lies inside visible F and passes the hit test').toBe(true);
  expect(await page.locator('#main').evaluate(el => el.scrollTop)).toBe(mainScroll);
  expect(await page.evaluate('window.scrollY')).toBe(0);
});

test('narrow refusal headline survives two toast expiries', async ({ page, dashboard }) => {
  await page.setViewportSize(FEEDBACK_VIEWPORTS.N);
  await prepareFeedback(page, dashboard.url, "activity");
  const feedback = page.locator('#feedback');
  // Keep the refused result overflowing after expiry so native clamping cannot conceal a stale offset.
  await page.evaluate('feedbackDriver.varyResult(); document.getElementById("feedback").scrollTop = document.getElementById("feedback").scrollHeight');
  expect(await feedback.evaluate(el => el.scrollTop), 'the retained refusal overflows F').toBeGreaterThan(0);
  await page.evaluate('feedbackDriver.toast("First toast"); feedbackDriver.toast("Newest toast", "error")');
  const liveToastText = await page.locator('#toast-host .toast').allTextContents();
  const liveScroll = await feedback.evaluate(el => el.scrollTop);
  await page.clock.runFor(TOAST_LIFETIME_MS);
  await expect(page.locator('#toast-host .toast')).toHaveCount(0);
  await expect(page.locator('#decision-feedback-result strong')).toHaveText('Decision refused');
  const visible = await page.evaluate<boolean>(`(() => {
    const headline = document.querySelector('#decision-feedback-result strong');
    const f = document.getElementById('feedback');
    const box = f.getBoundingClientRect(), rect = headline.getBoundingClientRect();
    // The midpoint of each dimension hits the headline itself, not clipped or covered content.
    return rect.top >= box.top + f.clientTop && rect.bottom <= box.top + f.clientTop + f.clientHeight &&
      rect.left >= box.left && rect.right <= box.right &&
      document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2) === headline;
  })()`);
  expect(visible, 'retained refusal headline lies inside F and passes the hit test after expiry').toBe(true);
  expect(liveToastText).toEqual(['Newest toast', 'First toast']);
  expect(liveScroll).toBe(0);
});

test('changed feedback resets stale F scroll', async ({ page, dashboard }) => {
  await page.setViewportSize(FEEDBACK_VIEWPORTS.N);
  await prepareFeedback(page, dashboard.url, "activity");
  await page.evaluate('document.getElementById("feedback").scrollTop = document.getElementById("feedback").scrollHeight');
  expect(await page.locator('#feedback').evaluate(el => el.scrollTop)).toBeGreaterThan(0);
  // Grow the result so a browser clamp on shorter content cannot impersonate the product reset.
  await page.evaluate('feedbackDriver.varyResult()');
  await expect(page.locator('#decision-feedback-result')).toContainText('Retained feedback.');
  expect(await page.locator('#feedback').evaluate(el => el.scrollTop)).toBe(0);
});

test('Page Down with nothing focused scrolls main', async ({ page, dashboard }) => {
  await page.setViewportSize({ width: 1399, height: 500 });
  // Start on Settings without ever clicking or focusing a descendant of main.
  await prepareFeedback(page, dashboard.url, "settings", false);
  await expect(page.locator('#main')).toContainText('Health');
  await page.evaluate('document.activeElement.blur(); document.getElementById("main").scrollTop = 0');
  expect(await page.evaluate('document.activeElement === document.body')).toBe(true);
  await page.keyboard.press('PageDown');
  await expect(page.locator('#main')).toBeFocused();
  await expect(page.locator('#main')).toHaveCSS('outline-style', 'none');
  // Let native smooth keyboard scrolling settle in the controlled browser clock.
  await page.clock.runFor(500);
  await expect.poll(() => page.locator('#main').evaluate(el => el.scrollTop)).toBeGreaterThan(0);
  expect(await page.evaluate('window.scrollY')).toBe(0);
});

test('quoted result preserves focused Clear on background redraw', async ({ page, dashboard }) => {
  await prepareFeedback(page, dashboard.url, "activity");
  await page.evaluate('feedbackDriver.quoteResult()');
  await page.locator('[data-action="decision-result-clear"]').focus();
  await page.evaluate('window.retainedClear = document.activeElement; feedbackDriver.backgroundRedraw()');
  await page.clock.runFor(SETTLE_FRAMES_MS);
  expect(await page.evaluate('retainedClear.isConnected && document.activeElement === retainedClear')).toBe(true);
});

test('Feedback focus is visible and announcements stay outside its scroller', async ({ page, dashboard }) => {
  await prepareFeedback(page, dashboard.url, "activity");
  // Distinct from --indigo so a hard-coded accent cannot impersonate the shared ring token.
  await page.evaluate('document.documentElement.style.setProperty("--focus", "rgb(1, 2, 3)")');
  await page.keyboard.press('Tab');
  await page.locator('#feedback').focus();
  await expect(page.locator('#feedback')).toBeFocused();
  const ring = await page.evaluate<boolean>(`(() => {
    const el = document.getElementById('feedback');
    const css = getComputedStyle(el);
    return el.matches(':focus-visible') && css.outlineStyle !== 'none' && parseFloat(css.outlineWidth) > 0;
  })()`);
  expect(ring, 'keyboard focus has a visible ring').toBe(true);
  await expect(page.locator('#feedback')).toHaveCSS('outline-color', 'rgb(1, 2, 3)');
  await expect(page.locator('body > #decision-announcement')).toHaveAttribute('aria-live', 'polite');
  await expect(page.locator('#feedback #decision-announcement')).toHaveCount(0);
});

test('Feedback height follows body typography tokens', async ({ page, dashboard }) => {
  await prepareFeedback(page, dashboard.url, "activity");
  // A larger body token detects a duplicated literal in the six-body-line reservation.
  await page.evaluate('document.documentElement.style.setProperty("--text-md", "20px")');
  const dimensions = await page.evaluate<{ actual: number; expected: number }>(`(() => {
    const el = document.getElementById('feedback');
    const css = getComputedStyle(el);
    const body = getComputedStyle(document.body);
    return {
      actual: el.getBoundingClientRect().height,
      expected: 6 * parseFloat(body.lineHeight) + parseFloat(css.paddingTop) + parseFloat(css.paddingBottom) +
        parseFloat(css.borderTopWidth) + parseFloat(css.borderBottomWidth),
    };
  })()`);
  expect(Math.abs(dimensions.actual - dimensions.expected)).toBeLessThanOrEqual(1);
});


test('observer assertion rejects a no-op after setup and explicit samples', async ({ page, dashboard }) => {
  await prepareFeedback(page, dashboard.url, "activity");
  await recordFeedbackBaseline(page, '[data-action="inbox-select"][data-item-id="later"]', false);
  await page.evaluate('feedbackRecord.sample()');
  await expect(assertFeedbackIsolation(page, "no-op control")).rejects.toThrow('observers sampled the transition after setup');
});
