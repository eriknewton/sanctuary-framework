/**
 * Playwright e2e for Finding DDD (v1.2.0-rc.4): concierge chat history
 * must auto-scroll so the latest message is visible in the operator's
 * viewport after a send. The rc.3 attempt scrolled
 * `concierge-history.scrollTop` to its scrollHeight, but the layout
 * has no fixed height on `.concierge-history` (`flex: 1 1 auto`, no
 * max-height), so the element GROWS to fit its content rather than
 * scroll internally; `scrollHeight === clientHeight`, and the scroll
 * assignment is a no-op. The page scrolls instead, but the rc.3 fix
 * does not push the latest message into the viewport. Operator sends
 * a message; the reply lands below the fold; operator must scroll the
 * page manually. This is the moltbook Pass 4 symptom.
 *
 * The right fix targets the latest message via `scrollIntoView`,
 * which is layout-agnostic and works regardless of which ancestor is
 * the actual scroll container.
 *
 * Three scenarios:
 *
 *   A. Send-message scrolls the latest reply into the viewport, even
 *      when the chat history has grown beyond the page fold.
 *   B. Operator scrolled UP to read history. Background renders
 *      (e.g. badge refresh, poll cycle) must NOT yank them back to
 *      bottom. Operator's NEXT send DOES scroll to bottom.
 *   C. Operator at-or-near-bottom. Background render does not disturb
 *      their position. (Symmetric to A on a passive render.)
 *
 * Scenarios B and C operate on the page-scroll container (window
 * scroll) since `.concierge-history` does not scroll internally.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures/dashboard.js";

interface ConciergeMessage {
  role: "operator" | "concierge";
  text: string;
  ts: string;
  served_by?: string;
}

async function installConciergeStub(page: Page): Promise<{ thread: ConciergeMessage[] }> {
  const thread: ConciergeMessage[] = [];
  await page.route("**/api/hub/chat/concierge", async (route) => {
    const req = route.request();
    if (req.method() === "POST") {
      const body = req.postDataJSON() as { message?: string };
      const operatorMsg: ConciergeMessage = {
        role: "operator",
        text: String(body.message ?? ""),
        ts: new Date().toISOString(),
      };
      const conciergeMsg: ConciergeMessage = {
        role: "concierge",
        text: "Echo: " + operatorMsg.text,
        ts: new Date().toISOString(),
        served_by: "local",
      };
      thread.push(operatorMsg, conciergeMsg);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ok: true,
          data: {
            reply_text: conciergeMsg.text,
            served_by: "local",
            display_label: "Concierge: Local model",
          },
        }),
      });
      return;
    }
    await route.continue();
  });
  await page.route("**/api/hub/chat/concierge/history", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true, data: { messages: thread.slice() } }),
      });
      return;
    }
    await route.continue();
  });
  return { thread };
}

/**
 * Returns true when the element's bounding box overlaps the browser
 * viewport with at least 95% of its height visible. The DDD operator-
 * visible criterion is "the latest reply is in the viewport"; we
 * accept a tiny tolerance for sub-pixel rounding in scrollIntoView's
 * block: "end" alignment (which can place the bottom edge at e.g.
 * 720.5 in a 720px viewport).
 */
async function isInViewport(page: Page, locator: ReturnType<Page["locator"]>): Promise<boolean> {
  return await locator.evaluate((el: Element) => {
    const rect = (el as HTMLElement).getBoundingClientRect();
    const visTop = Math.max(rect.top, 0);
    const visBottom = Math.min(rect.bottom, window.innerHeight);
    const visibleHeight = Math.max(0, visBottom - visTop);
    return rect.height > 0 && visibleHeight / rect.height >= 0.95;
  });
}

test.describe("Finding DDD: concierge chat auto-scroll on real DOM", () => {
  test("Scenario A: send-message brings the latest reply into the viewport, even when chat history has grown past the fold", async ({
    page,
    dashboard,
  }) => {
    await installConciergeStub(page);

    await page.goto(dashboard.url);
    await page.locator("#app").waitFor();
    await page.evaluate(() => {
      window.location.hash = "dashboard";
    });
    await page.locator(".concierge-history").waitFor();

    // Send 8 fat messages so the chat history grows past the fold.
    // 200-char messages at 80% max-width wrap to several lines; 8 of
    // each role overflows a 720-tall viewport easily.
    const big = "x".repeat(200);
    for (let i = 0; i < 8; i++) {
      await page.locator('[data-action="concierge-input"]').fill(`Q${i}: ${big}`);
      await page.locator('[data-action="concierge-send"]').click();
      await expect(
        page.locator(".concierge-msg-operator").nth(i),
      ).toBeVisible();
      await expect(
        page.locator(".concierge-msg-concierge").nth(i),
      ).toBeVisible();
    }

    // Confirm the chat has actually grown past the fold (so the test
    // is meaningfully exercising the bug surface, not silently
    // succeeding because everything fits in 720px).
    const overflow = await page.evaluate(() => {
      return {
        bodyHeight: document.body.scrollHeight,
        windowHeight: window.innerHeight,
      };
    });
    expect(
      overflow.bodyHeight,
      "test premise: page must overflow viewport for this test to exercise DDD",
    ).toBeGreaterThan(overflow.windowHeight);

    // The load-bearing operator-visible criterion: the last concierge
    // reply must be in the viewport after the send.
    const latestReply = page.locator(".concierge-msg-concierge").last();
    expect(
      await isInViewport(page, latestReply),
      "after operator send, latest concierge reply must be in viewport",
    ).toBe(true);
  });

  test("Scenario B: operator scrolled up; background renders preserve position; next send scrolls to bottom", async ({
    page,
    dashboard,
  }) => {
    await installConciergeStub(page);

    await page.goto(dashboard.url);
    await page.locator("#app").waitFor();
    await page.evaluate(() => {
      window.location.hash = "dashboard";
    });
    await page.locator(".concierge-history").waitFor();

    const big = "y".repeat(200);
    for (let i = 0; i < 8; i++) {
      await page.locator('[data-action="concierge-input"]').fill(`Q${i}: ${big}`);
      await page.locator('[data-action="concierge-send"]').click();
      await expect(
        page.locator(".concierge-msg-operator").nth(i),
      ).toBeVisible();
    }

    // Operator scrolls the PAGE (window scroll) all the way to top.
    // This is the real-world action since `.concierge-history` does
    // not scroll internally in this layout.
    await page.evaluate(() => window.scrollTo(0, 0));
    expect(
      await page.evaluate(() => window.scrollY),
      "page is scrolled to top after operator scroll-up",
    ).toBe(0);

    // Trigger a background rerender (no operator action). The capture-
    // before-replace logic should not move the operator's position.
    await page.evaluate(() => {
      window.dispatchEvent(new Event("hashchange"));
    });
    await page.waitForTimeout(200);

    expect(
      await page.evaluate(() => window.scrollY),
      "scrolled-up position must persist across background renders",
    ).toBeLessThan(50);

    // Operator's next SEND scrolls the latest reply into the viewport.
    await page.locator('[data-action="concierge-input"]').fill(`Q9: ${big}`);
    await page.locator('[data-action="concierge-send"]').click();
    await expect(page.locator(".concierge-msg-operator").nth(8)).toBeVisible();

    const latestReply = page.locator(".concierge-msg-concierge").last();
    expect(
      await isInViewport(page, latestReply),
      "operator send overrides scrolled-up state; latest reply in viewport",
    ).toBe(true);
  });

  test("Scenario C: operator at-or-near-bottom; background render leaves them at-or-near-bottom (no jump-to-top)", async ({
    page,
    dashboard,
  }) => {
    await installConciergeStub(page);

    await page.goto(dashboard.url);
    await page.locator("#app").waitFor();
    await page.evaluate(() => {
      window.location.hash = "dashboard";
    });
    await page.locator(".concierge-history").waitFor();

    const big = "z".repeat(200);
    for (let i = 0; i < 8; i++) {
      await page.locator('[data-action="concierge-input"]').fill(`Q${i}: ${big}`);
      await page.locator('[data-action="concierge-send"]').click();
      await expect(
        page.locator(".concierge-msg-operator").nth(i),
      ).toBeVisible();
    }

    // Operator is at-bottom (the natural state after the last send
    // since Scenario A guarantees the latest message is in viewport).
    // Trigger a background rerender. Operator should remain at-bottom;
    // a regression that yanked them to top of page would be visible
    // here.
    const beforeY = await page.evaluate(() => window.scrollY);
    await page.evaluate(() => {
      window.dispatchEvent(new Event("hashchange"));
    });
    await page.waitForTimeout(200);
    const afterY = await page.evaluate(() => window.scrollY);

    // Looser bound: a small layout shift is acceptable, but a jump to
    // the top of the page is not.
    expect(
      Math.abs(afterY - beforeY),
      "background render must not jump operator scroll position by more than 100px",
    ).toBeLessThan(100);

    // Latest reply should still be in the viewport (was-near-bottom
    // implies the auto-scroll path keeps following the conversation).
    const latestReply = page.locator(".concierge-msg-concierge").last();
    expect(
      await isInViewport(page, latestReply),
      "near-bottom operator stays following the conversation across background renders",
    ).toBe(true);
  });
});
