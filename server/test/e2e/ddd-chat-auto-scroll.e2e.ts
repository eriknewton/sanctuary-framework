/**
 * Playwright e2e for Finding DDD (v1.2.0-rc.5): the concierge chat
 * surface must auto-scroll the history to the latest message AND keep
 * the input bar visible so the operator can continue the conversation
 * without manually scrolling. The rc.4 attempt landed scrollIntoView
 * for the latest message, which fired correctly in both Chromium and
 * WebKit, but the layout pre-rc.5 had:
 *
 *   - .concierge-card with min-height (no max-height); card grew to
 *     fit content and pushed the page past the viewport fold.
 *   - .concierge-history with flex 1 1 auto + min-height: 360px (no
 *     min-height: 0); inner element never shrank below content size,
 *     so the overflow-y: auto never engaged. scrollHeight ===
 *     clientHeight; the page was the actual scroll container.
 *   - The composer was layout-below the history in the same scroll
 *     container; scrolling the latest message to viewport-bottom
 *     pushed the composer below the page fold.
 *
 * Operator quote from Pass 5 drill on Mini1 Safari: "It does move
 * the response up dynamically, but the input box is below the fold,
 * so I still have to scroll."
 *
 * rc.5 fix: bound the card with max-height: calc(100vh - 180px),
 * give the history min-height: 0 + flex-shrink to engage internal
 * scrolling, mark the composer flex-shrink: 0 so it stays pinned to
 * the bottom of the card. The input bar is now layout-below the
 * history element but layout-above the page fold; the history
 * scrolls internally to bring the latest message into its visible
 * region, and the composer is always visible.
 *
 * Three scenarios + a fourth assertion:
 *
 *   A. Send-message scrolls the latest reply into the history's
 *      visible region. The input bar stays visible in the viewport.
 *   B. Operator scrolled the HISTORY up to read older messages.
 *      Background renders (badge refresh, poll cycle) preserve
 *      history scroll position. Operator's NEXT send scrolls the
 *      history to bottom.
 *   C. Operator at-or-near-bottom of history. Background render does
 *      not yank them to top. (Symmetric to A on a passive render.)
 *
 * Scenarios B and C operate on the .concierge-history scroll
 * container (its scrollTop), which is now the actual inner-scroll
 * surface in the rc.5 layout.
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
  await page.route(/\/api\/hub\/chat\/concierge(\?|$)/, async (route) => {
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
  await page.route(/\/api\/hub\/chat\/concierge\/history/, async (route) => {
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
 * True when the element overlaps the browser viewport with at least
 * 95% of its height visible. Used for end-state assertions where the
 * element should be visible to the operator.
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

/**
 * True when the message overlaps the history container's clip region
 * with at least 95% of its height visible. The rc.5 layout makes
 * .concierge-history the inner scroll container; "visible to the
 * operator" requires intersection with the history's bounding rect,
 * not the window viewport (the history is a sub-region of the
 * viewport).
 */
async function isInHistoryViewport(
  page: Page,
  msgLocator: ReturnType<Page["locator"]>,
): Promise<boolean> {
  return await msgLocator.evaluate((el: Element) => {
    const histEl = document.getElementById("concierge-history");
    if (!histEl) return false;
    const histRect = histEl.getBoundingClientRect();
    const rect = (el as HTMLElement).getBoundingClientRect();
    const visTop = Math.max(rect.top, histRect.top);
    const visBottom = Math.min(rect.bottom, histRect.bottom);
    const visibleHeight = Math.max(0, visBottom - visTop);
    return rect.height > 0 && visibleHeight / rect.height >= 0.95;
  });
}

test.describe("Finding DDD: concierge chat auto-scroll on real DOM", () => {
  test("Scenario A: send-message brings the latest reply into the history's visible region; input bar stays visible", async ({
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

    // Send 8 fat messages. 200-char messages at 80% max-width wrap to
    // several lines; 8 of each role overflows the history container's
    // (max-height: calc(100vh - 180px)) bounded region easily.
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

    // Test premise: the history's inner scroll must actually engage
    // (scrollHeight > clientHeight). With the rc.5 layout this is
    // intrinsic: the card is bounded, the history fills the remaining
    // flex track, and 16+ fat messages overflow it.
    const overflow = await page.evaluate(() => {
      const h = document.getElementById("concierge-history");
      return h
        ? { scrollHeight: h.scrollHeight, clientHeight: h.clientHeight }
        : { scrollHeight: 0, clientHeight: 0 };
    });
    expect(
      overflow.scrollHeight,
      "test premise: history must overflow internally for this test to exercise DDD",
    ).toBeGreaterThan(overflow.clientHeight);

    // The latest concierge reply must be in the history's visible
    // region after the send.
    const latestReply = page.locator(".concierge-msg-concierge").last();
    expect(
      await isInHistoryViewport(page, latestReply),
      "after operator send, latest concierge reply must be in history viewport",
    ).toBe(true);

    // The load-bearing rc.5 acceptance criterion: the input bar stays
    // visible regardless of message count. The pre-rc.5 layout
    // pushed the composer below the page fold once the history grew;
    // operator quote from Pass 5: "the input box is below the fold,
    // so I still have to scroll."
    const inputBar = page.locator('[data-action="concierge-input"]');
    expect(
      await isInViewport(page, inputBar),
      "input bar must remain visible in the viewport regardless of history growth",
    ).toBe(true);
    const sendBtn = page.locator('[data-action="concierge-send"]');
    expect(
      await isInViewport(page, sendBtn),
      "send button must remain visible in the viewport regardless of history growth",
    ).toBe(true);
  });

  test("Scenario B: operator scrolled history up; background renders preserve position; next send scrolls history to bottom; input bar stays visible throughout", async ({
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

    // Operator scrolls the HISTORY container (inner scroll) to top.
    // The rc.5 layout makes .concierge-history the actual scroll
    // container; window scroll is no longer the right surface.
    await page.evaluate(() => {
      const h = document.getElementById("concierge-history");
      if (h) h.scrollTop = 0;
    });
    expect(
      await page.evaluate(() => {
        const h = document.getElementById("concierge-history");
        return h ? h.scrollTop : -1;
      }),
      "history is scrolled to top after operator scroll-up",
    ).toBe(0);

    // Trigger a background rerender (no operator action). The capture-
    // before-replace logic should detect the operator is NOT following
    // (last message is below the history's clip region) and leave the
    // scroll position alone.
    await page.evaluate(() => {
      window.dispatchEvent(new Event("hashchange"));
    });
    await page.waitForTimeout(200);

    expect(
      await page.evaluate(() => {
        const h = document.getElementById("concierge-history");
        return h ? h.scrollTop : -1;
      }),
      "scrolled-up position must persist across background renders",
    ).toBeLessThan(50);

    // Input bar visibility holds even when history is scrolled up.
    const inputBar = page.locator('[data-action="concierge-input"]');
    expect(
      await isInViewport(page, inputBar),
      "input bar must remain visible while history is scrolled up",
    ).toBe(true);

    // Operator's next SEND scrolls the latest reply into the history
    // viewport (pendingScroll flag overrides scrolled-up state).
    await page.locator('[data-action="concierge-input"]').fill(`Q9: ${big}`);
    await page.locator('[data-action="concierge-send"]').click();
    await expect(page.locator(".concierge-msg-operator").nth(8)).toBeVisible();

    const latestReply = page.locator(".concierge-msg-concierge").last();
    expect(
      await isInHistoryViewport(page, latestReply),
      "operator send overrides scrolled-up state; latest reply in history viewport",
    ).toBe(true);
  });

  test("Scenario C: operator at-or-near-bottom of history; background render leaves them at-or-near-bottom (no jump-to-top)", async ({
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

    // Operator is at-bottom of history (the natural state after the
    // last send since Scenario A guarantees the latest message is in
    // the history viewport). Trigger a background rerender. Operator
    // should remain at-bottom; a regression that yanked them to the
    // top of history would be visible here.
    const beforeScroll = await page.evaluate(() => {
      const h = document.getElementById("concierge-history");
      return h ? h.scrollTop : -1;
    });
    await page.evaluate(() => {
      window.dispatchEvent(new Event("hashchange"));
    });
    await page.waitForTimeout(200);
    const afterScroll = await page.evaluate(() => {
      const h = document.getElementById("concierge-history");
      return h ? h.scrollTop : -1;
    });

    // Looser bound: small layout shift is acceptable; a jump to the
    // top of history is not.
    expect(
      Math.abs(afterScroll - beforeScroll),
      "background render must not jump history scroll position by more than 100px",
    ).toBeLessThan(100);

    // Latest reply should still be in the history's viewport (was-
    // near-bottom implies the auto-scroll path keeps following).
    const latestReply = page.locator(".concierge-msg-concierge").last();
    expect(
      await isInHistoryViewport(page, latestReply),
      "near-bottom operator stays following the conversation across background renders",
    ).toBe(true);
  });
});
