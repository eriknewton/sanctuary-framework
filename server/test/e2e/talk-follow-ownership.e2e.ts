/**
 * Playwright e2e for the Talk mounted-owner contract (2026-10-16 follow-up).
 *
 * The VM unit harness in test/dashboard/v1_1/shell-wired-consumers.test.ts
 * has no native `template.content`, so it only ever runs Talk's legacy
 * whole-string path. These specs run the mounted-owner path in a real engine
 * (Chromium and WebKit projects in playwright.config.ts) and assert what the
 * operator sees:
 *
 *   (a) A suggestion click, then a refused send, leaves the suggestion in the
 *       live input and the next send posts that same text.
 *   (b) A mid-history reader who sends and then moves Talk from the side
 *       panel to the full page while the send is in flight is followed to the
 *       reply, with exactly one POST.
 *   (c) A background refresh that changes nothing keeps the reply nodes and
 *       the operator's text selection.
 *   (d1) A wheel that cannot move the history during a send does not revoke
 *       the send's follow request. (d2) A wheel at the bottom of the history
 *       never scrolls the outer page.
 *   (e) A reader who scrolls up during a send is not pulled down by the reply.
 *   (f1, f2) Closing the panel saves the reader's real position: reopening
 *       the panel, or then opening full-page Talk, restores it instead of
 *       jumping to the bottom (a hidden panel has no layout box to read).
 *   (g) A keyboard user on the read-status Retry keeps focus on Retry through
 *       a failed re-read.
 *
 * Fixture server and route-mocking style match ddd-chat-auto-scroll.e2e.ts.
 */
import type { Page, Route } from "@playwright/test";
import { test, expect } from "./fixtures/dashboard.js";

// The tests tsconfig has no DOM lib. These module-local declarations type the
// page.evaluate callbacks (which run in the browser, not in Node) so this file
// adds nothing to test/fixtures/typecheck-tests-baseline.txt.
interface PageElement {
  scrollTop: number; clientHeight: number; scrollHeight: number; isConnected: boolean;
  firstChild: unknown; getAttribute(name: string): string | null; closest(selector: string): PageElement | null;
}
interface PageRange { setStart(node: unknown, offset: number): void; setEnd(node: unknown, offset: number): void }
interface PageSelection { toString(): string; removeAllRanges(): void; addRange(range: PageRange): void }
declare const document: {
  activeElement: PageElement | null;
  getElementById(id: string): PageElement | null;
  querySelector(selector: string): PageElement | null;
  querySelectorAll(selector: string): ArrayLike<PageElement>;
  createRange(): PageRange;
};
declare const window: {
  scrollY: number; location: { hash: string }; dispatchEvent(event: unknown): boolean;
  getSelection(): PageSelection | null;
};

interface ConciergeMessage {
  role: "operator" | "concierge";
  body: string;
  created_at: string;
  served_by?: string;
}

interface StubOptions {
  /** Messages present before the page loads. */
  seed?: number;
  /** Status for every POST; 200 echoes, anything else refuses. */
  postStatus?: number;
  /** Status for every history GET. */
  historyStatus?: number;
  /** When true, each POST waits until the test calls release(). */
  holdPosts?: boolean;
}

interface ConciergeStub {
  thread: ConciergeMessage[];
  posts: string[];
  release: () => void;
}

// 240 characters per seeded message wraps to several lines in both hosts
// (full page and the 460 px panel), so 24 messages overflow either history.
const SEED_TEXT_LENGTH = 240;
const DEFAULT_SEED = 24;

async function installConciergeStub(page: Page, opts: StubOptions = {}): Promise<ConciergeStub> {
  const thread: ConciergeMessage[] = [];
  const seed = opts.seed ?? 0;
  for (let i = 0; i < seed; i++) {
    thread.push({
      role: i % 2 === 0 ? "operator" : "concierge",
      body: `Seed ${i}: ` + "s".repeat(SEED_TEXT_LENGTH),
      created_at: new Date(Date.UTC(2026, 9, 16, 12, 0, i)).toISOString(),
      served_by: i % 2 === 0 ? undefined : "local",
    });
  }
  const posts: string[] = [];
  const waiting: Array<() => void> = [];
  let released = !opts.holdPosts;
  const release = () => {
    released = true;
    waiting.splice(0).forEach((fn) => fn());
  };
  await page.route(/\/api\/hub\/chat\/concierge(\?|$)/, async (route: Route) => {
    const req = route.request();
    if (req.method() !== "POST") return route.continue();
    const message = String((req.postDataJSON() as { message?: string }).message ?? "");
    posts.push(message);
    if (!released) await new Promise<void>((resolve) => waiting.push(resolve));
    const status = opts.postStatus ?? 200;
    if (status !== 200) {
      await route.fulfill({ status, contentType: "application/json", body: JSON.stringify({ ok: false, error: "refused" }) });
      return;
    }
    const now = new Date().toISOString();
    thread.push(
      { role: "operator", body: message, created_at: now },
      { role: "concierge", body: "Echo: " + message, created_at: now, served_by: "local" },
    );
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ok: true, data: { reply_text: "Echo: " + message, served_by: "local", display_label: "Concierge: Local model" } }),
    });
  });
  await page.route(/\/api\/hub\/chat\/concierge\/history/, async (route: Route) => {
    if (route.request().method() !== "GET") return route.continue();
    const status = opts.historyStatus ?? 200;
    if (status !== 200) {
      await route.fulfill({ status, contentType: "application/json", body: JSON.stringify({ ok: false, error: "history unavailable" }) });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, data: { messages: thread.slice() } }) });
  });
  return { thread, posts, release };
}

async function gotoRoute(page: Page, url: string, route: string): Promise<void> {
  await page.goto(url + "#" + route);
  await page.locator("#app").waitFor();
}

/** Geometry of the one live history (Talk's ids exist once in the document). */
async function historyGeometry(page: Page) {
  return await page.evaluate(() => {
    const h = document.getElementById("concierge-history");
    if (!h) return null;
    return { top: h.scrollTop, client: h.clientHeight, height: h.scrollHeight, max: h.scrollHeight - h.clientHeight };
  });
}

/** Within 4 px of the bottom: the client's own "at the bottom" tolerance. */
// Must match TALK_BOTTOM_SLACK_PX in server/src/dashboard/v1_1/client.ts.
const BOTTOM_SLACK_PX = 4;
async function atBottom(page: Page): Promise<boolean> {
  const g = await historyGeometry(page);
  return !!g && g.top + g.client >= g.height - BOTTOM_SLACK_PX;
}

async function expectOverflow(page: Page): Promise<void> {
  const g = await historyGeometry(page);
  expect(g, "history mounted").not.toBeNull();
  expect(g!.height, "test premise: the history overflows its viewport").toBeGreaterThan(g!.client + 200);
}

async function waitForSeededHistory(page: Page, seed = DEFAULT_SEED): Promise<void> {
  await expect(page.locator("#concierge-history .concierge-msg")).toHaveCount(seed);
}

// A reader position well clear of both ends of the overflowing history.
const READER_OFFSET_PX = 120;
// Long enough for the scroll event of a programmatic scrollTop write to be
// delivered (it fires on the next animation frame, about 16 ms at 60 Hz).
const SCROLL_EVENT_SETTLE_MS = 100;

async function scrollReaderTo(page: Page, top: number): Promise<void> {
  await page.evaluate((offset) => { document.getElementById("concierge-history")!.scrollTop = offset; }, top);
  await page.waitForTimeout(SCROLL_EVENT_SETTLE_MS);
  expect((await historyGeometry(page))!.top, "test premise: the reader is where the test put it").toBe(top);
}

test.describe("Talk mounted owner on a real engine", () => {
  test("(a) a suggestion click then a refused send keeps the suggestion visible and as the next send's payload", async ({ page, dashboard }) => {
    const stub = await installConciergeStub(page, { postStatus: 403 });
    await gotoRoute(page, dashboard.url, "dashboard");
    const input = page.locator('#main input[data-action="concierge-input"]');
    await input.fill("draft A");
    await page.locator('[data-action="concierge-suggestion"][data-suggestion-id="summarize-hour"]').click();
    const suggestion = "Summarize what happened in this fortress in the last hour.";
    await expect(page.locator("[data-talk-error] .banner")).toBeVisible();
    await expect(input).toBeEnabled();
    await expect(input).toHaveValue(suggestion);
    expect(stub.posts).toEqual([suggestion]);
    await page.locator('#main [data-action="concierge-send"]').click();
    await expect.poll(() => stub.posts.length).toBe(2);
    expect(stub.posts[1], "the retry posts the suggestion, not the earlier draft").toBe(suggestion);
    await expect(input).toHaveValue(suggestion);
  });

  test("(b) a mid-history reader who sends, then moves from the panel to full-page Talk, is followed to the reply with one POST", async ({ page, dashboard }) => {
    const stub = await installConciergeStub(page, { seed: DEFAULT_SEED, holdPosts: true });
    await gotoRoute(page, dashboard.url, "posture");
    await page.locator("#btn-talk").click();
    await waitForSeededHistory(page);
    await expectOverflow(page);
    // The reader leaves the bottom BEFORE the send, so position alone can never
    // pull the moved host down; only the send's follow request can. The wait
    // lets the scroll event land before the send records its epoch.
    await scrollReaderTo(page, READER_OFFSET_PX);
    const panelInput = page.locator('#talk-panel-body input[data-action="concierge-input"]');
    await panelInput.fill("moving question");
    await page.locator('#talk-panel-body [data-action="concierge-send"]').click();
    await expect.poll(() => stub.posts.length).toBe(1);
    expect((await historyGeometry(page))!.top, "the send itself did not move the reader").toBe(READER_OFFSET_PX);
    await page.locator('[data-action="talk-open-full"]').click();
    await expect(page.locator('#main input[data-action="concierge-input"]')).toBeDisabled();
    await expect(page.locator("#talk-panel")).toBeHidden();
    // Still in flight: the moved host honours the send's follow request on mount.
    expect(await atBottom(page), "the remounted host follows the in-flight send").toBe(true);
    stub.release();
    await expect(page.locator("#concierge-history .concierge-msg")).toHaveCount(DEFAULT_SEED + 2);
    await expect(page.locator('#main input[data-action="concierge-input"]')).toBeEnabled();
    await expect(page.locator('#main input[data-action="concierge-input"]')).toHaveValue("");
    await expect.poll(() => atBottom(page), { message: "the moved send still follows its reply" }).toBe(true);
    expect(stub.posts).toEqual(["moving question"]);
  });

  test("(c) an unchanged refresh keeps the reply nodes and the text selection", async ({ page, dashboard }) => {
    await installConciergeStub(page, { seed: 4 });
    await gotoRoute(page, dashboard.url, "dashboard");
    await waitForSeededHistory(page, 4);
    const selected = await page.evaluate(() => {
      const reply = document.querySelector("#concierge-history .concierge-msg-concierge:last-of-type .concierge-msg-body")
        || document.querySelectorAll("#concierge-history .concierge-msg-body")[3];
      const text = reply!.firstChild!;
      const range = document.createRange();
      range.setStart(text, 0);
      range.setEnd(text, 7);
      const sel = window.getSelection()!;
      sel.removeAllRanges();
      sel.addRange(range);
      (window as unknown as { __talkReply: PageElement }).__talkReply = reply!;
      return sel.toString();
    });
    expect(selected).toBe("Seed 3:");
    for (let i = 0; i < 3; i++) {
      await page.evaluate(() => window.dispatchEvent(new Event("hashchange")));
      await page.waitForTimeout(150);
    }
    const kept = await page.evaluate(() => {
      const before = (window as unknown as { __talkReply: PageElement }).__talkReply;
      return { connected: before.isConnected, selection: window.getSelection()!.toString() };
    });
    expect(kept.connected, "the reply node is the same node after the refresh").toBe(true);
    expect(kept.selection, "the selection survives the refresh").toBe("Seed 3:");
  });

  test("(d1) a no-motion wheel during a send does not revoke the send's follow request", async ({ page, dashboard }) => {
    const stub = await installConciergeStub(page, { seed: DEFAULT_SEED, holdPosts: true });
    await gotoRoute(page, dashboard.url, "dashboard");
    await waitForSeededHistory(page);
    await expectOverflow(page);
    // The reader sits at the top, so the reply reaches the bottom only through
    // the send's follow request, and an upward wheel there cannot move anything.
    await scrollReaderTo(page, 0);
    await page.locator('#main input[data-action="concierge-input"]').fill("wheel question");
    await page.locator('#main [data-action="concierge-send"]').click();
    await expect.poll(() => stub.posts.length).toBe(1);
    const box = await page.locator("#concierge-history").boundingBox();
    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2);
    await page.mouse.wheel(0, -400);
    await page.waitForTimeout(300);
    expect((await historyGeometry(page))!.top, "the wheel produced no displacement").toBe(0);
    expect(await page.evaluate(() => window.scrollY), "outer page did not scroll").toBe(0);
    stub.release();
    await expect(page.locator("#concierge-history .concierge-msg")).toHaveCount(DEFAULT_SEED + 2);
    await expect.poll(() => atBottom(page), { message: "follow survives a no-motion wheel" }).toBe(true);
    expect(await page.evaluate(() => window.scrollY)).toBe(0);
  });

  test("(d2) a no-motion wheel at the bottom never scrolls the outer page", async ({ page, dashboard }) => {
    await installConciergeStub(page, { seed: DEFAULT_SEED });
    await gotoRoute(page, dashboard.url, "dashboard");
    await waitForSeededHistory(page);
    await expectOverflow(page);
    await expect.poll(() => atBottom(page), { message: "a long thread opens at its latest message" }).toBe(true);
    const box = await page.locator("#concierge-history").boundingBox();
    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2);
    // Downward wheel at the bottom: the history cannot move, and
    // overscroll-behavior: contain stops it chaining to the page.
    await page.mouse.wheel(0, 400);
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => window.scrollY), "outer page did not scroll").toBe(0);
    expect(await atBottom(page)).toBe(true);
  });

  test("(e) a reader who scrolls up during a send is not pulled down by the reply", async ({ page, dashboard }) => {
    const stub = await installConciergeStub(page, { seed: DEFAULT_SEED, holdPosts: true });
    await gotoRoute(page, dashboard.url, "dashboard");
    await waitForSeededHistory(page);
    await expectOverflow(page);
    await page.locator('#main input[data-action="concierge-input"]').fill("reader question");
    await page.locator('#main [data-action="concierge-send"]').click();
    await expect.poll(() => stub.posts.length).toBe(1);
    const box = await page.locator("#concierge-history").boundingBox();
    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2);
    await page.mouse.wheel(0, -600);
    await expect.poll(async () => (await atBottom(page)), { message: "the wheel moved the reader up" }).toBe(false);
    // Let any wheel animation settle, then record where the reader is.
    let top = -1;
    await expect.poll(async () => {
      const now = (await historyGeometry(page))!.top;
      const stable = now === top;
      top = now;
      return stable;
    }).toBe(true);
    stub.release();
    await expect(page.locator("#concierge-history .concierge-msg")).toHaveCount(DEFAULT_SEED + 2);
    await page.waitForTimeout(200);
    const after = (await historyGeometry(page))!;
    expect(Math.abs(after.top - top), "the reply did not move the reader").toBeLessThan(2);
    expect(await atBottom(page)).toBe(false);
  });

  async function scrollPanelUpThenClose(page: Page, url: string): Promise<void> {
    await gotoRoute(page, url, "posture");
    await page.locator("#btn-talk").click();
    await waitForSeededHistory(page);
    await expectOverflow(page);
    await scrollReaderTo(page, READER_OFFSET_PX);
    await page.locator('[data-action="talk-close"]').click();
    await expect(page.locator("#talk-panel")).toBeHidden();
  }

  test("(f1) closing the panel keeps the reader's position for the reopened panel", async ({ page, dashboard }) => {
    await installConciergeStub(page, { seed: DEFAULT_SEED });
    await scrollPanelUpThenClose(page, dashboard.url);
    await page.locator("#btn-talk").click();
    await expect(page.locator("#talk-panel")).toBeVisible();
    await waitForSeededHistory(page);
    expect((await historyGeometry(page))!.top, "the reopened panel restores the reader's offset").toBe(READER_OFFSET_PX);
  });

  test("(f2) closing the panel keeps the reader's position for full-page Talk opened afterwards", async ({ page, dashboard }) => {
    await installConciergeStub(page, { seed: DEFAULT_SEED });
    await scrollPanelUpThenClose(page, dashboard.url);
    await page.evaluate(() => { window.location.hash = "dashboard"; });
    await expect(page.locator("#main #concierge-history")).toBeVisible();
    await waitForSeededHistory(page);
    expect((await historyGeometry(page))!.top, "full-page Talk restores the reader's offset").toBe(READER_OFFSET_PX);
  });

  test("(g) a focused Retry keeps keyboard focus through a failed re-read", async ({ page, dashboard }) => {
    await installConciergeStub(page, { historyStatus: 500 });
    await gotoRoute(page, dashboard.url, "dashboard");
    const retry = page.locator('#main [data-talk-read-status] [data-action="retry-panel"]');
    await expect(retry).toBeVisible();
    await retry.focus();
    await page.keyboard.press("Enter");
    // The re-read passes through "Read in progress." and back to the failure.
    await page.waitForTimeout(400);
    await expect(retry).toBeVisible();
    expect(await page.evaluate(() => {
      const a = document.activeElement;
      return a ? a.getAttribute("data-action") + "|" + !!a.closest("[data-talk-read-status]") : "none";
    }), "focus stays on the read-status Retry").toBe("retry-panel|true");
  });
});
