/**
 * Sanctuary v1.2.0-rc.3 Dashboard — Concierge auto-scroll regression
 *
 * Finding DDD (P2, UX, surfaced in moltbook acceptance drill 2026-05-02):
 * concierge chat history grows below the fold; new messages land out of
 * view, forcing the operator to scroll down each turn. Standard chat-UI
 * affordance is missing.
 *
 * Fix shape (rc.3): renderMain captures concierge-history scroll position
 * before innerHTML replacement, then restores scroll-to-bottom on the
 * fresh DOM container when (a) the operator just sent a message
 * (pendingScroll flag set in onConciergeSend), or (b) the operator was
 * already at or near the bottom of the history before the render. If
 * the operator has scrolled up to read history, the render leaves their
 * position alone.
 *
 * Test environment is `node`, not `jsdom`, so these tests assert the
 * shape of the source-script logic. A live-DOM exercise would require a
 * jsdom or headless-browser harness which the repo does not currently
 * carry; the structural assertions here lock the regression channel.
 */

import { describe, expect, it } from "vitest";

import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

describe("v1.2.0-rc.3 concierge auto-scroll, Finding DDD", () => {
  it("declares an AUTO_SCROLL_TOLERANCE_PX constant within an operator-friendly range", () => {
    const src = getClientScript();
    const match = src.match(/AUTO_SCROLL_TOLERANCE_PX\s*=\s*(\d+)/);
    expect(match).toBeTruthy();
    const tolerance = Number(match![1]!);
    expect(tolerance).toBeGreaterThanOrEqual(20);
    expect(tolerance).toBeLessThanOrEqual(120);
  });

  it("captures concierge-history scroll-distance before innerHTML replacement so DOM rebuild does not look like a scroll-up", () => {
    const src = getClientScript();
    expect(src).toContain('concierge-history');
    expect(src).toContain("conciergeWasAtBottom");
    expect(src).toMatch(/scrollHeight\s*-\s*[a-zA-Z_.]+\.scrollTop\s*-\s*[a-zA-Z_.]+\.clientHeight/);
    expect(src).toContain("AUTO_SCROLL_TOLERANCE_PX");
  });

  it("restores scroll-to-bottom on the fresh container when pendingScroll OR was-at-bottom", () => {
    const src = getClientScript();
    expect(src).toContain("pendingScroll");
    expect(src).toMatch(/histEl\.scrollTop\s*=\s*histEl\.scrollHeight/);
  });

  it("does NOT scroll when the operator scrolled up (was-at-bottom false AND pendingScroll false)", () => {
    const src = getClientScript();
    expect(src).toMatch(/if\s*\(\s*pending\s*\|\|\s*conciergeWasAtBottom\s*\)/);
  });

  it("clears pendingScroll after consuming it so a single send does not auto-scroll forever", () => {
    const src = getClientScript();
    expect(src).toMatch(/state\.chat\.concierge\.pendingScroll\s*=\s*false/);
  });

  it("onConciergeSend sets pendingScroll true after the round-trip lands a fresh message pair", () => {
    const src = getClientScript();
    const sendIdx = src.indexOf("async function onConciergeSend");
    expect(sendIdx).toBeGreaterThan(0);
    const sendBody = src.slice(sendIdx, sendIdx + 4000);
    expect(sendBody).toMatch(/c\.pendingScroll\s*=\s*true/);
  });

  it("default state.chat.concierge.pendingScroll is false on dashboard boot", () => {
    const src = getClientScript();
    const stateBlockIdx = src.indexOf("chat: {");
    expect(stateBlockIdx).toBeGreaterThan(0);
    const stateBlock = src.slice(stateBlockIdx, stateBlockIdx + 1200);
    expect(stateBlock).toMatch(/pendingScroll:\s*false/);
  });
});
