import { describe, expect, it } from "vitest";
import { renderPostureHomeHTML } from "../../src/principal-policy/posture-home-html.js";
import {
  EVIDENCE_SPINE_CSS,
  REL_TIME_FN_SOURCE,
} from "../../src/principal-policy/posture-html-shared.js";
import { renderDashboardV11Html } from "../../src/dashboard/v1_1/html.js";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";

/**
 * S3 evidence spine (UI restyle, 2026-07-18).
 *
 * The spine adds three things to claims the posture surfaces already had data
 * for: a denominator ("N of M"), a freshness stamp ("checked 14s ago"), and a
 * link to the evidence behind the number. The value of all three rests entirely
 * on their being HONEST, so these tests pin the honesty properties rather than
 * the cosmetics:
 *
 *   - a missing timestamp renders as an explicit "no evidence" state, never as
 *     a blank that could be read as fresh and never as a fabricated age;
 *   - a missing denominator is omitted, never rendered as "of 0";
 *   - the freshness formatter is SHARED, so "checked 14s ago" cannot come to
 *     mean different things on different surfaces;
 *   - the quiet empty state (nothing wrong) stays distinct from the unknown
 *     state (we could not check), which is the same never-fake-green contract
 *     the status pills carry.
 */

/**
 * Evaluate the shared relative-time source in isolation. The constant is raw JS
 * SOURCE interpolated into each page's inline script, so evaluating it here
 * tests exactly the function the browser runs.
 */
function loadRelTime(): (iso: unknown) => string {
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(`${REL_TIME_FN_SOURCE}; return relTime;`)() as (iso: unknown) => string;
}

describe("S3 evidence spine: the shared freshness formatter", () => {
  it("returns the empty string for an absent timestamp, never a fabricated age", () => {
    const relTime = loadRelTime();
    // The whole point: a claim with no recorded check must not be able to
    // render an age. Call sites turn "" into an explicit "no evidence yet".
    expect(relTime(null)).toBe("");
    expect(relTime(undefined)).toBe("");
    expect(relTime("")).toBe("");
  });

  it("returns the empty string for an unparseable timestamp, never echoing the raw input", () => {
    const relTime = loadRelTime();
    // Echoing the input would put a garbage string into a slot the operator
    // reads as "how recently this was checked".
    expect(relTime("not-a-date")).toBe("");
    expect(relTime("2026-13-45T99:99:99Z")).toBe("");
  });

  it("formats an age on the seconds / minutes / hours / days ladder", () => {
    const relTime = loadRelTime();
    const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
    expect(relTime(ago(5_000))).toMatch(/^\d+s ago$/);
    expect(relTime(ago(5 * 60_000))).toBe("5m ago");
    expect(relTime(ago(5 * 3_600_000))).toBe("5h ago");
    expect(relTime(ago(5 * 86_400_000))).toBe("5d ago");
  });

  it("clamps a future-dated timestamp to zero rather than reporting a negative age", () => {
    const relTime = loadRelTime();
    // Clock skew between the daemon and the browser must not render "-3s ago".
    const future = new Date(Date.now() + 60_000).toISOString();
    expect(relTime(future)).toBe("0s ago");
  });
});

describe("S3 evidence spine: the standalone posture home page", () => {
  const html = renderPostureHomeHTML();

  it("interpolates the SHARED freshness formatter, not a local copy", () => {
    // If a surface hand-copies the ladder, "checked 14s ago" can silently come
    // to mean something different here than on the v1.1 board.
    expect(html).toContain(REL_TIME_FN_SOURCE);
  });

  it("interpolates the shared evidence-spine CSS", () => {
    expect(html).toContain(EVIDENCE_SPINE_CSS);
  });

  it("renders an explicit no-evidence state for the wall instead of a blank", () => {
    // The wall tile's freshness is the age of its last ENFORCEMENT evidence.
    // On a box that has never enforced, the tile must SAY that.
    expect(html).toContain("no enforcement evidence yet");
    expect(html).toContain("no enforcement evidence on record");
  });

  it("renders an explicit no-verify state for the audit chain instead of a blank", () => {
    expect(html).toContain("no verify on record");
  });

  it("omits a denominator that is not a finite number rather than rendering 'of 0'", () => {
    // The stat() helper gates the denominator behind a finite-number check, so
    // a null/undefined/NaN total renders a bare count.
    expect(html).toMatch(/typeof o\.of === "number" && isFinite\(o\.of\)/);
  });

  it("gives the quiet empty states a reason, keeping them distinct from unknown", () => {
    // "Nothing waiting" is a real answer; "we could not check" is not. The
    // quiet treatment states which one it is.
    expect(html).toContain("The detector answered and reported nothing open.");
    expect(html).toContain("No operation is waiting on your decision.");
  });

  it("renders the first-run empty state as a guided path", () => {
    expect(html).toContain("No agents protected yet.");
    expect(html).toContain("sanctuary protect");
    expect(html).toContain("sanctuary castle-wall arm");
    expect(html).toContain("sanctuary audit-chain verify");
  });

  it("links its numbers to the Evidence view, closing the gap with the v1.1 board", () => {
    // Before S3 the standalone board had no path to /posture/evidence at all.
    expect(html).toContain('href="/posture/evidence"');
  });
});

describe("S3 evidence spine: the v1.1 dashboard", () => {
  const html = renderDashboardV11Html({});
  const client = getClientScript();

  it("renames the relocated chip container to match where the chips live", () => {
    // S2 moved these chips into the sidebar footer; S3 renamed the id off
    // "topbar-pills", which described a place they had already left.
    expect(html).toContain('id="sidebar-pills"');
    expect(html).not.toContain('id="topbar-pills"');
    // The client looks the element up by the new id.
    expect(client).toContain('getElementById("sidebar-pills")');
  });

  it("replaces the bare boot placeholder with an S3 empty state", () => {
    expect(html).toContain("Checking how safe you are.");
    expect(html).not.toContain("Loading dashboard.");
  });

  it("renders an explicit no-evidence state for the wall tile", () => {
    expect(client).toContain("no enforcement evidence yet");
  });

  it("omits a tile denominator that is not a finite number", () => {
    expect(client).toMatch(/typeof o\.of === "number" && isFinite\(o\.of\)/);
  });

  it("keeps the clipboard copy from silently doing nothing", () => {
    // The async Clipboard API needs a secure context, so reaching this board
    // over plain http on a LAN address used to disable the chip silently while
    // it still looked clickable. A copy affordance must never no-op in silence.
    expect(client).toContain("copyViaExecCommand");
    expect(client).toContain("Select the id and copy it manually.");
  });

  it("renders the first-run posture empty state as a guided path", () => {
    expect(client).toContain("No agents protected yet.");
    expect(client).toContain("sanctuary castle-wall arm");
  });
});

describe("S3 evidence spine: the honesty mappers are untouched", () => {
  const client = getClientScript();
  const html = renderPostureHomeHTML();

  it("keeps green earned only by armed/active, never by the spine's additions", () => {
    // The spine adds denominators and ages around the pills; it must not have
    // widened any path to green. coarse_only stays its own non-green tone.
    expect(client).toContain('if (armState === "armed") return { cls: "pill tone-verified", text: "Enforcing" };');
    expect(client).toContain('if (armState === "coarse_only") return { cls: "pill tone-degraded", text: "Coarse-only" };');
  });

  it("keeps custody with no green branch", () => {
    // custodyPill has only damaged (red) and unconfirmed (amber) branches.
    expect(html).not.toMatch(/custodyPill[\s\S]{0,400}pill green/);
  });
});
