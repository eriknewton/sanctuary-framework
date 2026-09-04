/**
 * strings.ts unit tests — trailing-slash normalization is linear in input length.
 */

import { describe, it, expect } from "vitest";
import { stripTrailingSlashes } from "../../src/strings.js";

describe("stripTrailingSlashes", () => {
  it("strips a single trailing slash", () => {
    expect(stripTrailingSlashes("https://x/")).toBe("https://x");
  });

  it("leaves a value with no trailing slash unchanged", () => {
    expect(stripTrailingSlashes("https://x")).toBe("https://x");
  });

  it("strips multiple repeated trailing slashes", () => {
    expect(stripTrailingSlashes("https://x///")).toBe("https://x");
  });

  it("returns an empty string unchanged", () => {
    expect(stripTrailingSlashes("")).toBe("");
  });

  it("reduces an all-slash value to an empty string", () => {
    expect(stripTrailingSlashes("///")).toBe("");
  });

  it("only trims trailing slashes, not interior ones", () => {
    expect(stripTrailingSlashes("https://x/y//z//")).toBe("https://x/y//z");
  });

  it("reduces a large all-slash value to an empty string (plain correctness, no timer)", () => {
    // Correctness only: a long run of slashes with nothing after it is the
    // REGEX'S LINEAR case (one greedy match, "$" then succeeds immediately),
    // so this input alone cannot distinguish the linear scan from the
    // regex it replaced. The timing assertion below uses the shape that
    // actually separates them.
    expect(stripTrailingSlashes("/".repeat(200_000))).toBe("");
  });

  it("completes on a long slash run followed by a non-slash character well within a linear-time budget", () => {
    // This is the super-linear shape, not "many repeated slashes" in
    // general: a long run of slashes immediately followed by a non-slash
    // character. Against the regex it replaced (`/\/+$/`), the trailing "a"
    // means "$" never succeeds, so the backtracking engine retries the "+"
    // match at every one of the ~200k starting positions before giving up,
    // which is quadratic in the run length. Measured on this input
    // (200,000 slashes + "a", 200,001 chars total): the regex took ~15.5 s;
    // this linear backward scan took ~0.04 ms.
    const adversarialInput = `${"/".repeat(200_000)}a`;
    const start = performance.now();
    const result = stripTrailingSlashes(adversarialInput);
    const elapsedMs = performance.now() - start;
    // No trailing slash on this input, so it comes back unchanged.
    expect(result).toBe(adversarialInput);
    // 500 ms bound: the linear scan measures well under 1 ms on this input
    // (see derivation above); the regex it replaced measures ~15.5 s on the
    // same input. 500 ms sits comfortably above the linear scan's slowest
    // plausible run on a loaded CI runner (multiple orders of magnitude of
    // headroom) while sitting far below the ~15.5 s a reintroduced regex
    // would take, so this bound catches a regression without flaking on
    // scan noise.
    expect(elapsedMs).toBeLessThan(500);
  });
});
