/**
 * Guard-integrity regression tests for `stripCodeComments`
 * (registry row `sanctuary-structure-guard-stripcodecomments-desync`).
 *
 * THE BUG (fixed alongside this file): `stripCodeComments` (public-surface.ts)
 * tokenizes source with the TypeScript SCANNER so the no-em-dash / no-CIMC
 * structure guards see executable code + string literals but never code
 * comments. It never called `scanner.reScanTemplateToken()` at interpolation
 * boundaries, so the scanner's plain `scan()` treated the `}` that closes a
 * `${...}` interpolation as an ordinary `CloseBraceToken` and then re-lexed
 * the template's TAIL as if it were bare code. A `//` (or `/* *\/`) that is
 * really user-visible STRING content in that tail was therefore mis-read as a
 * comment and stripped -- hiding a real em-dash or CIMC mention from the
 * MANDATORY guards behind what looks like, but is not, a comment marker.
 *
 * These tests exercise `stripCodeComments` directly (the shared primitive the
 * em-dash and CIMC guards build on), not the full guard machinery, so the
 * proof is about the strip itself: it must never delete real string/template
 * content, and it must still do its actual job of removing true comments.
 *
 * Tests 1 and 2 are the actual exploit: they FAIL on the pre-fix scanner (the
 * em-dash / CIMC-shaped text gets stripped) and PASS after (verified by
 * running this file against the pre-fix `stripCodeComments` via `git stash`;
 * see the fix PR description for the transcript). Tests 3 and 4 are
 * regression guards proving the fix does not loosen or break the function's
 * actual job (true comments are still stripped; ordinary template forms still
 * round-trip byte-for-byte).
 */

import { describe, expect, it } from "vitest";
import { stripCodeComments } from "./public-surface";

describe("stripCodeComments (guard-integrity: template-literal tail desync)", () => {
  it("1. THE EXPLOIT: preserves an em-dash that lives in a template TAIL after an interpolation, even though it follows `//`", () => {
    // `${x}` closes the interpolation; everything from " // separator—here`"
    // onward is the template's TemplateTail -- real string content, not a
    // comment. The pre-fix scanner mis-read the `//` here as a line comment
    // and stripped the em-dash, hiding it from the em-dash ratchet.
    const source = "const label = `value: ${x} // separator—here`;";
    const stripped = stripCodeComments(source);

    expect(stripped).toContain("—"); // the em-dash must survive
    expect(stripped).toContain(" // separator—here`"); // the whole tail, verbatim
    // Nothing in this source is a real comment, so nothing should be removed.
    expect(stripped).toBe(source);
  });

  it("2. a CIMC-shaped mention hiding behind `//` in a template tail is preserved, not stripped", () => {
    const source = "const label = `... ${x} // CIMC`;";
    const stripped = stripCodeComments(source);

    expect(stripped).toContain("CIMC");
    expect(stripped).toBe(source);
  });

  it("3. true comments (outside any string/template) are still stripped, including their em-dashes", () => {
    const source =
      "// leading comment — note\n" +
      "const a = 1; /* block comment — note */\n" +
      "const b = 2;\n";
    const stripped = stripCodeComments(source);

    // Real comments are removed entirely, so no em-dash should survive.
    expect(stripped).not.toContain("—");
    expect(stripped).not.toContain("leading comment");
    expect(stripped).not.toContain("block comment");
    // Line structure and real code are preserved.
    expect(stripped).toContain("const a = 1;");
    expect(stripped).toContain("const b = 2;");
    expect(stripped.split("\n").length).toBe(source.split("\n").length);
    // Some real content was actually removed -- this is not a round-trip.
    expect(stripped).not.toBe(source);
  });

  it("4. structural template forms tokenize correctly and round-trip byte-for-byte (no comments present)", () => {
    const forms = [
      "const a = `a${`b${c}d`}e`;", // nested template inside an interpolation
      "const a = `x${ {y: 1} }z`;", // object literal (real inner braces) inside an interpolation
      "const a = `${a}${b}`;", // adjacent interpolations
      "const a = `plain`;", // no-substitution template
      "const a = sql`select ${x} // not a comment`;", // tagged template, `//` in the tail
      "const a = `${ {y: {z: 1}} }`;", // nested object literal inside an interpolation
    ];

    for (const source of forms) {
      const stripped = stripCodeComments(source);
      expect(stripped, `round-trip mismatch for: ${source}`).toBe(source);
    }
  });
});
