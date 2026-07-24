/**
 * Guard-integrity regression tests for `stripCodeComments`
 * (registry row `sanctuary-structure-guard-stripcodecomments-desync`).
 *
 * THE BUG, ROUND 1 (fixed alongside this file, then found still incomplete):
 * `stripCodeComments` (public-surface.ts) originally tokenized source with the
 * raw TypeScript SCANNER plus a hand-rolled template-interpolation brace-depth
 * counter, so the no-em-dash / no-CIMC structure guards would see executable
 * code + string literals but never code comments. Round 1 fixed the scanner
 * never calling `scanner.reScanTemplateToken()` at a `${...}` close-brace.
 * Tests 1 and 2 below are that exploit.
 *
 * THE BUG, ROUND 2 (parse-parity review, 2026-07-24): round 1's brace-depth
 * counter is STILL unsound, because whether a `/` starts a RegExpLiteral or a
 * division operator is a GRAMMAR fact a context-free scanner cannot always
 * get right. A template interpolation containing a regex literal with an
 * unmatched `{` -- `` `a${/{/.test(s)} // tail—`; `` -- made the hand-rolled
 * counter miscount the regex's `{` as a real `OpenBraceToken`, so the counter
 * never reached zero at the true interpolation-closing `}` and the template's
 * TAIL (real string content, including the em-dash) got re-lexed as bare code
 * and stripped as a comment. Test 5 below is this exact exploit.
 *
 * THE FIX (round 2): `stripCodeComments` no longer scans token-by-token at
 * all. It parses the source with `ts.createSourceFile` (the real TypeScript
 * PARSER, which resolves regex-vs-division and template continuation
 * correctly by construction), walks every token via `getChildren()`, and
 * blanks only the byte ranges the parser itself reports as comment trivia.
 * A comment range can never overlap a string/template/regex literal, because
 * those are each a single token and a comment range is, by definition, trivia
 * strictly BETWEEN two tokens. This closes the entire class of bug: no
 * scanner-side brace/regex/template bookkeeping is needed or present anymore.
 *
 * These tests exercise `stripCodeComments` directly (the shared primitive the
 * em-dash and CIMC guards build on), not the full guard machinery, so the
 * proof is about the strip itself: it must never delete real string/template
 * content, and it must still do its actual job of removing true comments.
 *
 * Tests 1 and 2 are the round-1 exploit: they FAIL on the pre-round-1 scanner
 * and PASS after (verified via `git stash` against the pre-fix commit; see the
 * fix PR description). Test 5 is the round-2 exploit: verified to FAIL (strips
 * the em-dash) against the round-1 scanner-plus-brace-counter implementation
 * committed in this PR at cee3c43d, and to PASS against the round-2
 * parser-backed implementation in this file. Tests 6-8 are further
 * grammar-ambiguous shapes (division that looks like a regex, a regex literal
 * containing a `}`, and both together in one template) added for robustness;
 * 6 and 7 individually did not trigger the round-1 bug (verified), but 8
 * (both together) did -- all four pass on the round-2 parser-backed fix.
 * Tests 3 and 4 are regression guards proving the fix does not loosen or
 * break the function's actual job (true comments are still stripped; ordinary
 * template forms still round-trip byte-for-byte).
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

  it("5. THE ROUND-2 EXPLOIT: a regex literal with an unmatched brace inside a template interpolation no longer desyncs the strip", () => {
    // `/{/.test(s)` is a regex literal whose body is a single unmatched `{`.
    // A scanner-only brace counter (round 1's approach) miscounts that `{` as
    // a real OpenBraceToken, so it never sees the interpolation's real
    // closing `}` as the boundary -- everything after gets re-lexed as bare
    // code and the `//` is misread as a comment, stripping the em-dash. The
    // real parser knows `/{/.test(s)` is one RegExpLiteral token, so the
    // interpolation-closing `}` and the TemplateTail after it are recovered
    // correctly and the tail (including the em-dash) survives untouched.
    const source = "const x = `a${/{/.test(s)} // tail—`;";
    const stripped = stripCodeComments(source);

    expect(stripped).toContain("—");
    expect(stripped).toBe(source); // nothing here is a real comment
  });

  it("6. division that looks like it could open a regex, inside an interpolation", () => {
    const source = "const x = `${a / b} // x—`;";
    const stripped = stripCodeComments(source);

    expect(stripped).toContain("—");
    expect(stripped).toBe(source);
  });

  it("7. a regex literal containing a `}` inside an interpolation", () => {
    const source = "const x = `a${/}/.test(s)} // tail—`;";
    const stripped = stripCodeComments(source);

    expect(stripped).toContain("—");
    expect(stripped).toBe(source);
  });

  it("8. a template whose interpolations mix division AND an unmatched-brace regex", () => {
    // Combines cases 6 and 7 in one source: a division in the first
    // interpolation, an unmatched-brace regex in the second. This shape also
    // desynced the round-1 brace counter (verified against the round-1
    // implementation committed at cee3c43d).
    const source = "const x = `${a/b}${/{/.test(c)} // tail—`;";
    const stripped = stripCodeComments(source);

    expect(stripped).toContain("—");
    expect(stripped).toBe(source);
  });
});
