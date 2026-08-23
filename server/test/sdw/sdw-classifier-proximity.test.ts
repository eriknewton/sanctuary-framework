/**
 * SDW classifier coverage for the keyword-gated entropy check and the
 * bare-credential fallback: the keyword-gated entropy check is scoped to a
 * proximity window (same line, or within a bounded Unicode code-point
 * distance) instead of the whole scanned text; a classifier_reject names
 * the detector and line; the keyword boundary matches UPPER_SNAKE_CASE=value
 * shapes; the proximity check and the bare-credential fallback are bounded
 * work per candidate, not per-candidate work proportional to file or line
 * length; and a bare, unexempted high-entropy value farther than the window
 * from any keyword is caught by a narrow, opt-in fallback.
 */
import { describe, expect, it } from "vitest";
import { assertSdwClassifierCleanText, rung1ClassifierTestOnly } from "../../src/sdw/write-gate.js";
import { SdwValidationError, type SdwClassifierDetector } from "../../src/sdw/errors.js";

// 46 characters, mixed-case alnum, Shannon entropy ~5.2 bits/char (> the 4.5
// keyword_gated_high_entropy threshold and > the 3.2 hex-only threshold),
// not a placeholder and not a known hash length (32/40/64 hex chars) — the
// same shape as the real 46-char identifier the drill's MEMORY.md refusal
// measured at entropy 4.537.
const FAR_IDENTIFIER = "Qx7Lm2Zt9Vb4Nc6Wp1Rk8Fy3Hd5Ju0Ge2Ia4Ob6Tn8Ys1x";
const SAME_LINE_IDENTIFIER = "Bk4Pt8Rw2Nc6Xf1Ju9Sy5Ma0Ib3Ge7Vd2Ox6Cl1Aq9Ty4z";
const LONG_LINE_IDENTIFIER = "Mv2Ct7Rk1Nb9Wf4Ju6Sy0Pa3Ib8Ge5Vd1Ox7Cl2Aq4Ty9z";

function fillerParagraph(lineCount: number): string {
  // Deliberately keyword-free (no api-key/access-key/auth/authorization/
  // bearer/credential/password/private-key/secret/token) and candidate-free
  // (no 32-128 char unbroken alnum/base64/hex run) prose, so it cannot itself
  // gate or be gated.
  const lines: string[] = [];
  for (let i = 0; i < lineCount; i += 1) {
    lines.push(`Line ${String(i)}: ordinary operator prose about weather and cooking.`);
  }
  return lines.join("\n") + "\n";
}

function classifierResult(text: string): { readonly ok: true } | { readonly ok: false; readonly error: SdwValidationError } {
  try {
    // true: these fixtures represent harness memory-file text, matching how
    // claude-code-file-adapter.ts/codex-memory-file-adapter.ts call this
    // function (Rung-1 fix-round DESIGN scoping — see write-gate.ts's
    // assertSdwClassifierCleanText doc comment for why this is opt-in, not
    // the default, for every other SDW caller).
    assertSdwClassifierCleanText(text, true);
    return { ok: true };
  } catch (error) {
    if (error instanceof SdwValidationError) return { ok: false, error };
    throw error;
  }
}

describe("SDW classifier: keyword-entropy proximity window (Rung-1 F1)", () => {
  it("passes a keyword and an unrelated high-entropy identifier 40 lines apart", () => {
    // Heading on line 1, identifier on line 41: 40 lines apart, reproducing
    // the drill's MEMORY.md shape (a "token" mention and one unrelated
    // high-entropy identifier, far apart in one large file). Backticked, as
    // the real corpus's one such identifier was (a file-path reference) —
    // this is what keeps it a MUST-PASS after the fix-round's bare-credential
    // fallback (see the DESIGN describe block below): an unbackticked bare
    // value in the same position is a separate, intentional MUST-FAIL case.
    const text = `# Token policy\n${fillerParagraph(39)}Unrelated identifier: \`${FAR_IDENTIFIER}\`\n`;
    expect(classifierResult(text)).toEqual({ ok: true });
  });

  it("refuses token= immediately followed by a high-entropy value on the same line", () => {
    const text = `Ops notes.\n\ntoken=${SAME_LINE_IDENTIFIER}\n`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.detector).toBe("keyword_gated_high_entropy");
      expect(result.error.line).toBe(3);
      expect(result.error.message).not.toContain(SAME_LINE_IDENTIFIER);
    }
  });

  it("refuses a keyword and its value split across a label/value line break", () => {
    // "label:\n  value" is a common authoring layout; the two are on
    // different physical lines but well within the character-distance leg
    // of the proximity window.
    const text = `Config\n\nauthorization:\n  ${FAR_IDENTIFIER}\n`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.detector).toBe("keyword_gated_high_entropy");
      expect(result.error.line).toBe(4);
    }
  });

  it("refuses a keyword and a high-entropy value far apart in characters but on one long line", () => {
    const padding = "filler word ".repeat(30); // ~360 chars: past the char window, still same line.
    const text = `secret ${padding}${LONG_LINE_IDENTIFIER}\n`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.detector).toBe("keyword_gated_high_entropy");
      expect(result.error.line).toBe(1);
    }
  });
});

describe("SDW classifier: keyword boundary catches UPPER_SNAKE_CASE=value shapes (Rung-1 fix-round HIGH-A2)", () => {
  // `_` is a \w character, so a `\b...\b`-anchored keyword alternation never
  // matched "PASSWORD" inside "DATABASE_PASSWORD" — there is no word
  // boundary between two word characters — and F1 removed the whole-file
  // scope that used to catch these by accident. This is exactly the
  // UPPER_SNAKE_CASE=value shape most secret-bearing environment/config
  // lines use.
  const UPPER_SNAKE_CASE_FIXTURES: readonly { readonly label: string; readonly text: string; readonly value: string }[] = [
    { label: "DATABASE_PASSWORD=", text: `DATABASE_PASSWORD=${SAME_LINE_IDENTIFIER}\n`, value: SAME_LINE_IDENTIFIER },
    { label: "OPENAI_API_KEY=", text: `OPENAI_API_KEY=${FAR_IDENTIFIER}\n`, value: FAR_IDENTIFIER },
    { label: "MY_SECRET_TOKEN=", text: `MY_SECRET_TOKEN=${LONG_LINE_IDENTIFIER}\n`, value: LONG_LINE_IDENTIFIER },
  ];

  it("refuses every UPPER_SNAKE_CASE=value shape, counted, with detector/line and no leaked content", () => {
    const outcomes = UPPER_SNAKE_CASE_FIXTURES.map((fixture) => ({
      fixture,
      result: classifierResult(fixture.text),
    }));
    const refused = outcomes.filter((entry) => !entry.result.ok);
    expect(refused).toHaveLength(UPPER_SNAKE_CASE_FIXTURES.length);
    for (const entry of refused) {
      const result = entry.result as { readonly ok: false; readonly error: SdwValidationError };
      expect(result.error.detector, entry.fixture.label).toBe("keyword_gated_high_entropy");
      expect(result.error.line, entry.fixture.label).toBe(1);
      expect(result.error.message, entry.fixture.label).not.toContain(entry.fixture.value);
    }
  });

  it("does not regress the #1217 must-pass prose set (no new false positives from the boundary widening)", () => {
    // Re-verified here (not just cited) per the coordinator's fix-round
    // instruction: none of these contain an UPPER_SNAKE_CASE-adjacent
    // keyword, so the HIGH-A2 boundary widening must not flip them.
    const stillPasses = [
      "# Security notes\n\nThe principal policy and recovery key are stored offline.\n",
      "Never paste a secret into an operator memory file.\n",
    ].map((text) => classifierResult(text));
    expect(stillPasses.filter((result) => result.ok)).toHaveLength(2);
  });
});

describe("SDW classifier: proximity window measured in Unicode code points (Rung-1 fix-round, Codex MEDIUM)", () => {
  // "secret" is 6 UTF-16 units / 6 code points, at index 0. Padding fills the
  // rest of the gap and ends with exactly one newline, so the keyword and
  // the candidate land on DIFFERENT lines — isolating the char-distance leg
  // of the proximity check from the same-line leg, which would otherwise
  // gate regardless of distance.
  function paddingWithLineBreak(distanceFromKeywordStart: number): string {
    const dotCount = distanceFromKeywordStart - "secret".length - 1;
    return ".".repeat(dotCount) + "\n";
  }

  it("gates at exactly 256 code points apart (the window boundary, inclusive)", () => {
    const text = `secret${paddingWithLineBreak(256)}${FAR_IDENTIFIER}\n`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.detector).toBe("keyword_gated_high_entropy");
  });

  it("does not gate via the keyword check at 257 code points apart, one past the window", () => {
    const text = `secret${paddingWithLineBreak(257)}${FAR_IDENTIFIER}\n`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Still refused overall — but via the bare-credential fallback
      // (DESIGN describe block below), never via the keyword gate: this is
      // what proves the keyword-proximity boundary itself sits at 256, not
      // "whatever the bare fallback also happens to catch".
      expect(result.error.detector).toBe("bare_high_entropy_credential");
    }
  });

  it("gates a keyword and candidate 256 CODE POINTS apart even when padded with non-BMP characters (505 UTF-16 units)", () => {
    // .index from a regex match is a UTF-16 code-UNIT offset. A non-BMP
    // character (here, an emoji) is ONE code point but TWO UTF-16 units, so
    // 249 of them is 249 code points of padding but 498 UTF-16 units — total
    // code-point distance from "secret" is 256 (6 + 1 newline + 249 emoji),
    // but the raw UTF-16 index distance is 505. A UTF-16-based
    // implementation would treat this as far outside the window and fall
    // through to the bare-credential fallback, exactly like the 257-apart
    // case above; a correct, code-point-based implementation gates it via
    // the keyword check, same as the 256-apart ASCII case.
    const emoji = "\u{1F600}"; // non-BMP: 2 UTF-16 code units, 1 code point.
    const text = `secret\n${emoji.repeat(249)}${FAR_IDENTIFIER}\n`;
    expect(text.indexOf(FAR_IDENTIFIER)).toBe(505); // sanity: UTF-16 distance really is 505, not 256.
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.detector).toBe("keyword_gated_high_entropy");
  });
});

describe("SDW classifier: bare high-entropy value far from any keyword", () => {
  // For a memory-file mirror the classifier is the ONLY backstop. A bare
  // credential-shaped value with no keyword nearby is refused unless it
  // sits in one of a small set of exempted contexts (see
  // server/src/sdw/README.md's capability bound).
  it("refuses a bare unexempted high-entropy value with no keyword anywhere nearby", () => {
    const text = `Some filler prose about weather.\n\n${FAR_IDENTIFIER}\n\nmore filler prose here.\n`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.detector).toBe("bare_high_entropy_credential");
      expect(result.error.message).not.toContain(FAR_IDENTIFIER);
    }
  });

  const EXEMPT_FIXTURES: readonly { readonly label: string; readonly text: string }[] = [
    { label: "backticked inline code span", text: `Some filler prose about weather.\n\n\`${FAR_IDENTIFIER}\`\n\nmore filler prose here.\n` },
    { label: "markdown link target", text: `See [notes](${FAR_IDENTIFIER}) for details.\n` },
    { label: "sha256: label", text: `content sha256:${FAR_IDENTIFIER} end\n` },
    { label: "URL path segment", text: `see https://example.test/path/${FAR_IDENTIFIER} for details\n` },
  ];

  it("passes every exempted bare-value context, counted", () => {
    const results = EXEMPT_FIXTURES.map((fixture) => ({ fixture, result: classifierResult(fixture.text) }));
    const passed = results.filter((entry) => entry.result.ok);
    expect(passed.map((entry) => entry.fixture.label)).toEqual(EXEMPT_FIXTURES.map((f) => f.label));
  });

  it("refuses a decoy URL earlier on the line followed by a separate bare value", () => {
    // The URL exemption requires CONTIGUITY: the value must itself be an
    // unbroken continuation of the URL, no whitespace between. An unrelated
    // URL mentioned earlier on the line does not exempt a later, separate
    // value.
    const text = `See https://docs.test/setup then paste ${FAR_IDENTIFIER} here
`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.detector).toBe("bare_high_entropy_credential");
      expect(result.error.message).not.toContain(FAR_IDENTIFIER);
    }
  });

  it("refuses a value sitting between two unrelated backtick-paired spans (decoy spans)", () => {
    // The backtick exemption pairs backticks left to right into real spans;
    // a value merely somewhere after one span's close and before an
    // UNRELATED later span's open is not "inside" either span.
    const text = `run \`npm test\` then ${FAR_IDENTIFIER} then \`npm build\`\n`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.detector).toBe("bare_high_entropy_credential");
      expect(result.error.message).not.toContain(FAR_IDENTIFIER);
    }
  });

  it("passes a value genuinely inside a backtick-paired span even with other spans on the same line", () => {
    const text = `run \`npm test\` then \`${FAR_IDENTIFIER}\` then \`npm build\`\n`;
    expect(classifierResult(text)).toEqual({ ok: true });
  });
});

describe("SDW classifier: keyword boundary is a plain non-alphanumeric delimiter (Rung-1 fix-round-3, subtracting fix-round-2's N3 attempt)", () => {
  // Fix-round-2 tried a two-way lookahead so a keyword followed by an
  // underscore-joined snake_case continuation ("authorization_code",
  // "auth_service") would not gate, while an assignment shape still would.
  // That attempt was itself a HIGH regression: it allows only ONE
  // underscore-joined segment before the required "="/":", so a keyword
  // followed by MORE than one segment before the assignment silently
  // passed. Fix-round-3 SUBTRACTS that attempt back to the plain
  // "(?<![A-Za-z0-9])...(?![A-Za-z0-9])" delimiter (do not reintroduce a
  // continuation-aware variant): `_`, `=`, `:`, quotes, and whitespace all
  // count as a boundary, with no exception for a longer identifier chain.
  // The accepted, documented trade-off (server/src/sdw/README.md) is that a
  // keyword named in ordinary prose, as the PREFIX of a longer snake_case
  // identifier, still gates when a high-entropy value is nearby — this is
  // fail-closed, not a defect, and is asserted as MUST-FAIL below rather
  // than engineered around with another lookahead. Fixture text uses the
  // fallback OFF explicitly (classifyRecord's default for every SDW record
  // kind other than harness memory-file text), so only the keyword-boundary
  // behavior is exercised, not the bare-credential fallback.
  it("refuses 'authorization_code' named in prose near a high-entropy value, fallback off (accepted false positive)", () => {
    const text = `The authorization_code flow is documented in \`${FAR_IDENTIFIER}\` notes.
`;
    expect(() => assertSdwClassifierCleanText(text, false)).toThrow(SdwValidationError);
  });

  it("still refuses a genuine UPPER_SNAKE_CASE=value assignment, fallback off", () => {
    const text = `DATABASE_PASSWORD=${SAME_LINE_IDENTIFIER}
`;
    expect(() => assertSdwClassifierCleanText(text, false)).toThrow(SdwValidationError);
  });

  // The fix-round-2 regression class, named explicitly: each of these has a
  // keyword followed by MORE than one underscore-joined segment before the
  // assignment (or a quoted-key JSON/Python-literal shape), which the
  // two-way lookahead silently passed. All must refuse, fallback off.
  const MULTI_SEGMENT_ASSIGNMENT_FIXTURES: readonly { readonly label: string; readonly text: string; readonly value: string }[] = [
    { label: "SECRET_KEY_BASE=", text: `SECRET_KEY_BASE=${SAME_LINE_IDENTIFIER}
`, value: SAME_LINE_IDENTIFIER },
    { label: "STRIPE_SECRET_KEY_LIVE=", text: `STRIPE_SECRET_KEY_LIVE=${FAR_IDENTIFIER}
`, value: FAR_IDENTIFIER },
    { label: "MY_TOKEN_VALUE_PROD=", text: `MY_TOKEN_VALUE_PROD=${LONG_LINE_IDENTIFIER}
`, value: LONG_LINE_IDENTIFIER },
    { label: "GITHUB_TOKEN_READ_ONLY=", text: `GITHUB_TOKEN_READ_ONLY=${SAME_LINE_IDENTIFIER}
`, value: SAME_LINE_IDENTIFIER },
    { label: "PASSWORD_HASH = (spaced)", text: `PASSWORD_HASH = ${FAR_IDENTIFIER}
`, value: FAR_IDENTIFIER },
    { label: '"token_value": "..." (JSON)', text: `"token_value": "${LONG_LINE_IDENTIFIER}"
`, value: LONG_LINE_IDENTIFIER },
    { label: "'api_key_live': '...' (Python/JS literal)", text: `'api_key_live': '${SAME_LINE_IDENTIFIER}'
`, value: SAME_LINE_IDENTIFIER },
  ];

  it("refuses every multi-segment assignment shape, counted, fallback off, with no leaked content", () => {
    const outcomes = MULTI_SEGMENT_ASSIGNMENT_FIXTURES.map((fixture) => {
      try {
        assertSdwClassifierCleanText(fixture.text, false);
        return { fixture, error: undefined as SdwValidationError | undefined };
      } catch (error) {
        if (error instanceof SdwValidationError) return { fixture, error };
        throw error;
      }
    });
    const refused = outcomes.filter((entry) => entry.error !== undefined);
    expect(refused).toHaveLength(MULTI_SEGMENT_ASSIGNMENT_FIXTURES.length);
    for (const entry of refused) {
      expect(entry.error!.detector, entry.fixture.label).toBe("keyword_gated_high_entropy");
      expect(entry.error!.message, entry.fixture.label).not.toContain(entry.fixture.value);
    }
  });
});

describe("SDW classifier: known_secret_token stays whole-record (Rung-1 F1 carve-out)", () => {
  // Every shape below has no keyword requirement in write-gate.ts and is far
  // from any keyword-pattern word in its fixture text; F1 must not add
  // proximity gating to this detector. Each fixture value is assembled from
  // two literal halves at runtime (prefix + suffix) rather than written as
  // one contiguous literal: a real-shaped token in the SOURCE TEXT trips
  // GitHub push protection even though it is inert synthetic test data, and
  // no half on its own is recognizable as a vendor token shape.
  const KNOWN_SECRET_TOKEN_FIXTURES: readonly { readonly label: string; readonly text: string }[] = [
    { label: "anthropic-shaped sk_ token", text: `${fillerParagraph(5)}value: ${"sk_live_" + "ab12cd34ef56gh78ij90kl12mn34"}\n` },
    { label: "AWS AKIA access key id", text: `${fillerParagraph(5)}value: ${"AKIA" + "IOSFODNN7EXAMPLQ"}\n` },
    { label: "AWS ASIA session key id", text: `${fillerParagraph(5)}value: ${"ASIA" + "IOSFODNN7EXAMPLQ"}\n` },
    { label: "Slack xoxb bot token", text: `${fillerParagraph(5)}value: ${"xoxb-" + "1234567890-abcdefghij"}\n` },
    { label: "Google AIza API key", text: `${fillerParagraph(5)}value: ${"AIza" + "SyD1234567890abcdefghijklmnopqrstuv"}\n` },
    { label: "GitLab glpat token", text: `${fillerParagraph(5)}value: ${"glpat-" + "ab12CD34ef56GH78ij90"}\n` },
    { label: "npm publish token", text: `${fillerParagraph(5)}value: ${"npm_" + "ab12CD34ef56GH78ij90kl12MN34op56QR78st"}\n` },
  ];

  it("refuses every known_secret_token shape, counted", () => {
    const results = KNOWN_SECRET_TOKEN_FIXTURES.map((fixture) => ({
      label: fixture.label,
      result: classifierResult(fixture.text),
    }));
    const refused = results.filter((entry) => !entry.result.ok);
    expect(refused).toHaveLength(KNOWN_SECRET_TOKEN_FIXTURES.length);
    for (const entry of refused) {
      const result = entry.result as { readonly ok: false; readonly error: SdwValidationError };
      expect(result.error.detector, entry.label).toBe("known_secret_token");
    }
  });
});

describe("SDW classifier: #1217 prose regression stays clean (Rung-1 F1 must not reopen it)", () => {
  const MUST_PASS_PROSE: readonly { readonly label: string; readonly text: string }[] = [
    {
      label: "security-notes prose",
      text: "# Security notes\n\nThe principal policy and recovery key are stored offline.\n",
    },
    {
      label: "operator warning prose",
      text: "Never paste a secret into an operator memory file.\n",
    },
    {
      label: "keyword far from an unrelated, backticked candidate",
      text: `# Token policy\n${fillerParagraph(39)}Unrelated identifier: \`${FAR_IDENTIFIER}\`\n`,
    },
  ];

  it("accepts every #1217-shaped prose fixture, counted", () => {
    const results = MUST_PASS_PROSE.map((fixture) => classifierResult(fixture.text));
    const passed = results.filter((result) => result.ok);
    expect(passed).toHaveLength(MUST_PASS_PROSE.length);
  });
});

describe("SDW classifier: refusal names the detector and line, never the content (Rung-1 F2)", () => {
  it("carries detector and line on a classifier_reject and omits the matched value from the message", () => {
    const text = `Ops notes.\n\ntoken=${SAME_LINE_IDENTIFIER}\n`;
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.category).toBe("classifier_reject");
    expect(result.error.detector).toBe("keyword_gated_high_entropy");
    expect(result.error.line).toBe(3);
    expect(result.error.message).not.toContain(SAME_LINE_IDENTIFIER);
  });

  it("carries no line for a hit found only in the normalized view", () => {
    // "BEGIN,PRIVATE.KEY" does not match either raw-text private-key probe
    // (probe 1 needs a literal "-----" run; probe 2 needs a literal single
    // space between BEGIN and PRIVATE, not a comma). normalizeClassifierText
    // collapses the comma and period to spaces, producing "BEGIN PRIVATE
    // KEY", which probe 2 matches. That match's offset is in the normalized
    // string, not the original text, so no reliable line exists to report.
    const text = "BEGIN,PRIVATE.KEY\n";
    const result = classifierResult(text);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.detector).toBe("private_key_marker");
    expect(result.error.line).toBeUndefined();
  });

  // One fixture per detector id, asserted as a COUNT (not per-item booleans
  // alone): a filter that silently dropped a row, or a detector id that
  // stopped firing, would still read as "some passed" without this.
  const ALL_DETECTOR_FIXTURES: readonly { readonly detector: SdwClassifierDetector; readonly text: string; readonly secret: string }[] = [
    {
      detector: "private_key_marker",
      text: "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ\n-----END RSA PRIVATE KEY-----\n",
      secret: "MIIBogIBAAJ",
    },
    {
      detector: "private_key_marker_split",
      text: "BEGIN some-other-text PRIVATE KEY\n",
      secret: "some-other-text",
    },
    {
      detector: "encoded_private_key",
      text: `content hash reference: ${"302e020100300506032b657004220420" + "11".repeat(32)}\n`,
      secret: "11".repeat(32),
    },
    {
      detector: "labeled_private_key",
      text: "ed25519 private key: AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE\n",
      secret: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE",
    },
    {
      detector: "labeled_recovery_key",
      text: "SANCTUARY_RECOVERY_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE\n",
      secret: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE",
    },
    {
      detector: "known_secret_token",
      text: `value: ${"AKIA" + "IOSFODNN7EXAMPLQ"}\n`,
      secret: "AKIA" + "IOSFODNN7EXAMPLQ",
    },
    {
      detector: "jwt",
      text: `token: ${"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}\n`,
      secret: "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    },
    {
      detector: "url_credential",
      text: "see https://user:password12345678@example.test/path for details\n",
      secret: "password12345678",
    },
    {
      detector: "keyword_gated_high_entropy",
      text: `Ops notes.\n\ntoken=${SAME_LINE_IDENTIFIER}\n`,
      secret: SAME_LINE_IDENTIFIER,
    },
    {
      detector: "bare_high_entropy_credential",
      text: `Some filler prose about weather.\n\n${FAR_IDENTIFIER}\n\nmore filler prose here.\n`,
      secret: FAR_IDENTIFIER,
    },
  ];

  it("names all ten detectors, counted, with the matched content absent from every message", () => {
    const outcomes = ALL_DETECTOR_FIXTURES.map((fixture) => ({
      fixture,
      result: classifierResult(fixture.text),
    }));
    const refused = outcomes.filter((entry) => !entry.result.ok);
    expect(refused).toHaveLength(ALL_DETECTOR_FIXTURES.length);
    const detectorsSeen = new Set<string>();
    for (const entry of refused) {
      const result = entry.result as { readonly ok: false; readonly error: SdwValidationError };
      expect(result.error.detector, entry.fixture.detector).toBe(entry.fixture.detector);
      expect(result.error.message, entry.fixture.detector).not.toContain(entry.fixture.secret);
      detectorsSeen.add(result.error.detector ?? "");
    }
    // Every detector id is DISTINCT (not two fixtures accidentally landing
    // on the same one, which would make the "ten" count vacuous).
    expect(detectorsSeen.size).toBe(ALL_DETECTOR_FIXTURES.length);
  });
});

describe("SDW classifier: O(candidates * log keywords), not O(candidates * keywords) (Rung-1 fix-round HIGH-A1)", () => {
  it("performs a bounded number of keyword-array reads per candidate on an adversarial input", () => {
    // Rung-1 fix-round HIGH-A1: the pre-fix linear-scan shape was unbounded
    // per call on attacker-influenced text, with the classifier returning
    // `ok: true` (no refusal), so nothing about the slowdown was logged.
    // This exercises the REAL shipped hasNearbyKeyword (via
    // rung1ClassifierTestOnly), not a reimplementation, and counts actual
    // array reads via a counting Proxy rather than wall time, which cannot
    // tell "still O(K), just under a small K today" apart from a real fix.
    const { hasNearbyKeyword, buildLineIndex } = rung1ClassifierTestOnly;

    const KEYWORD_COUNT = 4000;
    const CANDIDATE_COUNT = 4000;
    const STRIDE = 250;
    // Ascending, matching what matchAll produces on real text; spread far
    // enough apart (and off the candidate positions) that neither the
    // char-window nor the same-line leg trivially short-circuits the search.
    const keywordIndices = Array.from({ length: KEYWORD_COUNT }, (_, i) => i * STRIDE);
    const candidateIndices = Array.from({ length: CANDIDATE_COUNT }, (_, i) => i * STRIDE + Math.floor(STRIDE / 2));
    // A real (large, single-line) text and real lineStarts so isKeywordNear
    // runs against genuine data, not a stub. Every candidate here sits
    // within the code-point proximity window of its nearest keyword, so
    // isKeywordNear resolves via the distance check for all of them — this
    // is deliberate: the property under test is the READ COUNT the binary
    // search performs on keywordIndices, which is identical regardless of
    // which branch inside isKeywordNear ultimately returns true or false
    // (neither branch touches keywordIndices again), so which one resolves
    // a given candidate does not change what is being measured here.
    const text = "x".repeat(KEYWORD_COUNT * STRIDE + STRIDE);
    const lineStarts = buildLineIndex(text);

    let accessCount = 0;
    const countingKeywordIndices = new Proxy(keywordIndices, {
      get(target, prop, receiver) {
        if (typeof prop === "string" && /^\d+$/.test(prop)) accessCount += 1;
        return Reflect.get(target, prop, receiver);
      },
    });

    for (const candidateIndex of candidateIndices) {
      hasNearbyKeyword(text, countingKeywordIndices, lineStarts, candidateIndex);
    }

    // O(log K) per candidate: binary search over 4000 keywords needs at
    // most ceil(log2(4000)) = 12 comparisons, plus up to 2 more reads for
    // the two post-search neighbor lookups — a small constant, generously
    // bounded at 20 reads/candidate. A linear scan (the pre-fix shape) would
    // need up to KEYWORD_COUNT (4000) reads per candidate — 200x this bound.
    const perCandidateBound = 20;
    expect(accessCount).toBeLessThanOrEqual(CANDIDATE_COUNT * perCandidateBound);
    expect(accessCount).toBeGreaterThan(0); // the search does read the array; this is not a vacuous no-op count.
  });
});

describe("SDW classifier: bare-credential fallback stays bounded work per candidate, not O(candidates * line length) (fix-round-3)", () => {
  it("builds line-backtick-span features exactly once per call, not once per candidate", () => {
    // Feature construction is injectable specifically so this test can prove
    // the REAL shipped findBareHighEntropyCredential builds it once per
    // call, not once per candidate: moving the call back inside the
    // per-candidate loop would be invisible to a test that only exercises
    // the per-candidate check function in isolation.
    const { findBareHighEntropyCredential, buildLineBacktickSpans } = rung1ClassifierTestOnly;

    let buildCalls = 0;
    const countingBuildFeatures = (t: string, lineStarts: readonly number[]) => {
      buildCalls += 1;
      return buildLineBacktickSpans(t, lineStarts);
    };

    const text = `line one \`${FAR_IDENTIFIER}\` end
line two, no candidate here
line three \`${SAME_LINE_IDENTIFIER}\` also
`;
    findBareHighEntropyCredential(text, countingBuildFeatures);

    expect(buildCalls).toBe(1);
  });

  it("performs a bounded number of text-characters-scanned per candidate on a single-line adversarial input", () => {
    // Drives the COMPLETE shipped findBareHighEntropyCredential (not the
    // per-candidate check function in isolation) with the real default
    // feature builder, wrapping `text` in a proxy that accumulates an
    // estimate of characters scanned by every slice/indexOf/lastIndexOf/
    // includes call made against it. Single-character indexed reads and
    // `.length` are not counted (both are legitimately O(1) and are exactly
    // what the one-time, whole-text backtick-span pass uses), so this bound
    // targets per-candidate cost specifically, not the expected one-time
    // O(text length) preprocessing.
    //
    // Every candidate here is the SAME token, labeled "sha256:" (an exempt
    // context reached only through the text-slicing checks, not the
    // backtick-span check, which resolves without touching `text` at all —
    // exercising a backtick-only fixture here would silently measure zero).
    const { findBareHighEntropyCredential } = rung1ClassifierTestOnly;

    const CANDIDATE_COUNT = 4000;
    const unit = `sha256:${FAR_IDENTIFIER} ${"filler word ".repeat(15)}`;
    const realText = unit.repeat(CANDIDATE_COUNT);
    expect(realText).not.toContain("\n"); // single line, as intended.

    let charsScanned = 0;
    const countingText = new Proxy(Object(realText) as object, {
      get(target, prop, receiver) {
        if (prop === "slice") {
          return (start?: number, end?: number) => {
            const from = Math.max(0, Math.min(start ?? 0, realText.length));
            const to = Math.max(from, Math.min(end ?? realText.length, realText.length));
            charsScanned += to - from;
            return realText.slice(start, end);
          };
        }
        if (prop === "indexOf" || prop === "includes") {
          return (needle: string, fromIndex?: number) => {
            const from = fromIndex ?? 0;
            const found = realText.indexOf(needle, from);
            charsScanned += found === -1 ? Math.max(0, realText.length - from) : found - from + needle.length;
            return prop === "includes" ? found !== -1 : found;
          };
        }
        if (prop === "lastIndexOf") {
          return (needle: string, fromIndex?: number) => {
            const from = fromIndex ?? realText.length;
            const found = realText.lastIndexOf(needle, from);
            charsScanned += found === -1 ? from + 1 : from - found + needle.length;
            return found;
          };
        }
        // matchAll's ToString(this) needs these to resolve to the real
        // primitive string; delegating them is not itself counted (a
        // one-time ToString, not a per-candidate scan).
        if (prop === "toString" || prop === "valueOf") return () => realText;
        if (prop === Symbol.toPrimitive) return () => realText;
        return Reflect.get(target, prop, receiver);
      },
    }) as unknown as string;

    const result = findBareHighEntropyCredential(countingText);
    expect(result).toBeUndefined(); // every candidate is exempt (labeled sha256:); none refused.

    // <= 65 characters scanned per candidate: the lookback window
    // (HIGH_ENTROPY_EXEMPTION_LOOKBACK_CHARS = 64) bounds the one `slice`
    // call the current implementation makes against `text` per candidate
    // that reaches the exemption check, plus a small margin. On this
    // ~936,000-character line, an O(line length) regression would scan
    // orders of magnitude more than this bound.
    expect(charsScanned).toBeGreaterThan(0);
    expect(charsScanned / CANDIDATE_COUNT).toBeLessThanOrEqual(65);
  });
});
