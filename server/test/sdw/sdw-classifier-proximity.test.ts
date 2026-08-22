/**
 * Rung-1 F1/F2: the keyword-gated entropy check is scoped to a proximity
 * window (same line, or within a bounded character distance) instead of the
 * whole scanned text, and a classifier_reject names the detector and line.
 *
 * Fixtures here are shaped after the real refusals in the 2026-08-22
 * round-trip drill (Review/Sanctuary/drill-rung1-roundtrip-2026-08-22/RESULTS.md,
 * finding F1): a keyword and an unrelated high-entropy identifier that
 * happen to share a file but are not part of the same secret. Every
 * must-fail case here is a shape write-gate.ts already refused before this
 * change; only the must-pass, far-apart shape is new.
 */
import { describe, expect, it } from "vitest";
import { assertSdwClassifierCleanText } from "../../src/sdw/write-gate.js";
import { SdwValidationError } from "../../src/sdw/errors.js";

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
    assertSdwClassifierCleanText(text);
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
    // high-entropy identifier, far apart in one large file).
    const text = `# Token policy\n${fillerParagraph(39)}Unrelated identifier: ${FAR_IDENTIFIER}\n`;
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
      label: "keyword far from an unrelated candidate",
      text: `# Token policy\n${fillerParagraph(39)}Unrelated identifier: ${FAR_IDENTIFIER}\n`,
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
    expect(result.error.column).toBeUndefined();
  });
});
