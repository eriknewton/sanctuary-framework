/**
 * SHR canonicalization Unicode normalization (full-sweep #89).
 *
 * Verifies that canonicalizeForSigning normalizes to NFC before returning,
 * so that two bodies differing only in NFC vs NFD encoding produce the
 * same canonical byte sequence and the same signature.
 */

import { describe, it, expect } from "vitest";

import { canonicalizeForSigning } from "../../src/shr/types.js";

describe("canonicalizeForSigning Unicode normalization (#89)", () => {
  it("NFC and NFD variants produce identical canonical output", () => {
    // U+00E9 (e-acute) has two representations:
    // NFC: single code point \u00e9
    // NFD: base 'e' + combining acute accent \u0065\u0301
    const nfcBody = { agent_name: "caf\u00e9" };
    const nfdBody = { agent_name: "caf\u0065\u0301" };

    // Verify the inputs are actually different byte sequences pre-normalization
    expect(JSON.stringify(nfcBody)).not.toBe(JSON.stringify(nfdBody));

    const nfcCanonical = canonicalizeForSigning(nfcBody);
    const nfdCanonical = canonicalizeForSigning(nfdBody);

    // After NFC normalization, both should produce identical output
    expect(nfcCanonical).toBe(nfdCanonical);
    // The output should be NFC-normalized
    expect(nfcCanonical).toBe(nfcCanonical.normalize("NFC"));
  });

  it("ASCII-only bodies are unaffected by normalization", () => {
    const body = { version: "1.0", agent: "test-agent" };
    const canonical = canonicalizeForSigning(body);
    expect(canonical).toBe(JSON.stringify({ agent: "test-agent", version: "1.0" }));
  });
});
