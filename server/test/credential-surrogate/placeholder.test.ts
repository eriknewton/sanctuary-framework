/**
 * Tests for the surrogate placeholder grammar and its mint: a placeholder is
 * what Sanctuary issues the agent in place of a bound credential, so the grammar
 * has to be narrow enough that redaction and misroute detection can recognize one
 * anywhere it appears, and the mint has to be unguessable.
 */

import { describe, expect, it } from "vitest";

import {
  SURROGATE_PLACEHOLDER_HEX_LENGTH,
  SURROGATE_PLACEHOLDER_LENGTH,
  SURROGATE_PLACEHOLDER_PREFIX,
  isSurrogatePlaceholder,
  mintSurrogatePlaceholder,
  surrogatePlaceholderScanRe,
} from "../../src/credential-surrogate/placeholder.js";

describe("placeholder grammar", () => {
  it("accepts a correctly shaped placeholder", () => {
    expect(isSurrogatePlaceholder(`${SURROGATE_PLACEHOLDER_PREFIX}${"a".repeat(32)}`)).toBe(true);
    expect(isSurrogatePlaceholder(`${SURROGATE_PLACEHOLDER_PREFIX}0123456789abcdef0123456789abcdef`)).toBe(true);
  });

  it("refuses uppercase hex, so a case variant is not silently a placeholder", () => {
    expect(isSurrogatePlaceholder(`${SURROGATE_PLACEHOLDER_PREFIX}${"A".repeat(32)}`)).toBe(false);
  });

  it("refuses a wrong length, a wrong prefix, and non-hex characters", () => {
    expect(isSurrogatePlaceholder(`${SURROGATE_PLACEHOLDER_PREFIX}${"a".repeat(31)}`)).toBe(false);
    expect(isSurrogatePlaceholder(`${SURROGATE_PLACEHOLDER_PREFIX}${"a".repeat(33)}`)).toBe(false);
    expect(isSurrogatePlaceholder(`sanctuary_surrogat_${"a".repeat(32)}`)).toBe(false);
    expect(isSurrogatePlaceholder(`${SURROGATE_PLACEHOLDER_PREFIX}${"g".repeat(32)}`)).toBe(false);
  });

  it("is anchored: a placeholder embedded in a longer string is not a whole placeholder", () => {
    expect(isSurrogatePlaceholder(`Bearer ${SURROGATE_PLACEHOLDER_PREFIX}${"a".repeat(32)}`)).toBe(false);
  });

  it("refuses non-strings", () => {
    expect(isSurrogatePlaceholder(undefined)).toBe(false);
    expect(isSurrogatePlaceholder(null)).toBe(false);
    expect(isSurrogatePlaceholder(42)).toBe(false);
    expect(isSurrogatePlaceholder({})).toBe(false);
  });

  it("states its own length as prefix plus hex", () => {
    expect(SURROGATE_PLACEHOLDER_LENGTH).toBe(
      SURROGATE_PLACEHOLDER_PREFIX.length + SURROGATE_PLACEHOLDER_HEX_LENGTH,
    );
    expect(mintSurrogatePlaceholder()).toHaveLength(SURROGATE_PLACEHOLDER_LENGTH);
  });
});

describe("the scan regex finds placeholders inside a larger string", () => {
  it("finds every occurrence and does not share state between calls", () => {
    const a = `${SURROGATE_PLACEHOLDER_PREFIX}${"a".repeat(32)}`;
    const b = `${SURROGATE_PLACEHOLDER_PREFIX}${"b".repeat(32)}`;
    const haystack = `Bearer ${a}, alt ${b}`;
    expect(haystack.match(surrogatePlaceholderScanRe())).toEqual([a, b]);
    // A fresh regex per call: a shared global regex would carry `lastIndex` and
    // miss the first match on the second scan.
    expect(haystack.match(surrogatePlaceholderScanRe())).toEqual([a, b]);
  });
});

describe("mint", () => {
  it("mints a placeholder that matches the grammar", () => {
    for (let i = 0; i < 64; i += 1) {
      expect(isSurrogatePlaceholder(mintSurrogatePlaceholder())).toBe(true);
    }
  });

  it("does not repeat across many mints (128 bits of entropy per mint)", () => {
    const minted = new Set<string>();
    for (let i = 0; i < 1000; i += 1) minted.add(mintSurrogatePlaceholder());
    expect(minted.size).toBe(1000);
  });
});
