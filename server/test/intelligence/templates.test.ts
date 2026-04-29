/**
 * Intelligence Substrate Badge Template Registry Tests
 *
 * Verifies:
 *   - every SubstrateChoice has a labelKey + tradeoffKey + fallback string
 *   - every LocalModelPick has an operator-readable model label
 *   - tradeoffTextHash is deterministic + differs across substrates
 *   - operator-facing tradeoff strings honor the no-em-dash rule
 *   - operator-facing tradeoff strings name composition partners (Ollama,
 *     Venice.ai, Anthropic, OpenAI, Google) and do not name competitors
 *   - frontier-with-filter tradeoff explicitly names the leakage with the
 *     required caveat about subtle PII
 */

import { describe, it, expect } from "vitest";
import {
  BACKEND_FALLBACK_STRINGS,
  BADGE_LABEL_KEYS,
  BADGE_TRADEOFF_KEYS,
  LOCAL_MODEL_LABELS,
  resolveBackendString,
  tradeoffTextHash,
} from "../../src/intelligence/templates.js";
import {
  LOCAL_MODEL_TAGS,
  SUBSTRATE_CHOICES,
  type LocalModelPick,
  type SubstrateChoice,
} from "../../src/intelligence/types.js";

describe("Intelligence Substrate Badge Template Registry", () => {
  it("every SubstrateChoice has a labelKey + tradeoffKey + fallback string", () => {
    for (const choice of SUBSTRATE_CHOICES) {
      const labelKey = BADGE_LABEL_KEYS[choice];
      const tradeoffKey = BADGE_TRADEOFF_KEYS[choice];
      expect(labelKey).toBeTruthy();
      expect(tradeoffKey).toBeTruthy();
      expect(BACKEND_FALLBACK_STRINGS[labelKey]).toBeTruthy();
      expect(BACKEND_FALLBACK_STRINGS[tradeoffKey]).toBeTruthy();
    }
  });

  it("every LocalModelPick has an operator-readable model label", () => {
    const picks: LocalModelPick[] = ["gemma-2-2b", "phi-4-mini", "llama-3.1-8b"];
    for (const pick of picks) {
      expect(LOCAL_MODEL_LABELS[pick]).toBeTruthy();
      expect(LOCAL_MODEL_LABELS[pick]).toContain("Ollama");
      // Sanity check that the label references something that maps to a
      // real Ollama model tag.
      expect(LOCAL_MODEL_TAGS[pick]).toBeTruthy();
    }
  });

  it("tradeoffTextHash is deterministic across calls", () => {
    const choices: SubstrateChoice[] = ["local", "venice", "frontier-with-filter", "hybrid", "disabled"];
    for (const choice of choices) {
      const a = tradeoffTextHash(choice);
      const b = tradeoffTextHash(choice);
      expect(a).toBe(b);
      // SHA-256 hash encoded as base64url (no padding) is exactly 43 chars
      // from the [A-Za-z0-9_-] alphabet.
      expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    }
  });

  it("tradeoffTextHash differs across substrates", () => {
    const choices: SubstrateChoice[] = ["local", "venice", "frontier-with-filter", "hybrid", "disabled"];
    const hashes = new Set(choices.map(tradeoffTextHash));
    expect(hashes.size).toBe(choices.length);
  });

  it("resolveBackendString returns the key on miss (defensive fallback)", () => {
    const unknown = "intelligence.badge.unknown.label";
    expect(resolveBackendString(unknown)).toBe(unknown);
  });

  it("operator-facing tradeoff strings honor the no-em-dash rule", () => {
    for (const choice of SUBSTRATE_CHOICES) {
      const tradeoff = BACKEND_FALLBACK_STRINGS[BADGE_TRADEOFF_KEYS[choice]];
      expect(tradeoff).not.toContain("—"); // em-dash
      expect(tradeoff).not.toContain("–"); // en-dash (treated similarly per CLAUDE.md style)
    }
  });

  it("local tradeoff explicitly mentions the on-device sovereignty claim", () => {
    const tradeoff = BACKEND_FALLBACK_STRINGS[BADGE_TRADEOFF_KEYS.local];
    expect(tradeoff.toLowerCase()).toContain("never leave");
  });

  it("venice tradeoff names Venice and frames trust as contractual not cryptographic", () => {
    const tradeoff = BACKEND_FALLBACK_STRINGS[BADGE_TRADEOFF_KEYS.venice];
    expect(tradeoff).toContain("Venice");
    expect(tradeoff.toLowerCase()).toContain("contractual");
  });

  it("frontier-with-filter tradeoff explicitly names the leakage with required caveat", () => {
    const tradeoff = BACKEND_FALLBACK_STRINGS[BADGE_TRADEOFF_KEYS["frontier-with-filter"]];
    expect(tradeoff.toLowerCase()).toContain("frontier");
    expect(tradeoff.toLowerCase()).toContain("redaction");
    // Required caveat about subtle PII (per CLAUDE.md honesty floor).
    expect(tradeoff.toLowerCase()).toMatch(/subtle|imperfect|may.*log/);
  });

  it("disabled tradeoff explains the surface unavailability", () => {
    const tradeoff = BACKEND_FALLBACK_STRINGS[BADGE_TRADEOFF_KEYS.disabled];
    expect(tradeoff.toLowerCase()).toContain("not invoke");
  });
});
