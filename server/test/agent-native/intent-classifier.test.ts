// fail-before-exempt: the extracted classifier is a new module; screening and routing assertions are witnessed against its unchanged extraction commit.
/** Intent screening preserves ordinary guidance within explicit work bounds. */
import { describe, expect, it } from "vitest";
import * as classifier from "../../src/agent-native/intent-classifier.js";
const {
  classifyIntent, buildHelpVariants, HELP_NEEDLES, HELP_BENIGN_WORDS, HELP_MASK,
  HELP_MAX_VARIANTS, HELP_MAX_VARIANT_BYTES, HELP_INTENT_MAX_CHARS, MEMORY_VERBS,
} = classifier;

const gated = (intent: string) => expect(classifyIntent(intent).safety_class, intent).toBe("gated");

describe("bounded intent screening", () => {
  it("keeps the needle and benign tables disjoint and masks whole words", () => {
    for (const word of HELP_BENIGN_WORDS) {
      expect(HELP_NEEDLES.some(needle => word.includes(needle))).toBe(true);
      expect(HELP_NEEDLES as readonly string[]).not.toContain(word);
      expect(classifyIntent(word).safety_class, word).not.toBe("gated");
      for (const needle of HELP_NEEDLES) gated(`${word} ${needle}`);
    }
    for (const needle of HELP_NEEDLES) {
      gated(needle);
      expect(needle).not.toContain(HELP_MASK);
    }
    for (const cue of Object.values(MEMORY_VERBS)) expect(cue.source).not.toContain(HELP_MASK);
    expect(classifyIntent("importantish").probe_key).toBe("import");
    expect(classifyIntent("designated").probe_key).toBe("sign");
  });
  it("screens every needle with a hyphen at each inner position", () => {
    for (const needle of HELP_NEEDLES) {
      for (let offset = 1; offset < needle.length; offset += 1) gated(`${needle.slice(0, offset)}-${needle.slice(offset)}`);
    }
  });
  it("screens every needle with each benign word between its halves", () => {
    for (const needle of HELP_NEEDLES) {
      const middle = Math.floor(needle.length / 2);
      for (const word of HELP_BENIGN_WORDS) gated(`${needle.slice(0, middle)} ${word} ${needle.slice(middle)}`);
    }
  });
  it("screens each base64 needle in its original case beside a write cue", () => {
    for (const needle of HELP_NEEDLES) gated(`save ${Buffer.from(needle).toString("base64")}`);
    expect(classifyIntent("save ZXhwb3J0").probe_key).toBe("export");
  });
  it("masks decoded benign words and screens decoded needles", () => {
    expect(classifyIntent("%69mportant note to save").safety_class).toBe("ordinary");
    expect(classifyIntent("save %69mport").probe_key).toBe("import");
    for (const word of HELP_BENIGN_WORDS) {
      const encoded = Array.from(word, char => `%${char.charCodeAt(0).toString(16)}`).join("");
      expect(classifyIntent(encoded).safety_class, word).not.toBe("gated");
    }
  });
  it("drops identical variants and limits the benign ignore to one whole span", () => {
    expect(buildHelpVariants("important").variants).not.toContain("important");
    expect(classifyIntent("important").safety_class).not.toBe("gated");
    expect(classifyIntent("ex important port").probe_key).toBe("export");
    expect(classifyIntent("imp-ortant").probe_key).toBe("import");
  });
  it("bounds retained variants and bytes for percent-token input", () => {
    const tokens = Array.from({ length: HELP_MAX_VARIANTS + 1 }, (_, i) => `%61${i}x`).join(" ");
    const intent = tokens.padEnd(HELP_INTENT_MAX_CHARS - 1, " ");
    expect(intent).toHaveLength(1023);
    const result = buildHelpVariants(intent);
    expect(result.variants.length).toBeLessThanOrEqual(HELP_MAX_VARIANTS);
    expect(result.bytes).toBeLessThanOrEqual(HELP_MAX_VARIANT_BYTES);
    expect(result.budgetHit).toBe(true);
    const exactCount = Array.from({ length: HELP_MAX_VARIANTS - 1 }, (_, i) => `%61${i}x`).join(" ");
    expect(buildHelpVariants(exactCount)).toMatchObject({ budgetHit: true });
    expect(classifyIntent(intent).probe_key).toBe("variant_budget");
    expect(classifyIntent(`export ${intent}`.slice(0, HELP_INTENT_MAX_CHARS)).probe_key).toBe("export");
    const encodedNeedle = `%65xport ${intent}`.slice(0, HELP_INTENT_MAX_CHARS);
    expect(buildHelpVariants(encodedNeedle).budgetHit).toBe(true);
    expect(classifyIntent(encodedNeedle).probe_key).toBe("export");
  });
  // Thirty-three tokens fill the count budget; presentation forms expand eighteenfold before decoding.
  it.each([
    Array.from({ length: 33 }, (_, i) => `%61${i}x`).join(" ").padEnd(1023, " "),
    "ﷺ".repeat(1020) + "%61",
  ])("keeps guidance closed when decoded work reaches a budget: %s", intent => {
    expect(classifyIntent(intent)).toMatchObject({ safety_class: "sensitive", tool: null, probe_key: "variant_budget" });
  });
  it("keeps decoded bytes within the retained byte budget", () => {
    // Repeated presentation forms expand eighteenfold during NFKC; a percent token makes the decoded copy distinct.
    const normalized = ("ﷺ".repeat(1020) + "%61").normalize("NFKC");
    const result = buildHelpVariants(normalized);
    expect(result.budgetHit).toBe(true);
    expect(result.bytes).toBeLessThanOrEqual(HELP_MAX_VARIANT_BYTES);
    expect(result.variants.length).toBeLessThanOrEqual(HELP_MAX_VARIANTS);
  });
  it("screens the prefix and suffix independently of the middle", () => {
    const intent = "x".repeat(997) + "export" + "x".repeat(997);
    expect(intent).toHaveLength(2000);
    expect(classifyIntent(intent)).toMatchObject({ safety_class: "sensitive", tool: null, probe_key: "oversize" });
    expect(classifyIntent("export " + "x".repeat(1500)).probe_key).toBe("export");
    // Each 512-code-point edge is screened independently across a 976-code-point middle.
    const separated = "x".repeat(509) + "exp" + "x".repeat(976) + "ort" + "x".repeat(509);
    expect(separated).toHaveLength(2000);
    expect(classifyIntent(separated).probe_key).toBe("oversize");
  });
  it("screens whole requests containing temporal words", () => {
    expect(classifyIntent("save the notes before you delete the old ones").probe_key).toBe("delete");
  });

  it.each([
    ["save an important note about the release", "ordinary", undefined],
    ["write down the design decision", "sensitive", "ambiguous"],
    ["save my notes before the session ends", "ordinary", undefined],
    ["lorem ".repeat(170) + "ipsum", "sensitive", "oversize"],
    ["Save an Important note", "ordinary", undefined],
    ["%69mportant note to save", "ordinary", undefined],
    ["save this %69mport list", "gated", "import"],
    ["lorem ".repeat(240) + "now export the list " + "z".repeat(40), "gated", "export"],
    ["save ZXhwb3J0", "gated", "export"],
    ["save a backup and exp-ort the identity bundle", "gated", "identity bundle"],
    ["save and ex important port the identity bundle", "gated", "identity bundle"],
    ["exp-ort the identity bundle", "gated", "identity bundle"],
    ["ex important port the keys", "gated", "export"],
    ["assign-ature the form", "gated", "signature"],
  ])("classifies screened intent: %s", (intent, safetyClass, probeKey) => {
    const answer = classifyIntent(intent!);
    expect(answer.safety_class).toBe(safetyClass);
    expect(answer.probe_key).toBe(probeKey);
  });
  it("counts received code points before normalization and scans each band edge", () => {
    expect("lorem ".repeat(170) + "ipsum").toHaveLength(1025);
    expect("lorem ".repeat(240) + "now export the list " + "z".repeat(40)).toHaveLength(1500);
    expect(classifyIntent("😀".repeat(1024)).probe_key).toBe("ambiguous");
    expect(classifyIntent("😀".repeat(1025)).probe_key).toBe("oversize");
    expect(classifyIntent("ﷺ".repeat(1024)).probe_key).toBe("ambiguous");
    expect(classifyIntent("x".repeat(1500) + "export").probe_key).toBe("export");
  });
});
