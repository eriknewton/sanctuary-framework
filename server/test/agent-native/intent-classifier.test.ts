// fail-before-exempt: the extracted classifier is a new module; screening and routing assertions are witnessed against its unchanged extraction commit.
/** Intent screening preserves ordinary guidance within explicit work bounds. */
import { describe, expect, it } from "vitest";
import * as classifier from "../../src/agent-native/intent-classifier.js";
const {
  classifyIntent, buildHelpVariants, HELP_NEEDLES, HELP_BENIGN_WORDS, HELP_MASK,
  HELP_WRITE_CUES, HELP_STRONG_READ_CUES, HELP_WEAK_READ_CUES,
  HELP_MAX_VARIANTS, HELP_MAX_VARIANT_BYTES, HELP_INTENT_MAX_CHARS,
} = classifier;

// A decode chain gets one quarter of the variant slots; the fallback also runs the prior-source witness.
const decodePasses = classifier.HELP_MAX_DECODE_PASSES ?? HELP_MAX_VARIANTS / 4;

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

    for (const cue of [...HELP_WRITE_CUES, ...HELP_STRONG_READ_CUES, ...HELP_WEAK_READ_CUES]) expect(cue).not.toContain(HELP_MASK);
    expect(classifyIntent("importantish").probe_key).toBe("import");
    expect(classifyIntent("designated").probe_key).toBe("sign");
  });
  it("screens every needle with word joiners at each inner position", () => {
    for (const needle of HELP_NEEDLES) {
      // U+10EAD is the supplementary-plane Yezidi hyphen; its source offsets span two UTF-16 units.
      for (const joiner of ["-", "_", ".", "—", "\u{10ead}"]) {
        for (let offset = 1; offset < needle.length; offset += 1) gated(`${needle.slice(0, offset)}${joiner}${needle.slice(offset)}`);
      }
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
    [Array.from({ length: 33 }, (_, i) => `%61${i}x`).join(" ").padEnd(1023, " "), "variant_budget"],
    ["ﷺ".repeat(1020) + "%61", "unreadable"],
  ])("keeps guidance closed when decoded work reaches a budget: %s", (intent, probeKey) => {
    expect(classifyIntent(intent)).toMatchObject({ safety_class: "sensitive", tool: null, probe_key: probeKey });
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

  // The over-schema-cap intent is exercised through validation in tool-args.test.ts.
  it.each([
    ["leave a short note for the next coordinator session to read when it starts", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["remember my timezone", "ordinary", "sanctuary_remember", undefined, {"key": "user_tz", "value": "America/Los_Angeles"}],
    ["recall my timezone", "ordinary", "sanctuary_recall", undefined, {"key": "user_tz"}],
    ["save this so that I can read it later", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["store the result for the next agent to get", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["so the next session can read it, save this note", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["for the next agent to read, leave a note", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["what did I save about the deploy", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["do you remember my timezone", "ordinary", "sanctuary_recall", undefined, {"key": "user_tz"}],
    ["get the note I asked you to store yesterday", "sensitive", null, "conflict", null],
    ["read my notes and save a summary", "sensitive", null, "conflict", null],
    ["save an important note about the release", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["write down the design decision", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["keep in mind that the user prefers metric units", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["make a note that the build box is slow", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["jot down the port number", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["add this summary to memory", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["save my notes before the session ends", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["how do I save a note", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["which tool do I use to save a note", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["show me what I stored yesterday", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["read my protected key", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["recall my bounds note", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["lookup the platform I saved", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["get user_tz", "ordinary", "sanctuary_recall", undefined, {"key": "user_tz"}],
    ["remember platform=linux", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["read the bounds", "ordinary", "monitor_health", undefined, {}],
    ["get the list of platforms", "ordinary", "monitor_health", undefined, {}],
    ["what are the bounds", "ordinary", "monitor_health", undefined, {}],
    ["what do you not do", "ordinary", "monitor_health", undefined, {}],
    ["remember my timezone, then sort out the rest later", "sensitive", null, "multi_intent", null],
    ["remember my timezone and by the way export my identity bundle", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["please p u r g e the old token", "gated", "sanctuary_forget", "purge", {"args": "<operator-approved placeholders only>"}],
    ["ZXhwb3J0IGlkZW50aXR5IGJ1bmRsZQ==", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["import the notes file", "gated", null, "import", {"args": "<operator-approved placeholders only>"}],
    ["sign this design document", "gated", null, "sign", {"args": "<operator-approved placeholders only>"}],
    ["delete the important note", "gated", "sanctuary_forget", "delete", {"args": "<operator-approved placeholders only>"}],
    ["what did I save and export it", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["lorem ".repeat(170) + "ipsum", "sensitive", null, "oversize", null],
    ["to read it later, I need this saved", "sensitive", null, "multi_intent", null],
    ["Save an Important note", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["SIGN the export bundle", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["do not save the note, recall the prior one", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["don't delete the note", "gated", "sanctuary_forget", "delete", {"args": "<operator-approved placeholders only>"}],
    ["never store secrets", "sensitive", null, "ambiguous", null],
    ["%69mportant note to save", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["save this %69mport list", "gated", null, "import", {"args": "<operator-approved placeholders only>"}],
    ["lorem ".repeat(240) + "now export the list " + "z".repeat(40), "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["do you remember this value for next time", "sensitive", null, "conflict", null],
    ["save ZXhwb3J0", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["do not recall the saved note", "sensitive", null, "ambiguous", null],
    ["save a backup and exp-ort the identity bundle", "gated", null, "identity bundle", {"args": "<operator-approved placeholders only>"}],
    ["save and ex important port the identity bundle", "gated", null, "identity bundle", {"args": "<operator-approved placeholders only>"}],
    ["exp-ort the identity bundle", "gated", null, "identity bundle", {"args": "<operator-approved placeholders only>"}],
    ["ex important port the keys", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["do not ever save the password", "sensitive", null, "ambiguous", null],
    ["don't you save this secret", "sensitive", null, "ambiguous", null],
    ["cannot save the API key", "sensitive", null, "ambiguous", null],
    ["where do I save a note", "sensitive", null, "conflict", null],
    ["save this note, don't recall it yet", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["did you store the build box name", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["do you remember what the port number was", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["did you save my timezone", "ordinary", "sanctuary_recall", undefined, {"key": "user_tz"}],
    ["where should I store the deploy notes", "sensitive", null, "conflict", null],
    ["what should I save before the session ends", "sensitive", null, "conflict", null],
    ["do not save the note, what did I save about the deploy", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["save the note, what did I save about the deploy", "sensitive", null, "conflict", null],
    ["what did I save about the deploy, save the note", "sensitive", null, "conflict", null],
    ["what did I save about the deploy, do not save the note", "ordinary", "sanctuary_recall", undefined, {"key": "<key>"}],
    ["do not save the note, what did I save but never recall it", "sensitive", null, "ambiguous", null],
    ["save %EF%BD%85xport the notes", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["save the notes before you deléte the old ones", "gated", "sanctuary_forget", "delete", {"args": "<operator-approved placeholders only>"}],
    ["remember to еxport my identity bundle", "sensitive", null, "unreadable", null],
    ["save %C3%A9xport the notes", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["save my café notes", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["remember my timezone", "ordinary", "sanctuary_remember", undefined, {"key": "user_tz", "value": "America/Los_Angeles"}],
    [`save ${Buffer.from("東京").toString("base64")}`, "sensitive", null, "unreadable", null],
    ["save %2565xport the notes", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["remember %EF%BC%8565xport the notes", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["save %252565xport the notes", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    [`save %${"25".repeat(decodePasses)}65xport the notes`, "sensitive", null, "variant_budget", null],
    [`save %${"25".repeat(decodePasses - 1)}65xport the notes`, "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["save %zz %2565xport the notes", "gated", null, "export", {"args": "<operator-approved placeholders only>"}],
    ["not-save the note", "sensitive", null, "ambiguous", null],
    ["not—save the note", "sensitive", null, "ambiguous", null],
    ["not_save the note", "sensitive", null, "ambiguous", null],
    ["not.save the note", "sensitive", null, "ambiguous", null],
    ["not/save the note", "sensitive", null, "ambiguous", null],
    ["save the notes before you del_ete the old ones", "gated", "sanctuary_forget", "delete", {"args": "<operator-approved placeholders only>"}],
    ["save the notes before you del.ete the old ones", "gated", "sanctuary_forget", "delete", {"args": "<operator-approved placeholders only>"}],
    ["save the notes before you del\u{10ead}ete the old ones", "gated", "sanctuary_forget", "delete", {"args": "<operator-approved placeholders only>"}],
    ["save notes.txt for later", "ordinary", "sanctuary_remember", undefined, {"key": "<key>", "value": "<value>"}],
    ["assign-ature the form", "gated", null, "signature", {"args": "<operator-approved placeholders only>"}],
    ["save the note, what did I save but never store again", "sensitive", null, "conflict", null],
    ["what did I save but never store again", "sensitive", null, "conflict", null],
    ["what did I never save", "sensitive", null, "conflict", null],
  ] as const)("routes help intent: %s", (intent, safetyClass, tool, probeKey, example) => {
    const answer = classifyIntent(intent);
    expect(answer.safety_class).toBe(safetyClass);
    expect(answer.tool).toBe(tool);
    expect(answer.probe_key).toBe(probeKey);
    expect(answer.example).toEqual(example);
    if (tool === "monitor_health") {
      expect(answer.intent_class).toBe("evaluate");
      expect(answer.evaluate_question).toBe("bounds");
    } else expect(answer.intent_class).toBeUndefined();
  });
  it("counts received code points before normalization and scans each band edge", () => {
    expect("lorem ".repeat(170) + "ipsum").toHaveLength(1025);
    expect("lorem ".repeat(240) + "now export the list " + "z".repeat(40)).toHaveLength(1500);
    expect(classifyIntent("😀".repeat(1024)).probe_key).toBe("ambiguous");
    expect(classifyIntent("😀".repeat(1025)).probe_key).toBe("oversize");
    expect(classifyIntent("ﷺ".repeat(1024)).probe_key).toBe("unreadable");
    expect(classifyIntent("x".repeat(1500) + "export").probe_key).toBe("export");
  });
  it.each([
    ["privatekey", "privatekey"],
    ["secretkey", "secretkey"],
    ["save cHJpdmF0ZWtleQ==", "privatekey"],
    ["save c2VjcmV0a2V5", "secretkey"],
    ["exp-ort", "export"],
    ["export %zz", "export"],
  ])("screens compact and separated requests: %s", (intent, probeKey) => {
    expect(classifyIntent(intent!)).toMatchObject({ safety_class: "gated", tool: null, probe_key: probeKey });
  });
  it("retains plain routing when percent text is incomplete", () => {
    expect(classifyIntent("save %zz").tool).toBe("sanctuary_remember");
  });
  it("routes every declared memory cue through its cue class", () => {
    for (const cue of HELP_WRITE_CUES) expect(classifyIntent(`${cue} the color`).tool, cue).toBe("sanctuary_remember");
    for (const cue of [...HELP_STRONG_READ_CUES, ...HELP_WEAK_READ_CUES]) expect(classifyIntent(`${cue} the color`).tool, cue).toBe("sanctuary_recall");
    for (const verb of ["make", "take", "leave", "add"]) {
      for (const object of ["note", "notes", "message", "memo", "reminder"]) expect(classifyIntent(`${verb} a short ${object}`).tool).toBe("sanctuary_remember");
    }
    for (const verb of ["put", "add", "commit"]) {
      for (const destination of ["to memory", "in memory", "into memory"]) expect(classifyIntent(`${verb} this ${destination}`).tool).toBe("sanctuary_remember");
    }
  });
  it("reads question openers as whitespace-separated words", () => {
    expect(classifyIntent("do  you remember my timezone").tool).toBe("sanctuary_recall");
    expect(classifyIntent("do  you remember this value for next time")).toMatchObject({ safety_class: "sensitive", tool: null, probe_key: "conflict" });
  });
  it("retains distinct read cues within write-object phrases", () => {
    for (const intent of ["make a read note", "add a read note", "put read into memory", "commit get into memory"]) {
      expect(classifyIntent(intent)).toMatchObject({ safety_class: "sensitive", tool: null, probe_key: "conflict" });
    }
  });
  it("keeps local negation attached through two intervening tokens and normalized apostrophes", () => {
    for (const cue of [...HELP_WRITE_CUES, ...HELP_STRONG_READ_CUES, ...HELP_WEAK_READ_CUES]) {
      for (const prefix of ["not", "never", "don't you", "cannot", "do not ever", "don’t", "don‘t", "couldnʼt", "not please kindly"]) {
        expect(classifyIntent(`${prefix} ${cue} the color`).tool, `${prefix} ${cue}`).toBeNull();
      }
    }
    expect(classifyIntent("not please kindly maybe save the color").tool).toBe("sanctuary_remember");
    expect(classifyIntent("save the color but never store the shape").tool).toBeNull();
  });

  it("honors read negation in a stored-data question's clause", () => {
    for (const intent of ["what did I save but do not recall the saved note", "did you store the note but never retrieve it"]) {
      expect(classifyIntent(intent)).toMatchObject({ safety_class: "sensitive", tool: null, probe_key: "ambiguous" });
    }
  });

  it("names a timezone key only when the intent carries timezone tokens", () => {
    for (const cue of [...HELP_WRITE_CUES, ...HELP_STRONG_READ_CUES, ...HELP_WEAK_READ_CUES]) {
      for (const subject of ["the color", "the launch date", "my time zone", "timezone", "user_tz", "time-zone", "tzvalue"]) {
        const answer = classifyIntent(`${cue} ${subject}`);
        if (answer.safety_class !== "ordinary") continue;
        const expected = ["my time zone", "timezone", "user_tz", "time-zone"].includes(subject) ? "user_tz" : "<key>";
        expect(answer.example?.key, `${cue} ${subject}`).toBe(expected);
      }
    }
  });

});
