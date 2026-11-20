// The read-ahead retains at most its window of slots, and at most RECALL_READ_AHEAD_RETAINED_TEXT_UNITS of passage
// text, at every commit: a slot is released when its passage is decided, and a passage past the per-passage cap
// keeps no text.
import { afterEach, describe, expect, it } from "vitest";
import {
  RECALL_MAX_PASSAGE_SCAN_UNITS,
  RECALL_READ_AHEAD_PASSAGES,
  RECALL_READ_AHEAD_RETAINED_TEXT_UNITS,
} from "../../src/hermes-memory-bridge/recall.js";
import { RecallReadAheadRing } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { NOW, recallFixture } from "./recall-score-first-fixture.js";

/** Sample the ring's retained state on entry to and exit from every take(), the commit's turn for each passage. */
function sampleRetainedState() {
  const samples: { readonly slots: number; readonly text: number }[] = [];
  const original = RecallReadAheadRing.prototype.take;
  RecallReadAheadRing.prototype.take = async function (this: RecallReadAheadRing, ordinal: number) {
    samples.push({ slots: this.retainedSlots, text: this.retainedTextUnits });
    const taken = await original.call(this, ordinal);
    samples.push({ slots: this.retainedSlots, text: this.retainedTextUnits });
    return taken;
  };
  return { samples, restore: () => { RecallReadAheadRing.prototype.take = original; } };
}

let restore: (() => void) | undefined;
afterEach(() => { restore?.(); restore = undefined; });

describe("retained read-ahead state stays bounded at every commit", () => {
  it("over 1000 valid passages of 1024 units on a constant clock", async () => {
    const passages = 1000, units = 1024; // Within the corpus ceiling and the scanned-unit cap together.
    const f = await recallFixture();
    for (let n = 0; n < passages; n++) {
      const text = `alpha ${String(n).padStart(4, "0")} `.padEnd(units, "x");
      await f.seed({ kind: "valid", passageId: `p${String(n).padStart(4, "0")}`, text, createdAt: NOW });
    }
    f.storage.writes = 0;
    const watch = sampleRetainedState(); restore = watch.restore;
    const budget = f.budget();
    const result = await f.adapter.recallPassages(budget);
    expect(watch.samples.length).toBe(2 * passages);
    // The property: the ring never holds more than its window, nor more text than its derived bound.
    expect(Math.max(...watch.samples.map(sample => sample.slots))).toBeLessThanOrEqual(RECALL_READ_AHEAD_PASSAGES);
    expect(Math.max(...watch.samples.map(sample => sample.text))).toBeLessThanOrEqual(RECALL_READ_AHEAD_RETAINED_TEXT_UNITS);
    expect(Math.max(...watch.samples.map(sample => sample.text))).toBeLessThanOrEqual(RECALL_READ_AHEAD_PASSAGES * units);
    // Positive control: the window did fill, and every passage was committed.
    expect(Math.max(...watch.samples.map(sample => sample.slots))).toBe(RECALL_READ_AHEAD_PASSAGES);
    expect(budget.unitsScanned).toBe(passages * units);
    expect(result.truncated).toBe(false);
    expect(f.storage.writes).toBe(0);
  });

  it("over passages whose chunks sit at the largest chunk size the adapter accepts", async () => {
    const maxChunkChars = 100_000; // MAX_CONFIGURABLE_CHUNK_CHARS in sdw-memory-backend.ts, the largest it accepts.
    const f = await recallFixture({ maxChunkChars });
    // Passages at the per-passage cap are retained whole; two-chunk passages cross it at their first chunk.
    const atCap = 6, overCap = 4;
    for (let n = 0; n < atCap + overCap; n++) {
      const length = n % 2 === 0 && n / 2 < overCap ? 2 * maxChunkChars : RECALL_MAX_PASSAGE_SCAN_UNITS;
      const text = `alpha ${n} `.padEnd(length, "y");
      await f.seed({ kind: "valid", passageId: `q${String(n).padStart(2, "0")}`, text, createdAt: NOW });
    }
    f.storage.writes = 0;
    const watch = sampleRetainedState(); restore = watch.restore;
    const result = await f.adapter.recallPassages(f.budget());
    expect(Math.max(...watch.samples.map(sample => sample.slots))).toBeLessThanOrEqual(RECALL_READ_AHEAD_PASSAGES);
    expect(Math.max(...watch.samples.map(sample => sample.text))).toBeLessThanOrEqual(RECALL_READ_AHEAD_RETAINED_TEXT_UNITS);
    // Positive control: passages at the cap were retained, and the ones over it were refused as too long.
    expect(Math.max(...watch.samples.map(sample => sample.text))).toBeGreaterThanOrEqual(RECALL_MAX_PASSAGE_SCAN_UNITS);
    expect(result.truncated).toBe(true);
    expect(result.passages.length).toBe(3);
    expect(f.storage.writes).toBe(0);
  });
});
