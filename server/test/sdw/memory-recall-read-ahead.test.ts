// Recall reads passages ahead of an ordered commit: the commit makes the same budget calls and decisions in listing
// order at every window, completion order does not change the result, the screen still gates every chunk read, the
// read-ahead stops with the scan, and an error is raised only when the commit reaches its passage.
import { describe, expect, it } from "vitest";
import {
  HermesRecallBudget,
  RECALL_READ_AHEAD_PASSAGES,
  RECALL_VERIFY_RESERVE_MS,
  RECALL_WALL_BUDGET_MS,
  type HermesRecallLimits,
} from "../../src/hermes-memory-bridge/recall.js";
import { NOW, QUERY, QUERY_WORDS, FILLER_WORDS, prng, recallFixture, settle, type Seed, type SeedKind } from "./recall-score-first-fixture.js";

/** A budget that logs every call that can change its state, in order; scanOpen is pure and is not logged. */
class LoggedBudget extends HermesRecallBudget {
  readonly log: string[] = [];
  override active() { const value = super.active(); this.log.push(`active:${value}`); return value; }
  override scanning() { const value = super.scanning(); this.log.push(`scanning:${value}`); return value; }
  override verifying() { const value = super.verifying(); this.log.push(`verifying:${value}`); return value; }
  override candidate() { const value = super.candidate(); this.log.push(`candidate:${value}`); return value; }
  override scan(units: number) { const value = super.scan(units); this.log.push(`scan:${units}:${value}`); return value; }
  override admit(...args: Parameters<HermesRecallBudget["admit"]>) { this.log.push(`admit:${args[0].passage_id}`); super.admit(...args); }
}

// Kinds the commit skips, answers or verifies without aborting the call, including both full-verification arms.
const CONTINUING_KINDS: readonly SeedKind[] = ["valid", "valid", "valid", "foreign-valid", "stale-status", "quarantined",
  "invalid-signature", "bad-signer", "unresolved-signer", "quarantined-missing-chunk", "invalid-with-broken-chunk",
  "undecodable-provenance", "is-marked-throws-invalid"];
const ABORTING_KINDS: readonly SeedKind[] = ["missing-chunk", "undecodable-document", "undecodable-chunk", "is-marked-throws"];
const PASSAGES = 12; // Three read-ahead windows of passages, so slots are reused and errors can sit past a stop.

/** A seeded corpus of continuing kinds; `abortingAt` places one aborting kind at that position. */
function corpus(seed: number, abortingAt?: number): Seed[] {
  const random = prng(0xa11ead00 + seed);
  const pick = <T,>(items: readonly T[]) => items[Math.floor(random() * items.length)]!;
  return Array.from({ length: PASSAGES }, (_, n) => {
    const matching = random() < 0.6;
    const words = Array.from({ length: 3 + Math.floor(random() * 6) }, () => matching && random() < 0.5 ? pick(QUERY_WORDS) : pick(FILLER_WORDS));
    if (matching) words.push(pick(QUERY_WORDS));
    return { kind: n === abortingAt ? pick(ABORTING_KINDS) : pick(CONTINUING_KINDS),
      passageId: `p${String(n).padStart(2, "0")}`, text: words.join(" "), createdAt: NOW };
  });
}

async function seeded(seeds: readonly Seed[], readAhead: number) {
  const f = await recallFixture({ readAhead });
  for (const seed of seeds) await f.seed(seed);
  f.storage.writes = 0;
  f.storage.chunkReads = 0;
  return f;
}

async function recall(seeds: readonly Seed[], readAhead: number, tighten: Partial<HermesRecallLimits>, delays?: () => number) {
  const f = await seeded(seeds, readAhead);
  if (delays !== undefined) {
    f.storage.beforeRead = async () => {
      // Each read waits a random number of event-loop turns, so reads of different slots finish in shuffled order.
      for (let turn = delays(); turn > 0; turn--) await new Promise<void>(resolve => setImmediate(resolve));
    };
  }
  const budget = new LoggedBudget(QUERY, () => 0, new AbortController().signal, { ...tighten, readAhead });
  const outcome = await settle(() => f.adapter.recallPassages(budget));
  return { f, budget, outcome: outcome.ok ? outcome : { ok: false, error: String(outcome.error) } };
}

const SEEDS = 8;
const stops: readonly { readonly name: string; readonly tighten: Partial<HermesRecallLimits> }[] = [
  { name: "no stop", tighten: {} },
  { name: "the candidate cap", tighten: { candidates: PASSAGES - 2 } },
  { name: "the scanned-unit cap", tighten: { scannedUnits: 40 } }, // Forty units: a few short passages, then the cap.
];

describe("row 1: the commit makes the same budget calls in the same order at every window", () => {
  it.each(stops)("with $name", async ({ tighten }) => {
    for (let seed = 0; seed < SEEDS; seed++) {
      const seeds = corpus(seed);
      const sequential = await recall(seeds, 1, tighten);
      const readAhead = await recall(seeds, RECALL_READ_AHEAD_PASSAGES, tighten);
      expect(readAhead.budget.log, `seed ${seed}`).toEqual(sequential.budget.log);
      expect(readAhead.outcome, `seed ${seed}`).toEqual(sequential.outcome);
      expect(readAhead.f.storage.writes).toBe(0);
    }
  });
});

describe("row 2: random completion order equals the one-passage-at-a-time result", () => {
  it.each(Array.from({ length: SEEDS }, (_, seed) => seed))("seed %i", async seed => {
    // Odd seeds put an aborting passage past the candidate cap, where the one-at-a-time loop never reads it.
    const abortingAt = seed % 2 === 1 ? PASSAGES - 1 : seed % 4 === 2 ? Math.floor(PASSAGES / 2) : undefined;
    const tighten = seed % 2 === 1 ? { candidates: PASSAGES - 2 } : {};
    const seeds = corpus(seed, abortingAt);
    const sequential = await recall(seeds, 1, tighten);
    const random = prng(0xc0ffee00 + seed);
    const shuffled = await recall(seeds, RECALL_READ_AHEAD_PASSAGES, tighten, () => Math.floor(random() * 4)); // Zero to three turns.
    expect(shuffled.outcome).toEqual(sequential.outcome);
    expect(shuffled.f.storage.writes).toBe(0);
    if (abortingAt === PASSAGES - 1) expect(sequential.outcome.ok).toBe(true);
    if (abortingAt === Math.floor(PASSAGES / 2)) expect(sequential.outcome.ok).toBe(false);
  });
});

describe("row 3: a passage the screen skips reads no chunks at the default window", () => {
  it("reads none of the bad-signer maximum body's chunks and spends none of its units", async () => {
    const maxBody = 65_536; // RECALL_MAX_PASSAGE_SCAN_UNITS: the largest body recall scores in full.
    const body = ("alpha ".repeat(Math.ceil(maxBody / "alpha ".length))).slice(0, maxBody);
    const valid = (passageId: string): Seed => ({ kind: "valid", passageId, text: "alpha bravo", createdAt: NOW });
    const seeds: Seed[] = [valid("a0"), { kind: "bad-signer-max-body", passageId: "a1", text: body, createdAt: NOW }, valid("a2"), valid("a3")];
    const f = await seeded(seeds, RECALL_READ_AHEAD_PASSAGES);
    const chunkReads = new Map<string, number>();
    f.storage.beforeRead = key => {
      const owner = seeds.find(seed => key.startsWith(`chunk.${f.documentIdOf(seed.passageId)}.`));
      if (owner !== undefined) chunkReads.set(owner.passageId, (chunkReads.get(owner.passageId) ?? 0) + 1);
    };
    const budget = f.budget();
    const result = await f.adapter.recallPassages(budget);
    expect(chunkReads.get("a1") ?? 0).toBe(0);
    // Positive control: the valid neighbours, read in the same windows, each read their one chunk.
    expect(chunkReads.get("a0")).toBe(1);
    expect(chunkReads.get("a2")).toBe(1);
    expect(chunkReads.get("a3")).toBe(1);
    expect(budget.unitsScanned).toBe(3 * "alpha bravo".length); // Three valid neighbours, none of the skipped body.
    expect(result.passages.map(passage => passage.passage_id)).toEqual(["a0", "a2", "a3"]);
  });
});

describe("row 7: the read-ahead stops with the scan", () => {
  it("reads no chunk once the verification reserve has passed on a clock advanced by each read", async () => {
    const seeds = Array.from({ length: 30 }, (_, n): Seed => ({ kind: "valid", passageId: `p${String(n).padStart(2, "0")}`,
      text: "alpha bravo", createdAt: NOW })); // Thirty passages: more reads than the reserve allows.
    const f = await seeded(seeds, RECALL_READ_AHEAD_PASSAGES);
    const reserveAt = RECALL_WALL_BUDGET_MS - RECALL_VERIFY_RESERVE_MS;
    f.storage.step = reserveAt / 40; // Forty reads reach the reserve, about thirteen passages at three reads each.
    let late = 0, early = 0;
    f.storage.beforeRead = key => {
      if (!key.startsWith("chunk.")) return;
      if (f.storage.now >= reserveAt) late++; else early++;
    };
    const result = await f.adapter.recallPassages(f.budget(QUERY, () => f.storage.now));
    expect(late).toBe(0);
    // Positive control: chunks were read while the scan was open, and the scan did stop.
    expect(early).toBeGreaterThan(0);
    expect(result.truncated).toBe(true);
  });
});

describe("row 8: an error is raised only when the commit reaches its passage", () => {
  const failing = "p03"; // Inside the first read-ahead window, so its read fails before the commit reaches it.
  const seeds = Array.from({ length: 10 }, (_, n): Seed => ({ kind: "valid", passageId: `p${String(n).padStart(2, "0")}`,
    text: `alpha note ${n}`, createdAt: NOW })); // Ten passages: more than two windows.
  async function run(readAhead: number, tighten: Partial<HermesRecallLimits>) {
    const f = await seeded(seeds, readAhead);
    f.storage.beforeRead = key => { if (key === `doc.${f.documentIdOf(failing)}`) throw new Error("injected document read failure"); };
    const budget = new LoggedBudget(QUERY, () => 0, new AbortController().signal, { ...tighten, readAhead });
    const outcome = await settle(() => f.adapter.recallPassages(budget));
    return { budget, outcome };
  }
  it("aborts at the failing passage's turn when the commit reaches it", async () => {
    const readAhead = await run(RECALL_READ_AHEAD_PASSAGES, {});
    // The commit had admitted p00 to p03 as candidates when the error was raised, not just p00.
    expect(readAhead.budget.candidatesScanned).toBe(4);
    expect(readAhead.outcome).toMatchObject({ ok: false });
    expect(String((readAhead.outcome as { error: unknown }).error)).toContain("injected document read failure");
    const sequential = await run(1, {});
    expect(readAhead.budget.log).toEqual(sequential.budget.log);
  });
  it("discards the error when the scan stops before the failing passage", async () => {
    const tighten = { candidates: 3 }; // The commit stops at p02; p03 was read ahead in the first window.
    const readAhead = await run(RECALL_READ_AHEAD_PASSAGES, tighten);
    const sequential = await run(1, tighten);
    expect(readAhead.outcome).toEqual(sequential.outcome);
    expect(readAhead.outcome.ok).toBe(true);
    expect(readAhead.outcome.ok && readAhead.outcome.value.truncated).toBe(true);
  });
});
