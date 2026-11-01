// Immediate insert admission preserves the single slot, commit barriers, control ordering and cleanup.
import { describe, expect, it } from "vitest";
import { HermesApprovalLedger, HermesRateWindow, HERMES_INSERT_DEADLINE_MS, HERMES_TOOL_TIMEOUT_MS,
  HERMES_RATE_WINDOW_MS, HERMES_RESPONSE_MARGIN_MS, PROBE_REPLY_BOUND_MS, MAX_RESULT_FRAME_BYTES,
  type HermesApprovalCommitCheckInput } from "../../src/hermes-memory-bridge/index.js";
import { MEMORY_BATCH_LOCK_TIMEOUT_MS } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { ApprovalLedgerModel } from "./approval-ledger-model.js";

const ENTRY = "entry";
const HASH = "text-digest";
const INPUT: HermesApprovalCommitCheckInput = { probe: "resolved", admitDurable: true, nowMs: 0,
  recordCurrent: true, passageTextSha256: HASH, getFrameUtf8Bytes: MAX_RESULT_FRAME_BYTES };
type Subject = HermesApprovalLedger | ApprovalLedgerModel;
const STATES = ["empty", "admitted", "started", "committing", "committed", "indeterminate", "cancelled", "timed_out", "gone", "refused", "stopped", "latched"] as const;
const EVENTS = ["admit", "start", "check", "cancel", "shutdown", "deadline", "gone", "stop", "latch", "committed", "indeterminate", "write_refused", "settle"] as const;
type Event = typeof EVENTS[number];
function event(subject: Subject, kind: Event) {
  switch (kind) {
    case "admit": return subject.admit(ENTRY, "c1", "r1", HASH, 0);
    case "start": return subject.insertStarted(ENTRY);
    case "check": return subject.commitCheck(ENTRY, INPUT);
    case "cancel": return subject.cancel(ENTRY);
    case "shutdown": return subject.peerShutdown(ENTRY);
    case "deadline": return subject.deadline(ENTRY);
    case "gone": return subject.connectionGone(ENTRY);
    case "stop": return subject.stop();
    case "latch": return subject.latch("audit");
    case "committed": return subject.writeFinished(ENTRY, "committed");
    case "indeterminate": return subject.writeFinished(ENTRY, "indeterminate");
    case "write_refused": return subject.writeFinished(ENTRY, "failed");
    case "settle": return subject.settled(ENTRY);
  }
}
function setup(subject: Subject, state: typeof STATES[number]) {
  if (state === "empty") return;
  event(subject, "admit");
  if (state === "admitted") return;
  event(subject, "start");
  if (state === "started") return;
  if (["cancelled", "timed_out", "gone", "stopped", "latched"].includes(state)) {
    const control = { cancelled: "cancel", timed_out: "deadline", gone: "gone", stopped: "stop", latched: "latch" } as const;
    event(subject, control[state as keyof typeof control]);
    return;
  }
  event(subject, "check");
  if (state === "committing") return;
  event(subject, state === "refused" ? "write_refused" : state as "committed" | "indeterminate");
}
function pair(state: typeof STATES[number] = "started") {
  const real = new HermesApprovalLedger();
  const model = new ApprovalLedgerModel(HERMES_INSERT_DEADLINE_MS, MAX_RESULT_FRAME_BYTES);
  setup(real, state); setup(model, state);
  return { real, model };
}
it("derives the insert deadline from the unchanged client and storage budgets", () => {
  expect(HERMES_INSERT_DEADLINE_MS).toBe(HERMES_TOOL_TIMEOUT_MS - MEMORY_BATCH_LOCK_TIMEOUT_MS - PROBE_REPLY_BOUND_MS - HERMES_RESPONSE_MARGIN_MS);
});
it("starts admission without an approval state, prompt or audit action", () => {
  const ledger = new HermesApprovalLedger();
  expect(ledger.admit(ENTRY, "c1", "r1", HASH, 0)).toEqual({ actions: [] });
  expect(ledger.snapshot().entry?.state).toBe("INSERT_STARTED");
  expect(ledger).not.toHaveProperty("ownerApprove");
  expect(ledger).not.toHaveProperty("ownerDeny");
});
it.each(STATES.flatMap(state => EVENTS.map(kind => [state, kind] as const)))("keeps the full state/event table: %s / %s", (state, kind) => {
  const { real, model } = pair(state);
  expect(event(real, kind)).toEqual(event(model, kind));
  expect(real.snapshot()).toEqual(model.snapshot());
});
it.each([
  { probe: "refused" as const }, { recordCurrent: false }, { passageTextSha256: "different" },
  { getFrameUtf8Bytes: MAX_RESULT_FRAME_BYTES + 1 }, { getFrameUtf8Bytes: -1 },
  { getFrameUtf8Bytes: Number.NaN }, { admitDurable: false }, { nowMs: HERMES_INSERT_DEADLINE_MS },
  { nowMs: Number.NaN },
])("refuses every incomplete commit binding %j", override => {
  const { real } = pair();
  expect(real.commitCheck(ENTRY, { ...INPUT, ...override }).decision).toBe("refuse");
});
it("holds the slot through the storage outcome and answers exactly once on settlement", () => {
  const { real } = pair("committing");
  expect(real.writeFinished(ENTRY, "committed").actions).toEqual([]);
  expect(real.admit("other", "c2", "r2", HASH, 0).refusal).toBe("busy");
  expect(real.settled(ENTRY).actions).toEqual([{ kind: "respond", entryId: ENTRY, response: "success" }]);
  expect(real.snapshot().entry).toBeUndefined();
  expect(real.settled(ENTRY).actions).toEqual([]);
});
it("clamps a backward clock and preserves terminal control precedence", () => {
  const { real } = pair();
  real.admit("busy", "c2", "r2", HASH, HERMES_INSERT_DEADLINE_MS);
  expect(real.commitCheck(ENTRY, { ...INPUT, nowMs: -1 }).decision).toBe("refuse");
  expect(real.snapshot().entry?.state).toBe("TIMED_OUT");
});
it("suppresses responses after peer loss and latches an indeterminate write", () => {
  const { real } = pair("committing");
  real.connectionGone(ENTRY);
  real.writeFinished(ENTRY, "indeterminate");
  expect(real.settled(ENTRY).actions).toEqual([]);
  expect(real.admit("next", "c2", "r2", HASH, 0).refusal).toBe("latched");
});
it("matches independent seeded admission and fault schedules", () => {
  for (let seed = 1; seed <= 3000; seed++) {
    const { real, model } = pair("empty");
    let random = seed;
    for (let turn = 0; turn < 128; turn++) {
      random = (Math.imul(random, 1664525) + 1013904223) >>> 0; // Numerical Recipes 32-bit LCG.
      const kind = EVENTS[random % EVENTS.length]!;
      expect(event(real, kind), `seed ${seed}, turn ${turn}`).toEqual(event(model, kind));
      expect(real.snapshot(), `seed ${seed}, turn ${turn}`).toEqual(model.snapshot());
    }
  }
});

describe("Hermes rate window", () => {
  it("admits exactly the configured count inside a window", () => {
    const window = new HermesRateWindow(3, 10);
    expect(window.admit(0).allowed).toBe(true);
    expect(window.admit(1).allowed).toBe(true);
    expect(window.admit(2).allowed).toBe(true);
    expect(window.admit(3).allowed).toBe(false);
    expect(window.retainedCount).toBe(3);
  });

  it("reopens admission at the exact window boundary", () => {
    const window = new HermesRateWindow(1, 10);
    expect(window.admit(5).allowed).toBe(true);
    expect(window.admit(14).allowed).toBe(false);
    expect(window.admit(15).allowed).toBe(true);
  });

  it("does not reopen admission on a backward clock step", () => {
    const window = new HermesRateWindow(1, 10);
    expect(window.admit(100).allowed).toBe(true);
    expect(window.admit(50).allowed).toBe(false);
    expect(window.admit(109).allowed).toBe(false);
  });

  it("keeps bounded timestamp state under sustained refusal", () => {
    const window = new HermesRateWindow(2, HERMES_RATE_WINDOW_MS);
    for (let index = 0; index < 1_000_000; index += 1) window.admit(index);
    expect(window.retainedCount).toBeLessThanOrEqual(2);
  });
});


// The former hold controls now act on the started slot, with the same settlement and late-control guarantees.
it("applies admission checks without mutating refused entries", () => {
  for (const state of ["stopped", "latched"] as const) {
    const { real } = pair(state);
    const before = real.snapshot();
    expect(real.admit("other", "c2", "r2", HASH, 0).refusal).toBe(state);
    expect(real.snapshot()).toEqual(before);
  }
  const { real } = pair();
  const before = real.snapshot();
  expect(real.admit("other", "c2", "r2", HASH, Number.NaN).refusal).toBe("invalid_clock");
  expect(real.snapshot()).toEqual(before);
  for (let index = 0; index < 100; index++) expect(real.admit("other", "c2", "r2", HASH, 0).refusal).toBe("busy");
  expect(real.snapshot()).toEqual(before);
});
it("applies controls only to the named entry", () => {
  const { real } = pair();
  const before = real.snapshot();
  for (const kind of ["cancel", "deadline", "connectionGone", "peerShutdown"] as const) {
    expect(real[kind]("unknown")).toEqual({ actions: [] });
    expect(real.snapshot()).toEqual(before);
  }
});
it("derives admission deadlines from the clamped ledger clock", () => {
  const ledger = new HermesApprovalLedger();
  ledger.admit("first", "c1", "r1", HASH, HERMES_RATE_WINDOW_MS);
  ledger.cancel("first");
  ledger.admit("second", "c1", "r2", HASH, 0);
  expect(ledger.snapshot().entry?.deadlineAt).toBe(HERMES_RATE_WINDOW_MS + HERMES_INSERT_DEADLINE_MS);
});
it("uses the earliest refusing arm for paired signals", () => {
  for (const [first, second, expected] of [
    ["gone", "cancel", "DISCONNECTED"], ["cancel", "deadline", "CANCELED"], ["deadline", "stop", "REFUSED"],
    ["cancel", "latch", "REFUSED"],
  ] as const) {
    const { real } = pair(); event(real, first); event(real, second); event(real, "check");
    expect(real.snapshot().entry?.state).toBe(expected);
  }
});
it("does not mutate on a non-finite commit clock", () => {
  const { real } = pair(); const before = real.snapshot();
  expect(real.commitCheck(ENTRY, { ...INPUT, nowMs: Number.NaN })).toEqual({ actions: [], fatal: "ledger_order", decision: "refuse" });
  expect(real.snapshot()).toEqual(before);
});
it.each(["cancel", "shutdown", "deadline", "gone", "stop", "latch"] as const)("settles started entries from the recorded %s signal", kind => {
  const { real, model } = pair();
  expect(event(real, kind)).toEqual(event(model, kind));
  expect(event(real, "settle")).toEqual(event(model, "settle"));
  expect(real.snapshot()).toEqual(model.snapshot());
  expect(real.snapshot().entry).toBeUndefined();
});
it("preserves the latch reason in the terminal state without extra audit actions", () => {
  const { real } = pair();
  expect(real.latch("audit").actions).toEqual([]);
  expect(real.latch("another").actions).toEqual([]);
  expect(event(real, "check").actions).toEqual([]);
  expect(real.snapshot().entry?.terminalReason).toBe("audit");
});
it("covers complete live schedules before and after the commit decision", () => {
  const observed = new Set<string>();
  // Each control receives both a pre-allow and post-allow schedule, including repeated late delivery.
  for (const control of ["cancel", "shutdown", "deadline", "gone", "stop", "latch"] as const) {
    for (const afterAllow of [false, true]) {
      for (const outcome of ["committed", "indeterminate", "write_refused"] as const) {
        const { real, model } = pair();
        const step = (kind: Event) => {
          const actual = event(real, kind);
          expect(actual).toEqual(event(model, kind));
          expect(real.snapshot()).toEqual(model.snapshot());
          const state = real.snapshot().entry?.state;
          if (state !== undefined) observed.add(state);
          return actual;
        };
        if (afterAllow) expect(step("check").decision).toBe("allow");
        step(control); step(control);
        if (afterAllow) step(outcome); else expect(step("check").decision).toBe("refuse");
        step("settle"); step(control); step("settle");
        expect(real.snapshot().entry).toBeUndefined();
      }
    }
  }
  expect(observed).toEqual(new Set(["INSERT_STARTED", "COMMITTING", "COMMITTED", "INDETERMINATE", "REFUSED", "CANCELED", "TIMED_OUT", "DISCONNECTED"]));
});
