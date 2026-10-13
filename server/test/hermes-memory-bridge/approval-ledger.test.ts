import { describe, expect, it } from "vitest";

import {
  HERMES_APPROVAL_DEADLINE_MS,
  HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE,
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
  HERMES_RATE_WINDOW_MS,
  HERMES_RESPONSE_MARGIN_MS,
  HERMES_TOOL_TIMEOUT_MS,
  MAX_RESULT_FRAME_BYTES,
  PROBE_REPLY_BOUND_MS,
  HermesApprovalLedger,
  HermesRateWindow,
  type HermesApprovalAction,
  type HermesApprovalCommitCheckInput,
  type HermesApprovalEntryState,
  type HermesApprovalLedgerResult,
  type HermesApprovalLateEvent,
  type HermesApprovalRefusalReason,
  type HermesApprovalResponseClass,
  type HermesApprovalTerminalState,
  type HermesApprovalWriteOutcome,
} from "../../src/hermes-memory-bridge/index.js";
import {
  MEMORY_BATCH_LOCK_TIMEOUT_MS,
  hermesBridgePassageTextDigest,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { ApprovalLedgerModel } from "./approval-ledger-model.js";

type HermesApprovalRespondAction = Extract<HermesApprovalAction, { readonly kind: "respond" }>;

const PASSAGE_TEXT = "bridge passage\nwith unicode snow \u2603";
const HASH = hermesBridgePassageTextDigest(PASSAGE_TEXT);
const OTHER_HASH = hermesBridgePassageTextDigest("different bridge passage");
const ENTRY = "00112233445566778899aabbccddeeff";
const CONNECTION = "c1";
const RECORD = "record-1";
const DIFFERENTIAL_SCHEDULES = 3_000;
const DIFFERENTIAL_SEED = 0x2a1_0005;

type SetupState =
  | "PENDING"
  | "APPROVED_NOT_STARTED"
  | "APPROVED_STARTED"
  | "COMMITTING"
  | "TERMINAL_NOT_SETTLED"
  | "NO_ENTRY";

type CellEvent =
  | "approve_matching"
  | "approve_different"
  | "deny"
  | "deadline"
  | "cancel"
  | "peer_shutdown"
  | "connection_gone"
  | "stop"
  | "latch"
  | "insert_started"
  | "commit_check"
  | "write_finished"
  | "settled";

interface CellExpectation {
  readonly state?: HermesApprovalEntryState;
  readonly deleted?: boolean;
  readonly actions: readonly HermesApprovalAction[];
  readonly refusal?: string;
  readonly fatal?: string;
  readonly decision?: string;
  readonly responded?: boolean;
  readonly seen?: Partial<Record<HermesApprovalLateEvent, boolean>>;
}

const SETUP_STATES = [
  "PENDING",
  "APPROVED_NOT_STARTED",
  "APPROVED_STARTED",
  "COMMITTING",
  "TERMINAL_NOT_SETTLED",
  "NO_ENTRY",
] as const satisfies readonly SetupState[];

const CELL_EVENTS = [
  "approve_matching",
  "approve_different",
  "deny",
  "deadline",
  "cancel",
  "peer_shutdown",
  "connection_gone",
  "stop",
  "latch",
  "insert_started",
  "commit_check",
  "write_finished",
  "settled",
] as const satisfies readonly CellEvent[];

const terminalAudit = (
  state: HermesApprovalTerminalState,
  reason: string,
  lateEvents: readonly HermesApprovalLateEvent[] = [],
): HermesApprovalAction => ({ kind: "audit", entryId: ENTRY, event: "terminal", state, reason, lateEvents });
const respondDenial: HermesApprovalAction = { kind: "respond", entryId: ENTRY, response: "denial", message: HERMES_MEMORY_DENIAL };
const respondUnavailable: HermesApprovalAction = {
  kind: "respond",
  entryId: ENTRY,
  response: "unavailable",
  message: HERMES_MEMORY_UNAVAILABLE,
};
const respondSuccess: HermesApprovalAction = { kind: "respond", entryId: ENTRY, response: "success" };

const CELL_TABLE: Record<SetupState, Record<CellEvent, CellExpectation>> = {
  PENDING: {
    approve_matching: { state: "APPROVED", actions: [{ kind: "audit", entryId: ENTRY, event: "approved" }] },
    approve_different: { state: "PENDING", actions: [], refusal: "hash_mismatch" },
    deny: { deleted: true, actions: [terminalAudit("DENIED", "owner_denied"), respondDenial], responded: true },
    deadline: { deleted: true, actions: [terminalAudit("TIMED_OUT", "deadline"), respondDenial], responded: true },
    cancel: { deleted: true, actions: [terminalAudit("CANCELED", "cancel"), respondDenial], responded: true },
    peer_shutdown: { deleted: true, actions: [terminalAudit("CANCELED", "peer_shutdown"), respondDenial], responded: true },
    connection_gone: { deleted: true, actions: [terminalAudit("DISCONNECTED", "connection_gone")], seen: { gone: true } },
    stop: { deleted: true, actions: [terminalAudit("REFUSED", "stopped"), respondUnavailable], responded: true },
    latch: { deleted: true, actions: [terminalAudit("REFUSED", "audit_failed"), respondUnavailable], responded: true },
    insert_started: { state: "PENDING", actions: [], refusal: "not_approved" },
    commit_check: { state: "PENDING", actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { state: "PENDING", actions: [], fatal: "ledger_order" },
    settled: { state: "PENDING", actions: [], fatal: "ledger_order" },
  },
  APPROVED_NOT_STARTED: {
    approve_matching: { state: "APPROVED", actions: [], refusal: "not_pending" },
    approve_different: { state: "APPROVED", actions: [], refusal: "not_pending" },
    deny: { deleted: true, actions: [terminalAudit("DENIED", "owner_denied"), respondDenial], responded: true },
    deadline: { deleted: true, actions: [terminalAudit("TIMED_OUT", "deadline"), respondDenial], responded: true },
    cancel: { deleted: true, actions: [terminalAudit("CANCELED", "cancel"), respondDenial], responded: true },
    peer_shutdown: { deleted: true, actions: [terminalAudit("CANCELED", "peer_shutdown"), respondDenial], responded: true },
    connection_gone: { deleted: true, actions: [terminalAudit("DISCONNECTED", "connection_gone")], seen: { gone: true } },
    stop: { deleted: true, actions: [terminalAudit("REFUSED", "stopped"), respondUnavailable], responded: true },
    latch: { deleted: true, actions: [terminalAudit("REFUSED", "audit_failed"), respondUnavailable], responded: true },
    insert_started: { state: "APPROVED", actions: [] },
    commit_check: { state: "APPROVED", actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { state: "APPROVED", actions: [], fatal: "ledger_order" },
    settled: { state: "APPROVED", actions: [], fatal: "ledger_order" },
  },
  APPROVED_STARTED: {
    approve_matching: { state: "APPROVED", actions: [], refusal: "not_pending" },
    approve_different: { state: "APPROVED", actions: [], refusal: "not_pending" },
    deny: { state: "APPROVED", actions: [], seen: { deny: true } },
    deadline: { state: "APPROVED", actions: [], seen: { deadline: true } },
    cancel: { state: "APPROVED", actions: [], seen: { cancel: true } },
    peer_shutdown: { state: "APPROVED", actions: [], seen: { cancel: true } },
    connection_gone: { state: "APPROVED", actions: [], seen: { gone: true } },
    stop: { state: "APPROVED", actions: [], seen: { stop: true } },
    latch: { state: "APPROVED", actions: [], seen: { latch: true } },
    insert_started: { state: "APPROVED", actions: [], fatal: "ledger_order" },
    commit_check: { state: "COMMITTING", actions: [], decision: "allow" },
    write_finished: { state: "APPROVED", actions: [], fatal: "ledger_order" },
    settled: { deleted: true, actions: [terminalAudit("REFUSED", "insert_returned_before_commit_check"), respondDenial], responded: true },
  },
  COMMITTING: {
    approve_matching: { state: "COMMITTING", actions: [], refusal: "not_pending" },
    approve_different: { state: "COMMITTING", actions: [], refusal: "not_pending" },
    deny: { state: "COMMITTING", actions: [], seen: { deny: true } },
    deadline: { state: "COMMITTING", actions: [], seen: { deadline: true } },
    cancel: { state: "COMMITTING", actions: [], seen: { cancel: true } },
    peer_shutdown: { state: "COMMITTING", actions: [], seen: { cancel: true } },
    connection_gone: { state: "COMMITTING", actions: [], seen: { gone: true } },
    stop: { state: "COMMITTING", actions: [], seen: { stop: true } },
    latch: { state: "COMMITTING", actions: [], seen: { latch: true } },
    insert_started: { state: "COMMITTING", actions: [], fatal: "ledger_order" },
    commit_check: { state: "COMMITTING", actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { state: "COMMITTED", actions: [terminalAudit("COMMITTED", "write_committed")] },
    settled: { state: "COMMITTING", actions: [], fatal: "ledger_order" },
  },
  TERMINAL_NOT_SETTLED: {
    approve_matching: { state: "REFUSED", actions: [], refusal: "not_pending" },
    approve_different: { state: "REFUSED", actions: [], refusal: "not_pending" },
    deny: { state: "REFUSED", actions: [], refusal: "not_pending" },
    deadline: { state: "REFUSED", actions: [] },
    cancel: { state: "REFUSED", actions: [] },
    peer_shutdown: { state: "REFUSED", actions: [] },
    connection_gone: { state: "REFUSED", actions: [], seen: { gone: true } },
    stop: { state: "REFUSED", actions: [] },
    latch: { state: "REFUSED", actions: [] },
    insert_started: { state: "REFUSED", actions: [], fatal: "ledger_order" },
    commit_check: { state: "REFUSED", actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { state: "REFUSED", actions: [], fatal: "ledger_order" },
    settled: { deleted: true, actions: [respondDenial], responded: true },
  },
  NO_ENTRY: {
    approve_matching: { deleted: true, actions: [], refusal: "unknown_entry" },
    approve_different: { deleted: true, actions: [], refusal: "unknown_entry" },
    deny: { deleted: true, actions: [], refusal: "unknown_entry" },
    deadline: { deleted: true, actions: [] },
    cancel: { deleted: true, actions: [] },
    peer_shutdown: { deleted: true, actions: [] },
    connection_gone: { deleted: true, actions: [] },
    stop: { deleted: true, actions: [] },
    latch: { deleted: true, actions: [] },
    insert_started: { deleted: true, actions: [], refusal: "unknown_entry" },
    commit_check: { deleted: true, actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { deleted: true, actions: [], fatal: "ledger_order" },
    settled: { deleted: true, actions: [], fatal: "ledger_order" },
  },
};

function setup(state: SetupState): HermesApprovalLedger {
  const ledger = new HermesApprovalLedger();
  if (state === "NO_ENTRY") return ledger;
  expect(ledger.admit(ENTRY, CONNECTION, RECORD, HASH, 10).refusal).toBeUndefined();
  if (state === "PENDING") return ledger;
  expect(ledger.ownerApprove(ENTRY, HASH).refusal).toBeUndefined();
  if (state === "APPROVED_NOT_STARTED") return ledger;
  expect(ledger.insertStarted(ENTRY).refusal).toBeUndefined();
  if (state === "APPROVED_STARTED") return ledger;
  expect(ledger.commitCheck(ENTRY, commitInput()).decision).toBe("allow");
  if (state === "COMMITTING") return ledger;
  expect(ledger.writeFinished(ENTRY, "failed").actions).toEqual([terminalAudit("REFUSED", "write_failed")]);
  return ledger;
}

function commitInput(overrides: Partial<HermesApprovalCommitCheckInput> = {}): HermesApprovalCommitCheckInput {
  return {
    probe: "resolved",
    nowMs: 20,
    recordCurrent: true,
    passageTextSha256: HASH,
    getFrameUtf8Bytes: MAX_RESULT_FRAME_BYTES,
    ...overrides,
  };
}

function applyEvent(ledger: HermesApprovalLedger, event: CellEvent): HermesApprovalLedgerResult {
  switch (event) {
    case "approve_matching":
      return ledger.ownerApprove(ENTRY, HASH);
    case "approve_different":
      return ledger.ownerApprove(ENTRY, OTHER_HASH);
    case "deny":
      return ledger.ownerDeny(ENTRY);
    case "deadline":
      return ledger.deadline(ENTRY);
    case "cancel":
      return ledger.cancel(ENTRY);
    case "peer_shutdown":
      return ledger.peerShutdown(ENTRY);
    case "connection_gone":
      return ledger.connectionGone(ENTRY);
    case "stop":
      return ledger.stop();
    case "latch":
      return ledger.latch("audit_failed");
    case "insert_started":
      return ledger.insertStarted(ENTRY);
    case "commit_check":
      return ledger.commitCheck(ENTRY, commitInput());
    case "write_finished":
      return ledger.writeFinished(ENTRY, "committed");
    case "settled":
      return ledger.settled(ENTRY);
  }
}

function expectCell(state: SetupState, event: CellEvent): void {
  const ledger = setup(state);
  const result = applyEvent(ledger, event);
  const expected = CELL_TABLE[state][event];
  expect(result.actions).toEqual(expected.actions);
  expect(result.refusal).toBe(expected.refusal);
  expect(result.fatal).toBe(expected.fatal);
  expect(result.decision).toBe(expected.decision);
  const entry = ledger.snapshot().entry;
  if (expected.deleted === true) {
    expect(entry).toBeUndefined();
  } else {
    expect(entry?.state).toBe(expected.state);
    if (expected.responded !== undefined) expect(entry?.responded).toBe(expected.responded);
    for (const [flag, value] of Object.entries(expected.seen ?? {})) {
      expect(entry?.seen[flag as HermesApprovalLateEvent]).toBe(value);
    }
  }
}

function responseActions(result: HermesApprovalLedgerResult): readonly HermesApprovalRespondAction[] {
  return result.actions.filter((action): action is HermesApprovalRespondAction => action.kind === "respond");
}

function runToStarted(): HermesApprovalLedger {
  const ledger = new HermesApprovalLedger();
  ledger.admit(ENTRY, CONNECTION, RECORD, HASH, 0);
  ledger.ownerApprove(ENTRY, HASH);
  ledger.insertStarted(ENTRY);
  return ledger;
}

function terminalAtSettle(
  setupLedger: (ledger: HermesApprovalLedger) => void,
  input: Partial<HermesApprovalCommitCheckInput> = {},
): { readonly state: HermesApprovalTerminalState; readonly response?: HermesApprovalResponseClass; readonly result: HermesApprovalLedgerResult } {
  const ledger = runToStarted();
  setupLedger(ledger);
  const check = ledger.commitCheck(ENTRY, commitInput(input));
  expect(check.decision).toBe("refuse");
  const audit = check.actions.find((action) => action.kind === "audit" && action.event === "terminal");
  if (audit?.kind !== "audit" || audit.state === undefined) throw new Error("missing terminal audit");
  const result = ledger.settled(ENTRY);
  const response = responseActions(result)[0];
  return {
    state: audit.state,
    response: response?.kind === "respond" ? response.response : undefined,
    result,
  };
}

function rng(seed: number): () => number {
  let value = seed >>> 0;
  return () => {
    value = (value + 0x6d2b79f5) >>> 0;
    let mixed = value;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4_294_967_296;
  };
}

function stable(value: unknown): string {
  return JSON.stringify(value, (_key, inner) => inner instanceof Set ? [...inner].sort() : inner);
}

function normalizeSnapshot(snapshot: ReturnType<HermesApprovalLedger["snapshot"]>): unknown {
  return {
    stopped: snapshot.stopped,
    latched: snapshot.latched,
    largestNowMs: snapshot.largestNowMs,
    promptWindowCount: snapshot.promptWindowCount,
    entry: snapshot.entry === undefined ? undefined : {
      ...snapshot.entry,
      lateEvents: [...snapshot.entry.lateEvents].sort(),
    },
  };
}

describe("Hermes approval constants", () => {
  it("derives the approval deadline from the client and storage budgets", () => {
    expect(HERMES_APPROVAL_DEADLINE_MS).toBe(
      HERMES_TOOL_TIMEOUT_MS - MEMORY_BATCH_LOCK_TIMEOUT_MS - PROBE_REPLY_BOUND_MS - HERMES_RESPONSE_MARGIN_MS,
    );
    expect(HERMES_APPROVAL_DEADLINE_MS).toBe(83_000);
  });
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

describe("Hermes approval ledger table", () => {
  it("declares the full state and event cross product", () => {
    expect(Object.keys(CELL_TABLE).sort()).toEqual([...SETUP_STATES].sort());
    for (const state of SETUP_STATES) {
      expect(Object.keys(CELL_TABLE[state]).sort()).toEqual([...CELL_EVENTS].sort());
    }
  });

  it.each(SETUP_STATES.flatMap((state) => CELL_EVENTS.map((event) => [state, event] as const)))(
    "%s x %s follows the approval table",
    (state, event) => expectCell(state, event),
  );

  it("applies admission checks without mutating refused entries", () => {
    const stopped = new HermesApprovalLedger();
    stopped.stop();
    expect(stopped.admit("a", CONNECTION, RECORD, HASH, 0).refusal).toBe("stopped");

    const latched = new HermesApprovalLedger();
    latched.latch("audit_failed");
    expect(latched.admit("a", CONNECTION, RECORD, HASH, 0).refusal).toBe("latched");

    const invalidClock = new HermesApprovalLedger();
    expect(invalidClock.admit("a", CONNECTION, RECORD, HASH, Number.NaN).refusal).toBe("invalid_clock");
    expect(invalidClock.snapshot().entry).toBeUndefined();
    expect(invalidClock.snapshot().largestNowMs).toBe(Number.NEGATIVE_INFINITY);

    const busy = new HermesApprovalLedger();
    busy.admit("a", CONNECTION, RECORD, HASH, 0);
    expect(busy.admit("b", CONNECTION, "record-2", HASH, 1).refusal).toBe("busy");
    for (let index = 0; index < HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE; index += 1) {
      expect(busy.admit(`busy-${index}`, CONNECTION, `busy-record-${index}`, HASH, index + 2).refusal).toBe("busy");
    }
    expect(busy.ownerDeny("a").refusal).toBeUndefined();
    expect(busy.admit("after-busy", CONNECTION, "record-after-busy", HASH, 10).refusal).toBeUndefined();

    const promptRate = new HermesApprovalLedger();
    for (let index = 0; index < HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE; index += 1) {
      const id = `entry-${index}`;
      expect(promptRate.admit(id, CONNECTION, `record-${index}`, HASH, index).refusal).toBeUndefined();
      expect(promptRate.ownerDeny(id).refusal).toBeUndefined();
    }
    expect(promptRate.admit("rate", CONNECTION, "record-rate", HASH, 9).refusal).toBe("prompt_rate");
    expect(promptRate.snapshot().entry).toBeUndefined();
    expect(promptRate.admit("rate-open", CONNECTION, "record-open", HASH, HERMES_RATE_WINDOW_MS).refusal).toBeUndefined();
  });

  it("applies owner decisions only to the named entry", () => {
    const ledger = new HermesApprovalLedger();
    ledger.admit(ENTRY, CONNECTION, RECORD, HASH, 0);
    expect(ledger.ownerDeny("ffffffffffffffffffffffffffffffff").refusal).toBe("unknown_entry");
    expect(ledger.snapshot().entry?.state).toBe("PENDING");
  });

  it("derives admission deadlines from the clamped ledger clock", () => {
    const ledger = new HermesApprovalLedger();
    expect(ledger.admit("first", CONNECTION, "record-first", HASH, HERMES_RATE_WINDOW_MS).refusal).toBeUndefined();
    expect(ledger.ownerDeny("first").refusal).toBeUndefined();
    expect(ledger.admit("second", CONNECTION, "record-second", HASH, 0).refusal).toBeUndefined();
    expect(ledger.snapshot().entry?.deadlineAt).toBe(HERMES_RATE_WINDOW_MS + HERMES_APPROVAL_DEADLINE_MS);
  });
});

describe("Hermes approval commit decision", () => {
  it("resolves every decision arm before allowing a write", () => {
    expect(terminalAtSettle((ledger) => ledger.connectionGone(ENTRY), { probe: "refused" }).state).toBe("DISCONNECTED");
    expect(terminalAtSettle(() => undefined, { recordCurrent: false }).state).toBe("DISCONNECTED");
    expect(terminalAtSettle(() => undefined, { passageTextSha256: OTHER_HASH }).state).toBe("REFUSED");
    expect(terminalAtSettle(() => undefined, { getFrameUtf8Bytes: MAX_RESULT_FRAME_BYTES + 1 }).state).toBe("REFUSED");
    expect(terminalAtSettle(() => undefined, { getFrameUtf8Bytes: Number.NaN }).state).toBe("REFUSED");
    expect(terminalAtSettle(() => undefined, { getFrameUtf8Bytes: -1 }).state).toBe("REFUSED");
    expect(terminalAtSettle(() => undefined, { probe: "refused" }).state).toBe("REFUSED");
    expect(terminalAtSettle((ledger) => ledger.stop()).response).toBe("unavailable");
    expect(terminalAtSettle((ledger) => ledger.cancel(ENTRY)).state).toBe("CANCELED");
    expect(terminalAtSettle((ledger) => ledger.ownerDeny(ENTRY)).state).toBe("DENIED");
    expect(terminalAtSettle((ledger) => ledger.deadline(ENTRY)).state).toBe("TIMED_OUT");
    const ledger = runToStarted();
    const allowed = ledger.commitCheck(ENTRY, commitInput());
    expect(allowed).toEqual({ actions: [], decision: "allow" });
  });

  it("uses the earliest refusing arm for paired signals", () => {
    const pairs = [
      [(ledger: HermesApprovalLedger) => ledger.connectionGone(ENTRY), (ledger: HermesApprovalLedger) => ledger.cancel(ENTRY), "DISCONNECTED"],
      [(ledger: HermesApprovalLedger) => ledger.cancel(ENTRY), (ledger: HermesApprovalLedger) => ledger.ownerDeny(ENTRY), "CANCELED"],
      [(ledger: HermesApprovalLedger) => ledger.ownerDeny(ENTRY), (ledger: HermesApprovalLedger) => ledger.deadline(ENTRY), "DENIED"],
      [(ledger: HermesApprovalLedger) => ledger.deadline(ENTRY), (ledger: HermesApprovalLedger) => ledger.stop(), "REFUSED"],
    ] as const;
    for (const [first, second, state] of pairs) {
      const result = terminalAtSettle((ledger) => {
        first(ledger);
        second(ledger);
      });
      expect(result.state).toBe(state);
    }
  });

  it("clamps a backward clock before checking the deadline", () => {
    const ledger = runToStarted();
    expect(ledger.commitCheck(ENTRY, commitInput({ nowMs: HERMES_APPROVAL_DEADLINE_MS + 10 })).decision).toBe("refuse");
    const result = ledger.settled(ENTRY);
    expect(result.actions).toEqual([respondDenial]);
  });

  it("refuses the exact deadline boundary", () => {
    const ledger = runToStarted();
    const deadlineAt = ledger.snapshot().entry?.deadlineAt;
    expect(deadlineAt).toBeDefined();
    const result = ledger.commitCheck(ENTRY, commitInput({ nowMs: deadlineAt }));
    expect(result.decision).toBe("refuse");
    expect(result.actions).toEqual([terminalAudit("TIMED_OUT", "deadline")]);
  });

  it("settles started entries from each recorded signal", () => {
    const cases: readonly [
      flag: HermesApprovalLateEvent,
      apply: (ledger: HermesApprovalLedger) => void,
      actions: readonly HermesApprovalAction[],
    ][] = [
      ["gone", (ledger) => ledger.connectionGone(ENTRY), [terminalAudit("DISCONNECTED", "connection_gone")]],
      ["stop", (ledger) => ledger.stop(), [terminalAudit("REFUSED", "service_unavailable"), respondUnavailable]],
      ["latch", (ledger) => ledger.latch("audit_failed"), [terminalAudit("REFUSED", "audit_failed"), respondUnavailable]],
      ["cancel", (ledger) => ledger.cancel(ENTRY), [terminalAudit("CANCELED", "cancel"), respondDenial]],
      ["deny", (ledger) => ledger.ownerDeny(ENTRY), [terminalAudit("DENIED", "owner_denied"), respondDenial]],
      ["deadline", (ledger) => ledger.deadline(ENTRY), [terminalAudit("TIMED_OUT", "deadline"), respondDenial]],
    ];

    for (const [flag, apply, actions] of cases) {
      const ledger = runToStarted();
      apply(ledger);
      expect(ledger.snapshot().entry?.seen[flag]).toBe(true);
      expect(ledger.settled(ENTRY).actions).toEqual(actions);
      expect(ledger.snapshot().entry).toBeUndefined();
    }
  });

  it("does not mutate on a non-finite commit clock", () => {
    const ledger = runToStarted();
    const before = stable(normalizeSnapshot(ledger.snapshot()));
    const result = ledger.commitCheck(ENTRY, commitInput({ nowMs: Number.NaN }));
    expect(result).toEqual({ actions: [], fatal: "ledger_order", decision: "refuse" });
    expect(stable(normalizeSnapshot(ledger.snapshot()))).toBe(before);
  });

  it("answers started entries only when settled", () => {
    const ledger = runToStarted();
    const check = ledger.commitCheck(ENTRY, commitInput({ probe: "refused" }));
    expect(responseActions(check)).toHaveLength(0);
    const settled = ledger.settled(ENTRY);
    expect(responseActions(settled)).toEqual([respondDenial]);
  });

  it("records write completion without answering before settle", () => {
    const ledger = runToStarted();
    expect(ledger.commitCheck(ENTRY, commitInput()).decision).toBe("allow");
    const write = ledger.writeFinished(ENTRY, "committed");
    expect(write.actions).toEqual([terminalAudit("COMMITTED", "write_committed")]);
    const settled = ledger.settled(ENTRY);
    expect(responseActions(settled)).toEqual([respondSuccess]);
  });

  it("suppresses every answer after the connection is gone", () => {
    const cancelThenGone = runToStarted();
    expect(cancelThenGone.cancel(ENTRY).actions).toEqual([]);
    expect(cancelThenGone.commitCheck(ENTRY, commitInput()).decision).toBe("refuse");
    expect(cancelThenGone.connectionGone(ENTRY).actions).toEqual([]);
    expect(responseActions(cancelThenGone.settled(ENTRY))).toHaveLength(0);

    const writeThenGone = runToStarted();
    expect(writeThenGone.commitCheck(ENTRY, commitInput()).decision).toBe("allow");
    expect(writeThenGone.writeFinished(ENTRY, "committed").actions).toEqual([terminalAudit("COMMITTED", "write_committed")]);
    expect(writeThenGone.connectionGone(ENTRY).actions).toEqual([]);
    expect(responseActions(writeThenGone.settled(ENTRY))).toHaveLength(0);
  });

  it("answers a peer-shutdown record through the cancel signal", () => {
    const ledger = runToStarted();
    expect(ledger.peerShutdown(ENTRY).actions).toEqual([]);
    expect(ledger.commitCheck(ENTRY, commitInput({ recordCurrent: true })).actions).toEqual([
      terminalAudit("CANCELED", "cancel"),
    ]);
    expect(responseActions(ledger.settled(ENTRY))).toEqual([respondDenial]);
  });

  it("preserves the latch reason in the terminal audit", () => {
    const ledger = runToStarted();
    expect(ledger.latch("audit_failed").actions).toEqual([]);
    const check = ledger.commitCheck(ENTRY, commitInput());
    expect(check.actions).toEqual([terminalAudit("REFUSED", "audit_failed")]);
  });

  it("records indeterminate writes as unavailable and latches later admission", () => {
    const ledger = runToStarted();
    expect(ledger.commitCheck(ENTRY, commitInput()).decision).toBe("allow");
    expect(ledger.writeFinished(ENTRY, "indeterminate").actions).toEqual([
      terminalAudit("INDETERMINATE", "write_indeterminate"),
    ]);
    const settled = ledger.settled(ENTRY);
    expect(responseActions(settled)).toEqual([respondUnavailable]);
    expect(ledger.admit("next", CONNECTION, "record-next", HASH, 100).refusal).toBe("latched");
  });

  it("does not emit audit actions from repeated latch events", () => {
    const ledger = runToStarted();
    ledger.commitCheck(ENTRY, commitInput());
    expect(ledger.latch("first").actions).toEqual([]);
    expect(ledger.latch("second").actions).toEqual([]);
  });
});

describe("Hermes approval ledger differential schedules", () => {
  it("matches an independent approval model over seeded schedules", () => {
    const coverage = {
      terminal: new Set<HermesApprovalTerminalState>(),
      refusals: new Set<HermesApprovalRefusalReason>(),
      allows: 0,
      fatals: 0,
      auditFailures: 0,
      backwardClockSteps: 0,
      steps: 0,
    };
    const failures: string[] = [];

    for (let schedule = 0; schedule < DIFFERENTIAL_SCHEDULES; schedule += 1) {
      const random = rng(DIFFERENTIAL_SEED + schedule);
      const real = new HermesApprovalLedger();
      const model = new ApprovalLedgerModel(HERMES_APPROVAL_DEADLINE_MS, MAX_RESULT_FRAME_BYTES);
      const pendingAudits: { readonly entryId: string; readonly failAt: number; readonly fails: boolean }[] = [];
      let clock = Math.floor(random() * 1_000);
      let idCounter = 0;
      let currentTask: "none" | "start" | "precheck" | "write" | "settle" = "none";
      let taskAt = 0;
      let currentGone = false;
      let currentNodeClosed = false;
      let currentStopped = false;

      const step = (
        label: string,
        realRun: () => HermesApprovalLedgerResult,
        modelRun: () => HermesApprovalLedgerResult,
        expectNoChange = false,
      ): HermesApprovalLedgerResult => {
        coverage.steps += 1;
        const before = stable(normalizeSnapshot(real.snapshot()));
        const realResult = realRun();
        const modelResult = modelRun();
        const after = stable(normalizeSnapshot(real.snapshot()));
        expect(realResult, `${label} result schedule ${schedule}`).toEqual(modelResult);
        expect(normalizeSnapshot(real.snapshot()), `${label} snapshot schedule ${schedule}`).toEqual(normalizeSnapshot(model.snapshot()));
        if (expectNoChange) {
          expect(after, `${label} changed state schedule ${schedule}`).toBe(before);
          expect(realResult.actions, `${label} emitted schedule ${schedule}`).toEqual([]);
        }
        if (realResult.fatal !== undefined) {
          coverage.fatals += 1;
          expect(after, `${label} fatal changed state schedule ${schedule}`).toBe(before);
          expect(realResult.actions, `${label} fatal emitted schedule ${schedule}`).toEqual([]);
        }
        if (label === "admit" && realResult.refusal !== undefined) coverage.refusals.add(realResult.refusal);
        if (realResult.decision === "allow") coverage.allows += 1;
        for (const action of realResult.actions) {
          if (action.kind === "audit") {
            pendingAudits.push({ entryId: action.entryId, failAt: clock + Math.floor(random() * 3), fails: random() < 0.04 });
            if (action.event === "terminal" && action.state !== undefined) coverage.terminal.add(action.state);
          }
        }
        if (label === "latch") coverage.auditFailures += 1;
        const snapshot = real.snapshot();
        expect(snapshot.entry === undefined ? 0 : 1).toBeLessThanOrEqual(1);
        return realResult;
      };

      const freshId = (): string => {
        idCounter += 1;
        return `${schedule.toString(16).padStart(8, "0")}${idCounter.toString(16).padStart(8, "0")}aaaaaaaaaaaaaaaa`;
      };

      const activeId = (): string | undefined => real.snapshot().entry?.id;
      const activeHash = (): string => `hash-${activeId() ?? "none"}`;
      const admit = (): void => {
        const id = freshId();
        const hash = `hash-${id}`;
        const result = step(
          "admit",
          () => real.admit(id, CONNECTION, `record-${id}`, hash, clock),
          () => model.admit(id, CONNECTION, `record-${id}`, hash, clock),
        );
        if (result.refusal === undefined) {
          currentTask = "none";
          currentGone = false;
          currentNodeClosed = false;
          currentStopped = false;
        }
      };
      const admitWithClock = (nowMs: number): void => {
        const id = freshId();
        const hash = `hash-${id}`;
        step(
          "admit",
          () => real.admit(id, CONNECTION, `record-${id}`, hash, nowMs),
          () => model.admit(id, CONNECTION, `record-${id}`, hash, nowMs),
        );
      };
      const latch = (reason: string): void => {
        step("latch", () => real.latch(reason), () => model.latch(reason));
      };

      const ticks = 24 + Math.floor(random() * 48);
      for (let tick = 0; tick < ticks + 240; tick += 1) {
        const draining = tick >= ticks;
        const clockChoice = random();
        let delta: number;
        if (clockChoice < 0.05) {
          delta = -Math.floor(random() * 20_000);
          coverage.backwardClockSteps += 1;
        } else if (clockChoice < 0.14) {
          delta = HERMES_APPROVAL_DEADLINE_MS + Math.floor(random() * 2_000) - 1_000;
        } else {
          delta = Math.floor(random() * (draining ? 8_000 : 2_000));
        }
        clock += draining ? Math.abs(delta) + 2_000 : delta;

        for (let index = pendingAudits.length - 1; index >= 0; index -= 1) {
          const pending = pendingAudits[index]!;
          if (pending.failAt <= clock) {
            pendingAudits.splice(index, 1);
            if (pending.fails) latch("audit_failed");
          }
        }

        const entry = real.snapshot().entry;
        if (!entry) {
          if (!draining && random() < 0.03) admitWithClock(Number.NaN);
          if (!draining && random() < 0.45) admit();
          if (draining && pendingAudits.length === 0) break;
          continue;
        }

        const id = entry.id;
        if (!draining && random() < 0.04) admitWithClock(clock);
        if (entry.state === "PENDING" && random() < (draining ? 0.8 : 0.35)) {
          const choice = random();
          if (choice < 0.6) {
            const result = step("ownerApprove", () => real.ownerApprove(id, entry.textSha256), () => model.ownerApprove(id, entry.textSha256));
            if (result.refusal === undefined) {
              currentTask = "start";
              taskAt = tick + Math.floor(random() * 3);
            }
          } else if (choice < 0.75) {
            step("ownerApproveWrong", () => real.ownerApprove(id, OTHER_HASH), () => model.ownerApprove(id, OTHER_HASH));
          } else {
            step("ownerDeny", () => real.ownerDeny(id), () => model.ownerDeny(id));
          }
        }

        const afterOwner = real.snapshot().entry;
        if (afterOwner && !draining) {
          if (random() < 0.05) step("cancel", () => real.cancel(id), () => model.cancel(id));
          if (random() < 0.03) step("peerShutdown", () => real.peerShutdown(id), () => model.peerShutdown(id));
          if (random() < 0.04) {
            currentGone = true;
            step("connectionGone", () => real.connectionGone(id), () => model.connectionGone(id));
          }
          if (random() < 0.015) {
            currentStopped = true;
            step("stop", () => real.stop(), () => model.stop());
          }
          if (random() < 0.018) latch("partial_scope");
          if (clock >= afterOwner.deadlineAt && random() < 0.5) {
            step("deadline", () => real.deadline(id), () => model.deadline(id));
          }
        }

        const wrongId = freshId();
        if (!draining && random() < 0.03) {
          step("wrongCancel", () => real.cancel(wrongId), () => model.cancel(wrongId), true);
          step("wrongGone", () => real.connectionGone(wrongId), () => model.connectionGone(wrongId), true);
        }

        const taskEntry = real.snapshot().entry;
        if (taskEntry?.id !== id) continue;
        if (currentTask === "start" && tick >= taskAt) {
          const result = step("insertStarted", () => real.insertStarted(id), () => model.insertStarted(id));
          if (result.refusal === undefined && result.fatal === undefined) {
            currentTask = "precheck";
            taskAt = tick + Math.floor(random() * 3);
          } else {
            currentTask = "none";
          }
        } else if (currentTask === "precheck" && tick >= taskAt) {
          for (let index = pendingAudits.length - 1; index >= 0; index -= 1) {
            const pending = pendingAudits[index]!;
            if (pending.entryId === id) {
              pendingAudits.splice(index, 1);
              if (pending.fails) latch("audit_failed");
            }
          }
          if (random() < 0.04) latch("audit_failed");
          const snapshot = real.snapshot().entry;
          if (snapshot?.id !== id || snapshot.state !== "APPROVED" || !snapshot.started) continue;
          const clockRoll = random();
          const nowMs = clockRoll < 0.08
            ? Number.NaN
            : clockRoll < 0.16
              ? snapshot.deadlineAt
              : clockRoll < 0.22
                ? snapshot.deadlineAt - 1
                : clock;
          const frameRoll = random();
          const frameSize = frameRoll < 0.03
            ? Number.NaN
            : frameRoll < 0.06
              ? -1
              : frameRoll < 0.11
                ? MAX_RESULT_FRAME_BYTES + 1
                : Math.floor(random() * MAX_RESULT_FRAME_BYTES);
          const input = commitInput({
            probe: currentGone || currentNodeClosed || currentStopped || random() < 0.04 ? "refused" : "resolved",
            nowMs,
            recordCurrent: !(currentGone || currentNodeClosed || currentStopped),
            passageTextSha256: random() < 0.04 ? OTHER_HASH : activeHash(),
            getFrameUtf8Bytes: frameSize,
          });
          const result = step("commitCheck", () => real.commitCheck(id, input), () => model.commitCheck(id, input));
          currentTask = result.decision === "allow" ? "write" : "settle";
          taskAt = tick + Math.floor(random() * 3);
        } else if (currentTask === "write" && tick >= taskAt) {
          if (random() < 0.1) {
            currentGone = true;
            step("connectionGone", () => real.connectionGone(id), () => model.connectionGone(id));
          }
          const outcomes: readonly HermesApprovalWriteOutcome[] = ["committed", "failed", "indeterminate"];
          const outcome = outcomes[Math.floor(random() * outcomes.length)] ?? "failed";
          step("writeFinished", () => real.writeFinished(id, outcome), () => model.writeFinished(id, outcome));
          currentTask = "settle";
          taskAt = tick + Math.floor(random() * 3);
        } else if (currentTask === "settle" && tick >= taskAt) {
          step("settled", () => real.settled(id), () => model.settled(id));
          currentTask = "none";
        }

        const remaining = real.snapshot().entry;
        if (draining && remaining?.state === "PENDING") {
          step("deadline", () => real.deadline(remaining.id), () => model.deadline(remaining.id));
        } else if (draining && remaining?.state !== undefined && TERMINAL_STATES.has(remaining.state as HermesApprovalTerminalState)) {
          step("settled", () => real.settled(remaining.id), () => model.settled(remaining.id));
        }
      }

      if (real.snapshot().entry !== undefined) failures.push(`schedule ${schedule} left ${stable(real.snapshot().entry)}`);
    }

    expect(failures).toEqual([]);
    expect(coverage.terminal).toEqual(new Set(["COMMITTED", "DENIED", "CANCELED", "TIMED_OUT", "DISCONNECTED", "REFUSED", "INDETERMINATE"]));
    expect(coverage.refusals).toEqual(new Set(["stopped", "latched", "busy", "invalid_clock", "prompt_rate"]));
    expect(coverage.allows).toBeGreaterThan(0);
    expect(coverage.fatals).toBeGreaterThan(0);
    expect(coverage.auditFailures).toBeGreaterThan(0);
    expect(coverage.backwardClockSteps).toBeGreaterThan(0);
    console.info(
      `approval-ledger-differential schedules=${DIFFERENTIAL_SCHEDULES} steps=${coverage.steps} ` +
        `allows=${coverage.allows} fatals=${coverage.fatals} auditFailures=${coverage.auditFailures} ` +
        `backwardClockSteps=${coverage.backwardClockSteps}`,
    );
  });
});

describe("Hermes approval response messages", () => {
  it("uses fixed message classes only for denied and unavailable responses", () => {
    const denied = new HermesApprovalLedger();
    denied.admit(ENTRY, CONNECTION, RECORD, HASH, 0);
    const deniedResponse = responseActions(denied.ownerDeny(ENTRY))[0];
    expect(deniedResponse).toEqual(respondDenial);

    const unavailable = new HermesApprovalLedger();
    unavailable.admit(ENTRY, CONNECTION, RECORD, HASH, 0);
    const unavailableResponse = responseActions(unavailable.stop())[0];
    expect(unavailableResponse).toEqual(respondUnavailable);

    const success = runToStarted();
    expect(success.commitCheck(ENTRY, commitInput()).decision).toBe("allow");
    success.writeFinished(ENTRY, "committed");
    expect(responseActions(success.settled(ENTRY))).toEqual([respondSuccess]);
  });
});

const TERMINAL_STATES = new Set<HermesApprovalEntryState>([
  "COMMITTED",
  "DENIED",
  "CANCELED",
  "TIMED_OUT",
  "DISCONNECTED",
  "REFUSED",
  "INDETERMINATE",
]);
