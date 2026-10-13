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
  type HermesApprovalResponseClass,
  type HermesApprovalTerminalState,
  type HermesApprovalWriteOutcome,
} from "../../src/hermes-memory-bridge/index.js";
import { MEMORY_BATCH_LOCK_TIMEOUT_MS } from "../../src/sdw/adapters/sdw-memory-backend.js";

type HermesApprovalRespondAction = Extract<HermesApprovalAction, { readonly kind: "respond" }>;

const HASH = "body-digest";
const OTHER_HASH = "other-digest";
const ENTRY = "00112233445566778899aabbccddeeff";
const CONNECTION = "c1";
const RECORD = "record-1";
const FUZZ_SCHEDULES = 3_200;
const FUZZ_SEED = 0x2a1_0004;

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
  readonly actions: readonly string[];
  readonly refusal?: string;
  readonly fatal?: string;
  readonly decision?: string;
  readonly responded?: boolean;
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

const CELL_TABLE: Record<SetupState, Record<CellEvent, CellExpectation>> = {
  PENDING: {
    approve_matching: { state: "APPROVED", actions: ["audit:approved"] },
    approve_different: { state: "PENDING", actions: [], refusal: "hash_mismatch" },
    deny: { deleted: true, actions: ["respond:denial", "audit:DENIED"], responded: true },
    deadline: { deleted: true, actions: ["respond:denial", "audit:TIMED_OUT"], responded: true },
    cancel: { deleted: true, actions: ["respond:denial", "audit:CANCELED"], responded: true },
    peer_shutdown: { deleted: true, actions: ["respond:denial", "audit:CANCELED"], responded: true },
    connection_gone: { deleted: true, actions: ["audit:DISCONNECTED"] },
    stop: { deleted: true, actions: ["respond:unavailable", "audit:REFUSED"], responded: true },
    latch: { deleted: true, actions: ["respond:unavailable", "audit:REFUSED"], responded: true },
    insert_started: { state: "PENDING", actions: [], refusal: "not_approved" },
    commit_check: { state: "PENDING", actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { state: "PENDING", actions: [], fatal: "ledger_order" },
    settled: { state: "PENDING", actions: [], fatal: "ledger_order" },
  },
  APPROVED_NOT_STARTED: {
    approve_matching: { state: "APPROVED", actions: [], refusal: "not_pending" },
    approve_different: { state: "APPROVED", actions: [], refusal: "not_pending" },
    deny: { deleted: true, actions: ["respond:denial", "audit:DENIED"], responded: true },
    deadline: { deleted: true, actions: ["respond:denial", "audit:TIMED_OUT"], responded: true },
    cancel: { deleted: true, actions: ["respond:denial", "audit:CANCELED"], responded: true },
    peer_shutdown: { deleted: true, actions: ["respond:denial", "audit:CANCELED"], responded: true },
    connection_gone: { deleted: true, actions: ["audit:DISCONNECTED"] },
    stop: { deleted: true, actions: ["respond:unavailable", "audit:REFUSED"], responded: true },
    latch: { deleted: true, actions: ["respond:unavailable", "audit:REFUSED"], responded: true },
    insert_started: { state: "APPROVED", actions: [] },
    commit_check: { state: "APPROVED", actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { state: "APPROVED", actions: [], fatal: "ledger_order" },
    settled: { state: "APPROVED", actions: [], fatal: "ledger_order" },
  },
  APPROVED_STARTED: {
    approve_matching: { state: "APPROVED", actions: [], refusal: "not_pending" },
    approve_different: { state: "APPROVED", actions: [], refusal: "not_pending" },
    deny: { state: "APPROVED", actions: [] },
    deadline: { state: "APPROVED", actions: [] },
    cancel: { state: "APPROVED", actions: [] },
    peer_shutdown: { state: "APPROVED", actions: [] },
    connection_gone: { state: "APPROVED", actions: [] },
    stop: { state: "APPROVED", actions: [] },
    latch: { state: "APPROVED", actions: [] },
    insert_started: { state: "APPROVED", actions: [], fatal: "ledger_order" },
    commit_check: { state: "COMMITTING", actions: [], decision: "allow" },
    write_finished: { state: "APPROVED", actions: [], fatal: "ledger_order" },
    settled: { deleted: true, actions: ["respond:denial", "audit:REFUSED"], responded: true },
  },
  COMMITTING: {
    approve_matching: { state: "COMMITTING", actions: [], refusal: "not_pending" },
    approve_different: { state: "COMMITTING", actions: [], refusal: "not_pending" },
    deny: { state: "COMMITTING", actions: [] },
    deadline: { state: "COMMITTING", actions: [] },
    cancel: { state: "COMMITTING", actions: [] },
    peer_shutdown: { state: "COMMITTING", actions: [] },
    connection_gone: { state: "COMMITTING", actions: [] },
    stop: { state: "COMMITTING", actions: [] },
    latch: { state: "COMMITTING", actions: [] },
    insert_started: { state: "COMMITTING", actions: [], fatal: "ledger_order" },
    commit_check: { state: "COMMITTING", actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { state: "COMMITTED", actions: ["audit:COMMITTED"] },
    settled: { state: "COMMITTING", actions: [], fatal: "ledger_order" },
  },
  TERMINAL_NOT_SETTLED: {
    approve_matching: { state: "REFUSED", actions: [], refusal: "not_pending" },
    approve_different: { state: "REFUSED", actions: [], refusal: "not_pending" },
    deny: { state: "REFUSED", actions: [], refusal: "not_pending" },
    deadline: { state: "REFUSED", actions: [] },
    cancel: { state: "REFUSED", actions: [] },
    peer_shutdown: { state: "REFUSED", actions: [] },
    connection_gone: { state: "REFUSED", actions: [] },
    stop: { state: "REFUSED", actions: [] },
    latch: { state: "REFUSED", actions: [] },
    insert_started: { state: "REFUSED", actions: [], fatal: "ledger_order" },
    commit_check: { state: "REFUSED", actions: [], fatal: "ledger_order", decision: "refuse" },
    write_finished: { state: "REFUSED", actions: [], fatal: "ledger_order" },
    settled: { deleted: true, actions: ["respond:denial"], responded: true },
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

function actionNames(actions: readonly HermesApprovalAction[]): readonly string[] {
  return actions.map((action) => {
    if (action.kind === "audit") return `audit:${action.event === "terminal" ? action.state : action.event}`;
    if (action.kind === "respond") return `respond:${action.response}`;
    return action.kind;
  });
}

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
  expect(ledger.writeFinished(ENTRY, "failed").actions.map((action) => action.kind)).toEqual(["audit"]);
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
  expect(actionNames(result.actions)).toEqual(expected.actions);
  expect(result.refusal).toBe(expected.refusal);
  expect(result.fatal).toBe(expected.fatal);
  expect(result.decision).toBe(expected.decision);
  const entry = ledger.snapshot().entry;
  if (expected.deleted === true) {
    expect(entry).toBeUndefined();
  } else {
    expect(entry?.state).toBe(expected.state);
    if (expected.responded !== undefined) expect(entry?.responded).toBe(expected.responded);
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
  const result = ledger.settled(ENTRY);
  const audit = check.actions.find((action) => action.kind === "audit" && action.event === "terminal");
  if (audit?.kind !== "audit" || audit.state === undefined) throw new Error("missing terminal audit");
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
    value = (value * 1_664_525 + 1_013_904_223) >>> 0;
    return value / 4_294_967_296;
  };
}

function assertLedgerInvariants(ledger: HermesApprovalLedger, responses: readonly HermesApprovalResponseClass[]): void {
  const snapshot = ledger.snapshot();
  expect(snapshot.entry === undefined ? 0 : 1).toBeLessThanOrEqual(1);
  expect(responses.length).toBeLessThanOrEqual(1);
  if (snapshot.entry?.seen.gone === true || snapshot.entry?.state === "DISCONNECTED") {
    expect(responses).toHaveLength(0);
  }
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
    for (let index = 0; index < 1_000_000; index += 1) {
      window.admit(index);
    }
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
    (state, event) => {
      expectCell(state, event);
    },
  );

  it("applies admission checks without mutating refused entries", () => {
    const stopped = new HermesApprovalLedger();
    stopped.stop();
    expect(stopped.admit("a", CONNECTION, RECORD, HASH, 0).refusal).toBe("stopped");

    const latched = new HermesApprovalLedger();
    latched.latch("audit_failed");
    expect(latched.admit("a", CONNECTION, RECORD, HASH, 0).refusal).toBe("latched");

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
});

describe("Hermes approval commit decision", () => {
  it("resolves every decision arm before allowing a write", () => {
    expect(terminalAtSettle((ledger) => ledger.connectionGone(ENTRY), { probe: "refused" }).state).toBe("DISCONNECTED");
    expect(terminalAtSettle(() => undefined, { recordCurrent: false }).state).toBe("DISCONNECTED");
    expect(terminalAtSettle(() => undefined, { passageTextSha256: OTHER_HASH }).state).toBe("REFUSED");
    expect(terminalAtSettle(() => undefined, { getFrameUtf8Bytes: MAX_RESULT_FRAME_BYTES + 1 }).state).toBe("REFUSED");
    expect(terminalAtSettle(() => undefined, { probe: "refused" }).state).toBe("REFUSED");
    expect(terminalAtSettle((ledger) => ledger.stop()).response).toBe("unavailable");
    expect(terminalAtSettle((ledger) => ledger.cancel(ENTRY)).state).toBe("CANCELED");
    expect(terminalAtSettle((ledger) => ledger.ownerDeny(ENTRY)).state).toBe("DENIED");
    expect(terminalAtSettle((ledger) => ledger.deadline(ENTRY)).state).toBe("TIMED_OUT");
    const ledger = runToStarted();
    const allowed = ledger.commitCheck(ENTRY, commitInput());
    expect(allowed.decision).toBe("allow");
    expect(allowed.actions).toEqual([]);
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
    ledger.commitCheck(ENTRY, commitInput({ nowMs: HERMES_APPROVAL_DEADLINE_MS + 10 }));
    const result = ledger.settled(ENTRY);
    expect(actionNames(result.actions)).toEqual(["respond:denial"]);
  });

  it("answers started entries only when settled", () => {
    const ledger = runToStarted();
    const check = ledger.commitCheck(ENTRY, commitInput({ probe: "refused" }));
    expect(responseActions(check)).toHaveLength(0);
    const settled = ledger.settled(ENTRY);
    expect(responseActions(settled)).toHaveLength(1);
  });

  it("records write completion without answering before settle", () => {
    const ledger = runToStarted();
    expect(ledger.commitCheck(ENTRY, commitInput()).decision).toBe("allow");
    const write = ledger.writeFinished(ENTRY, "committed");
    expect(responseActions(write)).toHaveLength(0);
    const settled = ledger.settled(ENTRY);
    expect(responseActions(settled)).toHaveLength(1);
  });

  it("suppresses every answer after the connection is gone", () => {
    for (const prepare of [
      (ledger: HermesApprovalLedger) => ledger.connectionGone(ENTRY),
      (ledger: HermesApprovalLedger) => {
        ledger.commitCheck(ENTRY, commitInput());
        ledger.connectionGone(ENTRY);
        ledger.writeFinished(ENTRY, "committed");
      },
    ]) {
      const ledger = runToStarted();
      prepare(ledger);
      const result = ledger.snapshot().entry?.state === "COMMITTING"
        ? ledger.writeFinished(ENTRY, "committed")
        : ledger.commitCheck(ENTRY, commitInput({ probe: "refused" }));
      expect(responseActions(result)).toHaveLength(0);
      expect(responseActions(ledger.settled(ENTRY))).toHaveLength(0);
    }
  });

  it("records indeterminate writes as unavailable and latches later admission", () => {
    const ledger = runToStarted();
    expect(ledger.commitCheck(ENTRY, commitInput()).decision).toBe("allow");
    expect(actionNames(ledger.writeFinished(ENTRY, "indeterminate").actions)).toEqual(["audit:INDETERMINATE"]);
    const settled = ledger.settled(ENTRY);
    expect(responseActions(settled)[0]).toMatchObject({ response: "unavailable", message: HERMES_MEMORY_UNAVAILABLE });
    expect(ledger.admit("next", CONNECTION, "record-next", HASH, 100).refusal).toBe("latched");
  });

  it("does not emit audit actions from repeated latch events", () => {
    const ledger = runToStarted();
    ledger.commitCheck(ENTRY, commitInput());
    expect(ledger.latch("first").actions).toEqual([]);
    expect(ledger.latch("second").actions).toEqual([]);
  });
});

describe("Hermes approval schedule fuzz", () => {
  it("keeps the ledger bounded and responsive over seeded schedules", () => {
    const terminals = new Set<HermesApprovalTerminalState>();
    const admissionRefusals = new Set<string>();
    let auditFailureFeedback = 0;
    let directInvariantChecks = 0;
    for (let schedule = 0; schedule < FUZZ_SCHEDULES; schedule += 1) {
      const random = rng(FUZZ_SEED + schedule);
      const ledger = new HermesApprovalLedger();
      const responses: HermesApprovalResponseClass[] = [];
      const id = `entry-${schedule}`;
      const admitted = ledger.admit(id, CONNECTION, `record-${schedule}`, HASH, schedule * (HERMES_RATE_WINDOW_MS + 1));
      if (admitted.refusal !== undefined) {
        admissionRefusals.add(admitted.refusal);
        continue;
      }
      if (random() < 0.9) ledger.ownerApprove(id, HASH);
      else ledger.ownerApprove(id, OTHER_HASH);
      if (ledger.snapshot().entry?.state === "APPROVED" && random() < 0.85) ledger.insertStarted(id);
      const beforeCheckEvents = [
        () => ledger.ownerDeny(id),
        () => ledger.deadline(id),
        () => ledger.cancel(id),
        () => ledger.peerShutdown(id),
        () => ledger.connectionGone(id),
        () => ledger.stop(),
        () => ledger.latch("audit_failed"),
      ];
      for (const event of beforeCheckEvents) {
        if (random() < 0.18) event();
      }
      if (random() < 0.12) {
        auditFailureFeedback += 1;
        ledger.latch("audit_failed");
      }
      const entry = ledger.snapshot().entry;
      if (entry?.state === "APPROVED" && entry.started) {
        const check = ledger.commitCheck(id, commitInput({
          probe: random() < 0.14 ? "refused" : "resolved",
          recordCurrent: random() >= 0.08,
          passageTextSha256: random() < 0.08 ? OTHER_HASH : HASH,
          getFrameUtf8Bytes: random() < 0.08 ? MAX_RESULT_FRAME_BYTES + 1 : MAX_RESULT_FRAME_BYTES,
          nowMs: random() < 0.12 ? entry.deadlineAt + 1 : entry.deadlineAt - 1,
        }));
        for (const action of responseActions(check)) responses.push(action.response);
        if (check.decision === "allow") {
          if (random() < 0.25) ledger.connectionGone(id);
          const outcomes: readonly HermesApprovalWriteOutcome[] = ["committed", "failed", "indeterminate"];
          const write = ledger.writeFinished(id, outcomes[Math.floor(random() * outcomes.length)] ?? "failed");
          for (const action of responseActions(write)) responses.push(action.response);
        }
      }
      const current = ledger.snapshot().entry;
      if (current !== undefined && current.state !== "PENDING" && current.state !== "APPROVED" && current.state !== "COMMITTING") {
        terminals.add(current.state);
      }
      if (ledger.snapshot().entry !== undefined) {
        const beforeSettle = ledger.snapshot().entry;
        if (beforeSettle?.state === "APPROVED" && !beforeSettle.started) {
          const canceled = ledger.cancel(id);
          for (const action of responseActions(canceled)) responses.push(action.response);
        }
        if (beforeSettle?.state === "PENDING") {
          const timedOut = ledger.deadline(id);
          for (const action of responseActions(timedOut)) responses.push(action.response);
        }
        const settled = ledger.settled(id);
        for (const action of responseActions(settled)) responses.push(action.response);
      }
      assertLedgerInvariants(ledger, responses);
      expect(ledger.snapshot().entry).toBeUndefined();
      directInvariantChecks += 1;
    }

    for (const refusal of ["stopped", "latched", "busy", "prompt_rate"]) {
      const ledger = new HermesApprovalLedger();
      if (refusal === "stopped") ledger.stop();
      if (refusal === "latched") ledger.latch("audit_failed");
      if (refusal === "busy") ledger.admit("busy", CONNECTION, RECORD, HASH, 0);
      if (refusal === "prompt_rate") {
        for (let index = 0; index < HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE; index += 1) {
          ledger.admit(`rate-${index}`, CONNECTION, `record-${index}`, HASH, index);
          ledger.ownerDeny(`rate-${index}`);
        }
      }
      const result = ledger.admit(`refusal-${refusal}`, CONNECTION, `record-${refusal}`, HASH, 1);
      if (result.refusal !== undefined) admissionRefusals.add(result.refusal);
    }

    expect(terminals).toEqual(new Set(["COMMITTED", "DENIED", "CANCELED", "TIMED_OUT", "DISCONNECTED", "REFUSED", "INDETERMINATE"]));
    expect(admissionRefusals).toEqual(new Set(["stopped", "latched", "busy", "prompt_rate"]));
    expect(auditFailureFeedback).toBeGreaterThan(0);
    expect(directInvariantChecks).toBe(FUZZ_SCHEDULES);
  });
});

describe("Hermes approval response messages", () => {
  it("uses fixed message classes for denied and unavailable responses", () => {
    const denied = new HermesApprovalLedger();
    denied.admit(ENTRY, CONNECTION, RECORD, HASH, 0);
    const deniedResponse = responseActions(denied.ownerDeny(ENTRY))[0];
    expect(deniedResponse).toMatchObject({ response: "denial", message: HERMES_MEMORY_DENIAL });

    const unavailable = new HermesApprovalLedger();
    unavailable.admit(ENTRY, CONNECTION, RECORD, HASH, 0);
    const unavailableResponse = responseActions(unavailable.stop())[0];
    expect(unavailableResponse).toMatchObject({ response: "unavailable", message: HERMES_MEMORY_UNAVAILABLE });
  });
});
