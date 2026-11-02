import { constants as osConstants } from "node:os";
import { describe, expect, it } from "vitest";
import {
  classifyFullSupervisionExit, FULL_SUPERVISION_DEFAULT_CODES,
  type FullSupervisionExitInput, type FullSupervisionCodeTable,
} from "../../../src/castle-wall/runtime/full-supervision-exit.js";
import { input, RESTART_FIXTURE_CODE } from "../../fixtures/full-supervision/support.js";

const table: FullSupervisionCodeTable = {
  restartable: [RESTART_FIXTURE_CODE], terminal: [{ code: 2, reason: "parse_refusal" }],
  retryable: [{ code: 3, reason: "fixture_helper_unreachable" }], // Test-only distinct helper code.
};
const attemptId = "attempt";
const signals = [...new Set([...Object.keys(osConstants.signals), "SIGINFO", "SIGEMT", "SIGLOST"])] as NodeJS.Signals[];
const exits: FullSupervisionExitInput["exit"][] = [
  ...Array.from({ length: 256 }, (_, code) => ({ code })), // All unsigned-byte process exit statuses.
  ...[-1, NaN, Infinity].map((code) => ({ code })), // Non-status numbers still classify conservatively.
  ...signals.map((signal) => ({ signal })),
];
const intents: FullSupervisionExitInput["stopIntent"][] = [
  { kind: "none" }, ...(["operator", "lifecycle"] as const).flatMap((kind) => [
    { kind, attemptId }, { kind, attemptId: "other" },
  ]),
];
const completions: FullSupervisionExitInput["completion"][] = [undefined,
  ...(["ok", "failed"] as const).flatMap((cleanup) => [{ attemptId, cleanup }, { attemptId: "other", cleanup }]),
];

describe("full supervision exit evidence", () => {
  it("is total across the exit, intent, readiness and completion product", () => {
    let examined = 0;
    for (const exit of exits) for (const stopIntent of intents) for (const readinessCommitted of [false, true]) for (const completion of completions) {
      const value = input(attemptId, { exit, stopIntent, readinessCommitted, completion });
      const decision = classifyFullSupervisionExit(value, table);
      const matched = stopIntent.kind !== "none" && stopIntent.attemptId === attemptId;
      const stopShape = "code" in exit ? [0, 128 + 15].includes(exit.code)
        : exit.signal === "SIGTERM" || (exit.signal === "SIGKILL" && stopIntent.kind === "lifecycle");
      let expected: string;
      const matchedOk = completion?.attemptId === attemptId && completion.cleanup === "ok";
      const matchedFailed = completion?.attemptId === attemptId && completion.cleanup === "failed";
      if ("code" in exit && !stopShape && exit.code === 2) expected = "terminal";
      else if (matched) expected = stopShape && ("code" in exit ? matchedOk : !matchedFailed) ? "uncharged_stop" : "charged_unverified_exit";
      else if ("code" in exit && exit.code === 0) expected = completion?.attemptId === attemptId && completion.cleanup === "ok" ? "uncharged_clean" : "charged_unverified_exit";
      else if ("code" in exit && exit.code === 2) expected = "terminal";
      else if ("code" in exit && [3, RESTART_FIXTURE_CODE].includes(exit.code)) expected = "charged_restart";
      else expected = "charged_unverified_exit";
      expect(decision.kind, JSON.stringify(value)).toBe(expected);
      expect(decision.decidedBy).toBe(value);
      if (decision.kind === "terminal") expect(decision.reason).toBe("parse_refusal");
      examined++;
    }
    expect(examined).toBe(exits.length * intents.length * 2 * completions.length);
  });
  it("does not charge a clean matched stop", () => {
    expect(classifyFullSupervisionExit(input(attemptId, { exit: { signal: "SIGTERM" }, readinessCommitted: true, stopIntent: { kind: "operator", attemptId } })).kind).toBe("uncharged_stop");
  });
  it("does not charge an operator stop during startup", () => {
    expect(classifyFullSupervisionExit(input(attemptId, { exit: { signal: "SIGTERM" }, readinessCommitted: false, stopIntent: { kind: "operator", attemptId } })).kind).toBe("uncharged_stop");
  });
  it("charges zero without matching ok completion", () => {
    for (const completion of [undefined, { attemptId: "other", cleanup: "ok" as const }, { attemptId, cleanup: "failed" as const }]) {
      expect(classifyFullSupervisionExit(input(attemptId, { exit: { code: 0 }, completion })).kind).toBe("charged_unverified_exit");
    }
  });
  it("never hides a crash behind a stop request or a completion", () => {
    for (const kind of ["operator", "lifecycle"] as const) {
      expect(classifyFullSupervisionExit(input(attemptId, { exit: { signal: "SIGSEGV" }, stopIntent: { kind, attemptId }, completion: { attemptId, cleanup: "ok" } })).kind).toBe("charged_unverified_exit");
    }
  });
  it("uses only ruled base codes and retries an injected helper failure", () => {
    expect(FULL_SUPERVISION_DEFAULT_CODES).toEqual({ restartable: [], terminal: [{ code: 2, reason: "parse_refusal" }], retryable: [] });
    expect(classifyFullSupervisionExit(input(attemptId, { exit: { code: 1 } })).kind).toBe("charged_unverified_exit");
    expect(classifyFullSupervisionExit(input(attemptId, { exit: { code: 3 } }), table)).toMatchObject({ kind: "charged_restart", reason: "fixture_helper_unreachable" });
  });
});

for (const kind of ["operator", "lifecycle"] as const) {
  for (const code of [0, 128 + 15]) { // Zero or POSIX SIGTERM shell status.
    it.each([
      ["absent", undefined],
      ["mismatched ok", { attemptId: "other", cleanup: "ok" }],
      ["mismatched failed", { attemptId: "other", cleanup: "failed" }],
      ["matched failed", { attemptId, cleanup: "failed" }],
    ] as const)(`${kind} code ${code} charges %s completion and exempts matched ok`, (_label, completion) => {
      const value = input(attemptId, { exit: { code }, stopIntent: { kind, attemptId }, completion });
      expect(classifyFullSupervisionExit(value)).toMatchObject({ kind: "charged_unverified_exit", decidedBy: value });
      expect(classifyFullSupervisionExit({ ...value, completion: { attemptId, cleanup: "ok" } }).kind).toBe("uncharged_stop");
    });
  }
  for (const signal of (kind === "operator" ? ["SIGTERM"] : ["SIGTERM", "SIGKILL"]) as NodeJS.Signals[]) {
    it(`${kind} ${signal} charges failed cleanup but permits startup without a completion`, () => {
      const value = input(attemptId, { exit: { signal }, stopIntent: { kind, attemptId }, completion: { attemptId, cleanup: "failed" } });
      expect(classifyFullSupervisionExit(value).kind).toBe("charged_unverified_exit");
      for (const completion of [undefined, { attemptId, cleanup: "ok" as const }, { attemptId: "other", cleanup: "failed" as const }]) {
        expect(classifyFullSupervisionExit({ ...value, completion }).kind).toBe("uncharged_stop");
      }
    });
  }
  it(`${kind} stop preserves terminal parse refusal`, () => {
    expect(classifyFullSupervisionExit(input(attemptId, { exit: { code: 2 }, stopIntent: { kind, attemptId } })))
      .toMatchObject({ kind: "terminal", reason: "parse_refusal" });
  });
}
it("charges a malformed runtime stop intent cast through never", () => {
  const value = input(attemptId, { stopIntent: { kind: "Operator", attemptId } as never });
  expect(classifyFullSupervisionExit(value)).toEqual({ kind: "charged_unverified_exit", decidedBy: value });
});

it("charges matched malformed cleanup under an operator SIGTERM stop", () => {
  const value = input(attemptId, {
    exit: { signal: "SIGTERM" }, stopIntent: { kind: "operator", attemptId }, readinessCommitted: true,
    completion: { attemptId, cleanup: "FAILED" } as never,
  });
  expect(classifyFullSupervisionExit(value)).toEqual({ kind: "charged_unverified_exit", decidedBy: value });
});

it("charges matched malformed cleanup under a lifecycle SIGKILL stop", () => {
  const value = input(attemptId, {
    exit: { signal: "SIGKILL" }, stopIntent: { kind: "lifecycle", attemptId }, readinessCommitted: true,
    completion: { attemptId, cleanup: "FAILED" } as never,
  });
  expect(classifyFullSupervisionExit(value)).toEqual({ kind: "charged_unverified_exit", decidedBy: value });
});
