import * as fs from "node:fs/promises";
import { classifyFullSupervisionExit, type FullSupervisionExitInput } from "../../../src/castle-wall/runtime/full-supervision-exit.js";
import { FullSupervisionLedger, type FullSupervisionDependencies, type FullSupervisionResult } from "../../../src/castle-wall/runtime/full-supervision-state.js";

// W1_R2B_PROCESS_FENCE_DESIGN.md's proposed AUDIT_STALL_CEILING_EXIT_CODE is a fixture, never a reserved src code.
export const RESTART_FIXTURE_CODE = 74;
export const TEST_WALL = 2_000_000; // A fixed positive epoch with room for a complete 1,800 s window.
export const TEST_MONOTONIC = 100_000; // Fixed within-boot fixture, far enough from zero for regression tests.
export function input(attemptId: string, overrides: Partial<FullSupervisionExitInput> = {}): FullSupervisionExitInput {
  return { attemptId, exit: { code: RESTART_FIXTURE_CODE }, stopIntent: { kind: "none" }, readinessCommitted: false, ...overrides };
}
export function classification(attemptId: string, overrides: Partial<FullSupervisionExitInput> = {}) {
  return classifyFullSupervisionExit(input(attemptId, overrides), { restartable: [RESTART_FIXTURE_CODE], terminal: [], retryable: [] });
}
export function dependencies(directory: string, overrides: Partial<FullSupervisionDependencies> = {}): FullSupervisionDependencies {
  return {
    directory, fs, wallClock: () => TEST_WALL, monotonicClock: () => TEST_MONOTONIC,
    bootIdentity: async () => "test-boot", processLiveness: async () => "dead",
    processStartToken: async () => "test-start", throttleSeconds: 0, ...overrides,
  };
}
export function ledger(directory: string, overrides: Partial<FullSupervisionDependencies> = {}) {
  return new FullSupervisionLedger(dependencies(directory, overrides));
}
export function successful(result: FullSupervisionResult) {
  if (!result.ok) throw new Error(`unexpected refusal: ${result.reason}`);
  return result;
}
export async function charge(directory: string, attemptId: string, overrides: Partial<FullSupervisionDependencies> = {}) {
  const instance = ledger(directory, overrides);
  successful(await instance.admit(attemptId));
  return successful(await instance.settle(attemptId, classification(attemptId)));
}
/** Linux-only fixture reader. No test reaches credentials or operator state. */
export async function linuxStartToken(pid: number): Promise<string | null> {
  try {
    const stat = await fs.readFile(`/proc/${pid}/stat`, "utf8");
    // stat field 22 is starttime; fields after the parenthesized comm begin at field 3.
    return stat.slice(stat.lastIndexOf(")") + 2).split(" ")[22 - 3] ?? null;
  } catch { return null; }
}
export async function realLiveness(pid: number): Promise<"alive" | "dead" | "unknown"> {
  try { process.kill(pid, 0); return "alive"; }
  catch (error) { return (error as NodeJS.ErrnoException).code === "ESRCH" ? "dead" : "unknown"; }
}
