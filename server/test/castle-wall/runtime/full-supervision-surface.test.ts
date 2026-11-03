import * as runtime from "../../../src/castle-wall/runtime/index.js";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import type { FullSupervisionDependencies } from "../../../src/castle-wall/runtime/full-supervision-state.js";

it("exports a usable supervision ledger, classifier and provisional defaults through the runtime barrel", async () => {
  expect(runtime).toMatchObject({
    FullSupervisionLedger: expect.any(Function), classifyFullSupervisionExit: expect.any(Function),
    FULL_SUPERVISION_CRASH_BUDGET: 5, FULL_SUPERVISION_WINDOW_SECONDS: 1800, FULL_SUPERVISION_THROTTLE_SECONDS: 5,
  });
  expect(runtime.classifyFullSupervisionExit({
    attemptId: "surface", exit: { code: 2 }, stopIntent: { kind: "none" }, readinessCommitted: false,
  })).toMatchObject({ kind: "terminal", reason: "parse_refusal" });
  const directory = await mkdtemp(join(tmpdir(), "supervision-surface-"));
  try {
    const deps: FullSupervisionDependencies = {
      directory, wallClock: () => 0, monotonicClock: () => 0, bootIdentity: async () => "surface-boot",
      processLiveness: async () => "unknown", processStartToken: async () => null,
    };
    expect(await new runtime.FullSupervisionLedger(deps).admit("surface")).toMatchObject({ ok: true, admitted: true, state: "state_PENDING_UNIDENTIFIED" });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

it("pins the complete exported default code surface to the CLI producer sites", async () => {
  const source = await readFile(new URL("../../../src/cli/castle-wall.ts", import.meta.url), "utf8");
  const pins = [...source.matchAll(/\/\/ must match (FULL_SUPERVISION_[A-Z_]+) in server\/src\/castle-wall\/runtime\/full-supervision-exit\.ts\.\n([^\n]+)/g)];
  expect(pins.map((pin) => pin[1]).sort()).toEqual(["FULL_SUPERVISION_COMPLETION_CODES", "FULL_SUPERVISION_DEFAULT_CODES"]);
  const terminal = pins.find((pin) => pin[1] === "FULL_SUPERVISION_DEFAULT_CODES")![2]!;
  expect(terminal).toMatch(/if \(writeCastleWallParseError\(parsed, err\)\) return \d+;/);
  const completion = pins.find((pin) => pin[1] === "FULL_SUPERVISION_COMPLETION_CODES")![2]!;
  expect(completion).toMatch(/return \(await releaseDaemonMasterSession\(\)\) \? \d+ : \d+;/);
  const terminalCode = Number(terminal.match(/return (\d+)/)![1]);
  const completionMatch = completion.match(/\? (\d+) : (\d+)/)!;
  expect(runtime.FULL_SUPERVISION_DEFAULT_CODES).toEqual({ restartable: [], terminal: [{ code: terminalCode, reason: "parse_refusal" }], retryable: [] });
  expect(runtime.FULL_SUPERVISION_COMPLETION_CODES).toEqual({ ok: Number(completionMatch[1]), failed: Number(completionMatch[2]) });
});
