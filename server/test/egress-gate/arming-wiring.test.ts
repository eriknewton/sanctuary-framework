/**
 * Tests for the pure/injectable pieces of the S5-6 production wiring
 * (`egress-gate/arming-wiring.ts`): the lsof-backed loopback port-owner
 * check's fail-closed contract. The wiring module's side-effecting factories
 * (launchctl, pfctl, real fs under /var/db) are production-only by design and
 * are exercised through the pure S5-1..S5-5 libraries they compose (their own
 * suites) + the S5-DRILL; this suite pins the one seam that takes an injected
 * exec function.
 */

import { describe, expect, it, vi } from "vitest";

import { verifyLoopbackPortOwner } from "../../src/egress-gate/arming-wiring.js";

function lsofOutput(pid: number, uid: number): string {
  return `p${pid}\nu${uid}\nnlocalhost:40001\n`;
}

describe("egress-gate/arming-wiring verifyLoopbackPortOwner", () => {
  it("true when the listener pid (and uid, when expected) match", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(991, 503), stderr: "" }));
    await expect(
      verifyLoopbackPortOwner({ port: 40001, expectedPid: 991, expectedUid: 503, execFileFn: execFileFn as never }),
    ).resolves.toBe(true);
    expect(execFileFn).toHaveBeenCalledWith("lsof", ["-nP", "-iTCP:40001", "-sTCP:LISTEN", "-Fpu"]);
  });

  it("false on a pid mismatch (a squatter on the committed port is never owner-verified)", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(1234, 503), stderr: "" }));
    await expect(
      verifyLoopbackPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never }),
    ).resolves.toBe(false);
  });

  it("false on a uid mismatch when an expected uid is given (wrong service account)", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: lsofOutput(991, 0), stderr: "" }));
    await expect(
      verifyLoopbackPortOwner({ port: 40001, expectedPid: 991, expectedUid: 503, execFileFn: execFileFn as never }),
    ).resolves.toBe(false);
  });

  it("fail-closed: no listener / lsof failure resolves false, never throws", async () => {
    const execFileFn = vi.fn(async () => {
      throw new Error("lsof exited 1");
    });
    await expect(
      verifyLoopbackPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never }),
    ).resolves.toBe(false);
  });

  it("fail-closed: empty lsof output (no pid line) is not owner-verified", async () => {
    const execFileFn = vi.fn(async () => ({ stdout: "", stderr: "" }));
    await expect(
      verifyLoopbackPortOwner({ port: 40001, expectedPid: 991, execFileFn: execFileFn as never }),
    ).resolves.toBe(false);
  });
});
