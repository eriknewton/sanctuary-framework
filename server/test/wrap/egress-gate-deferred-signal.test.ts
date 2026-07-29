import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const autoProvisionMocks = vi.hoisted(() => ({
  runAutoProvisionForWrap: vi.fn(async () => ({ ran: false })),
  runEgressGateRepairForCli: vi.fn(),
  runEgressGateUnprotectForCli: vi.fn(),
}));

vi.mock("../../src/wrap/auto-provision.js", () => ({
  runAutoProvisionForWrap: autoProvisionMocks.runAutoProvisionForWrap,
  runEgressGateRepairForCli: autoProvisionMocks.runEgressGateRepairForCli,
  runEgressGateUnprotectForCli: autoProvisionMocks.runEgressGateUnprotectForCli,
}));

import {
  __resetProcessShutdownStateForTest,
  handleProcessShutdownSignal,
  runWrap,
} from "../../src/wrap/cli.js";

describe("exclusive-egress repair/unprotect deferred shutdown signals", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    autoProvisionMocks.runAutoProvisionForWrap.mockClear();
    autoProvisionMocks.runEgressGateRepairForCli.mockReset();
    autoProvisionMocks.runEgressGateUnprotectForCli.mockReset();
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code ?? 0}`);
    }) as never);
  });

  afterEach(() => {
    __resetProcessShutdownStateForTest();
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it("threads beforeFirstMutation through --repair-egress-gate and exits on a deferred signal even if repair throws", async () => {
    autoProvisionMocks.runEgressGateRepairForCli.mockImplementation(async (options) => {
      expect(typeof options.beforeFirstMutation).toBe("function");
      expect(await options.beforeFirstMutation()).toBe(true);
      await handleProcessShutdownSignal("SIGTERM");
      throw new Error("repair exploded");
    });

    await expect(
      runWrap({ repairEgressGate: true, standDownAgent: true }),
    ).rejects.toThrow("process.exit:143");

    expect(autoProvisionMocks.runEgressGateRepairForCli).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(143);
  });

  it("threads beforeFirstMutation through --unprotect-egress-gate and exits on a deferred signal even if unprotect throws", async () => {
    autoProvisionMocks.runEgressGateUnprotectForCli.mockImplementation(async (options) => {
      expect(typeof options.beforeFirstMutation).toBe("function");
      expect(await options.beforeFirstMutation()).toBe(true);
      await handleProcessShutdownSignal("SIGTERM");
      throw new Error("unprotect exploded");
    });

    await expect(
      runWrap({ unprotectEgressGate: true, standDownAgent: true }),
    ).rejects.toThrow("process.exit:143");

    expect(autoProvisionMocks.runEgressGateUnprotectForCli).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(143);
  });
});
