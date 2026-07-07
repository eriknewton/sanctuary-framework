/**
 * Tests for the one-flow orchestration (fold of the target flow's steps 1
 * through 11, folded fixes B2/H1/H3/H4/L2): every fail-closed branch is
 * driven purely through injected ops, so this exercises the FULL corrected
 * sequencing without touching a real host, TTY, or privileged binary.
 */

import { describe, it, expect, vi } from "vitest";

import { runProvisionFlow, type ProvisionFlowContext, type ProvisionFlowOps } from "../../../src/castle-wall/provision/orchestrate.js";
import type { ProvisionNeedResult } from "../../../src/castle-wall/provision/detect.js";
import type { RehomeStepResult } from "../../../src/castle-wall/provision/rehome.js";

const CEILING = 500;
const AGENT_UID = 502;

const NEEDS_PROVISIONING: ProvisionNeedResult = {
  needsProvisioning: true,
  alreadyDedicated: false,
  reason: "shared account",
};

const ALREADY_DEDICATED: ProvisionNeedResult = {
  needsProvisioning: false,
  alreadyDedicated: true,
  resolved: { uid: AGENT_UID, source: "harness-config" },
  reason: "already dedicated",
};

const REHOME_RESULTS: RehomeStepResult[] = [
  {
    entry: { sourcePath: "/Users/operator/.hermes/.env", destRelativePath: ".hermes/.env", isSecret: true },
    destPath: "/var/sanctuary-agents/sanctuary-hermes/.hermes/.env",
    status: "moved",
    backupPath: "/root/backup/.hermes/.env.bak",
  },
];

function baseCtx(overrides: Partial<ProvisionFlowContext> = {}): ProvisionFlowContext {
  return {
    agentId: "hermes",
    accountName: "sanctuary-hermes",
    ceiling: CEILING,
    detectResult: NEEDS_PROVISIONING,
    isTty: true,
    ...overrides,
  };
}

function happyPathOps(overrides: Partial<ProvisionFlowOps> = {}): ProvisionFlowOps {
  return {
    confirm: vi.fn(async () => true),
    print: vi.fn(),
    createAccount: vi.fn(async () => ({
      plan: { action: "create", accountName: "sanctuary-hermes", uid: AGENT_UID },
      uid: AGENT_UID,
    })),
    rehome: vi.fn(async () => ({
      plan: { harnessId: "hermes", steps: [], requiresInteractiveReconsent: false },
      results: REHOME_RESULTS,
    })),
    installHarnessDaemon: vi.fn(async () => undefined),
    preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => true }]),
    checkUidExistence: vi.fn(async () => ({ ok: true, accountName: "sanctuary-hermes", uid: AGENT_UID })),
    arm: vi.fn(async () => ({ ok: true as const })),
    postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => true }]),
    disarm: vi.fn(async () => undefined),
    restoreRehome: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe("castle-wall/provision/orchestrate", () => {
  it("happy path: runs every step in order and arms", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toEqual({ kind: "armed", uid: AGENT_UID });
    expect(ops.createAccount).toHaveBeenCalledTimes(1);
    expect(ops.rehome).toHaveBeenCalledWith(AGENT_UID, AGENT_UID);
    expect(ops.installHarnessDaemon).toHaveBeenCalledWith(AGENT_UID);
    expect(ops.checkUidExistence).toHaveBeenCalledWith(AGENT_UID);
    expect(ops.arm).toHaveBeenCalledWith(AGENT_UID, CEILING);
    expect(ops.disarm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).not.toHaveBeenCalled();
  });

  it("step 1 (detect): skips straight through when already dedicated, no mutation attempted", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ detectResult: ALREADY_DEDICATED }), ops);
    expect(result.kind).toBe("skipped-already-dedicated");
    expect(ops.createAccount).not.toHaveBeenCalled();
    expect(ops.confirm).not.toHaveBeenCalled();
  });

  it("fix H4: non-TTY skips provisioning (cooperative-wrap-only) WITHOUT ever confirming or mutating", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ isTty: false }), ops);
    expect(result.kind).toBe("skipped-non-tty-cooperative-only");
    expect(ops.confirm).not.toHaveBeenCalled();
    expect(ops.createAccount).not.toHaveBeenCalled();
  });

  it("fix L2: a pre-answered decline (--provision-agent-account not passed / declined) stops before the confirm prompt", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ preAnsweredProvision: false }), ops);
    expect(result.kind).toBe("declined-by-operator");
    expect(ops.confirm).not.toHaveBeenCalled();
    expect(ops.createAccount).not.toHaveBeenCalled();
  });

  it("fix L2: a pre-answered accept STILL shows the confirm prompt (pre-answers the choice only, not the mutation gate)", async () => {
    const ops = happyPathOps();
    const result = await runProvisionFlow(baseCtx({ preAnsweredProvision: true }), ops);
    expect(result.kind).toBe("armed");
    expect(ops.confirm).toHaveBeenCalledTimes(1);
  });

  it("operator declines the interactive confirm: stops before any mutation", async () => {
    const ops = happyPathOps({ confirm: vi.fn(async () => false) });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result.kind).toBe("declined-by-operator");
    expect(ops.createAccount).not.toHaveBeenCalled();
  });

  it("fail-closed: account creation failure aborts before re-home, no rollback needed (nothing moved yet)", async () => {
    const ops = happyPathOps({
      createAccount: vi.fn(async () => {
        throw new Error("sysadminctl exit 1");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "create-account", rolledBack: false });
    expect(ops.rehome).not.toHaveBeenCalled();
  });

  it("fail-closed: re-home failure aborts, no daemon install attempted", async () => {
    const ops = happyPathOps({
      rehome: vi.fn(async () => {
        throw new Error("chown failed: operation not permitted");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "rehome", rolledBack: false });
    expect(ops.installHarnessDaemon).not.toHaveBeenCalled();
  });

  it("fail-closed: daemon install failure restores the backup and aborts before verify/arm", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => {
        throw new Error("launchctl bootstrap exited 5");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon", rolledBack: true });
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
    expect(ops.checkUidExistence).not.toHaveBeenCalled();
    expect(ops.arm).not.toHaveBeenCalled();
  });

  it("fix B2 ordering: pre-arm verify runs AFTER daemon install, and failure restores + STOPS before arming", async () => {
    const callOrder: string[] = [];
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => {
        callOrder.push("install-daemon");
      }),
      preArmEndpoints: vi.fn(() => {
        callOrder.push("pre-arm-verify");
        return [{ name: "Gmail", probe: async () => false }];
      }),
      arm: vi.fn(async () => {
        callOrder.push("arm");
        return { ok: true as const };
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "verify-before-arm", rolledBack: true });
    expect(callOrder).toEqual(["install-daemon", "pre-arm-verify"]);
    expect(ops.arm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("fix H1: uid-existence-gate failure (account missing/mismatched) aborts before arm, with restore", async () => {
    const ops = happyPathOps({
      checkUidExistence: vi.fn(async () => ({
        ok: false,
        accountName: "sanctuary-hermes",
        reason: "account does not exist",
      })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "uid-existence-gate", rolledBack: true });
    expect(ops.arm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("arm failure (the shipped enable path refuses) aborts with restore", async () => {
    const ops = happyPathOps({
      arm: vi.fn(async () => ({ ok: false as const, error: "no agent-origin descriptor" })),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "arm", rolledBack: true });
    expect(ops.disarm).not.toHaveBeenCalled();
    expect(ops.restoreRehome).toHaveBeenCalledWith(REHOME_RESULTS);
  });

  it("fix B2 rollback: post-arm verify failure fast-disarms rather than restoring re-home (agent stays re-homed, wall comes down)", async () => {
    const ops = happyPathOps({
      postArmEndpoints: vi.fn(() => [{ name: "Gmail", probe: async () => false }]),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "armed-then-rolled-back", uid: AGENT_UID });
    expect(ops.disarm).toHaveBeenCalledTimes(1);
    // Post-arm rollback is a fast DISARM, not a re-home restore: the agent
    // stays on its dedicated, re-homed account; only enforcement comes down.
    expect(ops.restoreRehome).not.toHaveBeenCalled();
  });

  it("a restore failure during rollback does not mask the original abort reason", async () => {
    const ops = happyPathOps({
      installHarnessDaemon: vi.fn(async () => {
        throw new Error("launchctl bootstrap exited 5");
      }),
      restoreRehome: vi.fn(async () => {
        throw new Error("restore also failed");
      }),
    });
    const result = await runProvisionFlow(baseCtx(), ops);
    expect(result).toMatchObject({ kind: "aborted", stage: "install-daemon", rolledBack: true });
    if (result.kind === "aborted") {
      expect(result.reason).toMatch(/launchctl bootstrap exited 5/);
    }
  });
});
