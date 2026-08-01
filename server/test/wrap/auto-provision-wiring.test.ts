/**
 * Auto-provision Step 2 (Build 1): `sanctuary protect`-level wiring tests.
 *
 * `castle-wall/provision/orchestrate.test.ts` already exercises the full
 * folded-fix sequencing (detect -> plan -> confirm -> create -> re-home ->
 * install-daemon -> verify -> uid-gate -> arm -> post-arm-recheck) against
 * pure mocks. What that suite does NOT cover is the CALLER-SIDE gate this
 * file targets: `wrap/cli.ts`'s `maybeRunAutoProvisionForWrap`, which decides
 * WHETHER to invoke the orchestration at all from a real `runWrap` call, and
 * the `--provision-agent-account` / `--no-provision-agent-account` CLI flags
 * that feed it (fix L2: pre-answer the CHOICE only).
 *
 * Covered here:
 *   - `parseWrapArgs` captures both new flags correctly (and leaves the
 *     option unset when neither is passed, preserving the interactive-only
 *     default).
 *   - `runWrap` calls the injected `runAutoProvisionForWrap` dep ONLY for
 *     `--hermes` (v1 scope: D1 headless-agent-runtime-only, Hermes-first
 *     adapter) and never for other platforms.
 *   - `runWrap --dry-run` NEVER invokes auto-provision (dry-run must stay
 *     write-free end-to-end, matching the existing `options.dryRun`
 *     early-return the rest of the wrap pipeline honors).
 *   - the `isTty` and `preAnsweredProvision` values passed to the dep mirror
 *     `process.stdin.isTTY` and `options.provisionAgentAccount` exactly.
 *   - a thrown error from the auto-provision dep is caught and reported as a
 *     note (fix H4: it never turns an otherwise-successful cooperative wrap
 *     into a hard CLI failure -- `runWrap` must still resolve).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, cp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  __resetProcessShutdownStateForTest,
  parseWrapArgs,
  runWrap,
  type RunWrapDeps,
  type WrapOptions,
} from "../../src/wrap/cli.js";
import type { AutoProvisionSummary } from "../../src/wrap/auto-provision.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import {
  agreeingHermesParity,
  installHermesParityHook,
  clearHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");
const UNVERIFIED_NO_CHANNEL = {
  kind: "cos_liveness_unverified" as const,
  reason: "no_channel_configured" as const,
};

describe("parseWrapArgs --provision-agent-account / --no-provision-agent-account (fix L2)", () => {
  it("captures --provision-agent-account as true", () => {
    const opts = parseWrapArgs(["--hermes", "--provision-agent-account"]);
    expect(opts.provisionAgentAccount).toBe(true);
  });

  it("captures --no-provision-agent-account as false (explicit decline)", () => {
    const opts = parseWrapArgs(["--hermes", "--no-provision-agent-account"]);
    expect(opts.provisionAgentAccount).toBe(false);
  });

  it("leaves provisionAgentAccount undefined when neither flag is passed (interactive prompt is the sole decision point)", () => {
    const opts = parseWrapArgs(["--hermes"]);
    expect(opts.provisionAgentAccount).toBeUndefined();
  });
});

describe("runWrap: maybeRunAutoProvisionForWrap gating", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalIsTty: boolean | undefined;
  let originalArgv1: string | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-autoprovision-wiring-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalIsTty = process.stdin.isTTY;
    originalArgv1 = process.argv[1];
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    // SAFETY: stdout is not a real console; silencing the operator-facing
    // channel keeps test output clean without changing runWrap's behavior.
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    installHermesParityHook(agreeingHermesParity);
  });

  afterEach(async () => {
    __resetProcessShutdownStateForTest();
    stderrSpy.mockRestore();
    clearHermesParityHook();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    Object.defineProperty(process.stdin, "isTTY", {
      value: originalIsTty,
      configurable: true,
    });
    if (originalArgv1 === undefined) process.argv.splice(1, 1);
    else process.argv[1] = originalArgv1;
    await rm(tmpHome, { recursive: true, force: true });
  });

  function setTty(value: boolean | undefined): void {
    Object.defineProperty(process.stdin, "isTTY", { value, configurable: true });
  }

  function baseDeps(
    overrides: Partial<RunWrapDeps> = {},
  ): RunWrapDeps {
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated" as const,
      }),
      ...overrides,
    };
  }

  async function installHermesFixture(): Promise<void> {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));
  }

  async function installClaudeCodeFixture(): Promise<void> {
    await cp(join(fixturesDir, "flat-mcp.json"), join(tmpHome, ".claude.json"));
  }

  function options(extra: WrapOptions = {}): WrapOptions {
    return { noOpen: true, noDashboard: true, ...extra };
  }

  it("invokes the auto-provision dep for --hermes", async () => {
    await installHermesFixture();
    setTty(true);
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    await runWrap(options({ hermes: true }), baseDeps({ runAutoProvisionForWrap }));
    expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
  });

  it("never invokes the auto-provision dep for a non-Hermes platform (v1 = Hermes-only)", async () => {
    await installClaudeCodeFixture();
    setTty(true);
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    await runWrap(options({ claudeCode: true }), baseDeps({ runAutoProvisionForWrap }));
    expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
  });

  it("never invokes the auto-provision dep on --dry-run (dry-run stays write-free end-to-end)", async () => {
    await installHermesFixture();
    setTty(true);
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    await runWrap(options({ hermes: true, dryRun: true }), baseDeps({ runAutoProvisionForWrap }));
    expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
  });

  it("installs SIGINT/SIGTERM shutdown listeners at runWrap entry, including dry-run paths", async () => {
    await installHermesFixture();
    setTty(true);
    const processOnSpy = vi.spyOn(process, "on");
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));

    try {
      await runWrap(options({ hermes: true, dryRun: true }), baseDeps({ runAutoProvisionForWrap }));

      expect(processOnSpy).toHaveBeenCalledWith("SIGINT", expect.any(Function));
      expect(processOnSpy).toHaveBeenCalledWith("SIGTERM", expect.any(Function));
      expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
    } finally {
      processOnSpy.mockRestore();
    }
  });

  it("passes isTty from process.stdin.isTTY and preAnsweredProvision from options.provisionAgentAccount through unchanged", async () => {
    await installHermesFixture();
    setTty(false);
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    await runWrap(
      options({ hermes: true, provisionAgentAccount: false }),
      baseDeps({ runAutoProvisionForWrap }),
    );
    expect(runAutoProvisionForWrap).toHaveBeenCalledWith(
      expect.objectContaining({ isTty: false, preAnsweredProvision: false }),
    );
  });

  it("passes the actually-running CLI path into auto-provision so install-boot can receive --binary", async () => {
    await installHermesFixture();
    setTty(true);
    const cliPath = join(tmpHome, "bin", "sanctuary");
    await mkdir(dirname(cliPath), { recursive: true });
    await writeFile(cliPath, "#!/usr/bin/env node\n");
    process.argv[1] = cliPath;
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    await runWrap(options({ hermes: true }), baseDeps({ runAutoProvisionForWrap }));
    expect(runAutoProvisionForWrap).toHaveBeenCalledWith(
      expect.objectContaining({ cliBinary: cliPath }),
    );
  });

  it("passes a transient Castle Wall daemon stop hook into auto-provision before install-boot", async () => {
    await installHermesFixture();
    setTty(true);
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    await runWrap(options({ hermes: true }), baseDeps({ runAutoProvisionForWrap }));
    expect(runAutoProvisionForWrap).toHaveBeenCalledWith(
      expect.objectContaining({ stopTransientCastleWallDaemon: expect.any(Function) }),
    );
  });

  it("an armed auto-provision outcome renders one consistent claim: coarse-only, never 'status unknown' beside the armed line (F-11)", async () => {
    // The `armed` outcome is only mintable in orchestrate after the post-arm
    // as-uid egress verification passed (its uid is Observed<number>, thrown
    // otherwise), so the run HOLDS an arm observation. The old pin here
    // asserted the F-11 contradiction as correct: the armed line and a
    // "status unknown" summary in the same run. One observation, both
    // surfaces.
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({
      ran: true,
      outcome: { kind: "armed", uid: 503, liveness: UNVERIFIED_NO_CHANNEL },
    }));
    await installHermesFixture();
    setTty(true);
    await runWrap(options({ hermes: true }), baseDeps({ runAutoProvisionForWrap }));

    const stderr = stderrSpy.mock.calls.flat().join("\n");
    expect(stderr).toContain("Dedicated agent account provisioned and Castle Wall armed (uid 503)");
    expect(stderr).not.toContain("Castle Wall NOT ARMED");
    // B4 (merged main): one observation, both surfaces — the armed run's
    // summary claims coarse-only and never contradicts itself with unknown.
    expect(stderr).toContain("Castle Wall coarse-only");
    expect(stderr).not.toContain("Castle Wall status unknown");
    // F-GATEWAY-TWIN fix 8 (this PR): the armed summary must also surface the
    // liveness verdict the outcome now carries — before this fix the operator
    // could read a freshly-armed wrap as "functional through the wall" on zero
    // evidence (the exact false result the unconfined twin produced on Mini2).
    expect(stderr).toContain(
      "CoS liveness unverified (no_channel_configured); no functional-through-wall claim was made.",
    );
  });

  it("prefers --dev-dist as the auto-provision CLI binary for dogfood installs", async () => {
    await installHermesFixture();
    setTty(true);
    const devDist = join(tmpHome, "dist", "cli.js");
    await mkdir(dirname(devDist), { recursive: true });
    await writeFile(devDist, "#!/usr/bin/env node\n");
    process.argv[1] = join(tmpHome, "bin", "sanctuary");
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    await runWrap(options({ hermes: true, devDist }), baseDeps({ runAutoProvisionForWrap }));
    expect(runAutoProvisionForWrap).toHaveBeenCalledWith(
      expect.objectContaining({ cliBinary: devDist }),
    );
  });

  it("fix H4: a thrown auto-provision error is caught and reported as a note; runWrap still resolves", async () => {
    await installHermesFixture();
    setTty(true);
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => {
      throw new Error("sysadminctl exited 1");
    });
    await expect(
      runWrap(options({ hermes: true }), baseDeps({ runAutoProvisionForWrap })),
    ).resolves.toBeUndefined();
    expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
  });

  it("FIX (round 5, R8-2): a ProvisionLockHeldError is reported as an HONEST no-mutation note, not the generic 'may have partially applied / consider disarming' warning", async () => {
    const { ProvisionLockHeldError } = await import("../../src/castle-wall/provision/index.js");
    await installHermesFixture();
    setTty(true);
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => {
      throw new ProvisionLockHeldError("/var/run/sanctuary-provision.lock");
    });
    await expect(
      runWrap(options({ hermes: true }), baseDeps({ runAutoProvisionForWrap })),
    ).resolves.toBeUndefined();
    const printed = stderrSpy.mock.calls.map((c) => String(c[0])).join("\n");
    // Honest: another provisioning run is in progress; THIS run changed nothing.
    expect(printed).toMatch(/another 'sanctuary protect' provisioning run is already in progress/);
    expect(printed).toMatch(/made NO account, re-home, or Castle Wall changes/);
    expect(printed).toMatch(/if not, remove the stale lock file named above and re-run if needed/);
    expect(printed).not.toMatch(/Wait for it to finish, then re-run if needed/);
    // Must NOT emit the partial-apply / disarm warning for a lock-held no-op.
    expect(printed).not.toMatch(/may have PARTIALLY applied/);
  });
});
