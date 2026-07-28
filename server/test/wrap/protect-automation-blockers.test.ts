/**
 * N1: three bounded automation-blocker fixes for `sanctuary protect`
 * (drill record 2026-07-26), fix 2 corrected 2026-07-27 (harden-loop):
 *
 *   1. SIGINT/SIGTERM handlers must exit after cleanups run, and a repeat
 *      signal (a plain listener suppresses Node's default "exit on signal"
 *      action) waits for cleanup, while a repeat signal escalates and exits
 *      promptly with residual-state guidance. Without the exit, `sanctuary
 *      protect` and the standalone dashboard survived a plain `kill` and
 *      drills needed `kill -9`; without escalation, a second signal could
 *      leave the operator staring at a 75s rollback wait.
 *   2. CORRECTED 2026-07-27: a declined step-2 arm confirm must NOT exit
 *      the process. `declined-by-operator` is only ever returned when the
 *      run is interactive (a non-interactive run gets the distinct
 *      `skipped-non-tty-cooperative-only` kind), so this is always a real
 *      operator at a terminal -- for whom continuing to serve the
 *      dashboard, exactly like the accepted-arm path, is correct, not a
 *      hang. The initial fix's exit-on-decline regressed every interactive
 *      Hermes wrap: a bare Enter at the default-N confirm, or the common
 *      `--no-provision-agent-account` flag, killed the whole session and
 *      skipped the protection-claim / dashboard-URL / passphrase-location
 *      success output. Decline is informational only; the flow now falls
 *      through exactly like the `--no-dashboard` branch's handling of the
 *      same outcome kind.
 *   3. `--exclusive-egress` / `--provision-agent-account` without a
 *      provisionable agent selector (Hermes-only today) must refuse loudly
 *      and exit 2, not silently arm nothing -- checked AFTER the
 *      fresh-config bootstrap (so a first-install/yaml-only Hermes host is
 *      not falsely refused) and ALSO on non-darwin hosts (auto-provision is
 *      darwin-only and otherwise no-ops silently even when Hermes is the
 *      resolved platform).
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { cp, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AUTO_PROVISION_SHUTDOWN_DEADLINE_MS,
  handleProcessShutdownSignal,
  registerProcessShutdownCleanup,
  runWrap,
  type RunWrapDeps,
  type WrapOptions,
} from "../../src/wrap/cli.js";
import { handleStandaloneShutdownSignal } from "../../src/dashboard-standalone.js";
import type { AutoProvisionSummary } from "../../src/wrap/auto-provision.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import {
  runProvisionFlow,
  type ProvisionFlowContext,
  type ProvisionFlowOps,
} from "../../src/castle-wall/provision/orchestrate.js";
import type { RehomeStepResult } from "../../src/castle-wall/provision/rehome.js";
import {
  agreeingHermesParity,
  installHermesParityHook,
  clearHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");
const SIGNAL_TEST_UID = 503;
const SIGNAL_TEST_REHOME_RESULTS: RehomeStepResult[] = [
  {
    entry: { sourcePath: "/Users/operator/.hermes/.env", destRelativePath: ".hermes/.env", isSecret: true },
    destPath: "/var/sanctuary-agents/sanctuary-hermes/.hermes/.env",
    status: "moved",
    backupPath: "/root/backup/.hermes/.env.bak",
  },
];

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function signalProvisionCtx(
  shutdownSignal: AbortSignal | undefined,
  onShutdownStatus: ((status: unknown) => void) | undefined,
): ProvisionFlowContext {
  return {
    agentId: "hermes",
    accountName: "sanctuary-hermes",
    ceiling: 500,
    detectResult: { needsProvisioning: true, alreadyDedicated: false, reason: "shared account" },
    isTty: true,
    fortressPath: "/Users/operator/.sanctuary",
    harnessEndpoints: {
      harnessId: "hermes",
      endpoints: [
        {
          name: "LLM (Venice)",
          host: "api.venice.ai",
          port: 443,
          protocol: "tcp",
          riskClass: "standard",
        },
      ],
    },
    shutdownSignal,
    onShutdownStatus,
  } as ProvisionFlowContext & {
    shutdownSignal?: AbortSignal;
    onShutdownStatus?: (status: unknown) => void;
  };
}

function signalProvisionOps(overrides: Partial<ProvisionFlowOps> = {}): ProvisionFlowOps {
  return {
    confirm: vi.fn(async () => true),
    print: vi.fn(),
    createAccount: vi.fn(async () => ({
      plan: { action: "create", accountName: "sanctuary-hermes", uid: SIGNAL_TEST_UID },
      uid: SIGNAL_TEST_UID,
    })),
    rehome: vi.fn(async () => ({
      plan: { harnessId: "hermes", steps: [], requiresInteractiveReconsent: false },
      results: SIGNAL_TEST_REHOME_RESULTS,
    })),
    installHarnessDaemon: vi.fn(async () => ({ ok: true as const, bootstrappedThisRun: true })),
    restoreStoodDownHarness: vi.fn(async () => ({
      restored: true,
      wasRunning: true,
      harnessRestarted: true,
      problems: [],
    })),
    uninstallHarnessDaemon: vi.fn(async () => undefined),
    ensurePolicyDaemon: vi.fn(async () => ({ ok: true as const, freshlyInstalled: false })),
    teardownPolicyDaemon: vi.fn(async () => undefined),
    provisionEgress: vi.fn(async () => ({
      ok: true as const,
      ruleIds: ["provisioned-hermes-abc123def456"],
      checks: [{ name: "LLM (Venice)", host: "api.venice.ai", port: 443, allowed: true }],
      dnsRulePresent: true,
    })),
    restoreProvisionedEgressToPreRunState: vi.fn(async () => ({
      restored: true,
      reloadOk: true,
      problems: [],
    })),
    verifyAgentEgressAfterArm: vi.fn(async () => ({
      ok: true,
      rows: [
        {
          name: "LLM (Venice)",
          host: "api.venice.ai",
          port: 443,
          expected: "reachable" as const,
          observed: "reachable" as const,
          pass: true,
        },
      ],
    })),
    auditEgress: vi.fn(async () => undefined),
    preArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => true }]),
    checkUidExistence: vi.fn(async () => ({ ok: true, accountName: "sanctuary-hermes", uid: SIGNAL_TEST_UID })),
    arm: vi.fn(async () => ({ ok: true as const })),
    postArmEndpoints: vi.fn(() => [{ name: "LLM", probe: async () => true }]),
    disarm: vi.fn(async () => ({ nePreferenceOutcome: "corroborated_off" as const })),
    restoreRehome: vi.fn(async () => ({
      fullyRestored: true,
      restoredCount: SIGNAL_TEST_REHOME_RESULTS.length,
      attemptedCount: SIGNAL_TEST_REHOME_RESULTS.length,
      backupPaths: SIGNAL_TEST_REHOME_RESULTS.filter((r) => r.backupPath).map((r) => r.backupPath!),
      conflictPaths: [],
      failedPaths: [],
    })),
    reconcileExclusiveRoutingResidue: vi.fn(async () => ({ kind: "clear" as const })),
    lookupDedicatedAccountUid: vi.fn(async () => undefined),
    observeAgentConfinement: vi.fn(async () => ({
      known: true as const,
      confinedUids: [],
      exclusiveRoutingMarkerPresent: false,
    })),
    ...overrides,
  };
}

// ── Fix 1: signal handlers must exit ─────────────────────────────────────

describe("handleProcessShutdownSignal (wrap/cli.ts) exits after cleanups", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((
      _code?: number,
    ) => undefined) as never);
  });

  afterEach(() => {
    exitSpy.mockRestore();
  });

  it("exits with 130 (128 + SIGINT=2) on SIGINT", async () => {
    await handleProcessShutdownSignal("SIGINT");
    expect(exitSpy).toHaveBeenCalledWith(130);
  });

  it("exits with 143 (128 + SIGTERM=15) on SIGTERM", async () => {
    await handleProcessShutdownSignal("SIGTERM");
    expect(exitSpy).toHaveBeenCalledWith(143);
  });

  // FIX (N1-1 corrected, 2026-07-27): the handler must AWAIT every
  // registered cleanup before exiting, not just start them and exit in the
  // same synchronous turn (that truncated every cleanup past its first
  // `await` -- see the doc comment on `runProcessShutdownCleanups`).
  it("awaits a registered async cleanup before exiting", async () => {
    let cleanupSettled = false;
    registerProcessShutdownCleanup(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
      cleanupSettled = true;
    });
    await handleProcessShutdownSignal("SIGTERM");
    expect(cleanupSettled).toBe(true);
    expect(exitSpy).toHaveBeenCalledWith(143);
  });

  it("R4: a repeat signal while cleanup is in flight escalates to immediate exit", async () => {
    const cleanupEntered = deferred<void>();
    const finishCleanup = deferred<void>();
    let cleanupSettled = false;
    registerProcessShutdownCleanup(async () => {
      cleanupEntered.resolve();
      await finishCleanup.promise;
      cleanupSettled = true;
    });
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      const first = handleProcessShutdownSignal("SIGTERM");
      await cleanupEntered.promise;
      await handleProcessShutdownSignal("SIGINT");

      // Fails with the R4 fix reverted: the second signal awaited the first
      // cleanup promise, so this assertion would not run until finishCleanup.
      expect(cleanupSettled).toBe(false);
      expect(exitSpy).toHaveBeenCalledWith(130);
      expect(stderrSpy.mock.calls.flat().join("\n")).toMatch(/cleanup is still in flight/);

      finishCleanup.resolve();
      await first;
      expect(cleanupSettled).toBe(true);
      expect(exitSpy).toHaveBeenCalledWith(143);
    } finally {
      finishCleanup.resolve();
      stderrSpy.mockRestore();
    }
  });

  // FIX (harden-loop, late-registration drop): nothing stops `runWrap`'s
  // main flow when a signal lands -- it keeps running in the same await
  // window as the in-flight cleanup drain, and can register a brand-new
  // cleanup (e.g. the tenant-runtime unlink registered right after
  // `writeTenantRuntime` resolves) AFTER `runProcessShutdownCleanups` has
  // already snapshotted-and-cleared the set for its current batch. A
  // single-pass drain abandons that cleanup: `process.exit()` fires once
  // the drain returns, and the only other place that would ever run it,
  // the fire-and-forget `process.on("exit", ...)` listener, cannot
  // complete async work before the process actually tears down.
  it("a cleanup registered while a batch is already draining is still awaited before exit, not abandoned", async () => {
    let firstSettled = false;
    let lateSettled = false;
    registerProcessShutdownCleanup(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      firstSettled = true;
    });

    const signalPromise = handleProcessShutdownSignal("SIGTERM");
    // Simulates the main flow registering a new cleanup after the drain's
    // synchronous snapshot-and-clear has already run (the drain is
    // suspended on `Promise.allSettled` for the first batch at this point).
    registerProcessShutdownCleanup(async () => {
      lateSettled = true;
    });
    await signalPromise;

    expect(firstSettled).toBe(true);
    expect(lateSettled).toBe(true);
    expect(exitSpy).toHaveBeenCalledWith(143);
  });
});

describe("runWrap: SIGTERM during in-flight provisioning waits for rollback or a bounded deadline", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalIsTty: boolean | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-provision-signal-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalIsTty = process.stdin.isTTY;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((
      _code?: number,
    ) => undefined) as never);
    installHermesParityHook(agreeingHermesParity);
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
    clearHermesParityHook();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    Object.defineProperty(process.stdin, "isTTY", {
      value: originalIsTty,
      configurable: true,
    });
    await rm(tmpHome, { recursive: true, force: true });
  });

  function deps(overrides: Partial<RunWrapDeps> = {}): RunWrapDeps {
    return {
      startDashboard: vi.fn(),
      openBrowser: vi.fn(async () => {}),
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated" as const,
      }),
      ...overrides,
    };
  }

  it("R4: pins the first-signal rollback-completeness budget at 75 seconds", () => {
    // Fails if the R4 constant changes without updating the declared worst case.
    expect(AUTO_PROVISION_SHUTDOWN_DEADLINE_MS).toBe(75_000);
  });

  it("a real SIGTERM while provision-egress is in flight waits for runProvisionFlow's egress restore before exit", async () => {
    const provisionEntered = deferred<void>();
    const finishProvision = deferred<void>();
    let released = false;
    const releaseProvision = () => {
      if (released) return;
      released = true;
      finishProvision.resolve();
    };
    const restoreProvisionedEgressToPreRunState = vi.fn(async () => ({
      restored: true,
      reloadOk: true,
      problems: [],
    }));
    const ops = signalProvisionOps({
      provisionEgress: vi.fn(async () => {
        provisionEntered.resolve();
        await finishProvision.promise;
        return {
          ok: true as const,
          ruleIds: ["provisioned-hermes-abc123def456"],
          checks: [{ name: "LLM (Venice)", host: "api.venice.ai", port: 443, allowed: true }],
          dnsRulePresent: true,
        };
      }),
      restoreProvisionedEgressToPreRunState,
    });
    const runAutoProvisionForWrap = vi.fn(async (input: unknown): Promise<AutoProvisionSummary> => {
      const provisionInput = input as {
        shutdownSignal?: AbortSignal;
        onShutdownStatus?: (status: unknown) => void;
      };
      const outcome = await runProvisionFlow(
        signalProvisionCtx(provisionInput.shutdownSignal, provisionInput.onShutdownStatus),
        ops,
      );
      return { ran: true, outcome };
    });

    const runPromise = runWrap(
      { hermes: true, noOpen: true, noDashboard: true },
      deps({ runAutoProvisionForWrap }),
    );

    try {
      await provisionEntered.promise;
      process.kill(process.pid, "SIGTERM");
      await sleepMs(25);
      expect(exitSpy).not.toHaveBeenCalled();

      releaseProvision();
      await runPromise;
      await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(143));

      expect(restoreProvisionedEgressToPreRunState).toHaveBeenCalledTimes(1);
      expect(ops.arm).not.toHaveBeenCalled();
      const restoreOrder = restoreProvisionedEgressToPreRunState.mock.invocationCallOrder[0];
      const exitOrder = exitSpy.mock.invocationCallOrder[0];
      expect(restoreOrder).toBeLessThan(exitOrder);
    } finally {
      releaseProvision();
      await Promise.race([runPromise.catch(() => undefined), sleepMs(50)]);
    }
  });

  it("a hung rollback is bounded and the shutdown message names the residual state plus recovery verb", async () => {
    const provisionEntered = deferred<void>();
    const finishProvisionEgress = deferred<void>();
    const rollbackEntered = deferred<void>();
    const finishRollback = deferred<{ restored: true; reloadOk: true; problems: [] }>();
    let released = false;
    const releaseProvision = () => {
      if (released) return;
      released = true;
      finishRollback.resolve({ restored: true, reloadOk: true, problems: [] });
    };
    const ops = signalProvisionOps({
      provisionEgress: vi.fn(async () => {
        provisionEntered.resolve();
        await finishProvisionEgress.promise;
        return {
          ok: true as const,
          ruleIds: ["provisioned-hermes-abc123def456"],
          checks: [{ name: "LLM (Venice)", host: "api.venice.ai", port: 443, allowed: true }],
          dnsRulePresent: true,
        };
      }),
      restoreProvisionedEgressToPreRunState: vi.fn(async () => {
        rollbackEntered.resolve();
        return finishRollback.promise;
      }),
    });
    const runAutoProvisionForWrap = vi.fn(async (input: unknown): Promise<AutoProvisionSummary> => {
      const provisionInput = input as {
        shutdownSignal?: AbortSignal;
        onShutdownStatus?: (status: unknown) => void;
      };
      const outcome = await runProvisionFlow(
        signalProvisionCtx(provisionInput.shutdownSignal, provisionInput.onShutdownStatus),
        ops,
      );
      return { ran: true, outcome };
    });

    const runPromise = runWrap(
      { hermes: true, noOpen: true, noDashboard: true },
      {
        ...deps({ runAutoProvisionForWrap }),
        autoProvisionShutdownDeadlineMs: 5,
      } as RunWrapDeps & { autoProvisionShutdownDeadlineMs: number },
    ).catch(() => undefined);

    try {
      await vi.waitFor(() => expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1), { timeout: 5000 });
      await provisionEntered.promise;
      const shutdownPromise = handleProcessShutdownSignal("SIGTERM");
      finishProvisionEgress.resolve();
      await rollbackEntered.promise;
      await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(143), { timeout: 250 });
      await shutdownPromise;

      const printed = stderrSpy.mock.calls.flat().join("\n");
      expect(printed).toMatch(/rollback was NOT observed/i);
      expect(printed).toMatch(/rollback-shutdown-after-provision-egress/);
      expect(printed).toMatch(/shutdown rollback is in flight/);
      expect(printed).toMatch(/re-homed files may be mid-restore/);
      expect(printed).toMatch(/sudo sanctuary protect --hermes/);
    } finally {
      finishProvisionEgress.resolve();
      releaseProvision();
      await Promise.race([runPromise, sleepMs(50)]);
    }
  });

  it("R4: a second signal abandons the auto-provision wait and reports current residual state", async () => {
    const provisionEntered = deferred<void>();
    const finishProvisionEgress = deferred<void>();
    const rollbackEntered = deferred<void>();
    const finishRollback = deferred<{ restored: true; reloadOk: true; problems: [] }>();
    let released = false;
    const releaseProvision = () => {
      if (released) return;
      released = true;
      finishRollback.resolve({ restored: true, reloadOk: true, problems: [] });
    };
    const ops = signalProvisionOps({
      provisionEgress: vi.fn(async () => {
        provisionEntered.resolve();
        await finishProvisionEgress.promise;
        return {
          ok: true as const,
          ruleIds: ["provisioned-hermes-abc123def456"],
          checks: [{ name: "LLM (Venice)", host: "api.venice.ai", port: 443, allowed: true }],
          dnsRulePresent: true,
        };
      }),
      restoreProvisionedEgressToPreRunState: vi.fn(async () => {
        rollbackEntered.resolve();
        return finishRollback.promise;
      }),
    });
    const runAutoProvisionForWrap = vi.fn(async (input: unknown): Promise<AutoProvisionSummary> => {
      const provisionInput = input as {
        shutdownSignal?: AbortSignal;
        onShutdownStatus?: (status: unknown) => void;
      };
      const outcome = await runProvisionFlow(
        signalProvisionCtx(provisionInput.shutdownSignal, provisionInput.onShutdownStatus),
        ops,
      );
      return { ran: true, outcome };
    });

    const runPromise = runWrap(
      { hermes: true, noOpen: true, noDashboard: true },
      deps({ runAutoProvisionForWrap }),
    ).catch(() => undefined);

    try {
      await vi.waitFor(() => expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1), { timeout: 5000 });
      await provisionEntered.promise;
      const first = handleProcessShutdownSignal("SIGTERM");
      finishProvisionEgress.resolve();
      await rollbackEntered.promise;
      await handleProcessShutdownSignal("SIGINT");

      // Fails with the R4 fix reverted: the second signal joined the 75s
      // rollback wait and never printed the residual state immediately.
      expect(exitSpy).toHaveBeenCalledWith(130);
      const printed = stderrSpy.mock.calls.flat().join("\n");
      expect(printed).toMatch(/received SIGINT while shutdown cleanup is still in flight/i);
      expect(printed).toMatch(/rollback-shutdown-after-provision-egress/);
      expect(printed).toMatch(/shutdown rollback is in flight/);
      expect(printed).toMatch(/sudo sanctuary protect --hermes/);

      releaseProvision();
      await first;
    } finally {
      finishProvisionEgress.resolve();
      releaseProvision();
      await Promise.race([runPromise, sleepMs(50)]);
    }
  });
});

describe("handleStandaloneShutdownSignal (dashboard-standalone.ts) exits after cleanups", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((
      _code?: number,
    ) => undefined) as never);
  });

  afterEach(() => {
    exitSpy.mockRestore();
  });

  it("exits with 130 (128 + SIGINT=2) on SIGINT", async () => {
    await handleStandaloneShutdownSignal("SIGINT");
    expect(exitSpy).toHaveBeenCalledWith(130);
  });

  it("exits with 143 (128 + SIGTERM=15) on SIGTERM", async () => {
    await handleStandaloneShutdownSignal("SIGTERM");
    expect(exitSpy).toHaveBeenCalledWith(143);
  });

  // FIX (N1-1 second-signal, 2026-07-27 harden-loop): same latch as
  // `handleProcessShutdownSignal` above. Without it, two signals fired back
  // to back each independently race their own (here, trivially empty)
  // `Promise.allSettled([])` to resolution and BOTH call `process.exit()`
  // -- the second call's exit racing ahead is exactly the bug class the
  // latch closes, visible here even with no registered cleanup at all.
  it("a repeat signal joins the same run instead of both independently calling process.exit", async () => {
    const first = handleStandaloneShutdownSignal("SIGTERM");
    const second = handleStandaloneShutdownSignal("SIGINT");
    await Promise.all([first, second]);

    expect(exitSpy).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(143);
  });
});

// ── Fix 2: declined arm must NOT exit -- it's always interactive, so it
// continues exactly like the accepted-arm path ───────────────────────────

describe("runWrap: declined step-2 arm confirm does not exit, matching the accepted-arm path", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalIsTty: boolean | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-declined-arm-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalIsTty = process.stdin.isTTY;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    // `noOpen: true` below keeps `establishWrapCustody`'s `interactive` flag
    // false, so this stays on the headless-install custody path and never
    // blocks on the (unrelated) real recovery-key re-entry prompt. The
    // step-2 arm confirm itself is bypassed entirely via the injected
    // `runAutoProvisionForWrap` dep, so isTTY's value does not matter to
    // what this test exercises.
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code ?? 0}`);
    }) as never);
    installHermesParityHook(agreeingHermesParity);
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
    clearHermesParityHook();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    Object.defineProperty(process.stdin, "isTTY", {
      value: originalIsTty,
      configurable: true,
    });
    await rm(tmpHome, { recursive: true, force: true });
  });

  function baseDeps(stopSpy: ReturnType<typeof vi.fn>): RunWrapDeps {
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:3501",
      port: 3501,
      host: "127.0.0.1",
      mode: "co-located",
      stop: stopSpy,
      publish: () => {},
      publishActivity: () => {},
      publishApproval: () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: vi.fn(async () => {}),
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated" as const,
      }),
    };
  }

  it("does NOT exit early and does NOT stop the dashboard on a declined arm -- the cooperative wrap still serves normally, and still prints the informational decline line", async () => {
    const stopSpy = vi.fn(async () => {});
    const runAutoProvisionForWrap = vi.fn(
      async (): Promise<AutoProvisionSummary> => ({
        ran: true,
        outcome: { kind: "declined-by-operator" },
      }),
    );
    const deps = { ...baseDeps(stopSpy), runAutoProvisionForWrap };

    await expect(
      runWrap({ hermes: true, noOpen: true }, deps),
    ).resolves.toBeUndefined();

    expect(stopSpy).not.toHaveBeenCalled();
    expect(exitSpy).not.toHaveBeenCalled();
    const printed = stderrSpy.mock.calls.flat().join("\n");
    expect(printed).toMatch(/Account provisioning declined/);
  });

  it("does NOT exit early / does NOT stop the dashboard on an accepted arm", async () => {
    const stopSpy = vi.fn(async () => {});
    const runAutoProvisionForWrap = vi.fn(
      async (): Promise<AutoProvisionSummary> => ({
        ran: true,
        outcome: { kind: "armed", uid: 503 },
      }),
    );
    const deps = { ...baseDeps(stopSpy), runAutoProvisionForWrap };

    await expect(
      runWrap({ hermes: true, noOpen: true }, deps),
    ).resolves.toBeUndefined();

    expect(stopSpy).not.toHaveBeenCalled();
    expect(exitSpy).not.toHaveBeenCalled();
  });
});

// ── Fix 3: loud refusal for agent-less exclusive arm ─────────────────────

describe("runWrap: --exclusive-egress / --provision-agent-account require a provisionable agent selector", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;

  beforeEach(async () => {
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code ?? 0}`);
    }) as never);
    // FIX (N1-3 corrected, 2026-07-27): the refusal now checks the RESOLVED
    // platform, which means `detectAgentConfigWithDiagnostics` actually runs
    // (it's read-only). Sandbox HOME to an empty tmp dir so "no agent
    // selector" tests deterministically find no config, instead of
    // depending on whatever happens to exist on the machine running the
    // suite.
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-exclusive-egress-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    await rm(tmpHome, { recursive: true, force: true });
  });

  function options(extra: WrapOptions = {}): WrapOptions {
    return { noOpen: true, noDashboard: true, ...extra };
  }

  it("refuses --exclusive-egress alone (no agent config anywhere) before any wrap work, exit code 2", async () => {
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    const startDashboard = vi.fn();
    await expect(
      runWrap(options({ exclusiveEgress: true }), { runAutoProvisionForWrap, startDashboard }),
    ).rejects.toThrow("process.exit:2");

    expect(exitSpy).toHaveBeenCalledWith(2);
    const printed = stderrSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("--exclusive-egress");
    expect(printed).toContain("--hermes");
    // Refuses BEFORE any state-changing wrap work: no config rewrite, no
    // auto-provision, no dashboard start. (Detection itself is a read-only
    // probe and DOES run now -- that's the fix -- but it finds nothing here.)
    expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
    expect(startDashboard).not.toHaveBeenCalled();
  });

  it("refuses --provision-agent-account alone (no agent config anywhere) before any wrap work, exit code 2", async () => {
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    const startDashboard = vi.fn();
    await expect(
      runWrap(options({ provisionAgentAccount: true }), { runAutoProvisionForWrap, startDashboard }),
    ).rejects.toThrow("process.exit:2");

    expect(exitSpy).toHaveBeenCalledWith(2);
    const printed = stderrSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("--provision-agent-account");
    expect(printed).toContain("--hermes");
    expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
    expect(startDashboard).not.toHaveBeenCalled();
  });

  it("refuses --exclusive-egress when the detected platform is NOT hermes (explicit wrong selector)", async () => {
    // A non-hermes config exists and is explicitly selected -- the resolved
    // platform is knowably wrong, so this must still refuse loudly rather
    // than silently proceeding as a plain cooperative wrap.
    const cursorDir = join(tmpHome, ".cursor");
    await mkdir(cursorDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(cursorDir, "mcp.json"));

    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    const startDashboard = vi.fn();
    await expect(
      runWrap(
        options({ cursor: true, exclusiveEgress: true }),
        { runAutoProvisionForWrap, startDashboard },
      ),
    ).rejects.toThrow("process.exit:2");

    expect(exitSpy).toHaveBeenCalledWith(2);
    const printed = stderrSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("--exclusive-egress");
    expect(printed).toContain("cursor");
    expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
    expect(startDashboard).not.toHaveBeenCalled();
  });

  it("does NOT refuse --hermes --exclusive-egress (a supported selector was given)", async () => {
    installHermesParityHook(agreeingHermesParity);
    try {
      const hermesDir = join(tmpHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));

      const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
      await expect(
        runWrap(
          options({ hermes: true, exclusiveEgress: true }),
          {
            runAutoProvisionForWrap,
            // Pin the resolved OS platform to "darwin" so this deterministically
            // exercises the non-refusal path regardless of the CI runner's
            // actual OS (the darwin-only gate is fix N1-3's own check, tested
            // separately below).
            osPlatform: () => "darwin",
            resolvePassphrase: async () => ({
              value: "test-passphrase",
              location: "test-keychain",
              source: "generated" as const,
            }),
          },
        ),
      ).resolves.toBeUndefined();

      // Reaches the real wrap flow -- the refusal did not fire.
      expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
      expect(exitSpy).not.toHaveBeenCalledWith(2);
    } finally {
      clearHermesParityHook();
    }
  });

  // FIX (N1-3 corrected, 2026-07-27): the actual bug -- a Hermes host with
  // NO `--hermes` flag at all (plain `sanctuary protect --exclusive-egress`,
  // relying on auto-detect, exactly as the drill record described) must
  // still reach the real wrap flow. The pre-fix guard keyed on the CLI hint
  // (`platformHint`, only set by an explicit --openclaw/--hermes/etc. flag)
  // rather than the platform `detectAgentConfigWithDiagnostics` actually
  // resolves, so it refused this case even though auto-provision would have
  // gone on to arm successfully.
  it("does NOT refuse --exclusive-egress when Hermes is auto-detected without --hermes", async () => {
    installHermesParityHook(agreeingHermesParity);
    try {
      const hermesDir = join(tmpHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));

      const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
      await expect(
        runWrap(
          options({ exclusiveEgress: true }),
          {
            runAutoProvisionForWrap,
            osPlatform: () => "darwin",
            resolvePassphrase: async () => ({
              value: "test-passphrase",
              location: "test-keychain",
              source: "generated" as const,
            }),
          },
        ),
      ).resolves.toBeUndefined();

      expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
      expect(exitSpy).not.toHaveBeenCalledWith(2);
    } finally {
      clearHermesParityHook();
    }
  });

  // FIX (N1-3 placement, 2026-07-27 harden-loop): a Hermes host whose ONLY
  // MCP-routing surface is `~/.hermes/config.yaml` (no legacy
  // `cli-config.json` -- a fresh v0.16.0 install, or any install that never
  // had the compat JSON written) must still reach the real wrap flow for
  // `--hermes --exclusive-egress`. Pre-fix, the refusal ran on the FIRST
  // `detectAgentConfigWithDiagnostics` call, before the fresh-config
  // bootstrap that writes the compat JSON and re-detects -- so `agentConfig`
  // was still undefined at the refusal, and it exited 2 telling the
  // operator to "re-run with --hermes" when they already had.
  it("does NOT refuse --hermes --exclusive-egress on a config.yaml-only Hermes host (no cli-config.json yet)", async () => {
    installHermesParityHook(agreeingHermesParity);
    try {
      const hermesDir = join(tmpHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      // Only the authoritative YAML surface exists; no cli-config.json.
      await writeFile(
        join(hermesDir, "config.yaml"),
        "mcp_servers:\n  weather:\n    command: uvx\n    args:\n      - mcp-weather\n",
      );

      const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
      await expect(
        runWrap(
          options({ hermes: true, exclusiveEgress: true }),
          {
            runAutoProvisionForWrap,
            osPlatform: () => "darwin",
            resolvePassphrase: async () => ({
              value: "test-passphrase",
              location: "test-keychain",
              source: "generated" as const,
            }),
          },
        ),
      ).resolves.toBeUndefined();

      // Reaches the real wrap flow -- the bootstrap ran and resolved a
      // hermes config before the refusal check, so it never fired.
      expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
      expect(exitSpy).not.toHaveBeenCalledWith(2);
    } finally {
      clearHermesParityHook();
    }
  });

  // FIX (N1-3 non-darwin gap, 2026-07-27 harden-loop): a resolved Hermes
  // config on a non-darwin host must ALSO refuse -- auto-provision itself
  // is darwin-only (`runAutoProvisionForWrap` in auto-provision.ts no-ops
  // silently on any other platform), so without this the CLI-level refusal
  // only closed the platform-selector door, leaving the OS door open: a
  // non-darwin Hermes host reached the real wrap flow, auto-provision armed
  // nothing, and `printWrapSuccess` still rendered a plain success banner
  // with no statement that exclusive egress armed nothing.
  it("refuses --hermes --exclusive-egress on a non-darwin host even though Hermes is the resolved platform", async () => {
    installHermesParityHook(agreeingHermesParity);
    try {
      const hermesDir = join(tmpHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));

      const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
      const startDashboard = vi.fn();
      await expect(
        runWrap(
          options({ hermes: true, exclusiveEgress: true }),
          { runAutoProvisionForWrap, startDashboard, osPlatform: () => "linux" },
        ),
      ).rejects.toThrow("process.exit:2");

      expect(exitSpy).toHaveBeenCalledWith(2);
      const printed = stderrSpy.mock.calls.flat().join("\n");
      expect(printed).toContain("--exclusive-egress");
      expect(printed).toContain("darwin-only");
      // Refuses BEFORE any state-changing wrap work, exactly like the
      // platform-selector refusal above.
      expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
      expect(startDashboard).not.toHaveBeenCalled();
    } finally {
      clearHermesParityHook();
    }
  });

  // FIX (harden-loop, dry-run gap): on a FRESH host (no existing
  // ~/.hermes/cli-config.json), the exclusive-egress refusal used to live
  // only inside the fresh-config bootstrap's `options.dryRun` early return
  // as a check against the resolved `agentConfig?.platform` -- which stays
  // `undefined` on a dry run, since a dry run never writes the bootstrap
  // file or re-detects. Without this fix, `--dry-run` silently omitted the
  // refusal a real run would give, printing a clean "Would bootstrap.../Dry
  // run. No changes made." for a command that refuses when actually run.
  it("refuses --hermes --exclusive-egress --dry-run on a fresh (no-config) non-darwin host, instead of silently reporting a clean dry-run plan", async () => {
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    const startDashboard = vi.fn();
    await expect(
      runWrap(
        options({ hermes: true, exclusiveEgress: true, dryRun: true }),
        { runAutoProvisionForWrap, startDashboard, osPlatform: () => "linux" },
      ),
    ).rejects.toThrow("process.exit:2");

    expect(exitSpy).toHaveBeenCalledWith(2);
    const printed = stderrSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("--exclusive-egress");
    expect(printed).toContain("darwin-only");
    // The refusal must preempt the dry-run's own "Would bootstrap.../Dry
    // run. No changes made." reporting, not run alongside or after it.
    expect(printed).not.toContain("Would bootstrap");
    expect(printed).not.toContain("Dry run. No changes made.");
    expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
    expect(startDashboard).not.toHaveBeenCalled();
  });

  // FIX (harden-loop, side-effect-before-refusal): the fresh-config
  // bootstrap wrote the compat JSON config to disk (and printed
  // "Bootstrapped a fresh config at ...") BEFORE the resolved-platform
  // refusal further down ever ran, so a refused, exit-2
  // `--exclusive-egress` command still left a stub config an operator
  // never asked for at the canonical path. Assert the refusal now fires
  // before that write.
  it("refuses --hermes --exclusive-egress on a fresh (no-config) non-darwin host WITHOUT bootstrapping a config file first", async () => {
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    const startDashboard = vi.fn();
    await expect(
      runWrap(
        options({ hermes: true, exclusiveEgress: true }),
        { runAutoProvisionForWrap, startDashboard, osPlatform: () => "linux" },
      ),
    ).rejects.toThrow("process.exit:2");

    expect(exitSpy).toHaveBeenCalledWith(2);
    const printed = stderrSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("--exclusive-egress");
    expect(printed).toContain("darwin-only");
    expect(printed).not.toContain("Bootstrapped a fresh config");
    await expect(
      stat(join(tmpHome, ".hermes", "cli-config.json")),
    ).rejects.toThrow();
    expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
    expect(startDashboard).not.toHaveBeenCalled();
  });
});
