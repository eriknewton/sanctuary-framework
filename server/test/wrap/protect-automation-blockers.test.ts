/**
 * N1: three bounded automation-blocker fixes for `sanctuary protect`
 * (drill record 2026-07-26), fix 2 corrected 2026-07-27 (harden-loop):
 *
 *   1. SIGINT/SIGTERM handlers must exit after cleanups run, and a repeat
 *      non-provisioning signal must join the same cleanup instead of
 *      abandoning audit flush / Castle Wall teardown. During account
 *      provisioning only, the first signal is refused and the second forces
 *      exit with an honest partial-state warning.
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
import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  __resetProcessShutdownStateForTest,
  handleProcessShutdownSignal,
  registerProcessShutdownCleanup,
  renderAutoProvisionForcedExitWarning,
  renderAutoProvisionSignalRefusal,
  runWrap,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";
import {
  __registerStandaloneProcessCleanupForTest,
  __resetStandaloneShutdownStateForTest,
  handleStandaloneShutdownSignal,
} from "../../src/dashboard-standalone.js";
import type { AutoProvisionSummary } from "../../src/wrap/auto-provision.js";
import {
  agreeingHermesParity,
  installHermesParityHook,
  clearHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");
const wrapCliModuleUrl = pathToFileURL(join(__dirname, "..", "..", "src", "wrap", "cli.ts")).href;

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

async function runNodeSignalScript(script: string): Promise<{
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}> {
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
    cwd: join(__dirname, "..", ".."),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolve({ code, signal, stdout, stderr });
    });
  });
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
    __resetProcessShutdownStateForTest();
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

  it("an isolated real SIGTERM outside the provisioning window awaits registered cleanups before exit", async () => {
    const result = await runNodeSignalScript(`
      const {
        installProcessShutdownListeners,
        registerProcessShutdownCleanup,
      } = await import(${JSON.stringify(wrapCliModuleUrl)});
      installProcessShutdownListeners();
      registerProcessShutdownCleanup(async () => {
        console.log("cleanup-started");
        await new Promise((resolve) => setTimeout(resolve, 30));
        console.log("cleanup-finished");
      });
      process.kill(process.pid, "SIGTERM");
      setTimeout(() => {
        console.log("watchdog-timeout");
        process.exit(99);
      }, 1000);
    `);

    // Fails if the refuse-then-force provisioning rule is applied globally:
    // the child exits before the async cleanup reaches its second print.
    expect(result.code).toBe(143);
    expect(result.stdout).toContain("cleanup-started");
    expect(result.stdout).toContain("cleanup-finished");
    expect(result.stdout).not.toContain("watchdog-timeout");
  });

  it("repeat non-provisioning signals still await the same in-flight cleanup before exit", async () => {
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
      const second = handleProcessShutdownSignal("SIGINT");
      await sleepMs(25);

      // Fails if the provisioning-only force-exit rule leaks into the normal
      // cleanup path: the second signal exits immediately and abandons the
      // audit flush / Castle Wall teardown represented by finishCleanup.
      expect(cleanupSettled).toBe(false);
      expect(exitSpy).not.toHaveBeenCalled();
      expect(stderrSpy).not.toHaveBeenCalled();

      finishCleanup.resolve();
      await Promise.all([first, second]);
      expect(cleanupSettled).toBe(true);
      expect(exitSpy).toHaveBeenCalledWith(143);
      expect(exitSpy).toHaveBeenCalledTimes(1);
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

describe("runWrap: signals during in-flight provisioning refuse once, then force exit", () => {
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
    __resetProcessShutdownStateForTest();
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

  function neverSettlingProvisionRunner(): {
    entered: Promise<void>;
    finish: () => void;
    mutationStarted: () => boolean;
    runAutoProvisionForWrap: RunWrapDeps["runAutoProvisionForWrap"];
  } {
    const entered = deferred<void>();
    const finishProvision = deferred<void>();
    let finished = false;
    let started = false;
    return {
      entered: entered.promise,
      finish: () => {
        if (finished) return;
        finished = true;
        finishProvision.resolve();
      },
      mutationStarted: () => started,
      runAutoProvisionForWrap: vi.fn(async (options): Promise<AutoProvisionSummary> => {
        const opened = (await options.beforeFirstMutation?.()) ?? true;
        if (!opened) {
          return {
            ran: true,
            outcome: {
              kind: "aborted",
              stage: "shutdown-in-flight",
              reason:
                "shutdown was already in flight before the first provisioning mutation; no account, re-home, or Castle Wall changes were made by provisioning.",
              rolledBack: false,
              rehomeAttempted: false,
            },
          };
        }
        started = true;
        entered.resolve();
        await finishProvision.promise;
        return { ran: true, outcome: { kind: "armed", uid: 503 } };
      }),
    };
  }

  it("a first SIGTERM during runWrap provisioning is refused, then honored after provisioning closes", async () => {
    const provision = neverSettlingProvisionRunner();
    const runPromise = runWrap(
      { hermes: true, noOpen: true, noDashboard: true },
      deps({ runAutoProvisionForWrap: provision.runAutoProvisionForWrap }),
    );

    try {
      await provision.entered;
      await handleProcessShutdownSignal("SIGTERM");
      await sleepMs(25);

      // Fails when reverted to the rollback-coordination design: the first
      // signal starts shutdown cleanup and exits instead of refusing.
      expect(exitSpy).not.toHaveBeenCalled();
      expect(stderrSpy.mock.calls.flat().join("\n")).toContain(
        renderAutoProvisionSignalRefusal("SIGTERM"),
      );

      provision.finish();
      await runPromise;
      expect(exitSpy).toHaveBeenCalledWith(143);
    } finally {
      provision.finish();
      await runPromise.catch(() => undefined);
    }
  });

  it("a second SIGTERM during provisioning exits promptly without waiting for provisioning", async () => {
    const provision = neverSettlingProvisionRunner();
    const runPromise = runWrap(
      { hermes: true, noOpen: true, noDashboard: true },
      deps({ runAutoProvisionForWrap: provision.runAutoProvisionForWrap }),
    ).catch(() => undefined);

    try {
      await provision.entered;
      await handleProcessShutdownSignal("SIGTERM");
      await vi.waitFor(() =>
        expect(stderrSpy.mock.calls.flat().join("\n")).toContain(
          renderAutoProvisionSignalRefusal("SIGTERM"),
        ),
      );

      await handleProcessShutdownSignal("SIGTERM");
      await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(143), { timeout: 250 });

      // Fails if the non-provisioning latch is reused here: the second signal
      // waits for the never-settling provisioning promise and does not exit.
      expect(stderrSpy.mock.calls.flat().join("\n")).toContain(
        renderAutoProvisionForcedExitWarning("SIGTERM"),
      );
    } finally {
      provision.finish();
      await runPromise;
    }
  });

  it("a SIGTERM before the first provisioning mutation takes the normal shutdown path, not the partial-state refusal", async () => {
    const preMutationEntered = deferred<void>();
    const finishRunner = deferred<void>();
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => {
      preMutationEntered.resolve();
      await finishRunner.promise;
      return { ran: true };
    });
    const runPromise = runWrap(
      { hermes: true, noOpen: true, noDashboard: true },
      deps({ runAutoProvisionForWrap }),
    );

    try {
      await preMutationEntered.promise;
      await handleProcessShutdownSignal("SIGTERM");

      expect(exitSpy).toHaveBeenCalledWith(143);
      expect(stderrSpy.mock.calls.flat().join("\n")).not.toContain(
        "half-provisioned",
      );
      expect(stderrSpy.mock.calls.flat().join("\n")).not.toContain(
        "account provisioning is mid-flight",
      );
    } finally {
      finishRunner.resolve();
      await runPromise.catch(() => undefined);
    }
  });

  it("the forced-exit warning is honest about residual state and never claims rollback restored anything", async () => {
    const warning = renderAutoProvisionForcedExitWarning("SIGTERM");

    expect(warning).toContain("rollback did NOT run");
    expect(warning).toContain("machine may be in a partial state");
    expect(warning).toContain("audit trail may be incomplete");
    expect(warning).toContain("Castle Wall teardown did not run");
    expect(warning).toContain("filter_stopped close record may be missing");
    expect(warning).toContain("sudo sanctuary protect --hermes --provision-agent-account");
    expect(warning).toContain("sudo sanctuary castle-wall disable");
    expect(warning).not.toMatch(/fast-disarmed|rollback ran|rollback was observed|restored/i);
  });

  it("exclusive-egress signal recovery names the repair verb and stand-down acknowledgement", () => {
    const warning = renderAutoProvisionForcedExitWarning("SIGTERM", { exclusiveEgress: true });

    expect(warning).toContain("sudo sanctuary protect --repair-egress-gate --stand-down-agent");
    expect(warning).toContain("sudo sanctuary castle-wall disable");
    expect(warning).not.toContain("sudo sanctuary protect --hermes --provision-agent-account");
  });

  it("an isolated real kill during provisioning is deferred and exits after provisioning closes", async () => {
    const result = await runNodeSignalScript(`
      const {
        runWrap,
      } = await import(${JSON.stringify(wrapCliModuleUrl)});
      const { mkdir, cp, mkdtemp } = await import("node:fs/promises");
      const { tmpdir } = await import("node:os");
      const { join } = await import("node:path");
      const tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-real-deferred-signal-"));
      process.env.HOME = tmpHome;
      process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
      Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
      const hermesDir = join(tmpHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      await cp(${JSON.stringify(join(fixturesDir, "hermes.json"))}, join(hermesDir, "cli-config.json"));
      const runPromise = runWrap(
        { hermes: true, noOpen: true, noDashboard: true },
        {
          startDashboard: async () => { throw new Error("dashboard should not start"); },
          openBrowser: async () => {},
          resolvePassphrase: async () => ({ value: "test-passphrase", location: "test-keychain", source: "generated" }),
          runAutoProvisionForWrap: async (options) => {
            if (!await options.beforeFirstMutation()) {
              console.log("mutation-blocked");
              return { ran: true };
            }
            console.log("mutation-entered");
            process.kill(process.pid, "SIGTERM");
            await new Promise((resolve) => setTimeout(resolve, 30));
            console.log("provisioning-finished");
            return { ran: true, outcome: { kind: "armed", uid: 503 } };
          },
        },
      );
      setTimeout(() => process.exit(99), 10_000);
      await runPromise;
    `);

    expect(result.code).toBe(143);
    expect(result.stdout).toContain("mutation-entered");
    expect(result.stdout).toContain("provisioning-finished");
    expect(result.stderr).toContain(renderAutoProvisionSignalRefusal("SIGTERM"));
  });

  it("an isolated real second SIGTERM during provisioning exits promptly", async () => {
    const result = await runNodeSignalScript(`
      const {
        __setAutoProvisionMutationInFlightForTest,
        installProcessShutdownListeners,
      } = await import(${JSON.stringify(wrapCliModuleUrl)});
      process.env.NODE_ENV = "test";
      installProcessShutdownListeners();
      __setAutoProvisionMutationInFlightForTest({ inFlight: true });
      process.kill(process.pid, "SIGTERM");
      setTimeout(() => {
        console.log("sending-second");
        process.kill(process.pid, "SIGTERM");
      }, 30);
      setTimeout(() => process.exit(99), 1000);
    `);

    // Fails if the provisioning repeat signal joins cleanup or waits for the
    // still-in-flight provisioning work instead of forcing exit.
    expect(result.code).toBe(143);
    expect(result.stdout).toContain("sending-second");
    expect(result.stderr).toContain(renderAutoProvisionSignalRefusal("SIGTERM"));
    expect(result.stderr).toContain(renderAutoProvisionForcedExitWarning("SIGTERM"));
  });

  it("shutdown already in flight prevents the provisioning mutation window from opening", async () => {
    const cleanupEntered = deferred<void>();
    const finishCleanup = deferred<void>();
    registerProcessShutdownCleanup(async () => {
      cleanupEntered.resolve();
      await finishCleanup.promise;
    });
    const shutdownPromise = handleProcessShutdownSignal("SIGTERM");
    await cleanupEntered.promise;

    const provision = neverSettlingProvisionRunner();
    const runPromise = runWrap(
      { hermes: true, noOpen: true, noDashboard: true },
      deps({ runAutoProvisionForWrap: provision.runAutoProvisionForWrap }),
    );

    try {
      await vi.waitFor(() => expect(provision.runAutoProvisionForWrap).toHaveBeenCalled(), {
        timeout: 10_000,
      });
      expect(exitSpy).not.toHaveBeenCalled();
      expect(stderrSpy.mock.calls.flat().join("\n")).toContain(
        "automatic account provisioning did not start because shutdown is already in flight",
      );
      expect(provision.mutationStarted()).toBe(false);

      finishCleanup.resolve();
      provision.finish();
      await Promise.all([shutdownPromise, runPromise]);
      expect(exitSpy).toHaveBeenCalledWith(143);
    } finally {
      provision.finish();
      finishCleanup.resolve();
      await Promise.allSettled([shutdownPromise, runPromise]);
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
    __resetStandaloneShutdownStateForTest();
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

  it("a cleanup registered while standalone shutdown is draining is still awaited before exit", async () => {
    let firstSettled = false;
    let lateSettled = false;
    __registerStandaloneProcessCleanupForTest(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      firstSettled = true;
    });

    const signalPromise = handleStandaloneShutdownSignal("SIGTERM");
    __registerStandaloneProcessCleanupForTest(async () => {
      lateSettled = true;
    });
    await signalPromise;

    expect(firstSettled).toBe(true);
    expect(lateSettled).toBe(true);
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
