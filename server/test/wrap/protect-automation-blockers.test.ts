/**
 * N1: three bounded automation-blocker fixes for `sanctuary protect`
 * (drill record 2026-07-26):
 *
 *   1. SIGINT/SIGTERM handlers must exit after cleanups run. Installing a
 *      signal listener suppresses Node's default "exit on signal" action;
 *      without an explicit `process.exit`, `sanctuary protect` and the
 *      standalone dashboard survived a plain `kill` and drills needed
 *      `kill -9`.
 *   2. When the operator declines the step-2 arm confirm, the flow must not
 *      fall through to the foreground dashboard serve -- the listening
 *      handle held the event loop open forever.
 *   3. `--exclusive-egress` / `--provision-agent-account` without a
 *      provisionable agent selector (Hermes-only today) must refuse loudly
 *      and exit 2, not silently arm nothing.
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
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
  agreeingHermesParity,
  installHermesParityHook,
  clearHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

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
});

// ── Fix 2: declined arm must exit, not hold the dashboard open ──────────

describe("runWrap: declined step-2 arm confirm exits instead of holding the dashboard open", () => {
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

  it("exits 0, stops the already-started dashboard, and points at `sanctuary dashboard` -- does not hold the event loop open", async () => {
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
    ).rejects.toThrow("process.exit:0");

    expect(stopSpy).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(0);
    const printed = stderrSpy.mock.calls.flat().join("\n");
    expect(printed).toMatch(/sanctuary dashboard/);
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
});
