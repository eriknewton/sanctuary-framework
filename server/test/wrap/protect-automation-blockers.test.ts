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

  it("exits with 130 (128 + SIGINT=2) on SIGINT", () => {
    handleProcessShutdownSignal("SIGINT");
    expect(exitSpy).toHaveBeenCalledWith(130);
  });

  it("exits with 143 (128 + SIGTERM=15) on SIGTERM", () => {
    handleProcessShutdownSignal("SIGTERM");
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

  it("exits with 130 (128 + SIGINT=2) on SIGINT", () => {
    handleStandaloneShutdownSignal("SIGINT");
    expect(exitSpy).toHaveBeenCalledWith(130);
  });

  it("exits with 143 (128 + SIGTERM=15) on SIGTERM", () => {
    handleStandaloneShutdownSignal("SIGTERM");
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

  beforeEach(() => {
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code ?? 0}`);
    }) as never);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
  });

  function options(extra: WrapOptions = {}): WrapOptions {
    return { noOpen: true, noDashboard: true, ...extra };
  }

  it("refuses --exclusive-egress alone (no agent selector) before any wrap work, exit code 2", async () => {
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({ ran: true }));
    const startDashboard = vi.fn();
    await expect(
      runWrap(options({ exclusiveEgress: true }), { runAutoProvisionForWrap, startDashboard }),
    ).rejects.toThrow("process.exit:2");

    expect(exitSpy).toHaveBeenCalledWith(2);
    const printed = stderrSpy.mock.calls.flat().join("\n");
    expect(printed).toContain("--exclusive-egress");
    expect(printed).toContain("--hermes");
    // Refuses BEFORE any wrap work: no config detection/rewrite, no
    // auto-provision, no dashboard start.
    expect(runAutoProvisionForWrap).not.toHaveBeenCalled();
    expect(startDashboard).not.toHaveBeenCalled();
  });

  it("refuses --provision-agent-account alone (no agent selector) before any wrap work, exit code 2", async () => {
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

  it("does NOT refuse --hermes --exclusive-egress (a supported selector was given)", async () => {
    const tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-exclusive-egress-hermes-"));
    const originalHome = process.env.HOME;
    const originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
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
      if (originalHome === undefined) delete process.env.HOME;
      else process.env.HOME = originalHome;
      if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
      else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
      await rm(tmpHome, { recursive: true, force: true });
    }
  });
});
