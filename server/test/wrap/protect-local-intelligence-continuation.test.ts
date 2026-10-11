/**
 * CLI continuation semantics for explicit local-intelligence outcomes.
 *
 * The tests drive `runWrap` instead of a mock wrapper so the assertions cover
 * the same post-wrap sequencing that the CLI uses before it chooses an exit.
 */

import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const castleWallMocks = vi.hoisted(() => {
  const stop = vi.fn(async () => undefined);
  return {
    stop,
    startMacOSCastleWallDaemon: vi.fn(async () => ({ stop })),
  };
});

vi.mock("../../src/castle-wall/runtime/index.js", () => ({
  startMacOSCastleWallDaemon: castleWallMocks.startMacOSCastleWallDaemon,
  isLinuxProducerSignedActivationRequested: () => false,
}));

import { AuditLog } from "../../src/operational/audit-log.js";
import { RUNTIME_FILE_NAME } from "../../src/cli/agents/runtime.js";
import {
  __resetProcessShutdownStateForTest,
  ExplicitLocalIntelligenceRefusal,
  runWrap,
  wrapCliRefusalExitCode,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";
import type { AutoProvisionSummary } from "../../src/wrap/auto-provision.js";
import {
  agreeingHermesParity,
  clearHermesParityHook,
  installHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");
const AGENT_GUIDED_NOT_ARMED_EXIT_CODE = 2;
const OTHER_LIVE_PID = process.ppid;

async function writeRuntimeRecord(
  storagePath: string,
  port: number,
): Promise<void> {
  await mkdir(storagePath, { recursive: true });
  await writeFile(
    join(storagePath, RUNTIME_FILE_NAME),
    JSON.stringify({
      version: "9.9.9-test",
      pid: OTHER_LIVE_PID,
      started_at: new Date().toISOString(),
      dashboard_host: "127.0.0.1",
      dashboard_port: port,
      mode: "standalone",
    }),
  );
}

describe("runWrap explicit local-intelligence continuation", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalIsTty: boolean | undefined;
  let originalExitCode: string | number | null | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-li-continuation-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalIsTty = process.stdin.isTTY;
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    castleWallMocks.stop.mockClear();
    castleWallMocks.startMacOSCastleWallDaemon.mockClear();
    castleWallMocks.startMacOSCastleWallDaemon.mockResolvedValue({
      stop: castleWallMocks.stop,
    });
    installHermesParityHook(agreeingHermesParity);
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    __resetProcessShutdownStateForTest();
    stderrSpy.mockRestore();
    vi.restoreAllMocks();
    clearHermesParityHook();
    process.exitCode = originalExitCode;
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
      openBrowser: vi.fn(async () => {}),
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "stored-passphrase",
      }),
      checkPinResolvability: async () => "resolvable",
      ...overrides,
    };
  }

  it("continues through agent provisioning before surfacing a non-interactive explicit refusal", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({
      ran: true,
      outcome: {
        kind: "skipped-non-tty-cooperative-only",
        reason: "test non-interactive provisioning skip",
      },
    }));

    await expect(
      runWrap(
        {
          hermes: true,
          noOpen: true,
          noDashboard: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap,
          runLocalIntelligenceSetup: async () => ({ kind: "refused", reason: "non_tty" }),
        }),
      ),
    ).rejects.toThrow("--provision-local-intelligence was explicitly requested");

    expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
  });

  it("flushes the no-dashboard audit log after provisioning before surfacing an explicit refusal", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    const order: string[] = [];
    const originalFlush = AuditLog.prototype.flush;
    vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (
      this: AuditLog,
    ): Promise<void> {
      order.push("flush");
      return originalFlush.apply(this);
    });
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => {
      order.push("auto-provision");
      return {
        ran: true,
        outcome: {
          kind: "skipped-non-tty-cooperative-only",
          reason: "test non-interactive provisioning skip",
        },
      };
    });

    await expect(
      runWrap(
        {
          hermes: true,
          noOpen: true,
          noDashboard: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap,
          runLocalIntelligenceSetup: async () => ({ kind: "refused", reason: "non_tty" }),
        }),
      ),
    ).rejects.toThrow("--provision-local-intelligence was explicitly requested");

    expect(order.lastIndexOf("flush")).toBeGreaterThan(order.indexOf("auto-provision"));
  });

  it("keeps the explicit refusal when the final pre-exit audit flush fails", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    let finalFlushShouldThrow = false;
    castleWallMocks.stop.mockImplementationOnce(async () => {
      finalFlushShouldThrow = true;
    });
    const flushError = new Error("synthetic flush failure");
    const originalFlush = AuditLog.prototype.flush;
    vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (
      this: AuditLog,
    ): Promise<void> {
      if (finalFlushShouldThrow) throw flushError;
      return originalFlush.apply(this);
    });

    let caught: unknown;
    try {
      await runWrap(
        {
          hermes: true,
          noOpen: true,
          noDashboard: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap: async () => ({
            ran: true,
            outcome: {
              kind: "skipped-non-tty-cooperative-only",
              reason: "test non-interactive provisioning skip",
            },
          }),
          runLocalIntelligenceSetup: async () => ({ kind: "refused", reason: "non_tty" }),
        }),
      );
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(ExplicitLocalIntelligenceRefusal);
    expect((caught as Error).message).toContain("Sanctuary protect refused");
    expect(wrapCliRefusalExitCode(caught as ExplicitLocalIntelligenceRefusal)).toBe(1);
    const stderr = stderrSpy.mock.calls.flat().join("\n");
    expect(stderr).toContain("audit log flush before local-intelligence refusal exit failed");
    expect(stderr).not.toContain("Sanctuary MCP Server failed to start");
  });

  it("finishes no-dashboard continuation before surfacing an unexpected explicit setup error", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    const localError = new TypeError("synthetic local-intelligence failure");
    const order: string[] = [];
    const originalFlush = AuditLog.prototype.flush;
    vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (
      this: AuditLog,
    ): Promise<void> {
      order.push("flush");
      return originalFlush.apply(this);
    });
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => {
      order.push("auto-provision");
      return {
        ran: true,
        outcome: {
          kind: "skipped-non-tty-cooperative-only",
          reason: "test non-interactive provisioning skip",
        },
      };
    });

    await expect(
      runWrap(
        {
          hermes: true,
          noOpen: true,
          noDashboard: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap,
          runLocalIntelligenceSetup: async () => {
            throw localError;
          },
        }),
      ),
    ).rejects.toBe(localError);

    expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
    expect(order.lastIndexOf("flush")).toBeGreaterThan(order.indexOf("auto-provision"));
    expect(castleWallMocks.stop).toHaveBeenCalledTimes(1);
  });

  it("keeps an interactive declined local-intelligence prompt on the normal dashboard path", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({
      ran: true,
      outcome: { kind: "declined-by-operator" },
    }));

    await expect(
      runWrap(
        {
          hermes: true,
          noOpen: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap,
          runLocalIntelligenceSetup: async () => ({ kind: "refused", reason: "declined" }),
          startOwnedDashboard: async () => ({ url: "http://127.0.0.1:3501", port: 3501 }),
          probeDashboardHealth: async () => false,
        }),
      ),
    ).resolves.toBeUndefined();

    expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
    expect(process.exitCode).toBeUndefined();
  });

  it("preserves an unexpected local-intelligence exception as the original error", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });

    await expect(
      runWrap(
        {
          hermes: true,
          noOpen: true,
          noDashboard: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runLocalIntelligenceSetup: async () => {
            throw new TypeError("synthetic local-intelligence failure");
          },
        }),
      ),
    ).rejects.toBeInstanceOf(TypeError);
  });

  it("treats a non-Error explicit setup throw as a failed protect run", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    const notThrown = Symbol("not-thrown");
    let caught: unknown = notThrown;

    try {
      await runWrap(
        {
          hermes: true,
          noOpen: true,
          noDashboard: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap: async () => ({
            ran: true,
            outcome: {
              kind: "skipped-non-tty-cooperative-only",
              reason: "test non-interactive provisioning skip",
            },
          }),
          runLocalIntelligenceSetup: async () => {
            throw undefined;
          },
        }),
      );
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeUndefined();
    expect(castleWallMocks.stop).toHaveBeenCalledTimes(1);
  });

  it("warns only that transient daemon stop confirmation failed before deferred exit", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    castleWallMocks.stop.mockRejectedValueOnce(new Error("synthetic stop failure"));

    await expect(
      runWrap(
        {
          hermes: true,
          noOpen: true,
          noDashboard: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap: async () => ({
            ran: true,
            outcome: {
              kind: "skipped-non-tty-cooperative-only",
              reason: "test non-interactive provisioning skip",
            },
          }),
          runLocalIntelligenceSetup: async () => ({ kind: "refused", reason: "non_tty" }),
        }),
      ),
    ).rejects.toBeInstanceOf(ExplicitLocalIntelligenceRefusal);

    const stderr = stderrSpy.mock.calls.flat().join("\n");
    expect(stderr).toContain(
      "could not confirm the transient Castle Wall daemon stopped before --no-dashboard exit",
    );
    expect(stderr).toContain("Check whether a transient daemon is still holding the fortress socket");
    expect(stderr).not.toContain("Stop the holding process");
  });

  it("warns only that dashboard-path transient daemon stop confirmation failed before deferred exit", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    castleWallMocks.stop.mockRejectedValueOnce(new Error("synthetic stop failure"));

    await expect(
      runWrap(
        {
          hermes: true,
          noOpen: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap: async () => ({ ran: true }),
          runLocalIntelligenceSetup: async () => ({ kind: "refused", reason: "pull_failed" }),
          startOwnedDashboard: async () => ({ url: "http://127.0.0.1:3501", port: 3501 }),
          probeDashboardHealth: async () => false,
        }),
      ),
    ).rejects.toBeInstanceOf(ExplicitLocalIntelligenceRefusal);

    const stderr = stderrSpy.mock.calls.flat().join("\n");
    expect(stderr).toContain(
      "could not confirm the transient Castle Wall daemon stopped before refusal exit",
    );
    expect(stderr).toContain("Check whether a transient daemon is still holding the fortress socket");
    expect(stderr).not.toContain("could not be stopped");
    expect(stderr).not.toContain("Stop the holding process");
  });

  it("keeps the deferred exit when transient daemon stop rejects without an Error object", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    const localError = new TypeError("synthetic local-intelligence failure");
    castleWallMocks.stop.mockRejectedValueOnce(undefined);

    await expect(
      runWrap(
        {
          hermes: true,
          noOpen: true,
          provisionLocalIntelligence: true,
        },
        deps({
          runAutoProvisionForWrap: async () => ({ ran: true }),
          runLocalIntelligenceSetup: async () => {
            throw localError;
          },
          startOwnedDashboard: async () => ({ url: "http://127.0.0.1:3501", port: 3501 }),
          probeDashboardHealth: async () => false,
        }),
      ),
    ).rejects.toBe(localError);

    expect(castleWallMocks.stop).toHaveBeenCalledTimes(1);
    const stderr = stderrSpy.mock.calls.flat().join("\n");
    expect(stderr).toContain(
      "could not confirm the transient Castle Wall daemon stopped before refusal exit",
    );
  });

  it("does not open or announce an owned dashboard before surfacing an explicit refusal", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    const openBrowser = vi.fn(async () => {});

    await expect(
      runWrap(
        {
          hermes: true,
          provisionLocalIntelligence: true,
        },
        deps({
          openBrowser,
          runAutoProvisionForWrap: async () => ({ ran: true }),
          runLocalIntelligenceSetup: async () => ({ kind: "refused", reason: "pull_failed" }),
          startOwnedDashboard: async () => ({ url: "http://127.0.0.1:3501", port: 3501 }),
          probeDashboardHealth: async () => false,
        }),
      ),
    ).rejects.toThrow("--provision-local-intelligence was explicitly requested");

    expect(openBrowser).not.toHaveBeenCalled();
    expect(stderrSpy.mock.calls.flat().join("\n")).not.toContain(
      "Sovereignty Dashboard running at",
    );
  });

  it("opens and reports a reused dashboard before surfacing an explicit refusal", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    const reusedDashboardPort = 3507;
    const reusedDashboardUrl = `http://127.0.0.1:${reusedDashboardPort}`;
    await writeRuntimeRecord(process.env.SANCTUARY_STORAGE_PATH!, reusedDashboardPort);
    const openBrowser = vi.fn(async () => {});
    const startOwnedDashboard = vi.fn(async () => ({
      url: "http://127.0.0.1:3501",
      port: 3501,
    }));

    await expect(
      runWrap(
        {
          hermes: true,
          provisionLocalIntelligence: true,
        },
        deps({
          openBrowser,
          runAutoProvisionForWrap: async () => ({ ran: true }),
          runLocalIntelligenceSetup: async () => ({ kind: "refused", reason: "pull_failed" }),
          startOwnedDashboard,
          probeDashboardHealth: async (url) => url === reusedDashboardUrl,
        }),
      ),
    ).rejects.toThrow("--provision-local-intelligence was explicitly requested");

    expect(startOwnedDashboard).not.toHaveBeenCalled();
    expect(openBrowser).toHaveBeenCalledWith(reusedDashboardUrl);
    const stderr = stderrSpy.mock.calls.flat().join("\n");
    expect(stderr).toContain("Sovereignty Dashboard already running at");
    expect(stderr).toContain(reusedDashboardUrl);
    expect(stderr).not.toContain("Dashboard unavailable in this run");
  });

  it("preserves an existing specific refusal exit code", () => {
    process.exitCode = AGENT_GUIDED_NOT_ARMED_EXIT_CODE;

    expect(
      wrapCliRefusalExitCode(new ExplicitLocalIntelligenceRefusal("non_tty")),
    ).toBe(AGENT_GUIDED_NOT_ARMED_EXIT_CODE);
  });
});
