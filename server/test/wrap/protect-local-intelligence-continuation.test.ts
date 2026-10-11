/**
 * CLI continuation semantics for explicit local-intelligence outcomes.
 *
 * The tests drive `runWrap` instead of a mock wrapper so the assertions cover
 * the same post-wrap sequencing that the CLI uses before it chooses an exit.
 */

import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
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

  it("preserves an existing specific refusal exit code", () => {
    process.exitCode = AGENT_GUIDED_NOT_ARMED_EXIT_CODE;

    expect(
      wrapCliRefusalExitCode(new ExplicitLocalIntelligenceRefusal("non_tty")),
    ).toBe(AGENT_GUIDED_NOT_ARMED_EXIT_CODE);
  });
});
