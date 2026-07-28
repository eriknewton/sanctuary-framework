import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const castleWallMocks = vi.hoisted(() => {
  const stop = vi.fn(async () => undefined);
  return {
    runProvisionPin: vi.fn(async () => 0),
    stop,
    startMacOSCastleWallDaemon: vi.fn(async () => ({
      stop,
    })),
  };
});

vi.mock("../../src/cli/castle-wall.js", () => ({
  runProvisionPin: castleWallMocks.runProvisionPin,
}));

vi.mock("../../src/castle-wall/runtime/index.js", () => ({
  startMacOSCastleWallDaemon: castleWallMocks.startMacOSCastleWallDaemon,
  isLinuxProducerSignedActivationRequested: () => false,
}));

import {
  __processShutdownCleanupCountForTest,
  __resetProcessShutdownStateForTest,
  handleProcessShutdownSignal,
  runWrap,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { AutoProvisionSummary } from "../../src/wrap/auto-provision.js";
import {
  agreeingHermesParity,
  clearHermesParityHook,
  installHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

function deferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value?: T | PromiseLike<T>) => void;
} {
  let resolve!: (value?: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe("protect --hermes --no-dashboard transient Castle Wall cleanup", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalPassphrase: string | undefined;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-no-dashboard-daemon-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    process.env.SANCTUARY_PASSPHRASE = "test-passphrase";
    installHermesParityHook(agreeingHermesParity);
    vi.spyOn(console, "error").mockImplementation(() => {});
    castleWallMocks.runProvisionPin.mockClear();
    castleWallMocks.stop.mockClear();
    castleWallMocks.startMacOSCastleWallDaemon.mockClear();
    castleWallMocks.startMacOSCastleWallDaemon.mockResolvedValue({
      stop: castleWallMocks.stop,
    });

    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));
  });

  afterEach(async () => {
    __resetProcessShutdownStateForTest();
    vi.restoreAllMocks();
    clearHermesParityHook();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    if (originalPassphrase === undefined) delete process.env.SANCTUARY_PASSPHRASE;
    else process.env.SANCTUARY_PASSPHRASE = originalPassphrase;
    await rm(tmpHome, { recursive: true, force: true });
  });

  it("F10: stops the transient daemon on normal --no-dashboard exit even when provisioning refused before install-boot", async () => {
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "root-check",
        reason: "auto-provisioning requires root; re-run with sudo.",
        rolledBack: false,
        rehomeAttempted: false,
      },
    }));
    const deps: RunWrapDeps = {
      runAutoProvisionForWrap,
      startDashboard: vi.fn(),
      openBrowser: vi.fn(async () => undefined),
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
    };

    await runWrap({ hermes: true, noOpen: true, noDashboard: true }, deps);

    expect(castleWallMocks.startMacOSCastleWallDaemon).toHaveBeenCalledTimes(1);
    expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
    expect(castleWallMocks.stop).toHaveBeenCalledTimes(1);
  });

  it("registers the --no-dashboard audit flush during setup, then unregisters it after the explicit flush", async () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((
      _code?: number,
    ) => undefined) as never);
    const flushSpy = vi.spyOn(AuditLog.prototype, "flush");
    const registeredFlushEntered = deferred();
    const releaseRegisteredFlush = deferred();
    let flushCalls = 0;
    let blockedRegisteredFlush = false;
    flushSpy.mockImplementation(async function (
    ): Promise<void> {
      flushCalls += 1;
      if (!blockedRegisteredFlush && __processShutdownCleanupCountForTest() > 0) {
        blockedRegisteredFlush = true;
        registeredFlushEntered.resolve();
        await releaseRegisteredFlush.promise;
      }
    });
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "root-check",
        reason: "auto-provisioning requires root; re-run with sudo.",
        rolledBack: false,
        rehomeAttempted: false,
      },
    }));
    const deps: RunWrapDeps = {
      runAutoProvisionForWrap,
      startDashboard: vi.fn(),
      openBrowser: vi.fn(async () => undefined),
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
    };

    const run = runWrap({ hermes: true, noOpen: true, noDashboard: true }, deps);
    await registeredFlushEntered.promise;
    const flushCallsBeforeSignal = flushCalls;

    await handleProcessShutdownSignal("SIGTERM");

    expect(exitSpy).toHaveBeenCalledWith(143);
    expect(flushCalls).toBeGreaterThan(flushCallsBeforeSignal);

    releaseRegisteredFlush.resolve();
    await run;
    expect(__processShutdownCleanupCountForTest()).toBe(0);
  });
});
