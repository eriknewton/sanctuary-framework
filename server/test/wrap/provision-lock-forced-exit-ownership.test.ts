import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { access, cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const lockMock = vi.hoisted(() => ({
  path: `/tmp/sanctuary-provision-lock-${process.pid}-${Date.now()}.lock`,
}));

vi.mock("../../src/castle-wall/provision/index.js", async (importActual) => {
  const actual = await importActual<typeof import("../../src/castle-wall/provision/index.js")>();
  return {
    ...actual,
    PROVISION_LOCK_PATH: lockMock.path,
  };
});

import {
  __resetProcessShutdownStateForTest,
  handleProcessShutdownSignal,
  runWrap,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";
import { runEgressGateRepairUnderProvisionLock } from "../../src/wrap/auto-provision.js";
import {
  agreeingHermesParity,
  clearHermesParityHook,
  installHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

describe("provision lock forced-exit ownership", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    await rm(lockMock.path, { force: true });
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code ?? 0}`);
    }) as never);
  });

  afterEach(async () => {
    __resetProcessShutdownStateForTest();
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
    await rm(lockMock.path, { force: true });
  });

  it("releases its own acquired provision lock via the ownership-tracked exit listener", async () => {
    const beforeExitListeners = new Set(process.listeners("exit"));

    const result = await runEgressGateRepairUnderProvisionLock(
      async () => {
        expect(await exists(lockMock.path)).toBe(true);
        const ownedExitListeners = process
          .listeners("exit")
          .filter((listener) => !beforeExitListeners.has(listener));
        expect(ownedExitListeners.length).toBeGreaterThan(0);

        for (const listener of ownedExitListeners) {
          (listener as (code?: number) => void)(0);
        }

        expect(await exists(lockMock.path)).toBe(false);
        return { kind: "repaired", generationId: "test-generation" } as never;
      },
      () => {},
    );

    expect(result.locked).toBe(true);
    expect(await exists(lockMock.path)).toBe(false);
  });

  it("leaves a foreign provision lock intact on forced exit when this process never acquired it", async () => {
    const tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-foreign-provision-lock-"));
    const originalHome = process.env.HOME;
    const originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    const originalIsTty = process.stdin.isTTY;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
    installHermesParityHook(agreeingHermesParity);
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));
    await writeFile(lockMock.path, "foreign");
    exitSpy.mockImplementation((() => undefined) as never);
    const deps: RunWrapDeps = {
      startDashboard: vi.fn(),
      openBrowser: vi.fn(async () => {}),
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
      runAutoProvisionForWrap: vi.fn(async (options) => {
        expect(await options.beforeFirstMutation?.()).toBe(true);
        await handleProcessShutdownSignal("SIGTERM");
        await handleProcessShutdownSignal("SIGINT");
        return { ran: true };
      }),
    };

    try {
      await runWrap({ hermes: true, noOpen: true, noDashboard: true }, deps);

      expect(exitSpy).toHaveBeenCalledWith(143);
      expect(await exists(lockMock.path)).toBe(true);
    } finally {
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
    }
  });
});
