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

import { runWrap, type RunWrapDeps } from "../../src/wrap/cli.js";
import type { AutoProvisionSummary } from "../../src/wrap/auto-provision.js";
import {
  agreeingHermesParity,
  clearHermesParityHook,
  installHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

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
    installHermesParityHook(agreeingHermesParity);
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
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
});
