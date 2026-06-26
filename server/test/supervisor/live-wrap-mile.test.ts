/**
 * Phase S1 — LIVE wrap-launch mile (custody-hold + teardown via real runWrap).
 *
 * The hermetic A1 legs (#527) proved the supervisor MACHINERY against a stub
 * `wrap` that read its key and exited 2. This file proves the LIVE mile that
 * replaced that exit-2 stub: a supervised launch now threads the supervisor's
 * raw fortress master into the REAL `runWrap`, which adopts it through the
 * production custody path (`establishSupervisedWrapCustody`), reaches a
 * held-custody state, and zeroes the master on teardown.
 *
 * Hermetic + platform-unconditional by construction: it drives `runWrap`
 * IN-PROCESS with `--no-dashboard` and an injected dashboard/passphrase seam,
 * a temp HOME + temp fortress, and no Castle Wall / keychain / live HTTP. The
 * heavy live dashboard+enforcement boot is exactly what the Erik-present
 * signing-host drill proves (and depends on macOS arming, so CI cannot assert
 * it). What CI asserts here is the wiring that replaced the stub:
 *   1. a supervised launch adopts custody from the injected master WITHOUT
 *      resolving or deriving a passphrase (custody-hold via the new path);
 *   2. the adoption is audited (`custody_supervised_unlock`) so the dashboard
 *      can read held custody;
 *   3. the long-running wrap registers the agent + rewrites the harness config
 *      exactly as the interactive path does;
 *   4. a WRONG master FAILS CLOSED (process.exit(2)), never booting on a
 *      fallback credential, and zeroes the injected master on the refusal;
 *   5. the master buffer is zeroed on SIGTERM/exit teardown (no residency).
 *
 * The real over-fd spawn handoff (key never in env/argv) is covered by
 * `spawn-launcher.test.ts`; this file covers the consumer side that handoff
 * now feeds.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseWrapArgs,
  runWrap,
  type DashboardStarter,
  type RunWrapDeps,
  type WrapOptions,
} from "../../src/wrap/cli.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import { establishWrapCustody } from "../../src/wrap/custody-flow.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { readPersistedLocalAgents } from "../../src/hub/agent-registry-persistence.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

describe("Phase S1 live wrap-launch mile (custody-hold + teardown)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalPassphrase: string | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-s1-livemile-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    // A supervised launch has NO passphrase; make sure the env one cannot leak in.
    delete process.env.SANCTUARY_PASSPHRASE;
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    if (originalPassphrase === undefined) delete process.env.SANCTUARY_PASSPHRASE;
    else process.env.SANCTUARY_PASSPHRASE = originalPassphrase;
    // Drop any SIGTERM/exit teardown listeners this test installed via runWrap
    // so they cannot fire against a later test's buffers.
    process.removeAllListeners("SIGTERM");
    process.removeAllListeners("SIGINT");
    vi.restoreAllMocks();
    await rm(tmpHome, { recursive: true, force: true });
  });

  function storagePath(): string {
    return process.env.SANCTUARY_STORAGE_PATH!;
  }

  /** A dashboard seam that records spawns (live mile uses --no-dashboard, so it should stay 0). */
  function deps(over?: Partial<RunWrapDeps>): {
    runWrapDeps: RunWrapDeps;
    passphraseResolveCount: { value: number };
    dashboardSpawnCount: { value: number };
  } {
    const passphraseResolveCount = { value: 0 };
    const dashboardSpawnCount = { value: 0 };
    const startDashboard: DashboardStarter = async (startOpts) => {
      dashboardSpawnCount.value += 1;
      return {
        url: `http://127.0.0.1:${startOpts.port}`,
        port: startOpts.port,
        host: "127.0.0.1",
        mode: "co-located",
        stop: async () => {},
        setV11Bindings: () => {},
        setV11LoopbackAutoAuth: () => {},
        updateSources: () => {},
      } as unknown as DashboardHandle;
    };
    return {
      runWrapDeps: {
        startDashboard,
        openBrowser: async () => {},
        // CRITICAL: a supervised launch must NEVER call the passphrase resolver.
        // If it does, count it; the test asserts the count stays 0.
        resolvePassphrase: async () => {
          passphraseResolveCount.value += 1;
          return { value: "should-never-be-used", location: "x", source: "generated" as const };
        },
        ...over,
      },
      passphraseResolveCount,
      dashboardSpawnCount,
    };
  }

  async function installFixture(relPath: string, fixtureName: string): Promise<string> {
    const target = join(tmpHome, relPath);
    await mkdir(dirname(target), { recursive: true });
    await cp(join(fixturesDir, fixtureName), target);
    return target;
  }

  /** Establish an envelope fortress (the way the dashboard would have) and return its master. */
  async function seedEnvelopeFortress(): Promise<Uint8Array> {
    const result = await establishWrapCustody({
      storagePath: storagePath(),
      passphrase: "operator-passphrase",
      interactive: false,
    });
    // Return a COPY: runWrap adopts + owns + zeroes the buffer it is handed,
    // mirroring the over-fd handoff (the supervisor keeps its own resident copy).
    return Uint8Array.from(result.masterKey);
  }

  it("captures parse: a supervised dispatch forces --no-open and threads the master", () => {
    // The cli.ts dispatch sets opts.noOpen and passes deps.supervisedMaster; the
    // parse itself just confirms the wrap args parse cleanly for the supervised path.
    const opts = parseWrapArgs(["--claude-code", "--no-dashboard"]);
    expect(opts.claudeCode).toBe(true);
    expect(opts.noDashboard).toBe(true);
  });

  it("HOLDS CUSTODY from the supervisor master without ever resolving a passphrase", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    const master = await seedEnvelopeFortress();
    const { runWrapDeps, passphraseResolveCount, dashboardSpawnCount } = deps();

    await runWrap(
      { claudeCode: true, noDashboard: true } as WrapOptions,
      { ...runWrapDeps, supervisedMaster: master },
    );

    // Custody-hold via the supervised path: the adoption is audited.
    const storage = new FilesystemStorage(join(storagePath(), "state"));
    const auditLog = new AuditLog(storage, master);
    const { entries } = await auditLog.query({ layer: "l2", limit: 100 });
    expect(entries.map((e) => e.operation)).toContain("custody_supervised_unlock");

    // The supervised launch NEVER resolved/derived a passphrase.
    expect(passphraseResolveCount.value).toBe(0);
    // --no-dashboard: no dashboard server spawned.
    expect(dashboardSpawnCount.value).toBe(0);

    // The agent was registered + the harness config rewritten, same as interactive.
    const persisted = readPersistedLocalAgents(storagePath());
    expect(persisted).toHaveLength(1);
    expect(persisted[0]!.harness).toBe("claude_code");
    const rewritten = JSON.parse(
      await readFile(join(tmpHome, ".claude.json"), "utf-8"),
    ) as { mcpServers?: Record<string, unknown> };
    expect(rewritten.mcpServers?.sanctuary).toBeDefined();
  });

  it("ZEROES the supervisor master on SIGTERM teardown (no residency)", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    const master = await seedEnvelopeFortress();
    // Sanity: a freshly-seeded master is non-zero.
    expect(master.some((b) => b !== 0)).toBe(true);

    await runWrap(
      { claudeCode: true, noDashboard: true } as WrapOptions,
      { ...deps().runWrapDeps, supervisedMaster: master },
    );

    // The runWrap supervised path installs SIGTERM/exit teardown that zeroes the
    // master. Drive teardown by emitting SIGTERM (the same signal the supervisor
    // sends on stop) and confirm the buffer is wiped.
    process.emit("SIGTERM");
    // The teardown handler runs synchronously on emit.
    expect([...master].every((b) => b === 0)).toBe(true);
  });

  it("FAILS CLOSED on a WRONG master: process.exit(2), no custody, master zeroed", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await seedEnvelopeFortress(); // establish the real envelope...
    const wrongMaster = new Uint8Array(32).fill(9); // ...but supervise with the wrong key.

    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: number | string | null | undefined): never => {
        throw new Error(`process.exit:${code}`);
      });

    await expect(
      runWrap(
        { claudeCode: true, noDashboard: true } as WrapOptions,
        { ...deps().runWrapDeps, supervisedMaster: wrongMaster },
      ),
    ).rejects.toThrow("process.exit:2");

    // Fail-closed residency: the rejected supervised launch zeroed the master.
    expect([...wrongMaster].every((b) => b === 0)).toBe(true);

    // No agent was registered (we never reached the long-running body).
    const persisted = readPersistedLocalAgents(storagePath());
    expect(persisted).toHaveLength(0);

    exitSpy.mockRestore();
  });
});
