/**
 * `sanctuary intelligence config-reset`: the recovery verb for an unreadable
 * local-intelligence config record.
 *
 * Each test seeds a REAL custody envelope in a temp fortress so the verb runs
 * its production unlock path (write intent, rotation barrier held) with the
 * OS keyring never consulted. Covers: help, flag refusal, the interactive
 * consent gate (non-TTY and declined runs change nothing), the readable-record
 * refusal, the no-record no-op, and the full quarantine with its audit record.
 */

import { mkdtemp, mkdir, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CONFIG_RESET_EXIT,
  runIntelligenceCommand,
  type ConfigResetDeps,
} from "../../src/cli/intelligence.js";
import { unlockLocalFortress } from "../../src/cli/local-fortress-unlock.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { buildDefaultConfig } from "../../src/intelligence/defaults.js";
import {
  INTELLIGENCE_NAMESPACE,
  IntelligenceConfigStore,
  SUBSTRATE_CONFIG_KEY,
  SUBSTRATE_CONFIG_QUARANTINE_PREFIX,
} from "../../src/intelligence/policy-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const supported = process.platform === "darwin" || process.platform === "linux";
const PASSPHRASE = "config-reset-fortress-passphrase-not-a-real-secret";
const GARBAGE_RECORD = stringToBytes(
  '{"v":1,"alg":"aes-256-gcm","iv":"AAAA","ct":"AAAA","ts":"2026-04-29T00:00:00Z"}',
);

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })));
});

/**
 * Seed a fortress and, while the establishment write session is still live,
 * plant the durable record the test wants. The establishment barrier is then
 * released so the verb's own write-intent unlock can take it.
 */
async function seedFortress(
  plant: (storage: FilesystemStorage, masterKey: Uint8Array) => Promise<void>,
): Promise<{ root: string; masterKey: Uint8Array }> {
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-config-reset-"));
  roots.push(dir);
  const root = join(dir, ".sanctuary");
  await mkdir(join(root, "state"), { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(root, "state"));
  const est = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  await plant(storage, est.masterKey);
  await est.masterWriteBarrier?.release();
  const masterKey = new Uint8Array(est.masterKey);
  est.masterKey.fill(0);
  return { root, masterKey };
}

function deps(overrides: Partial<ConfigResetDeps> = {}) {
  const lines: string[] = [];
  const unlock = vi.fn((opts: Parameters<typeof unlockLocalFortress>[0]) =>
    unlockLocalFortress({
      ...opts,
      // The env passphrase must win; the keyring is never consulted.
      readStored: async () => {
        throw new Error("keyring must not be read when a credential is present");
      },
      readCustody: async () => ({ status: "not-found" as const }),
    }));
  const configResetDeps: ConfigResetDeps = {
    env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    isTty: true,
    ask: async () => "reset",
    print: (line) => lines.push(line),
    now: () => new Date("2026-09-03T21:15:00.000Z"),
    unlock,
    ...overrides,
  };
  return { configResetDeps, lines, unlock, output: () => lines.join("\n") };
}

async function readRecord(root: string): Promise<Uint8Array | null> {
  return new FilesystemStorage(join(root, "state"))
    .read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
}

async function sidecars(root: string): Promise<string[]> {
  const files = await readdir(join(root, "state", INTELLIGENCE_NAMESPACE)).catch(() => []);
  return files.filter((f) => f.startsWith(SUBSTRATE_CONFIG_QUARANTINE_PREFIX));
}

describe.skipIf(!supported)("sanctuary intelligence config-reset", () => {
  it("--help prints the verb's own help", async () => {
    const d = deps();
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--help"],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.OK);
    expect(d.output()).toContain("sanctuary intelligence config-reset.");
    expect(d.output()).toContain("--fortress");
    expect(d.unlock).not.toHaveBeenCalled();
  });

  it("refuses a dropped --fortress value and an unknown option before touching the fortress", async () => {
    const d = deps();
    expect(await runIntelligenceCommand({
      argv: ["config-reset", "--fortress"],
      configResetDeps: d.configResetDeps,
    })).toBe(CONFIG_RESET_EXIT.USAGE);
    expect(await runIntelligenceCommand({
      argv: ["config-reset", "--yes"],
      configResetDeps: d.configResetDeps,
    })).toBe(CONFIG_RESET_EXIT.USAGE);
    expect(d.unlock).not.toHaveBeenCalled();
  });

  it("refuses a non-interactive run before unlocking and changes nothing", async () => {
    const { root } = await seedFortress((storage) =>
      storage.write(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY, GARBAGE_RECORD));
    const d = deps({ isTty: false });
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--fortress", root],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.REFUSED);
    expect(d.output()).toContain("requires an interactive terminal");
    expect(d.unlock).not.toHaveBeenCalled();
    expect(await readRecord(root)).toEqual(GARBAGE_RECORD);
    expect(await sidecars(root)).toEqual([]);
  });

  it("aborts when the operator types anything but the confirmation word", async () => {
    const { root } = await seedFortress((storage) =>
      storage.write(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY, GARBAGE_RECORD));
    const d = deps({ ask: async () => "yes" });
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--fortress", root],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.REFUSED);
    expect(d.output()).toContain("Plan (no changes have been made)");
    expect(d.output()).toContain("Aborted; nothing was changed.");
    expect(await readRecord(root)).toEqual(GARBAGE_RECORD);
    expect(await sidecars(root)).toEqual([]);
  });

  it("refuses a readable record", async () => {
    const { root } = await seedFortress(async (storage, masterKey) => {
      await new IntelligenceConfigStore(storage, masterKey).save(buildDefaultConfig());
    });
    const before = await readRecord(root);
    const d = deps();
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--fortress", root],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.REFUSED);
    expect(d.output()).toContain("readable record, version 1");
    expect(d.output()).toContain("Refused");
    expect(await readRecord(root)).toEqual(before);
    expect(await sidecars(root)).toEqual([]);
  });

  it("is a no-op when there is no durable record", async () => {
    const { root } = await seedFortress(async () => undefined);
    const d = deps();
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--fortress", root],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.OK);
    expect(d.output()).toContain("Nothing to reset.");
    expect(await sidecars(root)).toEqual([]);
  });

  it("quarantines a corrupt record, restores writability, and writes the audit record", async () => {
    const { root, masterKey } = await seedFortress((storage) =>
      storage.write(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY, GARBAGE_RECORD));
    const d = deps();
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--fortress", root],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.OK);
    expect(d.unlock).toHaveBeenCalledOnce();
    expect(d.unlock.mock.calls[0]![0]).toMatchObject({ writeIntent: true, storagePath: root });
    expect(d.output()).toContain("unreadable record: does not decrypt or parse (corrupt)");
    expect(d.output()).toContain(`Quarantined ${GARBAGE_RECORD.length} bytes to `);

    const files = await sidecars(root);
    expect(files).toEqual([
      `${SUBSTRATE_CONFIG_QUARANTINE_PREFIX}2026-09-03T21-15-00-000Z.bin`,
    ]);
    expect(await readRecord(root)).toBeNull();

    // Writable again through a fresh store over the same fortress.
    const storage = new FilesystemStorage(join(root, "state"));
    const store = new IntelligenceConfigStore(storage, masterKey);
    await expect(store.load()).resolves.toMatchObject({ kind: "default" });

    const audit = new AuditLog(storage, masterKey);
    const { entries } = await audit.query({
      operation_type: INTEL_OPS.CONFIG_QUARANTINED,
    });
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      layer: "l2",
      result: "success",
      identity_id: expect.stringMatching(/^fortress:fortress-[0-9a-f]{16}$/),
      details: {
        persisted: "corrupt",
        persisted_version: null,
        quarantine_file: files[0],
        bytes: GARBAGE_RECORD.length,
      },
    });
  });
});
