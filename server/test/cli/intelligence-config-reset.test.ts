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
  classifyLocalIntelligenceState,
  INTELLIGENCE_CONFIG_RESET_VERB,
  INTELLIGENCE_NAMESPACE,
  IntelligenceConfigStore,
  SUBSTRATE_CONFIG_KEY,
  SUBSTRATE_CONFIG_QUARANTINE_PREFIX,
} from "../../src/intelligence/policy-store.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import type { SubstrateConfig } from "../../src/intelligence/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  Q5E_PUBLIC_KEY,
  q5eIntegrityState,
  q5eRuntimeTags,
} from "../intelligence/q5e-fixtures.js";

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

/** Plant a readable armed V2 record signed with the Q5E fixture key. */
async function plantArmedRecord(storage: FilesystemStorage, masterKey: Uint8Array) {
  const store = new IntelligenceConfigStore(storage, masterKey, {
    modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
  });
  const initial = await store.save(buildDefaultConfig());
  const state = q5eIntegrityState("/var/lib/ollama/models");
  const armed: SubstrateConfig = {
    ...initial,
    version: 2,
    customLocalModelTags: q5eRuntimeTags(state),
    localIntegrityState: state,
  };
  await store.save(armed);
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
    // The record line comes from the ONE classifier `diagnose` uses, so the two
    // verbs cannot describe one record differently.
    expect(d.output()).toContain("legacy-unarmed");
    expect(d.output()).toContain("Refused");
    expect(await readRecord(root)).toEqual(before);
    expect(await sidecars(root)).toEqual([]);
  });

  it("refuses a readable armed V2 record and quarantines nothing (cannot disarm a working record)", async () => {
    const { root } = await seedFortress(plantArmedRecord);
    const before = await readRecord(root);
    const d = deps({ modelManifestV2PublicKey: Q5E_PUBLIC_KEY });
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--fortress", root],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.REFUSED);
    expect(d.output()).toContain("armed");
    expect(d.output()).toContain(
      "Refused: config-reset only quarantines an unreadable record; a readable record is never discarded here.",
    );
    expect(await readRecord(root)).toEqual(before);
    expect(await sidecars(root)).toEqual([]);
  });

  it("refuses an armed record that fails Q5 integrity validation and quarantines nothing", async () => {
    const { root } = await seedFortress(plantArmedRecord);
    const before = await readRecord(root);
    // The production catalog pin does not verify the fixture-signed record, so
    // the verb sees an integrity refusal, never an unreadable record.
    const d = deps();
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--fortress", root],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.REFUSED);
    expect(d.output()).toContain(
      "integrity_state_invalid: the armed record failed Q5 integrity validation (",
    );
    expect(d.output()).toContain(
      "Refused: an armed record that fails Q5 integrity validation is not an unreadable record, and there is no in-product disarm.",
    );
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
    expect(d.output()).toContain("corrupt: the durable record does not decrypt or parse");
    expect(d.output()).toContain(`Quarantined ${GARBAGE_RECORD.length} bytes to `);
    expect(d.output()).toContain("default legacy-unarmed configuration");
    expect(d.output()).toContain("re-provision local intelligence before relying on load-integrity verification");

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

  /**
   * The recovery verb and the boot checkpoint read the SAME record through
   * deliberately different paths, and this pins that split.
   *
   * `SubstrateSelector.load()` refuses an unreadable record, because a
   * fortress must not start as though nobody had ever armed it. `config-reset`
   * reads the record through `IntelligenceConfigStore.load`, which still
   * returns the outcome rather than throwing, because the one command whose
   * whole job is to clear the record cannot be gated on being able to read it.
   *
   * Failure mode if that split is ever collapsed by moving the refusal down
   * into the store: the product deadlocks. Boot refuses and names
   * `config-reset` as the remedy, and `config-reset` then refuses for the same
   * reason, so the operator is told to run the one command that cannot run.
   */
  it("refuses the boot checkpoint on the same record config-reset can still clear", async () => {
    const { root, masterKey } = await seedFortress((storage) =>
      storage.write(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY, GARBAGE_RECORD));
    const storage = new FilesystemStorage(join(root, "state"));
    const auditLog = new AuditLog(storage, masterKey);
    const selectorOptions = {
      storage,
      masterKey,
      auditLog,
      identityId: "fortress:config-reset-split",
    };

    // The checkpoint refuses, and the refusal names the verb.
    await expect(
      new SubstrateSelector(selectorOptions).load(),
    ).rejects.toThrow(new RegExp(INTELLIGENCE_CONFIG_RESET_VERB));

    // The verb the refusal named still runs against that exact record.
    const d = deps();
    const code = await runIntelligenceCommand({
      argv: ["config-reset", "--fortress", root],
      configResetDeps: d.configResetDeps,
    });
    expect(code).toBe(CONFIG_RESET_EXIT.OK);
    // Derived from the shared classifier rather than re-typing the sentence:
    // this test is about the boot-refuses / reset-clears SPLIT, and a second
    // hand-copied snapshot of the prose only creates a second thing to drift.
    // It already did: the wording moved when `describeOutcome` was rederived
    // from `classifyLocalIntelligenceState`, and this line was the copy nobody
    // updated. The literal snapshot is pinned once, by the sibling quarantine
    // test above, which is the test that is actually about the wording.
    const classified = classifyLocalIntelligenceState({ kind: "corrupt", config: buildDefaultConfig() });
    expect(d.output()).toContain(`${classified.state}: ${classified.detail}`);
    // The record really was read as unreadable, not merely described.
    expect(d.output()).toContain("Quarantined ");

    // And the fortress starts again afterwards, now genuinely unarmed.
    await expect(new SubstrateSelector(selectorOptions).load()).resolves.toBeUndefined();
  });
});
