/**
 * Q5E residual 2: recovery path for an unreadable durable intelligence config.
 *
 * Covers the capability contract of `IntelligenceConfigStore` for a record this
 * build cannot consume (does not decrypt or parse, or carries a newer version):
 *   - every authoritative read and every write refuses with a typed error that
 *     names the one recovery verb;
 *   - `quarantineUnreadable()` copies the raw bytes to a sidecar file that stays
 *     outside the encrypted-record set, removes the record, and restores
 *     writability;
 *   - readable records (legacy or armed) and Q5 integrity refusals are never
 *     quarantined, and quarantined bytes are never overwritten.
 */

import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { buildDefaultConfig } from "../../src/intelligence/defaults.js";
import {
  INTELLIGENCE_CONFIG_RESET_VERB,
  INTELLIGENCE_NAMESPACE,
  IntelligenceConfigStore,
  IntelligenceConfigUnreadableError,
  LocalIntegrityStateLoadError,
  SUBSTRATE_CONFIG_KEY,
  SUBSTRATE_CONFIG_QUARANTINE_PREFIX,
} from "../../src/intelligence/policy-store.js";
import type { SubstrateConfig } from "../../src/intelligence/types.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  Q5E_PUBLIC_KEY,
  q5eIntegrityState,
  q5eRuntimeTags,
} from "./q5e-fixtures.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) =>
    rm(root, { recursive: true, force: true })));
});

const GARBAGE_RECORD = stringToBytes(
  '{"v":1,"alg":"aes-256-gcm","iv":"AAAA","ct":"AAAA","ts":"2026-04-29T00:00:00Z"}',
);
const FIXED_NOW = () => new Date("2026-09-03T21:15:00.000Z");
const FIXED_STAMP = "2026-09-03T21-15-00-000Z";

async function filesystemFixture() {
  const root = await mkdtemp(join(tmpdir(), "sanctuary-q5e-recovery-"));
  roots.push(root);
  const storage = new FilesystemStorage(root);
  const masterKey = generateRandomKey();
  const store = new IntelligenceConfigStore(storage, masterKey, {
    modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
  });
  return { root, storage, masterKey, store };
}

async function writeCorruptRecord(storage: FilesystemStorage | MemoryStorage) {
  await storage.write(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY, GARBAGE_RECORD);
}

async function writeVersionTooNewRecord(
  storage: FilesystemStorage | MemoryStorage,
  masterKey: Uint8Array,
) {
  // Route through a sibling store so the bytes are real ciphertext under the
  // fortress key; only the version field is from the future.
  const writer = new IntelligenceConfigStore(storage, masterKey, {
    modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
  });
  const future = { ...buildDefaultConfig(), version: 99 } as unknown as SubstrateConfig;
  await writer.save(future);
}

function armedConfig(base: SubstrateConfig): SubstrateConfig {
  const state = q5eIntegrityState("/var/lib/ollama/models");
  return {
    ...base,
    version: 2,
    customLocalModelTags: q5eRuntimeTags(state),
    localIntegrityState: state,
  };
}

function expectUnreadable(
  error: unknown,
  kind: "corrupt" | "version-too-new",
  persistedVersion: number | null,
) {
  expect(error).toBeInstanceOf(IntelligenceConfigUnreadableError);
  expect(error).toBeInstanceOf(LocalIntegrityStateLoadError);
  const typed = error as IntelligenceConfigUnreadableError;
  expect(typed.kind).toBe(kind);
  expect(typed.persistedVersion).toBe(persistedVersion);
  expect(typed.reason).toBe("integrity_state_invalid");
  expect(typed.remedy).toContain(INTELLIGENCE_CONFIG_RESET_VERB);
  expect(typed.message).toContain(INTELLIGENCE_CONFIG_RESET_VERB);
  expect(typed.message).toContain(kind);
}

describe("Q5E unreadable durable config: typed refusal names the remedy", () => {
  it("a corrupt record refuses every authoritative read, write, and clear with the remedy", async () => {
    const { store, storage } = await filesystemFixture();
    await writeCorruptRecord(storage);

    await expect(store.load()).resolves.toMatchObject({ kind: "corrupt" });
    expectUnreadable(await store.loadAuthoritative().catch((e) => e), "corrupt", null);
    expectUnreadable(await store.save(buildDefaultConfig()).catch((e) => e), "corrupt", null);
    expectUnreadable(await store.clear().catch((e) => e), "corrupt", null);
    // Nothing above may have touched the record.
    expect(await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY))
      .toEqual(GARBAGE_RECORD);
  });

  it("a version-too-new record refuses the same way and carries the persisted version", async () => {
    const { store, storage, masterKey } = await filesystemFixture();
    await writeVersionTooNewRecord(storage, masterKey);
    const before = await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);

    await expect(store.load()).resolves.toMatchObject({
      kind: "version-too-new",
      persistedVersion: 99,
    });
    expectUnreadable(await store.loadAuthoritative().catch((e) => e), "version-too-new", 99);
    expectUnreadable(await store.save(buildDefaultConfig()).catch((e) => e), "version-too-new", 99);
    expectUnreadable(await store.clear().catch((e) => e), "version-too-new", 99);
    expect(await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY)).toEqual(before);
  });
});

describe("Q5E quarantineUnreadable", () => {
  it("quarantines a corrupt record to a sidecar, preserves its bytes, and restores writability", async () => {
    const { root, store, storage } = await filesystemFixture();
    await writeCorruptRecord(storage);

    const outcome = await store.quarantineUnreadable({ now: FIXED_NOW });
    expect(outcome).toMatchObject({
      kind: "quarantined",
      persisted: "corrupt",
      persistedVersion: null,
      quarantineFile: `${SUBSTRATE_CONFIG_QUARANTINE_PREFIX}${FIXED_STAMP}.bin`,
      bytes: GARBAGE_RECORD.length,
    });
    if (outcome.kind !== "quarantined") throw new Error("unreachable");

    // Bytes preserved verbatim, owner-only, in the namespace directory.
    expect(new Uint8Array(await readFile(outcome.quarantinePath))).toEqual(GARBAGE_RECORD);
    expect((await stat(outcome.quarantinePath)).mode & 0o777).toBe(0o600);
    expect(outcome.quarantinePath.startsWith(storage.namespacePath(INTELLIGENCE_NAMESPACE)))
      .toBe(true);
    // The sidecar is not an encrypted entry: enumeration must skip it, so the
    // master-rotation walk and any namespace listing never try to decrypt it.
    expect((await storage.list(INTELLIGENCE_NAMESPACE)).map((e) => e.key)).toEqual([]);
    const files = await readdir(join(root, INTELLIGENCE_NAMESPACE));
    expect(files.filter((f) => f.endsWith(".enc"))).toEqual([]);
    expect(files).toContain(outcome.quarantineFile);

    // The record is gone and the store is writable again.
    await expect(store.load()).resolves.toMatchObject({ kind: "default" });
    await expect(store.loadAuthoritative()).resolves.toBeNull();
    const saved = await store.save(buildDefaultConfig());
    expect(saved.version).toBe(1);
    await expect(store.load()).resolves.toMatchObject({ kind: "loaded" });
  });

  it("quarantines a version-too-new record and reports the persisted version", async () => {
    const { store, storage, masterKey } = await filesystemFixture();
    await writeVersionTooNewRecord(storage, masterKey);
    const before = await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);

    const outcome = await store.quarantineUnreadable({ now: FIXED_NOW });
    expect(outcome).toMatchObject({
      kind: "quarantined",
      persisted: "version-too-new",
      persistedVersion: 99,
    });
    if (outcome.kind !== "quarantined") throw new Error("unreachable");
    expect(new Uint8Array(await readFile(outcome.quarantinePath))).toEqual(before);
    await expect(store.save(buildDefaultConfig())).resolves.toMatchObject({ version: 1 });
  });

  it("reports absent when there is no durable record", async () => {
    const { store } = await filesystemFixture();
    await expect(store.quarantineUnreadable({ now: FIXED_NOW }))
      .resolves.toEqual({ kind: "absent" });
  });

  it("refuses a readable legacy record and leaves it in place", async () => {
    const { store, storage } = await filesystemFixture();
    await store.save(buildDefaultConfig());
    const before = await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);

    await expect(store.quarantineUnreadable({ now: FIXED_NOW })).resolves.toMatchObject({
      kind: "refused",
      reason: "readable",
    });
    expect(await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY)).toEqual(before);
  });

  it("refuses a readable armed V2 record and leaves it in place", async () => {
    const { store, storage } = await filesystemFixture();
    const initial = await store.save(buildDefaultConfig());
    await store.save(armedConfig(initial));
    const before = await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);

    await expect(store.quarantineUnreadable({ now: FIXED_NOW })).resolves.toMatchObject({
      kind: "refused",
      reason: "readable",
      detail: expect.stringContaining("version 2"),
    });
    expect(await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY)).toEqual(before);
    await expect(store.load()).resolves.toMatchObject({
      kind: "loaded",
      config: { version: 2, localIntegrityState: { state: "armed" } },
    });
  });

  it("refuses an armed record that fails Q5 integrity validation; that is not an unreadable record", async () => {
    const { store, storage, masterKey } = await filesystemFixture();
    const initial = await store.save(buildDefaultConfig());
    await store.save(armedConfig(initial));
    const before = await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);

    // A store pinned to a different catalog key sees the same bytes as an
    // integrity refusal (signature does not verify), never as unreadable.
    const otherPin = new IntelligenceConfigStore(storage, masterKey, {
      modelManifestV2PublicKey: new Uint8Array(32).fill(7),
    });
    await expect(otherPin.load()).resolves.toMatchObject({ kind: "integrity-state-invalid" });
    await expect(otherPin.quarantineUnreadable({ now: FIXED_NOW })).resolves.toMatchObject({
      kind: "refused",
      reason: "integrity-state-invalid",
    });
    expect(await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY)).toEqual(before);
  });

  it("never overwrites an existing quarantine sidecar", async () => {
    const { store, storage } = await filesystemFixture();
    await writeCorruptRecord(storage);
    const sidecar = join(
      storage.namespacePath(INTELLIGENCE_NAMESPACE),
      `${SUBSTRATE_CONFIG_QUARANTINE_PREFIX}${FIXED_STAMP}.bin`,
    );
    await writeFile(sidecar, "earlier evidence", { mode: 0o600 });

    await expect(store.quarantineUnreadable({ now: FIXED_NOW })).resolves.toMatchObject({
      kind: "refused",
      reason: "quarantine-exists",
    });
    expect(await readFile(sidecar, "utf8")).toBe("earlier evidence");
    expect(await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY))
      .toEqual(GARBAGE_RECORD);
  });

  it("refuses on a backend with no filesystem sibling location", async () => {
    const storage = new MemoryStorage();
    const store = new IntelligenceConfigStore(storage, generateRandomKey(), {
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    });
    await writeCorruptRecord(storage);
    const error = await store.quarantineUnreadable({ now: FIXED_NOW }).catch((e) => e);
    expect(error).toBeInstanceOf(LocalIntegrityStateLoadError);
    expect((error as LocalIntegrityStateLoadError).reason).toBe("integrity_io_unavailable");
    expect(await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY))
      .toEqual(GARBAGE_RECORD);
  });
});
