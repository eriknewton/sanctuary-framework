// fail-before-exempt: authenticated StateStore fixture wiring only; key-resolution fail-before coverage lives in state-envelope-integrity.test.ts and master-rotation.test.ts
/**
 * Memory checkpoint restore tests.
 *
 * Proves the compromise-recovery path is a true reconstruct over exportable
 * namespaces: it refuses unless the harness is parked, seals a forensic copy
 * first, deletes post-checkpoint additions, restores changed/removed keys from
 * the checkpoint bundle, and never touches reserved namespaces.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  type StateExportCompletenessManifest,
  type StateStore,
} from "../../src/cognitive/state-store.js";
import { bytesToString, fromBase64url, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { hashToString } from "../../src/core/hashing.js";
import { generateRandomKey } from "../../src/core/random.js";
import { assessHarnessParked } from "../../src/egress-gate/parked-claim.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import { StateStore as RealStateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  CheckpointRestoreAgentNotParkedError,
  CheckpointRestoreBundleHashMismatchError,
  CheckpointRestoreForensicSourceError,
  CheckpointRestoreReconstructError,
  MemoryCheckpointStore,
  buildMemoryCheckpointId,
  createCheckpoint,
  restoreCheckpoint,
  type CheckpointPoisonMap,
} from "../../src/memory-checkpoint/index.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";

type AuditAppend = Pick<AuditLog, "append">["append"];
type AuditAppendCritical = Pick<AuditLog, "appendCritical">["appendCritical"];
type CriticalAuditCall = Parameters<AuditAppendCritical>[0];

interface Fixture {
  fortressPath: string;
  storage: MemoryStorage;
  stateStore: RealStateStore;
  checkpointStore: MemoryCheckpointStore;
  masterKey: Uint8Array;
  identity: ReturnType<typeof createIdentity>;
  identityEncKey: Uint8Array;
  audit: ReturnType<typeof makeAuditLog>;
}

interface ExportEntry {
  key: string;
  entry: {
    integrity_hash: string;
    [key: string]: unknown;
  };
}

interface DecodedExportBundle {
  namespaces: string[];
  data: Record<string, ExportEntry[]>;
}

const tempDirs: string[] = [];

afterEach(async () => {
  for (const dir of tempDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function makeTempFortress(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-checkpoint-restore-"));
  tempDirs.push(dir);
  return dir;
}

async function makeFixture(now = "2026-08-03T12:00:00.000Z"): Promise<Fixture> {
  const fortressPath = await makeTempFortress();
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new RealStateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const identity = createIdentity("restore-test", identityEncKey, "recovery-key");
  await persistStoredIdentity(storage, masterKey, identity.storedIdentity);
  const checkpointStore = new MemoryCheckpointStore({
    fortressPath,
    clock: { now: () => new Date(now) },
  });
  return {
    fortressPath,
    storage,
    stateStore,
    checkpointStore,
    masterKey,
    identity,
    identityEncKey,
    audit: makeAuditLog(),
  };
}

function makeAuditLog(): {
  auditLog: Pick<AuditLog, "append" | "appendCritical">;
  appendCalls: Parameters<AuditAppend>[];
  criticalCalls: CriticalAuditCall[];
} {
  const appendCalls: Parameters<AuditAppend>[] = [];
  const criticalCalls: CriticalAuditCall[] = [];
  return {
    appendCalls,
    criticalCalls,
    auditLog: {
      append: async (...args: Parameters<AuditAppend>): Promise<void> => {
        appendCalls.push(args);
      },
      appendCritical: async (entry: CriticalAuditCall): Promise<void> => {
        criticalCalls.push(entry);
      },
    },
  };
}

async function writeEntry(
  fixture: Fixture,
  namespace: string,
  key: string,
  value: string,
): Promise<void> {
  await fixture.stateStore.write(
    namespace,
    key,
    value,
    fixture.identity.storedIdentity.identity_id,
    fixture.identity.storedIdentity.encrypted_private_key,
    fixture.identityEncKey,
  );
}

function publicKeyResolver(fixture: Fixture): (kid: string) => Uint8Array | null {
  return (kid: string): Uint8Array | null =>
    kid === fixture.identity.storedIdentity.identity_id
      ? fromBase64url(fixture.identity.storedIdentity.public_key)
      : null;
}

async function parkedClaim() {
  return assessHarnessParked({
    probe: {
      harnessStatus: async () => ({ known: true, installed: true, running: false }),
      sleepMs: async () => undefined,
    },
  });
}

async function aliveClaim() {
  return assessHarnessParked({
    probe: {
      harnessStatus: async () => ({
        known: true,
        installed: true,
        running: true,
        pid: 4242,
      }),
      sleepMs: async () => undefined,
    },
  });
}

function decodeBundle(bundle: string): DecodedExportBundle {
  return JSON.parse(bytesToString(fromBase64url(bundle))) as DecodedExportBundle;
}

function entriesByPath(bundle: DecodedExportBundle): Map<string, ExportEntry["entry"]> {
  const out = new Map<string, ExportEntry["entry"]>();
  for (const [namespace, entries] of Object.entries(bundle.data)) {
    for (const entry of entries) {
      out.set(`${namespace}/${entry.key}`, entry.entry);
    }
  }
  return out;
}

async function exportEntries(stateStore: RealStateStore): Promise<Map<string, ExportEntry["entry"]>> {
  const exported = await stateStore.exportNamespaces(undefined);
  return entriesByPath(decodeBundle(exported.bundle));
}

function expectPoisonSummary(
  entry: CriticalAuditCall,
  poisonMap: CheckpointPoisonMap,
): void {
  expect(entry.details).toMatchObject({
    poison_map_summary: {
      added: poisonMap.added.length,
      changed: poisonMap.changed.length,
      removed: poisonMap.removed.length,
    },
  });
}

describe("restoreCheckpoint", () => {
  it("refuses when the harness is alive and does not mutate state or seal a forensic snapshot", async () => {
    const fixture = await makeFixture();
    await writeEntry(fixture, "mem", "Q", "known-good");
    const checkpoint = await createCheckpoint({
      stateStore: fixture.stateStore,
      store: fixture.checkpointStore,
      masterKey: fixture.masterKey,
      auditLog: fixture.audit.auditLog,
      identityId: fixture.identity.storedIdentity.identity_id,
      source: "on_demand",
      retentionValue: "off",
      now: new Date("2026-08-03T12:01:00.000Z"),
    });
    await writeEntry(fixture, "mem", "P", "poison-added");
    await writeEntry(fixture, "mem", "Q", "poison-changed");
    const before = await exportEntries(fixture.stateStore);

    await expect(
      restoreCheckpoint({
        stateStore: fixture.stateStore,
        checkpointStore: fixture.checkpointStore,
        masterKey: fixture.masterKey,
        auditLog: fixture.audit.auditLog,
        identityId: fixture.identity.storedIdentity.identity_id,
        checkpointId: checkpoint.id,
        assessParked: aliveClaim,
        publicKeyResolver: publicKeyResolver(fixture),
      }),
    ).rejects.toThrow(CheckpointRestoreAgentNotParkedError);
    await expect(
      restoreCheckpoint({
        stateStore: fixture.stateStore,
        checkpointStore: fixture.checkpointStore,
        masterKey: fixture.masterKey,
        auditLog: fixture.audit.auditLog,
        identityId: fixture.identity.storedIdentity.identity_id,
        checkpointId: checkpoint.id,
        assessParked: aliveClaim,
        publicKeyResolver: publicKeyResolver(fixture),
      }),
    ).rejects.toThrow(/Remedy: stop and park the agent harness/);

    await expect(
      restoreCheckpoint({
        stateStore: fixture.stateStore,
        checkpointStore: fixture.checkpointStore,
        masterKey: fixture.masterKey,
        auditLog: fixture.audit.auditLog,
        identityId: fixture.identity.storedIdentity.identity_id,
        checkpointId: checkpoint.id,
        assessParked: async () =>
          assessHarnessParked({ cannotProbe: "no harness job is registered on this host" }),
        publicKeyResolver: publicKeyResolver(fixture),
      }),
    ).rejects.toThrow(/no harness job is registered/);

    expect(await exportEntries(fixture.stateStore)).toEqual(before);
    const records = await fixture.checkpointStore.list();
    expect(records.map((record) => record.source)).toEqual(["on_demand"]);
  });

  it("deletes added keys, restores changed and removed keys, seals forensic state, and preserves reserved namespaces", async () => {
    const fixture = await makeFixture();
    await writeEntry(fixture, "mem", "Q", "known-good-q");
    await writeEntry(fixture, "mem", "R", "known-good-r");
    await writeEntry(fixture, "_audit", "audit-key", "audit-before");
    await writeEntry(fixture, "_identities", "identity-key", "identity-before");

    const checkpoint = await createCheckpoint({
      stateStore: fixture.stateStore,
      store: fixture.checkpointStore,
      masterKey: fixture.masterKey,
      auditLog: fixture.audit.auditLog,
      identityId: fixture.identity.storedIdentity.identity_id,
      source: "on_demand",
      retentionValue: "off",
      now: new Date("2026-08-03T12:02:00.000Z"),
    });
    const checkpointEntries = entriesByPath(
      decodeBundle(await fixture.checkpointStore.readBundle(checkpoint.id, fixture.masterKey)),
    );

    await writeEntry(fixture, "mem", "P", "poison-added");
    await writeEntry(fixture, "mem", "Q", "poison-changed-q");
    await fixture.stateStore.delete("mem", "R");
    await writeEntry(fixture, "_audit", "audit-key", "audit-after");
    await writeEntry(fixture, "_identities", "identity-key", "identity-after");

    const restored = await restoreCheckpoint({
      stateStore: fixture.stateStore,
      checkpointStore: fixture.checkpointStore,
      masterKey: fixture.masterKey,
      auditLog: fixture.audit.auditLog,
      identityId: fixture.identity.storedIdentity.identity_id,
      checkpointId: checkpoint.id,
      assessParked: parkedClaim,
      publicKeyResolver: publicKeyResolver(fixture),
      now: new Date("2026-08-03T12:03:00.000Z"),
    });

    expect(restored.checkpoint_id).toBe(checkpoint.id);
    expect(restored.poison_map).toEqual({
      added: ["mem/P"],
      changed: ["mem/Q"],
      removed: ["mem/R"],
    });
    expect(restored.import_result.imported_keys).toBe(2);

    const restoredEntries = await exportEntries(fixture.stateStore);
    expect(restoredEntries.has("mem/P")).toBe(false);
    expect(restoredEntries.get("mem/Q")).toEqual(checkpointEntries.get("mem/Q"));
    expect(restoredEntries.get("mem/R")).toEqual(checkpointEntries.get("mem/R"));

    await expect(fixture.stateStore.read("_audit", "audit-key")).resolves.toMatchObject({
      value: "audit-after",
    });
    await expect(fixture.stateStore.read("_identities", "identity-key")).resolves.toMatchObject({
      value: "identity-after",
    });

    const forensic = await fixture.checkpointStore.get(restored.forensic_id);
    expect(forensic).toMatchObject({
      source: "forensic_quarantine",
      retention_expires_at: null,
    });
    const forensicEntries = entriesByPath(
      decodeBundle(await fixture.checkpointStore.readBundle(restored.forensic_id, fixture.masterKey)),
    );
    expect(forensicEntries.has("mem/P")).toBe(true);
    expect(forensicEntries.get("mem/Q")).not.toEqual(checkpointEntries.get("mem/Q"));

    const critical = fixture.audit.criticalCalls.at(-1);
    expect(critical).toMatchObject({
      layer: "l1",
      operation: "memory_checkpoint_restore",
      identity_id: fixture.identity.storedIdentity.identity_id,
      result: "success",
      details: {
        checkpoint_id: checkpoint.id,
        forensic_id: restored.forensic_id,
      },
    });
    expectPoisonSummary(critical!, restored.poison_map);
  });

  it("refuses to restore from a forensic quarantine checkpoint", async () => {
    const fixture = await makeFixture();
    await writeEntry(fixture, "mem", "Q", "known-good");
    const forensic = await createCheckpoint({
      stateStore: fixture.stateStore,
      store: fixture.checkpointStore,
      masterKey: fixture.masterKey,
      auditLog: fixture.audit.auditLog,
      identityId: fixture.identity.storedIdentity.identity_id,
      source: "forensic_quarantine",
      retentionValue: "off",
      now: new Date("2026-08-03T12:04:00.000Z"),
    });

    await expect(
      restoreCheckpoint({
        stateStore: fixture.stateStore,
        checkpointStore: fixture.checkpointStore,
        masterKey: fixture.masterKey,
        auditLog: fixture.audit.auditLog,
        identityId: fixture.identity.storedIdentity.identity_id,
        checkpointId: forensic.id,
        assessParked: parkedClaim,
        publicKeyResolver: publicKeyResolver(fixture),
      }),
    ).rejects.toThrow(CheckpointRestoreForensicSourceError);

    const records = await fixture.checkpointStore.list();
    expect(records).toHaveLength(1);
    expect(records[0]!.id).toBe(forensic.id);
  });

  it("keeps the forensic snapshot inspectable when reconstruct fails after sealing", async () => {
    const fixture = await makeFixture();
    await writeEntry(fixture, "mem", "Q", "known-good");
    const checkpoint = await createCheckpoint({
      stateStore: fixture.stateStore,
      store: fixture.checkpointStore,
      masterKey: fixture.masterKey,
      auditLog: fixture.audit.auditLog,
      identityId: fixture.identity.storedIdentity.identity_id,
      source: "on_demand",
      retentionValue: "off",
      now: new Date("2026-08-03T12:05:00.000Z"),
    });
    await writeEntry(fixture, "mem", "P", "poison-added");
    await writeEntry(fixture, "mem", "Q", "poison-changed");

    const failingStateStore: Pick<
      StateStore,
      "exportNamespaces" | "delete" | "import" | "listCachedExportableNamespaces"
    > = {
      exportNamespaces: (namespaces?: string[]) => fixture.stateStore.exportNamespaces(namespaces),
      listCachedExportableNamespaces: () => fixture.stateStore.listCachedExportableNamespaces(),
      delete: async () => {
        throw new Error("injected reconstruct failure");
      },
      import: async () => {
        throw new Error("import should not be reached");
      },
    };

    let thrown: unknown;
    try {
      await restoreCheckpoint({
        stateStore: failingStateStore,
        checkpointStore: fixture.checkpointStore,
        masterKey: fixture.masterKey,
        auditLog: fixture.audit.auditLog,
        identityId: fixture.identity.storedIdentity.identity_id,
        checkpointId: checkpoint.id,
        assessParked: parkedClaim,
        publicKeyResolver: publicKeyResolver(fixture),
        now: new Date("2026-08-03T12:06:00.000Z"),
      });
    } catch (err) {
      thrown = err;
    }

    expect(thrown).toBeInstanceOf(CheckpointRestoreReconstructError);
    expect((thrown as CheckpointRestoreReconstructError).progress).toEqual({
      deleted_added: [],
      delete_remaining: ["mem/P"],
      import_applied: false,
    });

    const forensic = (await fixture.checkpointStore.list()).find(
      (record) => record.source === "forensic_quarantine",
    );
    expect(forensic).toBeDefined();
    const forensicEntries = entriesByPath(
      decodeBundle(await fixture.checkpointStore.readBundle(forensic!.id, fixture.masterKey)),
    );
    expect(forensicEntries.has("mem/P")).toBe(true);

    const failureAudit = fixture.audit.criticalCalls.at(-1);
    expect(failureAudit).toMatchObject({
      layer: "l1",
      operation: "memory_checkpoint_restore",
      identity_id: fixture.identity.storedIdentity.identity_id,
      result: "failure",
      details: {
        checkpoint_id: checkpoint.id,
        forensic_id: forensic!.id,
      },
    });
    expectPoisonSummary(failureAudit!, {
      added: ["mem/P"],
      changed: ["mem/Q"],
      removed: [],
    });
  });

  it("refuses (before any state change) when the decrypted bundle hash does not match the recorded bundle_hash", async () => {
    const fixture = await makeFixture();
    await writeEntry(fixture, "mem", "Q", "live-state");
    const liveBefore = await exportEntries(fixture.stateStore);

    // A record whose id/bundle_hash are internally consistent (so parse and the
    // GCM AAD accept it) but whose stored bundle bytes hash to something else.
    // store.create does not re-hash the bundle, so this models a bundle_hash
    // that disagrees with the actual decrypted content.
    const createdAt = "2026-08-03T12:07:00.000Z";
    const declaredBundle = toBase64url(stringToBytes(JSON.stringify({ namespaces: [], data: {} })));
    const declaredHash = hashToString(fromBase64url(declaredBundle));
    const tamperedBundle = toBase64url(
      stringToBytes(JSON.stringify({ namespaces: ["mem"], data: { mem: [] } })),
    );
    expect(hashToString(fromBase64url(tamperedBundle))).not.toBe(declaredHash);
    const id = buildMemoryCheckpointId(createdAt, declaredHash);
    await fixture.checkpointStore.create({
      record: {
        id,
        created_at: createdAt,
        source: "on_demand",
        namespaces: [],
        total_keys: 0,
        bundle_hash: declaredHash,
        completeness_summary: { namespace_count: 0, total_keys: 0, per_namespace: {} },
        retention_expires_at: null,
        format_version: 1,
      },
      bundle: tamperedBundle,
      masterKey: fixture.masterKey,
    });

    await expect(
      restoreCheckpoint({
        stateStore: fixture.stateStore,
        checkpointStore: fixture.checkpointStore,
        masterKey: fixture.masterKey,
        auditLog: fixture.audit.auditLog,
        identityId: fixture.identity.storedIdentity.identity_id,
        checkpointId: id,
        assessParked: parkedClaim,
        publicKeyResolver: publicKeyResolver(fixture),
      }),
    ).rejects.toThrow(CheckpointRestoreBundleHashMismatchError);

    // No state overwritten and no forensic snapshot sealed (the check fires
    // before any destructive step).
    expect(await exportEntries(fixture.stateStore)).toEqual(liveBefore);
    const forensic = (await fixture.checkpointStore.list()).find(
      (record) => record.source === "forensic_quarantine",
    );
    expect(forensic).toBeUndefined();
    const failureAudit = fixture.audit.criticalCalls.at(-1);
    expect(failureAudit).toMatchObject({
      operation: "memory_checkpoint_restore",
      result: "failure",
    });
  });
});
