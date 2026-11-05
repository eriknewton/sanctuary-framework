/** Audit log operational witnesses, set B. */
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditLog, deriveAuditStoreSplitBoundaryMacKey, writeAuditStoreSplitBoundary, type PersistedAuditEnvelopeV2 } from "../../src/operational/audit-log.js";
import { AUDIT_CHAIN_GENESIS, AUDIT_HEAD_ANCHOR_KEY, computeAuditEntryHash } from "../../src/audit/chain.js";
import { bytesToString, fromBase64url, stringToBytes } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { createTempHome } from "../helpers/temp-fortress.js";
import { installInMemoryKeychainStore } from "../setup/keychain-memory-store.js";

const SEED_OPERATIONS = ["first", "second", "third"];
const SEED_SEQUENCE = SEED_OPERATIONS.length;
const ENTRY_SEQUENCE_WIDTH = 20; // Matches the persisted entry key's decimal sequence width.
const OPTIONS = { checkpointInterval: 0 }; // 0 = periodic checkpoints off.

async function append(log: AuditLog, operation: string): Promise<void> {
  await log.appendCritical({ layer: "l1", operation, identity_id: "fixture", result: "success", details: {} });
}

describe("audit log witnesses B", () => {
  let temp: Awaited<ReturnType<typeof createTempHome>>;
  let storage: FilesystemStorage;
  let masterKey: Uint8Array;
  let writer: AuditLog;
  let keys: string[];
  let originals: PersistedAuditEnvelopeV2[];
  let sampleBytes: Uint8Array;

  beforeEach(async () => {
    temp = await createTempHome("audit-hardening-b");
    installInMemoryKeychainStore();
    storage = new FilesystemStorage(join(temp.home, "state"));
    masterKey = generateRandomKey();
    writer = new AuditLog(storage, masterKey, OPTIONS);
    for (const operation of SEED_OPERATIONS) await append(writer, operation);
    keys = (await storage.list("_audit")).map(({ key }) => key).sort();
    originals = await Promise.all(keys.map(async (key) => {
      const bytes = await storage.read("_audit", key);
      expect(bytes).not.toBeNull();
      return JSON.parse(bytesToString(bytes!)) as PersistedAuditEnvelopeV2;
    }));
    sampleBytes = (await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY))!;
    expect(sampleBytes).not.toBeNull();
    expect(await new AuditLog(storage, masterKey, OPTIONS).getIntegrityFindings()).toEqual([]);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await temp?.cleanup();
  });

  async function writeEntry(payload: PersistedAuditEnvelopeV2, sequence: number, prevHash: string): Promise<PersistedAuditEnvelopeV2> {
    const hashInput = {
      schema_version: payload.schema_version,
      sequence,
      prev_hash: prevHash,
      timestamp: payload.timestamp,
      encrypted_payload_bytes: payload.encrypted_payload_bytes,
    };
    const envelope = { ...hashInput, entry_hash: computeAuditEntryHash(hashInput) };
    const key = keys[sequence - 1] ?? `entry-${String(sequence).padStart(ENTRY_SEQUENCE_WIDTH, "0")}-fixture`;
    await storage.write("_audit", key, stringToBytes(JSON.stringify(envelope)));
    return envelope;
  }

  async function writeChainVariant(withExtraEntry: boolean): Promise<void> {
    const ordered = [...originals].reverse();
    if (withExtraEntry) ordered.push(originals[0]!);
    let prevHash = AUDIT_CHAIN_GENESIS;
    for (const [index, payload] of ordered.entries()) {
      prevHash = (await writeEntry(payload, index + 1, prevHash)).entry_hash;
    }
    expect(await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY)).toEqual(sampleBytes);
  }

  async function expectRefusal(onlyFinding: boolean): Promise<void> {
    const reader = new AuditLog(storage, masterKey, OPTIONS);
    const findings = await reader.getIntegrityFindings();
    expect(findings).toEqual(expect.arrayContaining([expect.objectContaining({ kind: "tail_anchor_invalid" })]));
    if (onlyFinding) expect(findings.map(({ kind }) => kind)).toEqual(["tail_anchor_invalid"]);
    await expect(reader.query({})).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([expect.objectContaining({ kind: "tail_anchor_invalid" })]),
    });
  }

  it("B1", async () => {
    await writeChainVariant(true);
    await expectRefusal(true);
  });

  it("B2", async () => {
    const tip = originals.at(-1)!;
    await writeEntry(originals[0]!, SEED_SEQUENCE + 1, tip.entry_hash);
    await storage.delete("_audit", keys.at(-1)!);
    expect(await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY)).toEqual(sampleBytes);
    const reader = new AuditLog(storage, masterKey, OPTIONS);
    const findings = await reader.getIntegrityFindings();
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "sequence_gap_or_reorder" }),
    ]));
    expect(findings.map(({ kind }) => kind)).not.toContain("tail_anchor_invalid");
    await expect(reader.query({})).rejects.toMatchObject({ name: "AuditIntegrityError" });
  });

  it("B3", async () => {
    const read = storage.read.bind(storage);
    let sampledSequence: number | undefined;
    let samplePending = false;
    let appending = false;
    vi.spyOn(storage, "read").mockImplementation(async (namespace, key) => {
      const bytes = await read(namespace, key);
      if (!appending && namespace === "_audit_checkpoints" && key === AUDIT_HEAD_ANCHOR_KEY && bytes) {
        sampledSequence = JSON.parse(bytesToString(bytes)).data.highest_sequence;
        samplePending = true;
      }
      return bytes;
    });
    const list = storage.list.bind(storage);
    const laterOperations = ["later-first", "later-second"];
    let appendedCount = 0;
    vi.spyOn(storage, "list").mockImplementation(async (namespace, prefix) => {
      if (samplePending && namespace === "_audit" && prefix === undefined) {
        expect(sampledSequence).toBe(SEED_SEQUENCE + appendedCount);
        samplePending = false;
        appending = true;
        try {
          for (const operation of laterOperations) {
            await append(writer, operation);
            appendedCount++;
          }
        } finally {
          appending = false;
        }
      }
      return list(namespace, prefix);
    });
    const reader = new AuditLog(storage, masterKey, OPTIONS);
    expect(await reader.getIntegrityFindings()).toEqual([]);
    expect(appendedCount).toBe(laterOperations.length);
    expect((await reader.query({})).total).toBe(SEED_OPERATIONS.length + appendedCount);
  });

  it("B4a", async () => {
    expect(await writer.getIntegrityFindings()).toEqual([]);
    expect((await writer.query({})).total).toBe(SEED_OPERATIONS.length);
  });

  it("B4b", async () => {
    const reopened = new AuditLog(storage, masterKey, OPTIONS);
    expect(await reopened.getIntegrityFindings()).toEqual([]);
    await append(reopened, "reopened");
    const reader = new AuditLog(storage, masterKey, OPTIONS);
    expect(await reader.getIntegrityFindings()).toEqual([]);
    expect((await reader.query({})).total).toBe(SEED_OPERATIONS.length + 1);
  });

  it("B4c", async () => {
    await writeChainVariant(false);
    await expectRefusal(true);
  });

  async function restoreSample(): Promise<void> {
    await storage.write("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY, sampleBytes);
  }

  async function persistEntryPending(log: AuditLog, operation: string): Promise<void> {
    const write = storage.writeDurable.bind(storage);
    const pending = new Error("fixture write pending");
    const spy = vi.spyOn(storage, "writeDurable").mockImplementation((namespace, key, bytes) =>
      namespace === "_audit_checkpoints" && key === AUDIT_HEAD_ANCHOR_KEY
        ? Promise.reject(pending)
        : write(namespace, key, bytes));
    try {
      await expect(append(log, operation)).rejects.toMatchObject({ name: "AuditPersistenceError", cause: pending });
    } finally {
      spy.mockRestore();
    }
    expect(await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY)).toEqual(sampleBytes);
  }

  async function seal(sequence: number, hash: string): Promise<void> {
    await writeAuditStoreSplitBoundary(join(temp.home, "state"), deriveAuditStoreSplitBoundaryMacKey(masterKey), {
      sealed_tip_sequence: sequence,
      sealed_base_sequence: 1, // These fixtures retain their first chained entry.
      sealed_tip_entry_hash: hash,
      daemon_namespace: "_audit-daemon",
    });
  }

  async function expectContinuation(): Promise<void> {
    const reopened = new AuditLog(storage, masterKey, OPTIONS);
    expect(await reopened.getIntegrityFindings()).toEqual([]);
    await expect(append(reopened, "continued")).resolves.toBeUndefined();
    expect(await new AuditLog(storage, masterKey, OPTIONS).getIntegrityFindings()).toEqual([]);
  }

  async function expectOtherSampleRefusal(): Promise<void> {
    const otherStorage = new FilesystemStorage(join(temp.home, "other-history"));
    const otherWriter = new AuditLog(otherStorage, masterKey, OPTIONS);
    for (const operation of SEED_OPERATIONS) await append(otherWriter, operation);
    const otherSample = (await otherStorage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY))!;
    expect(otherSample).not.toEqual(sampleBytes);
    await storage.write("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY, otherSample);
    await expectRefusal(true);
  }

  it("H1", async () => {
    storage = new FilesystemStorage(join(temp.home, "legacy-state"));
    for (const [index, entry] of originals.entries()) {
      await storage.write("_audit", `legacy-${index + 1}`, fromBase64url(entry.encrypted_payload_bytes));
    }
    const legacyWriter = new AuditLog(storage, masterKey, OPTIONS);
    expect(await legacyWriter.getIntegrityFindings()).toEqual([]);
    sampleBytes = (await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY))!;
    expect(JSON.parse(bytesToString(sampleBytes)).data.highest_sequence).toBe(SEED_SEQUENCE);
    await persistEntryPending(legacyWriter, "op-h1");
    await expectContinuation();
    await expectOtherSampleRefusal();
  });

  it("H2", async () => {
    await seal(SEED_SEQUENCE, originals.at(-1)!.entry_hash);
    await persistEntryPending(new AuditLog(storage, masterKey, OPTIONS), "op-h2");
    await expectContinuation();
    await expectOtherSampleRefusal();
  });

  it("H3", async () => {
    await persistEntryPending(writer, "op-h3");
    const tipKey = (await storage.list("_audit")).map(({ key }) => key).sort().at(-1)!;
    const tip = JSON.parse(bytesToString((await storage.read("_audit", tipKey))!)) as PersistedAuditEnvelopeV2;
    await seal(tip.sequence, tip.entry_hash);
    await expectContinuation();
  });

  it("H4", async () => {
    const capped = new AuditLog(storage, masterKey, { ...OPTIONS, maxEntries: 1 });
    await append(capped, "op-h4");
    await restoreSample();
    expect(await storage.listKeys("_audit")).toHaveLength(1);
    await expectContinuation();
  });

  it("W1a", async () => {
    await writeChainVariant(true);
    const beforeKeys = await storage.listKeys("_audit");
    const beforeCheckpoints = await storage.listKeys("_audit_checkpoints", "audit-checkpoint-");
    const outcomes = [];
    for (const candidate of [writer, new AuditLog(storage, masterKey, OPTIONS)]) {
      outcomes.push(await append(candidate, "op-w1a").then(() => undefined, error => error));
      expect(await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY)).toEqual(sampleBytes);
      expect(await storage.listKeys("_audit")).toEqual(beforeKeys);
      expect(await storage.listKeys("_audit_checkpoints", "audit-checkpoint-")).toEqual(beforeCheckpoints);
    }
    for (const outcome of outcomes) expect(outcome).toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([expect.objectContaining({ kind: "tail_anchor_invalid" })]),
    });
  });

  it("W1b", async () => {
    await writeChainVariant(true);
    const namedKey = keys.at(-1)!;
    const named = JSON.parse(bytesToString((await storage.read("_audit", namedKey))!)) as PersistedAuditEnvelopeV2;
    named.entry_hash = JSON.parse(bytesToString(sampleBytes)).data.head_hash;
    await storage.write("_audit", namedKey, stringToBytes(JSON.stringify(named)));
    await expect(append(writer, "op-w1b")).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([expect.objectContaining({ kind: "entry_hash_mismatch" })]),
    });
    expect(await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY)).toEqual(sampleBytes);
    expect(await storage.listKeys("_audit_checkpoints", "audit-checkpoint-")).toEqual([]);
  });

  it("W1c", async () => {
    const named = { ...originals.at(-1)!, entry_hash: originals[0]!.entry_hash };
    await storage.write("_audit", keys.at(-1)!, stringToBytes(JSON.stringify(named)));
    await expect(append(writer, "op-w1c")).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([expect.objectContaining({ kind: "entry_hash_mismatch" })]),
    });
    expect(await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY)).toEqual(sampleBytes);
    expect(await storage.listKeys("_audit_checkpoints", "audit-checkpoint-")).toEqual([]);
  });

  it("W1d", async () => {
    await writeChainVariant(true);
    await expect(writer.flush()).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([expect.objectContaining({ kind: "tail_anchor_invalid" })]),
    });
    expect(await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY)).toEqual(sampleBytes);
    expect(await storage.listKeys("_audit_checkpoints", "audit-checkpoint-")).toEqual([]);
  });

  it("L1a", async () => {
    const lenient = new AuditLog(storage, masterKey, { ...OPTIONS, integrityMode: "lenient" });
    expect(await lenient.getIntegrityFindings()).toEqual([]);
    await writeChainVariant(true);
    const beforeKeys = await storage.listKeys("_audit");
    await expect(append(lenient, "op-l1a")).resolves.toBeUndefined();
    await expect(lenient.flush()).resolves.toBeUndefined();
    expect(await storage.listKeys("_audit")).toHaveLength(beforeKeys.length + 1);
    expect(await lenient.getIntegrityFindings()).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "tail_anchor_invalid", sequence: SEED_SEQUENCE }),
    ]));
  });

  it("L1b", async () => {
    await writeChainVariant(true);
    const beforeKeys = await storage.listKeys("_audit");
    const beforeCheckpoints = await storage.listKeys("_audit_checkpoints", "audit-checkpoint-");
    await expect(append(writer, "op-l1b")).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([expect.objectContaining({ kind: "tail_anchor_invalid" })]),
    });
    expect(await storage.read("_audit_checkpoints", AUDIT_HEAD_ANCHOR_KEY)).toEqual(sampleBytes);
    expect(await storage.listKeys("_audit")).toEqual(beforeKeys);
    expect(await storage.listKeys("_audit_checkpoints", "audit-checkpoint-")).toEqual(beforeCheckpoints);
  });

  it("W2", async () => {
    const foreign = new AuditLog(storage, masterKey, OPTIONS);
    await append(foreign, "foreign-first");
    const foreignTipKey = (await storage.listKeys("_audit")).sort().at(-1)!;
    const reads = vi.spyOn(storage, "read");
    await append(writer, "local-first");
    const tipReads = reads.mock.calls.filter(([namespace, key]) => namespace === "_audit" && key === foreignTipKey);
    // One discovery read plus at most one confirmation read, independent of history length.
    expect(tipReads.length).toBeGreaterThan(0);
    expect(tipReads.length).toBeLessThanOrEqual(2);
    reads.mockRestore();
    await append(foreign, "foreign-second");
    await append(writer, "local-second");
    const reader = new AuditLog(storage, masterKey, OPTIONS);
    expect(await reader.getIntegrityFindings()).toEqual([]);
    const laterEntries = 4; // Two appends from each of the two writers.
    expect((await reader.query({})).total).toBe(SEED_SEQUENCE + laterEntries);
  });

});
