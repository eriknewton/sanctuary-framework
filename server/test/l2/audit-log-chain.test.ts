import { mkdir, writeFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AuditIntegrityError,
  AuditLog,
  type AuditEntry,
  type PersistedAuditEnvelopeV2,
} from "../../src/l2-operational/audit-log.js";
import {
  checkpointSigningBytes,
  type AuditCheckpointRecord,
  type AuditCheckpointSigningPayload,
} from "../../src/audit/chain.js";
import { encrypt } from "../../src/core/encryption.js";
import { bytesToString, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { createIdentity, sign as identitySign } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const MASTER_KEY = () => generateRandomKey();

async function appendCritical(log: AuditLog, operation: string): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: "id-1",
    result: "success",
    details: { operation },
  });
}

async function auditKeys(storage: MemoryStorage): Promise<string[]> {
  return (await storage.list("_audit")).map((entry) => entry.key);
}

async function readEnvelope(
  storage: MemoryStorage,
  key: string
): Promise<PersistedAuditEnvelopeV2> {
  const raw = await storage.read("_audit", key);
  if (!raw) throw new Error(`missing audit entry: ${key}`);
  return JSON.parse(bytesToString(raw)) as PersistedAuditEnvelopeV2;
}

async function writeEnvelope(
  storage: MemoryStorage,
  key: string,
  envelope: PersistedAuditEnvelopeV2
): Promise<void> {
  await storage.write("_audit", key, stringToBytes(JSON.stringify(envelope)));
}

async function expectStrictFinding(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  kind: string
): Promise<void> {
  const reader = new AuditLog(storage, masterKey);
  await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
    name: "AuditIntegrityError",
    findings: expect.arrayContaining([expect.objectContaining({ kind })]),
  } satisfies Partial<AuditIntegrityError>);
}

describe("AuditLog tamper-evident chain", () => {
  it("verifies a normal append/load chain cleanly", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const writer = new AuditLog(storage, masterKey);

    await appendCritical(writer, "state_write");
    await appendCritical(writer, "state_delete");
    await writer.flush();

    const keys = await auditKeys(storage);
    expect(keys).toHaveLength(2);
    const first = await readEnvelope(storage, keys[0]!);
    const second = await readEnvelope(storage, keys[1]!);
    expect(first).toMatchObject({
      schema_version: 2,
      sequence: 1,
      prev_hash: "GENESIS",
    });
    expect(second.prev_hash).toBe(first.entry_hash);

    const reader = new AuditLog(storage, masterKey);
    const result = await reader.query({ limit: 100 });
    expect(result.total).toBe(2);
    expect(result.integrity_findings).toEqual([]);
  });

  it("detects a single entry deletion", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const writer = new AuditLog(storage, masterKey);
    await appendCritical(writer, "one");
    await appendCritical(writer, "two");
    await appendCritical(writer, "three");

    const keys = await auditKeys(storage);
    await storage.delete("_audit", keys[1]!);

    await expectStrictFinding(storage, masterKey, "sequence_gap_or_reorder");
  });

  it("detects tail truncation below the MAC'd head floor", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
    await appendCritical(writer, "one");
    await appendCritical(writer, "two");
    await appendCritical(writer, "three");

    const keys = await auditKeys(storage);
    await storage.delete("_audit", keys[2]!);

    await expectStrictFinding(storage, masterKey, "tail_anchor_invalid");
  });

  it("fails closed when truncation is left behind with a fake in-progress writer marker", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-fake-marker-"));
    try {
      const storage = new FilesystemStorage(join(root, "state"));
      const masterKey = MASTER_KEY();
      const writer = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
      await appendCritical(writer, "one");
      await appendCritical(writer, "two");
      await appendCritical(writer, "three");

      const keys = (await storage.list("_audit")).map((entry) => entry.key);
      await storage.delete("_audit", keys.at(-1)!);

      const auditDir = storage.namespacePath("_audit");
      await mkdir(auditDir, { recursive: true, mode: 0o700 });
      await writeFile(join(auditDir, ".audit-write.lock"), "not-json", { mode: 0o600 });

      const reader = new AuditLog(storage, masterKey);
      await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
        name: "AuditIntegrityError",
        findings: expect.arrayContaining([
          expect.objectContaining({ kind: "tail_anchor_invalid" }),
        ]),
      });
    } finally {
      await rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  });

  it("allows a genuinely fresh empty log with no prior head anchor", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const reader = new AuditLog(storage, masterKey);

    const result = await reader.query({ limit: 100 });

    expect(result.total).toBe(0);
    expect(result.integrity_findings).toEqual([]);
  });

  it("detects whole-log deletion on an established audit store", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const writer = new AuditLog(storage, masterKey);
    await appendCritical(writer, "one");
    await appendCritical(writer, "two");

    for (const meta of await storage.list("_audit")) {
      await storage.delete(meta.namespace, meta.key);
    }
    for (const meta of await storage.list("_audit_checkpoints")) {
      await storage.delete(meta.namespace, meta.key);
    }

    await expectStrictFinding(storage, masterKey, "tail_anchor_missing");
  });

  it("detects a single entry byte modification", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const writer = new AuditLog(storage, masterKey);
    await appendCritical(writer, "one");

    const key = (await auditKeys(storage))[0]!;
    const envelope = await readEnvelope(storage, key);
    envelope.encrypted_payload_bytes =
      envelope.encrypted_payload_bytes.slice(0, -1) +
      (envelope.encrypted_payload_bytes.endsWith("A") ? "B" : "A");
    await writeEnvelope(storage, key, envelope);

    await expectStrictFinding(storage, masterKey, "entry_hash_mismatch");
  });

  it("detects two entries reordered under existing keys", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const writer = new AuditLog(storage, masterKey);
    await appendCritical(writer, "one");
    await appendCritical(writer, "two");

    const keys = await auditKeys(storage);
    const first = await storage.read("_audit", keys[0]!);
    const second = await storage.read("_audit", keys[1]!);
    if (!first || !second) throw new Error("missing test entries");
    await storage.write("_audit", keys[0]!, second);
    await storage.write("_audit", keys[1]!, first);

    await expectStrictFinding(storage, masterKey, "sequence_gap_or_reorder");
  });

  it("migrates legacy entries with a legacy-anchor checkpoint", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const auditKey = derivePurposeKey(masterKey, "audit-log");
    const legacyEntry: AuditEntry = {
      timestamp: "2026-05-16T00:00:00.000Z",
      layer: "l1",
      operation: "legacy",
      identity_id: "id-1",
      result: "success",
    };
    const encrypted = encrypt(stringToBytes(JSON.stringify(legacyEntry)), auditKey);
    const legacyRaw = stringToBytes(JSON.stringify(encrypted));
    await storage.write("_audit", "legacy-1", legacyRaw);

    const migrated = new AuditLog(storage, masterKey);
    const migratedResult = await migrated.query({ limit: 100 });
    expect(migratedResult.total).toBe(1);
    expect(migratedResult.integrity_findings).toEqual([]);

    const anchors = await storage.list("_audit_checkpoints", "legacy-anchor-");
    expect(anchors).toHaveLength(1);
    const anchorRaw = await storage.read("_audit_checkpoints", anchors[0]!.key);
    const anchor = JSON.parse(bytesToString(anchorRaw!)) as AuditCheckpointRecord;
    expect(anchor.checkpoint_sequence).toBe(1);
    expect(anchor.root_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(anchor.unsigned).toBe(true);

    await appendCritical(migrated, "after_legacy");
    const v2Key = (await auditKeys(storage)).find((key) => key.startsWith("entry-"));
    const v2 = await readEnvelope(storage, v2Key!);
    expect(v2.sequence).toBe(2);
    expect(v2.prev_hash).toBe(anchor.root_hash);
  });

  it("detects a checkpoint signature mismatch", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const identityKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "checkpoint-signer",
      identityKey,
      "recovery-key"
    );
    const signer = async (payload: AuditCheckpointSigningPayload) => ({
      signer_kid: storedIdentity.identity_id,
      signature: toBase64url(
        identitySign(
          checkpointSigningBytes(payload),
          storedIdentity.encrypted_private_key,
          identityKey
        )
      ),
      public_key: storedIdentity.public_key,
    });
    const writer = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      checkpointSigner: signer,
      checkpointPublicKeyResolver: () => storedIdentity.public_key,
    });
    await appendCritical(writer, "signed_checkpoint");

    const checkpointKey = (await storage.list("_audit_checkpoints", "audit-checkpoint-"))[0]!
      .key;
    const raw = await storage.read("_audit_checkpoints", checkpointKey);
    const checkpoint = JSON.parse(bytesToString(raw!)) as AuditCheckpointRecord;
    checkpoint.signature = toBase64url(new Uint8Array(64));
    await storage.write(
      "_audit_checkpoints",
      checkpointKey,
      stringToBytes(JSON.stringify(checkpoint))
    );

    const reader = new AuditLog(storage, masterKey, {
      checkpointPublicKeyResolver: () => storedIdentity.public_key,
    });
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "checkpoint_signature_mismatch" }),
      ]),
    });
  });

  it("throws in strict mode and returns findings in lenient mode", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const writer = new AuditLog(storage, masterKey);
    await appendCritical(writer, "one");

    const key = (await auditKeys(storage))[0]!;
    const envelope = await readEnvelope(storage, key);
    envelope.entry_hash = "0".repeat(64);
    await writeEnvelope(storage, key, envelope);

    await expectStrictFinding(storage, masterKey, "entry_hash_mismatch");

    const lenient = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const result = await lenient.query({ limit: 100 });
    expect(result.integrity_findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "entry_hash_mismatch" }),
      ])
    );
  });

  it("appends 1000 entries within the performance sanity budget", async () => {
    const storage = new MemoryStorage();
    const masterKey = MASTER_KEY();
    const writer = new AuditLog(storage, masterKey);
    const started = Date.now();

    for (let i = 0; i < 1000; i++) {
      writer.append("l2", `op-${i}`, "id-1", { i });
    }
    await writer.flush();

    expect(Date.now() - started).toBeLessThan(5000);
    expect(await storage.list("_audit")).toHaveLength(1000);
  });
});
