/**
 * IC-05 wired-consumer coverage (AGENTS.md assurance rules 3 and 4).
 *
 * The checkpoint signer and public-key resolver existed and passed their unit
 * tests for months while every production call site omitted them, so shipped
 * fortresses wrote unsigned checkpoints. Unit tests of the helper cannot
 * catch a recurrence: only a test that runs the PRODUCTION object graph can.
 * This file therefore drives two production shapes:
 *
 *  1. The real composition root: `createSanctuaryServer` (the actual
 *     `index.ts` boot path), a real `identity_create` MCP tool call, and the
 *     server's own `AuditLog` instance, asserting the checkpoints that come
 *     out the other side are SIGNED and verify through a second, equally
 *     bare, production-shaped `new AuditLog(storage, masterKey)`.
 *  2. The bare production constructor call over a fortress store, with no
 *     config at all, which is the exact shape ~50 production call sites use.
 *
 * It also proves the assertions are non-vacuous (rule 4's planted
 * divergence): a deliberately unwired signer (the pre-fix production shape)
 * demonstrably produces unsigned checkpoints, and a tampered signature is
 * demonstrably rejected by the default resolver, so a regression in either
 * direction fails a test rather than passing silently.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createSanctuaryServer } from "../../src/index.js";
import { AuditLog, AuditIntegrityError } from "../../src/operational/audit-log.js";
import type { AuditCheckpointRecord } from "../../src/audit/chain.js";
import { createFortressCheckpointIdentityBinding } from "../../src/audit/checkpoint-identity.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, rotateKeys } from "../../src/core/identity.js";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const CHECKPOINT_NAMESPACE = "_audit_checkpoints";
const CHECKPOINT_PREFIX = "audit-checkpoint-";
// Must match DEFAULT_CHECKPOINT_INTERVAL in operational/audit-log.ts: the
// composition-root test drives exactly one production interval so it never
// depends on a test-only interval override.
const PRODUCTION_CHECKPOINT_INTERVAL = 100;

async function readCheckpoints(
  storage: StorageBackend
): Promise<AuditCheckpointRecord[]> {
  const metas = await storage.list(CHECKPOINT_NAMESPACE, CHECKPOINT_PREFIX);
  const records: AuditCheckpointRecord[] = [];
  for (const meta of metas) {
    const raw = await storage.read(CHECKPOINT_NAMESPACE, meta.key);
    if (raw) records.push(JSON.parse(bytesToString(raw)));
  }
  return records;
}

async function appendCriticalEntries(
  auditLog: AuditLog,
  count: number,
  identityId: string
): Promise<void> {
  for (let i = 0; i < count; i++) {
    await auditLog.appendCritical({
      layer: "l2",
      operation: "state_write",
      identity_id: identityId,
      result: "success",
      details: { index: i },
    });
  }
  await auditLog.flush();
}

/** Seed a fortress identity the way IdentityManager persists it (same
 * namespace, key layout, and identity-encryption purpose key), without
 * booting the whole server. */
async function seedStoredIdentity(
  storage: StorageBackend,
  masterKey: Uint8Array,
  label: string
) {
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    label,
    identityEncryptionKey,
    "recovery-key"
  );
  await writeStoredIdentity(storage, identityEncryptionKey, storedIdentity);
  await storage.write(
    "_meta",
    "primary_identity_id",
    stringToBytes(JSON.stringify(storedIdentity.identity_id))
  );
  return { storedIdentity, identityEncryptionKey };
}

async function writeStoredIdentity(
  storage: StorageBackend,
  identityEncryptionKey: Uint8Array,
  identity: ReturnType<typeof createIdentity>["storedIdentity"]
) {
  const encrypted = encrypt(
    stringToBytes(JSON.stringify(identity)),
    identityEncryptionKey
  );
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(JSON.stringify(encrypted))
  );
}

describe("IC-05: bare production constructor signs and verifies checkpoints", () => {
  it("signs checkpoints with the fortress primary identity with NO config supplied", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey, "fortress");

    // The exact production shape: no config object at all.
    const writer = new AuditLog(storage, masterKey);
    await appendCriticalEntries(
      writer,
      PRODUCTION_CHECKPOINT_INTERVAL,
      storedIdentity.identity_id
    );

    const checkpoints = await readCheckpoints(storage);
    expect(checkpoints.length).toBeGreaterThan(0);
    for (const checkpoint of checkpoints) {
      expect(checkpoint.unsigned).toBe(false);
      expect(checkpoint.signer_kid).toBe(storedIdentity.identity_id);
      expect(checkpoint.signature).toBeTruthy();
    }

    // A second bare production instance must verify those signatures through
    // the constructor-derived resolver: zero findings, strict mode survives.
    const reader = new AuditLog(storage, masterKey);
    const result = await reader.query({ limit: 200 });
    expect(result.integrity_findings).toEqual([]);
  });

  it("keeps pre-rotation checkpoints verifiable through the authenticated rotation chain", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity, identityEncryptionKey } = await seedStoredIdentity(
      storage,
      masterKey,
      "rotating"
    );

    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id);
    const [preRotation] = await readCheckpoints(storage);
    expect(preRotation!.unsigned).toBe(false);

    // Rotate the signing identity and persist it, exactly as the identity
    // rotation path does. The old key survives only inside the signed
    // rotation history.
    const { updatedIdentity } = rotateKeys(
      storedIdentity,
      identityEncryptionKey,
      "wiring-test rotation"
    );
    await writeStoredIdentity(storage, identityEncryptionKey, updatedIdentity);

    // Old-key checkpoint must still verify: the default resolver returns the
    // full authenticated key set (current + verified rotation predecessors),
    // so a rotation must never turn historical checkpoints into findings.
    const reader = new AuditLog(storage, masterKey);
    const afterRotation = await reader.query({ limit: 100 });
    expect(afterRotation.integrity_findings).toEqual([]);

    // And a post-rotation checkpoint signs with the NEW key and verifies too.
    const writer2 = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer2, 1, updatedIdentity.identity_id);
    const reader2 = new AuditLog(storage, masterKey);
    const afterSecond = await reader2.query({ limit: 100 });
    expect(afterSecond.integrity_findings).toEqual([]);
  });

  it("writes an honest unsigned checkpoint when the store holds no identity", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 1, "no-identity-fortress");

    const [checkpoint] = await readCheckpoints(storage);
    expect(checkpoint!.unsigned).toBe(true);
    expect(checkpoint!.unsigned_reason).toContain("no signing identity");

    // An unsigned checkpoint is skipped by signature verification, so the
    // fresh-fortress path stays finding-free (today's shipped behavior).
    const reader = new AuditLog(storage, masterKey);
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
  });

  it("planted divergence: the pre-fix unwired shape demonstrably produces unsigned checkpoints", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey, "fortress");

    // Simulate the pre-IC-05 wiring (a signer that never signs). If the
    // constructor default ever regresses to this, the positive assertions in
    // the tests above fail; this test proves they CAN fail by showing the
    // unwired shape flips the exact property they assert.
    const unwired = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      checkpointSigner: async () => null,
    });
    await appendCriticalEntries(unwired, 1, storedIdentity.identity_id);

    const checkpoints = await readCheckpoints(storage);
    expect(checkpoints.length).toBeGreaterThan(0);
    expect(checkpoints.every((checkpoint) => checkpoint.unsigned === true)).toBe(true);
  });

  it("planted divergence: a tampered signature is rejected by the default resolver", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey, "fortress");

    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id);

    const metas = await storage.list(CHECKPOINT_NAMESPACE, CHECKPOINT_PREFIX);
    const raw = await storage.read(CHECKPOINT_NAMESPACE, metas[0]!.key);
    const checkpoint = JSON.parse(bytesToString(raw!)) as AuditCheckpointRecord;
    expect(checkpoint.unsigned).toBe(false);
    // 86 = base64url length of a 64-byte Ed25519 signature, no padding; an
    // all-zero signature of valid shape must fail cryptographic verification,
    // not shape validation.
    checkpoint.signature = "A".repeat(86);
    await storage.write(
      CHECKPOINT_NAMESPACE,
      metas[0]!.key,
      stringToBytes(JSON.stringify(checkpoint))
    );

    const reader = new AuditLog(storage, masterKey);
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "checkpoint_signature_mismatch" }),
      ]),
    } satisfies Partial<AuditIntegrityError>);
  });

  it("silent-downgrade probe: stripping a signed checkpoint to unsigned:true raises checkpoint_signing_downgrade", async () => {
    // The reviewer's empirical probe, kept as a regression test: before the
    // signing latch existed, this exact mutation produced ZERO integrity
    // findings on a strict production reader, indistinguishable from an
    // honest pre-bootstrap fortress (MUST-NEVER #5, silent degrade).
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey, "fortress");

    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id);

    const metas = await storage.list(CHECKPOINT_NAMESPACE, CHECKPOINT_PREFIX);
    const raw = await storage.read(CHECKPOINT_NAMESPACE, metas[0]!.key);
    const checkpoint = JSON.parse(bytesToString(raw!)) as AuditCheckpointRecord;
    expect(checkpoint.unsigned).toBe(false);
    await storage.write(
      CHECKPOINT_NAMESPACE,
      metas[0]!.key,
      stringToBytes(
        JSON.stringify({
          ...checkpoint,
          signer_kid: null,
          signature: null,
          signature_algorithm: null,
          unsigned: true,
          unsigned_reason: "no signing identity available at checkpoint time",
        })
      )
    );

    const reader = new AuditLog(storage, masterKey);
    await expect(reader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "checkpoint_signing_downgrade" }),
      ]),
    } satisfies Partial<AuditIntegrityError>);
  });

  it("forward downgrade: an unsigned checkpoint written after the identity vanished raises the finding", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey, "fortress");

    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id);

    // Remove the signing identity (and the primary pointer to it), so the
    // NEXT checkpoint honestly writes unsigned. The latch remembers signing
    // was established, so that unsigned checkpoint is a downgrade finding,
    // never a quiet return to the pre-bootstrap read.
    await storage.delete("_identities", storedIdentity.identity_id);
    await storage.delete("_meta", "primary_identity_id");
    const writer2 = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer2, 1, "post-identity-loss");

    const checkpoints = await readCheckpoints(storage);
    expect(checkpoints.some((checkpoint) => checkpoint.unsigned === true)).toBe(true);

    const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "checkpoint_signing_downgrade" }),
      ])
    );
  });

  it("migration stays clean: unsigned pre-bootstrap checkpoints below the signing floor raise nothing", async () => {
    // The false-positive guard for every fortress upgraded across IC-05:
    // historical unsigned checkpoints PRECEDE the first signed one and must
    // stay finding-free forever, or the downgrade detector would brick every
    // legitimately migrated store in strict mode.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();

    const preBootstrap = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(preBootstrap, 2, "pre-bootstrap");

    const { storedIdentity } = await seedStoredIdentity(storage, masterKey, "fortress");
    const signedWriter = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(signedWriter, 2, storedIdentity.identity_id);

    const checkpoints = await readCheckpoints(storage);
    expect(checkpoints.some((checkpoint) => checkpoint.unsigned === true)).toBe(true);
    expect(checkpoints.some((checkpoint) => checkpoint.unsigned === false)).toBe(true);

    const reader = new AuditLog(storage, masterKey);
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
  });

  it("a tampered signing latch is a loud finding, never a silent skip", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey, "fortress");

    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id);

    const latchRaw = await storage.read(CHECKPOINT_NAMESPACE, "__signing_latch");
    expect(latchRaw).not.toBeNull();
    const latch = JSON.parse(bytesToString(latchRaw!)) as { mac: string };
    latch.mac = `${latch.mac.slice(0, -2)}AA`;
    await storage.write(
      CHECKPOINT_NAMESPACE,
      "__signing_latch",
      stringToBytes(JSON.stringify(latch))
    );

    const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "checkpoint_signing_downgrade" }),
      ])
    );
  });

  it("latch deletion alone does not disarm the detector: a surviving signed checkpoint keeps the floor", async () => {
    // Second, independent memory (the head-anchor OR pattern): with the latch
    // deleted, an unsigned checkpoint AFTER a still-signed one must still read
    // as a downgrade via the in-store signed-checkpoint floor.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey, "fortress");

    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 2, storedIdentity.identity_id);

    await storage.delete(CHECKPOINT_NAMESPACE, "__signing_latch");
    const metas = await storage.list(CHECKPOINT_NAMESPACE, CHECKPOINT_PREFIX);
    const lastKey = metas[metas.length - 1]!.key;
    const raw = await storage.read(CHECKPOINT_NAMESPACE, lastKey);
    const checkpoint = JSON.parse(bytesToString(raw!)) as AuditCheckpointRecord;
    await storage.write(
      CHECKPOINT_NAMESPACE,
      lastKey,
      stringToBytes(
        JSON.stringify({
          ...checkpoint,
          signer_kid: null,
          signature: null,
          signature_algorithm: null,
          unsigned: true,
          unsigned_reason: "no signing identity available at checkpoint time",
        })
      )
    );

    const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const result = await reader.query({ limit: 100 });
    expect(result.integrity_findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "checkpoint_signing_downgrade" }),
      ])
    );
  });

  it("refuses to let a checkpoint-supplied signer_kid shape a storage lookup", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const binding = createFortressCheckpointIdentityBinding(
      storage,
      derivePurposeKey(masterKey, "identity-encryption")
    );
    // signer_kid is read back from a persisted record, so it is
    // attacker-influenceable by anyone with storage write access; anything
    // that is not a well-formed identity id must resolve to nothing.
    for (const hostile of ["../../evil", "_meta/primary_identity_id", "", "Z".repeat(32)]) {
      expect(await binding.checkpointPublicKeyResolver(hostile)).toBeUndefined();
    }
  });
});

describe("IC-05: real composition root (createSanctuaryServer)", () => {
  let fortressHome: Awaited<ReturnType<typeof createTempHome>>;

  beforeEach(async () => {
    // Hermeticity: the real boot path writes config ambiently, so HOME must
    // be redirected off the operator's real ~/.sanctuary.
    fortressHome = await createTempHome("sanctuary-ic05-wiring");
  });

  afterEach(async () => {
    await fortressHome.cleanup();
  });

  it("the booted server's audit log writes signed checkpoints that a bare production reader verifies", async () => {
    const storage = new MemoryStorage();
    const { server, auditLog, masterKey } = await createSanctuaryServer({
      storage,
      passphrase: TEST_PASSPHRASE,
    });

    // Create the fortress identity through the real MCP pipeline, exactly as
    // an operator's first bootstrap does.
    const handler = (
      server as unknown as { _requestHandlers: Map<string, Function> }
    )._requestHandlers.get("tools/call");
    if (!handler) throw new Error("tools/call handler not registered");
    const created = await handler(
      {
        method: "tools/call" as const,
        params: { name: "identity_create", arguments: { label: "wiring-test" } },
      },
      {}
    );
    const identity = JSON.parse(created.content[0]!.text);
    expect(identity.identity_id).toBeDefined();

    // Drive one full production checkpoint interval on the SERVER'S OWN
    // AuditLog instance (constructed by index.ts with no config), so the
    // checkpoint that comes out is the one production would write.
    await appendCriticalEntries(
      auditLog,
      PRODUCTION_CHECKPOINT_INTERVAL,
      identity.identity_id
    );

    const checkpoints = await readCheckpoints(storage);
    const signed = checkpoints.filter((checkpoint) => checkpoint.unsigned === false);
    expect(signed.length).toBeGreaterThan(0);
    for (const checkpoint of signed) {
      expect(checkpoint.signer_kid).toBe(identity.identity_id);
      expect(checkpoint.signature).toBeTruthy();
    }

    // The wired-consumer closing assertion: a second production-shaped
    // instance over the same fortress store verifies those signatures via
    // the constructor-derived resolver, strict mode, zero findings.
    const reader = new AuditLog(storage, masterKey);
    const result = await reader.query({ limit: 300 });
    expect(result.integrity_findings).toEqual([]);
  }, 60_000);
});
