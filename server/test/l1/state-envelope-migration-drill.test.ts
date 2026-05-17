import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { encrypt } from "../../src/core/encryption.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import {
  generateIdentityId,
  publicKeyToDid,
  sign,
  type StoredIdentity,
} from "../../src/core/identity.js";
import { hashToString } from "../../src/core/hashing.js";
import { deriveNamespaceKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  StateStore,
  type StateEntry,
} from "../../src/l1-cognitive/state-store.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";

type ToolResult = { content: Array<{ type: string; text: string }> };
type Tool = {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<ToolResult>;
};

interface Fixture {
  fixture: string;
  schema: 1 | 2;
  namespace: string;
  key: string;
  value: string;
  corruption?: "integrity_hash_mismatch" | "signature_mismatch";
}

const FIXTURE_ROOT = new URL("../fixtures/state-envelope/", import.meta.url);
const MASTER_KEY = new Uint8Array([
  0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
  0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
  0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88,
  0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
]);
const WRITER_PRIVATE_KEY = new Uint8Array([
  0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
  0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
  0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
  0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
]);
const STATE_ENVELOPE_SIGNING_DOMAIN = "sanctuary.state-envelope.v1\n";
const ANCHORS_KEY = "state-envelope-version-anchors-v1";

function fixture(name: string): Fixture {
  return JSON.parse(
    readFileSync(new URL(name, FIXTURE_ROOT), "utf8")
  ) as Fixture;
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => canonicalize(item));
  const record = value as Record<string, unknown>;
  const canonical: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    if (record[key] !== undefined) canonical[key] = canonicalize(record[key]);
  }
  return canonical;
}

function signingBytes(envelope: StateEntry["envelope"]): Uint8Array {
  return stringToBytes(
    STATE_ENVELOPE_SIGNING_DOMAIN + JSON.stringify(canonicalize(envelope))
  );
}

async function callTool(
  tools: Tool[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function makeStoredIdentity(identityEncKey: Uint8Array): StoredIdentity {
  const publicKey = ed25519.getPublicKey(WRITER_PRIVATE_KEY);
  const now = "2026-05-16T00:00:00.000Z";
  const base = {
    identity_id: generateIdentityId(publicKey),
    label: "state-envelope-drill-writer",
    public_key: toBase64url(publicKey),
    did: publicKeyToDid(publicKey),
    created_at: now,
    key_type: "ed25519" as const,
    key_protection: "recovery-key" as const,
  };
  return {
    ...base,
    encrypted_private_key: encrypt(WRITER_PRIVATE_KEY, identityEncKey),
    rotation_history: [],
  };
}

async function makeRig() {
  const storage = new MemoryStorage();
  const stateStore = new StateStore(storage, MASTER_KEY);
  const identityEncKey = derivePurposeKey(MASTER_KEY, "identity-encryption");
  const identity = makeStoredIdentity(identityEncKey);
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), identityEncKey)))
  );
  return { storage, stateStore, identityEncKey, identity };
}

async function readEntry(
  storage: MemoryStorage,
  namespace: string,
  key: string
): Promise<StateEntry> {
  const raw = await storage.read(namespace, key);
  if (!raw) throw new Error(`missing state entry: ${namespace}/${key}`);
  return JSON.parse(bytesToString(raw)) as StateEntry;
}

async function writeEntry(
  storage: MemoryStorage,
  namespace: string,
  key: string,
  entry: StateEntry
): Promise<void> {
  await storage.write(namespace, key, stringToBytes(JSON.stringify(entry)));
}

async function seedLegacyEntry(args: {
  storage: MemoryStorage;
  identity: StoredIdentity;
  identityEncKey: Uint8Array;
  fixture: Fixture;
}): Promise<void> {
  const plaintext = stringToBytes(args.fixture.value);
  const payload = encrypt(
    plaintext,
    deriveNamespaceKey(MASTER_KEY, args.fixture.namespace)
  );
  const signature = sign(
    fromBase64url(payload.ct),
    args.identity.encrypted_private_key,
    args.identityEncKey
  );
  const entry: StateEntry = {
    v: 1,
    payload,
    ver: 1,
    sig: toBase64url(signature),
    kid: args.identity.identity_id,
    integrity_hash: hashToString(plaintext),
    metadata: {
      written_at: "2026-05-16T00:00:01.000Z",
    },
  };
  await writeEntry(args.storage, args.fixture.namespace, args.fixture.key, entry);
}

async function seedSchema2Entry(args: {
  storage: MemoryStorage;
  stateStore: StateStore;
  identity: StoredIdentity;
  identityEncKey: Uint8Array;
  fixture: Fixture;
}): Promise<StateEntry> {
  await args.stateStore.write(
    args.fixture.namespace,
    args.fixture.key,
    args.fixture.value,
    args.identity.identity_id,
    args.identity.encrypted_private_key,
    args.identityEncKey
  );
  return readEntry(args.storage, args.fixture.namespace, args.fixture.key);
}

async function corruptIntegrityHash(args: {
  storage: MemoryStorage;
  identity: StoredIdentity;
  identityEncKey: Uint8Array;
  fixture: Fixture;
}): Promise<void> {
  const entry = await readEntry(args.storage, args.fixture.namespace, args.fixture.key);
  entry.integrity_hash = hashToString(stringToBytes(`${args.fixture.value}:mutated`));
  entry.envelope!.integrity_hash = entry.integrity_hash;
  entry.envelope_sig = toBase64url(
    sign(signingBytes(entry.envelope), args.identity.encrypted_private_key, args.identityEncKey)
  );
  await writeEntry(args.storage, args.fixture.namespace, args.fixture.key, entry);
}

async function corruptSignature(storage: MemoryStorage, target: Fixture): Promise<void> {
  const entry = await readEntry(storage, target.namespace, target.key);
  const sig = fromBase64url(entry.envelope_sig!);
  sig[0] = sig[0]! ^ 0xff;
  entry.envelope_sig = toBase64url(sig);
  await writeEntry(storage, target.namespace, target.key, entry);
}

function makeTools(storage: MemoryStorage, stateStore: StateStore) {
  const auditLog = new AuditLog(storage, MASTER_KEY);
  const { tools } = createL1Tools(
    stateStore,
    storage,
    MASTER_KEY,
    "recovery-key",
    auditLog
  );
  return { auditLog, tools: tools as Tool[] };
}

async function expectCriticalVerificationAudit(
  auditLog: AuditLog,
  classification: string
): Promise<void> {
  const audit = await auditLog.query({
    layer: "l1",
    operation_type: "state_read_verification_failed",
    limit: 10,
  });
  expect(audit.entries.at(-1)).toMatchObject({
    result: "failure",
    details: { classification },
  });
}

describe("state envelope migration drill", () => {
  it("loads legacy entries and auto-migrates representative namespaces to schema-2", async () => {
    const fixtures = [
      fixture("legacy-namespace-a.json"),
      fixture("legacy-namespace-b.json"),
      { ...fixture("legacy-namespace-a.json"), namespace: "policies", key: "legacy-policy" },
    ];
    const { storage, stateStore, identity, identityEncKey } = await makeRig();

    for (const item of fixtures) {
      await seedLegacyEntry({ storage, identity, identityEncKey, fixture: item });
      const read = await stateStore.read(item.namespace, item.key);
      expect(read?.value).toBe(item.value);
      expect(read?.warnings?.[0]?.classification).toBe("legacy_schema_1");

      const raw = await readEntry(storage, item.namespace, item.key);
      expect(raw.v).toBe(2);
      expect(raw.envelope).toMatchObject({
        namespace: item.namespace,
        key: item.key,
        version: 1,
        kid: identity.identity_id,
        metadata: { schema_version: 2 },
      });
      expect(raw.envelope_sig).toEqual(expect.any(String));
    }
  });

  it("rejects corrupt schema-2 envelopes by default with generic denial and critical audit", async () => {
    const payloadTarget = fixture("schema2-corrupt-payload.json");
    const signatureTarget = fixture("schema2-corrupt-signature.json");
    const { storage, stateStore, identity, identityEncKey } = await makeRig();
    const { auditLog, tools } = makeTools(storage, stateStore);

    await seedSchema2Entry({ storage, stateStore, identity, identityEncKey, fixture: payloadTarget });
    await corruptIntegrityHash({ storage, identity, identityEncKey, fixture: payloadTarget });
    const payloadRead = await callTool(tools, "state_read", {
      namespace: payloadTarget.namespace,
      key: payloadTarget.key,
    });
    expect(payloadRead).toMatchObject({
      error: "state_verification_failed",
      classification: "integrity_hash_mismatch",
      message: "State verification failed.",
    });
    await expectCriticalVerificationAudit(auditLog, "integrity_hash_mismatch");

    await seedSchema2Entry({ storage, stateStore, identity, identityEncKey, fixture: signatureTarget });
    await corruptSignature(storage, signatureTarget);
    const signatureRead = await callTool(tools, "state_read", {
      namespace: signatureTarget.namespace,
      key: signatureTarget.key,
    });
    expect(signatureRead).toMatchObject({
      error: "state_verification_failed",
      classification: "signature_mismatch",
      message: "State verification failed.",
    });
    await expectCriticalVerificationAudit(auditLog, "signature_mismatch");
  });

  it("persists rollback anchors across simulated restart", async () => {
    const stale = fixture("schema2-rollback-stale.json");
    const target = fixture("schema2-rollback-target.json");
    const { storage, stateStore, identity, identityEncKey } = await makeRig();

    await seedSchema2Entry({ storage, stateStore, identity, identityEncKey, fixture: stale });
    const staleEntry = await readEntry(storage, stale.namespace, stale.key);
    await stateStore.write(
      target.namespace,
      target.key,
      target.value,
      identity.identity_id,
      identity.encrypted_private_key,
      identityEncKey
    );

    const restarted = new StateStore(storage, MASTER_KEY);
    expect(await restarted.read(target.namespace, target.key)).toMatchObject({
      value: target.value,
      version: 2,
    });
    const anchors = JSON.parse(bytesToString((await storage.read("_meta", ANCHORS_KEY))!));
    expect(anchors[`${target.namespace}/${target.key}`]).toBe(2);

    await writeEntry(storage, stale.namespace, stale.key, staleEntry);
    const { auditLog, tools } = makeTools(storage, new StateStore(storage, MASTER_KEY));
    const rollbackRead = await callTool(tools, "state_read", {
      namespace: stale.namespace,
      key: stale.key,
    });
    expect(rollbackRead).toMatchObject({
      error: "state_verification_failed",
      classification: "rollback_detected",
      message: "State verification failed.",
    });
    await expectCriticalVerificationAudit(auditLog, "rollback_detected");
  });

  it("covers agent-state, reputation-bundle, and policies for legacy migration and corrupt reads", async () => {
    for (const namespace of ["agent-state", "reputation-bundle", "policies"]) {
      const { storage, stateStore, identity, identityEncKey } = await makeRig();
      const item: Fixture = {
        fixture: `representative-${namespace}`,
        schema: 1,
        namespace,
        key: "representative-key",
        value: `legacy ${namespace} value`,
      };
      await seedLegacyEntry({ storage, identity, identityEncKey, fixture: item });
      expect(await stateStore.read(namespace, item.key)).toMatchObject({
        value: item.value,
      });
      expect((await readEntry(storage, namespace, item.key)).v).toBe(2);

      const corrupt: Fixture = {
        ...item,
        schema: 2,
        key: "representative-corrupt",
        value: `corrupt ${namespace} value`,
      };
      await seedSchema2Entry({ storage, stateStore, identity, identityEncKey, fixture: corrupt });
      await corruptIntegrityHash({ storage, identity, identityEncKey, fixture: corrupt });
      const { tools } = makeTools(storage, stateStore);
      await expect(
        callTool(tools, "state_read", { namespace, key: corrupt.key })
      ).resolves.toMatchObject({
        error: "state_verification_failed",
        message: "State verification failed.",
      });
    }
  });
});
