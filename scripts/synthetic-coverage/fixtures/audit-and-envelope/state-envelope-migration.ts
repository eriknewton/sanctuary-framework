import { encrypt } from "../../../../server/src/core/encryption.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../../../server/src/core/encoding.js";
import {
  createIdentity,
  sign,
  type StoredIdentity,
} from "../../../../server/src/core/identity.js";
import { hashToString } from "../../../../server/src/core/hashing.js";
import { deriveNamespaceKey, derivePurposeKey } from "../../../../server/src/core/key-derivation.js";
import {
  StateStore,
  StateVerificationError,
  type StateEntry,
} from "../../../../server/src/cognitive/state-store.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";
import { registerFixture, type FixtureOutcome } from "../../registry.js";

const CLAIM_ID = "6";
const CLAIM_LABEL = "State envelope integrity / default verify-on-read";
const MASTER_KEY = new Uint8Array([
  0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
  0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
  0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88,
  0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
]);

interface Rig {
  storage: MemoryStorage;
  stateStore: StateStore;
  identityEncKey: Uint8Array;
  identity: StoredIdentity;
}

function outcome(started: number, passed: boolean, message?: string): FixtureOutcome {
  return {
    passed,
    message: passed ? undefined : message,
    durationMs: Math.round(performance.now() - started),
  };
}

function storedIdentity(identityEncKey: Uint8Array): StoredIdentity {
  return createIdentity(
    "synthetic-state-envelope-writer",
    identityEncKey,
    "recovery-key"
  ).storedIdentity;
}

async function rig(): Promise<Rig> {
  const storage = new MemoryStorage();
  const stateStore = new StateStore(storage, MASTER_KEY);
  const identityEncKey = derivePurposeKey(MASTER_KEY, "identity-encryption");
  const identity = storedIdentity(identityEncKey);
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), identityEncKey)))
  );
  return { storage, stateStore, identityEncKey, identity };
}

async function readEntry(storage: MemoryStorage, namespace: string, key: string): Promise<StateEntry> {
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
  namespace: string;
  key: string;
  value: string;
}): Promise<StateEntry> {
  const plaintext = stringToBytes(args.value);
  const payload = encrypt(plaintext, deriveNamespaceKey(MASTER_KEY, args.namespace));
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
      written_at: "2026-05-19T00:00:01.000Z",
    },
  };
  await writeEntry(args.storage, args.namespace, args.key, entry);
  return entry;
}

async function seedSchema2Entry(
  target: Rig,
  namespace: string,
  key: string,
  value: string
): Promise<void> {
  await target.stateStore.write(
    namespace,
    key,
    value,
    target.identity.identity_id,
    target.identity.encrypted_private_key,
    target.identityEncKey
  );
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "state-envelope-migration: v1-to-v2", async () => {
  const started = performance.now();
  const target = await rig();
  await seedLegacyEntry({
    storage: target.storage,
    identity: target.identity,
    identityEncKey: target.identityEncKey,
    namespace: "agent-state",
    key: "legacy-profile",
    value: "legacy state value",
  });

  const read = await target.stateStore.read("agent-state", "legacy-profile");
  const migrated = await readEntry(target.storage, "agent-state", "legacy-profile");
  const passed =
    read?.value === "legacy state value" &&
    read.warnings?.[0]?.classification === "legacy_schema_1" &&
    migrated.v === 2 &&
    migrated.envelope?.namespace === "agent-state" &&
    migrated.envelope?.key === "legacy-profile" &&
    typeof migrated.envelope_sig === "string";

  return outcome(started, passed, "Legacy v1 entry did not migrate cleanly to schema 2");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "state-envelope-migration: malformed envelope", async () => {
  const started = performance.now();
  const target = await rig();
  await seedSchema2Entry(target, "agent-state", "malformed", "schema 2 value");
  const entry = await readEntry(target.storage, "agent-state", "malformed");
  entry.envelope!.namespace = "forged-namespace";
  await writeEntry(target.storage, "agent-state", "malformed", entry);

  try {
    await new StateStore(target.storage, MASTER_KEY).read("agent-state", "malformed");
    return outcome(started, false, "Malformed schema 2 envelope was accepted");
  } catch (err) {
    const passed =
      err instanceof StateVerificationError && err.classification === "schema_mismatch";
    return outcome(started, passed, `Expected schema_mismatch, got ${String(err)}`);
  }
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "state-envelope-migration: future-version rejected", async () => {
  const started = performance.now();
  const target = await rig();
  await seedSchema2Entry(target, "agent-state", "future-version", "schema 2 value");
  const entry = await readEntry(target.storage, "agent-state", "future-version");
  entry.v = 4;
  await writeEntry(target.storage, "agent-state", "future-version", entry);

  try {
    await new StateStore(target.storage, MASTER_KEY).read("agent-state", "future-version");
    return outcome(started, false, "Future schema version was accepted");
  } catch (err) {
    const passed =
      err instanceof StateVerificationError && err.classification === "schema_mismatch";
    return outcome(started, passed, `Expected schema_mismatch, got ${String(err)}`);
  }
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "state-envelope-migration: partial rollback", async () => {
  const started = performance.now();
  const target = await rig();
  const legacy = await seedLegacyEntry({
    storage: target.storage,
    identity: target.identity,
    identityEncKey: target.identityEncKey,
    namespace: "agent-state",
    key: "rollback-profile",
    value: "legacy rollback value",
  });
  await target.stateStore.read("agent-state", "rollback-profile");
  await seedSchema2Entry(target, "agent-state", "rollback-profile", "schema 2 value");
  await writeEntry(target.storage, "agent-state", "rollback-profile", legacy);

  const unverified = await new StateStore(target.storage, MASTER_KEY).readUnverified(
    "agent-state",
    "rollback-profile"
  );

  try {
    await new StateStore(target.storage, MASTER_KEY).read("agent-state", "rollback-profile");
    return outcome(started, false, "Rolled-back legacy entry was accepted by verified read");
  } catch (err) {
    const passed =
      unverified?.value === "legacy rollback value" &&
      err instanceof StateVerificationError &&
      err.classification === "rollback_detected";
    return outcome(started, passed, `Expected deterministic v1 recovery plus rollback_detected, got ${String(err)}`);
  }
});
