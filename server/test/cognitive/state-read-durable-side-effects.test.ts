/**
 * A read that did not verify must not mutate durable state
 * (STATE-READ-MIGRATE-01, STATE-READ-ANCHOR-01).
 *
 * `readInternal` has exactly two durable side effects: the legacy-schema
 * migration (which overwrites the entry in place) and the version-anchor
 * advance (which raises a MAC-authenticated monotone floor). Both must be
 * gated on the OUTCOME of signature verification, never on the request option
 * that asked for verification.
 *
 * These tests assert the MECHANISM, not the return value: they compare the
 * on-disk bytes of the entry and the on-disk anchor record across the read.
 * The verified counterpart of each case is asserted in the same file so a
 * regression that simply disables the capability cannot pass.
 */
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
import {
  deriveNamespaceKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import { StateStore, type StateEntry } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const MASTER_KEY = new Uint8Array([
  0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
  0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x10,
  0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97,
  0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00, 0x1f,
]);
const WRITER_PRIVATE_KEY = new Uint8Array([
  0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
  0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01,
  0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87,
  0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0x0f,
]);

// CONTRACT PIN (server/src/cognitive/state-store.ts
// `STATE_ENVELOPE_VERSION_ANCHORS_KEY`): the anchor record's `_meta` key is not
// exported, so this test mirrors it. Must match that constant.
const ANCHORS_NAMESPACE = "_meta";
const ANCHORS_KEY = "state-envelope-version-anchors-v1";

/**
 * A rotation hop whose `old_public_key` is not a 32-byte Ed25519 key. The
 * rotation chain therefore fails to verify, so
 * `resolveAuthenticatedIdentityWriterPublicKeys` yields NO authenticated writer
 * key for this identity. That is the shape that makes a legacy-schema read
 * return `verified: false` WITHOUT throwing, which is the exact state in which
 * a durable side effect must not fire. The identity record itself still parses,
 * so the migration path can still resolve it: that asymmetry is the point.
 */
const CHAIN_BREAKING_ROTATION_HOP = {
  old_public_key: "AAAA",
  new_public_key: "BBBB",
  rotation_event: "e30",
  rotated_at: "2026-05-16T00:00:00.000Z",
};

function makeStoredIdentity(
  identityEncKey: Uint8Array,
  options: { breakRotationChain: boolean }
): StoredIdentity {
  const publicKey = ed25519.getPublicKey(WRITER_PRIVATE_KEY);
  return {
    identity_id: generateIdentityId(publicKey),
    label: "durable-side-effect-writer",
    public_key: toBase64url(publicKey),
    did: publicKeyToDid(publicKey),
    created_at: "2026-05-16T00:00:00.000Z",
    key_type: "ed25519",
    key_protection: "recovery-key",
    encrypted_private_key: encrypt(WRITER_PRIVATE_KEY, identityEncKey),
    rotation_history: options.breakRotationChain
      ? [CHAIN_BREAKING_ROTATION_HOP]
      : [],
  };
}

async function makeRig(options: { breakRotationChain: boolean }) {
  const storage = new MemoryStorage();
  const stateStore = new StateStore(storage, MASTER_KEY);
  const identityEncKey = derivePurposeKey(MASTER_KEY, "identity-encryption");
  const identity = makeStoredIdentity(identityEncKey, options);
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(
      JSON.stringify(
        encrypt(stringToBytes(JSON.stringify(identity)), identityEncKey)
      )
    )
  );
  return { storage, stateStore, identityEncKey, identity };
}

/** Seed a legacy (schema-1) entry signed over the ciphertext by the writer. */
async function seedLegacyEntry(args: {
  storage: MemoryStorage;
  identity: StoredIdentity;
  identityEncKey: Uint8Array;
  namespace: string;
  key: string;
  value: string;
  version: number;
}): Promise<void> {
  const plaintext = stringToBytes(args.value);
  const payload = encrypt(
    plaintext,
    deriveNamespaceKey(MASTER_KEY, args.namespace)
  );
  const entry: StateEntry = {
    v: 1,
    payload,
    ver: args.version,
    sig: toBase64url(
      sign(
        fromBase64url(payload.ct),
        args.identity.encrypted_private_key,
        args.identityEncKey
      )
    ),
    kid: args.identity.identity_id,
    integrity_hash: hashToString(plaintext),
    metadata: { written_at: "2026-05-16T00:00:01.000Z" },
  };
  await args.storage.write(
    args.namespace,
    args.key,
    stringToBytes(JSON.stringify(entry))
  );
}

async function rawBytes(
  storage: MemoryStorage,
  namespace: string,
  key: string
): Promise<string | null> {
  const raw = await storage.read(namespace, key);
  return raw ? bytesToString(raw) : null;
}

describe("read-path durable side effects require a verified read", () => {
  it("leaves the on-disk entry byte-identical when the read did not verify", async () => {
    const { storage, stateStore, identity, identityEncKey } = await makeRig({
      breakRotationChain: true,
    });
    await seedLegacyEntry({
      storage,
      identity,
      identityEncKey,
      namespace: "memories",
      key: "unverified-legacy",
      value: "evidence-under-investigation",
      version: 1,
    });

    const before = await rawBytes(storage, "memories", "unverified-legacy");
    expect(before).not.toBeNull();

    const read = await stateStore.read("memories", "unverified-legacy");
    expect(read?.value).toBe("evidence-under-investigation");
    expect(read?.signature_verified).toBe(false);

    const after = await rawBytes(storage, "memories", "unverified-legacy");
    expect(after).toBe(before);
    // The entry is still schema-1: nothing re-signed it under a locally
    // resolved identity, so the original bytes survive for a later read.
    expect((JSON.parse(after!) as StateEntry).v).toBe(1);
  });

  it("still migrates the on-disk entry when the read DID verify", async () => {
    const { storage, stateStore, identity, identityEncKey } = await makeRig({
      breakRotationChain: false,
    });
    await seedLegacyEntry({
      storage,
      identity,
      identityEncKey,
      namespace: "memories",
      key: "verified-legacy",
      value: "routine-legacy-value",
      version: 1,
    });

    const before = await rawBytes(storage, "memories", "verified-legacy");
    const read = await stateStore.read("memories", "verified-legacy");
    expect(read?.value).toBe("routine-legacy-value");
    expect(read?.signature_verified).toBe(true);

    const after = await rawBytes(storage, "memories", "verified-legacy");
    expect(after).not.toBe(before);
    const migrated = JSON.parse(after!) as StateEntry;
    expect(migrated.v).toBe(2);
    expect(migrated.envelope_sig).toEqual(expect.any(String));
  });

  it("does not raise the persisted version anchor on a read that did not verify", async () => {
    const { storage, stateStore, identity, identityEncKey } = await makeRig({
      breakRotationChain: true,
    });
    await seedLegacyEntry({
      storage,
      identity,
      identityEncKey,
      namespace: "memories",
      key: "unverified-anchor",
      value: "anchor-probe",
      version: 7,
    });

    const before = await rawBytes(storage, ANCHORS_NAMESPACE, ANCHORS_KEY);
    expect(before).toBeNull();

    const read = await stateStore.read("memories", "unverified-anchor");
    expect(read?.signature_verified).toBe(false);

    // The anchor floor is monotone, so a pin taken from an unattested version
    // could never be lowered again; the read must leave the record untouched.
    const after = await rawBytes(storage, ANCHORS_NAMESPACE, ANCHORS_KEY);
    expect(after).toBe(before);
  });

  it("still raises the persisted version anchor when the read DID verify", async () => {
    const { storage, stateStore, identity, identityEncKey } = await makeRig({
      breakRotationChain: false,
    });
    await seedLegacyEntry({
      storage,
      identity,
      identityEncKey,
      namespace: "memories",
      key: "verified-anchor",
      value: "anchor-probe",
      version: 7,
    });

    expect(await rawBytes(storage, ANCHORS_NAMESPACE, ANCHORS_KEY)).toBeNull();

    const read = await stateStore.read("memories", "verified-anchor");
    expect(read?.signature_verified).toBe(true);

    const after = await rawBytes(storage, ANCHORS_NAMESPACE, ANCHORS_KEY);
    expect(after).not.toBeNull();
    const anchors = JSON.parse(after!) as { data: Record<string, number> };
    expect(anchors.data["memories/verified-anchor"]).toBe(7);
  });
});
