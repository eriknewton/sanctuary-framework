// fail-before-exempt: new state-entry opener module, no base behaviour; the state store's read is the parity reference.
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { generateIdentityId, publicKeyToDid, type StoredIdentity } from "../../src/core/identity.js";
import { hashToString } from "../../src/core/hashing.js";
import { deriveNamespaceKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { StateStore, type StateEntry } from "../../src/cognitive/state-store.js";
import { openStateEntry } from "../../src/cognitive/state-entry-open.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const MASTER_KEY = Uint8Array.from({ length: 32 }, (_, index) => (index * 7 + 3) & 0xff);
const WRITER_PRIVATE_KEY = Uint8Array.from({ length: 32 }, (_, index) => (index * 11 + 5) & 0xff);
const OTHER_PRIVATE_KEY = Uint8Array.from({ length: 32 }, (_, index) => (index * 13 + 1) & 0xff);
const NAMESPACE = "notes";

async function makeRig() {
  const storage = new MemoryStorage();
  const stateStore = new StateStore(storage, MASTER_KEY);
  const identityEncKey = derivePurposeKey(MASTER_KEY, "identity-encryption");
  const publicKey = ed25519.getPublicKey(WRITER_PRIVATE_KEY);
  const identity: StoredIdentity = {
    identity_id: generateIdentityId(publicKey),
    label: "opener-fixture-writer",
    public_key: toBase64url(publicKey),
    did: publicKeyToDid(publicKey),
    created_at: "2026-11-22T00:00:00.000Z",
    key_type: "ed25519",
    key_protection: "recovery-key",
    encrypted_private_key: encrypt(WRITER_PRIVATE_KEY, identityEncKey),
    rotation_history: [],
  };
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), identityEncKey))),
  );
  const resolveWriterKeys = async (kid: string) => (kid === identity.identity_id ? [publicKey] : []);
  return { storage, stateStore, identity, identityEncKey, resolveWriterKeys };
}

async function rawEntry(storage: MemoryStorage, key: string): Promise<Uint8Array> {
  const raw = await storage.read(NAMESPACE, key);
  if (raw === null) throw new Error("fixture entry missing");
  return raw;
}

/** A schema-1 entry signed over its ciphertext by the fixture writer, with a chosen integrity hash. */
async function plantLegacyEntry(storage: MemoryStorage, kid: string, key: string, value: string, integrityHash?: string) {
  const plaintext = stringToBytes(value);
  const payload = encrypt(plaintext, deriveNamespaceKey(MASTER_KEY, NAMESPACE));
  const signature = ed25519.sign(Buffer.from(payload.ct, "base64url"), WRITER_PRIVATE_KEY);
  const entry: StateEntry = {
    v: 1,
    payload,
    ver: 1,
    sig: toBase64url(signature),
    kid,
    integrity_hash: integrityHash ?? hashToString(plaintext),
    metadata: { written_at: "2026-11-22T00:00:01.000Z" },
  };
  await storage.write(NAMESPACE, key, stringToBytes(JSON.stringify(entry)));
}

function classification(promise: Promise<unknown>): Promise<string | undefined> {
  return promise.then(
    () => undefined,
    (error: unknown) => (error as { classification?: string }).classification,
  );
}

describe("state entry opener", () => {
  it("a record opened through the extracted function equals the state store's read", async () => {
    const { storage, stateStore, identity, identityEncKey, resolveWriterKeys } = await makeRig();
    await stateStore.write(NAMESPACE, "entry", "a routine value", identity.identity_id, identity.encrypted_private_key, identityEncKey, { provenance: { origin_actor: "operator" } });

    const opened = await openStateEntry(await rawEntry(storage, "entry"), {
      namespace: NAMESPACE,
      key: "entry",
      namespaceKey: deriveNamespaceKey(MASTER_KEY, NAMESPACE),
      resolveWriterKeys,
    });
    const read = await stateStore.read(NAMESPACE, "entry");
    expect(read?.signature_verified).toBe(true);
    expect(opened.value).toBe(read?.value);
    expect(opened.entry.kid).toBe(identity.identity_id);
  });

  it("a record whose signature does not verify is refused as the state store refuses it", async () => {
    const { storage, stateStore, identity, identityEncKey, resolveWriterKeys } = await makeRig();
    await stateStore.write(NAMESPACE, "entry", "a routine value", identity.identity_id, identity.encrypted_private_key, identityEncKey, { provenance: { origin_actor: "operator" } });
    const entry = JSON.parse(new TextDecoder().decode(await rawEntry(storage, "entry"))) as StateEntry;
    entry.sig = toBase64url(ed25519.sign(Buffer.from(entry.payload.ct, "base64url"), OTHER_PRIVATE_KEY));
    await storage.write(NAMESPACE, "entry", stringToBytes(JSON.stringify(entry)));

    const options = { namespace: NAMESPACE, key: "entry", namespaceKey: deriveNamespaceKey(MASTER_KEY, NAMESPACE), resolveWriterKeys };
    const opened = await classification(openStateEntry(await rawEntry(storage, "entry"), options));
    expect(opened).toBe("signature_mismatch");
    expect(await classification(stateStore.read(NAMESPACE, "entry"))).toBe(opened);
  });

  it("a record whose writer cannot be established is refused as the state store refuses it", async () => {
    const { storage, stateStore, resolveWriterKeys } = await makeRig();
    await plantLegacyEntry(storage, "sanctuary-no-such-writer-identity", "orphan", "an unattributable value");

    const options = { namespace: NAMESPACE, key: "orphan", namespaceKey: deriveNamespaceKey(MASTER_KEY, NAMESPACE), resolveWriterKeys };
    const opened = await classification(openStateEntry(await rawEntry(storage, "orphan"), options));
    expect(opened).toBe("writer_unverified");
    expect(await classification(stateStore.read(NAMESPACE, "orphan"))).toBe(opened);
  });

  it("a record whose integrity hash does not match its plaintext is refused as the state store refuses it", async () => {
    const { storage, stateStore, identity, resolveWriterKeys } = await makeRig();
    await plantLegacyEntry(storage, identity.identity_id, "drifted", "a signed value", hashToString(stringToBytes("some other value")));

    const options = { namespace: NAMESPACE, key: "drifted", namespaceKey: deriveNamespaceKey(MASTER_KEY, NAMESPACE), resolveWriterKeys };
    const opened = await classification(openStateEntry(await rawEntry(storage, "drifted"), options));
    expect(opened).toBe("integrity_hash_mismatch");
    expect(await classification(stateStore.read(NAMESPACE, "drifted"))).toBe(opened);
  });

  it("a record opened under the wrong namespace key is refused", async () => {
    const { storage, stateStore, identity, identityEncKey, resolveWriterKeys } = await makeRig();
    await stateStore.write(NAMESPACE, "entry", "a routine value", identity.identity_id, identity.encrypted_private_key, identityEncKey, { provenance: { origin_actor: "operator" } });

    await expect(
      openStateEntry(await rawEntry(storage, "entry"), {
        namespace: NAMESPACE,
        key: "entry",
        namespaceKey: deriveNamespaceKey(MASTER_KEY, "another-namespace"),
        resolveWriterKeys,
      }),
    ).rejects.toThrow();
  });
});
