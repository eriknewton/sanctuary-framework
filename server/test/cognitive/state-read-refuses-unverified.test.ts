/**
 * CAPABILITY (STATE-READ-REFUSE-01): the enforcing read path returns a value
 * only when signature verification established who wrote the entry. An entry
 * whose writer cannot be established is REFUSED with the distinct
 * classification `writer_unverified`, so the obligation sits at one line
 * rather than at every caller that has to remember to inspect a flag.
 *
 * These tests assert the MECHANISM, not the property. Each one pins a specific
 * discriminator rather than "the read did not return":
 *
 *   - the refusal carries `writer_unverified`, which is what tells a caller
 *     that restoring the writer identity, not repairing the entry, is the
 *     remedy;
 *   - a verified entry still reads, so a change that merely stopped reads
 *     working could not pass;
 *   - `readUnverified` still returns the SAME entry the enforcing path
 *     refuses, which is the only thing that makes the split meaningful;
 *   - an entry that is both unattributable and below its anchor is reported
 *     as the rollback, proving the refusal is ordered below the detection it
 *     would otherwise mask;
 *   - the owner's `list`, `export`, and `delete` still reach a refused entry,
 *     which is the AGENTS.md MUST-NEVER #2 obligation the refusal must not
 *     trade away. The export assertion decrypts the exported bytes with the
 *     owner's own namespace key, because a bundle that merely CONTAINS opaque
 *     bytes would not prove the owner can still get their data out.
 */
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { decrypt, encrypt } from "../../src/core/encryption.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import {
  generateIdentityId,
  publicKeyToDid,
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
  0x5a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
  0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
  0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
  0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
]);
const WRITER_PRIVATE_KEY = new Uint8Array([
  0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
  0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
  0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
  0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
]);

// CONTRACT PIN (server/src/cognitive/state-store.ts
// `STATE_ENVELOPE_VERSION_ANCHORS_KEY`): the anchor record's `_meta` key is not
// exported, so this test mirrors it. Must match that constant.
const ANCHORS_NAMESPACE = "_meta";
const ANCHORS_KEY = "state-envelope-version-anchors-v1";

const NAMESPACE = "memories";

function makeStoredIdentity(identityEncKey: Uint8Array): StoredIdentity {
  const publicKey = ed25519.getPublicKey(WRITER_PRIVATE_KEY);
  return {
    identity_id: generateIdentityId(publicKey),
    label: "refusal-fixture-writer",
    public_key: toBase64url(publicKey),
    did: publicKeyToDid(publicKey),
    created_at: "2026-08-18T00:00:00.000Z",
    key_type: "ed25519",
    key_protection: "recovery-key",
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
    stringToBytes(
      JSON.stringify(
        encrypt(stringToBytes(JSON.stringify(identity)), identityEncKey)
      )
    )
  );
  return { storage, stateStore, identityEncKey, identity };
}

/**
 * Plant a legacy (schema-1) entry whose `kid` resolves to NO stored identity
 * and to no AUTHENTICATED registry key. `verifyEntrySignature` short-circuits
 * the v1 branch and returns `verified: false` WITHOUT throwing as soon as no
 * authenticated writer key resolves, so this is the one persisted shape that
 * used to hand a value back with the writer unestablished. Everything else
 * either verifies or throws a more specific classification, which is why this
 * fixture is the whole reachable surface of the refusal.
 */
async function plantUnattributableLegacyEntry(args: {
  storage: MemoryStorage;
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
    // ED25519_SIGNATURE_BYTES = 64; the value is irrelevant because no key
    // resolves for `kid`, which is the point of this fixture.
    sig: toBase64url(new Uint8Array(64)),
    kid: "sanctuary-no-such-writer-identity",
    integrity_hash: hashToString(plaintext),
    metadata: { written_at: "2026-08-18T00:00:01.000Z" },
  };
  await args.storage.write(
    args.namespace,
    args.key,
    stringToBytes(JSON.stringify(entry))
  );
}

describe("the enforcing read path refuses a value it cannot attribute", () => {
  it("refuses with `writer_unverified` when the writer cannot be established", async () => {
    const { storage, stateStore } = await makeRig();
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "orphaned",
      value: "value-with-no-establishable-writer",
      version: 1,
    });

    const refusal = await stateStore
      .read(NAMESPACE, "orphaned")
      .then(() => null)
      .catch((err: unknown) => err as { name?: string; classification?: string });

    // Assert the DISCRIMINATOR, not merely that the read failed: the value of
    // this change is a caller being able to tell this outcome apart from the
    // other four, and an assertion on "it threw" would survive collapsing them.
    expect(refusal?.name).toBe("StateVerificationError");
    expect(refusal?.classification).toBe("writer_unverified");
    expect(refusal?.classification).not.toBe("kid_unknown");
    expect(refusal?.classification).not.toBe("integrity_hash_mismatch");
    expect(refusal?.classification).not.toBe("rollback_detected");
  });

  it("still returns a verified entry", async () => {
    const { stateStore, identity, identityEncKey } = await makeRig();
    await stateStore.write(
      NAMESPACE,
      "attributable",
      "routine-value",
      identity.identity_id,
      identity.encrypted_private_key,
      identityEncKey
    );

    const read = await stateStore.read(NAMESPACE, "attributable");
    expect(read?.value).toBe("routine-value");
    expect(read?.signature_verified).toBe(true);
  });

  it("still returns through the unverified escape hatch the enforcing path refuses", async () => {
    const { storage, stateStore } = await makeRig();
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "escape-hatch",
      value: "reachable-for-migration",
      version: 1,
    });

    // Same store, same entry, same call: only `verifySignature` differs. The
    // refusal is conditioned on verification having been REQUESTED, so a
    // migration flow that must reach the plaintext first is unaffected.
    await expect(stateStore.read(NAMESPACE, "escape-hatch")).rejects.toMatchObject(
      { classification: "writer_unverified" }
    );
    const unverified = await stateStore.readUnverified(NAMESPACE, "escape-hatch");
    expect(unverified?.value).toBe("reachable-for-migration");
    expect(unverified?.signature_verified).toBe(false);
  });

  it("reports the rollback, not the refusal, when the entry is also below its anchor", async () => {
    const { storage, stateStore, identity, identityEncKey } = await makeRig();
    for (let version = 1; version <= 4; version += 1) {
      await stateStore.write(
        NAMESPACE,
        "policy",
        `ALLOW=v${version}`,
        identity.identity_id,
        identity.encrypted_private_key,
        identityEncKey
      );
    }
    const anchors = await storage.read(ANCHORS_NAMESPACE, ANCHORS_KEY);
    expect(
      (JSON.parse(bytesToString(anchors!)) as { data: Record<string, number> })
        .data[`${NAMESPACE}/policy`]
    ).toBe(4);

    // Both conditions hold at once: this entry cannot be attributed AND it sits
    // below the persisted floor.
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "policy",
      value: "ALLOW=nobody",
      version: 1,
    });

    // Cold process: the in-memory version cache is empty, so the persisted
    // anchor is the discriminator.
    const restarted = new StateStore(storage, MASTER_KEY);
    await expect(restarted.read(NAMESPACE, "policy")).rejects.toMatchObject({
      classification: "rollback_detected",
    });
  });

  it("leaves the owner able to list, export, and delete a refused entry", async () => {
    const { storage, stateStore } = await makeRig();
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "owner-data",
      value: "the-owner-must-still-get-this-out",
      version: 1,
    });
    await expect(stateStore.read(NAMESPACE, "owner-data")).rejects.toMatchObject({
      classification: "writer_unverified",
    });

    // INSPECT: `list` reads metadata straight from the storage backend and
    // never routes through `readInternal`, so the refused key is still visible.
    const listed = await stateStore.list(NAMESPACE);
    expect(listed.keys.map((entry) => entry.key)).toContain("owner-data");

    // EXPORT: `exportNamespaces` also serializes from the storage backend, so
    // the refused entry is still in the bundle, and the owner, who holds the
    // master key the namespace key derives from, can still recover the
    // plaintext. Asserting only that the bundle contains the key would not
    // distinguish "exportable" from "exported as unreadable bytes".
    const exported = await stateStore.export(NAMESPACE);
    const bundle = JSON.parse(
      bytesToString(fromBase64url(exported.bundle))
    ) as { data: Record<string, Array<{ key: string; entry: StateEntry }>> };
    const exportedItem = bundle.data[NAMESPACE]!.find(
      (item) => item.key === "owner-data"
    );
    expect(exportedItem).toBeDefined();
    expect(
      bytesToString(
        decrypt(
          exportedItem!.entry.payload,
          deriveNamespaceKey(MASTER_KEY, NAMESPACE)
        )
      )
    ).toBe("the-owner-must-still-get-this-out");

    // DELETE: also independent of the read path.
    const deleted = await stateStore.delete(NAMESPACE, "owner-data");
    expect(deleted.deleted).toBe(true);
    expect(await storage.read(NAMESPACE, "owner-data")).toBeNull();
  });
});
