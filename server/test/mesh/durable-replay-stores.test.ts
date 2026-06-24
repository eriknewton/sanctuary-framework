/**
 * Durability tests for the two federation single-use replay stores.
 *
 * The DEBT these close: both the local-join nonce store and the operator-cloud
 * provision-claim store were in-memory only, so a daemon restart mid-TTL FORGOT a
 * spent nonce / consumed claim and re-allowed that one already-authorized token
 * until its (<=15 min) expiry. These tests prove the durable backend remembers
 * the spent set across a restart (a NEW store instance over the SAME storage),
 * fails closed on a persist failure and a corrupt record, prunes expired entries,
 * and keeps the pure in-memory path working for non-persistent callers.
 *
 * Headline (a): RESTART replay denied for BOTH stores.
 * (b) persist-failure -> consume DENIES (failing storage injected).
 * (c) corrupt durable record -> fail closed (deny), no silent reset.
 * (d) expired entries pruned on load.
 * (e) in-memory back-compat (no backend) still works.
 *
 * Deterministic in-memory storage fakes only; keychain-free; no sockets / temp
 * dirs (no teardown races).
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import {
  BootstrapNonceStore,
  BOOTSTRAP_NONCE_STORE_NAMESPACE,
  BOOTSTRAP_NONCE_STORE_KEY,
} from "../../src/mesh/lifecycle/standalone-join-approver.js";
import {
  OperatorCloudProvisionClaimStore,
  OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE,
  OPERATOR_CLOUD_CLAIM_STORE_KEY,
  type RecordProvisionClaimParams,
} from "../../src/mesh/lifecycle/operator-cloud-join-approver.js";
import {
  DurableSpentSetStore,
  DurableSpentSetStoreError,
} from "../../src/mesh/lifecycle/durable-spent-set-store.js";
import { DurableClaimSetStore } from "../../src/mesh/lifecycle/durable-claim-set-store.js";

const FORTRESS = "fortress-1";
const NODE = "node-1";
const NONCE = "nonce-abc";

/** A 32-byte custody master stand-in (deterministic, keychain-free). */
function masterKey(): Uint8Array {
  return new Uint8Array(32).fill(7);
}

/** A storage backend whose `write` always throws (persist-failure injection). */
class FailingWriteStorage extends MemoryStorage {
  override async write(): Promise<void> {
    throw new Error("disk write failed");
  }
}

/** A storage backend that returns a non-decryptable blob for any read. */
class CorruptReadStorage implements StorageBackend {
  async write(): Promise<void> {}
  async read(): Promise<Uint8Array | null> {
    // Valid EncryptedPayload JSON shape, but ciphertext that will fail AEAD.
    const garbage = JSON.stringify({
      v: 1,
      alg: "aes-256-gcm",
      iv: "AAAAAAAAAAAAAAAA",
      ct: "AAAAAAAAAAAAAAAAAAAAAA",
      ts: new Date().toISOString(),
    });
    return new TextEncoder().encode(garbage);
  }
  async delete(): Promise<boolean> {
    return false;
  }
  async list(): Promise<StorageEntryMeta[]> {
    return [];
  }
  async exists(): Promise<boolean> {
    return true;
  }
  async totalSize(): Promise<number> {
    return 0;
  }
}

function claimParams(overrides?: Partial<RecordProvisionClaimParams>): RecordProvisionClaimParams {
  return {
    fortress_id: FORTRESS,
    node_id: NODE,
    node_pubkey_hash: "pubkey-hash",
    bootstrap_nonce: NONCE,
    manifest_digest: "md",
    scoped_secret_ciphertext_digest: "ccd",
    scope_digest: "sd",
    bundle_digest: "bd",
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    ...overrides,
  };
}

describe("durable nonce store — RESTART replay denied (criterion a, headline)", () => {
  it("a new store instance over the SAME storage remembers a spent nonce", async () => {
    const storage = new MemoryStorage();
    const expiresAtMs = Date.now() + 60_000;

    // Boot 1: consume the nonce. First use approved (true).
    const store1 = BootstrapNonceStore.durableFromBoot(storage, masterKey());
    expect(await store1.consume(FORTRESS, NODE, NONCE, expiresAtMs)).toBe(true);

    // Boot 2: a fresh instance loads from the same encrypted storage. The replay
    // of the SAME nonce is DENIED. On `main` (in-memory only) this would ALLOW.
    const store2 = BootstrapNonceStore.durableFromBoot(storage, masterKey());
    expect(await store2.consume(FORTRESS, NODE, NONCE, expiresAtMs)).toBe(false);

    // A DIFFERENT nonce is still independently allowed after restart.
    expect(await store2.consume(FORTRESS, NODE, "nonce-other", expiresAtMs)).toBe(true);
  });

  it("the spent nonce was persisted under the frozen namespace + key", async () => {
    const storage = new MemoryStorage();
    const store = BootstrapNonceStore.durableFromBoot(storage, masterKey());
    await store.consume(FORTRESS, NODE, NONCE, Date.now() + 60_000);
    const raw = await storage.read(
      BOOTSTRAP_NONCE_STORE_NAMESPACE,
      BOOTSTRAP_NONCE_STORE_KEY,
    );
    expect(raw).not.toBeNull();
    // It is ciphertext, not plaintext: the nonce must not appear in the clear.
    expect(new TextDecoder().decode(raw!)).not.toContain(NONCE);
  });
});

describe("durable claim store — RESTART replay denied (criterion a, headline)", () => {
  it("a consumed claim stays consumed across a new store instance (restart)", async () => {
    const storage = new MemoryStorage();

    // Boot 1: record + consume the claim. First consume returns the claim.
    const store1 = OperatorCloudProvisionClaimStore.durableFromBoot(storage, masterKey());
    await store1.record(claimParams());
    const first = await store1.consume(FORTRESS, NODE, NONCE);
    expect(first).not.toBeNull();

    // Boot 2: a fresh instance loads from the same storage. The claim is already
    // consumed, so a replay is DENIED. On `main` (in-memory only) this ALLOWS.
    const store2 = OperatorCloudProvisionClaimStore.durableFromBoot(storage, masterKey());
    const replay = await store2.consume(FORTRESS, NODE, NONCE);
    expect(replay).toBeNull();
  });

  it("an UNCONSUMED recorded claim survives a restart and is then consumable once", async () => {
    const storage = new MemoryStorage();

    // Boot 1: only record (do not consume).
    const store1 = OperatorCloudProvisionClaimStore.durableFromBoot(storage, masterKey());
    await store1.record(claimParams());

    // Boot 2: the recorded claim is remembered and consumable exactly once.
    const store2 = OperatorCloudProvisionClaimStore.durableFromBoot(storage, masterKey());
    expect(await store2.consume(FORTRESS, NODE, NONCE)).not.toBeNull();
    expect(await store2.consume(FORTRESS, NODE, NONCE)).toBeNull();
  });

  it("the claim record is ciphertext under the frozen namespace + key", async () => {
    const storage = new MemoryStorage();
    const store = OperatorCloudProvisionClaimStore.durableFromBoot(storage, masterKey());
    await store.record(claimParams());
    const raw = await storage.read(
      OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE,
      OPERATOR_CLOUD_CLAIM_STORE_KEY,
    );
    expect(raw).not.toBeNull();
    expect(new TextDecoder().decode(raw!)).not.toContain(NONCE);
  });
});

describe("persist-failure -> consume DENIES (criterion b)", () => {
  it("nonce store: a failing durable persist DENIES (no allow-without-persist)", async () => {
    const storage = new FailingWriteStorage();
    const store = BootstrapNonceStore.durableFromBoot(storage, masterKey());
    // The persist throws; consume must fail closed (false), NOT allow.
    expect(await store.consume(FORTRESS, NODE, NONCE, Date.now() + 60_000)).toBe(false);
    // The in-memory mark was rolled back: nothing is held as spent.
    expect(store.isSpent(FORTRESS, NODE, NONCE)).toBe(false);
  });

  it("claim store: a failing durable persist on consume DENIES and rolls back", async () => {
    // Record into a normal storage (so a claim exists), then swap to a storage
    // whose write fails for the consume's persist.
    const good = new MemoryStorage();
    const seed = OperatorCloudProvisionClaimStore.durableFromBoot(good, masterKey());
    await seed.record(claimParams());

    // Build a failing-write store seeded from the same encrypted bytes.
    const failing = new FailingWriteStorage();
    const raw = await good.read(
      OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE,
      OPERATOR_CLOUD_CLAIM_STORE_KEY,
    );
    // Seed the failing store's backing map via the parent read path: write once
    // through MemoryStorage's own map BEFORE consume tries (and fails) to persist.
    await MemoryStorage.prototype.write.call(
      failing,
      OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE,
      OPERATOR_CLOUD_CLAIM_STORE_KEY,
      raw!,
    );

    const store = OperatorCloudProvisionClaimStore.durableFromBoot(failing, masterKey());
    // The claim loads, consume flips consumed + tries to persist (throws) ->
    // rolls back + returns null (deny). It must NOT be returned as approved.
    expect(await store.consume(FORTRESS, NODE, NONCE)).toBeNull();
  });

  it("claim store: a failing durable persist on record THROWS (not silently recorded)", async () => {
    const storage = new FailingWriteStorage();
    const store = OperatorCloudProvisionClaimStore.durableFromBoot(storage, masterKey());
    await expect(store.record(claimParams())).rejects.toThrow();
  });
});

describe("corrupt durable record -> fail closed (criterion c)", () => {
  it("nonce store: a corrupt record makes consume FAIL CLOSED (throws -> deny), no reset", async () => {
    const store = BootstrapNonceStore.durableFromBoot(new CorruptReadStorage(), masterKey());
    // The durable load cannot decrypt the record. consume must THROW (the
    // approver translates this to a denial) rather than silently treat the set as
    // empty and ALLOW the token.
    await expect(
      store.consume(FORTRESS, NODE, NONCE, Date.now() + 60_000),
    ).rejects.toBeInstanceOf(DurableSpentSetStoreError);
  });

  it("claim store: a corrupt record makes consume FAIL CLOSED (throws -> deny)", async () => {
    const store = OperatorCloudProvisionClaimStore.durableFromBoot(
      new CorruptReadStorage(),
      masterKey(),
    );
    await expect(store.consume(FORTRESS, NODE, NONCE)).rejects.toThrow();
  });

  it("the standalone backend rejects a tampered ciphertext byte (AEAD)", async () => {
    const storage = new MemoryStorage();
    const backend = new DurableSpentSetStore({
      storage,
      masterKey: masterKey(),
      namespace: "_test",
      recordKey: "spent",
      hkdfLabel: "test-spent-set",
    });
    await backend.persist(new Map([["k", Date.now() + 60_000]]));
    // Flip a byte in the stored ciphertext.
    const raw = await storage.read("_test", "spent");
    const parsed = JSON.parse(new TextDecoder().decode(raw!));
    parsed.ct = parsed.ct.slice(0, -2) + (parsed.ct.endsWith("AA") ? "BB" : "AA");
    await storage.write("_test", "spent", new TextEncoder().encode(JSON.stringify(parsed)));
    await expect(backend.load(Date.now())).rejects.toBeInstanceOf(DurableSpentSetStoreError);
  });
});

describe("expired entries pruned on load (criterion d)", () => {
  it("nonce store: an expired spent entry is dropped on the next boot's load", async () => {
    const storage = new MemoryStorage();
    const past = Date.now() - 1000;

    // Boot 1: persist a spent nonce that is ALREADY expired.
    const store1 = BootstrapNonceStore.durableFromBoot(storage, masterKey());
    expect(await store1.consume(FORTRESS, NODE, NONCE, past)).toBe(true);

    // Boot 2: load prunes the expired entry, so the same key is consumable again
    // (the token itself would be expiry-rejected upstream; the pruned record is
    // moot and keeps the set bounded).
    const store2 = BootstrapNonceStore.durableFromBoot(storage, masterKey());
    expect(await store2.consume(FORTRESS, NODE, NONCE, Date.now() + 60_000)).toBe(true);
  });

  it("claim store: an expired claim is dropped on load (backend prune)", async () => {
    const storage = new MemoryStorage();
    const backend = new DurableClaimSetStore({
      storage,
      masterKey: masterKey(),
      namespace: "_test",
      recordKey: "claims",
      hkdfLabel: "test-claim-set",
    });
    await backend.persist(
      new Map([
        [
          "k",
          {
            fortress_id: FORTRESS,
            node_id: NODE,
            node_mode: "operator_cloud",
            node_pubkey_hash: "h",
            bootstrap_nonce: NONCE,
            manifest_digest: "md",
            scoped_secret_ciphertext_digest: "ccd",
            scope_digest: "sd",
            bundle_digest: "bd",
            expires_at: new Date(Date.now() - 1000).toISOString(),
            consumed: false,
          },
        ],
      ]),
    );
    const loaded = await backend.load(Date.now());
    expect(loaded.size).toBe(0);
  });
});

describe("in-memory back-compat (criterion e)", () => {
  it("nonce store with NO backend keeps the original single-use semantics", async () => {
    const store = new BootstrapNonceStore();
    const expiresAtMs = Date.now() + 60_000;
    expect(await store.consume(FORTRESS, NODE, NONCE, expiresAtMs)).toBe(true);
    expect(await store.consume(FORTRESS, NODE, NONCE, expiresAtMs)).toBe(false);
    expect(await store.consume(FORTRESS, NODE, "nonce-2", expiresAtMs)).toBe(true);
  });

  it("claim store with NO backend keeps the original single-use semantics", async () => {
    const store = new OperatorCloudProvisionClaimStore();
    await store.record(claimParams());
    expect(await store.consume(FORTRESS, NODE, NONCE)).not.toBeNull();
    expect(await store.consume(FORTRESS, NODE, NONCE)).toBeNull();
    expect(await store.peek(FORTRESS, NODE, NONCE)).not.toBeNull();
  });
});
