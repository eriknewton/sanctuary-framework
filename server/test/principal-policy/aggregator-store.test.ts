/**
 * WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-3
 *
 * Regression suite for AggregatorPayloadStore: at-rest encrypted
 * persistence of full request payloads keyed by aggregator_id.
 *
 * Coverage map (spawn prompt acceptance criteria):
 *   - savePayload + loadPayload round-trip                         (1)
 *   - At-rest plaintext sentinel never appears in stored bytes     (2)
 *   - Tampering with aggregator_id binding breaks decrypt          (3)
 *   - pruneExpired drops bundles past retention_until              (4)
 *   - Multi-fortress isolation enforced cryptographically          (5)
 */

import { describe, it, expect } from "vitest";

import {
  AggregatorPayloadStore,
  AGGREGATOR_PAYLOAD_NAMESPACE,
  AGGREGATOR_PAYLOAD_KEY_PREFIX,
} from "../../src/principal-policy/aggregator-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";

const FORTRESS = "fortress_test";

describe("WP-V1.3-10 Upsilon-3 AggregatorPayloadStore", () => {
  it("round-trips a saved payload through loadPayload", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new AggregatorPayloadStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const payload = { operation: "state_export", path: "/etc/secrets" };
    await store.savePayload("agg-1", payload);
    const loaded = await store.loadPayload("agg-1");
    expect(loaded).toEqual(payload);
  });

  it("never writes the plaintext payload to storage", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new AggregatorPayloadStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const sentinel = "operator-secret-canary-marker-zzz";
    await store.savePayload("agg-2", { secret_value: sentinel });
    const stored = await storage.read(
      AGGREGATOR_PAYLOAD_NAMESPACE,
      `${AGGREGATOR_PAYLOAD_KEY_PREFIX}agg-2`,
    );
    expect(stored).not.toBeNull();
    const asText = bytesToString(stored!);
    expect(asText.includes(sentinel)).toBe(false);
  });

  it("returns null when the aggregator_id binding is tampered (wrong-id lookup fails)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new AggregatorPayloadStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    await store.savePayload("agg-real", { secret: "yes" });
    // Re-key the on-disk record under a different aggregator_id to
    // simulate an on-disk shuffle attack. The AAD is bound to
    // "agg-real" so a load under "agg-fake" must fail decryption.
    const ciphertext = await storage.read(
      AGGREGATOR_PAYLOAD_NAMESPACE,
      `${AGGREGATOR_PAYLOAD_KEY_PREFIX}agg-real`,
    );
    expect(ciphertext).not.toBeNull();
    await storage.write(
      AGGREGATOR_PAYLOAD_NAMESPACE,
      `${AGGREGATOR_PAYLOAD_KEY_PREFIX}agg-fake`,
      ciphertext!,
    );
    const result = await store.loadPayload("agg-fake");
    expect(result).toBeNull();
  });

  it("pruneExpired drops bundles whose retention_until is in the past", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new AggregatorPayloadStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
      retentionDays: 1,
    });
    await store.savePayload("agg-fresh", { kept: true });
    // Run the prune well past the retention window.
    const future = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
    const result = await store.pruneExpired(future);
    expect(result.pruned).toBe(1);
    const after = await store.loadPayload("agg-fresh");
    expect(after).toBeNull();
  });

  it("isolates payloads cryptographically across fortresses (different masterKey cannot decrypt)", async () => {
    const storage = new MemoryStorage();
    const masterKeyA = generateRandomKey();
    const masterKeyB = generateRandomKey();
    const storeA = new AggregatorPayloadStore({
      storage,
      masterKey: masterKeyA,
      fortressId: "fortress_a",
    });
    const storeB = new AggregatorPayloadStore({
      storage,
      masterKey: masterKeyB,
      fortressId: "fortress_b",
    });
    await storeA.savePayload("agg-shared-id", { fortress: "a" });
    const fromB = await storeB.loadPayload("agg-shared-id");
    expect(fromB).toBeNull();
    const fromA = await storeA.loadPayload("agg-shared-id");
    expect(fromA).toEqual({ fortress: "a" });
  });
});
