/**
 * Security Test: SEC-005 — Import Verifies Ed25519 Signatures
 *
 * Verifies that the import path rejects entries with:
 * - Forged or invalid signatures
 * - Unknown identity references (kid)
 *
 * This is the first test in the signature verification cluster
 * (SEC-005, SEC-010, SEC-014). The verification pattern established
 * here — mandatory verification with structured rejection counts —
 * is the reference architecture for the subsequent two findings.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
} from "../../src/core/encoding.js";
import type { StateEntry } from "../../src/l1-cognitive/state-store.js";

describe("SEC-005: Import Verifies Ed25519 Signatures", () => {
  let storage: MemoryStorage;
  let stateStore: StateStore;
  let masterKey: Uint8Array;
  let identityEncKey: Uint8Array;
  let identity: ReturnType<typeof createIdentity>;

  // Public key resolver that knows about the test identity
  let resolver: (kid: string) => Uint8Array | null;

  beforeEach(async () => {
    masterKey = generateRandomKey();
    storage = new MemoryStorage();
    stateStore = new StateStore(storage, masterKey);
    identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    identity = createIdentity("test-identity", identityEncKey, "recovery-key");

    resolver = (kid: string): Uint8Array | null => {
      if (kid === identity.storedIdentity.identity_id) {
        return fromBase64url(identity.storedIdentity.public_key);
      }
      return null;
    };
  });

  /**
   * Helper: write entries to storage, export, and return the bundle string.
   */
  async function createValidBundle(
    entries: Array<{ ns: string; key: string; value: string }>
  ): Promise<string> {
    for (const { ns, key, value } of entries) {
      await stateStore.write(
        ns,
        key,
        value,
        identity.storedIdentity.identity_id,
        identity.storedIdentity.encrypted_private_key,
        identityEncKey
      );
    }

    const exportResult = await stateStore.export();
    return exportResult.bundle;
  }

  /**
   * Helper: decode a bundle, modify it, and re-encode.
   */
  function decodeBundle(bundleBase64: string): {
    sanctuary_export_version: number;
    exported_at: string;
    namespaces: string[];
    data: Record<string, Array<{ key: string; entry: StateEntry }>>;
  } {
    const bundleBytes = fromBase64url(bundleBase64);
    return JSON.parse(bytesToString(bundleBytes));
  }

  function encodeBundle(bundle: ReturnType<typeof decodeBundle>): string {
    return toBase64url(stringToBytes(JSON.stringify(bundle)));
  }

  it("should accept valid import with correct signatures", async () => {
    const bundle = await createValidBundle([
      { ns: "notes", key: "note1", value: "hello world" },
      { ns: "notes", key: "note2", value: "second note" },
    ]);

    // Import into a fresh store (same master key, so same identity resolution)
    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, masterKey);

    const result = await freshStore.import(bundle, "skip", resolver);

    expect(result.imported_keys).toBe(2);
    expect(result.skipped_invalid_sig).toBe(0);
    expect(result.skipped_unknown_kid).toBe(0);
  });

  it("should reject entries with forged signatures", async () => {
    const bundle = await createValidBundle([
      { ns: "notes", key: "good-entry", value: "legitimate" },
      { ns: "notes", key: "tampered-entry", value: "will be tampered" },
    ]);

    // Tamper with one entry's signature
    const decoded = decodeBundle(bundle);
    const notesEntries = decoded.data["notes"]!;
    const tamperedEntry = notesEntries.find(
      (e) => e.key === "tampered-entry"
    )!;

    // Corrupt the signature by flipping bits
    const sigBytes = fromBase64url(tamperedEntry.entry.sig);
    sigBytes[0] = sigBytes[0]! ^ 0xff;
    sigBytes[1] = sigBytes[1]! ^ 0xff;
    tamperedEntry.entry.sig = toBase64url(sigBytes);

    const tamperedBundle = encodeBundle(decoded);

    // Import into a fresh store
    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, masterKey);

    const result = await freshStore.import(tamperedBundle, "skip", resolver);

    expect(result.imported_keys).toBe(1); // Only the good entry
    expect(result.skipped_invalid_sig).toBe(1); // The tampered entry
    expect(result.skipped_unknown_kid).toBe(0);
  });

  it("should reject entries with unknown kid", async () => {
    const bundle = await createValidBundle([
      { ns: "notes", key: "entry1", value: "test value" },
    ]);

    // Change the kid to a nonexistent identity
    const decoded = decodeBundle(bundle);
    decoded.data["notes"]![0]!.entry.kid = "nonexistent-identity-id";

    const modifiedBundle = encodeBundle(decoded);

    // Import into a fresh store
    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, masterKey);

    const result = await freshStore.import(modifiedBundle, "skip", resolver);

    expect(result.imported_keys).toBe(0);
    expect(result.skipped_unknown_kid).toBe(1);
    expect(result.skipped_invalid_sig).toBe(0);
  });

  it("should reject all entries when all have bad signatures", async () => {
    const bundle = await createValidBundle([
      { ns: "data", key: "a", value: "value-a" },
      { ns: "data", key: "b", value: "value-b" },
      { ns: "data", key: "c", value: "value-c" },
    ]);

    // Tamper with every entry's signature
    const decoded = decodeBundle(bundle);
    for (const entries of Object.values(decoded.data)) {
      for (const item of entries as Array<{ key: string; entry: StateEntry }>) {
        const sigBytes = fromBase64url(item.entry.sig);
        sigBytes[0] = sigBytes[0]! ^ 0xff;
        item.entry.sig = toBase64url(sigBytes);
      }
    }

    const tamperedBundle = encodeBundle(decoded);

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, masterKey);

    const result = await freshStore.import(tamperedBundle, "skip", resolver);

    expect(result.imported_keys).toBe(0);
    expect(result.skipped_invalid_sig).toBe(3);
    expect(result.skipped_keys).toBe(3);
  });

  it("should still skip reserved namespaces during import", async () => {
    // Manually construct a bundle with a reserved namespace
    const validBundle = await createValidBundle([
      { ns: "notes", key: "legit", value: "legit value" },
    ]);

    const decoded = decodeBundle(validBundle);

    // Copy the legit entry into a reserved namespace
    decoded.data["_identities"] = [
      {
        key: "injected",
        entry: decoded.data["notes"]![0]!.entry,
      },
    ];
    decoded.namespaces.push("_identities");

    const modifiedBundle = encodeBundle(decoded);

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, masterKey);

    const result = await freshStore.import(modifiedBundle, "skip", resolver);

    // The legit entry should import; the reserved namespace entry should be skipped
    expect(result.imported_keys).toBe(1);
    expect(result.skipped_keys).toBeGreaterThanOrEqual(1); // At least the reserved ns entry
    // Verify nothing was written to the reserved namespace
    const reservedEntries = await freshStorage.list("_identities");
    expect(reservedEntries).toHaveLength(0);
  });

  it("should skip non-curated underscore-prefixed namespaces during import (F6)", async () => {
    // `_escrows` (plural) is NOT in RESERVED_NAMESPACE_PREFIXES (which lists the
    // singular `_escrow`), so the curated check alone missed it. Export never
    // emits a `_`-prefixed namespace, so any in a bundle is crafted and must be
    // rejected regardless of the curated list. Pre-F6 this entry was imported.
    const validBundle = await createValidBundle([
      { ns: "notes", key: "legit", value: "legit value" },
    ]);

    const decoded = decodeBundle(validBundle);
    decoded.data["_escrows"] = [
      {
        key: "injected",
        entry: decoded.data["notes"]![0]!.entry,
      },
    ];
    decoded.namespaces.push("_escrows");

    const modifiedBundle = encodeBundle(decoded);

    const freshStorage = new MemoryStorage();
    const freshStore = new StateStore(freshStorage, masterKey);

    const result = await freshStore.import(modifiedBundle, "skip", resolver);

    expect(result.imported_keys).toBe(1);
    expect(result.skipped_keys).toBeGreaterThanOrEqual(1);
    const injected = await freshStorage.list("_escrows");
    expect(injected).toHaveLength(0);
  });
});
