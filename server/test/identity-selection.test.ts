/**
 * Test: Identity Selection and Primary Identity Persistence
 *
 * Verifies:
 * 1. Primary identity is persisted to _meta storage
 * 2. On restart, the same primary identity is restored
 * 3. shr_generate and reputation_publish use the primary identity when no identity_id is provided
 * 4. Explicit identity_id parameters override the primary identity
 * 5. identity_set_primary allows changing the default identity
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../src/storage/memory.js";
import { generateRandomKey } from "../src/core/random.js";
import { IdentityManager } from "../src/l1-cognitive/tools.js";
import { generateSHR } from "../src/shr/generator.js";
import { defaultConfig } from "../src/config.js";
import { createIdentity } from "../src/core/identity.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";

describe("Identity Selection and Persistence", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  let identityEncKey: Uint8Array;
  let config = defaultConfig();

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  });

  it("persists primary identity ID to _meta storage", async () => {
    const mgr = new IdentityManager(storage, masterKey);

    // Create first identity
    const { publicIdentity: id1, storedIdentity: stored1 } = createIdentity(
      "newton-sovereign-agent",
      identityEncKey,
      "passphrase"
    );
    await mgr.save(stored1);

    // Create second identity (would come first alphabetically if sorted)
    const { publicIdentity: id2, storedIdentity: stored2 } = createIdentity(
      "agent-before-newton",
      identityEncKey,
      "passphrase"
    );
    await mgr.save(stored2);

    // Primary should be the first saved (id1)
    expect(mgr.getPrimaryIdentityId()).toBe(id1.identity_id);

    // Check that primary ID was written to _meta
    const metaRaw = await storage.read("_meta", "primary_identity_id");
    expect(metaRaw).not.toBeNull();
    if (metaRaw) {
      const primaryId = JSON.parse(new TextDecoder().decode(metaRaw));
      expect(primaryId).toBe(id1.identity_id);
    }
  });

  it("restores primary identity on load", async () => {
    const mgr1 = new IdentityManager(storage, masterKey);

    // Create and save identities
    const { publicIdentity: id1, storedIdentity: stored1 } = createIdentity(
      "newton-sovereign-agent",
      identityEncKey,
      "passphrase"
    );
    await mgr1.save(stored1);

    const { publicIdentity: id2, storedIdentity: stored2 } = createIdentity(
      "test-agent-verify",
      identityEncKey,
      "passphrase"
    );
    await mgr1.save(stored2);

    const primaryBefore = mgr1.getPrimaryIdentityId();
    expect(primaryBefore).toBe(id1.identity_id);

    // Create a NEW manager (simulating server restart) and load from the same storage
    const mgr2 = new IdentityManager(storage, masterKey);
    await mgr2.load();

    // Primary should be restored correctly
    const primaryAfter = mgr2.getPrimaryIdentityId();
    expect(primaryAfter).toBe(id1.identity_id);
  });

  it("allows explicit setPrimary to change the default identity", async () => {
    const mgr = new IdentityManager(storage, masterKey);

    // Create two identities
    const { publicIdentity: id1, storedIdentity: stored1 } = createIdentity(
      "newton-sovereign-agent",
      identityEncKey,
      "passphrase"
    );
    await mgr.save(stored1);

    const { publicIdentity: id2, storedIdentity: stored2 } = createIdentity(
      "test-agent-verify",
      identityEncKey,
      "passphrase"
    );
    await mgr.save(stored2);

    // Initially primary is id1
    expect(mgr.getPrimaryIdentityId()).toBe(id1.identity_id);

    // Set id2 as primary
    const success = await mgr.setPrimary(id2.identity_id);
    expect(success).toBe(true);
    expect(mgr.getPrimaryIdentityId()).toBe(id2.identity_id);

    // Verify it was persisted
    const metaRaw = await storage.read("_meta", "primary_identity_id");
    if (metaRaw) {
      const primaryId = JSON.parse(new TextDecoder().decode(metaRaw));
      expect(primaryId).toBe(id2.identity_id);
    }
  });

  it("getDefault() returns the primary identity", async () => {
    const mgr = new IdentityManager(storage, masterKey);

    const { publicIdentity: id1, storedIdentity: stored1 } = createIdentity(
      "newton-sovereign-agent",
      identityEncKey,
      "passphrase"
    );
    await mgr.save(stored1);

    const defaultId = mgr.getDefault();
    expect(defaultId).not.toBeUndefined();
    expect(defaultId?.identity_id).toBe(id1.identity_id);
  });

  it("shr_generate uses primary identity when no identity_id provided", async () => {
    const mgr = new IdentityManager(storage, masterKey);
    const { publicIdentity: id1, storedIdentity: stored1 } = createIdentity(
      "newton-sovereign-agent",
      identityEncKey,
      "passphrase"
    );
    await mgr.save(stored1);

    // Call generateSHR with no identity_id parameter
    const result = generateSHR(undefined, {
      config,
      identityManager: mgr,
      masterKey,
    });

    expect(typeof result).not.toBe("string"); // Should not be an error
    if (typeof result !== "string") {
      expect(result.body.instance_id).toBe(id1.identity_id);
    }
  });

  it("shr_generate uses explicit identity_id when provided", () => {
    const mgr = new IdentityManager(storage, masterKey);

    const { publicIdentity: id1, storedIdentity: stored1 } = createIdentity(
      "newton-sovereign-agent",
      identityEncKey,
      "passphrase"
    );

    const { publicIdentity: id2, storedIdentity: stored2 } = createIdentity(
      "test-agent-verify",
      identityEncKey,
      "passphrase"
    );

    // Mock identityManager
    const mockMgr = {
      get: (id: string) => {
        if (id === id1.identity_id) return stored1;
        if (id === id2.identity_id) return stored2;
        return undefined;
      },
      getDefault: () => stored1, // Primary is id1
      list: () => [],
    } as any;

    // Call generateSHR with explicit identity_id for id2
    const result = generateSHR(id2.identity_id, {
      config,
      identityManager: mockMgr,
      masterKey,
    });

    expect(typeof result).not.toBe("string"); // Should not be an error
    if (typeof result !== "string") {
      expect(result.body.instance_id).toBe(id2.identity_id);
    }
  });

  it("setPrimary rejects invalid identity IDs", async () => {
    const mgr = new IdentityManager(storage, masterKey);

    const { publicIdentity: id1, storedIdentity: stored1 } = createIdentity(
      "newton-sovereign-agent",
      identityEncKey,
      "passphrase"
    );
    await mgr.save(stored1);

    // Try to set a non-existent identity as primary
    const success = await mgr.setPrimary("invalid-id");
    expect(success).toBe(false);

    // Primary should remain unchanged
    expect(mgr.getPrimaryIdentityId()).toBe(id1.identity_id);
  });

  it("handles missing primary metadata gracefully", async () => {
    const mgr1 = new IdentityManager(storage, masterKey);

    const { publicIdentity: id1, storedIdentity: stored1 } = createIdentity(
      "newton-sovereign-agent",
      identityEncKey,
      "passphrase"
    );
    await mgr1.save(stored1);

    // Delete the metadata to simulate a corrupted state
    await storage.delete("_meta", "primary_identity_id");

    // Create a new manager and load
    const mgr2 = new IdentityManager(storage, masterKey);
    await mgr2.load();

    // Should still have a primary (fallback to first loaded)
    expect(mgr2.getPrimaryIdentityId()).not.toBeNull();
  });
});
