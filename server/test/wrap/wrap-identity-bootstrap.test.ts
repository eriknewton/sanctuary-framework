/**
 * v1.3.0 WWWWW: wrap-time identity bootstrap regression tests.
 *
 * Finding NNN (v1.2.1) added identity creation at wrap time so CLI
 * surfaces (exit export, identity show) work immediately. Finding
 * WWWWW confirmed this regressed when --no-dashboard wraps skipped the
 * identity bootstrap because the code lived after the dashboard startup.
 *
 * These tests pin:
 *   - Fresh fortress + key derivation + identity bootstrap creates a
 *     "default" identity reachable by IdentityManager.load().
 *   - The identity has label "default" and key protection "passphrase".
 *   - Idempotency: running bootstrap twice does not overwrite or duplicate.
 *   - After bootstrap, a second IdentityManager on the same storage
 *     can load the identity (simulates `sanctuary exit export` or
 *     `sanctuary identity show` after wrap without dashboard launch).
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { IdentityManager } from "../../src/l1-cognitive/tools.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";

/**
 * Mirrors the identity bootstrap block in wrap/cli.ts (both the
 * dashboard path and the --no-dashboard path). Exercises the same
 * sequence: IdentityManager.load() → check loaded === 0 → createIdentity
 * → save → audit append.
 */
async function bootstrapIdentity(
  storage: MemoryStorage,
  masterKey: Uint8Array,
): Promise<{ created: boolean; identityId?: string }> {
  const auditLog = new AuditLog(storage, masterKey);
  const identityMgr = new IdentityManager(storage, masterKey);
  const loadResult = await identityMgr.load();
  if (loadResult.loaded === 0) {
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity, publicIdentity } = createIdentity(
      "default",
      identityEncKey,
      "passphrase",
    );
    await identityMgr.save(storedIdentity);
    await auditLog.append("l1", "identity_create", publicIdentity.identity_id, {
      label: "default",
      source: "wrap-auto",
    });
    await auditLog.flush();
    return { created: true, identityId: publicIdentity.identity_id };
  }
  return { created: false };
}

describe("wrap-time identity bootstrap (WWWWW)", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
  });

  it("creates a default identity on fresh fortress", async () => {
    const result = await bootstrapIdentity(storage, masterKey);
    expect(result.created).toBe(true);
    expect(result.identityId).toBeDefined();
    expect(result.identityId!.length).toBeGreaterThan(0);
  });

  it("identity is loadable by a fresh IdentityManager (simulates post-wrap CLI)", async () => {
    // Bootstrap (simulates wrap)
    await bootstrapIdentity(storage, masterKey);

    // Fresh IdentityManager on same storage (simulates `sanctuary exit export`
    // or `sanctuary identity show` invoked after wrap without dashboard)
    const mgr = new IdentityManager(storage, masterKey);
    const loadResult = await mgr.load();
    expect(loadResult.loaded).toBe(1);
    expect(mgr.getPrimaryIdentityId()).toBeDefined();
  });

  it("does not overwrite existing identity on re-wrap", async () => {
    const first = await bootstrapIdentity(storage, masterKey);
    const second = await bootstrapIdentity(storage, masterKey);

    expect(first.created).toBe(true);
    expect(second.created).toBe(false);

    // Still exactly one identity
    const mgr = new IdentityManager(storage, masterKey);
    const loadResult = await mgr.load();
    expect(loadResult.loaded).toBe(1);
    expect(mgr.getPrimaryIdentityId()).toBe(first.identityId);
  });

  it("identity has correct label and protection mode", async () => {
    const result = await bootstrapIdentity(storage, masterKey);

    // Load and decrypt the identity to verify metadata
    const mgr = new IdentityManager(storage, masterKey);
    await mgr.load();
    const identities = mgr.list();
    expect(identities).toHaveLength(1);
    expect(identities[0]!.label).toBe("default");
    expect(identities[0]!.key_protection).toBe("passphrase");
  });

  it("audit log records identity_create event", async () => {
    const result = await bootstrapIdentity(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);
    const entries = await auditLog.query({ layer: "l1", limit: 10 });
    const createEntries = entries.entries.filter(
      (e) => e.operation === "identity_create",
    );
    expect(createEntries).toHaveLength(1);
    expect(createEntries[0]!.identity_id).toBe(result.identityId);
  });
});
