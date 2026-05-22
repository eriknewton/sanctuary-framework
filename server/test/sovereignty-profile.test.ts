/**
 * Sovereignty Profile Store Tests
 *
 * Verifies:
 * - Default profile creation on first run
 * - Profile persistence and loading from encrypted storage
 * - Partial updates to features
 * - Encryption using HKDF domain separation
 * - Reserved namespace protection
 * - Profile survives re-initialization (restart simulation)
 */

import { describe, it, expect } from "vitest";
import { mkdir, readFile, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  SovereigntyProfileStore,
  createDefaultProfile,
  type SovereigntyProfile,
} from "../src/sovereignty-profile.js";
import { MemoryStorage } from "../src/storage/memory.js";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import { generateRandomKey } from "../src/core/random.js";
import { encrypt } from "../src/core/encryption.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";
import { stringToBytes } from "../src/core/encoding.js";
import { AuditLog } from "../src/l2-operational/audit-log.js";
import {
  bindContextGateEnforcerToProfileStore,
  createContextGateTools,
} from "../src/l2-operational/context-gate-tools.js";
import { createSovereigntyProfileTools } from "../src/sovereignty-profile-tools.js";

function createStore(): { store: SovereigntyProfileStore; storage: MemoryStorage; masterKey: Uint8Array } {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const store = new SovereigntyProfileStore(storage, masterKey);
  return { store, storage, masterKey };
}

async function expectProfilePreserved(
  storage: MemoryStorage,
  originalRaw: Uint8Array
): Promise<void> {
  expect(await storage.read("_sovereignty_profile", "active")).toEqual(originalRaw);
  const entries = await storage.list("_sovereignty_profile");
  const quarantine = entries.find((entry) =>
    /^active\.corrupted\.\d{4}-\d{2}-\d{2}T/.test(entry.key)
  );
  expect(quarantine).toBeUndefined();
}

describe("SovereigntyProfileStore", () => {
  // ── Default Profile ───────────────────────────────────────────────

  describe("createDefaultProfile", () => {
    it("creates profile with version 1", () => {
      const profile = createDefaultProfile();
      expect(profile.version).toBe(1);
    });

    it("enables audit_logging by default", () => {
      const profile = createDefaultProfile();
      expect(profile.features.audit_logging.enabled).toBe(true);
    });

    it("enables injection_detection by default", () => {
      const profile = createDefaultProfile();
      expect(profile.features.injection_detection.enabled).toBe(true);
    });

    it("disables context_gating by default", () => {
      const profile = createDefaultProfile();
      expect(profile.features.context_gating.enabled).toBe(false);
    });

    it("disables approval_gate by default", () => {
      const profile = createDefaultProfile();
      expect(profile.features.approval_gate.enabled).toBe(true); // SEC-057: always enabled
    });

    it("disables zk_proofs by default", () => {
      const profile = createDefaultProfile();
      expect(profile.features.zk_proofs.enabled).toBe(false);
    });

    it("includes ISO 8601 updated_at timestamp", () => {
      const profile = createDefaultProfile();
      expect(profile.updated_at).toBeTruthy();
      expect(new Date(profile.updated_at).toISOString()).toBe(profile.updated_at);
    });
  });

  // ── Load ──────────────────────────────────────────────────────────

  describe("load", () => {
    it("creates default profile on first run", async () => {
      const { store } = createStore();
      const profile = await store.load();
      expect(profile.version).toBe(1);
      expect(profile.features.audit_logging.enabled).toBe(true);
      expect(profile.features.injection_detection.enabled).toBe(true);
      expect(profile.features.context_gating.enabled).toBe(false);
    });

    it("returns cached profile on subsequent loads", async () => {
      const { store } = createStore();
      const first = await store.load();
      const second = await store.load();
      expect(first).toBe(second); // Same reference
    });

    it("persists profile to encrypted storage", async () => {
      const { store, storage, masterKey } = createStore();
      await store.load();

      // Verify data exists in the reserved namespace
      const raw = await storage.read("_sovereignty_profile", "active");
      expect(raw).not.toBeNull();
      expect(raw!.length).toBeGreaterThan(0);

      // Verify it's encrypted (not readable as plain JSON profile)
      const text = new TextDecoder().decode(raw!);
      const parsed = JSON.parse(text);
      expect(parsed).toHaveProperty("ct");
      expect(parsed).toHaveProperty("iv");
    });

    it("throws without modifying truncated encrypted profile bytes", async () => {
      const { store, storage } = createStore();
      const originalRaw = stringToBytes('{"v":1,"alg":"aes-256-gcm","iv"');
      await storage.write("_sovereignty_profile", "active", originalRaw);

      await expect(store.load()).rejects.toMatchObject({
        name: "ProfileLoadError",
        classification: "corrupted",
        path: "_sovereignty_profile/active",
      });
      await expectProfilePreserved(storage, originalRaw);
    });

    it("leaves truncated filesystem profile bytes in place", async () => {
      const tempDir = join(
        tmpdir(),
        `sanctuary-profile-fs-${Date.now()}-${Math.random().toString(36).slice(2)}`
      );
      await mkdir(tempDir, { recursive: true });
      try {
        const storage = new FilesystemStorage(tempDir);
        const originalRaw = stringToBytes('{"v":1,"alg":"aes-256-gcm","ct"');
        await storage.write("_sovereignty_profile", "active", originalRaw);
        const store = new SovereigntyProfileStore(storage, generateRandomKey());

        await expect(store.load()).rejects.toMatchObject({
          name: "ProfileLoadError",
          classification: "corrupted",
        });

        expect(await storage.read("_sovereignty_profile", "active")).toEqual(originalRaw);
        const files = await readdir(join(tempDir, "_sovereignty_profile"));
        const quarantine = files.find((file) =>
          file.startsWith("active.corrupted.") && file.endsWith(".enc")
        );
        expect(quarantine).toBeUndefined();
        expect(await readFile(join(tempDir, "_sovereignty_profile", "active.enc"))).toEqual(
          Buffer.from(originalRaw)
        );
      } finally {
        await rm(tempDir, { recursive: true, force: true });
      }
    });

    it("throws without modifying schema-invalid decrypted profile data", async () => {
      const { store, storage, masterKey } = createStore();
      const invalidProfile = {
        ...createDefaultProfile(),
        features: {
          ...createDefaultProfile().features,
          approval_gate: { enabled: false },
        },
      };
      const encrypted = encrypt(
        stringToBytes(JSON.stringify(invalidProfile)),
        derivePurposeKey(masterKey, "sovereignty-profile")
      );
      const originalRaw = stringToBytes(JSON.stringify(encrypted));
      await storage.write("_sovereignty_profile", "active", originalRaw);

      await expect(store.load()).rejects.toMatchObject({
        name: "ProfileLoadError",
        classification: "schema-mismatch",
        path: "_sovereignty_profile/active",
      });
      await expectProfilePreserved(storage, originalRaw);
    });
  });

  // ── Profile Survives Restart ──────────────────────────────────────

  describe("persistence across restarts", () => {
    it("loads previously saved profile from storage", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();

      // First "session": create and modify profile
      const store1 = new SovereigntyProfileStore(storage, masterKey);
      await store1.load();
      await store1.update({ zk_proofs: { enabled: true } });

      // Second "session": new store, same storage and key
      const store2 = new SovereigntyProfileStore(storage, masterKey);
      const loaded = await store2.load();

      expect(loaded.features.zk_proofs.enabled).toBe(true);
      expect(loaded.features.audit_logging.enabled).toBe(true); // Still default
    });

    it("rejects and preserves profile encrypted with a different key", async () => {
      const storage = new MemoryStorage();
      const masterKey1 = generateRandomKey();
      const masterKey2 = generateRandomKey();

      // Create profile with key1
      const store1 = new SovereigntyProfileStore(storage, masterKey1);
      await store1.load();
      const originalRaw = await storage.read("_sovereignty_profile", "active");
      expect(originalRaw).not.toBeNull();

      // Try to load with key2. This must fail closed, not recreate defaults.
      const store2 = new SovereigntyProfileStore(storage, masterKey2);
      await expect(store2.load()).rejects.toMatchObject({
        name: "ProfileLoadError",
        classification: "wrong-key",
        path: "_sovereignty_profile/active",
      });
      await expectProfilePreserved(storage, originalRaw!);
    });

    it("reports that wrong-key failures do not modify the profile file", async () => {
      const storage = new MemoryStorage();
      const masterKey1 = generateRandomKey();
      const masterKey2 = generateRandomKey();
      const store1 = new SovereigntyProfileStore(storage, masterKey1);
      await store1.load();

      const store2 = new SovereigntyProfileStore(storage, masterKey2);
      await expect(store2.load()).rejects.toThrow("The file has NOT been modified");
    });

    it("scopes profile operations to the configured filesystem storage path", async () => {
      const rootDir = join(
        tmpdir(),
        `sanctuary-profile-scope-${Date.now()}-${Math.random().toString(36).slice(2)}`
      );
      const hostStateDir = join(rootDir, "host", "state");
      const fortressStateDir = join(rootDir, "fortress", "state");
      await mkdir(hostStateDir, { recursive: true });
      await mkdir(fortressStateDir, { recursive: true });
      try {
        const hostStorage = new FilesystemStorage(hostStateDir);
        const fortressStorage = new FilesystemStorage(fortressStateDir);
        const hostKey = generateRandomKey();
        const fortressKey = generateRandomKey();

        await new SovereigntyProfileStore(hostStorage, hostKey).load();
        await new SovereigntyProfileStore(fortressStorage, fortressKey).load();
        const hostRaw = await hostStorage.read("_sovereignty_profile", "active");
        const fortressRaw = await fortressStorage.read("_sovereignty_profile", "active");
        expect(hostRaw).not.toBeNull();
        expect(fortressRaw).not.toBeNull();

        const wrongFortressStore = new SovereigntyProfileStore(
          fortressStorage,
          generateRandomKey()
        );
        await expect(wrongFortressStore.load()).rejects.toMatchObject({
          name: "ProfileLoadError",
          classification: "wrong-key",
        });

        expect(await hostStorage.read("_sovereignty_profile", "active")).toEqual(hostRaw);
        expect(await fortressStorage.read("_sovereignty_profile", "active")).toEqual(
          fortressRaw
        );
        expect(await hostStorage.list("_sovereignty_profile")).toHaveLength(1);
        expect(await fortressStorage.list("_sovereignty_profile")).toHaveLength(1);
      } finally {
        await rm(rootDir, { recursive: true, force: true });
      }
    });
  });

  // ── Get ───────────────────────────────────────────────────────────

  describe("get", () => {
    it("throws if load() was not called", () => {
      const { store } = createStore();
      expect(() => store.get()).toThrow("call load() before get()");
    });

    it("returns current profile after load", async () => {
      const { store } = createStore();
      await store.load();
      const profile = store.get();
      expect(profile.version).toBe(1);
    });
  });

  // ── Update ────────────────────────────────────────────────────────

  describe("update", () => {
    it("enables a disabled feature", async () => {
      const { store } = createStore();
      await store.load();

      const updated = await store.update({ zk_proofs: { enabled: true } });
      expect(updated.features.zk_proofs.enabled).toBe(true);
    });

    it("disables an enabled feature", async () => {
      const { store } = createStore();
      await store.load();

      const updated = await store.update({ audit_logging: { enabled: false } });
      expect(updated.features.audit_logging.enabled).toBe(false);
    });

    it("preserves unmodified features", async () => {
      const { store } = createStore();
      await store.load();

      await store.update({ context_gating: { enabled: true } });
      const profile = store.get();

      expect(profile.features.audit_logging.enabled).toBe(true);
      expect(profile.features.injection_detection.enabled).toBe(true);
      expect(profile.features.context_gating.enabled).toBe(true);
      expect(profile.features.approval_gate.enabled).toBe(true); // SEC-057: always enabled
      expect(profile.features.zk_proofs.enabled).toBe(false);
    });

    it("updates injection_detection sensitivity", async () => {
      const { store } = createStore();
      await store.load();

      const updated = await store.update({
        injection_detection: { sensitivity: "high" },
      });
      expect(updated.features.injection_detection.sensitivity).toBe("high");
      expect(updated.features.injection_detection.enabled).toBe(true); // Unchanged
    });

    it("updates context_gating policy_id", async () => {
      const { store } = createStore();
      await store.load();

      const updated = await store.update({
        context_gating: { enabled: true, policy_id: "cg-test-123" },
      });
      expect(updated.features.context_gating.enabled).toBe(true);
      expect(updated.features.context_gating.policy_id).toBe("cg-test-123");
    });

    it("syncs context_gating toggles to the live enforcer and audits the toggle", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new SovereigntyProfileStore(storage, masterKey);
      await store.load();
      const auditLog = new AuditLog(storage, masterKey);
      const { enforcer } = createContextGateTools(storage, masterKey, auditLog);
      bindContextGateEnforcerToProfileStore(store, auditLog, enforcer);
      const { tools } = createSovereigntyProfileTools(store, auditLog);
      const tool = tools.find((candidate) => candidate.name === "sovereignty_profile_update")!;

      await tool.handler({ context_gating: { enabled: true, policy_id: "cg-live" } });

      expect(store.get().features.context_gating.enabled).toBe(true);
      expect(enforcer.getStatus()).toMatchObject({
        enabled: true,
        default_policy_id: "cg-live",
      });

      const audit = await auditLog.query({ operation_type: "context_gate.toggled" });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]!.details).toMatchObject({
        event_type: "context_gate.toggled",
        old_state: false,
        new_state: true,
        new_policy_id: "cg-live",
      });
    });

    it("updates updated_at timestamp", async () => {
      const { store } = createStore();
      const initial = await store.load();
      const initialTime = initial.updated_at;

      // Small delay to ensure different timestamp
      await new Promise((r) => setTimeout(r, 10));

      const updated = await store.update({ zk_proofs: { enabled: true } });
      expect(updated.updated_at).not.toBe(initialTime);
    });

    it("applies multiple feature changes at once", async () => {
      const { store } = createStore();
      await store.load();

      const updated = await store.update({
        audit_logging: { enabled: false },
        context_gating: { enabled: true },
        zk_proofs: { enabled: true },
      });

      expect(updated.features.audit_logging.enabled).toBe(false);
      expect(updated.features.context_gating.enabled).toBe(true);
      expect(updated.features.zk_proofs.enabled).toBe(true);
      expect(updated.features.injection_detection.enabled).toBe(true); // Unchanged
    });

    it("persists changes to storage", async () => {
      const { store, storage, masterKey } = createStore();
      await store.load();
      await store.update({ approval_gate: { enabled: true } });

      // Load from same storage to verify persistence
      const store2 = new SovereigntyProfileStore(storage, masterKey);
      const loaded = await store2.load();
      expect(loaded.features.approval_gate.enabled).toBe(true);
    });

    it("auto-loads if load() was not called", async () => {
      const { store } = createStore();
      // Skip load(), go directly to update
      const updated = await store.update({ zk_proofs: { enabled: true } });
      expect(updated.features.zk_proofs.enabled).toBe(true);
      expect(updated.features.audit_logging.enabled).toBe(true); // Default
    });
  });

  // ── Input Validation (SEC-042) ────────────────────────────────────

  describe("input validation", () => {
    it("rejects non-boolean enabled value", async () => {
      const { store } = createStore();
      await store.load();
      await expect(
        store.update({ audit_logging: { enabled: "yes" as unknown as boolean } })
      ).rejects.toThrow("must be a boolean");
    });

    it("rejects invalid sensitivity value", async () => {
      const { store } = createStore();
      await store.load();
      await expect(
        store.update({
          injection_detection: { sensitivity: "INVALID" as "low" | "medium" | "high" },
        })
      ).rejects.toThrow("must be low, medium, or high");
    });

    it("rejects policy_id exceeding 256 characters", async () => {
      const { store } = createStore();
      await store.load();
      await expect(
        store.update({
          context_gating: { policy_id: "x".repeat(257) },
        })
      ).rejects.toThrow("256 characters or fewer");
    });

    it("rejects non-string policy_id", async () => {
      const { store } = createStore();
      await store.load();
      await expect(
        store.update({
          context_gating: { policy_id: 12345 as unknown as string },
        })
      ).rejects.toThrow("must be a string");
    });

    it("accepts valid sensitivity values", async () => {
      const { store } = createStore();
      await store.load();
      for (const s of ["low", "medium", "high"] as const) {
        const updated = await store.update({
          injection_detection: { sensitivity: s },
        });
        expect(updated.features.injection_detection.sensitivity).toBe(s);
      }
    });

    it("accepts policy_id at 256 character limit", async () => {
      const { store } = createStore();
      await store.load();
      const id = "x".repeat(256);
      const updated = await store.update({
        context_gating: { policy_id: id },
      });
      expect(updated.features.context_gating.policy_id).toBe(id);
    });
  });
});
