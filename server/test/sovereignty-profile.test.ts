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
import {
  SovereigntyProfileStore,
  createDefaultProfile,
  type SovereigntyProfile,
} from "../src/sovereignty-profile.js";
import { MemoryStorage } from "../src/storage/memory.js";
import { generateRandomKey } from "../src/core/random.js";

function createStore(): { store: SovereigntyProfileStore; storage: MemoryStorage; masterKey: Uint8Array } {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const store = new SovereigntyProfileStore(storage, masterKey);
  return { store, storage, masterKey };
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
      expect(profile.features.approval_gate.enabled).toBe(false);
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

    it("rejects profile encrypted with a different key", async () => {
      const storage = new MemoryStorage();
      const masterKey1 = generateRandomKey();
      const masterKey2 = generateRandomKey();

      // Create profile with key1
      const store1 = new SovereigntyProfileStore(storage, masterKey1);
      await store1.load();

      // Try to load with key2 — should fall back to defaults
      const store2 = new SovereigntyProfileStore(storage, masterKey2);
      const loaded = await store2.load();

      // Should get default profile (not the modified one)
      expect(loaded.version).toBe(1);
      expect(loaded.features.audit_logging.enabled).toBe(true);
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
      expect(profile.features.approval_gate.enabled).toBe(false);
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
