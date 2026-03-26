/**
 * Behavioral Baseline Tracker Tests
 *
 * Verifies:
 * - Tool call recording and rate tracking
 * - Namespace access tracking (new vs known)
 * - Counterparty tracking (new vs known)
 * - Signing frequency tracking
 * - Bulk read detection
 * - Internal namespace exclusion (prefixed with "_")
 * - Baseline persistence (save/load encrypted)
 * - First session detection
 */

import { describe, it, expect, beforeEach } from "vitest";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

describe("Behavioral Baseline Tracker", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  let tracker: BaselineTracker;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    tracker = new BaselineTracker(storage, masterKey);
  });

  describe("first session detection", () => {
    it("reports first session when no prior baseline exists", async () => {
      await tracker.load();
      expect(tracker.isFirstSession).toBe(true);
    });

    it("reports non-first session after save/load cycle", async () => {
      // Save a baseline
      await tracker.save();

      // Load into a new tracker
      const tracker2 = new BaselineTracker(storage, masterKey);
      await tracker2.load();
      expect(tracker2.isFirstSession).toBe(false);
    });
  });

  describe("tool call tracking", () => {
    it("records tool calls and tracks counts", () => {
      tracker.recordToolCall("state_read");
      tracker.recordToolCall("state_read");
      tracker.recordToolCall("state_write");

      const profile = tracker.getProfile();
      expect(profile.tool_call_counts["state_read"]).toBe(2);
      expect(profile.tool_call_counts["state_write"]).toBe(1);
    });

    it("tracks call rates within the sliding window", () => {
      tracker.recordToolCall("state_read");
      tracker.recordToolCall("state_read");
      tracker.recordToolCall("state_read");

      expect(tracker.getCallRate("state_read")).toBe(3);
      expect(tracker.getCallRate("unknown_tool")).toBe(0);
    });

    it("computes average call rate across tools", () => {
      // 3 calls for tool A, 1 call for tool B → average = (3 + 1) / 2 = 2
      tracker.recordToolCall("tool_a");
      tracker.recordToolCall("tool_a");
      tracker.recordToolCall("tool_a");
      tracker.recordToolCall("tool_b");

      expect(tracker.getAverageCallRate()).toBe(2);
    });
  });

  describe("namespace tracking", () => {
    it("returns true for new namespaces", () => {
      expect(tracker.recordNamespaceAccess("my-data")).toBe(true);
      expect(tracker.recordNamespaceAccess("other-data")).toBe(true);
    });

    it("returns false for known namespaces", () => {
      tracker.recordNamespaceAccess("my-data");
      expect(tracker.recordNamespaceAccess("my-data")).toBe(false);
    });

    it("excludes internal namespaces (prefixed with _)", () => {
      expect(tracker.recordNamespaceAccess("_principal")).toBe(false);
      expect(tracker.recordNamespaceAccess("_audit")).toBe(false);
      expect(tracker.recordNamespaceAccess("_meta")).toBe(false);
    });

    it("persists known namespaces across save/load", async () => {
      tracker.recordNamespaceAccess("persistent-ns");
      await tracker.save();

      const tracker2 = new BaselineTracker(storage, masterKey);
      await tracker2.load();

      // Should not be flagged as new
      expect(tracker2.recordNamespaceAccess("persistent-ns")).toBe(false);
      expect(tracker2.getProfile().known_namespaces).toContain("persistent-ns");
    });
  });

  describe("counterparty tracking", () => {
    it("returns true for new counterparties", () => {
      expect(tracker.recordCounterparty("did:sanctuary:abc123")).toBe(true);
    });

    it("returns false for known counterparties", () => {
      tracker.recordCounterparty("did:sanctuary:abc123");
      expect(tracker.recordCounterparty("did:sanctuary:abc123")).toBe(false);
    });

    it("persists known counterparties across save/load", async () => {
      tracker.recordCounterparty("did:sanctuary:known");
      await tracker.save();

      const tracker2 = new BaselineTracker(storage, masterKey);
      await tracker2.load();

      expect(tracker2.recordCounterparty("did:sanctuary:known")).toBe(false);
    });
  });

  describe("signing frequency", () => {
    it("counts signs in the sliding window", () => {
      expect(tracker.recordSign()).toBe(1);
      expect(tracker.recordSign()).toBe(2);
      expect(tracker.recordSign()).toBe(3);
    });
  });

  describe("bulk read detection", () => {
    it("counts reads per namespace in the sliding window", () => {
      expect(tracker.recordNamespaceRead("my-ns")).toBe(1);
      expect(tracker.recordNamespaceRead("my-ns")).toBe(2);
      expect(tracker.recordNamespaceRead("my-ns")).toBe(3);
    });

    it("tracks namespaces independently", () => {
      tracker.recordNamespaceRead("ns-a");
      tracker.recordNamespaceRead("ns-a");
      tracker.recordNamespaceRead("ns-b");

      expect(tracker.recordNamespaceRead("ns-a")).toBe(3);
      expect(tracker.recordNamespaceRead("ns-b")).toBe(2);
    });
  });

  describe("baseline encryption", () => {
    it("cannot be loaded with a different key", async () => {
      tracker.recordNamespaceAccess("secret-ns");
      await tracker.save();

      const wrongKey = generateRandomKey();
      const tracker2 = new BaselineTracker(storage, wrongKey);
      await tracker2.load();

      // Should treat as first session (decryption failed)
      expect(tracker2.isFirstSession).toBe(true);
      expect(tracker2.getProfile().known_namespaces).toEqual([]);
    });
  });
});
