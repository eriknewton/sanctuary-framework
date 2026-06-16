/**
 * L2 Call Governor Tests
 *
 * Verifies:
 * - Volume limit enforcement (sliding window)
 * - Rate limit enforcement per tool (loop detection + escalation)
 * - Duplicate detection via SHA-256 hashing
 * - Duplicate cache TTL expiry
 * - Lifetime counter and hard stop
 * - Reset clears all state
 * - Per-server config overrides
 * - Status reporting
 * - Default config behavior
 * - Canonical hashing (arg order independence)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CallGovernor } from "../../src/operational/call-governor.js";

describe("CallGovernor", () => {
  let governor: CallGovernor;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-04-01T00:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ── Default config ──────────────────────────────────────────────────

  describe("default config", () => {
    it("works with no config provided", () => {
      governor = new CallGovernor();
      const result = governor.check("server", "tool", {});
      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it("returns correct defaults in status", () => {
      governor = new CallGovernor();
      const status = governor.getStatus();
      expect(status.volume_limit).toBe(200);
      expect(status.lifetime_limit).toBe(1000);
      expect(status.volume_current).toBe(0);
      expect(status.lifetime_current).toBe(0);
      expect(status.hard_stopped).toBe(false);
      expect(status.duplicate_cache_size).toBe(0);
    });
  });

  // ── Volume limit ──────────────────────────────────────────────────

  describe("volume limit", () => {
    it("allows calls under the volume limit", () => {
      governor = new CallGovernor({ volume_limit: 5, volume_window_ms: 60000 });
      for (let i = 0; i < 5; i++) {
        const result = governor.check("server", `tool-${i}`, {});
        expect(result.allowed).toBe(true);
      }
    });

    it("blocks when volume limit is reached", () => {
      governor = new CallGovernor({ volume_limit: 3, volume_window_ms: 60000 });
      for (let i = 0; i < 3; i++) {
        governor.check("server", `tool-${i}`, {});
      }
      const result = governor.check("server", "tool-extra", {});
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("volume_exceeded");
    });

    it("allows calls after volume window expires (sliding window)", () => {
      governor = new CallGovernor({ volume_limit: 2, volume_window_ms: 10000 });

      governor.check("server", "tool-0", {});
      governor.check("server", "tool-1", {});

      // Volume exhausted
      let result = governor.check("server", "tool-2", {});
      expect(result.allowed).toBe(false);

      // Advance past the window
      vi.advanceTimersByTime(10001);

      result = governor.check("server", "tool-2", {});
      expect(result.allowed).toBe(true);
    });
  });

  // ── Rate limit ────────────────────────────────────────────────────

  describe("rate limit", () => {
    it("allows calls under the rate limit for a tool", () => {
      governor = new CallGovernor({ rate_limit: 3, rate_window_ms: 60000, volume_limit: 100 });
      for (let i = 0; i < 3; i++) {
        const result = governor.check("server", "tool", { i });
        expect(result.allowed).toBe(true);
      }
    });

    it("blocks and escalates when rate limit is exceeded", () => {
      governor = new CallGovernor({ rate_limit: 2, rate_window_ms: 60000, volume_limit: 100 });
      governor.check("server", "tool", { a: 1 });
      governor.check("server", "tool", { b: 2 });

      const result = governor.check("server", "tool", { c: 3 });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("rate_exceeded");
      expect(result.escalate).toBe(true);
    });

    it("isolates rate limits per tool — tool A does not affect tool B", () => {
      governor = new CallGovernor({ rate_limit: 2, rate_window_ms: 60000, volume_limit: 100 });
      governor.check("server", "toolA", { x: 1 });
      governor.check("server", "toolA", { x: 2 });

      // toolA is rate-limited
      const resultA = governor.check("server", "toolA", { x: 3 });
      expect(resultA.allowed).toBe(false);
      expect(resultA.reason).toBe("rate_exceeded");

      // toolB is unaffected
      const resultB = governor.check("server", "toolB", {});
      expect(resultB.allowed).toBe(true);
    });

    it("rate limit resets after the rate window expires", () => {
      governor = new CallGovernor({ rate_limit: 2, rate_window_ms: 5000, volume_limit: 100 });
      governor.check("server", "tool", { a: 1 });
      governor.check("server", "tool", { b: 2 });

      let result = governor.check("server", "tool", { c: 3 });
      expect(result.allowed).toBe(false);

      vi.advanceTimersByTime(5001);

      result = governor.check("server", "tool", { d: 4 });
      expect(result.allowed).toBe(true);
    });
  });

  // ── Duplicate detection ───────────────────────────────────────────

  describe("duplicate detection", () => {
    it("returns cached result for identical call", () => {
      governor = new CallGovernor({ volume_limit: 100, rate_limit: 100, duplicate_ttl_ms: 60000 });
      const args = { path: "/test", depth: 3 };

      // First call — allowed and no cache
      const first = governor.check("server", "tool", args);
      expect(first.allowed).toBe(true);
      expect(first.reason).toBeUndefined();

      // Record a result
      governor.recordResult("server", "tool", args, { data: "cached-value" });

      // Second identical call — returns cached
      const second = governor.check("server", "tool", args);
      expect(second.allowed).toBe(true);
      expect(second.reason).toBe("duplicate_cached");
      expect(second.cached_result).toEqual({ data: "cached-value" });
    });

    it("does not return cached result after TTL expires", () => {
      governor = new CallGovernor({ volume_limit: 100, rate_limit: 100, duplicate_ttl_ms: 5000 });
      const args = { key: "value" };

      governor.check("server", "tool", args);
      governor.recordResult("server", "tool", args, { result: "old" });

      vi.advanceTimersByTime(5001);

      const result = governor.check("server", "tool", args);
      // Should not be duplicate_cached since TTL expired
      expect(result.reason).not.toBe("duplicate_cached");
      expect(result.allowed).toBe(true);
    });

    it("different args produce different cache entries", () => {
      governor = new CallGovernor({ volume_limit: 100, rate_limit: 100, duplicate_ttl_ms: 60000 });

      governor.check("server", "tool", { a: 1 });
      governor.recordResult("server", "tool", { a: 1 }, "result-a");

      governor.check("server", "tool", { a: 2 });
      governor.recordResult("server", "tool", { a: 2 }, "result-b");

      const resultA = governor.check("server", "tool", { a: 1 });
      expect(resultA.cached_result).toBe("result-a");

      const resultB = governor.check("server", "tool", { a: 2 });
      expect(resultB.cached_result).toBe("result-b");
    });
  });

  // ── Canonical hashing ─────────────────────────────────────────────

  describe("canonical hashing", () => {
    it("same args in different key order produce the same hash (cache hit)", () => {
      governor = new CallGovernor({ volume_limit: 100, rate_limit: 100, duplicate_ttl_ms: 60000 });

      const args1 = { alpha: 1, beta: 2, gamma: 3 };
      governor.check("server", "tool", args1);
      governor.recordResult("server", "tool", args1, "canonical-result");

      // Same keys, different insertion order
      const args2 = { gamma: 3, alpha: 1, beta: 2 };
      const result = governor.check("server", "tool", args2);
      expect(result.reason).toBe("duplicate_cached");
      expect(result.cached_result).toBe("canonical-result");
    });
  });

  // ── Lifetime limit ────────────────────────────────────────────────

  describe("lifetime limit", () => {
    it("blocks after lifetime limit is reached", () => {
      governor = new CallGovernor({ lifetime_limit: 3, volume_limit: 100, rate_limit: 100 });
      governor.check("server", "t1", {});
      governor.check("server", "t2", {});
      governor.check("server", "t3", {});

      const result = governor.check("server", "t4", {});
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("lifetime_exceeded");
    });

    it("sets hard_stopped after lifetime limit is reached", () => {
      governor = new CallGovernor({ lifetime_limit: 1, volume_limit: 100, rate_limit: 100 });
      governor.check("server", "tool", {});

      // Trigger hard stop
      governor.check("server", "tool2", {});

      const status = governor.getStatus();
      expect(status.hard_stopped).toBe(true);
    });

    it("blocks all calls after hard stop, even to new tools", () => {
      governor = new CallGovernor({ lifetime_limit: 1, volume_limit: 100, rate_limit: 100 });
      governor.check("server", "tool1", {});

      // Hard stop triggered
      const r1 = governor.check("server", "tool2", {});
      expect(r1.allowed).toBe(false);
      expect(r1.reason).toBe("lifetime_exceeded");

      // Further calls still blocked
      const r2 = governor.check("other-server", "other-tool", {});
      expect(r2.allowed).toBe(false);
      expect(r2.reason).toBe("lifetime_exceeded");
    });
  });

  // ── Reset ─────────────────────────────────────────────────────────

  describe("reset", () => {
    it("clears all counters and hard stop", () => {
      governor = new CallGovernor({ lifetime_limit: 2, volume_limit: 100, rate_limit: 100 });
      governor.check("server", "tool", { a: 1 });
      governor.recordResult("server", "tool", { a: 1 }, "cached");
      governor.check("server", "tool2", {});

      // Should be hard stopped now
      const blocked = governor.check("server", "tool3", {});
      expect(blocked.allowed).toBe(false);

      governor.reset();

      const status = governor.getStatus();
      expect(status.volume_current).toBe(0);
      expect(status.lifetime_current).toBe(0);
      expect(status.hard_stopped).toBe(false);
      expect(status.duplicate_cache_size).toBe(0);
      expect(Object.keys(status.rate_by_tool)).toHaveLength(0);

      // Calls work again
      const result = governor.check("server", "tool", {});
      expect(result.allowed).toBe(true);
    });
  });

  // ── Per-server overrides ──────────────────────────────────────────

  describe("per-server overrides", () => {
    it("applies different limits per server", () => {
      governor = new CallGovernor({
        volume_limit: 100,
        rate_limit: 10,
        rate_window_ms: 60000,
        per_server_overrides: {
          "restricted-server": { rate_limit: 2 },
        },
      });

      // restricted-server has rate_limit 2
      governor.check("restricted-server", "tool", { a: 1 });
      governor.check("restricted-server", "tool", { b: 2 });
      const restricted = governor.check("restricted-server", "tool", { c: 3 });
      expect(restricted.allowed).toBe(false);
      expect(restricted.reason).toBe("rate_exceeded");

      // default server still has rate_limit 10
      for (let i = 0; i < 5; i++) {
        const r = governor.check("normal-server", "tool", { i });
        expect(r.allowed).toBe(true);
      }
    });

    it("overrides volume limit per server", () => {
      governor = new CallGovernor({
        volume_limit: 100,
        volume_window_ms: 60000,
        per_server_overrides: {
          "limited": { volume_limit: 2 },
        },
      });

      governor.check("limited", "t1", {});
      governor.check("limited", "t2", {});
      const result = governor.check("limited", "t3", {});
      // Note: volume window is global, but the limit is per-server config.
      // The governor uses effectiveConfig for the limit check but the global
      // volumeWindow array. So the per-server volume_limit applies to the
      // global window count.
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("volume_exceeded");
    });
  });

  // ── Status ────────────────────────────────────────────────────────

  describe("status", () => {
    it("returns correct counters after activity", () => {
      governor = new CallGovernor({ volume_limit: 100, rate_limit: 100 });

      governor.check("server", "tool-a", { x: 1 });
      governor.check("server", "tool-a", { x: 2 });
      governor.check("server", "tool-b", {});
      governor.recordResult("server", "tool-a", { x: 1 }, "cached");

      const status = governor.getStatus();
      expect(status.volume_current).toBe(3);
      expect(status.lifetime_current).toBe(3);
      expect(status.rate_by_tool["server::tool-a"]).toBe(2);
      expect(status.rate_by_tool["server::tool-b"]).toBe(1);
      expect(status.duplicate_cache_size).toBe(1);
      expect(status.hard_stopped).toBe(false);
    });

    it("prunes expired entries from rate_by_tool in status", () => {
      governor = new CallGovernor({ volume_limit: 100, rate_limit: 100, rate_window_ms: 5000 });

      governor.check("server", "tool", {});

      vi.advanceTimersByTime(5001);

      const status = governor.getStatus();
      // Rate entry should be pruned since it's outside the rate window
      expect(status.rate_by_tool["server::tool"]).toBeUndefined();
    });
  });

  // ── Evaluation order ──────────────────────────────────────────────

  describe("evaluation order", () => {
    it("lifetime check happens before volume check", () => {
      // Set lifetime_limit=2, volume_limit=100 so only lifetime triggers
      governor = new CallGovernor({ lifetime_limit: 2, volume_limit: 100, rate_limit: 100, volume_window_ms: 60000 });
      governor.check("server", "t1", {});
      governor.check("server", "t2", {});

      // Lifetime is exceeded. Verify it reports lifetime_exceeded, not volume.
      const result = governor.check("server", "t3", {});
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("lifetime_exceeded");
    });

    it("volume check happens before rate check", () => {
      // Set volume_limit=1, rate_limit=100 so only volume triggers after first call
      governor = new CallGovernor({ lifetime_limit: 100, volume_limit: 1, rate_limit: 100, volume_window_ms: 60000 });
      governor.check("server", "tool", {});

      const result = governor.check("server", "tool", { different: true });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("volume_exceeded");
    });
  });
});
