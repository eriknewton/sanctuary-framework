/**
 * Sanctuary v1.1 Dashboard — Status Mapping tests.
 *
 * Covers required test 8: backend status → UI label/glyph table per
 * binding addendum 1.3.
 */

import { describe, expect, it } from "vitest";
import {
  STATUS_MAPPING,
  resolveStatus,
  resolveStatusWithLiveness,
  effectiveLivenessStatus,
  ACTIVE_LIVENESS_STALENESS_MS,
} from "../../../src/dashboard/v1_1/status-mapping.js";

describe("v1.1 dashboard status mapping", () => {
  it("maps active to Running / online", () => {
    const e = STATUS_MAPPING.active;
    expect(e.label).toBe("Running");
    expect(e.glyph).toBe("online");
  });

  it("maps paused to Paused / idle", () => {
    expect(STATUS_MAPPING.paused.label).toBe("Paused");
    expect(STATUS_MAPPING.paused.glyph).toBe("idle");
  });

  it("maps restarting to Restarting / idle", () => {
    expect(STATUS_MAPPING.restarting.label).toBe("Restarting");
    expect(STATUS_MAPPING.restarting.glyph).toBe("idle");
  });

  it("maps locked_down to Locked down / offline", () => {
    expect(STATUS_MAPPING.locked_down.label).toBe("Locked down");
    expect(STATUS_MAPPING.locked_down.glyph).toBe("offline");
  });

  it("maps error to Error / away", () => {
    expect(STATUS_MAPPING.error.label).toBe("Error");
    expect(STATUS_MAPPING.error.glyph).toBe("away");
  });

  it("falls back to unknown for off-enum values", () => {
    // Type-cast to bypass compile-time constraint; runtime fallback is
    // the load-bearing behavior.
    const out = resolveStatus("not-a-real-status" as never);
    expect(out.glyph).toBe("unknown");
  });

  // Seam #10: a stale `active` is a liveness claim that must not survive
  // silence. Aging it drops the "Running / online" label and the
  // "protected / verified" badge that the renderer ties to `active`.
  describe("liveness staleness aging", () => {
    const now = Date.parse("2026-06-17T12:00:00.000Z");
    const fresh = new Date(now - 1_000).toISOString();
    const stale = new Date(now - ACTIVE_LIVENESS_STALENESS_MS - 1_000).toISOString();

    it("keeps a fresh active agent active", () => {
      expect(effectiveLivenessStatus("active", fresh, now)).toBe("active");
      expect(resolveStatusWithLiveness("active", fresh, now).label).toBe(
        "Running",
      );
    });

    it("ages a stale active agent to unknown (drops Running/online)", () => {
      expect(effectiveLivenessStatus("active", stale, now)).toBe("unknown");
      const ui = resolveStatusWithLiveness("active", stale, now);
      expect(ui.label).toBe("Unknown");
      expect(ui.glyph).toBe("unknown");
    });

    it("ages active with missing or unparseable last_activity_at to unknown", () => {
      expect(effectiveLivenessStatus("active", null, now)).toBe("unknown");
      expect(effectiveLivenessStatus("active", undefined, now)).toBe("unknown");
      expect(effectiveLivenessStatus("active", "not-a-date", now)).toBe(
        "unknown",
      );
    });

    it("does NOT age explicit non-active states on silence", () => {
      // Even with a long-stale timestamp, operator/system states pass through.
      for (const s of [
        "paused",
        "locked_down",
        "error",
        "unwrapping",
        "restarting",
        "unknown",
      ] as const) {
        expect(effectiveLivenessStatus(s, stale, now)).toBe(s);
      }
    });

    it("treats the window boundary conservatively (exactly at window = still active)", () => {
      const atBoundary = new Date(now - ACTIVE_LIVENESS_STALENESS_MS).toISOString();
      expect(effectiveLivenessStatus("active", atBoundary, now)).toBe("active");
    });
  });
});
