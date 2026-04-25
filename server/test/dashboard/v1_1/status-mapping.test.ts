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
});
