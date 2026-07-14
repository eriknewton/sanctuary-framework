/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: audit-read derivation tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pins the honesty semantics of `deriveAuditReadOutcome` (the pure derivation
 * behind the pack's audit read): WATCH-2 (retained_total from the on-disk
 * census, windowed fallback only when the census is unreadable) and F3
 * (round-2 sweep: a provably incomplete read fails closed to `read_failed`
 * instead of feeding a truncated window into the aggregation and the
 * shortfall reassurance arm).
 */

import { describe, it, expect } from "vitest";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import { deriveAuditReadOutcome } from "../../src/evidence-pack/cli.js";

function entry(timestamp: string): AuditEntry {
  return {
    timestamp,
    layer: "l2",
    operation: "gate_approve",
    identity_id: "agent-a",
    result: "success",
  };
}

const RETENTION_CONFIG = { maxEntries: 100_000, maxTotalSizeBytes: 0 };

describe("deriveAuditReadOutcome", () => {
  it("F3: fails closed when the on-disk census exceeds the windowed total (RAM window truncated)", () => {
    const outcome = deriveAuditReadOutcome({
      entries: [entry("2026-07-02T00:00:00.000Z")],
      windowedTotal: 1,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 5, totalSizeBytes: 1024, everPruned: false },
    });
    expect(outcome.status).toBe("read_failed");
    if (outcome.status === "read_failed") {
      expect(outcome.reason).toContain("retains 5 entries");
      expect(outcome.reason).toContain("only 1 could be read");
      expect(outcome.reason).toContain("not read to completion");
    }
  });

  it("F3: fails closed when query() returned fewer entries than its own total (limit truncated)", () => {
    const outcome = deriveAuditReadOutcome({
      entries: [entry("2026-07-02T00:00:00.000Z")],
      windowedTotal: 3,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 3, totalSizeBytes: 1024, everPruned: false },
    });
    expect(outcome.status).toBe("read_failed");
  });

  it("WATCH-2: retained_total comes from the on-disk census when it is readable", () => {
    const entries = [
      entry("2026-07-02T00:00:00.000Z"),
      entry("2026-07-03T00:00:00.000Z"),
    ];
    const outcome = deriveAuditReadOutcome({
      entries,
      windowedTotal: 2,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 2, totalSizeBytes: 2048, everPruned: false },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.retained_total).toBe(2);
      expect(outcome.value.retention.earliest_retained_at).toBe(
        "2026-07-02T00:00:00.000Z"
      );
      expect(outcome.value.retention.ever_pruned).toBe(false);
    }
  });

  it("WATCH-2: falls back to the windowed total ONLY when the census itself was unreadable", () => {
    const entries = [entry("2026-07-02T00:00:00.000Z")];
    const outcome = deriveAuditReadOutcome({
      entries,
      windowedTotal: 1,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: null, totalSizeBytes: 0, everPruned: null },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.retained_total).toBe(1);
      // The unreadable-census fallback keeps ever_pruned null (hedged arm),
      // never false (the reassurance arm).
      expect(outcome.value.retention.ever_pruned).toBeNull();
    }
  });

  it("a genuinely empty store derives a populated zero, not a failure (empty is not truncated)", () => {
    const outcome = deriveAuditReadOutcome({
      entries: [],
      windowedTotal: 0,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 0, totalSizeBytes: 0, everPruned: false },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.retained_total).toBe(0);
      expect(outcome.value.retention.earliest_retained_at).toBeNull();
    }
  });
});
