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
import { AuditIntegrityError } from "../../src/operational/audit-log.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import {
  classifyDaemonIntegrityError,
  daemonStoreCliWarning,
  daemonUnreadableReason,
  deriveAuditReadOutcome,
  mergeEverPruned,
} from "../../src/evidence-pack/cli.js";
import { detectShortfall } from "../../src/evidence-pack/aggregate.js";
import { quarterWindow } from "../../src/evidence-pack/quarter.js";

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

  it("R3-3: earliest_retained_at is the timestamp MINIMUM, not the positionally-first entry (backward clock skew)", () => {
    // Append order puts the LATER-appended entry with an EARLIER timestamp
    // (backward clock skew). Positional entries[0] would report 00:10 and let
    // the never-pruned reassurance arm assert "no recorded activity before
    // 00:10" while a retained entry is timestamped 00:05.
    const entries = [
      entry("2026-07-02T00:10:00.000Z"),
      entry("2026-07-02T00:05:00.000Z"),
      entry("2026-07-02T00:20:00.000Z"),
    ];
    const outcome = deriveAuditReadOutcome({
      entries,
      windowedTotal: 3,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 3, totalSizeBytes: 3072, everPruned: false },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.earliest_retained_at).toBe(
        "2026-07-02T00:05:00.000Z"
      );
    }
  });

  it("R3-3: an unparseable timestamp is skipped by the min-scan; a non-empty read still yields a non-null earliest", () => {
    const entries = [entry("not-a-timestamp"), entry("2026-07-02T00:05:00.000Z")];
    const outcome = deriveAuditReadOutcome({
      entries,
      windowedTotal: 2,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 2, totalSizeBytes: 2048, everPruned: false },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.earliest_retained_at).toBe(
        "2026-07-02T00:05:00.000Z"
      );
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

  // ─── WATCH-1: F2 audit-store split — the daemon store must be read too ───
  describe("WATCH-1: daemon enforcement store (_audit-daemon)", () => {
    it("no daemon param defaults to `absent` — a non-split fortress is unchanged", () => {
      const outcome = deriveAuditReadOutcome({
        entries: [entry("2026-07-02T00:00:00.000Z")],
        windowedTotal: 1,
        retentionConfig: RETENTION_CONFIG,
        usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
      });
      expect(outcome.status).toBe("populated");
      if (outcome.status === "populated") {
        expect(outcome.value.retention.daemon_store.status).toBe("absent");
        expect(outcome.value.retention.daemon_store.included_entry_count).toBe(0);
        expect(outcome.value.entries.length).toBe(1);
        expect(outcome.value.retention.retained_total).toBe(1);
      }
    });

    it("`included` MERGES daemon entries + retention into the census", () => {
      const outcome = deriveAuditReadOutcome({
        entries: [entry("2026-07-02T00:00:00.000Z")],
        windowedTotal: 1,
        retentionConfig: RETENTION_CONFIG,
        usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
        daemon: {
          status: "included",
          entries: [
            entry("2026-07-03T00:00:00.000Z"),
            entry("2026-07-04T00:00:00.000Z"),
          ],
          windowedTotal: 2,
          usage: { entryCount: 2, totalSizeBytes: 2048, everPruned: true },
          retentionConfig: RETENTION_CONFIG,
        },
      });
      expect(outcome.status).toBe("populated");
      if (outcome.status === "populated") {
        // Entries unioned; retention summed; ever_pruned OR-ed across stores.
        expect(outcome.value.entries.length).toBe(3);
        expect(outcome.value.retention.retained_total).toBe(3);
        expect(outcome.value.retention.retained_total_size_bytes).toBe(3072);
        expect(outcome.value.retention.ever_pruned).toBe(true);
        expect(outcome.value.retention.daemon_store.status).toBe("included");
        expect(outcome.value.retention.daemon_store.included_entry_count).toBe(2);
      }
    });

    it("`included`: a daemon entry can be the earliest retained (min-scan over the merged set)", () => {
      const outcome = deriveAuditReadOutcome({
        entries: [entry("2026-07-10T00:00:00.000Z")],
        windowedTotal: 1,
        retentionConfig: RETENTION_CONFIG,
        usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
        daemon: {
          status: "included",
          entries: [entry("2026-07-01T00:00:00.000Z")],
          windowedTotal: 1,
          usage: { entryCount: 1, totalSizeBytes: 512, everPruned: false },
          retentionConfig: RETENTION_CONFIG,
        },
      });
      expect(outcome.status).toBe("populated");
      if (outcome.status === "populated") {
        expect(outcome.value.retention.earliest_retained_at).toBe(
          "2026-07-01T00:00:00.000Z"
        );
      }
    });

    it("`included` but the daemon read is TRUNCATED fails closed (same honesty bar as the operator store)", () => {
      const outcome = deriveAuditReadOutcome({
        entries: [entry("2026-07-02T00:00:00.000Z")],
        windowedTotal: 1,
        retentionConfig: RETENTION_CONFIG,
        usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
        daemon: {
          status: "included",
          entries: [entry("2026-07-03T00:00:00.000Z")],
          windowedTotal: 1,
          usage: { entryCount: 9, totalSizeBytes: 4096, everPruned: true },
          retentionConfig: RETENTION_CONFIG,
        },
      });
      expect(outcome.status).toBe("read_failed");
      if (outcome.status === "read_failed") {
        expect(outcome.reason).toContain("_audit-daemon");
        expect(outcome.reason).toContain("not read to completion");
      }
    });

    it("`present_tampered`: the pack still generates, counts EXCLUDE the daemon store, and the TAMPER (not a privilege excuse) is disclosed", () => {
      const outcome = deriveAuditReadOutcome({
        entries: [entry("2026-07-02T00:00:00.000Z")],
        windowedTotal: 1,
        retentionConfig: RETENTION_CONFIG,
        usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
        daemon: { status: "present_tampered" },
      });
      expect(outcome.status).toBe("populated");
      if (outcome.status === "populated") {
        expect(outcome.value.entries.length).toBe(1);
        expect(outcome.value.retention.retained_total).toBe(1);
        expect(outcome.value.retention.daemon_store.status).toBe("present_tampered");
        expect(outcome.value.retention.daemon_store.included_entry_count).toBe(0);
      }
    });

    it("`present_unreadable`: the pack still generates (populated), counts EXCLUDE the daemon store, and the omission is disclosed", () => {
      const outcome = deriveAuditReadOutcome({
        entries: [entry("2026-07-02T00:00:00.000Z")],
        windowedTotal: 1,
        retentionConfig: RETENTION_CONFIG,
        usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
        daemon: { status: "present_unreadable" },
      });
      expect(outcome.status).toBe("populated");
      if (outcome.status === "populated") {
        // NOT a silent inclusion and NOT a whole-pack failure: counts are the
        // operator store only, and the disclosure carries the caveat forward.
        expect(outcome.value.entries.length).toBe(1);
        expect(outcome.value.retention.retained_total).toBe(1);
        expect(outcome.value.retention.daemon_store.status).toBe(
          "present_unreadable"
        );
        expect(outcome.value.retention.daemon_store.included_entry_count).toBe(0);
      }
    });

    it("G-2: `included` hands the daemon entries through so the generator can window them", () => {
      const daemonEntries = [
        entry("2026-07-03T00:00:00.000Z"),
        entry("2026-07-04T00:00:00.000Z"),
      ];
      const outcome = deriveAuditReadOutcome({
        entries: [entry("2026-07-02T00:00:00.000Z")],
        windowedTotal: 1,
        retentionConfig: RETENTION_CONFIG,
        usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
        daemon: {
          status: "included",
          entries: daemonEntries,
          windowedTotal: 2,
          usage: { entryCount: 2, totalSizeBytes: 2048, everPruned: false },
          retentionConfig: RETENTION_CONFIG,
        },
      });
      expect(outcome.status).toBe("populated");
      if (outcome.status === "populated") {
        expect(outcome.value.daemon_entries).toEqual(daemonEntries);
      }
    });

    it("G-3: a present_unreadable daemon carries its unreadable_reason forward for the disclosure", () => {
      const outcome = deriveAuditReadOutcome({
        entries: [entry("2026-07-02T00:00:00.000Z")],
        windowedTotal: 1,
        retentionConfig: RETENTION_CONFIG,
        usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
        daemon: { status: "present_unreadable", unreadable_reason: "io" },
      });
      expect(outcome.status).toBe("populated");
      if (outcome.status === "populated") {
        expect(outcome.value.retention.daemon_store.unreadable_reason).toBe("io");
      }
    });
  });
});

describe("daemonUnreadableReason (G-3 classifier)", () => {
  it("classifies EACCES / EPERM as a privilege limitation", () => {
    for (const code of ["EACCES", "EPERM"]) {
      const err = Object.assign(new Error(`${code}: denied`), { code });
      expect(daemonUnreadableReason(err)).toBe("privilege");
    }
  });

  it("walks the error `cause` chain to find a nested privilege error", () => {
    const root = Object.assign(new Error("EACCES: denied"), { code: "EACCES" });
    const wrapped = new Error("read failed", { cause: root });
    expect(daemonUnreadableReason(wrapped)).toBe("privilege");
  });

  it("classifies a generic / corruption error as io (root will not fix it)", () => {
    expect(daemonUnreadableReason(new Error("unexpected token in JSON"))).toBe("io");
    expect(
      daemonUnreadableReason(Object.assign(new Error("bad"), { code: "EIO" }))
    ).toBe("io");
    expect(daemonUnreadableReason(undefined)).toBe("io");
  });
});

describe("classifyDaemonIntegrityError (G-3 follow-up: access failure is not tamper)", () => {
  it("classifies a purely-access-failure strict throw as present_unreadable/privilege, NEVER tamper", () => {
    const err = new AuditIntegrityError([
      { kind: "entry_unreadable", key: "entry-1", message: "EACCES: denied" },
      { kind: "storage_unavailable", message: "list failed" },
    ]);
    const out = classifyDaemonIntegrityError(err);
    expect(out.status).toBe("present_unreadable");
    if (out.status === "present_unreadable") {
      expect(out.unreadable_reason).toBe("privilege");
    }
  });

  it("classifies a genuine tamper finding as present_tampered", () => {
    const err = new AuditIntegrityError([
      {
        kind: "entry_hash_mismatch",
        key: "entry-1",
        sequence: 1,
        expected: "aa",
        actual: "bb",
        message: "hash mismatch",
      },
    ]);
    expect(classifyDaemonIntegrityError(err).status).toBe("present_tampered");
  });

  it("a MIX of access + tamper findings is present_tampered (tamper wins)", () => {
    const err = new AuditIntegrityError([
      { kind: "entry_unreadable", key: "entry-1", message: "EACCES" },
      { kind: "prev_hash_mismatch", key: "entry-2", message: "link broken" },
    ]);
    expect(classifyDaemonIntegrityError(err).status).toBe("present_tampered");
  });
});

describe("daemonStoreCliWarning (G-1 follow-up: CLI summary is not a silent single-store count)", () => {
  it("warns for present_unreadable (operator-store-only count) and present_tampered", () => {
    const unreadable = daemonStoreCliWarning({
      status: "present_unreadable",
      included_entry_count: 0,
    }).join("\n");
    expect(unreadable).toContain("OPERATOR audit");
    expect(unreadable).toContain("_audit-daemon");
    expect(unreadable).toContain("not a complete enforcement census");

    const tampered = daemonStoreCliWarning({
      status: "present_tampered",
      included_entry_count: 0,
    }).join("\n");
    expect(tampered).toContain("FAILED integrity verification");
    expect(tampered).toContain("tamper evidence");
  });

  it("stays silent for absent / included / undefined (the count IS the census)", () => {
    expect(daemonStoreCliWarning({ status: "absent", included_entry_count: 0 })).toEqual([]);
    expect(daemonStoreCliWarning({ status: "included", included_entry_count: 5 })).toEqual([]);
    expect(daemonStoreCliWarning(undefined)).toEqual([]);
  });
});

// ─── D5-2 (dry-bar round 5): the pruned-status merge must not launder an ───
// ─── UNKNOWN (null) into a definitive `false`. ────────────────────────────
describe("mergeEverPruned (D5-2: null is absorbing, never laundered to false)", () => {
  it("true dominates: any store that definitely pruned makes the merge true", () => {
    expect(mergeEverPruned(true, false)).toBe(true);
    expect(mergeEverPruned(false, true)).toBe(true);
    expect(mergeEverPruned(true, null)).toBe(true);
    expect(mergeEverPruned(null, true)).toBe(true);
    expect(mergeEverPruned(true, true)).toBe(true);
  });

  it("an UNKNOWN (null) can NEVER become a definitive never-pruned false", () => {
    // The exact D5-2 regression: `null || false` used to collapse to `false`,
    // re-enabling the flattering "never pruned / no activity before X" arm from
    // an unreadable census. It must stay UNKNOWN (null).
    expect(mergeEverPruned(null, false)).toBeNull();
    expect(mergeEverPruned(false, null)).toBeNull();
    expect(mergeEverPruned(null, null)).toBeNull();
  });

  it("only two DEFINITE never-pruned reads merge to a definitive false", () => {
    expect(mergeEverPruned(false, false)).toBe(false);
  });
});

describe("D5-2: deriveAuditReadOutcome keeps an unreadable store's pruned-status UNKNOWN", () => {
  it("operator pruned-status UNKNOWN + daemon false merges to null, NOT a definitive false", () => {
    // Operator `getRetentionUsage()` threw (entryCount null / everPruned null),
    // daemon store readable and genuinely never-pruned. The merged census must
    // NOT assert a definitive never-pruned; it stays UNKNOWN so the flattering
    // reassurance arm cannot fire from a census that was not fully read.
    const outcome = deriveAuditReadOutcome({
      entries: [entry("2026-07-02T00:00:00.000Z")],
      windowedTotal: 1,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: null, totalSizeBytes: 0, everPruned: null },
      daemon: {
        status: "included",
        entries: [entry("2026-07-03T00:00:00.000Z")],
        windowedTotal: 1,
        usage: { entryCount: 1, totalSizeBytes: 512, everPruned: false },
        retentionConfig: RETENTION_CONFIG,
      },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.ever_pruned).toBeNull();
    }
  });

  it("daemon pruned-status UNKNOWN + operator false ALSO merges to null (both directions)", () => {
    const outcome = deriveAuditReadOutcome({
      entries: [entry("2026-07-02T00:00:00.000Z")],
      windowedTotal: 1,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
      daemon: {
        status: "included",
        entries: [entry("2026-07-03T00:00:00.000Z")],
        windowedTotal: 1,
        usage: { entryCount: null, totalSizeBytes: 0, everPruned: null },
        retentionConfig: RETENTION_CONFIG,
      },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.ever_pruned).toBeNull();
    }
  });

  it("either store definitely pruned still merges to a definitive true", () => {
    const outcome = deriveAuditReadOutcome({
      entries: [entry("2026-07-02T00:00:00.000Z")],
      windowedTotal: 1,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
      daemon: {
        status: "included",
        entries: [entry("2026-07-03T00:00:00.000Z")],
        windowedTotal: 1,
        usage: { entryCount: 1, totalSizeBytes: 512, everPruned: true },
        retentionConfig: RETENTION_CONFIG,
      },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      expect(outcome.value.retention.ever_pruned).toBe(true);
    }
  });
});

// ─── D5-1 (dry-bar round 5): the merge must carry each store's OWN cap so ──
// ─── at-cap is judged per store, not the merged total vs a single cap. ────
describe("D5-1: deriveAuditReadOutcome builds a per-store retention breakdown", () => {
  it("`included` emits an operator + daemon per-store breakdown, each with its OWN cap", () => {
    // Non-truncated reads (entryCount == windowedTotal == entries.length); the
    // point is that each store carries its OWN distinct cap, not the merged one.
    const outcome = deriveAuditReadOutcome({
      entries: [entry("2026-07-02T00:00:00.000Z")],
      windowedTotal: 1,
      retentionConfig: { maxEntries: 100_000, maxTotalSizeBytes: 100 },
      usage: { entryCount: 1, totalSizeBytes: 40, everPruned: false },
      daemon: {
        status: "included",
        entries: [entry("2026-07-03T00:00:00.000Z")],
        windowedTotal: 1,
        usage: { entryCount: 1, totalSizeBytes: 30, everPruned: false },
        retentionConfig: { maxEntries: 90_000, maxTotalSizeBytes: 90 },
      },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      const per = outcome.value.retention.per_store_retention;
      expect(per).toEqual([
        {
          store: "operator",
          max_entries: 100_000,
          retained_total: 1,
          max_total_size_bytes: 100,
          retained_total_size_bytes: 40,
        },
        {
          store: "daemon",
          max_entries: 90_000,
          retained_total: 1,
          max_total_size_bytes: 90,
          retained_total_size_bytes: 30,
        },
      ]);
      // The merged DISPLAY totals still sum both stores (WATCH-2 semantics).
      expect(outcome.value.retention.retained_total).toBe(2);
      expect(outcome.value.retention.retained_total_size_bytes).toBe(70);
    }
  });

  it("a non-split fortress emits only the operator store in the breakdown", () => {
    const outcome = deriveAuditReadOutcome({
      entries: [entry("2026-07-02T00:00:00.000Z")],
      windowedTotal: 1,
      retentionConfig: RETENTION_CONFIG,
      usage: { entryCount: 1, totalSizeBytes: 1024, everPruned: false },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status === "populated") {
      const per = outcome.value.retention.per_store_retention;
      expect(per).toHaveLength(1);
      expect(per?.[0]?.store).toBe("operator");
    }
  });

  it("false→honest end-to-end: two stores EACH below their own cap, merged over one cap, is NOT 'at cap'", () => {
    // The exact D5-1 falsifying state, scaled: operator 60 + daemon 50 entries,
    // each store's OWN cap 100 (combined capacity 200). The old code summed to
    // 110 and compared against a single 100-cap -> false "at cap". Per-store,
    // neither store is at its own cap, so retention_at_cap must be false AND the
    // genuine "no recorded activity before X" reassurance is NOT suppressed.
    const opEntries = Array.from({ length: 60 }, (_, i) =>
      entry(`2026-08-01T00:00:${String(i % 60).padStart(2, "0")}.000Z`)
    );
    const daemonEntries = Array.from({ length: 50 }, (_, i) =>
      entry(`2026-08-02T00:00:${String(i % 60).padStart(2, "0")}.000Z`)
    );
    const outcome = deriveAuditReadOutcome({
      entries: opEntries,
      windowedTotal: 60,
      retentionConfig: { maxEntries: 100, maxTotalSizeBytes: 0 },
      usage: { entryCount: 60, totalSizeBytes: 600, everPruned: false },
      daemon: {
        status: "included",
        entries: daemonEntries,
        windowedTotal: 50,
        usage: { entryCount: 50, totalSizeBytes: 500, everPruned: false },
        retentionConfig: { maxEntries: 100, maxTotalSizeBytes: 0 },
      },
    });
    expect(outcome.status).toBe("populated");
    if (outcome.status !== "populated") return;
    // Sanity: the merged display total DOES exceed the single-store cap of 100.
    expect(outcome.value.retention.retained_total).toBe(110);

    const report = detectShortfall(quarterWindow({ year: 2026, quarter: 3 }), outcome.value.retention, {
      generatedAt: "2026-11-01T00:00:00.000Z",
      lastEntryAt: null,
    });
    // The healthy split fortress is NOT at a retention cap...
    expect(report.retention_at_cap).toBe(false);
    // ...and the false "at a retention cap"/pruned prose is gone; the earned
    // "no recorded activity before X" reassurance renders (the daemon store is
    // `included`, so the whole-fortress wording is correct).
    expect(report.explanation).toMatch(/no recorded activity before/i);
    expect(report.explanation).not.toMatch(/at a retention cap/i);
  });
});
