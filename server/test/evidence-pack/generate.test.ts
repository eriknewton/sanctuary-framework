/**
 * Sanctuary MCP Server - Evidence Pack generator tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hermetic end-to-end tests for the pack generator: PDF renders without
 * throwing, every emitted file signature and the manifest signature verify
 * offline, the quarter aggregation is correct, and the covered-window shortfall
 * is disclosed honestly. Every read-dependent claim flows through a typed
 * ReadOutcome. Uses an in-memory storage backend + a real fortress identity;
 * never touches `~/.sanctuary`.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, verify } from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { fromBase64url, stringToBytes } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import {
  buildEvidencePack,
  type AuditReadData,
  type BuildEvidencePackDeps,
} from "../../src/evidence-pack/generate.js";
import { canonicalJSON } from "../../src/evidence-pack/signer.js";
import { deriveAuditReadOutcome } from "../../src/evidence-pack/cli.js";
import { emptyInventorySnapshot } from "../../src/evidence-pack/inventory.js";
import {
  populated,
  emptyVerified,
  readFailed,
  type ReadOutcome,
} from "../../src/evidence-pack/read-outcome.js";
import type {
  EvidencePack,
  EvidencePackInput,
  QuarterAggregation,
  RetentionFacts,
} from "../../src/evidence-pack/types.js";

let masterKey: Uint8Array;
let signer: StoredIdentity;

beforeEach(async () => {
  masterKey = generateRandomKey(32);
  const storage = new MemoryStorage();
  const identityManager = new IdentityManager(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("acme-law", identityEncKey, "pw");
  await identityManager.save(storedIdentity);
  const primary = identityManager.getDefault();
  if (!primary) throw new Error("fixture: no primary identity");
  signer = primary;
});

function entry(
  timestamp: string,
  operation: string,
  result: "success" | "failure" = "success",
  details?: Record<string, unknown>
): AuditEntry {
  return { timestamp, layer: "l2", operation, identity_id: "agent-a", result, details };
}

/** A gate entry marked as a HUMAN control-point decision (decided_by human). */
function humanEntry(
  timestamp: string,
  operation: string,
  result: "success" | "failure" = "success"
): AuditEntry {
  return entry(timestamp, operation, result, { decided_by: "human" });
}

const FULL_COVERAGE: RetentionFacts = {
  max_entries: 100_000,
  retained_total: 3,
  max_total_size_bytes: 100 * 1024 * 1024,
  retained_total_size_bytes: 0,
  ever_pruned: false,
  earliest_retained_at: "2026-06-01T00:00:00.000Z",
  daemon_store: { status: "absent", included_entry_count: 0 },
};

/** Deps with a populated audit read. */
function deps(
  entries: AuditEntry[],
  retention: RetentionFacts = FULL_COVERAGE
): BuildEvidencePackDeps {
  const audit: ReadOutcome<AuditReadData> = populated({ entries, retention });
  return { audit, signer, masterKey };
}

function baseInput(): EvidencePackInput {
  return {
    firm_name: "Acme Law LLP",
    quarter: { year: 2026, quarter: 3 },
    generated_at_override: "2026-10-02T00:00:00.000Z",
    custody: populated({
      custody_mode: "passphrase",
      outbound_denied_by_default: populated(true),
    }),
  };
}

function agg(pack: EvidencePack): QuarterAggregation {
  if (pack.aggregation.status !== "populated") {
    throw new Error("expected populated aggregation");
  }
  return pack.aggregation.value;
}

function coverage(pack: EvidencePack) {
  const c = pack.manifest.coverage;
  if (!c.determinable) throw new Error("expected determinable coverage");
  return c;
}

describe("buildEvidencePack", () => {
  it("renders a PDF that begins with the PDF header and ends with %%EOF", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const pdf = Buffer.from(pack.pdf).toString("latin1");
    expect(pdf.startsWith("%PDF-1.4")).toBe(true);
    expect(pdf.includes("%%EOF")).toBe(true);
    expect(pack.pdf.length).toBeGreaterThan(1000);
  });

  it("signs every file and the manifest so a third party can verify offline", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const signerPub = fromBase64url(pack.manifest.signer.public_key_base64url);
    for (const file of pack.files) {
      const digest = hash(stringToBytes(file.content));
      expect(verify(digest, fromBase64url(file.signature), signerPub)).toBe(true);
      expect(file.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
    const { manifest_signature, ...body } = pack.manifest;
    const manifestDigest = hash(stringToBytes(canonicalJSON(body)));
    expect(verify(manifestDigest, fromBase64url(manifest_signature), signerPub)).toBe(true);
  });

  it("counts quarter decisions correctly, ignoring out-of-window entries", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([
        entry("2026-06-30T00:00:00.000Z", "gate_allow:before"), // out
        entry("2026-08-01T00:00:00.000Z", "gate_allow:a"),
        entry("2026-08-02T00:00:00.000Z", "gate_deny:b"),
        entry("2026-08-03T00:00:00.000Z", "gate_approval_proof:c"),
        entry("2026-10-01T00:00:00.000Z", "gate_allow:after"), // out (end excl)
      ])
    );
    expect(agg(pack).total_in_window).toBe(3);
    expect(agg(pack).by_category.allowed).toBe(1);
    expect(agg(pack).by_category.denied).toBe(1);
    expect(agg(pack).by_category.human_approved).toBe(1);
  });

  // ─── Codex-F1 / D7-1 (dry-bar round 7): the SIGNED manifest must never
  // serialize a definitive `retention_at_cap` boolean for a state where at-cap
  // was NOT determinable (a merged census with no usable per-store breakdown).
  // It emits the explicit `retention_at_cap_determinable: false` marker and
  // omits the boolean, mirroring the top-level `determinable: false` convention. ─
  describe("F1: manifest retention_at_cap determinability", () => {
    // The round-7 state: daemon `included`, merged retained_total (110) over
    // one store's cap (100), never-pruned, earliest after the quarter start.
    function mergedOverCap(
      perStore: RetentionFacts["per_store_retention"]
    ): RetentionFacts {
      return {
        max_entries: 100,
        retained_total: 110,
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: false,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        daemon_store: { status: "included", included_entry_count: 50 },
        per_store_retention: perStore,
      };
    }

    const variants: Array<[string, RetentionFacts["per_store_retention"]]> = [
      ["absent (undefined)", undefined],
      ["empty ([])", []],
      ["null (untyped caller)", null as unknown as undefined],
      [
        "operator-only while the daemon store is `included`",
        [
          {
            store: "operator",
            max_entries: 100,
            retained_total: 60,
            max_total_size_bytes: 0,
            retained_total_size_bytes: 0,
          },
        ],
      ],
      // Fix-round F1: mirror of the operator-only case -- a daemon-only
      // breakdown omits the operator row that EVERY census includes, so the
      // SIGNED manifest must carry the not-determinable marker, never a
      // definitive retention_at_cap:false computed over the daemon row alone.
      [
        "daemon-only (operator row missing)",
        [
          {
            store: "daemon",
            max_entries: 100,
            retained_total: 50,
            max_total_size_bytes: 0,
            retained_total_size_bytes: 0,
          },
        ],
      ],
      // ─── F2-R2 (Codex second-family review + Dry-8 sweep): row PRESENCE
      // without row FIELD COMPLETENESS. Presence-only rows sailed through the
      // chokepoint, atCapForStore evaluated the missing/NaN/wrong-typed fields
      // as "not at cap", and the SIGNED manifest carried a definitive
      // flattering retention_at_cap:false; duplicate/unknown-store rows fed
      // the at-cap OR and could sign the definitive OVER-claim (true). Every
      // variant must serialize the not-determinable marker instead. ───
      [
        "tags-only rows with NO cap fields (presence-only exploit)",
        [
          { store: "operator" },
          { store: "daemon" },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        "operator row with NaN max_entries",
        [
          { store: "operator", max_entries: NaN, retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
        ],
      ],
      [
        "operator row with string-typed max_entries (wrong type)",
        [
          { store: "operator", max_entries: "100", retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        "operator row with undefined retained_total_size_bytes (contract is null-or-finite)",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: undefined },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        "daemon row missing max_total_size_bytes",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, retained_total_size_bytes: 0 },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        // Dry-8 HIGH repro: the duplicate is AT its cap -- the old code signed
        // a definitive retention_at_cap:true from the invalid extra row.
        "duplicate operator rows (second duplicate at cap)",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "operator", max_entries: 100, retained_total: 100, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
        ],
      ],
      [
        "duplicate daemon rows",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
        ],
      ],
      [
        // Dry-8 HIGH repro: an unknown store tag AT its own (tiny) cap flipped
        // the at-cap OR -- a signed falsehood in the OVER-claiming direction.
        "unknown-store row (store:'archive' at its own cap) alongside complete rows",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "archive", max_entries: 1, retained_total: 1, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
    ];

    for (const [name, perStore] of variants) {
      it(`serializes the not-determinable marker (never a definitive boolean) for ${name}`, () => {
        const pack = buildEvidencePack(
          baseInput(),
          deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], mergedOverCap(perStore))
        );
        const c = coverage(pack);
        // The definitive boolean is OMITTED...
        expect("retention_at_cap" in c).toBe(false);
        // ...and the explicit marker is present.
        expect(c.retention_at_cap_determinable).toBe(false);
        // The serialized SIGNED manifest agrees byte-for-byte with the typed view
        // (the marker key name contains the boolean's, so match the exact key).
        const json = canonicalJSON(pack.manifest);
        expect(json).toContain('"retention_at_cap_determinable":false');
        expect(json).not.toContain('"retention_at_cap":');
        // The report PROSE for the same render hedges: no flattering reassurance.
        const report = pack.files[0]!.content;
        expect(report).not.toMatch(/below both/i);
        expect(report).not.toMatch(/no recorded activity before/i);
        expect(report).toMatch(/cannot be ruled out/i);
      });
    }

    it("non-vacuity: a determinable render serializes the definitive boolean, NO marker, and the pre-change key shape", () => {
      const pack = buildEvidencePack(
        baseInput(),
        deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
      );
      const c = coverage(pack);
      expect(c.retention_at_cap).toBe(false);
      expect("retention_at_cap_determinable" in c).toBe(false);
      // The determinable manifest coverage shape is UNCHANGED by the round-7 fix.
      expect(Object.keys(c)).toEqual([
        "determinable",
        "covered_from",
        "covered_to_exclusive",
        "shortfall",
        "in_progress_quarter",
        "retention_at_cap",
        "daemon_store",
      ]);
    });

    it("shipped-CLI-path: retention derived by deriveAuditReadOutcome (daemon included) stays determinable with an unchanged manifest shape", () => {
      // runEvidencePack derives its RetentionFacts exclusively through
      // deriveAuditReadOutcome, which ALWAYS seeds a complete per-store
      // breakdown (operator row + daemon row when merged), so a real CLI pack
      // must never hit the not-determinable branch. Exercises the same
      // derivation + generation components runEvidencePack composes.
      // Full untruncated reads (entryCount == entries read == windowed total)
      // so the derivation's fail-closed truncation guards do not fire: operator
      // 60 + daemon 50 retained -> merged 110 over one store's 100 cap while
      // NEITHER store is at its own cap.
      const operatorEntries = Array.from({ length: 60 }, (_, i) =>
        entry(`2026-08-02T00:00:${String(i).padStart(2, "0")}.000Z`, "gate_allow:op")
      );
      const daemonEntries = Array.from({ length: 50 }, (_, i) =>
        entry(`2026-08-03T00:00:${String(i).padStart(2, "0")}.000Z`, "gate_deny:daemon")
      );
      const outcome = deriveAuditReadOutcome({
        entries: operatorEntries,
        windowedTotal: 60,
        retentionConfig: { maxEntries: 100, maxTotalSizeBytes: 0 },
        usage: { entryCount: 60, totalSizeBytes: 1024, everPruned: false },
        daemon: {
          status: "included",
          entries: daemonEntries,
          windowedTotal: 50,
          usage: { entryCount: 50, totalSizeBytes: 1024, everPruned: false },
          retentionConfig: { maxEntries: 100, maxTotalSizeBytes: 0 },
        },
      });
      if (outcome.status !== "populated") throw new Error("expected populated");
      // The merged total (110) exceeds one store's cap (100) -- the exact
      // figures that are NOT determinable when hand-built without a breakdown --
      // but the shipped derivation carries the complete breakdown, so the
      // manifest serializes the definitive (false) boolean and no marker.
      expect(outcome.value.retention.retained_total).toBe(110);
      const pack = buildEvidencePack(baseInput(), {
        audit: outcome,
        signer,
        masterKey,
      });
      const c = coverage(pack);
      expect(c.retention_at_cap).toBe(false);
      expect("retention_at_cap_determinable" in c).toBe(false);
      expect(Object.keys(c)).toEqual([
        "determinable",
        "covered_from",
        "covered_to_exclusive",
        "shortfall",
        "in_progress_quarter",
        "retention_at_cap",
        "daemon_store",
      ]);
    });
  });

  it("discloses a covered-window shortfall in the manifest and the report", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        max_entries: 100,
        retained_total: 100, // at cap -> pruning likely
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: true,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
      })
    );
    expect(coverage(pack).shortfall).toBe(true);
    expect(coverage(pack).retention_at_cap).toBe(true);
    expect(pack.files[0]!.content).toContain("COVERAGE NOTICE");
  });

  it("WATCH-1: discloses a present-but-unreadable daemon enforcement store in the report", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        ...FULL_COVERAGE,
        daemon_store: { status: "present_unreadable", included_entry_count: 0 },
      })
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("_audit-daemon");
    expect(report).toContain("NOT included in the counts");
    expect(report).toContain("Re-run the pack as root");
  });

  it("WATCH-1: states that an included daemon enforcement store was merged", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        ...FULL_COVERAGE,
        daemon_store: { status: "included", included_entry_count: 7 },
      })
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("Daemon enforcement store: included");
    expect(report).toContain("7 daemon-recorded enforcement entries");
  });

  it("WATCH-1 round-5: a TAMPERED daemon store renders an INTEGRITY notice, never the privilege excuse", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        ...FULL_COVERAGE,
        daemon_store: { status: "present_tampered", included_entry_count: 0 },
      })
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("INTEGRITY NOTICE");
    expect(report).toContain("FAILED integrity verification");
    expect(report).toContain("NOT included in the counts");
    // The futile privilege advice must NOT appear for a tamper.
    expect(report).not.toContain("Re-run the pack as root");
    expect(report).not.toContain("NOT readable at this privilege");
  });

  it("WATCH-1: an absent daemon store adds no daemon disclosure (non-split fortress unchanged)", () => {
    const pack = buildEvidencePack(baseInput(), deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")]));
    const report = pack.files[0]!.content;
    expect(report).not.toContain("_audit-daemon");
    expect(report).not.toContain("Daemon enforcement store");
  });

  // ── G-1: daemon disclosure threaded into every census-presenting section ──

  /** The Markdown of one section (by its `# ` heading) from the assembled report. */
  function section(pack: EvidencePack, heading: string): string {
    const parts = pack.files[0]!.content.split("\n---\n");
    const found = parts.find((p) => p.trimStart().startsWith(`# ${heading}`));
    if (!found) throw new Error(`section not found: ${heading}`);
    return found;
  }

  it("G-1: a present-unreadable daemon store is disclosed in the EXECUTIVE SUMMARY and §6 HUMAN REVIEW, not only §7", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        ...FULL_COVERAGE,
        daemon_store: { status: "present_unreadable", included_entry_count: 0 },
      })
    );
    const exec = section(pack, "Executive summary");
    const human = section(pack, "Human review of AI actions at the control point");
    for (const s of [exec, human]) {
      expect(s).toContain("operator audit store only");
      expect(s).toContain("_audit-daemon");
      expect(s).toContain("not a complete enforcement census");
    }
    // The definitive-count sections defer the "re-run as root" remedy to §7 (G-3
    // scoping lives there); they must not emit the root advice themselves.
    expect(exec).not.toContain("Re-run the pack as root");
    expect(human).not.toContain("Re-run the pack as root");
  });

  it("G-1: a present-tampered daemon store raises an INTEGRITY notice in the exec summary and §6, never a privilege excuse", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        ...FULL_COVERAGE,
        daemon_store: { status: "present_tampered", included_entry_count: 0 },
      })
    );
    const exec = section(pack, "Executive summary");
    const human = section(pack, "Human review of AI actions at the control point");
    for (const s of [exec, human]) {
      expect(s).toContain("INTEGRITY NOTICE");
      expect(s).toContain("FAILED integrity verification");
      expect(s).not.toContain("Re-run the pack as root");
      expect(s).not.toContain("not readable at this privilege");
    }
  });

  it("G-1: an absent OR included daemon store adds NO operator-only caveat to the exec summary / §6 (no false alarm)", () => {
    for (const daemon_store of [
      { status: "absent" as const, included_entry_count: 0 },
      { status: "included" as const, included_entry_count: 3 },
    ]) {
      const pack = buildEvidencePack(
        baseInput(),
        deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
          ...FULL_COVERAGE,
          daemon_store,
        })
      );
      const exec = section(pack, "Executive summary");
      const human = section(pack, "Human review of AI actions at the control point");
      expect(exec).not.toContain("operator audit store only");
      expect(human).not.toContain("operator audit store only");
    }
  });

  it("G-1(c): a ZERO-ENTRY quarter with an unreadable daemon store scopes 'no history' to the operator log and signposts the daemon store", () => {
    const pack = buildEvidencePack(
      baseInput(), // Q3 complete at generation
      deps([], {
        max_entries: 100_000,
        retained_total: 0,
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: false,
        earliest_retained_at: null,
        daemon_store: { status: "present_unreadable", included_entry_count: 0 },
      })
    );
    const report = pack.files[0]!.content;
    // The old absolute "The audit log holds no retained entries" is scoped now.
    expect(report).toContain("The operator audit log holds no retained entries");
    expect(report).not.toContain("The audit log holds no retained entries, so");
    // And the daemon store is signposted right in the coverage prose.
    expect(report).toContain("daemon enforcement store (_audit-daemon) IS");
  });

  it("G-1(c) follow-up: a ZERO-ENTRY quarter with NO daemon store keeps neutral wording (no under-claiming 'operator' scoping)", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([], {
        max_entries: 100_000,
        retained_total: 0,
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: false,
        earliest_retained_at: null,
        daemon_store: { status: "absent", included_entry_count: 0 },
      })
    );
    const report = pack.files[0]!.content;
    // Single-store fortress: the neutral absolute is correct, not "operator".
    expect(report).toContain("The audit log holds no retained entries, so");
    expect(report).not.toContain("operator audit log holds no retained entries");
  });

  it("manifest coverage carries the daemon-store disclosure (no silent single-store signal in the SIGNED manifest)", () => {
    const unreadable = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        ...FULL_COVERAGE,
        daemon_store: {
          status: "present_unreadable",
          included_entry_count: 0,
          unreadable_reason: "io",
        },
      })
    );
    const c = coverage(unreadable);
    expect(c.daemon_store.status).toBe("present_unreadable");
    expect(c.daemon_store.unreadable_reason).toBe("io");

    // absent still serializes an explicit status (never simply omitted).
    const absent = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    expect(coverage(absent).daemon_store.status).toBe("absent");
  });

  // ── G-2: the §7 "N merged" figure is the QUARTER-WINDOWED daemon count ──

  it("G-2: §7 reports the WINDOWED daemon count that contributes to the counts, not the all-time total read", () => {
    const inWindow = [
      entry("2026-08-05T00:00:00.000Z", "gate_deny:d1"),
      entry("2026-08-06T00:00:00.000Z", "gate_deny:d2"),
    ];
    const outOfWindow = [
      entry("2026-01-01T00:00:00.000Z", "gate_deny:old1"),
      entry("2026-01-02T00:00:00.000Z", "gate_deny:old2"),
      entry("2026-11-01T00:00:00.000Z", "gate_deny:future"),
    ];
    const daemonEntries = [...inWindow, ...outOfWindow]; // 5 read, 2 in Q3
    const audit: ReadOutcome<AuditReadData> = populated({
      entries: [entry("2026-08-01T00:00:00.000Z", "gate_allow:op"), ...daemonEntries],
      retention: {
        ...FULL_COVERAGE,
        daemon_store: { status: "included", included_entry_count: 5 },
      },
      daemon_entries: daemonEntries,
    });
    const pack = buildEvidencePack(baseInput(), { audit, signer, masterKey });
    const report = pack.files[0]!.content;
    // Of 5 merged into the census, only 2 fall in Q3 and contribute to the counts.
    expect(report).toContain("Of 5 daemon-recorded enforcement entries merged");
    expect(report).toContain("2 fall within the reporting quarter");
    expect(report).toContain("contribute to the counts above");
  });

  // ── G-3: "re-run as root" only for a PRIVILEGE-unreadable daemon store ──

  it("G-3: a privilege-unreadable daemon store advises re-running as root", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        ...FULL_COVERAGE,
        daemon_store: {
          status: "present_unreadable",
          included_entry_count: 0,
          unreadable_reason: "privilege",
        },
      })
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("Re-run the pack as root for a complete enforcement census");
  });

  it("G-3: an I/O-unreadable daemon store gives honest framing and does NOT advise re-running as root", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        ...FULL_COVERAGE,
        daemon_store: {
          status: "present_unreadable",
          included_entry_count: 0,
          unreadable_reason: "io",
        },
      })
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("I/O or corruption error");
    expect(report).toContain("Re-running the pack as root will NOT resolve this");
    expect(report).not.toContain("Re-run the pack as root for a complete enforcement census");
  });

  it("N2: an all-post-quarter completed quarter cover banner says NONE covered, not the generic 'does not reach the start'", () => {
    const pack = buildEvidencePack(
      baseInput(), // generated_at 2026-10-02 (Q3 complete)
      deps([], {
        max_entries: 100_000,
        retained_total: 5,
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: true,
        earliest_retained_at: "2026-11-01T00:00:00.000Z", // entirely after Q3
      })
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("NONE of this quarter is covered");
    expect(report).not.toContain("does NOT reach the quarter start");
  });

  it("prints the honest coverage-basis and scope-and-limits language", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("Coverage basis");
    expect(report).toContain("INVISIBLE to this inventory");
    expect(report).toContain("Scope and limits");
    expect(report).toContain("do not claim per-rule per-flow");
  });

  it("renders each section title into the PDF", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const pdf = Buffer.from(pack.pdf).toString("latin1");
    expect(pdf).toContain("Executive summary");
    expect(pdf).toContain("AI tool inventory");
    expect(pdf).toContain("Scope and limits");
  });

  it("N1: counts human approvals AND human denials by decided_by; automated denials stay 'by policy'", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([
        humanEntry("2026-08-01T00:00:00.000Z", "gate_approve:tool_a"),
        humanEntry("2026-08-02T00:00:00.000Z", "gate_approve:tool_b"),
        humanEntry("2026-08-03T00:00:00.000Z", "gate_deny:tool_c", "failure"), // human denial
        entry("2026-08-04T00:00:00.000Z", "gate_deny:tool_e", "failure"), // automated denial
        entry("2026-08-05T00:00:00.000Z", "gate_allow:tool_d"),
      ])
    );
    expect(agg(pack).by_category.human_approved).toBe(2);
    expect(agg(pack).by_category.human_denied).toBe(1); // N1: real, not always 0
    expect(agg(pack).by_category.denied).toBe(1); // the automated one only
    const report = pack.files[0]!.content;
    expect(report).toContain("| Human-approved | 2 |");
    expect(report).toContain("| Human-denied | 1 |");
    expect(report).toContain("Denied by automated policy (no human) | 1");
    expect(report).not.toContain("Denied by policy |"); // old wrong wording
  });

  it("renders no phantom Escalated row", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    expect(pack.files[0]!.content).not.toContain("Escalated");
  });

  it("an in-progress quarter is stamped PARTIAL, shortfall:true, covered_to capped at generation time", () => {
    const pack = buildEvidencePack(
      {
        firm_name: "Acme Law LLP",
        quarter: { year: 2026, quarter: 3 },
        generated_at_override: "2026-08-15T12:00:00.000Z", // mid-Q3
        custody: populated({
          custody_mode: "passphrase",
          outbound_denied_by_default: populated(true),
        }),
      },
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], {
        max_entries: 100_000,
        retained_total: 3,
        max_total_size_bytes: 100 * 1024 * 1024,
        retained_total_size_bytes: 0,
        ever_pruned: false,
        earliest_retained_at: "2026-06-01T00:00:00.000Z",
      })
    );
    expect(coverage(pack).in_progress_quarter).toBe(true);
    expect(coverage(pack).shortfall).toBe(true);
    expect(coverage(pack).covered_to_exclusive).toBe("2026-08-15T12:00:00.000Z");
    expect(coverage(pack).covered_to_exclusive).not.toBe("2026-10-01T00:00:00.000Z");
    expect(pack.files[0]!.content).toContain("PARTIAL QUARTER");
  });

  it("a POPULATED inventory still prints the coverage-basis + never-complete language", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: populated([
            {
              agent_id: "coding-bot",
              harness: "claude_code",
              model_vendor: "anthropic",
              model_id: "claude-opus-4",
              wrapped_at: "2026-07-15T00:00:00.000Z",
              status: "active",
            },
          ]),
          mcp_servers: populated([{ name: "filesystem", transport: "stdio", enabled: true }]),
          observed_destinations: populated([
            { host: "api.openai.com", port: 443, protocol: "tcp", times_seen: 3, exfil_risk: false },
          ]),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("coding-bot");
    expect(report).toContain("filesystem");
    expect(report).toContain("api.openai.com");
    expect(report).toContain("Coverage basis");
    expect(report).toContain("INVISIBLE to this inventory");
    expect(report).toContain("never be read as an exhaustive list");
    expect(report).toContain("What is NOT in this inventory");
    expect(report).toContain("NOT a complete census");
    expect(report).toContain("since decommissioned");
  });

  it("HIGH-1 (sample-render): the egress table cannot be read as a breach admission", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: emptyVerified(),
          observed_destinations: populated([
            { host: "paste.example-exfil.ru", port: 443, protocol: "tcp", times_seen: 2, exfil_risk: true },
            { host: "api.anthropic.com", port: 443, protocol: "tcp", times_seen: 812, exfil_risk: false },
          ]),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // The bare, misreadable jargon is gone.
    expect(report).not.toContain("Exfil risk");
    expect(report).not.toMatch(/paste\.example-exfil\.ru.*\| yes \|/);
    // Replaced by a classification column + values that read as a category.
    expect(report).toContain("Destination risk class");
    expect(report).toContain("elevated (review)");
    expect(report).toContain("standard");
    // And an unmissable legend defining it as NOT a finding of exfiltration.
    expect(report).toContain("NOT a finding that any data left the firm");
    expect(report).toContain("NOT a confirmed exfiltration");
  });

  it("F1 (round-2 sweep): the egress table discloses its deny-only row basis", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: emptyVerified(),
          observed_destinations: populated([
            { host: "api.telegram.org", port: 443, protocol: "tcp", times_seen: 812, exfil_risk: true },
          ]),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // The legend must state, adjacent to the table, that rows are BLOCKED
    // observations (not contacts) and that allowed egress is structurally
    // absent - closing both the self-incriminating and the flattering read.
    expect(report).toContain("BLOCKED flow observations only");
    expect(report).toContain("a destination the wall DENIED");
    expect(report).toContain("a count of those denied attempts");
    expect(report).toContain("This table never lists allowed egress");
    expect(report).toContain("Allowed egress is not inventoried");
    expect(report).toContain("not a census of where the machines' traffic actually went");
    // R3-1 re-truing (final, post two-family-gate engine hardening): the
    // legend claims the engine's VERIFIED-suppression semantics -- rows are
    // suppressed/cleared only for flows the engine can positively verify
    // the signed policy permits for the attempting agent (exact host/IP
    // allows, the promote workflow's shape) -- and explicitly discloses
    // that a row may remain listed when permission cannot be verified that
    // exactly. No falsifiable "permitted destinations never appear"
    // absolute survives.
    expect(report).toContain("positively verify the current");
    expect(report).toContain("for the agent that attempted it");
    expect(report).toContain("as of its most recent refresh");
    expect(report).toContain("clears any pending candidate");
    expect(report).toContain("may also remain listed while its permission cannot be verified");
    expect(report).toContain("never that data was exchanged");
    expect(report).not.toContain("do NOT appear here");
    // R4-1 re-truing vs #934 (provenance-scoped belt + Linux flat-shape fold):
    // the auto-clearing claim is scoped to where the engine can attribute the
    // flow (Linux daemon rows), and the legend discloses that on the current
    // macOS build every flow is recorded "unknown" so macOS rows are NOT
    // auto-cleared by policy and must be cleared via promote/discard. This
    // keeps the auto-clear claim from over-generalizing to macOS.
    expect(report).toContain("Linux enforcement-daemon rows today");
    expect(report).toContain('unresolved "unknown" agent attribution');
    expect(report).toContain("macOS rows are NOT auto-cleared by policy");
    expect(report).toContain("Reconcile this table against current policy");
  });

  it("OPEN-MED-1 + F2: the egress 'Seen' legend states its true basis (candidate-record lifetime, not quarter-scoped)", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: emptyVerified(),
          observed_destinations: populated([
            { host: "api.anthropic.com", port: 443, protocol: "tcp", times_seen: 812, exfil_risk: false },
          ]),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // The legend must state the count's true basis adjacent to the table: the
    // current candidate record (discard/promote resets the count - F2), and
    // never quarter-scoped (OPEN-MED-1).
    expect(report).toContain("Legend - Seen:");
    expect(report).toContain("current candidate record was created");
    expect(report).toContain("later observed again restarts its count");
    expect(report).toContain(
      "NOT a count scoped to the reporting quarter"
    );
    expect(report).toContain(
      "may not have been seen within the reporting quarter"
    );
    // The falsifiable-under-reset absolute basis claim is gone.
    expect(report).not.toContain("since observation began on this install");
    // R4-2: with no pre-idempotency flag, no staleness caveat is printed - the
    // exactly-once basis stands unqualified for a reconciled/current store.
    expect(report).not.toContain("has not completed a reconciling refresh");
  });

  it("R4-2: an un-reconciled observe store (rows, no watermark) prints the staleness caveat", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: emptyVerified(),
          observed_destinations: populated([
            { host: "api.telegram.org", port: 443, protocol: "tcp", times_seen: 999, exfil_risk: true },
          ]),
          observed_destinations_pre_idempotency: true,
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // The caveat must state the neutral observable (no completed reconciling
    // refresh) WITHOUT attributing a specific cause (gate HIGH #1: "earlier
    // engine version" would be false in the crash-window case), name the remedy
    // (observe candidates completes the refresh; regenerate), and disclose that
    // the LISTED SET may also be stale, not just the Seen magnitude (gate HIGH
    // #2). The true blocked-only invariant is preserved.
    expect(report).toContain("has not completed a reconciling refresh");
    expect(report).toContain("castle-wall observe candidates");
    expect(report).toContain("regenerate this pack");
    expect(report).toContain("it may still include a destination the engine would clear");
    expect(report).toContain("every listed row is a destination where denied attempts were recorded");
    // Gate run 2 HIGH: the remedy must NOT overclaim that a refresh removes a
    // re-surfaced DISCARDED destination (a discard leaves no allow rule; the
    // recompute replacement path keeps an already-resurfaced discard). Tell the
    // operator to discard the re-surfaced ones again.
    expect(report).toContain("you would need to discard it again");
    expect(report).not.toContain("that a reconciling refresh would remove");
    // Gate run 3 HIGH: the "would clear on refresh" claim must NOT
    // over-generalize to "any destination the policy permits" -- the prune only
    // clears candidateCurrentlyAllowed rows (provenance-scoped, exact-allow),
    // NEVER a macOS "unknown" row. The caveat defers to the Row-basis legend's
    // conditions and calls out the macOS non-clearing case explicitly.
    expect(report).toContain("provenance-scoped conditions described in the Row-basis legend");
    expect(report).toContain("NOT a macOS 'unknown' row, which is never auto-cleared");
    expect(report).not.toContain("a reconciling refresh removes those");
    // Must NOT attribute cause to an "earlier engine version" (false in the
    // crash-interrupted-heal case), and must NOT falsely reassure that only
    // the Seen magnitude is affected.
    expect(report).not.toContain("earlier engine version");
    expect(report).not.toContain("only the Seen magnitude may be high");
    // The row still renders faithfully (the pack never mutates the store).
    expect(report).toContain("api.telegram.org");
    expect(report).toContain("999");
  });

  it("R4-2: the staleness caveat is NOT printed when the pre-idempotency flag is false", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: emptyVerified(),
          observed_destinations: populated([
            { host: "api.telegram.org", port: 443, protocol: "tcp", times_seen: 4, exfil_risk: true },
          ]),
          observed_destinations_pre_idempotency: false,
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).not.toContain("has not completed a reconciling refresh");
  });

  it("MED-1 (sample-render): the tool count carries an active/recorded denominator", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: populated([
            { agent_id: "live-bot", harness: "claude_code", status: "active" },
            { agent_id: "old-bot", harness: "generic_mcp", status: "retired" },
          ]),
          mcp_servers: populated([
            { name: "filesystem", transport: "stdio", enabled: true },
            { name: "legacy", transport: "stdio", enabled: false },
          ]),
          observed_destinations: emptyVerified(),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // 4 recorded (2 agents + 2 servers), 2 active (one agent active, one server enabled).
    expect(report).toContain("AI tools inventoried:** 4 recorded, of which 2 active");
    expect(report).toContain("NOT a count of live tools");
    // The bare "inventoried: 4 (" form is gone.
    expect(report).not.toMatch(/AI tools inventoried:\*\* 4 \(/);
  });

  it("an MCP read FAILURE renders incomplete-with-reason, never an affirmative 'none configured'", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: emptyVerified(),
          mcp_servers: readFailed(
            "the sovereignty profile could not be read: decrypt failed"
          ),
          observed_destinations: emptyVerified(),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).not.toContain("No MCP tool servers are configured on this fortress.");
    expect(report).toContain("could not be read for this period, so this section is INCOMPLETE");
    expect(report).toContain("NOT a statement that none exist");
    expect(report).toContain("decrypt failed");
    // A genuinely-empty (empty_verified) source DOES get the affirmative census line.
    expect(report).toContain("No wrapped AI harnesses are recorded");
    // The exec summary flags the incomplete read (MCP source failed).
    expect(report).toContain("could not be fully determined this period");
  });

  it("the executive summary says 'configured', never 'connected', for MCP servers", () => {
    // R3-5: the definitive census wording requires an explicitly COLLECTED
    // (verified-empty) inventory; an absent inventory renders hedged
    // not-collected language with no census sentence at all.
    const pack = buildEvidencePack(
      { ...baseInput(), inventory: emptyInventorySnapshot() },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("configured AI tool servers");
    expect(report).not.toContain("connected AI tool servers");
  });

  it("MED-1: a failed inventory read never prints 'AI tools inventoried: 0' (routed through the gate)", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        inventory: {
          agents: readFailed("registry read failed"),
          mcp_servers: readFailed("profile read failed"),
          observed_destinations: readFailed("observe read failed"),
        },
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    // No bare definitive zero for a failed read, in any form.
    expect(report).not.toContain("AI tools inventoried:** 0");
    expect(report).not.toContain("AI tools inventoried: 0");
    // Instead: "could not be fully determined", explicitly NOT a zero.
    expect(report).toContain("could not be fully determined this period");
    expect(report).toContain("This is NOT a count of zero.");
  });

  it("MED-1: an all-empty_verified inventory DOES print the definitive gated 0", () => {
    const pack = buildEvidencePack(
      // R3-5: the definitive 0 now requires an EXPLICIT verified-empty
      // inventory (every source actually read, each empty) -- it is no longer
      // the default for an input that supplied no inventory at all.
      { ...baseInput(), inventory: emptyInventorySnapshot() },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("AI tools inventoried:** 0");
    expect(report).toContain("NOT a claim that the firm uses no AI tools");
  });

  it("R3-5: an input with NO inventory renders hedged not-collected language, never a definitive census minted from nothing", () => {
    const pack = buildEvidencePack(baseInput(), deps([]));
    const report = pack.files[0]!.content;
    // No definitive zero census from an inventory nobody collected.
    expect(report).not.toContain("AI tools inventoried:** 0");
    expect(report).not.toContain("No wrapped AI harnesses are recorded");
    expect(report).not.toContain("No MCP tool servers are configured");
    // Hedged instead: could-not-be-determined with the not-collected reason.
    expect(report).toContain("could not be fully determined this period");
    expect(report).toContain("This is NOT a count of zero.");
    expect(report).toContain("not collected");
  });

  it("R3-2: the covered-window line and Scope-and-limits disclose retention-span vs recording-liveness", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const report = pack.files[0]!.content;
    // The section-7 covered-window sentence carries the liveness clause: the
    // window reflects what the retained log SPANS, and does not by itself
    // prove the stack was recording throughout it.
    expect(report).toContain("reflects what the retained audit log spans");
    expect(report).toContain(
      "does not by itself prove the enforcement stack was running and recording"
    );
    // And the mandatory Scope-and-limits page names the class directly.
    expect(report).toContain(
      "A covered window proves retention span, not recording liveness."
    );
    expect(report).toContain(
      "zero recorded decisions in a period does not mean zero AI"
    );
  });

  it("LOW-1: the total bullet is labeled 'audit operations' and splits out non-decision 'other'", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([
        entry("2026-08-01T00:00:00.000Z", "gate_allow:x"),
        entry("2026-08-02T00:00:00.000Z", "identity_create"), // 'other'
      ])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("Total recorded audit operations in the quarter");
    expect(report).not.toContain("Total recorded control-point decisions in the quarter");
    // Splits 2 total into 1 control-point decision + 1 other.
    expect(report).toContain("1 control-point decisions + 1 other recorded operations");
  });

  it("CHOKEPOINT: a read_failed audit source never renders a definitive negative", () => {
    const pack = buildEvidencePack(baseInput(), {
      audit: readFailed("the audit log could not be read: decrypt failed"),
      signer,
      masterKey,
    });
    const report = pack.files[0]!.content;
    // Aggregation + shortfall are read_failed.
    expect(pack.aggregation.status).toBe("read_failed");
    expect(pack.shortfall.status).toBe("read_failed");
    // The manifest coverage is non-determinable - NOT a false "shortfall: false".
    expect(pack.manifest.coverage.determinable).toBe(false);
    // The report asserts NO decision counts and NO full-quarter coverage.
    expect(report).toContain("could NOT be computed");
    expect(report).toContain("decrypt failed");
    expect(report).toContain("COVERAGE UNAVAILABLE");
    // It never claims zero denials or full coverage.
    expect(report).not.toContain("Denied by automated policy (no human) | 0");
    expect(report).not.toMatch(/Covered window attested for this quarter/);
  });

  it("CHOKEPOINT: a custody read_failed renders incomplete, not a definitive fact table", () => {
    const pack = buildEvidencePack(
      { ...baseInput(), custody: readFailed("custody probe failed") },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("The per-install custody facts could not be read");
    expect(report).toContain("custody probe failed");
    // The definitive custody fact table is omitted.
    expect(report).not.toContain("| Master-key custody |");
  });

  it("surfaces an UNCATEGORIZED gate op honestly, never folded into a flattering total", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([
        entry("2026-08-01T00:00:00.000Z", "gate_allow:x"),
        entry("2026-08-02T00:00:00.000Z", "gate_frobnicate:y"), // unknown gate op
      ])
    );
    expect(agg(pack).by_category.uncategorized).toBe(1);
    expect(agg(pack).by_category.allowed).toBe(1);
    expect(agg(pack).by_category.other).toBe(0);
    const report = pack.files[0]!.content;
    expect(report).toContain("Uncategorized control-point operations");
  });

  it("HIGH-2: an un-probed outbound posture renders 'not determinable', NEVER a hardcoded 'yes'", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        custody: populated({
          custody_mode: "unknown",
          outbound_denied_by_default: readFailed("not probed by this build"),
        }),
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("not determinable for this install");
    // The custody row must not assert a definitive "denied by default | yes".
    expect(report).not.toMatch(/outbound denied by default \| yes/i);
  });

  it("HIGH-2: a probed outbound=true scopes the claim to Sanctuary's gateway, not machine-level", () => {
    const pack = buildEvidencePack(
      {
        ...baseInput(),
        custody: populated({
          custody_mode: "passphrase",
          outbound_denied_by_default: populated(true),
        }),
      },
      deps([])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("Sanctuary-gateway outbound denied by default");
    expect(report).toContain("does NOT deny egress from other applications");
  });

  it("HIGH-3: the incident line is 'not assessed', NEVER a flattering 'none surfaced'", () => {
    const pack = buildEvidencePack(baseInput(), deps([]));
    const report = pack.files[0]!.content;
    expect(report).not.toContain("Unresolved incidents:** none");
    expect(report).not.toContain("none surfaced");
    expect(report).toContain("Incidents:** not assessed in this build");
  });

  it("HIGH-4: the cover uses evidence-toward framing, not 'answers, one for one' + 'without trusting the vendor'", () => {
    const pack = buildEvidencePack(baseInput(), deps([]));
    const report = pack.files[0]!.content;
    expect(report).not.toContain("answers, one for one, the five questions");
    expect(report).not.toContain("verify the underlying evidence without trusting");
    expect(report).toContain("organized around the five questions");
    // Placeholder sections are named on the cover.
    expect(report).toContain("governance-policy, training, and incident-response sections are placeholders");
  });

  it("HIGH-4: placeholder CNA subtitles say 'Maps to' + 'NOT included', not 'Answers'", () => {
    const pack = buildEvidencePack(baseInput(), deps([]));
    const report = pack.files[0]!.content;
    expect(report).toContain("Maps to CNA Question 2");
    expect(report).toContain("Maps to CNA Question 5");
    expect(report).not.toContain("Answers CNA Question 2");
    expect(report).not.toContain("Answers CNA Question 5");
  });

  it("round-2 wording: 'vendor-independent' (not 'firm-independent'); data-export is an architecture property", () => {
    const pack = buildEvidencePack(baseInput(), deps([])); // no discrete exports
    const report = pack.files[0]!.content;
    expect(report).not.toContain("firm-independent");
    expect(report).toContain("vendor-independent");
    // Data-export is labeled a product property, not a per-install table value.
    expect(report).toContain("a product property, not a per-install read");
    expect(report).not.toContain("| Data export | requires human (Tier 1) approval |");
  });
});

describe("R2-2: PDF footer digest label", () => {
  it("labels the evidence-pack footer digest 'Report SHA-256' (its digest is the report file, not the manifest)", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const pdfText = Buffer.from(pack.pdf).toString("latin1");
    // The footer digest passed by generate.ts is `reportFile.sha256`, so the
    // label must say so -- the shared PDF builder's default "Manifest SHA-256"
    // (correct only for the EU AI Act bundle) would be a false label here.
    expect(pdfText).toContain("Report SHA-256:");
    expect(pdfText).not.toContain("Manifest SHA-256:");
    // Sanity: the digest shown IS the report file's SHA-256 prefix.
    expect(pdfText).toContain("Report SHA-256: " + pack.files[0]!.sha256.slice(0, 16));
  });
});

describe("dry-bar gate-round: cover enforcement-census caveat (shortfall=false)", () => {
  it("the COVER caveats an excluded daemon store even when operator coverage is FULL (no shortfall)", () => {
    // FULL_COVERAGE => shortfall=false, so none of the coverage banners fire.
    // A present-but-unreadable daemon store must still be disclosed on the cover
    // so a full-coverage quarter is not read as a complete enforcement record.
    const retention: RetentionFacts = {
      ...FULL_COVERAGE,
      daemon_store: {
        status: "present_unreadable",
        included_entry_count: 0,
        unreadable_reason: "privilege",
      },
    };
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], retention)
    );
    expect(pack.shortfall.status).toBe("populated");
    if (pack.shortfall.status === "populated") {
      expect(pack.shortfall.value.shortfall).toBe(false);
    }
    const cover = pack.files[0]!.content;
    expect(cover).toContain("ENFORCEMENT-CENSUS NOTICE");
  });

  it("the COVER caveat describes a MISSING (deleted) daemon store as destruction, never 'present'", () => {
    const retention: RetentionFacts = {
      ...FULL_COVERAGE,
      daemon_store: { status: "missing", included_entry_count: 0 },
    };
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], retention)
    );
    const cover = pack.files[0]!.content.split("---")[0]!; // cover section only
    expect(cover).toContain("ENFORCEMENT-CENSUS NOTICE");
    expect(cover).toMatch(/ABSENT/);
    expect(cover).toMatch(/deleted or renamed|unverifiable/i);
    // Never describes the daemon store itself as "present" on the cover for a
    // missing store, and never over-definitely asserts it "ran and provisioned".
    expect(cover).not.toMatch(/\(_audit-daemon\) is\s+present/i);
    expect(cover).not.toMatch(/ran the audit-store writer split and provisioned/i);
  });

  it("a daemon store that is ABSENT/included adds no cover caveat", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], FULL_COVERAGE)
    );
    expect(pack.files[0]!.content.split("---")[0]).not.toContain(
      "ENFORCEMENT-CENSUS NOTICE"
    );
  });
});

describe("gate round 2: §7 covered-window is operator-scoped when the daemon store is excluded", () => {
  it("scopes the access-log covered-window sentence to the OPERATOR store on an excluded daemon", () => {
    const retention: RetentionFacts = {
      ...FULL_COVERAGE,
      daemon_store: {
        status: "present_unreadable",
        included_entry_count: 0,
        unreadable_reason: "privilege",
      },
    };
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], retention)
    );
    const full = pack.files[0]!.content;
    const accessLog = full.slice(full.indexOf("# Access-log and enforcement summary"));
    // The covered-window sentence itself is scoped, not just the counts note.
    expect(accessLog).toMatch(/retained OPERATOR audit log spans/);
    expect(accessLog).toMatch(/operator-store view, not a complete enforcement census/);
  });

  it("leaves the neutral covered-window wording when the daemon store is absent/included", () => {
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")], FULL_COVERAGE)
    );
    const full = pack.files[0]!.content;
    const accessLog = full.slice(full.indexOf("# Access-log and enforcement summary"));
    expect(accessLog).toMatch(/retained audit log spans/);
    expect(accessLog).not.toMatch(/retained OPERATOR audit log spans/);
  });
});

describe("D5-3: a caller that OMITS discrete_exports never mints definitive §10 negatives", () => {
  it("renders honest 'not gathered' read-failed §10 arms, NOT verified-empty definitives", () => {
    // baseInput() supplies no `discrete_exports`; the generator default must NOT
    // mint empty_verified witnesses (a definitive 'read to completion, zero
    // records' for reads that never happened) -- the R3-5/C4 witness-minting class.
    const pack = buildEvidencePack(
      baseInput(),
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const report = pack.files[0]!.content;
    // The three definitive negatives minted from a NON-read are gone...
    expect(report).not.toContain("emitted no signed transparency checkpoints yet");
    expect(report).not.toContain("the audit-chain export was empty for this fortress");
    expect(report).not.toContain("no public-anchor (Sigstore/Rekor) evidence is available");
    // ...replaced by the honest not-gathered disclosure for each export.
    expect(report).toContain("discrete exports were not gathered by this pack run");
    // And no discrete-export FILE is signed in from a non-read.
    const names = pack.files.map((f) => f.filename);
    expect(names).not.toContain("transparency-bundle.json");
    expect(names).not.toContain("audit-chain.jsonl");
    expect(names).not.toContain("anchor-evidence.json");
  });

  it("an EXPLICIT empty_verified discrete read STILL renders the definitive-empty §10 (a real 'none')", () => {
    // The fix scopes to the NON-read default only; a genuine verified-empty read
    // (a real completed read that found nothing) keeps its definitive wording.
    const input: EvidencePackInput = {
      ...baseInput(),
      discrete_exports: {
        transparency: emptyVerified(),
        audit_chain: emptyVerified(),
        anchor: emptyVerified(),
      },
    };
    const pack = buildEvidencePack(
      input,
      deps([entry("2026-08-01T00:00:00.000Z", "gate_allow:x")])
    );
    const report = pack.files[0]!.content;
    expect(report).toContain("emitted no signed transparency checkpoints yet");
    expect(report).toContain("the audit-chain export was empty for this fortress");
    expect(report).toContain("no public-anchor (Sigstore/Rekor) evidence is available");
  });
});
