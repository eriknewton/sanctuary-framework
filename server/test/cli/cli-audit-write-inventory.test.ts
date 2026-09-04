/**
 * Tests for the CLI audit-write completeness inventory script.
 *
 * ZZZZZ batch 5a.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const OUTPUT_PATH = resolve(
  import.meta.dirname,
  "..",
  "..",
  "scripts",
  "cli-audit-write-inventory.output.json",
);

interface InventoryEntry {
  subcommand: string;
  file_path: string;
  line_number: number;
  classification: "mutator" | "read-only" | "pure-ui";
  audits_currently: boolean | null;
  notes: string;
}

function loadInventory(): InventoryEntry[] {
  const raw = readFileSync(OUTPUT_PATH, "utf-8");
  return JSON.parse(raw) as InventoryEntry[];
}

describe("CLI audit-write inventory", () => {
  it("output JSON is valid and matches expected shape", () => {
    const entries = loadInventory();
    expect(Array.isArray(entries)).toBe(true);
    expect(entries.length).toBeGreaterThan(0);

    for (const entry of entries) {
      expect(typeof entry.subcommand).toBe("string");
      expect(entry.subcommand.startsWith("sanctuary ")).toBe(true);
      expect(typeof entry.file_path).toBe("string");
      expect(typeof entry.line_number).toBe("number");
      expect(["mutator", "read-only", "pure-ui"]).toContain(entry.classification);
      expect([true, false, null]).toContain(entry.audits_currently);
      expect(typeof entry.notes).toBe("string");
    }
  });

  it("classifies sanctuary identity show as read-only", () => {
    const entries = loadInventory();
    const identityShow = entries.find(
      (e) => e.subcommand === "sanctuary identity show",
    );
    expect(identityShow).toBeDefined();
    expect(identityShow!.classification).toBe("read-only");
    expect(identityShow!.audits_currently).toBeNull();
  });

  it("classifies sanctuary task create as mutator", () => {
    const entries = loadInventory();
    const taskCreate = entries.find(
      (e) => e.subcommand === "sanctuary task create",
    );
    expect(taskCreate).toBeDefined();
    expect(taskCreate!.classification).toBe("mutator");
  });

  it("classifies sanctuary did-web rotate-key as mutator with audit", () => {
    const entries = loadInventory();
    const rotateKey = entries.find(
      (e) => e.subcommand === "sanctuary did-web rotate-key",
    );
    expect(rotateKey).toBeDefined();
    expect(rotateKey!.classification).toBe("mutator");
    expect(rotateKey!.audits_currently).toBe(true);
  });

  it("classifies sanctuary file-grant list as a mutator, not read-only (R3-2: reconcile side effect)", () => {
    const entries = loadInventory();
    const fileGrantList = entries.find(
      (e) => e.subcommand === "sanctuary file-grant list",
    );
    expect(fileGrantList).toBeDefined();
    // cmdList calls reconcileFileGrantTree before listing, which can scrub
    // expired tree entries, flip expired status, and emit
    // file_grant_revoke/expired_ttl_scrub audits -- a safe-direction mutator
    // side effect, not a pure read. Pin this so the classification cannot
    // silently regress back to "read-only".
    expect(fileGrantList!.classification).toBe("mutator");
    expect(fileGrantList!.audits_currently).toBe(true);
  });

  it("classifies sanctuary file-grant mint and revoke as mutators with audit", () => {
    const entries = loadInventory();
    for (const sub of ["sanctuary file-grant mint", "sanctuary file-grant revoke"]) {
      const entry = entries.find((e) => e.subcommand === sub);
      expect(entry, sub).toBeDefined();
      expect(entry!.classification, sub).toBe("mutator");
      expect(entry!.audits_currently, sub).toBe(true);
    }
  });

  it("classifies sanctuary anomaly subscribe as mutator with audit (ZZZZZ batch 5b closed)", () => {
    const entries = loadInventory();
    const sub = entries.find(
      (e) => e.subcommand === "sanctuary anomaly subscribe",
    );
    expect(sub).toBeDefined();
    expect(sub!.classification).toBe("mutator");
    expect(sub!.audits_currently).toBe(true);
  });

  it("has no uncertain/unclassified entries", () => {
    const entries = loadInventory();
    const uncertain = entries.filter((e) => e.notes.includes("review needed"));
    expect(uncertain).toHaveLength(0);
  });

  // Confirmed, deliberately-recorded mutator-without-audit gaps: the
  // generator classified these honestly (auditOverride: false) rather than
  // hiding them as read-only or leaving them "review needed". This is the
  // register's expected/allowlist mechanism for such gaps -- a bidirectional
  // pin, not a one-way suppression:
  //   - a NEW gap not on this list fails the first assertion below, so it
  //     surfaces immediately instead of silently passing;
  //   - a listed gap that gets its audit call added must be removed here,
  //     so the register cannot go stale-positive and keep claiming an open
  //     gap that was actually closed.
  // "sanctuary identity create" (src/cli/identity.ts cmdCreate ->
  // IdentityManager.saveNew -> save(), src/cognitive/tools.ts): mints and
  // persists a new Ed25519 operator identity with no AuditLog call anywhere
  // in that path. Fixing it (adding an audit-log entry for identity
  // creation) is a source change, tracked separately -- out of scope for
  // this inventory/test change.
  const KNOWN_AUDIT_GAPS = ["sanctuary identity create"];

  it("mutators without audit are exactly the known/tracked gap set", () => {
    const entries = loadInventory();
    const gaps = entries.filter(
      (e) => e.classification === "mutator" && e.audits_currently === false,
    );
    const gapNames = gaps.map((e) => e.subcommand).sort();
    // No UNTRACKED gap: every mutator-without-audit entry must be one this
    // register already names, not a new one slipping through unnoticed.
    expect(gapNames).toEqual([...KNOWN_AUDIT_GAPS].sort());
    // No STALE entry: every name on the known list must still actually be
    // a gap, so a fix lands here in the same change that closes it.
    for (const name of KNOWN_AUDIT_GAPS) {
      const entry = entries.find((e) => e.subcommand === name);
      expect(entry, name).toBeDefined();
      expect(entry!.classification, name).toBe("mutator");
      expect(entry!.audits_currently, name).toBe(false);
    }
  });

  it("routes policy changes, egress denials, and identity exports through appendCritical", () => {
    const contextGateTools = readFileSync(
      resolve(import.meta.dirname, "..", "..", "src", "operational", "context-gate-tools.ts"),
      "utf-8",
    );
    const sanctuaryTools = readFileSync(
      resolve(import.meta.dirname, "..", "..", "src", "sanctuary-tools.ts"),
      "utf-8",
    );

    for (const operation of ["context_gate_set_policy", "context_gate_deny"]) {
      expect(contextGateTools).toMatch(
        new RegExp(`appendCritical\\(\\{[\\s\\S]*operation: "${operation}"`),
      );
      expect(contextGateTools).not.toMatch(
        new RegExp(`append\\("l2", "${operation}"`),
      );
    }
    expect(sanctuaryTools).toMatch(
      /appendCritical\(\{[\s\S]*operation: "sanctuary_export_identity_bundle"/,
    );
    expect(sanctuaryTools).not.toMatch(
      /append\("l1", "sanctuary_export_identity_bundle"/,
    );
  });
});
