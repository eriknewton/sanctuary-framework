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

  it("classifies sanctuary anomaly subscribe as mutator without audit", () => {
    const entries = loadInventory();
    const sub = entries.find(
      (e) => e.subcommand === "sanctuary anomaly subscribe",
    );
    expect(sub).toBeDefined();
    expect(sub!.classification).toBe("mutator");
    expect(sub!.audits_currently).toBe(false);
  });

  it("has no uncertain/unclassified entries", () => {
    const entries = loadInventory();
    const uncertain = entries.filter((e) => e.notes.includes("review needed"));
    expect(uncertain).toHaveLength(0);
  });

  it("mutator-no-audit gap count is below 20", () => {
    const entries = loadInventory();
    const gaps = entries.filter(
      (e) => e.classification === "mutator" && e.audits_currently === false,
    );
    expect(gaps.length).toBeLessThan(20);
    expect(gaps.length).toBeGreaterThan(0); // We know gaps exist
  });
});
