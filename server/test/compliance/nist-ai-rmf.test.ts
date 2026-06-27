/**
 * NIST AI RMF crosswalk tests
 *
 * Covers:
 *   - CLI arg parsing via runCompliance / runNistAiRmf (help, unknown
 *     flag, stdout vs --output file).
 *   - Crosswalk internal consistency: every evidence_emitter exists in
 *     the SHARED control catalog (the EU AI Act matrix's emitter set);
 *     no row is mis-shaped; covered/partial rows have emitters; n/a rows
 *     do not; counts add up.
 *   - Rendered-output key assertions (preamble disclaimer, per-function
 *     tables, honest "not-applicable (organizational)" labelling).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { runCompliance } from "../../src/compliance/eu_ai_act/cli.js";
import {
  NIST_CROSSWALK_V1,
  coverageStats,
  allEvidenceEmitters as nistEmitters,
  subcategoriesByCoverage,
} from "../../src/compliance/nist_ai_rmf/crosswalk.js";
import { renderNistCrosswalk } from "../../src/compliance/nist_ai_rmf/generator.js";
import {
  COVERAGE_MATRIX_V1,
  allEvidenceEmitters as euEmitters,
} from "../../src/compliance/eu_ai_act/coverage_matrix.js";

const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
  throw new Error(`process.exit(${code})`);
}) as typeof process.exit);

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    mkdir: vi.fn(async () => undefined),
    writeFile: vi.fn(async () => undefined),
  };
});

describe("NIST AI RMF crosswalk, data integrity", () => {
  it("every row has a well-formed id, function, category, and coverage", () => {
    const fns = new Set(["GOVERN", "MAP", "MEASURE", "MANAGE"]);
    const flags = new Set(["covered", "partial", "not-applicable", "gap"]);
    for (const row of NIST_CROSSWALK_V1.subcategories) {
      expect(row.id).toMatch(/^(GOVERN|MAP|MEASURE|MANAGE) \d+\.\d+$/);
      expect(fns.has(row.function)).toBe(true);
      expect(row.id.startsWith(row.function)).toBe(true);
      expect(flags.has(row.coverage)).toBe(true);
      expect(row.summary.length).toBeGreaterThan(0);
      expect(row.evidence_note.length).toBeGreaterThan(0);
      expect(row.review_notes.length).toBeGreaterThan(0);
    }
  });

  it("row ids are unique", () => {
    const ids = NIST_CROSSWALK_V1.subcategories.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("coverage counts add up to the total", () => {
    const s = coverageStats(NIST_CROSSWALK_V1);
    expect(s.covered).toBe(0);
    expect(s.partial).toBe(27);
    expect(s.not_applicable).toBe(25);
    expect(s.gap).toBe(3);
    expect(s.covered + s.partial + s.not_applicable + s.gap).toBe(s.total);
    expect(s.total).toBe(NIST_CROSSWALK_V1.subcategories.length);
  });

  it("covered and partial rows name at least one Sanctuary control", () => {
    for (const row of NIST_CROSSWALK_V1.subcategories) {
      if (row.coverage === "covered" || row.coverage === "partial") {
        expect(row.evidence_emitter.length).toBeGreaterThan(0);
      }
    }
  });

  it("not-applicable (organizational) rows name no control", () => {
    for (const row of subcategoriesByCoverage(NIST_CROSSWALK_V1, "not-applicable")) {
      expect(row.evidence_emitter).toEqual([]);
    }
  });

  it("gap rows ship no control (honest holes)", () => {
    for (const row of subcategoriesByCoverage(NIST_CROSSWALK_V1, "gap")) {
      expect(row.evidence_emitter).toEqual([]);
    }
  });

  it("no row is both covered and a gap (mutually exclusive flags)", () => {
    const covered = new Set(
      subcategoriesByCoverage(NIST_CROSSWALK_V1, "covered").map((s) => s.id)
    );
    const gap = subcategoriesByCoverage(NIST_CROSSWALK_V1, "gap").map((s) => s.id);
    for (const id of gap) expect(covered.has(id)).toBe(false);
  });
});

describe("NIST AI RMF crosswalk, shared control catalog", () => {
  it("every NIST evidence_emitter is also an EU AI Act matrix emitter", () => {
    const euCatalog = new Set(euEmitters(COVERAGE_MATRIX_V1));
    const nist = nistEmitters(NIST_CROSSWALK_V1);
    expect(nist.length).toBeGreaterThan(0);
    for (const tool of nist) {
      expect(
        euCatalog.has(tool),
        `NIST emitter "${tool}" is not in the shared (EU AI Act) control catalog`
      ).toBe(true);
    }
  });

  it("the strong EU<->NIST security overlap is present (MEASURE 2.7)", () => {
    const m27 = NIST_CROSSWALK_V1.subcategories.find((s) => s.id === "MEASURE 2.7");
    expect(m27).toBeDefined();
    expect(m27!.coverage).toBe("partial");
    // sovereignty_audit + principal_policy_view are real runtime
    // cybersecurity controls; the broader NIST poisoning/model scope
    // keeps this row partial.
    expect(m27!.evidence_emitter).toContain("sovereignty_audit");
    expect(m27!.evidence_emitter).toContain("principal_policy_view");
  });
});

describe("NIST AI RMF crosswalk, rendered output", () => {
  const md = renderNistCrosswalk(NIST_CROSSWALK_V1);

  it("renders the tooling-coverage-map disclaimer in the preamble", () => {
    expect(md).toContain("tooling-coverage map, not a certification");
    expect(md).toContain("NOT a NIST conformity assessment");
  });

  it("renders a coverage summary table", () => {
    expect(md).toContain("## Coverage summary");
    expect(md).toContain("| covered |");
    expect(md).toContain("| gap |");
  });

  it("renders one table per AI RMF function", () => {
    for (const fn of ["GOVERN", "MAP", "MEASURE", "MANAGE"]) {
      expect(md).toContain(`## ${fn}`);
    }
  });

  it("labels not-applicable rows as organizational, never as covered", () => {
    expect(md).toContain("not-applicable (organizational)");
    // A known organizational row must not be rendered as covered.
    const governLine = md
      .split("\n")
      .find((l) => l.startsWith("| GOVERN 2.1 "));
    expect(governLine).toBeDefined();
    expect(governLine).toContain("not-applicable (organizational)");
  });

  it("renders control tool names in backticks for evidence rows", () => {
    expect(md).toContain("`sovereignty_audit`");
    expect(md).toContain("`monitor_audit_log`");
  });
});

describe("NIST AI RMF crosswalk, CLI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("prints help on `compliance nist-ai-rmf --help`", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await expect(runCompliance(["nist-ai-rmf", "--help"])).rejects.toThrow(
      "process.exit(0)"
    );
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("NIST AI RMF 1.0 Crosswalk");
    logSpy.mockRestore();
  });

  it("prints the crosswalk Markdown to stdout when no --output is given", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCompliance(["nist-ai-rmf"]);
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("# NIST AI RMF 1.0, Sanctuary Tooling-Coverage Crosswalk");
    expect(out).toContain("## MEASURE");
    logSpy.mockRestore();
  });

  it("writes to a file and reports honest counts when --output is given", async () => {
    const { writeFile, mkdir } = await import("node:fs/promises");
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const outputPath = "nist-crosswalk.md";
    await runCompliance(["nist-ai-rmf", "--output", outputPath]);
    expect(mkdir).toHaveBeenCalled();
    expect(writeFile).toHaveBeenCalledWith(
      outputPath,
      expect.stringContaining("NIST AI RMF"),
      "utf-8"
    );
    const err = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(err).toContain("covered:");
    expect(err).toContain("NOT a certification");
    errSpy.mockRestore();
  });

  it("exits with error on an unknown flag", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(
      runCompliance(["nist-ai-rmf", "--bogus"])
    ).rejects.toThrow("process.exit(2)");
    errSpy.mockRestore();
  });
});
