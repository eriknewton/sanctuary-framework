import { describe, expect, it } from "vitest";
import { buildReport, renderMarkdownSummary } from "../report.js";
import { registerFixture } from "../registry.js";

describe.sequential("coverage report", () => {
  it("marks every current in-flight/proven row without a fixture as no_fixture", async () => {
    const report = await buildReport({ platform: "linux", sha: "test-sha" });

    expect(report.summary.total_rows).toBe(23);
    expect(report.summary.rows_with_fixtures).toBe(0);
    expect(report.summary.rows_no_fixture).toBe(23);
    expect(report.summary.rows_not_implemented).toBe(0);
    expect(report.summary.rows_failing).toBe(0);
    expect(report.rows.find((row) => row.assurance_row_id === "9")?.coverage_state).toBe(
      "no_fixture",
    );
    expect(
      report.rows
        .every((row) => row.coverage_state === "no_fixture"),
    ).toBe(true);

    const markdown = renderMarkdownSummary(report);
    expect(markdown).toContain("Total rows: 23");
    expect(markdown).toContain("Rows without fixtures: 23");
    expect(markdown).toContain("Rows not implemented: 0");
  });

  it("runs and reports a failing fixture attached to the in-flight Linux row", async () => {
    registerFixture(
      "9",
      "Egress enforcement: Linux (Castle Wall Phase 1)",
      "in-flight-reported-failure",
      async () => ({
        passed: false,
        message: "in-flight rows must not suppress their fixture evidence",
        durationMs: 1,
      }),
    );

    const report = await buildReport({ platform: "linux", sha: "not-implemented-fixture" });
    const row = report.rows.find((entry) => entry.assurance_row_id === "9");

    expect(row).toBeDefined();
    expect(row?.coverage_state).toBe("partial");
    expect(row?.fixtures_run).toBe(1);
    expect(row?.fixtures_passed).toBe(0);
    expect(row?.fixtures_failed).toBe(1);
    expect(row?.fixtures).toHaveLength(1);
    expect(report.summary.rows_with_fixtures).toBe(1);
    expect(report.summary.rows_failing).toBe(1);
  });
});
