import { describe, expect, it, vi } from "vitest";
import { buildReport, renderMarkdownSummary } from "../report.js";
import { registerFixture } from "../registry.js";
import { EXPECTED_ASSURANCE_ROW_COUNT } from "../assurance-matrix.js";

describe.sequential("coverage report", () => {
  it("marks every empty-registry matrix row as no_fixture when no row is not_implemented", async () => {
    const report = await buildReport({ platform: "linux", sha: "test-sha" });

    expect(report.summary.total_rows).toBe(EXPECTED_ASSURANCE_ROW_COUNT);
    expect(report.summary.rows_with_fixtures).toBe(0);
    expect(report.summary.rows_no_fixture).toBe(EXPECTED_ASSURANCE_ROW_COUNT);
    expect(report.summary.rows_not_implemented).toBe(0);
    expect(report.summary.rows_failing).toBe(0);
    expect(report.rows.find((row) => row.assurance_row_id === "9")?.coverage_state).toBe("no_fixture");
    expect(
      report.rows
        .every((row) => row.coverage_state === "no_fixture"),
    ).toBe(true);

    const markdown = renderMarkdownSummary(report);
    expect(markdown).toContain(`Total rows: ${EXPECTED_ASSURANCE_ROW_COUNT}`);
    expect(markdown).toContain(`Rows without fixtures: ${EXPECTED_ASSURANCE_ROW_COUNT}`);
    expect(markdown).toContain("Rows not implemented: 0");
  });

  it("counts fixture outcomes attached to the now-proven Linux row", async () => {
    registerFixture(
      "9",
      "Egress enforcement: Linux (Castle Wall Phase 1)",
      "linux-proven-failure-counted",
      async () => ({
        passed: false,
        message: "should be counted for the proven Linux row",
        durationMs: 1,
      }),
    );

    const report = await buildReport({ platform: "linux", sha: "proven-linux-fixture" });
    const row = report.rows.find((entry) => entry.assurance_row_id === "9");

    expect(row).toBeDefined();
    expect(row?.coverage_state).toBe("partial");
    expect(row?.fixtures_run).toBe(1);
    expect(row?.fixtures_passed).toBe(0);
    expect(row?.fixtures_failed).toBe(1);
    expect(row?.fixtures.map((fixture) => fixture.name)).toEqual(["linux-proven-failure-counted"]);
    expect(report.summary.rows_with_fixtures).toBe(1);
    expect(report.summary.rows_failing).toBe(1);
  });

  it("suppresses fixture outcomes attached to a not_implemented matrix row", async () => {
    vi.resetModules();
    vi.doMock("../assurance-matrix.js", () => ({
      EXPECTED_ASSURANCE_ROW_COUNT: 1,
      loadAssuranceMatrix: () => [
        {
          id: "synthetic-not-implemented",
          label: "Synthetic not implemented row",
          status: "not_implemented" as const,
        },
      ],
    }));

    const { registerFixture: registerMockedFixture } = await import("../registry.js");
    const { buildReport: buildMockedReport } = await import("../report.js");

    registerMockedFixture(
      "synthetic-not-implemented",
      "Synthetic not implemented row",
      "synthetic-not-implemented-failure-suppressed",
      async () => ({
        passed: false,
        message: "should be suppressed while the row is not_implemented",
        durationMs: 1,
      }),
    );

    const report = await buildMockedReport({ platform: "linux", sha: "not-implemented-fixture" });
    const row = report.rows.find((entry) => entry.assurance_row_id === "synthetic-not-implemented");

    expect(row).toBeDefined();
    expect(row?.coverage_state).toBe("not_implemented");
    expect(row?.fixtures).toEqual([]);
    expect(row?.fixtures_run).toBe(0);
    expect(row?.fixtures_failed).toBe(0);
    expect(report.summary.rows_with_fixtures).toBe(0);
    expect(report.summary.rows_not_implemented).toBe(1);
    expect(report.summary.rows_failing).toBe(0);

    vi.doUnmock("../assurance-matrix.js");
    vi.resetModules();
  });
});
