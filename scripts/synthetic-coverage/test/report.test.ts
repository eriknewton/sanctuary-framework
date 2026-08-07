import { describe, expect, it } from "vitest";
import { buildReport, renderMarkdownSummary } from "../report.js";

describe("coverage report", () => {
  it("marks empty-registry matrix rows as no_fixture except not_implemented rows", async () => {
    const report = await buildReport({ platform: "linux", sha: "test-sha" });

    expect(report.summary.total_rows).toBe(22);
    expect(report.summary.rows_with_fixtures).toBe(0);
    expect(report.summary.rows_no_fixture).toBe(21);
    expect(report.summary.rows_not_implemented).toBe(1);
    expect(report.summary.rows_failing).toBe(0);
    expect(report.rows.find((row) => row.assurance_row_id === "9")?.coverage_state).toBe(
      "not_implemented",
    );
    expect(
      report.rows
        .filter((row) => row.assurance_row_id !== "9")
        .every((row) => row.coverage_state === "no_fixture"),
    ).toBe(true);

    const markdown = renderMarkdownSummary(report);
    expect(markdown).toContain("Total rows: 22");
    expect(markdown).toContain("Rows without fixtures: 21");
    expect(markdown).toContain("Rows not implemented: 1");
  });
});
