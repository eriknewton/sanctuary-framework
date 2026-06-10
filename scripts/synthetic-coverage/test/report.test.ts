import { describe, expect, it } from "vitest";
import { buildReport, renderMarkdownSummary } from "../report.js";

describe("coverage report", () => {
  it("marks every matrix row as no_fixture with an empty registry", async () => {
    const report = await buildReport({ platform: "linux", sha: "test-sha" });

    expect(report.summary.total_rows).toBe(21);
    expect(report.summary.rows_with_fixtures).toBe(0);
    expect(report.summary.rows_no_fixture).toBe(21);
    expect(report.summary.rows_failing).toBe(0);
    expect(report.rows.every((row) => row.coverage_state === "no_fixture")).toBe(true);

    const markdown = renderMarkdownSummary(report);
    expect(markdown).toContain("Total rows: 21");
    expect(markdown).toContain("Rows without fixtures: 21");
  });
});
