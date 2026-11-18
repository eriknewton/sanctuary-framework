// Probe run ONLY as a child by test/structure/git-env-scrub.test.ts. The name
// does not end in .test.ts, so the main suite's include glob never collects it.
// It records every GIT_* name it inherited into PROBE_REPORT, then writes
// `core.bare=true` into the fixture repo named by PROBE_REPO, with cwd set to
// that repo, exactly as a leaky test would; if GIT_DIR or GIT_CONFIG leaked in,
// git writes the redirected repository's config instead. It never asserts on
// what leaked, so the child exits 0 in both controls and the parent judges.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

describe("git-env-scrub probe", () => {
  it("reports inherited git variables and writes core.bare into its own repo", () => {
    const repo = process.env.PROBE_REPO;
    const report = process.env.PROBE_REPORT;
    if (!repo || !report) throw new Error("PROBE_REPO and PROBE_REPORT are required: this file only runs as a child of the structural test");
    // Written before the git call so the parent sees the environment even if git fails.
    writeFileSync(report, JSON.stringify({ git: Object.keys(process.env).filter((k) => k.startsWith("GIT_")).sort() }));
    execFileSync("git", ["config", "core.bare", "true"], { cwd: repo });
  });
});
