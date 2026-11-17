// Probe run ONLY as a child by test/structure/git-env-scrub.test.ts. The name
// does not end in .test.ts, so the main suite's include glob never collects it.
// It writes `core.bare=true` into the fixture repo named by PROBE_REPO, with
// cwd set to that repo, exactly as a leaky test would; if GIT_DIR leaked in,
// git writes the real (redirected) repository's config instead.
import { execFileSync } from "node:child_process";

describe("git-env-scrub probe", () => {
  it("writes core.bare into its own repo", () => {
    const repo = process.env.PROBE_REPO;
    if (!repo) throw new Error("PROBE_REPO is required: this file only runs as a child of the structural test");
    execFileSync("git", ["config", "core.bare", "true"], { cwd: repo });
  });
});
