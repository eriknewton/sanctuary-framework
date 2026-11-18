// globalSetup probe run ONLY in the child vitest of
// test/structure/git-env-scrub.test.ts, appended AFTER the real globalSetup
// list. It records every GIT_* name the vitest MAIN process still holds into
// PROBE_MAIN_REPORT, which is what shows the scrub's globalSetup entry ran
// first (setup files reach workers only), plus whether the parent-assigned
// marker token (PROBE_TOKEN_PATH) exists while the run is live. Never collected by the main suite:
// its name does not end in .test.ts.
import { existsSync, writeFileSync } from "node:fs";

export default function probeMainProcess(): void {
  const report = process.env.PROBE_MAIN_REPORT;
  if (!report) throw new Error("PROBE_MAIN_REPORT is required: this file only runs as a child globalSetup of the structural test");
  const token = process.env.PROBE_TOKEN_PATH;
  writeFileSync(report, JSON.stringify({
    git: Object.keys(process.env).filter((k) => k.startsWith("GIT_")).sort(),
    // Runs after test-run-marker's setup callback, so the assigned token must exist now.
    tokenPresent: token !== undefined && existsSync(token),
  }));
}
