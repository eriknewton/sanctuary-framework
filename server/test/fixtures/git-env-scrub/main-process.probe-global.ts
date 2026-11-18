// globalSetup probe run ONLY in the child vitest of
// test/structure/git-env-scrub.test.ts, listed AFTER the scrub entry. It
// records every GIT_* name the vitest MAIN process still holds into
// PROBE_MAIN_REPORT, which is what shows the scrub's globalSetup entry ran
// first (setup files reach workers only). Never collected by the main suite:
// its name does not end in .test.ts.
import { writeFileSync } from "node:fs";

export default function probeMainProcess(): void {
  const report = process.env.PROBE_MAIN_REPORT;
  if (!report) throw new Error("PROBE_MAIN_REPORT is required: this file only runs as a child globalSetup of the structural test");
  writeFileSync(report, JSON.stringify({ git: Object.keys(process.env).filter((k) => k.startsWith("GIT_")).sort() }));
}
