/**
 * Every workflow job that runs the server test suite must first provision the
 * root-owned Node interpreter that the packaged Linux policy signer trusts.
 *
 * The packaged signer (`server/bin/sanctuary-linux-policy-sign`) hands its key
 * descriptor only to a root-owned node at a fixed path, and the suite runs that
 * real entry point. setup-node's tool cache is runner-writable, so a job that
 * skips the provisioning step fails those tests. The step was hand-mirrored into
 * ci.yml and test-baseline-guard.yml and missed in publish-on-tag.yml, which
 * blocked a release; this test derives the job set from the workflow files
 * themselves so a new suite-running job cannot be missed.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const workflowsDir = join(repoRoot, ".github", "workflows");

// Must match the step name in ci.yml, test-baseline-guard.yml and publish-on-tag.yml.
const PROVISION_STEP = "name: Provision the root-owned workstation signer interpreter";
const PROVISION_COMMAND = 'sudo install -o root -g root -m 0755 "$(command -v node)" /usr/bin/node';

/** Splits a workflow into its jobs (two-space-indented keys under `jobs:`). */
function jobsOf(source: string): Array<{ name: string; body: string }> {
  const start = source.indexOf("\njobs:\n");
  if (start < 0) return [];
  const lines = source.slice(start + "\njobs:\n".length).split("\n");
  const jobs: Array<{ name: string; body: string[] }> = [];
  for (const line of lines) {
    const header = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (header) { jobs.push({ name: header[1], body: [] }); continue; }
    if (/^\S/.test(line)) break;
    jobs[jobs.length - 1]?.body.push(line);
  }
  return jobs.map((j) => ({ name: j.name, body: j.body.join("\n") }));
}

// A non-comment line whose command is `npm test` (bare, after `run:`, or after `cd server &&`).
const NPM_TEST_COMMAND = /^\s*(?:run:\s*)?(?:cd server &&\s*)?npm test(?:\s|$)/m;

/** True when the job runs the server suite. */
function runsServerSuite(body: string): boolean {
  return NPM_TEST_COMMAND.test(body);
}

const suiteJobs = readdirSync(workflowsDir)
  .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
  .flatMap((file) => jobsOf(readFileSync(join(workflowsDir, file), "utf8"))
    .filter((job) => runsServerSuite(job.body))
    .map((job) => ({ file, ...job })));

describe("packaged signer interpreter is provisioned before every server suite run", () => {
  it("finds the suite-running jobs (non-vacuous)", () => {
    const files = new Set(suiteJobs.map((j) => j.file));
    for (const f of ["ci.yml", "test-baseline-guard.yml", "publish-on-tag.yml"]) expect(files.has(f), f).toBe(true);
  });
  for (const job of suiteJobs) {
    it(`${job.file} job ${job.name} provisions the root-owned node before npm test`, () => {
      const provision = job.body.indexOf(PROVISION_STEP);
      expect(provision, "provisioning step missing").toBeGreaterThanOrEqual(0);
      expect(job.body.slice(provision)).toContain(PROVISION_COMMAND);
      expect(provision).toBeLessThan(job.body.search(NPM_TEST_COMMAND));
    });
  }
});
