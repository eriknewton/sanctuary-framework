/**
 * Every workflow job that runs the server test suite must first provision the
 * root-owned Node interpreter that the packaged Linux policy signer trusts.
 *
 * The packaged signer (`server/bin/sanctuary-linux-policy-sign`) hands its key
 * descriptor only to a root-owned node at a fixed path, and the suite runs that
 * real entry point. setup-node's tool cache is runner-writable, so a job that
 * skips the provisioning step fails those tests. The step was hand-mirrored into
 * ci.yml and test-baseline-guard.yml and missed in publish-on-tag.yml, which
 * blocked a release. This test parses every workflow as YAML, derives the
 * suite-running jobs from the parsed steps, and requires an executable
 * provisioning command in an earlier step of the same job.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { load as loadYaml } from "js-yaml";

const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const workflowsDir = join(repoRoot, ".github", "workflows");

// Must match the run line of the "Provision the root-owned workstation signer
// interpreter" step in ci.yml, test-baseline-guard.yml and publish-on-tag.yml.
const PROVISION_COMMAND = 'sudo install -o root -g root -m 0755 "$(command -v node)" /usr/bin/node';

// The full suite is npm's `test` script however it is spelled: `npm test`, the
// `t`/`tst` aliases, `npm run test`, `npm run-script test`, with any options
// before it (`npm --prefix server test`). `npm run test:<x>` targets a named
// subset and is not the suite. Over-matching only adds a job to the exact-set
// assertion below, which then fails until the job is reviewed and listed.
const SUITE_COMMAND = /(?:^|[\s;&|(])npm\b[^;&|#]*?\s(?:(?:run|run-script)\s+)?(?:test|tst|t)(?=$|[\s;&|)])/;

type Step = { run?: unknown; if?: unknown };
type Workflow = { jobs?: Record<string, { steps?: Step[] }> };

/** The executable lines of a step's run script: comment and blank lines removed. */
function commandLines(step: Step): string[] {
  if (typeof step.run !== "string") return [];
  return step.run.split("\n").map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"));
}

/** Every suite-running job in one workflow source, with whether it is provisioned in time. */
export function auditWorkflow(source: string): Array<{ job: string; provisioned: boolean }> {
  const workflow = (loadYaml(source) ?? {}) as Workflow;
  const results: Array<{ job: string; provisioned: boolean }> = [];
  for (const [job, body] of Object.entries(workflow.jobs ?? {})) {
    const steps = body?.steps ?? [];
    const suiteAt = steps.findIndex((s) => commandLines(s).some((l) => SUITE_COMMAND.test(l)));
    if (suiteAt < 0) continue;
    // Provisioning counts only as an unconditional step (no `if:`) that runs before the suite step and
    // whose whole executable body is the install command, so it cannot be skipped by a step condition
    // or wrapped in shell control flow that never reaches it.
    const provisioned = steps.slice(0, suiteAt).some((s) => s.if === undefined
      && commandLines(s).length === 1 && commandLines(s)[0] === PROVISION_COMMAND);
    results.push({ job, provisioned });
  }
  return results;
}

const audited = readdirSync(workflowsDir)
  .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
  .flatMap((file) => auditWorkflow(readFileSync(join(workflowsDir, file), "utf8")).map((r) => ({ file, ...r })));

describe("packaged signer interpreter is provisioned before every server suite run", () => {
  it("the suite-running jobs are exactly the known set (a new one must be added here deliberately)", () => {
    expect(audited.map((r) => `${r.file}#${r.job}`).sort()).toEqual([
      "ci.yml#test",
      "publish-on-tag.yml#build-release",
      "test-baseline-guard.yml#test-baseline-guard",
    ]);
  });

  for (const r of audited) {
    it(`${r.file} job ${r.job} runs the provisioning command in a step before the suite`, () => {
      expect(r.provisioned).toBe(true);
    });
  }

  // Negative fixtures: shapes a line scanner would miss or wrongly accept.
  const provision = `      - name: Provision the root-owned workstation signer interpreter\n        run: ${PROVISION_COMMAND}\n`;
  const fixtures: Array<[string, string, boolean]> = [
    ["provisioned before a working-directory suite step", `jobs:\n  t:\n    steps:\n${provision}      - working-directory: server\n        run: npm test\n`, true],
    ["sequence-marker run with no provisioning", `jobs:\n  t:\n    steps:\n      - run: npm test\n        working-directory: server\n`, false],
    ["provisioning commented out", `jobs:\n  t:\n    steps:\n      - name: Provision the root-owned workstation signer interpreter\n        run: |\n          # ${PROVISION_COMMAND}\n          echo skipped\n      - run: npm test\n`, false],
    ["step name kept, install moved after the suite", `jobs:\n  t:\n    steps:\n      - name: Provision the root-owned workstation signer interpreter\n        run: echo placeholder\n      - run: cd server && npm test\n      - run: ${PROVISION_COMMAND}\n`, false],
    ["suite inside a multi-line pipeline", `jobs:\n  t:\n    steps:\n      - run: |\n          set -o pipefail\n          npm test 2>&1 | tee out.log\n`, false],
    ["provisioning step skipped by a step condition", `jobs:\n  t:\n    steps:\n      - if: false\n        run: ${PROVISION_COMMAND}\n      - run: npm test\n`, false],
    ["provisioning wrapped in shell control flow", `jobs:\n  t:\n    steps:\n      - run: |\n          if false; then\n            ${PROVISION_COMMAND}\n          fi\n      - run: npm test\n`, false],
    ["suite run with a prefix option", `jobs:\n  t:\n    steps:\n      - run: npm --prefix server test\n`, false],
    ["suite run through run-script", `jobs:\n  t:\n    steps:\n      - run: npm run-script test\n`, false],
  ];
  for (const [label, source, expected] of fixtures) {
    it(`audit fixture: ${label}`, () => {
      const result = auditWorkflow(source);
      expect(result).toHaveLength(1);
      expect(result[0].provisioned).toBe(expected);
    });
  }

  it("a named subset script is not the suite", () => {
    expect(auditWorkflow(`jobs:\n  t:\n    steps:\n      - run: npm run test:security\n`)).toEqual([]);
  });
});
