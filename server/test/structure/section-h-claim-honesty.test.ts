import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

describe("Section-H enforcement claim hygiene", () => {
  it("keeps approval aggregator audit op names in a side-effect-free catalog", () => {
    const ops = read("server/src/principal-policy/approval-aggregator-ops.ts");
    const aggregator = read("server/src/principal-policy/approval-aggregator.ts");

    expect(ops).toContain("export const APPROVAL_AGGREGATOR_AUDIT_OPS");
    expect(ops).toContain('RESOLVED: "cross_harness_approval_resolved"');
    expect(aggregator).toContain(
      'import { APPROVAL_AGGREGATOR_AUDIT_OPS } from "./approval-aggregator-ops.js";'
    );
    expect(aggregator).toContain(
      'export { APPROVAL_AGGREGATOR_AUDIT_OPS } from "./approval-aggregator-ops.js";'
    );
  });

  it("does not let the evidence pack privately retype the aggregator resolved op", () => {
    const aggregate = read("server/src/evidence-pack/aggregate.ts");

    expect(aggregate).toContain(
      'import { APPROVAL_AGGREGATOR_AUDIT_OPS } from "../principal-policy/approval-aggregator-ops.js";'
    );
    expect(aggregate).toContain("APPROVAL_AGGREGATOR_AUDIT_OPS.RESOLVED");
    expect(aggregate).not.toContain(
      'const CROSS_HARNESS_APPROVAL_RESOLVED = "cross_harness_approval_resolved";'
    );
    expect(aggregate).not.toContain(
      "Kept in lockstep with `APPROVAL_AGGREGATOR_AUDIT_OPS.RESOLVED`"
    );
  });

  it("does not overstate hub or supervisor enforcement coverage", () => {
    const hubRouter = read("server/src/hub/api-router.ts");
    const supervisor = read("server/src/supervisor/supervisor.ts");

    expect(hubRouter).not.toContain("auth gate cannot drift");
    expect(supervisor).not.toContain("concurrent-duplicate-fails");
  });
});
