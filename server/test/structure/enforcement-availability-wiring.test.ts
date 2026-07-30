import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function source(path: string): string {
  return readFileSync(join(REPO_ROOT, path), "utf8");
}

describe("enforcement availability status wiring", () => {
  it("threads the local enforcement_unavailable resolver through every dashboard/wrap construction site", () => {
    const wrapCli = source("server/src/wrap/cli.ts");
    const dashboardApi = source("server/src/dashboard/api.ts");
    const dashboardIndex = source("server/src/dashboard/index.ts");

    expect(wrapCli).toContain("readEnforcementAvailabilityStatus(storagePath)");
    expect(wrapCli).toContain("resolveEnforcementAvailabilityStatus: () =>");
    expect(wrapCli).toContain("resolveEnforcementAvailabilityStatus: async () =>");
    expect(dashboardApi).toContain(
      "resolveEnforcementAvailabilityStatus:\n          deps.sources.resolveEnforcementAvailabilityStatus",
    );
    expect(dashboardIndex).toContain(
      "resolveEnforcementAvailabilityStatus:\n            options.resolveEnforcementAvailabilityStatus",
    );
  });
});
