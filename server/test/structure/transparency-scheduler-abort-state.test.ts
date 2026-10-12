import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function readSource(relativePath: string): string {
  return readFileSync(join(REPO_ROOT, relativePath), "utf8");
}

describe("transparency scheduler abort state wiring", () => {
  it("the daemon scheduled path never substitutes the foreground-only abort constant", () => {
    const daemon = readSource("server/src/cli/castle-wall.ts");
    const scheduledFactory = daemon.slice(
      daemon.indexOf("createTransparencyDaemonScheduledEmit"),
      daemon.indexOf("export async function runProvisionPin"),
    );

    expect(daemon).not.toContain("TRANSPARENCY_NEVER_ABORTED");
    expect(daemon).toContain(
      "const scheduledEmit = createTransparencyDaemonScheduledEmit({",
    );
    expect(scheduledFactory).toContain("abortState.assertNotAborted");
    expect(scheduledFactory).toContain("abortState,");
  });
});
