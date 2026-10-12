import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function readSource(relativePath: string): string {
  return readFileSync(join(REPO_ROOT, relativePath), "utf8");
}

describe("transparency scheduler abort state wiring", () => {
  it("uses an ES private runtime brand for abort-state checks", () => {
    const scheduler = readSource("server/src/transparency/scheduler.ts");

    expect(scheduler).toContain("export class TransparencySchedulerAbortState");
    expect(scheduler).toContain("#brand in value");
    expect(scheduler).toContain("static assertNotAborted(");
    expect(scheduler).not.toContain("static create(");
    expect(scheduler).toContain("Object.freeze(TransparencySchedulerAbortState)");
  });

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
    expect(daemon).toContain("emit: scheduledEmit,");
    expect(
      [
        ...scheduledFactory.matchAll(
          /(?:resolveTransparencySigner|emitEnforcementCheckpoint|readAnchorConfig|anchorCheckpoint)\(\{[\s\S]*?\n\s+abortState,\n/g,
        ),
      ],
    ).toHaveLength(4);
    expect(scheduledFactory).not.toMatch(/\.\.\.\s*abortState\b/);
    expect(scheduledFactory).not.toMatch(/\babortState\s+as\b/);
    expect(scheduledFactory).not.toMatch(/\bas\s+[^;\n]*TransparencySchedulerAbortState\b/);
  });
});
