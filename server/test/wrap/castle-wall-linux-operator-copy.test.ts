/**
 * Wrap's Linux Castle Wall bring-up tells the operator the wall is DEGRADED
 * whenever the activation's completeness is anything other than `full`, and its
 * degraded copy never doubles as a claim that traffic is being filtered.
 *
 * The branch lives in a closure inside `runWrap` with no exported seam, and
 * exporting one to reach it would be a production change made for a test, so
 * this pins the gate at the source instead of driving it. The behavioural twin
 * for the sibling `castle-wall daemon` verb, which does have a callable
 * entrypoint, is in `server/test/cli/castle-wall.test.ts`.
 * Register: `ic-sweep-linux-enforcement-actually-enforces`.
 */
import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";

describe("wrap Linux Castle Wall operator copy", () => {
  async function linuxBringUpSource(): Promise<string> {
    const source = await readFile(
      new URL("../../src/wrap/cli.ts", import.meta.url),
      "utf8",
    );
    const start = source.indexOf("const startCastleWallForWrap");
    expect(start).toBeGreaterThan(-1);
    const end = source.indexOf("startMacOSCastleWallDaemon", start);
    expect(end).toBeGreaterThan(start);
    return source.slice(start, end);
  }

  it("gates the operator warning on the completeness, not on the activation having returned", async () => {
    const branch = await linuxBringUpSource();
    expect(branch).toContain('const completeness = outcome.activation.activationCompleteness()');
    expect(branch).toContain('if (completeness !== "full")');
  });

  it("says DEGRADED on both non-full completeness values and claims filtering on neither", async () => {
    const branch = await linuxBringUpSource();
    const warning = branch.slice(branch.indexOf('if (completeness !== "full")'));
    // Both shortfalls are named, and they carry different copy: the ACK
    // shortfall leaves the kernel runtime proven, absent kernel evidence does
    // not, so one sentence covering both would overclaim for the weaker case.
    expect(warning).toContain('completeness === "unconfirmed_audit_ack"');
    expect(warning).toContain("does not confirm audit ACKs");
    expect(warning).toContain("no current proof of a live");
    // Two branches of the ternary, each saying DEGRADED.
    expect(warning.match(/Castle Wall is DEGRADED/g) ?? []).toHaveLength(2);
    // The degraded copy must never read as an enforcement claim.
    expect(warning).not.toMatch(/ACTIVE|is filtering|traffic is being filtered/);
  });
});
