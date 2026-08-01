/**
 * Custody-normalize chokepoint tail of the protect flow (fortress-ownership
 * spec 2026-07-30 §4(a2)(1)): `runAutoProvisionForWrap` finishes EVERY
 * post-identity outcome through `finishProvisionOutcomeWithCustodyNormalize`,
 * which is exercised here directly (the full provisioning flow is root-only
 * -- /var/run lock, dscl, launchd -- so the tail is exported for the unit
 * suite; reachability of the tail is the single return statement of the
 * production flow).
 */
import { describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { finishProvisionOutcomeWithCustodyNormalize } from "../../src/wrap/auto-provision.js";
import type { NormalizeFortressCustodyInput } from "../../src/castle-wall/provision/fortress-custody.js";

const UNVERIFIED_NO_CHANNEL = {
  kind: "cos_liveness_unverified" as const,
  reason: "no_channel_configured" as const,
};

describe("finishProvisionOutcomeWithCustodyNormalize", () => {
  it("normalizes with the resolved operator and returns the summary for a success outcome", async () => {
    const calls: { fortressPath: string; operator: { uid: number; gid: number } }[] = [];
    const summary = await finishProvisionOutcomeWithCustodyNormalize({
      outcome: { kind: "armed", uid: { value: 550, observedVia: "test" } as never, liveness: UNVERIFIED_NO_CHANNEL },
      wallFortressPath: "/Users/operator/.sanctuary",
      operator: { uid: 501, gid: 20 },
      print: () => undefined,
      normalize: async (input: NormalizeFortressCustodyInput) => {
        calls.push({ fortressPath: input.fortressPath, operator: input.operator });
        return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
      },
    });
    expect(summary.ran).toBe(true);
    expect(summary.outcome?.kind).toBe("armed");
    expect(calls).toEqual([
      { fortressPath: "/Users/operator/.sanctuary", operator: { uid: 501, gid: 20 } },
    ]);
  });

  it("normalizes even for an aborted outcome (partial mutation must not strand a root-owned fortress)", async () => {
    const calls: string[] = [];
    const summary = await finishProvisionOutcomeWithCustodyNormalize({
      outcome: {
        kind: "aborted",
        stage: "rehome",
        reason: "test abort",
        rolledBack: true,
        rehomeAttempted: true,
      } as never,
      wallFortressPath: "/Users/operator/.sanctuary",
      operator: { uid: 501, gid: 20 },
      print: () => undefined,
      normalize: async (input) => {
        calls.push(input.fortressPath);
        return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
      },
    });
    expect(summary.outcome?.kind).toBe("aborted");
    expect(calls).toHaveLength(1);
  });

  it("uses the REAL normalize by default and repairs a deviant fortress mode end to end", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "protect-normalize-"));
    try {
      await writeFile(join(fortress, "a.enc"), "a", { mode: 0o600 });
      const { chmod, lstat } = await import("node:fs/promises");
      await chmod(fortress, 0o755);
      const lines: string[] = [];
      const summary = await finishProvisionOutcomeWithCustodyNormalize({
        outcome: { kind: "declined-by-operator" },
        wallFortressPath: fortress,
        operator: {
          uid: process.getuid?.() ?? 501,
          gid: process.getgid?.() ?? 20,
        },
        print: (line) => lines.push(line),
      });
      expect(summary.ran).toBe(true);
      // The default (real) normalize restored the canonical 0700 fortress mode.
      expect(((await lstat(fortress)).mode & 0o7777)).toBe(0o700);
    } finally {
      await rm(fortress, { recursive: true, force: true });
    }
  });
});
