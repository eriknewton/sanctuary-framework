/**
 * Tests for the H2-a unprovision rollback: disarm -> uninstall daemon ->
 * restore re-home, each step attempted even if an earlier one failed
 * (fail-loud reporting, not fail-stop), and NO account-removal primitive
 * anywhere in this module (H2-b is explicitly out of scope).
 */

import { describe, it, expect } from "vitest";

import {
  unprovision,
  unprovisionFullyOk,
  type UnprovisionOps,
} from "../../../src/castle-wall/provision/unprovision.js";
import type { RehomeOps, RehomeStepResult } from "../../../src/castle-wall/provision/rehome.js";

function mockRehomeOps(overrides: Partial<RehomeOps> = {}): RehomeOps & { restores: string[] } {
  const restores: string[] = [];
  return {
    restores,
    pathExists: async () => true,
    backup: async (path) => ({ backupPath: `${path}.bak` }),
    move: async () => undefined,
    chown: async () => undefined,
    restore: async (backupPath) => {
      restores.push(backupPath);
    },
    ...overrides,
  };
}

const SAMPLE_RESULTS: RehomeStepResult[] = [
  {
    entry: { sourcePath: "/Users/operator/.hermes/.env", destRelativePath: ".hermes/.env", isSecret: true },
    destPath: "/var/sanctuary-agents/sanctuary-hermes/.hermes/.env",
    status: "moved",
    backupPath: "/root/.sanctuary-rehome-backups/.hermes/.env.bak",
  },
];

describe("castle-wall/provision/unprovision", () => {
  it("disarms, uninstalls the daemon, and restores re-home, in that order, all reported ok", async () => {
    const callOrder: string[] = [];
    const unprovisionOps: UnprovisionOps = {
      disarm: async () => {
        callOrder.push("disarm");
      },
      uninstallHarnessDaemon: async () => {
        callOrder.push("uninstall-daemon");
      },
    };
    const rehomeOps = mockRehomeOps();

    const outcomes = await unprovision({
      rehomeResults: SAMPLE_RESULTS,
      rehomeOps,
      unprovisionOps,
    });

    expect(callOrder).toEqual(["disarm", "uninstall-daemon"]);
    expect(rehomeOps.restores).toEqual(["/root/.sanctuary-rehome-backups/.hermes/.env.bak"]);
    expect(unprovisionFullyOk(outcomes)).toBe(true);
    expect(outcomes.map((o) => o.step)).toEqual(["disarm", "uninstall-daemon", "restore-rehome"]);
  });

  it("still attempts later steps when an earlier step fails (fail-loud, not fail-stop)", async () => {
    const unprovisionOps: UnprovisionOps = {
      disarm: async () => {
        throw new Error("disarm socket unreachable");
      },
      uninstallHarnessDaemon: async () => undefined,
    };
    const rehomeOps = mockRehomeOps();

    const outcomes = await unprovision({
      rehomeResults: SAMPLE_RESULTS,
      rehomeOps,
      unprovisionOps,
    });

    expect(unprovisionFullyOk(outcomes)).toBe(false);
    const disarmOutcome = outcomes.find((o) => o.step === "disarm");
    expect(disarmOutcome?.ok).toBe(false);
    expect(disarmOutcome?.error).toMatch(/disarm socket unreachable/);
    // Later steps still ran and succeeded despite the earlier failure.
    const uninstallOutcome = outcomes.find((o) => o.step === "uninstall-daemon");
    expect(uninstallOutcome?.ok).toBe(true);
    const restoreOutcome = outcomes.find((o) => o.step === "restore-rehome");
    expect(restoreOutcome?.ok).toBe(true);
  });

  it("reports restore-rehome failure without masking it as success", async () => {
    const unprovisionOps: UnprovisionOps = {
      disarm: async () => undefined,
      uninstallHarnessDaemon: async () => undefined,
    };
    const rehomeOps = mockRehomeOps({
      restore: async () => {
        throw new Error("backup file missing");
      },
    });

    const outcomes = await unprovision({
      rehomeResults: SAMPLE_RESULTS,
      rehomeOps,
      unprovisionOps,
    });

    expect(unprovisionFullyOk(outcomes)).toBe(false);
    const restoreOutcome = outcomes.find((o) => o.step === "restore-rehome");
    expect(restoreOutcome?.ok).toBe(false);
    expect(restoreOutcome?.error).toMatch(/backup file missing/);
  });

  it("H2-b guard: this module exposes no account-deletion function (account removal is a separate, out-of-scope PR)", async () => {
    const moduleExports = await import("../../../src/castle-wall/provision/unprovision.js");
    const exportNames = Object.keys(moduleExports);
    for (const name of exportNames) {
      expect(name.toLowerCase()).not.toMatch(/deleteuser|removeaccount|deleteaccount/);
    }
  });
});
