/**
 * Tests for the re-home adapter plumbing: plan building (pure), execution
 * (backup-first for secrets, move, chown), restore, and the Hermes v1
 * adapter's path list (grounded in the live Mini2 D2 finding: file-based
 * secrets, no keychain).
 */

import { describe, it, expect } from "vitest";

import {
  planRehome,
  executeRehomePlan,
  restoreRehomeSteps,
  hermesRehomeAdapter,
  type RehomeOps,
  type AgentRehomeAdapter,
} from "../../../src/castle-wall/provision/rehome.js";

const OPERATOR_HOME = "/Users/operator";
const NEW_ACCOUNT_HOME = "/var/sanctuary-agents/sanctuary-hermes";

function mockOps(existingPaths: Set<string>, overrides: Partial<RehomeOps> = {}): RehomeOps & {
  backups: string[];
  moves: Array<{ from: string; to: string }>;
  chowns: Array<{ path: string; uid: number; gid: number }>;
  restores: Array<{ backupPath: string; destPath: string }>;
} {
  const backups: string[] = [];
  const moves: Array<{ from: string; to: string }> = [];
  const chowns: Array<{ path: string; uid: number; gid: number }> = [];
  const restores: Array<{ backupPath: string; destPath: string }> = [];
  return {
    backups,
    moves,
    chowns,
    restores,
    pathExists: async (path) => existingPaths.has(path),
    backup: async (path) => {
      const backupPath = `/root/.sanctuary-rehome-backups${path}.bak`;
      backups.push(backupPath);
      return { backupPath };
    },
    move: async (from, to) => {
      moves.push({ from, to });
    },
    chown: async (path, uid, gid) => {
      chowns.push({ path, uid, gid });
    },
    restore: async (backupPath, destPath) => {
      restores.push({ backupPath, destPath });
    },
    ...overrides,
  };
}

describe("castle-wall/provision/rehome", () => {
  describe("hermesRehomeAdapter", () => {
    it("enumerates the Mini2-D2-grounded file-based secret paths, all marked isSecret", () => {
      const entries = hermesRehomeAdapter.pathsToRehome(OPERATOR_HOME);
      expect(entries.length).toBeGreaterThan(0);
      expect(entries.every((e) => e.isSecret)).toBe(true);
      const sourcePaths = entries.map((e) => e.sourcePath);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/.env`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/auth.json`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/config.yaml`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.google_workspace_mcp/credentials`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.workspace-mcp/cli-tokens`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/google-mcp-creds`);
    });

    it("requires no interactive re-consent in v1 (file-portable Google refresh tokens, calendar:readonly scope)", () => {
      expect(hermesRehomeAdapter.requiresInteractiveReconsent()).toBe(false);
    });
  });

  describe("planRehome", () => {
    it("joins operator-home source paths to new-account-home dest paths, performing no I/O", () => {
      const plan = planRehome(hermesRehomeAdapter, {
        operatorHome: OPERATOR_HOME,
        newAccountHome: NEW_ACCOUNT_HOME,
      });
      expect(plan.harnessId).toBe("hermes");
      const envStep = plan.steps.find((s) => s.entry.destRelativePath === ".hermes/.env");
      expect(envStep?.destPath).toBe(`${NEW_ACCOUNT_HOME}/.hermes/.env`);
      expect(plan.requiresInteractiveReconsent).toBe(false);
    });
  });

  describe("executeRehomePlan", () => {
    it("backs up (fix M4) then moves then chowns each existing secret path", async () => {
      const plan = planRehome(hermesRehomeAdapter, {
        operatorHome: OPERATOR_HOME,
        newAccountHome: NEW_ACCOUNT_HOME,
      });
      const allPaths = new Set(plan.steps.map((s) => s.entry.sourcePath));
      const ops = mockOps(allPaths);
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });

      expect(results.every((r) => r.status === "moved")).toBe(true);
      expect(ops.backups.length).toBe(plan.steps.length);
      expect(ops.moves.length).toBe(plan.steps.length);
      expect(ops.chowns.every((c) => c.uid === 502 && c.gid === 502)).toBe(true);
      // Every moved secret step recorded a backupPath (M4: reversibility).
      expect(results.every((r) => r.status !== "moved" || r.backupPath !== undefined)).toBe(true);
    });

    it("marks a source path that does not exist as skipped-absent, with no backup/move/chown", async () => {
      const plan = planRehome(hermesRehomeAdapter, {
        operatorHome: OPERATOR_HOME,
        newAccountHome: NEW_ACCOUNT_HOME,
      });
      const ops = mockOps(new Set()); // nothing exists
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });

      expect(results.every((r) => r.status === "skipped-absent")).toBe(true);
      expect(ops.backups).toEqual([]);
      expect(ops.moves).toEqual([]);
      expect(ops.chowns).toEqual([]);
    });

    it("propagates a backup failure without moving the file (fail-closed: never move an un-backed-up secret)", async () => {
      const plan = planRehome(hermesRehomeAdapter, {
        operatorHome: OPERATOR_HOME,
        newAccountHome: NEW_ACCOUNT_HOME,
      });
      const allPaths = new Set(plan.steps.map((s) => s.entry.sourcePath));
      const ops = mockOps(allPaths, {
        backup: async () => {
          throw new Error("backup destination not root-only writable");
        },
      });
      await expect(executeRehomePlan(plan, ops, { uid: 502, gid: 502 })).rejects.toThrow(
        /backup destination not root-only writable/,
      );
      expect(ops.moves).toEqual([]);
    });

    it("adapter with a non-secret path skips the backup step but still moves+chowns it", async () => {
      const nonSecretAdapter: AgentRehomeAdapter = {
        harnessId: "test",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.test/public.txt`, destRelativePath: ".test/public.txt", isSecret: false },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const plan = planRehome(nonSecretAdapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });
      const ops = mockOps(new Set([`${OPERATOR_HOME}/.test/public.txt`]));
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });
      expect(results[0]?.status).toBe("moved");
      expect(results[0]?.backupPath).toBeUndefined();
      expect(ops.backups).toEqual([]);
      expect(ops.moves.length).toBe(1);
    });
  });

  describe("restoreRehomeSteps", () => {
    it("restores every moved step from its backup (or dest, when no backup) and skips absent steps", async () => {
      const plan = planRehome(hermesRehomeAdapter, {
        operatorHome: OPERATOR_HOME,
        newAccountHome: NEW_ACCOUNT_HOME,
      });
      const allPaths = new Set(plan.steps.map((s) => s.entry.sourcePath));
      const ops = mockOps(allPaths);
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });

      await restoreRehomeSteps(results, ops);
      expect(ops.restores.length).toBe(results.filter((r) => r.status === "moved").length);
    });
  });
});
