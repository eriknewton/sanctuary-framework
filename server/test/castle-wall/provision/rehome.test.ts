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
const OPERATOR_UID_GID = { uid: 501, gid: 501 };

/**
 * In-memory filesystem-tree simulation so restore tests can assert that
 * data ACTUALLY moves, not merely that a function was called with the right
 * arguments. `contents` maps a path to its "file contents" (a directory is
 * represented by keying every file under it, e.g. `<dir>/token.json`).
 */
function mockOps(
  existingPaths: Set<string>,
  overrides: Partial<RehomeOps> = {},
): RehomeOps & {
  backups: string[];
  moves: Array<{ from: string; to: string }>;
  chowns: Array<{ path: string; uid: number; gid: number }>;
  restores: Array<{ destPath: string; sourcePath: string }>;
  restoreCustodyCalls: Array<{ path: string; uid: number; gid: number }>;
  contents: Map<string, string>;
} {
  const backups: string[] = [];
  const moves: Array<{ from: string; to: string }> = [];
  const chowns: Array<{ path: string; uid: number; gid: number }> = [];
  const restores: Array<{ destPath: string; sourcePath: string }> = [];
  const restoreCustodyCalls: Array<{ path: string; uid: number; gid: number }> = [];
  const contents = new Map<string, string>();
  return {
    backups,
    moves,
    chowns,
    restores,
    restoreCustodyCalls,
    contents,
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
    restore: async (destPath, sourcePath) => {
      restores.push({ destPath, sourcePath });
      // Simulate a reverse-move: reproduce whatever "content" is recorded at
      // destPath (the real path the data lives at post-move) back onto
      // sourcePath, mirroring the production reverse-rename semantics.
      const data = contents.get(destPath);
      if (data !== undefined) {
        contents.set(sourcePath, data);
        contents.delete(destPath);
        return { restored: true };
      }
      return { restored: false };
    },
    restoreCustody: async (path, uid, gid) => {
      restoreCustodyCalls.push({ path, uid, gid });
    },
    ...overrides,
  };
}

describe("castle-wall/provision/rehome", () => {
  describe("hermesRehomeAdapter", () => {
    it("enumerates the Mini2-D2-grounded runtime + file-based secret paths", () => {
      const entries = hermesRehomeAdapter.pathsToRehome(OPERATOR_HOME);
      expect(entries.length).toBeGreaterThan(0);
      const sourcePaths = entries.map((e) => e.sourcePath);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/.env`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/auth.json`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/config.yaml`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/hermes-agent`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.google_workspace_mcp/credentials`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.workspace-mcp/cli-tokens`);
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/google-mcp-creds`);
      expect(entries.find((e) => e.destRelativePath === ".hermes/hermes-agent")?.isSecret).toBe(false);
      expect(
        entries
          .filter((e) => e.destRelativePath !== ".hermes/hermes-agent")
          .every((e) => e.isSecret),
      ).toBe(true);
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
      expect(ops.backups.length).toBe(plan.steps.filter((s) => s.entry.isSecret).length);
      expect(ops.moves.length).toBe(plan.steps.length);
      expect(ops.chowns.every((c) => c.uid === 502 && c.gid === 502)).toBe(true);
      // Every moved secret step recorded a backupPath (M4: reversibility);
      // non-secret runtime code is reverse-moved on rollback but not backed up.
      expect(
        results.every((r) => r.status !== "moved" || !r.entry.isSecret || r.backupPath !== undefined),
      ).toBe(true);
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
    it("restores every moved step via a REVERSE-MOVE from destPath (fix F2: not the shallow backup) and skips absent steps", async () => {
      const plan = planRehome(hermesRehomeAdapter, {
        operatorHome: OPERATOR_HOME,
        newAccountHome: NEW_ACCOUNT_HOME,
      });
      const allPaths = new Set(plan.steps.map((s) => s.entry.sourcePath));
      const ops = mockOps(allPaths);
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });
      // Simulate the real data living at destPath post-move (this is what
      // `move` = `rename` guarantees in production).
      for (const r of results) {
        if (r.status === "moved") ops.contents.set(r.destPath, `data-for-${r.destPath}`);
      }

      const restoreResult = await restoreRehomeSteps(results, ops, OPERATOR_UID_GID);
      expect(ops.restores.length).toBe(results.filter((r) => r.status === "moved").length);
      // The restore call must pass destPath (where the data actually is),
      // not backupPath (the M4 custody copy) -- fix F2's reverse-move.
      for (const r of results.filter((x) => x.status === "moved")) {
        expect(ops.restores.some((call) => call.destPath === r.destPath && call.sourcePath === r.entry.sourcePath)).toBe(
          true,
        );
      }
      expect(restoreResult.fullyRestored).toBe(true);
      expect(restoreResult.steps.filter((s) => s.status === "restored").length).toBe(
        results.filter((r) => r.status === "moved").length,
      );
    });

    it("fix F2: a directory-shaped secret's restore reproduces the actual contents (not an empty dir) and returns them to the operator", async () => {
      // Ground this in the exact defect: `.hermes/google-mcp-creds/` is a
      // directory-shaped secret in the real Hermes adapter. This test
      // exercises restore for a directory entry and asserts the DATA (not
      // just an empty placeholder) comes back to the operator's source path.
      const dirAdapter: AgentRehomeAdapter = {
        harnessId: "test-dir",
        pathsToRehome: (home) => [
          {
            sourcePath: `${home}/.hermes/google-mcp-creds`,
            destRelativePath: ".hermes/google-mcp-creds",
            isSecret: true,
          },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const plan = planRehome(dirAdapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });
      const sourceDir = `${OPERATOR_HOME}/.hermes/google-mcp-creds`;
      const ops = mockOps(new Set([sourceDir]));
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });
      expect(results[0]?.status).toBe("moved");
      const destDir = results[0]!.destPath;
      // The directory's real content now lives at destPath (a real `rename`
      // moves the whole tree, unlike the old shallow `mkdir` backup).
      ops.contents.set(destDir, "oauth-refresh-token-contents");

      const restoreResult = await restoreRehomeSteps(results, ops, OPERATOR_UID_GID);

      expect(restoreResult.fullyRestored).toBe(true);
      expect(ops.contents.get(sourceDir)).toBe("oauth-refresh-token-contents");
      expect(ops.contents.has(destDir)).toBe(false);
      // Fix F3: custody handed back to the operator for the restored secret.
      expect(ops.restoreCustodyCalls).toEqual([
        { path: sourceDir, uid: OPERATOR_UID_GID.uid, gid: OPERATOR_UID_GID.gid },
      ]);
    });

    it("fix F2/F5: reports a FAILED restore (not a hardcoded success) when the ops layer cannot reproduce the data", async () => {
      const plan = planRehome(hermesRehomeAdapter, {
        operatorHome: OPERATOR_HOME,
        newAccountHome: NEW_ACCOUNT_HOME,
      });
      const allPaths = new Set(plan.steps.map((s) => s.entry.sourcePath));
      const ops = mockOps(allPaths, {
        restore: async () => ({ restored: false }),
      });
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });

      const restoreResult = await restoreRehomeSteps(results, ops, OPERATOR_UID_GID);
      expect(restoreResult.fullyRestored).toBe(false);
      expect(restoreResult.steps.every((s) => s.status === "skipped-absent" || s.status === "failed")).toBe(true);
    });

    it("fix F3: restore hands custody (chmod/chown) back to the operator for secret entries only", async () => {
      const plan = planRehome(hermesRehomeAdapter, {
        operatorHome: OPERATOR_HOME,
        newAccountHome: NEW_ACCOUNT_HOME,
      });
      const allPaths = new Set(plan.steps.map((s) => s.entry.sourcePath));
      const ops = mockOps(allPaths);
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });
      for (const r of results) {
        if (r.status === "moved") ops.contents.set(r.destPath, "secret-data");
      }

      await restoreRehomeSteps(results, ops, OPERATOR_UID_GID);
      const movedCount = results.filter((r) => r.status === "moved" && r.entry.isSecret).length;
      expect(ops.restoreCustodyCalls.length).toBe(movedCount);
      expect(ops.restoreCustodyCalls.every((c) => c.uid === OPERATOR_UID_GID.uid && c.gid === OPERATOR_UID_GID.gid)).toBe(
        true,
      );
    });

    it("restores non-secret runtime trees by chowning back to the operator without restoreCustody chmod", async () => {
      const runtimeAdapter: AgentRehomeAdapter = {
        harnessId: "test-runtime-restore",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.hermes/hermes-agent`, destRelativePath: ".hermes/hermes-agent", isSecret: false },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const src = `${OPERATOR_HOME}/.hermes/hermes-agent`;
      const ops = mockOps(new Set([src]));
      const plan = planRehome(runtimeAdapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });
      ops.chowns.length = 0;
      ops.contents.set(results[0]!.destPath, "runtime-tree");

      const restoreResult = await restoreRehomeSteps(results, ops, OPERATOR_UID_GID);

      expect(restoreResult.fullyRestored).toBe(true);
      expect(ops.restoreCustodyCalls).toEqual([]);
      expect(ops.chowns).toEqual([{ path: src, uid: OPERATOR_UID_GID.uid, gid: OPERATOR_UID_GID.gid }]);
    });

    it("FIX (round 5, N6): a CONFLICT outcome for a secret hands custody of the RECOVERED data (at conflictPath) back to the operator, never the untouched source", async () => {
      const singleAdapter: AgentRehomeAdapter = {
        harnessId: "test-conflict",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.hermes/.env`, destRelativePath: ".hermes/.env", isSecret: true },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const src = `${OPERATOR_HOME}/.hermes/.env`;
      const conflictPath = `${src}.restored-conflict`;
      const ops = mockOps(new Set([src]), {
        restore: async () => ({ restored: false, conflictPath }),
      });
      const plan = planRehome(singleAdapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });

      const restoreResult = await restoreRehomeSteps(results, ops, OPERATOR_UID_GID);

      expect(restoreResult.fullyRestored).toBe(false);
      expect(restoreResult.steps[0]?.status).toBe("conflict");
      expect(restoreResult.steps[0]?.conflictPath).toBe(conflictPath);
      // The recovered data at conflictPath was reverse-moved from the
      // agent-owned re-home destination; custody handback must target THAT
      // path (so the operator can read it), NOT the operator's untouched
      // recreated source. Before N6 no handback happened at all.
      expect(ops.restoreCustodyCalls).toEqual([
        { path: conflictPath, uid: OPERATOR_UID_GID.uid, gid: OPERATOR_UID_GID.gid },
      ]);
    });

    it("a CONFLICT outcome for a NON-secret entry chowns the recovered data back without restoreCustody chmod", async () => {
      const nonSecretAdapter: AgentRehomeAdapter = {
        harnessId: "test-conflict-nonsecret",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.config/plain`, destRelativePath: ".config/plain", isSecret: false },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const src = `${OPERATOR_HOME}/.config/plain`;
      const conflictPath = `${src}.restored-conflict`;
      const ops = mockOps(new Set([src]), {
        restore: async () => ({ restored: false, conflictPath }),
      });
      const plan = planRehome(nonSecretAdapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });
      ops.chowns.length = 0;

      const restoreResult = await restoreRehomeSteps(results, ops, OPERATOR_UID_GID);

      expect(restoreResult.steps[0]?.status).toBe("conflict");
      expect(ops.restoreCustodyCalls).toEqual([]);
      expect(ops.chowns).toEqual([{ path: conflictPath, uid: OPERATOR_UID_GID.uid, gid: OPERATOR_UID_GID.gid }]);
    });

    it("FIX (round 5, R2-5): a restoreCustody THROW on the conflict branch keeps status 'conflict' + conflictPath (never relabeled 'failed'), folding the custody error into the note", async () => {
      const singleAdapter: AgentRehomeAdapter = {
        harnessId: "test-conflict-custody-throw",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.hermes/.env`, destRelativePath: ".hermes/.env", isSecret: true },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const src = `${OPERATOR_HOME}/.hermes/.env`;
      const conflictPath = `${src}.restored-conflict`;
      const ops = mockOps(new Set([src]), {
        restore: async () => ({ restored: false, conflictPath }),
        restoreCustody: async () => {
          throw new Error("chown: operation not permitted");
        },
      });
      const plan = planRehome(singleAdapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });
      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });

      const restoreResult = await restoreRehomeSteps(results, ops, OPERATOR_UID_GID);

      const step = restoreResult.steps[0];
      // The custody handback failed, but the step must NOT be relabeled
      // "failed" (which would DROP conflictPath and lose the "your recreated
      // file is safe; recovered data is at <path>" guidance). It stays
      // "conflict" with conflictPath, and the custody error is folded in.
      expect(step?.status).toBe("conflict");
      expect(step?.conflictPath).toBe(conflictPath);
      expect(step?.error).toMatch(/custody handback to the operator failed/);
      expect(step?.error).toMatch(/chown: operation not permitted/);
      expect(restoreResult.fullyRestored).toBe(false);
    });
  });
});
