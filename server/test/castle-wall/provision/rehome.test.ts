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
  RehomeExecutionError,
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
  sourceDuplicateRemovals: string[];
  sourceDuplicateRestores: Array<{ backupPath: string; sourcePath: string }>;
  moves: Array<{ from: string; to: string }>;
  chowns: Array<{ path: string; uid: number; gid: number }>;
  restores: Array<{ destPath: string; sourcePath: string; backupPath?: string }>;
  restoreCustodyCalls: Array<{ path: string; uid: number; gid: number }>;
  contents: Map<string, string>;
} {
  const backups: string[] = [];
  const sourceDuplicateRemovals: string[] = [];
  const sourceDuplicateRestores: Array<{ backupPath: string; sourcePath: string }> = [];
  const moves: Array<{ from: string; to: string }> = [];
  const chowns: Array<{ path: string; uid: number; gid: number }> = [];
  const restores: Array<{ destPath: string; sourcePath: string; backupPath?: string }> = [];
  const restoreCustodyCalls: Array<{ path: string; uid: number; gid: number }> = [];
  const contents = new Map<string, string>();
  return {
    backups,
    sourceDuplicateRemovals,
    sourceDuplicateRestores,
    moves,
    chowns,
    restores,
    restoreCustodyCalls,
    contents,
    pathExists: async (path) => existingPaths.has(path),
    pathExistsNoFollow: async (path) => existingPaths.has(path),
    hashPath: async (path) => ({ algorithm: "sha256", value: `hash-${path}` }),
    readDestinationProvenance: async () => undefined,
    recordDestinationProvenance: async () => {},
    clearDestinationProvenance: async () => {},
    displaceDestination: async (destPath) => {
      const displacedPath = `${destPath}.displaced-20260729T000000000Z`;
      existingPaths.delete(destPath);
      existingPaths.add(displacedPath);
      return { displacedPath };
    },
    restoreDisplacedDestination: async (displacedPath, destPath) => {
      if (!existingPaths.has(displacedPath)) return { restored: false };
      if (existingPaths.has(destPath)) {
        const conflictPath = `${destPath}.restored-conflict`;
        existingPaths.delete(displacedPath);
        existingPaths.add(conflictPath);
        return { restored: false, conflictPath };
      }
      existingPaths.delete(displacedPath);
      existingPaths.add(destPath);
      return { restored: true };
    },
    backup: async (path) => {
      const backupPath = `/root/.sanctuary-rehome-backups${path}.bak`;
      backups.push(backupPath);
      contents.set(backupPath, contents.get(path) ?? `backup-data-for-${path}`);
      return { backupPath };
    },
    removeSourceDuplicate: async (path) => {
      sourceDuplicateRemovals.push(path);
      existingPaths.delete(path);
      contents.delete(path);
    },
    restoreSourceDuplicate: async (backupPath, sourcePath) => {
      sourceDuplicateRestores.push({ backupPath, sourcePath });
      const data = contents.get(backupPath);
      if (data === undefined) return { restored: false };
      if (existingPaths.has(sourcePath)) {
        const conflictPath = `${sourcePath}.restored-conflict`;
        existingPaths.add(conflictPath);
        contents.set(conflictPath, data);
        return { restored: false, conflictPath };
      }
      existingPaths.add(sourcePath);
      contents.set(sourcePath, data);
      return { restored: true };
    },
    move: async (from, to) => {
      moves.push({ from, to });
      existingPaths.delete(from);
      existingPaths.add(to);
    },
    chown: async (path, uid, gid) => {
      chowns.push({ path, uid, gid });
      return { excludedPaths: [] };
    },
    restore: async (destPath, sourcePath, backupPath) => {
      restores.push({ destPath, sourcePath, backupPath });
      // Simulate a reverse-move: reproduce whatever "content" is recorded at
      // destPath (the real path the data lives at post-move) back onto
      // sourcePath, mirroring the production reverse-rename semantics.
      const data = contents.get(destPath);
      if (data !== undefined) {
        contents.set(sourcePath, data);
        contents.delete(destPath);
        existingPaths.delete(destPath);
        existingPaths.add(sourcePath);
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
      expect(sourcePaths).toContain(`${OPERATOR_HOME}/.hermes/cli-config.json`);
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

    it("refuses a dual source+destination conflict before backup or move, printing both hashes and paths", async () => {
      const adapter: AgentRehomeAdapter = {
        harnessId: "test-conflict",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.hermes/config.yaml`, destRelativePath: ".hermes/config.yaml", isSecret: true },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const src = `${OPERATOR_HOME}/.hermes/config.yaml`;
      const dest = `${NEW_ACCOUNT_HOME}/.hermes/config.yaml`;
      const ops = mockOps(new Set([src, dest]));
      const plan = planRehome(adapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });

      await expect(executeRehomePlan(plan, ops, { uid: 502, gid: 502 })).rejects.toThrow(
        new RegExp(`source ${src} \\(sha256:hash-${src}\\).*destination ${dest} \\(sha256:hash-${dest}\\)`),
      );
      expect(ops.backups).toEqual([]);
      expect(ops.moves).toEqual([]);
      expect(ops.chowns).toEqual([]);
    });

    it("lets a provenance-backed destination win, then backs up and removes the duplicate secret source", async () => {
      const adapter: AgentRehomeAdapter = {
        harnessId: "test-provenance",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.hermes/config.yaml`, destRelativePath: ".hermes/config.yaml", isSecret: true },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const src = `${OPERATOR_HOME}/.hermes/config.yaml`;
      const dest = `${NEW_ACCOUNT_HOME}/.hermes/config.yaml`;
      const ops = mockOps(new Set([src, dest]), {
        hashPath: async () => ({ algorithm: "sha256", value: "hash-identical-rehomed-config" }),
        readDestinationProvenance: async () => ({
          schemaVersion: 1,
          sourcePath: src,
          destPath: dest,
          destHash: { algorithm: "sha256", value: "hash-identical-rehomed-config" },
          recordedAt: "2026-07-29T00:00:00.000Z",
        }),
      });
      const plan = planRehome(adapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });

      const results = await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });

      expect(results).toEqual([
        {
          entry: { sourcePath: src, destRelativePath: ".hermes/config.yaml", isSecret: true },
          destPath: dest,
          status: "destination-authoritative",
          backupPath: `/root/.sanctuary-rehome-backups${src}.bak`,
          sourceDuplicateRemoved: true,
          sourceHash: { algorithm: "sha256", value: "hash-identical-rehomed-config" },
          destinationHash: { algorithm: "sha256", value: "hash-identical-rehomed-config" },
        },
      ]);
      expect(ops.backups).toEqual([`/root/.sanctuary-rehome-backups${src}.bak`]);
      expect(ops.sourceDuplicateRemovals).toEqual([src]);
      expect(await ops.pathExists(src)).toBe(false);
      expect(ops.moves).toEqual([]);
      expect(ops.chowns).toEqual([]);
    });

    it("refuses divergent dual presence even when provenance marks the destination as previously re-homed", async () => {
      const adapter: AgentRehomeAdapter = {
        harnessId: "test-divergent-provenance",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.hermes/config.yaml`, destRelativePath: ".hermes/config.yaml", isSecret: true },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const src = `${OPERATOR_HOME}/.hermes/config.yaml`;
      const dest = `${NEW_ACCOUNT_HOME}/.hermes/config.yaml`;
      const ops = mockOps(new Set([src, dest]), {
        readDestinationProvenance: async () => ({
          schemaVersion: 1,
          sourcePath: src,
          destPath: dest,
          destHash: { algorithm: "sha256", value: `hash-${dest}` },
          recordedAt: "2026-07-29T00:00:00.000Z",
        }),
      });
      const plan = planRehome(adapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });

      await expect(executeRehomePlan(plan, ops, { uid: 502, gid: 502 })).rejects.toThrow(/hashes diverge/);
      expect(ops.backups).toEqual([]);
      expect(ops.moves).toEqual([]);
      expect(ops.chowns).toEqual([]);
    });

    it("--overwrite-destination records the displaced destination before backup/move so abort rollback can restore it", async () => {
      const adapter: AgentRehomeAdapter = {
        harnessId: "test-overwrite",
        pathsToRehome: (home) => [
          { sourcePath: `${home}/.hermes/config.yaml`, destRelativePath: ".hermes/config.yaml", isSecret: true },
        ],
        requiresInteractiveReconsent: () => false,
      };
      const src = `${OPERATOR_HOME}/.hermes/config.yaml`;
      const dest = `${NEW_ACCOUNT_HOME}/.hermes/config.yaml`;
      const ops = mockOps(new Set([src, dest]), {
        backup: async () => {
          throw new Error("forced later abort");
        },
      });
      const plan = planRehome(adapter, { operatorHome: OPERATOR_HOME, newAccountHome: NEW_ACCOUNT_HOME });

      let caught: unknown;
      try {
        await executeRehomePlan(plan, ops, { uid: 502, gid: 502 }, { overwriteDestination: true });
      } catch (err) {
        caught = err;
      }

      expect(caught).toBeInstanceOf(RehomeExecutionError);
      const rehomeErr = caught as RehomeExecutionError;
      expect(rehomeErr.partialResults).toEqual([
        {
          entry: { sourcePath: src, destRelativePath: ".hermes/config.yaml", isSecret: true },
          destPath: dest,
          status: "destination-displaced",
          displacedDestinationPath: `${dest}.displaced-20260729T000000000Z`,
          sourceHash: { algorithm: "sha256", value: `hash-${src}` },
          destinationHash: { algorithm: "sha256", value: `hash-${dest}` },
        },
      ]);
    });
  });

  describe("restoreRehomeSteps", () => {
    it("restores a removed destination-authoritative source duplicate from backup without moving the destination", async () => {
      const src = `${OPERATOR_HOME}/.hermes/config.yaml`;
      const dest = `${NEW_ACCOUNT_HOME}/.hermes/config.yaml`;
      const backupPath = `/root/.sanctuary-rehome-backups${src}.bak`;
      const ops = mockOps(new Set([dest]));
      ops.contents.set(backupPath, "operator-secret-copy");

      const restoreResult = await restoreRehomeSteps(
        [
          {
            entry: { sourcePath: src, destRelativePath: ".hermes/config.yaml", isSecret: true },
            destPath: dest,
            status: "destination-authoritative",
            backupPath,
            sourceDuplicateRemoved: true,
          },
        ],
        ops,
        OPERATOR_UID_GID,
      );

      expect(restoreResult.fullyRestored).toBe(true);
      expect(restoreResult.steps).toEqual([
        {
          entry: { sourcePath: src, destRelativePath: ".hermes/config.yaml", isSecret: true },
          sourcePath: src,
          status: "restored",
        },
      ]);
      expect(ops.sourceDuplicateRestores).toEqual([{ backupPath, sourcePath: src }]);
      expect(ops.restores).toEqual([]);
      expect(await ops.pathExists(src)).toBe(true);
      expect(await ops.pathExists(dest)).toBe(true);
      expect(ops.contents.get(src)).toBe("operator-secret-copy");
      expect(ops.restoreCustodyCalls).toEqual([{ path: src, uid: OPERATOR_UID_GID.uid, gid: OPERATOR_UID_GID.gid }]);
    });

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
        expect(
          ops.restores.some(
            (call) =>
              call.destPath === r.destPath &&
              call.sourcePath === r.entry.sourcePath &&
              call.backupPath === r.backupPath,
          ),
        ).toBe(true);
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
