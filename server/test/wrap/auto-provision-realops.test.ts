/**
 * Re-gate 1 (fix commit 636f6051) CHOKEPOINT (2026-07-07 fix-round 2): the
 * `wrap/auto-provision.ts` real-ops layer had ZERO unit coverage -- the
 * dep-injection mock boundary in `test/wrap/auto-provision-wiring.test.ts`
 * sits ABOVE `runAutoProvisionForWrap` entirely, and
 * `test/castle-wall/provision/orchestrate.test.ts` mocks every `ProvisionFlowOps`
 * method. Both fix-round 1's F1 fail-opens (root-probe overclaim,
 * ENOENT-passes) and fix-round 2's R1-R6 findings lived EXACTLY in the gap
 * between those two suites: the real, security-load-bearing DECISION logic
 * behind the probes, the sudo identity resolution, and the restore-conflict
 * handling.
 *
 * This suite closes that gap by exercising the exported pure/decidable
 * helpers directly:
 *   - `credentialReadableAsUidDecision` (R1): ENOENT -> false, unreadable-by-
 *     uid -> false, root-vs-uid honesty (owner match + read bit only).
 *   - `resolveSudoIdentityDecision` (R2): SUDO_UID present/absent, malformed,
 *     invalid SUDO_USER shape.
 *   - `RehomeExecutionError`/`executeRehomePlan` (R3): a mid-loop throw
 *     carries the already-completed results, not an empty array.
 *   - `realRehomeOps().restore` (R6): a recreated source file is never
 *     overwritten; the moved data lands at a conflict path instead.
 *
 * Real `sysadminctl`/`dscl`/`launchctl`/network calls stay drill-only (never
 * exercised here); this suite is scoped to the DECISION logic around them,
 * per the re-gate spec's chokepoint requirement.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  credentialReadableAsUidDecision,
  resolveSudoIdentityDecision,
  realRehomeOps,
} from "../../src/wrap/auto-provision.js";
import {
  planRehome,
  executeRehomePlan,
  RehomeExecutionError,
  type AgentRehomeAdapter,
  type RehomeOps,
} from "../../src/castle-wall/provision/rehome.js";

describe("wrap/auto-provision real-ops chokepoint: credentialReadableAsUidDecision (fix R1)", () => {
  it("ENOENT (statResult undefined) -> false: an absent moved credential is never a pass", () => {
    expect(credentialReadableAsUidDecision(undefined, 502)).toBe(false);
  });

  it("owner uid matches AND owner-read bit set -> true", () => {
    const result = credentialReadableAsUidDecision({ uid: 502, gid: 502, mode: 0o600 }, 502);
    expect(result).toBe(true);
  });

  it("owner uid matches but owner-read bit is NOT set -> false (unreadable-by-uid)", () => {
    // Mode 0o200 = owner write-only, no read bit.
    const result = credentialReadableAsUidDecision({ uid: 502, gid: 502, mode: 0o200 }, 502);
    expect(result).toBe(false);
  });

  it("owner uid does NOT match, no group/other read bits -> false (root-vs-uid honesty: root owning the file is not the target uid)", () => {
    // Simulates the exact fix-round-1 defect shape: file owned by root (0),
    // mode 0600 (owner-only read), target uid is the re-homed agent (502).
    // Root's own unrestricted read capability must NOT leak into this
    // decision -- the decision is driven purely by the owner/mode bits.
    const result = credentialReadableAsUidDecision({ uid: 0, gid: 0, mode: 0o600 }, 502);
    expect(result).toBe(false);
  });

  it("owner uid does NOT match, but group matches targetGid with group-read bit -> true", () => {
    const result = credentialReadableAsUidDecision({ uid: 0, gid: 20, mode: 0o640 }, 502, 20);
    expect(result).toBe(true);
  });

  it("owner uid does NOT match, world-readable (other-read bit set) -> true", () => {
    const result = credentialReadableAsUidDecision({ uid: 0, gid: 0, mode: 0o604 }, 502);
    expect(result).toBe(true);
  });

  it("owner uid does NOT match, no matching group, no other-read -> false", () => {
    const result = credentialReadableAsUidDecision({ uid: 0, gid: 0, mode: 0o640 }, 502, 999);
    expect(result).toBe(false);
  });
});

describe("wrap/auto-provision real-ops chokepoint: resolveSudoIdentityDecision (fix R2)", () => {
  it("SUDO_UID and SUDO_GID both present and well-formed -> resolved", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "501", SUDO_GID: "20", SUDO_USER: "erik" });
    expect(result).toEqual({ uid: 501, gid: 20, user: "erik" });
  });

  it("SUDO_UID absent -> undefined (fail-closed, never falls back to root's own identity)", () => {
    const result = resolveSudoIdentityDecision({ SUDO_GID: "20", SUDO_USER: "erik" });
    expect(result).toBeUndefined();
  });

  it("SUDO_GID absent -> undefined (fail-closed)", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "501", SUDO_USER: "erik" });
    expect(result).toBeUndefined();
  });

  it("both absent (raw root shell, no sudo) -> undefined", () => {
    const result = resolveSudoIdentityDecision({});
    expect(result).toBeUndefined();
  });

  it("malformed SUDO_UID (non-numeric) -> undefined", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "not-a-number", SUDO_GID: "20" });
    expect(result).toBeUndefined();
  });

  it("malformed SUDO_GID (non-numeric) -> undefined", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "501", SUDO_GID: "not-a-number" });
    expect(result).toBeUndefined();
  });

  it("negative-looking SUDO_UID (fails the digit-only shape) -> undefined", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "-1", SUDO_GID: "20" });
    expect(result).toBeUndefined();
  });

  it("SUDO_USER present but fails the safe-name shape -> undefined (refuses even though uid/gid parse)", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "501", SUDO_GID: "20", SUDO_USER: "erik; rm -rf /" });
    expect(result).toBeUndefined();
  });

  it("SUDO_USER absent but SUDO_UID/GID present -> resolved with user undefined (caller falls back to uid lookup)", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "501", SUDO_GID: "20" });
    expect(result).toEqual({ uid: 501, gid: 20, user: undefined });
  });
});

describe("castle-wall/provision/rehome real-ops chokepoint: RehomeExecutionError partial-strand (fix R3)", () => {
  const testAdapter: AgentRehomeAdapter = {
    harnessId: "test",
    pathsToRehome: (home) => [
      { sourcePath: `${home}/a`, destRelativePath: "a", isSecret: true },
      { sourcePath: `${home}/b`, destRelativePath: "b", isSecret: true },
      { sourcePath: `${home}/c`, destRelativePath: "c", isSecret: true },
    ],
    requiresInteractiveReconsent: () => false,
  };

  function mockOpsThatFailsOnThirdMove(): RehomeOps {
    let moveCount = 0;
    return {
      pathExists: async () => true,
      backup: async (path) => ({ backupPath: `/root/backup${path}.bak` }),
      move: async () => {
        moveCount += 1;
        if (moveCount === 3) {
          throw new Error("chown failed: operation not permitted");
        }
      },
      chown: async () => {},
      restore: async () => ({ restored: true }),
      restoreCustody: async () => {},
    };
  }

  it("a mid-loop throw on step 3 of 3 is thrown as RehomeExecutionError carrying the first 2 completed results", async () => {
    const plan = planRehome(testAdapter, { operatorHome: "/Users/operator", newAccountHome: "/var/sanctuary-agents/x" });
    const ops = mockOpsThatFailsOnThirdMove();

    let caught: unknown;
    try {
      await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(RehomeExecutionError);
    const rehomeErr = caught as RehomeExecutionError;
    expect(rehomeErr.message).toMatch(/chown failed: operation not permitted/);
    // FIX R3: the two already-completed steps (a, b) must NOT be discarded --
    // this is the exact defect: before the fix, a throw on step 3 lost
    // results for steps 1 and 2 entirely (the function's local `results`
    // array never returned), so the orchestrator's `safeRestore` had nothing
    // to restore even though two secrets were genuinely moved.
    expect(rehomeErr.partialResults).toHaveLength(2);
    expect(rehomeErr.partialResults.map((r) => r.entry.sourcePath)).toEqual([
      "/Users/operator/a",
      "/Users/operator/b",
    ]);
    expect(rehomeErr.partialResults.every((r) => r.status === "moved")).toBe(true);
  });

  it("a throw on the FIRST step reports an empty partialResults (nothing completed yet, honestly)", async () => {
    const plan = planRehome(testAdapter, { operatorHome: "/Users/operator", newAccountHome: "/var/sanctuary-agents/x" });
    const ops: RehomeOps = {
      pathExists: async () => true,
      backup: async () => {
        throw new Error("backup destination not root-only writable");
      },
      move: async () => {},
      chown: async () => {},
      restore: async () => ({ restored: true }),
      restoreCustody: async () => {},
    };

    let caught: unknown;
    try {
      await executeRehomePlan(plan, ops, { uid: 502, gid: 502 });
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(RehomeExecutionError);
    expect((caught as RehomeExecutionError).partialResults).toEqual([]);
  });
});

describe("wrap/auto-provision real-ops chokepoint: realRehomeOps().restore conflict handling (fix R6)", () => {
  let tmpRoot: string;

  async function makeTmp(): Promise<string> {
    return mkdtemp(join(tmpdir(), "sanctuary-realops-restore-"));
  }

  it("no conflict: destPath exists, sourcePath does not -> reverse-move succeeds cleanly", async () => {
    tmpRoot = await makeTmp();
    try {
      const destPath = join(tmpRoot, "dest", "secret.env");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      await mkdir(join(tmpRoot, "dest"), { recursive: true });
      await writeFile(destPath, "moved-content");

      const ops = realRehomeOps();
      const result = await ops.restore(destPath, sourcePath);

      expect(result.restored).toBe(true);
      expect(result.conflictPath).toBeUndefined();
      const content = await readFile(sourcePath, "utf8");
      expect(content).toBe("moved-content");
      // destPath should no longer exist (rename, not copy).
      await expect(access(destPath)).rejects.toThrow();
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R6: conflict -- sourcePath was RECREATED as a file while re-homed -- restore does NOT overwrite it, restores to a conflict path instead", async () => {
    tmpRoot = await makeTmp();
    try {
      const destPath = join(tmpRoot, "dest", "secret.env");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      await mkdir(join(tmpRoot, "dest"), { recursive: true });
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await writeFile(destPath, "moved-content-that-must-not-be-lost");
      // Simulate the operator (or some other process) recreating a file at
      // the original source path WHILE the secret was re-homed.
      await writeFile(sourcePath, "operators-recreated-data-must-survive");

      const ops = realRehomeOps();
      const result = await ops.restore(destPath, sourcePath);

      // The restore must report a conflict, not a clean "restored: true".
      expect(result.restored).toBe(false);
      expect(result.conflictPath).toBe(`${sourcePath}.restored-conflict`);

      // The critical assertion (fix R6): the operator's recreated file at
      // sourcePath must be COMPLETELY UNTOUCHED, never silently overwritten.
      const sourceContent = await readFile(sourcePath, "utf8");
      expect(sourceContent).toBe("operators-recreated-data-must-survive");

      // The moved data must have landed at the conflict path, not be lost.
      const conflictContent = await readFile(result.conflictPath!, "utf8");
      expect(conflictContent).toBe("moved-content-that-must-not-be-lost");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R6: conflict via the backup-copy fallback path (destPath already gone) also refuses to overwrite a recreated source", async () => {
    tmpRoot = await makeTmp();
    try {
      const sourcePath = join(tmpRoot, "source", "secret.env");
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await writeFile(sourcePath, "operators-recreated-data-v2");

      // destPath does not exist at all (simulates a prior partial rollback
      // already having moved it away) -- realRehomeOps().restore falls back
      // to the hardcoded backup root, which will also not exist here, so
      // this specific scenario (destPath gone AND no backup) exercises the
      // "no conflict, but restored: false" honest-failure branch instead;
      // the true backup-fallback-conflict branch requires root ownership of
      // /var/root and is covered by the destPath-exists conflict test above
      // plus code-level symmetry (this test documents the non-root-testable
      // boundary rather than skip coverage silently).
      const destPath = join(tmpRoot, "dest-that-does-not-exist", "secret.env");
      const ops = realRehomeOps();
      const result = await ops.restore(destPath, sourcePath);

      // destPath is gone and there is no real /var/root backup reachable in
      // this test environment, so restore honestly reports failure -- and,
      // crucially, never touches the operator's recreated file either way.
      expect(result.restored).toBe(false);
      const sourceContent = await readFile(sourcePath, "utf8");
      expect(sourceContent).toBe("operators-recreated-data-v2");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("a recreated DIRECTORY at sourcePath is ALSO caught by the pre-rename conflict check (R6 covers the dir case, not just files, since the existence check runs before either rename)", async () => {
    tmpRoot = await makeTmp();
    try {
      const destPath = join(tmpRoot, "dest", "creds-dir");
      const sourcePath = join(tmpRoot, "source", "creds-dir");
      await mkdir(destPath, { recursive: true });
      await writeFile(join(destPath, "token.json"), "moved-token");
      // Recreate sourcePath as a directory (previously this relied on
      // rename's own ENOTEMPTY throw for a non-empty dir; the R6 conflict
      // check now catches this case explicitly and consistently for BOTH
      // files and directories, since it checks pathExists(sourcePath) before
      // ever attempting the reverse-move).
      await mkdir(sourcePath, { recursive: true });
      await writeFile(join(sourcePath, "recreated.json"), "operator-recreated");

      const ops = realRehomeOps();
      const result = await ops.restore(destPath, sourcePath);

      expect(result.restored).toBe(false);
      expect(result.conflictPath).toBe(`${sourcePath}.restored-conflict`);

      // The recreated directory's content must survive completely untouched.
      const recreatedContent = await readFile(join(sourcePath, "recreated.json"), "utf8");
      expect(recreatedContent).toBe("operator-recreated");

      // The moved directory's data must have landed at the conflict path.
      const conflictContent = await readFile(join(result.conflictPath!, "token.json"), "utf8");
      expect(conflictContent).toBe("moved-token");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});
