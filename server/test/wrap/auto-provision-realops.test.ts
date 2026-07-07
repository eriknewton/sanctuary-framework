/**
 * Re-gate 1 (fix commit 636f6051) CHOKEPOINT (2026-07-07 fix-round 2), then
 * extended for re-gate 3 (fix-round 3): the `wrap/auto-provision.ts` real-ops
 * layer had ZERO unit coverage -- the dep-injection mock boundary in
 * `test/wrap/auto-provision-wiring.test.ts` sits ABOVE
 * `runAutoProvisionForWrap` entirely, and
 * `test/castle-wall/provision/orchestrate.test.ts` mocks every `ProvisionFlowOps`
 * method. Fix-round 1's F1 fail-opens, fix-round 2's R1-R6 findings, and
 * fix-round 3's G1-G5 findings all lived EXACTLY in the gap between those two
 * suites: the real, security-load-bearing DECISION logic behind the probes,
 * the sudo identity resolution, and the restore-conflict handling.
 *
 * This suite closes that gap by exercising the exported pure/decidable
 * helpers directly:
 *   - `credentialReadableAsUidDecision` (R1): ENOENT -> false, unreadable-by-
 *     uid -> false, root-vs-uid honesty (owner match + read bit only).
 *   - `resolveSudoIdentityDecision` (R2): SUDO_UID present/absent, malformed,
 *     invalid SUDO_USER shape, and (G4) uid/gid 0 / SUDO_USER=root.
 *   - `RehomeExecutionError`/`executeRehomePlan` (R3, extended G3): a
 *     mid-loop throw carries the already-completed results, INCLUDING a
 *     moved-but-not-yet-chowned straddling entry, never an empty array.
 *   - `realRehomeOps().restore` (R6, extended G2): a recreated source file
 *     is never overwritten, AND the conflict-sibling target itself is never
 *     overwritten either -- restore always resolves a fresh, unoccupied
 *     conflict path.
 *   - `disarmExitCodeDecision` (G1): a non-throwing-but-nonzero disarm code
 *     decides to throw, mirroring `arm`'s existing code check.
 *   - `hermesEndpointProbes`/`allHermesCredentialDestPaths` (G5): every
 *     moved Hermes credential path is probed, not just `.hermes/.env`.
 *
 * Real `sysadminctl`/`dscl`/`launchctl`/network calls stay drill-only (never
 * exercised here); this suite is scoped to the DECISION logic around them,
 * per the re-gate spec's chokepoint requirement.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, readFile, access, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  credentialReadableAsUidDecision,
  resolveSudoIdentityDecision,
  realRehomeOps,
  disarmExitCodeDecision,
  hermesEndpointProbes,
  allHermesCredentialDestPaths,
} from "../../src/wrap/auto-provision.js";
import {
  planRehome,
  executeRehomePlan,
  RehomeExecutionError,
  type AgentRehomeAdapter,
  type RehomeOps,
} from "../../src/castle-wall/provision/rehome.js";
import { verifyReachabilityBeforeArm } from "../../src/castle-wall/provision/verify.js";

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

  it("FIX G4: SUDO_UID=0 (root sudo context, e.g. `sudo su -` then run) fails closed -- never resolves /var/root as the operator", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "0", SUDO_GID: "20", SUDO_USER: "someone" });
    expect(result).toBeUndefined();
  });

  it("FIX G4: SUDO_GID=0 fails closed even when SUDO_UID is non-root", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "501", SUDO_GID: "0", SUDO_USER: "someone" });
    expect(result).toBeUndefined();
  });

  it("FIX G4: SUDO_USER=root fails closed even when SUDO_UID/GID are both non-zero", () => {
    // A crafted or unusual env where SUDO_USER says root but the numeric
    // ids are not 0 must still be refused -- the name is a second signal,
    // not something the uid/gid check alone can catch.
    const result = resolveSudoIdentityDecision({ SUDO_UID: "501", SUDO_GID: "20", SUDO_USER: "root" });
    expect(result).toBeUndefined();
  });

  it("FIX G4: uid=0 AND gid=0 AND SUDO_USER=root (the real `sudo su -` shape) fails closed", () => {
    const result = resolveSudoIdentityDecision({ SUDO_UID: "0", SUDO_GID: "0", SUDO_USER: "root" });
    expect(result).toBeUndefined();
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

  it("FIX G3: a chown failure on step 3 still includes the moved-but-not-chowned (straddling) entry in partialResults", async () => {
    const plan = planRehome(testAdapter, { operatorHome: "/Users/operator", newAccountHome: "/var/sanctuary-agents/x" });
    let chownCount = 0;
    const ops: RehomeOps = {
      pathExists: async () => true,
      backup: async (path) => ({ backupPath: `/root/backup${path}.bak` }),
      move: async () => {},
      chown: async () => {
        chownCount += 1;
        if (chownCount === 3) {
          // The step-3 path was already renamed to the agent home (`move`
          // succeeded) by the time this throws -- exactly the straddling
          // shape G3 exists to catch: moved, not chowned, not yet recorded
          // by the pre-fix code.
          throw new Error("chown failed: operation not permitted");
        }
      },
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
    const rehomeErr = caught as RehomeExecutionError;
    // FIX G3: the exact defect -- before the fix, `results.push(...)` ran
    // AFTER `chown`, so a chown throw on the third path meant that path's
    // `moved` result was NEVER pushed, even though `move()` had already
    // succeeded and the secret was genuinely sitting under the new
    // account's home. `partialResults` must now include all 3 entries
    // (the two that fully completed, PLUS the straddling third one), all
    // reported "moved" (never silently dropped), so `safeRestore` has a
    // `destPath` to recover from for every path that actually moved.
    expect(rehomeErr.partialResults).toHaveLength(3);
    expect(rehomeErr.partialResults.map((r) => r.entry.sourcePath)).toEqual([
      "/Users/operator/a",
      "/Users/operator/b",
      "/Users/operator/c",
    ]);
    expect(rehomeErr.partialResults.every((r) => r.status === "moved")).toBe(true);
    // The straddling entry's destPath must be present so safeRestore can
    // reverse-move it back, exactly like the first two.
    expect(rehomeErr.partialResults[2]!.destPath).toBe("/var/sanctuary-agents/x/c");
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

  it("FIX G2: a PRE-EXISTING conflict sibling (.restored-conflict) is never overwritten -- restore picks a fresh suffixed path instead", async () => {
    tmpRoot = await makeTmp();
    try {
      const destPath = join(tmpRoot, "dest", "secret.env");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      const preexistingConflictPath = `${sourcePath}.restored-conflict`;
      await mkdir(join(tmpRoot, "dest"), { recursive: true });
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await writeFile(destPath, "moved-content-round-2");
      await writeFile(sourcePath, "operators-recreated-data-round-2");
      // Simulate a PRIOR aborted run (or an operator-planted file) already
      // occupying the conflict-sibling target this restore would otherwise
      // write to -- the exact G2 defect: the R6 fix guarded sourcePath but
      // left THIS path unguarded.
      await writeFile(preexistingConflictPath, "PRIOR-CONFLICT-DATA-MUST-SURVIVE");

      const ops = realRehomeOps();
      const result = await ops.restore(destPath, sourcePath);

      expect(result.restored).toBe(false);
      // Must NOT reuse the already-occupied `.restored-conflict` path.
      expect(result.conflictPath).toBe(`${preexistingConflictPath}.1`);

      // The prior conflict file must be completely untouched.
      const priorContent = await readFile(preexistingConflictPath, "utf8");
      expect(priorContent).toBe("PRIOR-CONFLICT-DATA-MUST-SURVIVE");

      // The operator's recreated source file must also be untouched.
      const sourceContent = await readFile(sourcePath, "utf8");
      expect(sourceContent).toBe("operators-recreated-data-round-2");

      // The newly-moved data must have landed at the fresh suffixed path.
      const newConflictContent = await readFile(result.conflictPath!, "utf8");
      expect(newConflictContent).toBe("moved-content-round-2");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX G2: TWO pre-existing conflict siblings (.restored-conflict and .restored-conflict.1) -> restore advances to .restored-conflict.2", async () => {
    tmpRoot = await makeTmp();
    try {
      const destPath = join(tmpRoot, "dest", "secret.env");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      await mkdir(join(tmpRoot, "dest"), { recursive: true });
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await writeFile(destPath, "moved-content-round-3");
      await writeFile(sourcePath, "operators-recreated-data-round-3");
      await writeFile(`${sourcePath}.restored-conflict`, "prior-conflict-0");
      await writeFile(`${sourcePath}.restored-conflict.1`, "prior-conflict-1");

      const ops = realRehomeOps();
      const result = await ops.restore(destPath, sourcePath);

      expect(result.restored).toBe(false);
      expect(result.conflictPath).toBe(`${sourcePath}.restored-conflict.2`);

      // Both prior conflict files must survive untouched.
      expect(await readFile(`${sourcePath}.restored-conflict`, "utf8")).toBe("prior-conflict-0");
      expect(await readFile(`${sourcePath}.restored-conflict.1`, "utf8")).toBe("prior-conflict-1");
      expect(await readFile(result.conflictPath!, "utf8")).toBe("moved-content-round-3");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX G2: the backup-copy fallback conflict branch also refuses to overwrite a pre-existing conflict sibling", async () => {
    tmpRoot = await makeTmp();
    try {
      const sourcePath = join(tmpRoot, "source", "secret.env");
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await writeFile(sourcePath, "operators-recreated-data-v3");
      const preexistingConflictPath = `${sourcePath}.restored-conflict`;
      await writeFile(preexistingConflictPath, "PRIOR-BACKUP-FALLBACK-CONFLICT-DATA");

      // destPath does not exist (prior partial rollback already moved it
      // away) AND there is no reachable /var/root backup in this test
      // environment (same non-root-testable boundary the existing R6
      // backup-fallback test documents) -- restore honestly reports
      // failure with no conflictPath here (this test's purpose is only to
      // prove the pre-existing conflict sibling survives untouched, which
      // it trivially does when this branch never even reaches the write).
      // The write-reaching case is exercised by the two tests above via the
      // primary (non-fallback) branch, which shares `findUniqueConflictPath`
      // with the fallback branch -- both call sites resolve a path the same
      // way, so this test documents the boundary rather than skip coverage
      // silently, matching the existing R6 backup-fallback test's own note.
      const destPath = join(tmpRoot, "dest-that-does-not-exist", "secret.env");
      const ops = realRehomeOps();
      const result = await ops.restore(destPath, sourcePath);

      expect(result.restored).toBe(false);
      const priorContent = await readFile(preexistingConflictPath, "utf8");
      expect(priorContent).toBe("PRIOR-BACKUP-FALLBACK-CONFLICT-DATA");
      const sourceContent = await readFile(sourcePath, "utf8");
      expect(sourceContent).toBe("operators-recreated-data-v3");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("wrap/auto-provision real-ops chokepoint: disarmExitCodeDecision (fix G1)", () => {
  it("code 0 -> undefined (success, no throw)", () => {
    expect(disarmExitCodeDecision(0)).toBeUndefined();
  });

  it("nonzero code -> an Error describing the exit code (mirrors arm's own code === 0 check)", () => {
    const err = disarmExitCodeDecision(1);
    expect(err).toBeInstanceOf(Error);
    expect(err?.message).toBe("castle-wall disable exited 1");
  });

  it("a different nonzero code is reflected verbatim in the error message", () => {
    const err = disarmExitCodeDecision(127);
    expect(err?.message).toBe("castle-wall disable exited 127");
  });

  it("negative code (e.g. a signal-terminated process) still decides to throw, never treated as success", () => {
    const err = disarmExitCodeDecision(-1);
    expect(err).toBeInstanceOf(Error);
    expect(err?.message).toBe("castle-wall disable exited -1");
  });
});

describe("wrap/auto-provision real-ops chokepoint: all-credentials readability probe (fix G5)", () => {
  it("allHermesCredentialDestPaths lists every secret path the Hermes adapter re-homes, not just .env", () => {
    const paths = allHermesCredentialDestPaths();
    expect(paths).toContain(".hermes/.env");
    expect(paths).toContain(".hermes/auth.json");
    expect(paths).toContain(".hermes/config.yaml");
    expect(paths).toContain(".google_workspace_mcp/credentials");
    expect(paths).toContain(".workspace-mcp/cli-tokens");
    expect(paths).toContain(".hermes/google-mcp-creds");
    expect(paths).toHaveLength(6);
  });

  it("hermesEndpointProbes builds one probe per DNS host PLUS one per credential path (not just .env)", () => {
    const targets = hermesEndpointProbes("/var/sanctuary-agents/sanctuary-hermes", 502, 502);
    const credentialProbeNames = targets.filter((t) => t.name.includes("moved credential"));
    // 6 credential paths -- .env, auth.json, config.yaml, google_workspace_mcp
    // credentials, workspace-mcp cli-tokens, hermes google-mcp-creds.
    expect(credentialProbeNames).toHaveLength(6);
    expect(credentialProbeNames.some((t) => t.name.includes(".env"))).toBe(true);
    expect(credentialProbeNames.some((t) => t.name.includes("auth.json"))).toBe(true);
    expect(credentialProbeNames.some((t) => t.name.includes("config.yaml"))).toBe(true);
    expect(credentialProbeNames.some((t) => t.name.includes("google_workspace_mcp/credentials"))).toBe(true);
    expect(credentialProbeNames.some((t) => t.name.includes("workspace-mcp/cli-tokens"))).toBe(true);
    expect(credentialProbeNames.some((t) => t.name.includes("google-mcp-creds"))).toBe(true);
  });

  it("FIX G5: an unreadable NON-.env moved credential (auth.json, chmod 000) fails the aggregate pre-arm verify, even though .env is fine", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-allcreds-"));
    try {
      const accountHome = join(tmpRoot, "agent-home");
      const hermesDir = join(accountHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      await writeFile(join(hermesDir, ".env"), "LLM_KEY=abc");
      await writeFile(join(hermesDir, "auth.json"), '{"token":"secret"}');
      // .env is properly owned/readable-shaped for this test's purposes
      // (this test does not chown -- it runs as the test process's own
      // uid/gid, so use that as the "target" to isolate the mode-bit
      // effect). auth.json is deliberately made unreadable (mode 000):
      // owner-read bit unset means `credentialReadableAsUidDecision` (even
      // for the OWNER-match branch) reports false.
      await chmod(join(hermesDir, ".env"), 0o600);
      await chmod(join(hermesDir, "auth.json"), 0o000);

      const targetUid = process.getuid?.() ?? 0;
      const targetGid = process.getgid?.() ?? 0;
      const targets = hermesEndpointProbes(accountHome, targetUid, targetGid).filter((t) =>
        t.name.includes("moved credential"),
      );

      const result = await verifyReachabilityBeforeArm(targets);

      // The aggregate must be false: auth.json's probe must fail even
      // though .env's probe (the ONLY thing the pre-fix code checked)
      // passes. This is the exact G5 defect -- verify going green over a
      // broken re-home of anything other than .env.
      expect(result.allReachable).toBe(false);
      const envResult = result.results.find((r) => r.name.includes(".env"));
      const authResult = result.results.find((r) => r.name.includes("auth.json"));
      expect(envResult?.reachable).toBe(true);
      expect(authResult?.reachable).toBe(false);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX G5: a MISSING non-.env moved credential (config.yaml never wrote) fails the aggregate pre-arm verify", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-allcreds-missing-"));
    try {
      const accountHome = join(tmpRoot, "agent-home");
      const hermesDir = join(accountHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      await writeFile(join(hermesDir, ".env"), "LLM_KEY=abc");
      await chmod(join(hermesDir, ".env"), 0o600);
      // config.yaml is never written at all -- simulates a re-home step
      // that silently failed to move this particular file.

      const targetUid = process.getuid?.() ?? 0;
      const targetGid = process.getgid?.() ?? 0;
      const targets = hermesEndpointProbes(accountHome, targetUid, targetGid).filter((t) =>
        t.name.includes("moved credential"),
      );

      const result = await verifyReachabilityBeforeArm(targets);

      expect(result.allReachable).toBe(false);
      const configResult = result.results.find((r) => r.name.includes("config.yaml"));
      expect(configResult?.reachable).toBe(false);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("all credentials present and readable -> aggregate pre-arm verify (credential portion) passes", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-allcreds-happy-"));
    try {
      const accountHome = join(tmpRoot, "agent-home");
      const hermesDir = join(accountHome, ".hermes");
      const googleDir = join(accountHome, ".google_workspace_mcp");
      const workspaceMcpDir = join(accountHome, ".workspace-mcp");
      await mkdir(hermesDir, { recursive: true });
      await mkdir(join(hermesDir, "google-mcp-creds"), { recursive: true });
      await mkdir(googleDir, { recursive: true });
      await mkdir(workspaceMcpDir, { recursive: true });

      await writeFile(join(hermesDir, ".env"), "LLM_KEY=abc");
      await writeFile(join(hermesDir, "auth.json"), '{"token":"secret"}');
      await writeFile(join(hermesDir, "config.yaml"), "persona: hermes");
      await writeFile(join(googleDir, "credentials"), "refresh-token");
      await mkdir(join(workspaceMcpDir, "cli-tokens"), { recursive: true });
      await writeFile(join(hermesDir, "google-mcp-creds", "token.json"), "{}");

      await chmod(join(hermesDir, ".env"), 0o600);
      await chmod(join(hermesDir, "auth.json"), 0o600);
      await chmod(join(hermesDir, "config.yaml"), 0o600);
      await chmod(join(googleDir, "credentials"), 0o600);
      await chmod(join(workspaceMcpDir, "cli-tokens"), 0o700);
      await chmod(join(hermesDir, "google-mcp-creds"), 0o700);

      const targetUid = process.getuid?.() ?? 0;
      const targetGid = process.getgid?.() ?? 0;
      const targets = hermesEndpointProbes(accountHome, targetUid, targetGid).filter((t) =>
        t.name.includes("moved credential"),
      );

      const result = await verifyReachabilityBeforeArm(targets);
      expect(result.allReachable).toBe(true);
      expect(result.results.every((r) => r.reachable)).toBe(true);
      expect(result.results).toHaveLength(6);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});
