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

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, readFile, access, chmod, lstat, stat, symlink, readlink, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";

import {
  credentialReadableAsUidDecision,
  pathTraversableByUidDecision,
  ancestorsTraversableByUid,
  parseDsclSearchAccountNames,
  resolveSudoIdentityDecision,
  realRehomeOps,
  disarmExitCodeDecision,
  hermesEndpointProbes,
  allHermesCredentialDestPaths,
  resolveCredentialDestPathsToVerify,
  resolveWallFortressPath,
  resolveHarnessDaemonLogDir,
  hermesRuntimeRehomePaths,
  moveAsideStaleHermesRuntimeDestination,
  policyDaemonInstallBootArgs,
  resolvePolicyDaemonActionForAutoProvision,
  decideDsclAttributeRead,
  decideDsclRecordRead,
  dsclDiagnostic,
  runLaunchctlWithTimeout,
  LAUNCHCTL_TIMEOUT_MS,
  LAUNCHCTL_KILL_SIGNAL,
  runAgentEgressProbesAsUid,
  buildHermesExclusiveCliWiring,
  describeRepairCoarseComposition,
  resolveGateDaemonArgvPrefix,
  resolveProvisionedAgentHome,
} from "../../src/wrap/auto-provision.js";
import { HERMES_ENDPOINT_SET } from "../../src/castle-wall/provision/egress.js";
import { harnessLaunchSpec } from "../../src/egress-gate/harness-daemon.js";
import {
  planRehome,
  planBrainRehome,
  executeRehomePlan,
  executeBrainRehomePlan,
  restoreRehomeSteps,
  RehomeExecutionError,
  type AgentRehomeAdapter,
  type RehomeOps,
} from "../../src/castle-wall/provision/rehome.js";
import { verifyReachabilityBeforeArm } from "../../src/castle-wall/provision/verify.js";

describe("wrap/auto-provision real-ops chokepoint: dscl read classifiers (fix round-3 B1)", () => {
  it("distinguishes an absent attribute from an absent record when No such key is on stderr with exit 0", () => {
    expect(
      decideDsclAttributeRead("UniqueID", {
        code: 0,
        stdout: "",
        stderr: "No such key: UniqueID\n",
      }),
    ).toEqual({ kind: "attribute-absent" });
    expect(
      decideDsclRecordRead({
        code: 0,
        stdout: "RecordName: sanctuary-hermes\n",
        stderr: "",
      }),
    ).toBe("present");
  });

  it("recognizes absent records from dscl eDSRecordNotFound diagnostics", () => {
    const absent = {
      code: 56,
      stdout: "",
      stderr: "/usr/bin/dscl DS Error: -14136 (eDSRecordNotFound)\n",
    };
    expect(decideDsclRecordRead(absent)).toBe("record-absent");
    expect(decideDsclAttributeRead("UniqueID", absent)).toEqual({ kind: "record-absent" });
  });

  it("preserves the full attribute value instead of truncating at the first space", () => {
    expect(
      decideDsclAttributeRead("NFSHomeDirectory", {
        code: 0,
        stdout: "NFSHomeDirectory: /var/sanctuary agents/sanctuary-hermes\n",
        stderr: "",
      }),
    ).toEqual({ kind: "value", value: "/var/sanctuary agents/sanctuary-hermes" });
  });

  it("S5 drill: parses the native IsHidden capture without losing absent-record classifications or suffix anchoring", () => {
    // Captured from the drill host with od -c: dsAttrTypeNative:IsHidden: 1\n.
    const capturedNativeIsHiddenStdout = "dsAttrTypeNative:IsHidden: 1\n";
    expect(Buffer.byteLength(capturedNativeIsHiddenStdout, "utf8")).toBe(29);
    expect(
      decideDsclAttributeRead("IsHidden", {
        code: 0,
        stdout: capturedNativeIsHiddenStdout,
        stderr: "",
      }),
    ).toEqual({ kind: "value", value: "1" });
    expect(
      decideDsclAttributeRead("IsHidden", {
        code: 0,
        stdout: "IsHidden: 1\n",
        stderr: "",
      }),
    ).toEqual({ kind: "value", value: "1" });
    expect(
      decideDsclAttributeRead("IsHidden", {
        code: 0,
        stdout: "",
        stderr: "No such key: IsHidden\n",
      }),
    ).toEqual({ kind: "attribute-absent" });
    expect(
      decideDsclAttributeRead("IsHidden", {
        code: 56,
        stdout: "",
        stderr: "/usr/bin/dscl DS Error: -14136 (eDSRecordNotFound)\n",
      }),
    ).toEqual({ kind: "record-absent" });
    expect(
      decideDsclAttributeRead("IsHidden", {
        code: 0,
        stdout: "NotIsHidden: 1\n",
        stderr: "",
      }).kind,
    ).toBe("unknown");
  });

  it("S5 drill: diagnoses the native IsHidden capture as an attribute line", () => {
    const capturedNativeIsHiddenStdout = "dsAttrTypeNative:IsHidden: 1\n";
    const diagnostic = dsclDiagnostic({
      code: 0,
      stdout: capturedNativeIsHiddenStdout,
      stderr: "",
    });
    expect(diagnostic).toContain("stdout: 29 bytes");
    expect(diagnostic).toContain("attributes=[IsHidden]");
    expect(diagnostic).not.toContain("unclassified-lines");
  });

  it("diagnoses an underscore-prefixed native attribute rather than calling it residue", () => {
    // Real macOS emits native attributes whose names begin with an underscore,
    // e.g. `dscl . -read /Users/<x> _writers_passwd`. Naming no attribute here
    // is what sent an operator to repair a healthy account on 2026-07-20.
    const diagnostic = dsclDiagnostic({
      code: 0,
      stdout: "dsAttrTypeNative:_writers_passwd: eriknewton\n",
      stderr: "",
    });
    expect(diagnostic).toContain("attributes=[_writers_passwd]");
    expect(diagnostic).not.toContain("unclassified-lines");
  });

  it("still counts genuinely unparseable dscl output as residue", () => {
    // The fail-closed property must survive widening the attribute charclass.
    expect(dsclDiagnostic({ code: 0, stdout: "total nonsense here\n", stderr: "" })).toContain(
      "unclassified-lines=1",
    );
    expect(
      dsclDiagnostic({
        code: 0,
        stdout: "dsAttrTypeNative:dsAttrTypeNative:IsHidden: 1\n",
        stderr: "",
      }),
    ).toContain("unclassified-lines=1");
  });

  it("returns unknown rather than claiming absence on unclassified dscl output", () => {
    expect(
      decideDsclRecordRead({
        code: 5,
        stdout: "",
        stderr: "DirectoryService daemon unavailable",
      }),
    ).toBe("unknown");
    expect(
      decideDsclAttributeRead("UserShell", {
        code: 0,
        stdout: "",
        stderr: "",
      }),
    ).toEqual({ kind: "unknown", diagnostic: "" });
  });

  it("B4: the existence probe reads only UniqueID, never the whole account record", async () => {
    const source = await readFile(new URL("../../src/wrap/auto-provision.ts", import.meta.url), "utf8");
    expect(source).toContain('[".", "-read", `/Users/${accountName}`, "UniqueID"]');
    expect(source).not.toMatch(
      /dsclReadResult\(\[\s*"\.",\s*"-read",\s*`\/Users\/\$\{accountName\}`\s*\]\)/,
    );
  });

  it("A3: agent account creation has a direct candidate-uid observation and excluded-uid backstop", async () => {
    const source = await readFile(new URL("../../src/wrap/auto-provision.ts", import.meta.url), "utf8");
    expect(source).toContain("excludedUids: excludedAgentAccountUids");
    expect(source).toContain("lookupAccountNamesByUid: async (uid: number)");
    expect(source).toContain('[".", "-search", "/Users", "UniqueID", String(uid)]');
    expect(source).toContain("...(runningAgentUid !== undefined ? [runningAgentUid] : [])");
    expect(source).not.toContain('accountShapeVerdict !== "verified-dedicated" ? [candidateUid] : []');
  });

  it("B4: an execFile maxBuffer overflow is explicit unknown, not a normal exit-1 record absence", () => {
    expect(
      decideDsclRecordRead({
        code: 1,
        execErrorCode: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
        stdout: "AuthenticationAuthority: secret-aa\n",
        stderr: "",
      }),
    ).toBe("unknown");
    const attributeDecision = decideDsclAttributeRead("UniqueID", {
      code: 1,
      execErrorCode: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
      stdout: "AuthenticationAuthority: secret-aa\n",
      stderr: "",
    });
    expect(attributeDecision.kind).toBe("unknown");
    if (attributeDecision.kind === "unknown") {
      expect(attributeDecision.diagnostic).toContain("exec-error=ERR_CHILD_PROCESS_STDIO_MAXBUFFER");
      expect(attributeDecision.diagnostic).toContain("attributes=[AuthenticationAuthority]");
      expect(attributeDecision.diagnostic).not.toContain("secret-aa");
    }
  });

  it("B4: dscl diagnostics summarize oversized records without leaking value payloads", () => {
    const hugeRecord = [
      "AuthenticationAuthority: super-secret-auth-authority",
      `JPEGPhoto: ${"A".repeat(1024 * 1024)}`,
      "GeneratedUID: generated-secret-value",
      "ShadowHashData: salted-sha512-password-verifier",
    ].join("\n");
    const diagnostic = dsclDiagnostic({
      code: 1,
      execErrorCode: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
      stdout: hugeRecord,
      stderr: "",
    });
    expect(diagnostic.length).toBeLessThanOrEqual(512);
    expect(diagnostic).toContain("exec-error=ERR_CHILD_PROCESS_STDIO_MAXBUFFER");
    expect(diagnostic).toContain("attributes=[AuthenticationAuthority");
    expect(diagnostic).toContain("GeneratedUID");
    expect(diagnostic).toContain("JPEGPhoto");
    expect(diagnostic).toContain("ShadowHashData");
    expect(diagnostic).not.toContain("super-secret-auth-authority");
    expect(diagnostic).not.toContain("generated-secret-value");
    expect(diagnostic).not.toContain("salted-sha512-password-verifier");
    expect(diagnostic).not.toContain("A".repeat(64));
  });

  it("B4: mixed diagnostics are unknown, not record-absent by any-match", () => {
    const mixed = {
      code: 56,
      stdout: "",
      stderr: "DirectoryService daemon unavailable\n/usr/bin/dscl DS Error: -14136 (eDSRecordNotFound)\n",
    };
    expect(decideDsclRecordRead(mixed)).toBe("unknown");
    expect(decideDsclAttributeRead("UniqueID", mixed).kind).toBe("unknown");
  });
});

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

  // FIX (round 5, item a): a directory-shaped credential needs the EXECUTE
  // (traverse) bit of its applicable class, not just the read bit -- a
  // read-only directory can be listed but not ENTERED, so the agent cannot
  // open the credential files inside it.
  it("FIX round-5(a): a DIRECTORY with owner read but NO owner-execute (mode 0600) -> false (unenterable)", () => {
    expect(credentialReadableAsUidDecision({ uid: 502, gid: 502, mode: 0o600, isDirectory: true }, 502)).toBe(false);
  });

  it("FIX round-5(a): a DIRECTORY with owner read AND owner-execute (mode 0700) -> true (enterable)", () => {
    expect(credentialReadableAsUidDecision({ uid: 502, gid: 502, mode: 0o700, isDirectory: true }, 502)).toBe(true);
  });

  it("FIX round-5(a): a DIRECTORY at mode 0500 (r-x, no write) is still enterable+readable -> true", () => {
    expect(credentialReadableAsUidDecision({ uid: 502, gid: 502, mode: 0o500, isDirectory: true }, 502)).toBe(true);
  });

  it("FIX round-5(a): a FILE at mode 0600 stays readable on the read bit alone (execute bit irrelevant for files)", () => {
    expect(credentialReadableAsUidDecision({ uid: 502, gid: 502, mode: 0o600, isDirectory: false }, 502)).toBe(true);
  });

  it("FIX round-5(a): a group-owned DIRECTORY needs group-execute too (mode 0640 = group r, no group x) -> false", () => {
    expect(credentialReadableAsUidDecision({ uid: 0, gid: 20, mode: 0o640, isDirectory: true }, 502, 20)).toBe(false);
  });

  it("FIX round-5(a): a group-owned DIRECTORY with group r+x (mode 0650) -> true", () => {
    expect(credentialReadableAsUidDecision({ uid: 0, gid: 20, mode: 0o650, isDirectory: true }, 502, 20)).toBe(true);
  });

  // POSIX class-exclusivity: a group member does NOT additionally inherit the
  // "other" bits. Before round 5, a group match with the group-read bit clear
  // fell through to the world-readable check and could overclaim readable.
  it("FIX round-5(a): group class is authoritative -- group match with NO group-read bit does NOT fall through to other-read (mode 0604, gid match) -> false", () => {
    expect(credentialReadableAsUidDecision({ uid: 0, gid: 20, mode: 0o604 }, 502, 20)).toBe(false);
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
      pathExistsNoFollow: async () => false,
      hashPath: async (path) => ({ algorithm: "sha256", value: `hash-${path}` }),
      readDestinationProvenance: async () => undefined,
      recordDestinationProvenance: async () => {},
      clearDestinationProvenance: async () => {},
      displaceDestination: async (destPath) => ({ displacedPath: `${destPath}.displaced-20260729T000000000Z` }),
      restoreDisplacedDestination: async () => ({ restored: true }),
      backup: async (path) => ({ backupPath: `/root/backup${path}.bak` }),
      removeSourceDuplicate: async () => undefined,
      restoreSourceDuplicate: async () => ({ restored: true }),
      move: async () => {
        moveCount += 1;
        if (moveCount === 3) {
          throw new Error("chown failed: operation not permitted");
        }
      },
      chown: async () => ({ excludedPaths: [] }),
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
      pathExistsNoFollow: async () => false,
      hashPath: async (path) => ({ algorithm: "sha256", value: `hash-${path}` }),
      readDestinationProvenance: async () => undefined,
      recordDestinationProvenance: async () => {},
      clearDestinationProvenance: async () => {},
      displaceDestination: async (destPath) => ({ displacedPath: `${destPath}.displaced-20260729T000000000Z` }),
      restoreDisplacedDestination: async () => ({ restored: true }),
      backup: async () => {
        throw new Error("backup destination not root-only writable");
      },
      removeSourceDuplicate: async () => undefined,
      restoreSourceDuplicate: async () => ({ restored: true }),
      move: async () => {},
      chown: async () => ({ excludedPaths: [] }),
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
      pathExistsNoFollow: async () => false,
      hashPath: async (path) => ({ algorithm: "sha256", value: `hash-${path}` }),
      readDestinationProvenance: async () => undefined,
      recordDestinationProvenance: async () => {},
      clearDestinationProvenance: async () => {},
      displaceDestination: async (destPath) => ({ displacedPath: `${destPath}.displaced-20260729T000000000Z` }),
      restoreDisplacedDestination: async () => ({ restored: true }),
      backup: async (path) => ({ backupPath: `/root/backup${path}.bak` }),
      removeSourceDuplicate: async () => undefined,
      restoreSourceDuplicate: async () => ({ restored: true }),
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
        return { excludedPaths: [] };
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

describe("F-9 Tier-M real-ops journal and parent-custody guards", () => {
  it("P0: auto-provision preflights Tier-M with the same prospective account home used by provision", async () => {
    expect(resolveProvisionedAgentHome("sanctuary-hermes")).toBe("/var/sanctuary-agents/sanctuary-hermes");

    const source = await readFile(new URL("../../src/wrap/auto-provision.ts", import.meta.url), "utf8");
    const accountHome = source.indexOf("const newAccountHome = resolveProvisionedAgentHome(accountName)");
    const preflightStart = source.indexOf("preflightBrainRehome: async () =>");
    const preflightOps = source.indexOf("realRehomeOps({ fortressPath: wallFortressPath, newAccountHome })", preflightStart);
    const preflightPlan = source.indexOf("planBrainRehome(hermesRehomeAdapter, { operatorHome, newAccountHome })", preflightStart);
    const preflightAssert = source.indexOf("assertBrainRehomePreflight(brainPlan, rehomeOps as BrainRehomeOps)", preflightStart);

    expect(accountHome).toBeGreaterThanOrEqual(0);
    expect(preflightStart).toBeGreaterThan(accountHome);
    expect(preflightOps).toBeGreaterThan(preflightStart);
    expect(preflightPlan).toBeGreaterThan(preflightStart);
    expect(preflightAssert).toBeGreaterThan(preflightPlan);
  });

  it("P0: auto-provision keeps the in-rehome open-journal assertion before the Tier-K move starts", async () => {
    const source = await readFile(new URL("../../src/wrap/auto-provision.ts", import.meta.url), "utf8");
    const rehomeStart = source.indexOf("rehome: async (uid, gid) =>");
    const tierKMove = source.indexOf("executeRehomePlan", rehomeStart);
    const journalPreflight = source.indexOf("assertNoOpenBrainRehomeJournal", rehomeStart);

    expect(rehomeStart).toBeGreaterThanOrEqual(0);
    expect(journalPreflight).toBeGreaterThan(rehomeStart);
    expect(journalPreflight).toBeLessThan(tierKMove);
  });

  it("P0: corrupt Tier-M journal is a hard refusal with the journal path, never treated as absent", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-brain-journal-corrupt-"));
    try {
      const fortressPath = join(tmpRoot, "fortress");
      const journalPath = join(fortressPath, "state", "rehome-brain-journal.json");
      await mkdir(dirname(journalPath), { recursive: true });
      await writeFile(journalPath, "{ not json");
      const ops = realRehomeOps({
        fortressPath,
        backupRoot: join(tmpRoot, "backups"),
        newAccountHome: join(tmpRoot, "account"),
      });

      await expect(ops.readBrainJournal()).rejects.toThrow(journalPath);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("P0: Tier-M staging cleanup refuses a symlinked ancestor before deleting a stale staging leaf", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-brain-stage-parent-"));
    try {
      const operatorHome = join(tmpRoot, "operator");
      const accountHome = join(tmpRoot, "account");
      const fortressPath = join(tmpRoot, "fortress");
      const backupRoot = join(tmpRoot, "backups");
      const sourcePath = join(operatorHome, "SOUL.md");
      const destPath = join(accountHome, ".hermes", "config.yaml");
      const stagingPath = `${destPath}.sanctuary-brain-stage-stage-guard`;
      const outside = join(tmpRoot, "outside");
      const outsideStagingPath = join(outside, basename(stagingPath));
      const adapter: AgentRehomeAdapter = {
        harnessId: "test-brain",
        pathsToRehome: () => [],
        brainPathsToRehome: () => [
          {
            tier: "mind",
            relPath: ".hermes/config.yaml",
            sourcePath,
            destRelativePath: ".hermes/config.yaml",
            kind: "file",
            required: true,
            isSecret: true,
            largeObject: false,
          },
        ],
        requiresInteractiveReconsent: () => false,
      };
      await mkdir(dirname(sourcePath), { recursive: true });
      await mkdir(dirname(destPath), { recursive: true });
      await mkdir(outside, { recursive: true });
      await writeFile(sourcePath, "agent-memory");
      await rm(dirname(destPath), { recursive: true, force: true });
      await symlink(outside, dirname(destPath));
      await writeFile(outsideStagingPath, "outside-must-survive");
      const plan = planBrainRehome(adapter, { operatorHome, newAccountHome: accountHome });
      const ops = realRehomeOps({ fortressPath, backupRoot, newAccountHome: accountHome });
      const uidGid = { uid: process.getuid?.() ?? 0, gid: process.getgid?.() ?? 0 };

      await expect(
        executeBrainRehomePlan(plan, ops, uidGid, { runId: "stage-guard" }),
      ).rejects.toThrow(/symlink|outside|refusing|too many levels/i);

      expect(await readFile(outsideStagingPath, "utf8")).toBe("outside-must-survive");
      expect(await readFile(sourcePath, "utf8")).toBe("agent-memory");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("P1: backup vault parent mutations refuse a symlinked ancestor instead of copying outside the vault", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-backup-parent-"));
    try {
      const sourcePath = join(tmpRoot, "operator", "SOUL.md");
      const backupRoot = join(tmpRoot, "backups");
      const outside = join(tmpRoot, "outside");
      await mkdir(dirname(sourcePath), { recursive: true });
      await mkdir(outside, { recursive: true });
      await writeFile(sourcePath, "agent-memory");
      const backupStem = `${backupRoot}${sourcePath}.bak-`;
      const symlinkedBackupParent = dirname(backupStem);
      await mkdir(dirname(symlinkedBackupParent), { recursive: true });
      await symlink(outside, symlinkedBackupParent);

      const ops = realRehomeOps({ backupRoot });

      await expect(ops.backup(sourcePath)).rejects.toThrow(/symlink|outside|refusing/i);
      expect(await readdir(outside)).toEqual([]);
      expect(await readFile(sourcePath, "utf8")).toBe("agent-memory");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("P1: displaced-destination backup parents refuse a symlinked ancestor instead of renaming outside the vault", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-displace-parent-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const accountHome = join(tmpRoot, "account");
      const destPath = join(accountHome, ".hermes", "config.yaml");
      const outside = join(tmpRoot, "outside");
      await mkdir(dirname(destPath), { recursive: true });
      await mkdir(outside, { recursive: true });
      await writeFile(destPath, "real-destination");
      const displacedStem = `${backupRoot}/.displaced${destPath}.displaced-`;
      const symlinkedDisplacedParent = dirname(displacedStem);
      await mkdir(dirname(symlinkedDisplacedParent), { recursive: true });
      await symlink(outside, symlinkedDisplacedParent);

      const ops = realRehomeOps({ backupRoot, newAccountHome: accountHome });

      await expect(ops.displaceDestination(destPath)).rejects.toThrow(/symlink|outside|refusing/i);
      expect(await readFile(destPath, "utf8")).toBe("real-destination");
      expect(await readdir(outside)).toEqual([]);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("P1: displaced-destination restore parents refuse a symlinked ancestor instead of renaming outside the account", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-restore-displace-parent-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const displacedPath = join(backupRoot, ".displaced", "config.yaml");
      const destParent = join(tmpRoot, "account", ".hermes");
      const destPath = join(destParent, "config.yaml");
      const outside = join(tmpRoot, "outside");
      await mkdir(dirname(displacedPath), { recursive: true });
      await mkdir(dirname(destParent), { recursive: true });
      await mkdir(outside, { recursive: true });
      await writeFile(displacedPath, "real-destination");
      await symlink(outside, destParent);

      const ops = realRehomeOps({ backupRoot });

      await expect(ops.restoreDisplacedDestination(displacedPath, destPath)).rejects.toThrow(/symlink|outside|refusing/i);
      expect(await readFile(displacedPath, "utf8")).toBe("real-destination");
      expect(await readdir(outside)).toEqual([]);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("install-preflight Build 2 re-home custody real-ops fixtures", () => {
  const uidGid = { uid: process.getuid?.() ?? 0, gid: process.getgid?.() ?? 0 };

  function singleConfigAdapter(): AgentRehomeAdapter {
    return {
      harnessId: "hermes",
      pathsToRehome: (home) => [
        { sourcePath: join(home, ".hermes", "config.yaml"), destRelativePath: ".hermes/config.yaml", isSecret: true },
      ],
      requiresInteractiveReconsent: () => false,
    };
  }

  it("F-7/F-8 incident: rerun with a fresh source stub and existing real destination refuses before backup/move, leaving the real backup untouched", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-b2-incident-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const operatorHome = join(tmpRoot, "operator");
      const accountHome = join(tmpRoot, "account");
      const sourcePath = join(operatorHome, ".hermes", "config.yaml");
      const destPath = join(accountHome, ".hermes", "config.yaml");
      await mkdir(dirname(sourcePath), { recursive: true });
      await writeFile(sourcePath, "REAL_CONFIG_WITH_SECRET=one");

      const ops = realRehomeOps({ backupRoot });
      const plan = planRehome(singleConfigAdapter(), { operatorHome, newAccountHome: accountHome });
      const first = await executeRehomePlan(plan, ops, uidGid);
      const realBackupPath = first[0]!.backupPath!;
      expect(await readFile(destPath, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=one");
      expect(await readFile(realBackupPath, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=one");

      // Simulate the real Mini2 incident's pre-Build-2 state: the destination
      // is a prior re-home product, but no provenance record exists yet.
      await ops.clearDestinationProvenance(sourcePath, destPath);
      await mkdir(dirname(sourcePath), { recursive: true });
      await writeFile(sourcePath, "stub: true\n");

      await expect(executeRehomePlan(plan, ops, uidGid)).rejects.toThrow(/re-home destination conflict/);

      expect(await readFile(destPath, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=one");
      expect(await readFile(sourcePath, "utf8")).toBe("stub: true\n");
      expect(await readFile(realBackupPath, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=one");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("--overwrite-destination preserves the displaced destination and restores it on a forced later abort through the real restore path", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-b2-overwrite-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const operatorHome = join(tmpRoot, "operator");
      const accountHome = join(tmpRoot, "account");
      const sourcePath = join(operatorHome, ".hermes", "config.yaml");
      const destPath = join(accountHome, ".hermes", "config.yaml");
      await mkdir(dirname(sourcePath), { recursive: true });
      await mkdir(dirname(destPath), { recursive: true });
      await writeFile(sourcePath, "stub: true\n");
      await writeFile(destPath, "REAL_CONFIG_WITH_SECRET=two");

      const ops = realRehomeOps({ backupRoot });
      const plan = planRehome(singleConfigAdapter(), { operatorHome, newAccountHome: accountHome });
      const results = await executeRehomePlan(plan, ops, uidGid, { overwriteDestination: true });

      expect(results[0]?.status).toBe("moved");
      expect(results[0]?.displacedDestinationPath).toMatch(/\.displaced-\d{8}T\d{9}Z$/);
      expect(results[0]?.displacedDestinationPath?.startsWith(`${backupRoot}/.displaced`)).toBe(true);
      expect(dirname(results[0]!.displacedDestinationPath!)).not.toBe(dirname(destPath));
      expect(await readFile(results[0]!.displacedDestinationPath!, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=two");
      expect(await readFile(destPath, "utf8")).toBe("stub: true\n");

      const restore = await restoreRehomeSteps(results, ops, uidGid);

      expect(restore.fullyRestored).toBe(true);
      expect(await readFile(sourcePath, "utf8")).toBe("stub: true\n");
      expect(await readFile(destPath, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=two");
      await expect(access(results[0]!.displacedDestinationPath!)).rejects.toThrow();
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("destination-authoritative rerun backs up and removes the duplicate operator secret source", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-b2-authoritative-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const operatorHome = join(tmpRoot, "operator");
      const accountHome = join(tmpRoot, "account");
      const sourcePath = join(operatorHome, ".hermes", "config.yaml");
      const destPath = join(accountHome, ".hermes", "config.yaml");
      await mkdir(dirname(sourcePath), { recursive: true });
      await writeFile(sourcePath, "REAL_CONFIG_WITH_SECRET=authoritative");

      const ops = realRehomeOps({ backupRoot });
      const plan = planRehome(singleConfigAdapter(), { operatorHome, newAccountHome: accountHome });
      const first = await executeRehomePlan(plan, ops, uidGid);
      expect(first[0]?.status).toBe("moved");
      expect(await readFile(destPath, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=authoritative");

      await mkdir(dirname(sourcePath), { recursive: true });
      await writeFile(sourcePath, "REAL_CONFIG_WITH_SECRET=authoritative");
      const second = await executeRehomePlan(plan, ops, uidGid);

      expect(second[0]?.status).toBe("destination-authoritative");
      expect(second[0]?.sourceDuplicateRemoved).toBe(true);
      expect(second[0]?.backupPath?.startsWith(backupRoot)).toBe(true);
      await expect(access(sourcePath)).rejects.toThrow();
      expect(await readFile(destPath, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=authoritative");
      expect(await readFile(second[0]!.backupPath!, "utf8")).toBe("REAL_CONFIG_WITH_SECRET=authoritative");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("restoreRehomeSteps consumes the recorded versioned backupPath through the real restore path, not a recomputed .bak path", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-b2-backup-path-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const sourcePath = join(tmpRoot, "operator", ".hermes", "config.yaml");
      const destPath = join(tmpRoot, "account", ".hermes", "config.yaml");
      await mkdir(dirname(sourcePath), { recursive: true });
      await writeFile(sourcePath, "VERSIONED_BACKUP_CONTENT");

      const ops = realRehomeOps({ backupRoot });
      const { backupPath } = await ops.backup(sourcePath);
      const legacyBak = `${backupRoot}${sourcePath}.bak`;
      await mkdir(dirname(legacyBak), { recursive: true });
      await writeFile(legacyBak, "WRONG_LEGACY_BACKUP");
      await rm(sourcePath, { force: true });

      const restore = await restoreRehomeSteps(
        [
          {
            entry: { sourcePath, destRelativePath: ".hermes/config.yaml", isSecret: true },
            destPath,
            status: "moved",
            backupPath,
          },
        ],
        ops,
        uidGid,
      );

      expect(restore.fullyRestored).toBe(true);
      expect(await readFile(sourcePath, "utf8")).toBe("VERSIONED_BACKUP_CONTENT");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("versioned backups are content-addressed and bounded by the per-source retention cap", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-b2-retention-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const sourcePath = join(tmpRoot, "operator", ".hermes", "config.yaml");
      await mkdir(dirname(sourcePath), { recursive: true });
      const ops = realRehomeOps({ backupRoot });
      let firstBackupName: string | undefined;

      for (let i = 0; i < 12; i++) {
        await writeFile(sourcePath, `secret-version-${i}`);
        const backup = await ops.backup(sourcePath);
        firstBackupName ??= basename(backup.backupPath);
      }

      const stem = `${backupRoot}${sourcePath}.bak-`;
      const names = await readdir(dirname(stem));
      const backupNames = names.filter((name) => name.startsWith(basename(stem)));
      expect(backupNames.length).toBeLessThanOrEqual(10);
      expect(firstBackupName).toBeDefined();
      expect(backupNames).toContain(firstBackupName!);
      expect(backupNames.every((name) => /\d{8}T\d{9}Z-[a-f0-9]{16}$/.test(name))).toBe(true);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("chownRecursive excludes a macOS TCC data-vault subtree, reports it, and the re-home fixture still completes", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-b2-datavault-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const operatorHome = join(tmpRoot, "operator");
      const accountHome = join(tmpRoot, "account");
      const sourcePath = join(operatorHome, ".hermes", "config.yaml");
      const dataVaultPath = join(accountHome, "Library", "Caches", "com.apple.containermanagerd");
      await mkdir(dirname(sourcePath), { recursive: true });
      await mkdir(dataVaultPath, { recursive: true });
      await writeFile(sourcePath, "REAL_CONFIG_WITH_SECRET=three");
      await writeFile(join(dataVaultPath, "blocked.db"), "tcc-vault");

      const ops = realRehomeOps({ backupRoot });
      const plan = planRehome(singleConfigAdapter(), { operatorHome, newAccountHome: accountHome });
      await executeRehomePlan(plan, ops, uidGid);
      const chownReport = await ops.chown(accountHome, uidGid.uid, uidGid.gid);

      expect(await readFile(join(accountHome, ".hermes", "config.yaml"), "utf8")).toBe("REAL_CONFIG_WITH_SECRET=three");
      expect(chownReport.excludedPaths).toContain(dataVaultPath);
      expect(await readFile(join(dataVaultPath, "blocked.db"), "utf8")).toBe("tcc-vault");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
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

  it("FIX round-5(b): a DANGLING symlink occupying the .restored-conflict target is never clobbered -- restore advances to .restored-conflict.1 (access() would have followed it and read it as free)", async () => {
    tmpRoot = await makeTmp();
    try {
      const destPath = join(tmpRoot, "dest", "secret.env");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      const conflictBase = `${sourcePath}.restored-conflict`;
      await mkdir(join(tmpRoot, "dest"), { recursive: true });
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await writeFile(destPath, "moved-content-symlink-round");
      await writeFile(sourcePath, "operators-recreated-data-symlink-round");
      // A DANGLING symlink: its target does not exist, so access()/stat()
      // (which follow symlinks) would report the conflict base as "does not
      // exist" and the pre-fix code would rename onto it, destroying it.
      // lstat (round-5 fix) sees the symlink itself and treats it as occupied.
      await symlink(join(tmpRoot, "nonexistent-target"), conflictBase);

      const ops = realRehomeOps();
      const result = await ops.restore(destPath, sourcePath);

      expect(result.restored).toBe(false);
      expect(result.conflictPath).toBe(`${conflictBase}.1`);

      // The dangling symlink must still be present and untouched.
      const linkStat = await lstat(conflictBase);
      expect(linkStat.isSymbolicLink()).toBe(true);
      expect(await readlink(conflictBase)).toBe(join(tmpRoot, "nonexistent-target"));

      expect(await readFile(sourcePath, "utf8")).toBe("operators-recreated-data-symlink-round");
      expect(await readFile(result.conflictPath!, "utf8")).toBe("moved-content-symlink-round");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX round-5(d): backup-copy FALLBACK restore (destPath gone) with an injected backupRoot restores cleanly when there is no conflict", async () => {
    tmpRoot = await makeTmp();
    try {
      const backupRoot = join(tmpRoot, "backups");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      const backupPath = `${backupRoot}${sourcePath}.bak`;
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await mkdir(dirname(backupPath), { recursive: true });
      await writeFile(backupPath, "backup-copy-content");

      const destPath = join(tmpRoot, "dest-that-does-not-exist", "secret.env");
      const ops = realRehomeOps({ backupRoot });
      const result = await ops.restore(destPath, sourcePath, backupPath);

      expect(result.restored).toBe(true);
      expect(result.conflictPath).toBeUndefined();
      expect(await readFile(sourcePath, "utf8")).toBe("backup-copy-content");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX round-5(d): backup-copy FALLBACK CONFLICT branch (now reachable via injected backupRoot) restores the backup to a fresh conflict path and NEVER overwrites the recreated source", async () => {
    tmpRoot = await makeTmp();
    try {
      const backupRoot = join(tmpRoot, "backups");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      const backupPath = `${backupRoot}${sourcePath}.bak`;
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await mkdir(dirname(backupPath), { recursive: true });
      await writeFile(backupPath, "backup-copy-content-must-not-be-lost");
      await writeFile(sourcePath, "operators-recreated-data-fallback-conflict");

      const destPath = join(tmpRoot, "dest-that-does-not-exist", "secret.env");
      const ops = realRehomeOps({ backupRoot });
      const result = await ops.restore(destPath, sourcePath, backupPath);

      expect(result.restored).toBe(false);
      expect(result.conflictPath).toBe(`${sourcePath}.restored-conflict`);
      expect(await readFile(sourcePath, "utf8")).toBe("operators-recreated-data-fallback-conflict");
      expect(await readFile(result.conflictPath!, "utf8")).toBe("backup-copy-content-must-not-be-lost");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX round-5(d): backup-copy FALLBACK CONFLICT branch also refuses to overwrite a PRE-EXISTING conflict sibling (advances to .restored-conflict.1)", async () => {
    tmpRoot = await makeTmp();
    try {
      const backupRoot = join(tmpRoot, "backups");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      const backupPath = `${backupRoot}${sourcePath}.bak`;
      const preexistingConflictPath = `${sourcePath}.restored-conflict`;
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      await mkdir(dirname(backupPath), { recursive: true });
      await writeFile(backupPath, "backup-copy-content-round-2");
      await writeFile(sourcePath, "operators-recreated-data-fallback-round-2");
      await writeFile(preexistingConflictPath, "PRIOR-FALLBACK-CONFLICT-DATA");

      const destPath = join(tmpRoot, "dest-that-does-not-exist", "secret.env");
      const ops = realRehomeOps({ backupRoot });
      const result = await ops.restore(destPath, sourcePath, backupPath);

      expect(result.restored).toBe(false);
      expect(result.conflictPath).toBe(`${preexistingConflictPath}.1`);
      expect(await readFile(preexistingConflictPath, "utf8")).toBe("PRIOR-FALLBACK-CONFLICT-DATA");
      expect(await readFile(sourcePath, "utf8")).toBe("operators-recreated-data-fallback-round-2");
      expect(await readFile(result.conflictPath!, "utf8")).toBe("backup-copy-content-round-2");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R9-1: the backup-copy FALLBACK restores a SYMLINK backup faithfully as a LINK (no dereference to a plain file) -- the last follow-semantics branch", async () => {
    tmpRoot = await makeTmp();
    try {
      const backupRoot = join(tmpRoot, "backups");
      const sourcePath = join(tmpRoot, "source", "secret.env");
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      // A live target the operator's symlinked credential pointed at.
      const realTarget = join(tmpRoot, "real-secret.env");
      await writeFile(realTarget, "SHARED-ROTATING-SECRET");
      // The backup is a SYMLINK (exactly what backup() stores for a symlinked
      // secret). destPath is gone -> the fallback branch handles it.
      const backupPath = `${backupRoot}${sourcePath}.bak`;
      await mkdir(dirname(backupPath), { recursive: true });
      await symlink(realTarget, backupPath);
      const destPath = join(tmpRoot, "dest-that-does-not-exist", "secret.env");

      const result = await realRehomeOps({ backupRoot }).restore(destPath, sourcePath, backupPath);

      expect(result.restored).toBe(true);
      // The credential must round-trip as a SYMLINK, NOT a dereferenced plain
      // file (which would silently stop tracking the shared/rotating target).
      const st = await lstat(sourcePath);
      expect(st.isSymbolicLink()).toBe(true);
      expect(await readlink(sourcePath)).toBe(realTarget);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("wrap/auto-provision real-ops chokepoint: stale Hermes runtime retry cleanup", () => {
  it("moves a stale non-secret Hermes runtime destination aside when the operator source also exists", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-stale-hermes-runtime-"));
    try {
      const operatorHome = join(tmpRoot, "operator");
      const accountHome = join(tmpRoot, "account");
      const { sourcePath, destPath } = hermesRuntimeRehomePaths(operatorHome, accountHome);
      await mkdir(sourcePath, { recursive: true });
      await mkdir(destPath, { recursive: true });
      await writeFile(join(sourcePath, "source.txt"), "operator-runtime");
      await writeFile(join(destPath, "stale.txt"), "stale-runtime");

      const conflictPath = await moveAsideStaleHermesRuntimeDestination(operatorHome, accountHome);

      expect(conflictPath).toBe(`${destPath}.restored-conflict`);
      await expect(access(destPath)).rejects.toThrow();
      expect(await readFile(join(sourcePath, "source.txt"), "utf8")).toBe("operator-runtime");
      expect(await readFile(join(conflictPath!, "stale.txt"), "utf8")).toBe("stale-runtime");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("does nothing when the operator Hermes runtime source is absent", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-stale-hermes-runtime-"));
    try {
      const operatorHome = join(tmpRoot, "operator");
      const accountHome = join(tmpRoot, "account");
      const { destPath } = hermesRuntimeRehomePaths(operatorHome, accountHome);
      await mkdir(destPath, { recursive: true });
      await writeFile(join(destPath, "stale.txt"), "stale-runtime");

      const conflictPath = await moveAsideStaleHermesRuntimeDestination(operatorHome, accountHome);

      expect(conflictPath).toBeUndefined();
      expect(await readFile(join(destPath, "stale.txt"), "utf8")).toBe("stale-runtime");
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

describe("wrap/auto-provision real-ops chokepoint: resolveWallFortressPath (Bug B, consistency)", () => {
  it("honors SANCTUARY_STORAGE_PATH when the operator set it (an explicit non-default fortress)", () => {
    expect(resolveWallFortressPath({ SANCTUARY_STORAGE_PATH: "/srv/fortress-a" }, "/Users/erik")).toBe(
      "/srv/fortress-a",
    );
  });

  it("falls back to the OPERATOR's home (never root's /var/root) when no override is set -- the sudo-aware R2-safe resolution", () => {
    // Under `sudo`, resolveStoragePath/os.homedir() would give /var/root/.sanctuary;
    // this must resolve the operator's own fortress instead.
    expect(resolveWallFortressPath({}, "/Users/erik")).toBe("/Users/erik/.sanctuary");
    expect(resolveWallFortressPath({}, "/Users/erik")).not.toMatch(/var\/root/);
  });

  it("treats an empty SANCTUARY_STORAGE_PATH as unset (falls back to the operator home)", () => {
    expect(resolveWallFortressPath({ SANCTUARY_STORAGE_PATH: "" }, "/Users/erik")).toBe("/Users/erik/.sanctuary");
  });

  it("strips a trailing slash on the operator home before appending .sanctuary", () => {
    expect(resolveWallFortressPath({}, "/Users/erik/")).toBe("/Users/erik/.sanctuary");
  });
});

describe("wrap/auto-provision real-ops chokepoint: resolveHarnessDaemonLogDir", () => {
  it("anchors harness daemon logs under the dedicated account home, not the operator fortress", () => {
    expect(resolveHarnessDaemonLogDir("/var/sanctuary-agents/sanctuary-hermes")).toBe(
      "/var/sanctuary-agents/sanctuary-hermes/logs",
    );
  });

  it("strips a trailing slash before appending logs", () => {
    expect(resolveHarnessDaemonLogDir("/var/sanctuary-agents/sanctuary-hermes/")).toBe(
      "/var/sanctuary-agents/sanctuary-hermes/logs",
    );
  });
});

describe("wrap/auto-provision real-ops chokepoint: policy daemon install-boot binary resolution", () => {
  it("passes the running CLI binary explicitly to install-boot so bundled installs do not rely on import.meta.url layout", () => {
    expect(policyDaemonInstallBootArgs("/Users/erik/.sanctuary", "/opt/sanctuary/dist/cli.js")).toEqual([
      "--fortress",
      "/Users/erik/.sanctuary",
      "--binary",
      "/opt/sanctuary/dist/cli.js",
    ]);
  });
});

describe("wrap/auto-provision real-ops chokepoint: policy daemon action wiring", () => {
  it("does not noop for a reachable socket when launchd is loaded for a different fortress (Bug E)", () => {
    const action = resolvePolicyDaemonActionForAutoProvision({
      socketReachable: true,
      diskForThisFortress: true,
      readyForThisFortress: false,
      plistPresent: true,
      loadedState: { loaded: true, fortressPath: "/Users/other/.sanctuary" },
      fortressPath: "/Users/operator/.sanctuary",
    });

    expect(action).toBe("refuse-conflict");
  });

  it("noops only for the same-fortress loaded service plus reachable socket when the stable-pid sample missed", () => {
    const action = resolvePolicyDaemonActionForAutoProvision({
      socketReachable: true,
      diskForThisFortress: true,
      readyForThisFortress: false,
      plistPresent: true,
      loadedState: { loaded: true, fortressPath: "/Users/operator/.sanctuary" },
      fortressPath: "/Users/operator/.sanctuary",
    });

    expect(action).toBe("noop");
  });
});

describe("wrap/auto-provision real-ops chokepoint: bounded launchctl wrapper", () => {
  it("passes timeout and SIGKILL to execFileAsync and maps a never-returning launchctl to failure", async () => {
    let observed:
      | { file: string; args: string[]; options: { timeout: number; killSignal: NodeJS.Signals } }
      | undefined;
    const neverReturningLaunchctl = async (
      file: string,
      args: string[],
      options: { timeout: number; killSignal: NodeJS.Signals },
    ): Promise<{ stdout: string; stderr: string }> => {
      observed = { file, args, options };
      const error = new Error("spawn /bin/launchctl ETIMEDOUT") as Error & {
        code: string;
        stdout: string;
        stderr: string;
      };
      error.code = "ETIMEDOUT";
      error.stdout = "";
      error.stderr = "";
      throw error;
    };

    const result = await runLaunchctlWithTimeout(
      ["bootout", "system/ai.sanctuaryprotocol.agent-harness"],
      neverReturningLaunchctl,
    );

    expect(observed).toEqual({
      file: "/bin/launchctl",
      args: ["bootout", "system/ai.sanctuaryprotocol.agent-harness"],
      options: { timeout: LAUNCHCTL_TIMEOUT_MS, killSignal: LAUNCHCTL_KILL_SIGNAL },
    });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("ETIMEDOUT");
  });
});

describe("wrap/auto-provision real-ops chokepoint: all-credentials readability probe (fix G5)", () => {
  it("allHermesCredentialDestPaths lists every secret path the Hermes adapter re-homes, not just .env", () => {
    const paths = allHermesCredentialDestPaths();
    expect(paths).toContain(".hermes/.env");
    expect(paths).toContain(".hermes/auth.json");
    expect(paths).toContain(".hermes/cli-config.json");
    expect(paths).toContain(".hermes/config.yaml");
    expect(paths).toContain(".google_workspace_mcp/credentials");
    expect(paths).toContain(".workspace-mcp/cli-tokens");
    expect(paths).toContain(".hermes/google-mcp-creds");
    expect(paths).toHaveLength(7);
  });

  it("hermesEndpointProbes builds one probe per DNS host PLUS one per credential path (not just .env)", () => {
    const targets = hermesEndpointProbes("/var/sanctuary-agents/sanctuary-hermes", 502, 502);
    const credentialProbeNames = targets.filter((t) => t.name.includes("moved credential"));
    // 7 credential paths -- .env, auth.json, cli-config.json, config.yaml,
    // google_workspace_mcp credentials, workspace-mcp cli-tokens, hermes google-mcp-creds.
    expect(credentialProbeNames).toHaveLength(7);
    expect(credentialProbeNames.some((t) => t.name.includes(".env"))).toBe(true);
    expect(credentialProbeNames.some((t) => t.name.includes("auth.json"))).toBe(true);
    expect(credentialProbeNames.some((t) => t.name.includes("cli-config.json"))).toBe(true);
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

  it("FIX round-5(a): a DIRECTORY-shaped moved credential at mode 0600 (readable but NOT traversable) fails the aggregate pre-arm verify end-to-end", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-dir-noexec-"));
    try {
      const accountHome = join(tmpRoot, "agent-home");
      const hermesDir = join(accountHome, ".hermes");
      const googleDir = join(accountHome, ".google_workspace_mcp");
      const workspaceMcpDir = join(accountHome, ".workspace-mcp");
      await mkdir(hermesDir, { recursive: true });
      await mkdir(join(hermesDir, "google-mcp-creds"), { recursive: true });
      await mkdir(googleDir, { recursive: true });
      await mkdir(workspaceMcpDir, { recursive: true });
      await mkdir(join(workspaceMcpDir, "cli-tokens"), { recursive: true });

      await writeFile(join(hermesDir, ".env"), "LLM_KEY=abc");
      await writeFile(join(hermesDir, "auth.json"), '{"token":"secret"}');
      await writeFile(join(hermesDir, "cli-config.json"), '{"legacy":true}');
      await writeFile(join(hermesDir, "config.yaml"), "persona: hermes");
      await writeFile(join(googleDir, "credentials"), "refresh-token");

      await chmod(join(hermesDir, ".env"), 0o600);
      await chmod(join(hermesDir, "auth.json"), 0o600);
      await chmod(join(hermesDir, "cli-config.json"), 0o600);
      await chmod(join(hermesDir, "config.yaml"), 0o600);
      await chmod(join(googleDir, "credentials"), 0o600);
      await chmod(join(workspaceMcpDir, "cli-tokens"), 0o700);
      // A DIRECTORY credential at mode 0600 (read, no execute): the agent
      // could not enter it to reach the files inside. Pre-round-5 the
      // read-bit-only decision reported this readable and verify went green.
      await chmod(join(hermesDir, "google-mcp-creds"), 0o600);

      const targetUid = process.getuid?.() ?? 0;
      const targetGid = process.getgid?.() ?? 0;
      const targets = hermesEndpointProbes(accountHome, targetUid, targetGid).filter((t) =>
        t.name.includes("moved credential"),
      );

      const result = await verifyReachabilityBeforeArm(targets);

      expect(result.allReachable).toBe(false);
      const dirResult = result.results.find((r) => r.name.includes("google-mcp-creds"));
      expect(dirResult?.reachable).toBe(false);
      const envResult = result.results.find((r) => r.name.includes(".env"));
      expect(envResult?.reachable).toBe(true);
    } finally {
      // Restore traversability so recursive cleanup can enter the dir.
      await chmod(join(tmpRoot, "agent-home", ".hermes", "google-mcp-creds"), 0o700).catch(() => {});
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
      await writeFile(join(hermesDir, "cli-config.json"), '{"legacy":true}');
      await writeFile(join(hermesDir, "config.yaml"), "persona: hermes");
      await writeFile(join(googleDir, "credentials"), "refresh-token");
      await mkdir(join(workspaceMcpDir, "cli-tokens"), { recursive: true });
      await writeFile(join(hermesDir, "google-mcp-creds", "token.json"), "{}");

      await chmod(join(hermesDir, ".env"), 0o600);
      await chmod(join(hermesDir, "auth.json"), 0o600);
      await chmod(join(hermesDir, "cli-config.json"), 0o600);
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
      expect(result.results).toHaveLength(7);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("wrap/auto-provision real-ops chokepoint: ancestor traversability (fix round-5 N1)", () => {
  it("pathTraversableByUidDecision: owner match with owner-execute bit -> true; without it -> false", () => {
    expect(pathTraversableByUidDecision({ uid: 502, gid: 502, mode: 0o700 }, 502)).toBe(true);
    expect(pathTraversableByUidDecision({ uid: 502, gid: 502, mode: 0o600 }, 502)).toBe(false);
  });

  it("pathTraversableByUidDecision: a root-owned 0700 dir is NOT traversable by a non-owner uid (the exact N1 shape)", () => {
    // Root-owned (uid 0) 0700 dir, target is the agent (502): agent falls in
    // the OTHER class, which has no execute bit in 0700 -> not traversable.
    expect(pathTraversableByUidDecision({ uid: 0, gid: 0, mode: 0o700 }, 502)).toBe(false);
    // A world-traversable base (0711) IS traversable by the agent (other-x set).
    expect(pathTraversableByUidDecision({ uid: 0, gid: 0, mode: 0o711 }, 502)).toBe(true);
  });

  it("pathTraversableByUidDecision: group class is authoritative (group match, group-exec set/clear)", () => {
    expect(pathTraversableByUidDecision({ uid: 0, gid: 20, mode: 0o710 }, 502, 20)).toBe(true);
    expect(pathTraversableByUidDecision({ uid: 0, gid: 20, mode: 0o700 }, 502, 20)).toBe(false);
    expect(pathTraversableByUidDecision(undefined, 502)).toBe(false);
  });

  it("ancestorsTraversableByUid: all ancestors traversable -> true; a non-traversable intermediate dir -> false", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-ancestors-"));
    try {
      const base = join(tmpRoot, "base");
      const home = join(base, "agent-home");
      const hermes = join(home, ".hermes");
      const leaf = join(hermes, ".env");
      await mkdir(hermes, { recursive: true });
      await writeFile(leaf, "x");
      const uid = process.getuid?.() ?? 0;
      const gid = process.getgid?.() ?? 0;

      // All dirs are owner-traversable (default mkdir mode has owner-x).
      expect(await ancestorsTraversableByUid(leaf, base, uid, gid)).toBe(true);

      // Make the intermediate `.hermes` non-traversable (0600, no owner-x).
      await chmod(hermes, 0o600);
      expect(await ancestorsTraversableByUid(leaf, base, uid, gid)).toBe(false);
    } finally {
      await chmod(join(tmpRoot, "base", "agent-home", ".hermes"), 0o700).catch(() => {});
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("ancestorsTraversableByUid: a leaf NOT under traverseFrom fails closed (never silently skips the check)", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-ancestors-esc-"));
    try {
      const base = join(tmpRoot, "base");
      await mkdir(base, { recursive: true });
      const uid = process.getuid?.() ?? 0;
      // Leaf outside base -> ".." relative -> fail closed.
      expect(await ancestorsTraversableByUid(join(tmpRoot, "elsewhere", "x"), base, uid)).toBe(false);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX round-5(N1): a leaf under a root-shape non-traversable intermediate dir fails the credential probe end-to-end even though the leaf's own bits are fine", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-n1-e2e-"));
    try {
      const accountHome = join(tmpRoot, "agent-home");
      const hermesDir = join(accountHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      await writeFile(join(hermesDir, ".env"), "LLM_KEY=abc");
      await chmod(join(hermesDir, ".env"), 0o600);
      // The intermediate `.hermes` is non-traversable (0600): the agent cannot
      // enter it to open `.env`, even though `.env`'s own bits are fine and a
      // root stat() of the leaf would report it readable.
      await chmod(hermesDir, 0o600);

      const targetUid = process.getuid?.() ?? 0;
      const targetGid = process.getgid?.() ?? 0;
      const envTarget = hermesEndpointProbes(accountHome, targetUid, targetGid).find(
        (t) => t.name.includes("moved credential") && t.name.includes(".hermes/.env"),
      );
      expect(envTarget).toBeDefined();
      expect(await envTarget!.probe()).toBe(false);
    } finally {
      await chmod(join(tmpRoot, "agent-home", ".hermes"), 0o700).catch(() => {});
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("wrap/auto-provision real-ops chokepoint: symlink-safe recursive chmod/chown (fix round-5 N2)", () => {
  it("restoreCustody (chmodRecursive) NEVER follows a symlink out of the tree -- an outside file's mode is untouched", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-n2-chmod-"));
    try {
      const tree = join(tmpRoot, "tree");
      const outside = join(tmpRoot, "outside.txt");
      await mkdir(tree, { recursive: true });
      await writeFile(join(tree, "file.txt"), "in-tree");
      await writeFile(outside, "outside-secret");
      await chmod(outside, 0o644);
      // A symlink INSIDE the tree pointing at a file OUTSIDE it.
      await symlink(outside, join(tree, "escape-link"));

      const uid = process.getuid?.() ?? 0;
      const gid = process.getgid?.() ?? 0;
      // restoreCustody runs chmodRecursive + chownRecursive on the tree.
      await realRehomeOps().restoreCustody(tree, uid, gid);

      // The outside file's mode MUST be unchanged (0644): the pre-fix
      // stat-follows-symlink code would have chmod'd it to 0600 through the
      // link. The symlink itself must survive.
      expect((await stat(outside)).mode & 0o777).toBe(0o644);
      expect((await lstat(join(tree, "escape-link"))).isSymbolicLink()).toBe(true);
      // In-tree file is custody-moded 0600.
      expect((await stat(join(tree, "file.txt"))).mode & 0o777).toBe(0o600);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("restoreCustody NEVER recurses THROUGH a symlink-to-directory -- files under the outside dir are untouched", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-n2-recurse-"));
    try {
      const tree = join(tmpRoot, "tree");
      const outsideDir = join(tmpRoot, "outsidedir");
      await mkdir(tree, { recursive: true });
      await mkdir(outsideDir, { recursive: true });
      await writeFile(join(outsideDir, "secret.txt"), "must-stay");
      await chmod(join(outsideDir, "secret.txt"), 0o644);
      // A symlink-to-directory inside the tree.
      await symlink(outsideDir, join(tree, "linkdir"));

      const uid = process.getuid?.() ?? 0;
      const gid = process.getgid?.() ?? 0;
      await realRehomeOps().restoreCustody(tree, uid, gid);

      // The file under the outside dir must be untouched (0644): the pre-fix
      // code would have readdir'd through the symlink-to-dir and chmod'd it.
      expect((await stat(join(outsideDir, "secret.txt"))).mode & 0o777).toBe(0o644);
      expect((await lstat(join(tree, "linkdir"))).isSymbolicLink()).toBe(true);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("wrap/auto-provision real-ops chokepoint: dscl -search parser (fix round-5 N4)", () => {
  it("parses the account name from the real PARENTHESIZED multi-line dscl -search output (the pre-fix regex never matched this)", () => {
    const realOutput = "eriknewton\t\tUniqueID = (\n    501\n)\n";
    expect(parseDsclSearchAccountNames(realOutput, 501)).toEqual(["eriknewton"]);
  });

  it("parses quoted numeric uid values from dscl -search output", () => {
    expect(parseDsclSearchAccountNames("nobody\t\tUniqueID = (\n    \"-2\"\n)\n", -2)).toEqual(["nobody"]);
    expect(parseDsclSearchAccountNames("sanctuary-hermes\t\tUniqueID = (\n    \"503\"\n)\n", 503)).toEqual(["sanctuary-hermes"]);
  });

  it("also parses the single-line form (name  UniqueID = 501)", () => {
    expect(parseDsclSearchAccountNames("sanctuary-hermes  UniqueID = 502\n", 502)).toEqual(["sanctuary-hermes"]);
  });

  it("returns every matched record name when a -search returns more than one", () => {
    const twoRecords = "first\t\tUniqueID = (\n    501\n)\nsecond\t\tUniqueID = (\n    501\n)\n";
    expect(parseDsclSearchAccountNames(twoRecords, 501)).toEqual(["first", "second"]);
  });

  it("parses a holder record whose account name contains a space", () => {
    expect(parseDsclSearchAccountNames("Legacy Admin\t\tUniqueID = (\n    503\n)\n", 503)).toEqual(["Legacy Admin"]);
  });

  it("returns [] only on empty output", () => {
    expect(parseDsclSearchAccountNames("", 503)).toEqual([]);
  });

  it("rejects a parsed holder record whose UniqueID is not the searched uid", () => {
    expect(() => parseDsclSearchAccountNames("sanctuary-gate-hermes  UniqueID = 999\n", 503)).toThrow(
      /record "sanctuary-gate-hermes" reported UniqueID=999, expected 503/,
    );
  });

  it("renders residue counts from the same non-empty line count", () => {
    const stdout = "eriknewton\t\tUniqueID = (\n    501\n)\nNFSHomeDirectory: /Users/eriknewton\n";
    expect(() => parseDsclSearchAccountNames(stdout, 501)).toThrow(
      /returned 4 non-empty lines, but only 3 parsed\/accounted for \(1 unparsed at line 4\)/,
    );
  });

  it.each([
    ["localized attribute name", "Legacy Admin\t\tIdentifiantUnique = (\n    503\n)\n"],
    ["trailing unmatched line", "eriknewton\t\tUniqueID = (\n    501\n)\nNFSHomeDirectory: /Users/x\n"],
    ["stray continuation", "    501\n)\n"],
  ])("throws on %s because unparsed dscl output is not evidence of absence", (_name, stdout) => {
    expect(() => parseDsclSearchAccountNames(stdout, 503)).toThrow(/Unparsed output is not evidence of absence/);
  });
});

describe("wrap/auto-provision real-ops chokepoint: round-2 symlink residuals (R2-1 restore, R2-4 probe)", () => {
  it("FIX R2-1: restore() reverse-moves a re-homed credential that is a (dangling-at-dest) symlink, faithfully restoring the original link (not a plain file), never stranding it", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-r2-1-"));
    try {
      const destPath = join(tmpRoot, "dest", "config.yaml");
      const sourcePath = join(tmpRoot, "source", "config.yaml");
      await mkdir(join(tmpRoot, "dest"), { recursive: true });
      await mkdir(join(tmpRoot, "source"), { recursive: true });
      // A relative symlink `rename`'d onto the agent home dangles there
      // (./real.txt does not resolve under dest/). access() FOLLOWS it to
      // ENOENT and skips the reverse-move; lstat (R2-1 fix) sees the link.
      await symlink("./real.txt", destPath);

      const result = await realRehomeOps().restore(destPath, sourcePath);

      // The link is faithfully restored to sourcePath as a SYMLINK (not a
      // plain file from the backup), reported restored:true, and the moved
      // link is gone from destPath (never stranded under the agent home).
      expect(result.restored).toBe(true);
      const st = await lstat(sourcePath);
      expect(st.isSymbolicLink()).toBe(true);
      expect(await readlink(sourcePath)).toBe("./real.txt");
      await expect(lstat(destPath)).rejects.toThrow();
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R2-4: a re-homed credential leaf that is a SYMLINK fails the credential probe -- its secret data did not physically move onto the isolated account", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-r2-4-"));
    try {
      const accountHome = join(tmpRoot, "agent-home");
      const hermesDir = join(accountHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      // The real secret lives OUTSIDE the account home; the "moved" credential
      // is only a symlink to it (move()'s rename relocated the LINK, not the
      // data). Even though the link target is readable, the secret is not on
      // the isolated account, so the probe must fail closed.
      const elsewhere = join(tmpRoot, "elsewhere.env");
      await writeFile(elsewhere, "LLM_KEY=abc");
      await chmod(elsewhere, 0o600);
      await symlink(elsewhere, join(hermesDir, ".env"));

      const targetUid = process.getuid?.() ?? 0;
      const targetGid = process.getgid?.() ?? 0;
      const envTarget = hermesEndpointProbes(accountHome, targetUid, targetGid).find(
        (t) => t.name.includes("moved credential") && t.name.includes(".hermes/.env"),
      );
      expect(envTarget).toBeDefined();
      expect(await envTarget!.probe()).toBe(false);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("wrap/auto-provision real-ops chokepoint: backup() shape handling (fix round-5 R3-1)", () => {
  it("FIX R3-1: backup of a DIRECTORY-shaped secret makes a REAL recursive copy (no ERR_OUT_OF_RANGE from an invalid fs.cp mode arg)", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-backup-dir-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const srcDir = join(tmpRoot, "creds-dir");
      await mkdir(srcDir, { recursive: true });
      await writeFile(join(srcDir, "token.json"), "oauth-token");

      // Pre-fix this threw `ERR_OUT_OF_RANGE` (fs.cp mode:0o700 is an invalid
      // copy-flag), so the directory-backup branch was dead on arrival.
      const { backupPath } = await realRehomeOps({ backupRoot }).backup(srcDir);

      expect(await readFile(join(backupPath, "token.json"), "utf8")).toBe("oauth-token");
      // M4 custody modes: dir 0700, file inside 0600.
      expect((await stat(backupPath)).mode & 0o777).toBe(0o700);
      expect((await stat(join(backupPath, "token.json"))).mode & 0o777).toBe(0o600);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R3-1: backup of a FILE secret still copies + chmods 0600 (file branch unchanged)", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-backup-file-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const srcFile = join(tmpRoot, "secret.env");
      await writeFile(srcFile, "LLM_KEY=abc");
      const { backupPath } = await realRehomeOps({ backupRoot }).backup(srcFile);
      expect(await readFile(backupPath, "utf8")).toBe("LLM_KEY=abc");
      expect((await stat(backupPath)).mode & 0o777).toBe(0o600);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R3-1: backup of a SYMLINK secret preserves the LINK (no dereference into operator space, no recursive copy of the target)", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-backup-symlink-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      // A symlink-to-directory: stat() reports it as a directory, so the
      // pre-fix (stat-based) branch would have recursively copied the target
      // OUT of custody. lstat (R3-1) sees the link and copies the link only.
      const realDir = join(tmpRoot, "real-creds");
      await mkdir(realDir, { recursive: true });
      await writeFile(join(realDir, "t.json"), "data");
      const linkSrc = join(tmpRoot, "link-creds");
      await symlink(realDir, linkSrc);

      const { backupPath } = await realRehomeOps({ backupRoot }).backup(linkSrc);

      const st = await lstat(backupPath);
      expect(st.isSymbolicLink()).toBe(true);
      expect(await readlink(backupPath)).toBe(realDir);
      // The backup is the link itself -- NOT a directory copy of the target.
      expect(st.isDirectory()).toBe(false);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R4-1: backup() of a SYMLINK secret is IDEMPOTENT across retries (a leftover .bak from a prior aborted run does not EEXIST-abort the retry)", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-backup-symlink-idem-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const realDir = join(tmpRoot, "real");
      await mkdir(realDir, { recursive: true });
      const linkSrc = join(tmpRoot, "link-creds");
      await symlink(realDir, linkSrc);

      const ops = realRehomeOps({ backupRoot });
      const first = await ops.backup(linkSrc);
      // Second backup (the "re-run to retry" path) must NOT reject with EEXIST
      // -- the rm-first (R5-1) makes every branch idempotent.
      const second = await ops.backup(linkSrc);
      expect(second.backupPath).toBe(first.backupPath);
      expect((await lstat(second.backupPath)).isSymbolicLink()).toBe(true);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R5-1: backup() FILE branch never FOLLOWS a stale symlink .bak (cross-shape retry) -- no secret-through-link leak, no victim clobber", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-backup-file-stalelink-"));
    try {
      const backupRoot = join(tmpRoot, "backups");
      const victim = join(tmpRoot, "victim.txt");
      await writeFile(victim, "OPERATOR-DATA-MUST-SURVIVE");
      await chmod(victim, 0o644);
      const srcFile = join(tmpRoot, "secret.env");
      await writeFile(srcFile, "SUPER-SECRET-LLM-KEY");
      // A stale symlink .bak left by a prior run when the secret was a symlink
      // (nothing cleans up the backup root). copyFile would FOLLOW it.
      const backupPath = `${backupRoot}${srcFile}.bak`;
      await mkdir(dirname(backupPath), { recursive: true });
      await symlink(victim, backupPath);

      const { backupPath: returned } = await realRehomeOps({ backupRoot }).backup(srcFile);

      // The backup is now a REAL file holding the secret (not a symlink); the
      // secret was NOT written through the link, and the victim is untouched.
      // Read each path's content BEFORE its shape/mode check (use-then-check,
      // never check-then-use) so no assertion trusts a stat across a later
      // read of the same path (js/file-system-race; the tmp tree is private,
      // but the no-check-then-use shape is the honest one to model in a test).
      const returnedContent = await readFile(returned, "utf8");
      const returnedIsLink = (await lstat(returned)).isSymbolicLink();
      const victimContent = await readFile(victim, "utf8");
      const victimMode = (await stat(victim)).mode & 0o777;
      expect(returnedIsLink).toBe(false);
      expect(returnedContent).toBe("SUPER-SECRET-LLM-KEY");
      expect(victimContent).toBe("OPERATOR-DATA-MUST-SURVIVE");
      expect(victimMode).toBe(0o644);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("wrap/auto-provision real-ops chokepoint: probe-what-moved + directory recursion (fix round-5 R6-1/R6-5)", () => {
  it("FIX R6-1: a DIRECTORY credential containing an INNER symlink fails the probe (the inner secret did not physically move onto the account)", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-r6-1-"));
    try {
      const accountHome = join(tmpRoot, "agent-home");
      const credsDir = join(accountHome, ".hermes", "google-mcp-creds");
      await mkdir(credsDir, { recursive: true });
      const elsewhere = join(tmpRoot, "outside-token.json");
      await writeFile(elsewhere, "operator-token");
      // An inner secret file that is a symlink OUT of the moved tree.
      await symlink(elsewhere, join(credsDir, "token.json"));

      const targetUid = process.getuid?.() ?? 0;
      const targetGid = process.getgid?.() ?? 0;
      const t = hermesEndpointProbes(accountHome, targetUid, targetGid, [".hermes/google-mcp-creds"]).find((x) =>
        x.name.includes("google-mcp-creds"),
      );
      expect(t).toBeDefined();
      expect(await t!.probe()).toBe(false);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R6-1: a DIRECTORY credential whose inner files are all real + readable passes the probe", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "sanctuary-realops-r6-1b-"));
    try {
      const accountHome = join(tmpRoot, "agent-home");
      const credsDir = join(accountHome, ".hermes", "google-mcp-creds");
      await mkdir(credsDir, { recursive: true });
      await writeFile(join(credsDir, "token.json"), "{}");
      await chmod(join(credsDir, "token.json"), 0o600);
      await chmod(credsDir, 0o700);

      const targetUid = process.getuid?.() ?? 0;
      const targetGid = process.getgid?.() ?? 0;
      const t = hermesEndpointProbes(accountHome, targetUid, targetGid, [".hermes/google-mcp-creds"]).find((x) =>
        x.name.includes("google-mcp-creds"),
      );
      expect(await t!.probe()).toBe(true);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("FIX R6-5: hermesEndpointProbes probes ONLY the supplied moved-credential list -- an absent/skipped credential is never probed, so a partial-credential install can arm", () => {
    // Only .env moved this run; the other six were skipped-absent.
    const targets = hermesEndpointProbes("/var/sanctuary-agents/sanctuary-hermes", 502, 502, [".hermes/.env"]);
    const credTargets = targets.filter((t) => t.name.includes("moved credential"));
    expect(credTargets).toHaveLength(1);
    expect(credTargets[0]!.name).toContain(".hermes/.env");
  });

  // FIX F-ALREADYDEDICATED: this `undefined` branch is no longer reachable
  // from production -- `resolveCredentialDestPathsToVerify` (covered below)
  // supplies a MEASURED set on the alreadyDedicated path too. Kept as the
  // defensive last resort for a caller with no knowledge at all.
  it("with no explicit list at all (defensive last resort, not a production path), it falls back to the full adapter set", () => {
    const targets = hermesEndpointProbes("/var/sanctuary-agents/sanctuary-hermes", 502, 502);
    const credTargets = targets.filter((t) => t.name.includes("moved credential"));
    expect(credTargets).toHaveLength(7);
  });

  it("FIX R7-2: a FRESH provision that re-homed ZERO secrets (explicit empty moved-set []) adds a synthetic FAIL-CLOSED probe, so verify aborts instead of arming with a vacuous credential gate", async () => {
    const targets = hermesEndpointProbes("/var/sanctuary-agents/sanctuary-hermes", 502, 502, []);
    // No per-credential probes (nothing moved), but a synthetic guard probe.
    expect(targets.filter((t) => t.name.includes("moved credential"))).toHaveLength(0);
    const guard = targets.find((t) => t.name.includes("nothing to confine"));
    expect(guard).toBeDefined();
    expect(await guard!.probe()).toBe(false);
  });
});

/**
 * FIX F-ALREADYDEDICATED (HIGH, Mini1 confined-Hermes drill 2026-07-26).
 *
 * On hardware the FIRST `protect --hermes` armed, and every SECOND and later
 * run refused at verify-before-arm on `.hermes/auth.json`,
 * `.google_workspace_mcp/credentials`, `.workspace-mcp/cli-tokens` and
 * `.hermes/google-mcp-creds` -- four files a Hermes install with no Google
 * Workspace MCP and no OAuth login has never had. Cause: the alreadyDedicated
 * path skips re-home, left the moved-set `undefined`, and fell back to the
 * full static adapter list. That is what made the exclusive-egress gate
 * unarmable (and therefore what left drills P5 and #994 unmeasured).
 *
 * The fix does NOT widen the check: it recovers "what was actually moved" by
 * OBSERVING the account, so a present-but-unreadable credential still fails
 * and an account with nothing on it still refuses.
 */
describe("wrap/auto-provision: credential set to verify on the alreadyDedicated path (fix F-ALREADYDEDICATED)", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-alreadydedicated-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  const realExistsNoFollow = async (p: string): Promise<boolean> => {
    try {
      await lstat(p);
      return true;
    } catch (err) {
      return (err as NodeJS.ErrnoException).code !== "ENOENT";
    }
  };

  it("REGRESSION: with no moved set (re-home did not run), the verified set is OBSERVED from the account -- credentials the install never had are never probed", async () => {
    // The exact drill install: .env + config.yaml present, no OAuth/Google MCP.
    await mkdir(join(dir, ".hermes"), { recursive: true });
    await writeFile(join(dir, ".hermes", ".env"), "X=1\n");
    await writeFile(join(dir, ".hermes", "config.yaml"), "a: 1\n");

    const resolved = await resolveCredentialDestPathsToVerify({
      movedThisRun: undefined,
      newAccountHome: dir,
      existsNoFollow: realExistsNoFollow,
    });

    expect(resolved.sort()).toEqual([".hermes/.env", ".hermes/config.yaml"]);
    // The four the pre-fix static fallback demanded, and the install never had.
    expect(resolved).not.toContain(".hermes/auth.json");
    expect(resolved).not.toContain(".google_workspace_mcp/credentials");
    expect(resolved).not.toContain(".workspace-mcp/cli-tokens");
    expect(resolved).not.toContain(".hermes/google-mcp-creds");
  });

  it("REGRESSION: the resulting probe list lets a partial install arm -- only the observed credentials are probed", async () => {
    await mkdir(join(dir, ".hermes"), { recursive: true });
    await writeFile(join(dir, ".hermes", ".env"), "X=1\n");
    const resolved = await resolveCredentialDestPathsToVerify({
      movedThisRun: undefined,
      newAccountHome: dir,
      existsNoFollow: realExistsNoFollow,
    });
    const credTargets = hermesEndpointProbes(dir, 502, 502, resolved).filter((t) =>
      t.name.includes("moved credential"),
    );
    expect(credTargets).toHaveLength(1);
    expect(credTargets[0]!.name).toContain(".hermes/.env");
  });

  it("does NOT widen into a fail-open: an account with no credential at all returns [], which the R7-2 guard turns into a refusal", async () => {
    const resolved = await resolveCredentialDestPathsToVerify({
      movedThisRun: undefined,
      newAccountHome: dir,
      existsNoFollow: realExistsNoFollow,
    });
    expect(resolved).toEqual([]);
    const guard = hermesEndpointProbes(dir, 502, 502, resolved).find((t) =>
      t.name.includes("nothing to confine"),
    );
    expect(guard).toBeDefined();
    expect(await guard!.probe()).toBe(false);
  });

  it("a DANGLING symlink at a credential path counts as present and is probed (fail-closed), never dropped from the verified set", async () => {
    await mkdir(join(dir, ".hermes"), { recursive: true });
    await symlink(join(dir, ".hermes", "gone"), join(dir, ".hermes", ".env"));
    const resolved = await resolveCredentialDestPathsToVerify({
      movedThisRun: undefined,
      newAccountHome: dir,
      existsNoFollow: realExistsNoFollow,
    });
    expect(resolved).toEqual([".hermes/.env"]);
  });

  it("the FRESH path is untouched: an explicit moved set passes through unchanged, including the empty set", async () => {
    await mkdir(join(dir, ".hermes"), { recursive: true });
    await writeFile(join(dir, ".hermes", "auth.json"), "{}\n");
    // The account holds auth.json, but re-home says only .env moved: the moved
    // set wins, because on the fresh path it is the stronger fact.
    expect(
      await resolveCredentialDestPathsToVerify({
        movedThisRun: [".hermes/.env"],
        newAccountHome: dir,
        existsNoFollow: realExistsNoFollow,
      }),
    ).toEqual([".hermes/.env"]);
    expect(
      await resolveCredentialDestPathsToVerify({
        movedThisRun: [],
        newAccountHome: dir,
        existsNoFollow: realExistsNoFollow,
      }),
    ).toEqual([]);
  });
});

describe("confined-agent egress: runAgentEgressProbesAsUid (injected execFile, never a real spawn)", () => {
  // No-op sleep so MED-3 retries add zero wall-clock delay in tests.
  const noSleep = { sleep: async () => {} };

  it("spawns one sudo -u '#<uid>' curl probe per declared endpoint plus the negative control, and passes when endpoints resolve and the control rejects", async () => {
    const spawned: Array<{ file: string; args: string[] }> = [];
    const execFileFn = async (file: string, args: string[]) => {
      spawned.push({ file, args });
      const url = args[args.length - 1]!;
      if (url.includes("example.com")) {
        // Negative control: the wall blocks it (curl exits nonzero -> reject).
        throw Object.assign(new Error("curl: (7) Failed to connect"), { code: 7 });
      }
      return { stdout: "", stderr: "" };
    };
    const report = await runAgentEgressProbesAsUid(503, execFileFn, noSleep);
    expect(report.ok).toBe(true);
    expect(spawned).toHaveLength(HERMES_ENDPOINT_SET.endpoints.length + 1);
    for (const call of spawned) {
      expect(call.file).toBe("/usr/bin/sudo");
      expect(call.args).toContain("#503");
      expect(call.args).toContain("-n");
      // MED-2: every probe forces the DIRECT path (no proxy).
      expect(call.args).toContain("--noproxy");
      const idx = call.args.indexOf("--noproxy");
      expect(call.args[idx + 1]).toBe("*");
    }
  });

  it("fails (fail-closed) when an endpoint probe rejects: the agent would be confined into silence", async () => {
    const execFileFn = async (_file: string, args: string[]) => {
      const url = args[args.length - 1]!;
      if (url.includes("api.venice.ai") || url.includes("example.com")) {
        throw new Error("blocked");
      }
      return { stdout: "", stderr: "" };
    };
    const report = await runAgentEgressProbesAsUid(503, execFileFn, noSleep);
    expect(report.ok).toBe(false);
    const venice = report.rows.find((r) => r.host === "api.venice.ai")!;
    expect(venice.pass).toBe(false);
    expect(venice.observed).toBe("blocked");
  });

  it("fails when the NEGATIVE CONTROL is reachable (the wall is not confining the agent at all)", async () => {
    const execFileFn = async () => ({ stdout: "", stderr: "" });
    const report = await runAgentEgressProbesAsUid(503, execFileFn, noSleep);
    expect(report.ok).toBe(false);
    const control = report.rows[report.rows.length - 1]!;
    expect(control.expected).toBe("blocked");
    expect(control.observed).toBe("reachable");
    expect(control.pass).toBe(false);
  });

  it("MED-3: a POSITIVE reachability check that flakes once then succeeds PASSES (bounded retry), and the whole run passes", async () => {
    const attemptsPerUrl = new Map<string, number>();
    const execFileFn = async (_file: string, args: string[]) => {
      const url = args[args.length - 1]!;
      const n = (attemptsPerUrl.get(url) ?? 0) + 1;
      attemptsPerUrl.set(url, n);
      if (url.includes("example.com")) {
        // Negative control stays blocked.
        throw new Error("blocked");
      }
      // api.venice.ai flakes on its FIRST attempt, succeeds on the second.
      if (url.includes("api.venice.ai") && n === 1) {
        throw new Error("transient network flake");
      }
      return { stdout: "", stderr: "" };
    };
    const report = await runAgentEgressProbesAsUid(503, execFileFn, {
      reachableAttempts: 3,
      sleep: async () => {},
    });
    expect(report.ok).toBe(true);
    // Venice was retried (2 attempts); a healthy endpoint took just 1.
    expect(attemptsPerUrl.get("https://api.venice.ai:443/")).toBe(2);
    expect(attemptsPerUrl.get("https://api.telegram.org:443/")).toBe(1);
  });

  it("MED-3: a POSITIVE check that fails ALL attempts still fails (retry is bounded, not infinite)", async () => {
    const attempts = new Map<string, number>();
    const execFileFn = async (_file: string, args: string[]) => {
      const url = args[args.length - 1]!;
      attempts.set(url, (attempts.get(url) ?? 0) + 1);
      if (url.includes("api.venice.ai")) throw new Error("hard-down");
      if (url.includes("example.com")) throw new Error("blocked");
      return { stdout: "", stderr: "" };
    };
    const report = await runAgentEgressProbesAsUid(503, execFileFn, {
      reachableAttempts: 3,
      sleep: async () => {},
    });
    expect(report.ok).toBe(false);
    // Exactly the bounded number of attempts, never more.
    expect(attempts.get("https://api.venice.ai:443/")).toBe(3);
  });

  it("MED-3 asymmetry: the NEGATIVE control is NEVER retried (a reachable control is a single-assertion security failure)", async () => {
    const attempts = new Map<string, number>();
    const execFileFn = async (_file: string, args: string[]) => {
      const url = args[args.length - 1]!;
      attempts.set(url, (attempts.get(url) ?? 0) + 1);
      // The negative control is REACHABLE (the confinement is broken).
      return { stdout: "", stderr: "" };
    };
    const report = await runAgentEgressProbesAsUid(503, execFileFn, {
      reachableAttempts: 3,
      sleep: async () => {},
    });
    expect(report.ok).toBe(false);
    // The control was probed EXACTLY once -- never retried, so a broken
    // confinement can never be masked by a lucky later attempt.
    expect(attempts.get("https://example.com:443/")).toBe(1);
    const control = report.rows[report.rows.length - 1]!;
    expect(control.pass).toBe(false);
  });
});

describe("resolveGateDaemonArgvPrefix: gate-daemon interpreter chokepoint (real D9)", () => {
  // Both provisioning builders route through this single helper, so pinning it
  // here guards BOTH construction sites (the inline builder in
  // runAutoProvisionForWrap AND buildHermesExclusiveCliWiring) against drifting
  // back to a bare `[cliBinary]` shebang-dependent argv.
  it("prefixes the node interpreter when a cliBinary is supplied (the D9 crash path)", () => {
    const cliBinary = "/opt/sanctuary/dist/cli.js";
    const prefix = resolveGateDaemonArgvPrefix(cliBinary);
    expect(prefix[0]).toBe(process.execPath);
    expect(prefix[1]).toBe(cliBinary);
    // The bare-binary form the bug rode in on must never be the whole prefix.
    expect(prefix).not.toEqual([cliBinary]);
  });

  it("prefixes the node interpreter when cliBinary is empty or undefined (the else branch that already worked)", () => {
    expect(resolveGateDaemonArgvPrefix(undefined)[0]).toBe(process.execPath);
    expect(resolveGateDaemonArgvPrefix("")[0]).toBe(process.execPath);
  });
});

describe("buildHermesExclusiveCliWiring: gate-daemon interpreter prefix (real D9)", () => {
  const baseInput = (cliBinary?: string) => ({
    agentUid: 503,
    accountName: "_sanctuary-hermes",
    newAccountHome: "/var/empty/_sanctuary-hermes",
    wallFortressPath: "/tmp/fortress",
    harnessLaunch: harnessLaunchSpec({
      programArguments: [process.execPath, "/opt/agent.js"],
      environment: { HOME: "/var/empty/_sanctuary-hermes", PYTHONPATH: "/var/empty/_sanctuary-hermes/.hermes/hermes-agent" },
    }),
    operatorUid: 501,
    auditSource: "test",
    print: () => {},
    // accountOps is not consulted when computing gateDaemonArgvPrefix.
    accountOps: {} as never,
    cliBinary,
  });

  it("prefixes the gate-daemon argv with the node interpreter when a cliBinary is supplied, so the daemon launches under a confined account whose launchd PATH has no `node`", () => {
    // The confined gate account (uid 504) has no `node` on its launchd PATH.
    // A bare `[cliBinary]` prefix relies on the `#!/usr/bin/env node` shebang,
    // which fails with `env: node: No such file or directory` -- the real "D9"
    // gate-daemon startup crash proven on hardware 2026-07-21. The interpreter
    // must be pinned explicitly via process.execPath.
    const cliBinary = "/opt/sanctuary/dist/cli.js";
    const wiring = buildHermesExclusiveCliWiring(baseInput(cliBinary));
    expect(wiring.gateDaemonArgvPrefix[0]).toBe(process.execPath);
    expect(wiring.gateDaemonArgvPrefix[1]).toBe(cliBinary);
    // The bare-binary form (which the shebang crash rode in on) must never be
    // the whole prefix.
    expect(wiring.gateDaemonArgvPrefix).not.toEqual([cliBinary]);
  });

  it("still pins the interpreter when no cliBinary is supplied (the else branch that already worked)", () => {
    const wiring = buildHermesExclusiveCliWiring(baseInput(undefined));
    expect(wiring.gateDaemonArgvPrefix[0]).toBe(process.execPath);
  });

  it("REGRESSION (F-HARNESSENV): an UNRESOLVED harness launch is absent, not a /usr/bin/false placeholder, and drives the plist-removal park", () => {
    // Pre-fix the unprotect path invented `harnessArgv: ["/usr/bin/false"]`
    // plus a separate `parkPlistFallbackRemoval: true` -- two fields for one
    // condition, and the placeholder was what the parked-form COMPARISON
    // rendered against. The condition is now representable directly.
    const { harnessLaunch: _drop, ...withoutLaunch } = baseInput(undefined);
    const wiring = buildHermesExclusiveCliWiring(withoutLaunch);
    expect(wiring.harnessLaunch).toBeUndefined();
    expect(JSON.stringify(wiring)).not.toContain("/usr/bin/false");
    expect(Object.keys(wiring)).not.toContain("parkPlistFallbackRemoval");
  });
});

describe("describeRepairCoarseComposition (F-COARSE-AFTER-EXCLUSIVE, operator sentence)", () => {
  it("says nothing when this run never entered exclusive composition", () => {
    expect(describeRepairCoarseComposition("not-attempted")).toBe("");
  });

  it("confirms the coarse path works again after a restored composition", () => {
    const sentence = describeRepairCoarseComposition("restored");
    expect(sentence).toMatch(/COARSE routing composition/);
    expect(sentence).toMatch(/protect --hermes/);
    expect(sentence).not.toMatch(/unprotect-egress-gate/);
  });

  it("names the REFUSAL and the product path that clears it when the fortress is left exclusive", () => {
    // The drill's operator experience: a plain `protect --hermes` refused with
    // no product path named. `--unprotect-egress-gate --stand-down-agent` is the one that works.
    const sentence = describeRepairCoarseComposition("exclusive-left", "coarse republish failed");
    expect(sentence).toMatch(/EXCLUSIVE routing composition/);
    expect(sentence).toMatch(/will be REFUSED/);
    expect(sentence).toMatch(/coarse republish failed/);
    expect(sentence).toMatch(/sudo sanctuary protect --unprotect-egress-gate --stand-down-agent/);
  });
});
