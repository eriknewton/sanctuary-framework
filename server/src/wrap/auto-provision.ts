/**
 * Auto-provision Step 2 (Build 1): the `sanctuary protect` CLI-facing
 * wrapper around `castle-wall/provision`'s pure orchestration.
 *
 * This module is the ONLY place in the codebase that wires the pure
 * `runProvisionFlow` sequencing (castle-wall/provision/orchestrate.ts) to
 * REAL side effects: real fs ops, real `dscl`/`sysadminctl` invocations
 * (drill-only -- never exercised by CI or by unit tests, only by an
 * Erik-present console ceremony on real hardware), the real
 * `egress-gate/harness-daemon.ts` daemon install, and the real shipped
 * `castle-wall enable --agent-uid` arm path (`runEnable` /
 * `cli/castle-wall.ts`, step 1, reused unchanged).
 *
 * Wired into `wrap/cli.ts`'s `runWrap` for the Hermes + darwin case only
 * (v1 scope, D1/D2 resolved): called after the Hermes config is wrapped and
 * the agent record is persisted, before the final success banner, so a
 * declined/skipped/non-TTY provisioning run still lets the cooperative wrap
 * complete and print its own honest banner (fix H4).
 *
 * SECURITY: this module is intentionally thin. It does not itself decide
 * WHETHER to provision (`castle-wall/provision/detect.ts` decides that) or
 * HOW the sequence is ordered (`orchestrate.ts` decides that); it only
 * supplies the real implementations of each injected step. If a step here
 * needs a privileged operation, it is written to fail closed on any error
 * rather than degrade to a less-secure fallback, matching AGENTS.md
 * invariant #5.
 */

import { platform as osPlatform } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, rename, copyFile, chmod, chown as fsChown, lchown, access, lstat, readlink, symlink, rm, cp } from "node:fs/promises";
import { dirname, relative, resolve as pathResolve, sep } from "node:path";
import { resolve as dnsResolve } from "node:dns/promises";

import {
  detectProvisionNeed,
  deriveAgentAccountName,
  hermesRehomeAdapter,
  planRehome,
  executeRehomePlan,
  RehomeExecutionError,
  restoreRehomeSteps,
  resolveHermesGatewayArgv,
  runProvisionFlow,
  resolvePolicyDaemonAction,
  withProvisionLock,
  PROVISION_LOCK_PATH,
  type ProvisionFlowOps,
  type ProvisionFlowOutcome,
  type RehomeStepResult,
  type EndpointProbeTarget,
  type PolicyDaemonAction,
  HERMES_ENDPOINT_SET,
  publishProvisionedEgressRules,
  readEgressRulesFromDisk,
  verifyProvisionedEgressStatically,
  scrubProvisionedEgressRules,
  buildAgentEgressProbeSpecs,
  buildAgentEgressReport,
  asUidTlsProbeArgv,
  asUidProbeReachableDecision,
  type AgentEgressVerifyReport,
} from "../castle-wall/provision/index.js";
import { resolveCastleWallSocketPath } from "../castle-wall/runtime/socket-path.js";
import {
  planAgentHarnessDaemonInstall,
  installAgentHarnessDaemon,
  uninstallAgentHarnessDaemon,
  agentHarnessDaemonStatus,
  type HarnessDaemonOps,
} from "../egress-gate/harness-daemon.js";
import {
  planParkedHarnessInstall,
  executeParkedHarnessInstall,
} from "../egress-gate/release-barrier.js";
import {
  createInstallExclusiveEgressOps,
  createRepairExclusiveEgressOps,
  createUnprotectExclusiveEgressOps,
  type ExclusiveEgressWiringInput,
} from "../egress-gate/arming-wiring.js";
import { deriveGateAccountName } from "../egress-gate/gate-account.js";
import {
  runEgressGateRepair,
  type ExclusiveEgressArmOps,
} from "../castle-wall/provision/exclusive-arm.js";
import { runEgressGateUnprotect } from "../castle-wall/provision/exclusive-unprotect.js";

const execFileAsync = promisify(execFile);

const PROVISION_CEILING = 500;
const NEW_ACCOUNT_HOME_BASE = "/var/sanctuary-agents";

/** Budget for polling the policy-daemon socket to become reachable after install-boot (Bug B). */
const POLICY_DAEMON_SOCKET_BUDGET_MS = 10_000;
export const LAUNCHCTL_TIMEOUT_MS = 15_000;
export const LAUNCHCTL_KILL_SIGNAL = "SIGKILL";

/** Dedicated harness daemon logs must be writable by the agent uid, not the operator-only fortress. */
export function resolveHarnessDaemonLogDir(newAccountHome: string): string {
  return `${newAccountHome.replace(/\/+$/, "")}/logs`;
}

/**
 * Bug B (consistency): resolve the fortress path whose Castle Wall the
 * auto-provision flow ensures a policy daemon for AND arms. This flow ONLY runs
 * under `sudo sanctuary protect --hermes`, and under sudo `resolveStoragePath`/
 * `os.homedir()` resolve to ROOT (`/var/root/.sanctuary`), never the operator's
 * fortress -- the R2 trap. So this resolves sudo-aware exactly like install-boot
 * does: `SANCTUARY_STORAGE_PATH` if the operator set it, else the operator's own
 * `<operatorHome>/.sanctuary`. The SAME value is passed to `ensurePolicyDaemon`,
 * `arm --fortress`, and `disarm --fortress`, so all three target one fortress
 * end to end and a non-default fortress is never probed at the default socket.
 *
 * Exported (fix chokepoint) so the unit suite can prove the sudo-aware
 * resolution (operator home, never `/var/root`) and the env override directly.
 */
export function resolveWallFortressPath(
  env: { SANCTUARY_STORAGE_PATH?: string },
  operatorHome: string,
): string {
  const override = env.SANCTUARY_STORAGE_PATH;
  if (override !== undefined && override.length > 0) {
    return override;
  }
  return `${operatorHome.replace(/\/+$/, "")}/.sanctuary`;
}

/**
 * Poll a daemon socket until `probe` answers, or a bounded budget elapses
 * (Bug B). After install-boot proves a STABLE pid, the policy daemon still needs
 * a moment to bind its Unix socket; poll (not sleep-then-check-once) so a fast
 * bind returns promptly and a never-binding daemon fails closed at the budget.
 * Never throws (the probe itself is fail-closed).
 */
async function pollSocketReachable(
  socketPath: string,
  probe: (socketPath: string) => Promise<boolean>,
  budgetMs: number,
): Promise<boolean> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    if (await probe(socketPath)) {
      return true;
    }
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 250));
  }
}

// FIX R1 (BLOCKER, 2026-07-07 fix-round 2): the real endpoint hosts Hermes
// needs to reach, so `preArmEndpoints`/`postArmEndpoints` below supply a
// non-empty, meaningful probe list instead of `[]`. `verify.ts`'s fail-closed
// empty-list guard means an empty list here would abort/disarm every real
// run, so this list must stay accurate as Hermes' real dependencies.
//
// Re-gate 1 (commit 636f6051) found the PRIOR probe overclaimed: it ran a
// root TCP connect and called that "the re-homed agent can reach this
// endpoint" -- a root socket connecting proves nothing about what the new,
// unprivileged uid can reach, because this whole module runs in-process
// inside the ROOT `sanctuary protect` process (no setuid/seteuid/launchctl
// asuser boundary crosses before the probe runs). The fix is HONESTY, not a
// weaker check: this module now only claims what root can actually prove
// from here -- (1) the hostname resolves via DNS (name resolution does not
// depend on the calling uid, so this is a true statement about ANY caller,
// not an overclaim), and (2) each moved credential is genuinely present and
// readable BY THE TARGET UID (checked via `stat`, not assumed via a root
// `access()` call -- see `credentialReadableAsUidDecision` below). Proving that the
// re-homed agent, running AS the new uid, actually reaches these hosts
// end-to-end is the Erik-present drill's job, never this module's.
// ONE LIST, TWO CONSUMERS (confined-agent egress design, section 3.1): the
// DNS-probe host list is DERIVED from the same `HarnessEndpointSet` the
// rule-provisioning step publishes signed allow rules from
// (`castle-wall/provision/egress.ts`), so the granted set and the probed set
// can never drift. MED-1: the previous hand-maintained copy of this list
// carried `www.googleapis.com`, Google's SHARED multi-API gateway; the
// endpoint set now declares the PER-SERVICE Google hosts instead (Gmail,
// Calendar, OAuth) -- see HERMES_ENDPOINT_SET for the honesty notes.
const HERMES_ENDPOINT_HOSTS: ReadonlyArray<{ name: string; host: string }> = Object.freeze(
  HERMES_ENDPOINT_SET.endpoints.map(({ name, host }) => ({ name, host })),
);

/**
 * DNS-resolves-only reachability probe for one hostname (fix R1). This is
 * deliberately NOT a TCP connect: a TCP connect made by this (root) process
 * proves nothing about whether the re-homed agent, running as a DIFFERENT
 * (unprivileged) uid, can reach the same host -- a root socket is not
 * uid-scoped and would silently overclaim end-to-end reachability. DNS
 * resolution is not uid-scoped either, so it makes no false claim: it only
 * confirms the hostname is resolvable from this host/network right now,
 * which is a real (if narrow) precondition for the agent reaching it later.
 * Fail-closed: any resolution error (including timeout) resolves false,
 * never throws.
 */
export function dnsResolvesProbe(host: string): () => Promise<boolean> {
  return async () => {
    try {
      const addresses = await dnsResolve(host);
      return addresses.length > 0;
    } catch {
      return false;
    }
  };
}

/**
 * FIX G1 (HIGH, 2026-07-07 re-gate 3 / fix-round 3): pure decision logic
 * behind the `disarm` op's exit-code check (chokepoint seam, mirroring the
 * existing R1/R2 pattern of exporting the pure decision behind a real-ops
 * closure so the unit suite can drive every branch directly). `runDisable`
 * (`cli/castle-wall.js`) RETURNS a numeric exit code on failure -- it does
 * NOT throw -- exactly like `runEnable`, which `arm` above already checks
 * via `code === 0`. Before this fix, `disarm`'s closure discarded the
 * returned code entirely, so a FAILED disable resolved WITHOUT throwing;
 * `orchestrate.ts`'s post-arm rollback only routes to the loud
 * `armed-rollback-failed` outcome when `ops.disarm()` THROWS, so a silently-
 * swallowed failure instead fell through to `armed-then-rolled-back`
 * ("only enforcement came down, agent still runs") while the wall could
 * STILL BE ARMED -- a falsely-green drill, exactly the outcome the re-gate
 * exists to catch. Returns the `Error` to throw on a nonzero code, or
 * `undefined` on success (code 0) -- never throws itself, so it stays a
 * pure value-in/value-out decision the caller chooses to throw.
 */
export function disarmExitCodeDecision(code: number): Error | undefined {
  return code === 0 ? undefined : new Error(`castle-wall disable exited ${code}`);
}

/** Throws iff {@link disarmExitCodeDecision} decides the exit code is a failure. */
function throwIfDisarmFailed(code: number): void {
  const err = disarmExitCodeDecision(code);
  if (err !== undefined) {
    throw err;
  }
}

/**
 * Pure decision logic behind "is this moved credential path readable by the
 * target uid" (fix R1 chokepoint seam): given a `stat` result (or `undefined`
 * for ENOENT) and the target uid, decide whether the credential counts as
 * present-and-readable. Exported so the real-ops unit-test suite can drive
 * every branch (ENOENT, owner match, group/other read bits, owner mismatch
 * with no read bits) without touching a real filesystem.
 *
 * Fail-closed semantics:
 *   - `undefined` (ENOENT: the path does not exist) -> `false`. This is a
 *     deliberate tightening from the pre-fix-round-2 probe, which treated an
 *     ABSENT moved credential as "reachable" -- exactly the F7/R1 symptom
 *     this probe exists to catch. A credential that was supposed to move but
 *     did not must fail the probe, not pass it.
 *   - the single applicable POSIX permission class (owner if the uid matches,
 *     else group if the gid matches, else other) has its read bit set ->
 *     readable. The class is resolved FIRST and only that class's bits are
 *     consulted: POSIX makes the first matching class authoritative (a group
 *     member does not additionally inherit "other" bits), so this never falls
 *     through from a group match with the group-read bit clear into the
 *     world-readable check. Production custody always chowns to the target
 *     uid, so the owner-match branch is the one that actually fires
 *     post-re-home; the group/other branches exist so the seam is honest
 *     about what POSIX permission bits actually allow.
 *   - FIX (round 5, item a): a DIRECTORY-shaped credential (e.g.
 *     `.hermes/google-mcp-creds/`, `.workspace-mcp/cli-tokens/`) additionally
 *     requires the EXECUTE/traverse bit of the applicable class. A directory
 *     with the read bit but not the execute bit (e.g. mode 0600) is only
 *     listable-if-you-can-enter; the agent CANNOT enter it to open the
 *     credential files inside, so a read-only directory must fail the probe.
 *     Files need read alone; dirs need read AND execute.
 *   - anything else -> `false`.
 */
export function credentialReadableAsUidDecision(
  statResult: { uid: number; gid: number; mode: number; isDirectory?: boolean } | undefined,
  targetUid: number,
  targetGid?: number,
): boolean {
  if (statResult === undefined) {
    return false;
  }
  const { uid, gid, mode, isDirectory } = statResult;
  const cls = applicablePermClass({ uid, gid }, targetUid, targetGid);
  if ((mode & cls.read) === 0) {
    return false;
  }
  // FIX (round 5, item a): a directory the agent cannot traverse (no execute
  // bit for its class) cannot yield its contents even though its read bit is
  // set -- fail closed. Files are readable on the read bit alone.
  if (isDirectory === true) {
    return (mode & cls.exec) !== 0;
  }
  return true;
}

/**
 * Resolve the single applicable POSIX permission-bit pair (read + execute)
 * for `targetUid`/`targetGid` against a file owned by `uid`/`gid`. Owner ->
 * group -> other, first match wins (a group member never additionally
 * inherits "other" bits). Shared by {@link credentialReadableAsUidDecision}
 * and {@link pathTraversableByUidDecision} so both agree on which class
 * governs.
 */
function applicablePermClass(
  owner: { uid: number; gid: number },
  targetUid: number,
  targetGid?: number,
): { read: number; exec: number } {
  if (owner.uid === targetUid) {
    return { read: 0o400, exec: 0o100 };
  }
  if (targetGid !== undefined && owner.gid === targetGid) {
    return { read: 0o040, exec: 0o010 };
  }
  return { read: 0o004, exec: 0o001 };
}

/**
 * FIX (round 5, item N1): pure decision for "can the target uid TRAVERSE
 * (enter) this directory" -- the execute bit of its applicable POSIX class.
 * A root `stat()` of a deep credential leaf bypasses ancestor DAC, so the
 * readable-by-uid probe would otherwise go green over a re-home whose
 * intermediate directories the agent cannot actually enter (e.g. a root-owned
 * 0700 `.hermes/` the agent has no execute bit on). Exported so the seam can
 * drive every class/bit combination directly.
 */
export function pathTraversableByUidDecision(
  statResult: { uid: number; gid: number; mode: number } | undefined,
  targetUid: number,
  targetGid?: number,
): boolean {
  if (statResult === undefined) {
    return false;
  }
  const cls = applicablePermClass(statResult, targetUid, targetGid);
  return (statResult.mode & cls.exec) !== 0;
}

/**
 * "Moved credential file is present and readable by the target (re-homed
 * agent's) uid" probe (fix R1, replaces the fix-round-1 `access()`-based
 * probe). Uses `stat` (not `access`, which as root would report every file
 * "accessible" regardless of mode -- root bypasses the permission bits
 * `access()` would otherwise check) so the decision is driven by the actual
 * owner/mode bits via `credentialReadableAsUidDecision`, never by root's own
 * unrestricted read capability. ENOENT resolves `false` (fail-closed: an
 * absent moved credential is exactly the F7 symptom this probe backstops,
 * never a silent pass).
 */
function credentialReadableProbe(
  path: string,
  targetUid: number,
  targetGid?: number,
  traverseFrom?: string,
): () => Promise<boolean> {
  return async () => {
    try {
      // FIX (round 5, item N1): before trusting the leaf's own owner/mode
      // bits, confirm the target uid can TRAVERSE every ancestor directory
      // from `traverseFrom` down to the leaf's parent. This process runs as
      // ROOT, and root's `stat()` bypasses ancestor DAC, so without this walk
      // a root-owned non-traversable intermediate dir (the exact shape
      // `move()`'s recursive mkdir creates) would let verify go green over a
      // re-home the agent cannot actually reach.
      if (traverseFrom !== undefined) {
        const traversable = await ancestorsTraversableByUid(path, traverseFrom, targetUid, targetGid);
        if (!traversable) {
          return false;
        }
      }
      // FIX (round 5 / R2-4): lstat (no-follow) the leaf and fail closed if
      // it is a symlink. A re-homed credential must be a REAL file/dir
      // physically resident on the dedicated account -- if the leaf is a
      // symlink, `move`'s `rename` relocated only the LINK and the secret
      // data still lives at the (operator-owned, or now-dangling) target the
      // agent cannot read. A root `stat` would FOLLOW the link and report the
      // target's bits, greening verify over a re-home that never actually
      // moved the secret onto the isolated account. lstat === stat for a real
      // file/dir, so this only tightens the symlink case.
      const st = await lstat(path);
      if (st.isSymbolicLink()) {
        return false;
      }
      const leafOk = credentialReadableAsUidDecision(
        { uid: st.uid, gid: st.gid, mode: st.mode, isDirectory: st.isDirectory() },
        targetUid,
        targetGid,
      );
      if (!leafOk) {
        return false;
      }
      // FIX (round 5 / R6-1): for a DIRECTORY credential, the leaf's own bits
      // are not enough -- the SECRET lives in the files INSIDE it. R2-4 only
      // rejected a symlink AT the leaf; a directory whose inner secret file is
      // a symlink out of the moved tree (e.g. `google-mcp-creds/token.json` ->
      // an operator-owned file) still passed, so verify greenlit an
      // armed-but-bricked re-home the agent uid cannot actually read. Recurse:
      // reject any inner symlink (its data did not physically move onto the
      // account) and require every inner file readable + every inner dir
      // traversable by the target uid.
      if (st.isDirectory()) {
        return directoryTreeReadableByUid(path, targetUid, targetGid);
      }
      return true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        // Fail-closed (fix R1): the fix-round-1 probe treated ENOENT as
        // "reachable" (true), which fail-opened on the exact defect it was
        // meant to backstop -- a credential that should have moved but did
        // not. An absent credential is never a pass.
        return false;
      }
      // Any other stat error (permission denied on a parent directory, etc.)
      // is fail-closed the same way: unknown state is never a pass.
      return false;
    }
  };
}

/**
 * FIX (round 5 / R6-1): recursively confirm every entry inside a moved
 * DIRECTORY credential is readable BY THE TARGET UID and physically present on
 * the isolated account. Fail-closed (no-follow) on: any stat/readdir error, ANY
 * symbolic link (its data lives outside the moved tree the agent cannot read --
 * the R2-4 rationale one level down), an inner directory the target uid cannot
 * traverse, or an inner regular file it cannot read. Exported so the seam can
 * drive the inner-symlink case directly.
 */
export async function directoryTreeReadableByUid(
  dir: string,
  targetUid: number,
  targetGid?: number,
): Promise<boolean> {
  const { readdir } = await import("node:fs/promises");
  const { join } = await import("node:path");
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return false;
  }
  for (const name of entries) {
    const child = join(dir, name);
    let st;
    try {
      st = await lstat(child);
    } catch {
      return false;
    }
    if (st.isSymbolicLink()) {
      return false;
    }
    const bits = { uid: st.uid, gid: st.gid, mode: st.mode, isDirectory: st.isDirectory() };
    if (!credentialReadableAsUidDecision(bits, targetUid, targetGid)) {
      return false;
    }
    if (st.isDirectory() && !(await directoryTreeReadableByUid(child, targetUid, targetGid))) {
      return false;
    }
  }
  return true;
}

/**
 * FIX (round 5, item N1): every directory from `traverseFrom` down to the
 * leaf's PARENT (inclusive) must be enterable by the target uid, or the agent
 * cannot open the credential even though root can `stat()` it. `lstat` (no
 * follow) is used so a symlink smuggled in as an ancestor is treated as a
 * non-directory and fails closed rather than being silently followed out of
 * the account home. Exported so the seam can drive the ancestor-walk directly.
 * Returns false (fail-closed) on any stat error, a non-directory ancestor, a
 * leaf that is not under `traverseFrom`, or any ancestor the target uid cannot
 * traverse.
 */
export async function ancestorsTraversableByUid(
  leafPath: string,
  traverseFrom: string,
  targetUid: number,
  targetGid?: number,
): Promise<boolean> {
  const parent = dirname(leafPath);
  const rel = relative(traverseFrom, parent);
  // A leaf outside `traverseFrom` (rel starts with "..") is not something we
  // can reason about -- fail closed rather than skip the check.
  if (rel.startsWith("..")) {
    return false;
  }
  const segments = rel.length === 0 ? [] : rel.split(sep);
  const chain: string[] = [traverseFrom];
  let current = traverseFrom;
  for (const seg of segments) {
    current = `${current}/${seg}`;
    chain.push(current);
  }
  for (const dir of chain) {
    let st;
    try {
      st = await lstat(dir);
    } catch {
      return false;
    }
    if (!st.isDirectory()) {
      return false;
    }
    if (!pathTraversableByUidDecision({ uid: st.uid, gid: st.gid, mode: st.mode }, targetUid, targetGid)) {
      return false;
    }
  }
  return true;
}

/**
 * FIX G5 (MEDIUM, 2026-07-07 re-gate 3 / fix-round 3): every moved-credential
 * dest-relative path the Hermes re-home adapter actually moves (fix-round 2's
 * `HERMES_ENDPOINT_HOSTS`/probe list checked ONLY `.hermes/.env`, while the
 * doc comments above claimed "each moved credential present-and-readable").
 * `auth.json`, `config.yaml`, the Google OAuth credentials, and the
 * workspace-mcp tokens could be moved-but-unreadable-by-uid while DNS +
 * `.env` still passed, so verify went green over a broken re-home. Derived
 * DIRECTLY from `hermesRehomeAdapter.pathsToRehome`'s `isSecret` entries
 * (rather than a second, hand-maintained list) so this can never silently
 * drift out of sync with what re-home actually moves; the adapter takes an
 * `operatorHome` argument only to build its (unused here) `sourcePath`, so
 * an empty string is passed and only `destRelativePath` is read.
 *
 * Exported (fix chokepoint, 2026-07-07 re-gate 3) so the real-ops unit suite
 * can assert this list stays in lockstep with `hermesRehomeAdapter` and
 * covers every secret path, not just `.env`.
 */
export function allHermesCredentialDestPaths(): string[] {
  return hermesRehomeAdapter
    .pathsToRehome("")
    .filter((entry) => entry.isSecret)
    .map((entry) => entry.destRelativePath);
}

/**
 * Build the real, injected pre-arm/post-arm endpoint probe list for Hermes.
 * Exported (fix chokepoint, 2026-07-07 re-gate 3) so the real-ops unit suite
 * can drive the FULL probe list (DNS hosts + every credential path) against
 * a real disposable tmpdir and assert an unreadable non-.env credential
 * fails the aggregate verify, not just `.hermes/.env`.
 */
export function hermesEndpointProbes(
  newAccountHome: string,
  targetUid: number,
  targetGid: number,
  credentialDestPaths?: string[],
): EndpointProbeTarget[] {
  const targets: EndpointProbeTarget[] = HERMES_ENDPOINT_HOSTS.map(({ name, host }) => ({
    name: `${name} (DNS-resolves)`,
    probe: dnsResolvesProbe(host),
  }));
  // FIX G5: probe EVERY moved credential path for readable-by-target-uid,
  // not just `.hermes/.env` -- fail-closed if any is unreadable, so a
  // broken re-home of a non-.env credential can no longer sail through
  // verify while only the .env probe was checked.
  //
  // FIX (round 5, item N1): the probe walks every ancestor from the
  // account-home BASE (`dirname(newAccountHome)`) down to each credential,
  // requiring the target uid can traverse each one -- so a root-owned,
  // non-traversable intermediate directory fails the probe instead of
  // sailing through on root's ancestor-bypassing `stat()`.
  //
  // FIX (round 5, item R6-5): probe the credentials re-home ACTUALLY moved,
  // not the full static adapter list. A legitimate partial Hermes install
  // (e.g. no Google Workspace MCP, so `google-mcp-creds`/`cli-tokens`/
  // `credentials` are `skipped-absent`) would otherwise fail verify on the
  // absent-credential probes and could NEVER arm. `credentialDestPaths` is
  // the `moved` set threaded from the re-home results; it falls back to the
  // full adapter list only when unknown (the alreadyDedicated path, where the
  // account is presumed already complete).
  const destPaths = credentialDestPaths ?? allHermesCredentialDestPaths();
  const traverseFrom = dirname(newAccountHome);
  for (const destRelativePath of destPaths) {
    targets.push({
      name: `moved credential present + readable by agent uid (${destRelativePath})`,
      probe: credentialReadableProbe(`${newAccountHome}/${destRelativePath}`, targetUid, targetGid, traverseFrom),
    });
  }
  // FIX (round 5 / R7-2): a FRESH provision that re-homed ZERO secrets (an
  // EXPLICIT empty moved-set -- distinct from `undefined`, the alreadyDedicated
  // path that falls back to the full adapter set above) must NOT arm with a
  // vacuous credential gate. The R6-5 `?? full` fallback does not catch this,
  // because `[] ?? full` is `[]` (an empty array is not nullish), so the loop
  // above would add zero credential probes and verify would pass on the DNS
  // probes alone -- arming over an agent with no secrets to confine. Push a
  // synthetic fail-closed probe so verify aborts instead (a Hermes install
  // with none of its secret files present is not a valid armed state).
  if (credentialDestPaths !== undefined && credentialDestPaths.length === 0) {
    targets.push({
      name: "no credential was re-homed onto the account (nothing to confine)",
      probe: async () => false,
    });
  }
  return targets;
}

/**
 * FIX R1: fail-closed wrapper around `hermesEndpointProbes` for the
 * (should-never-happen) case where the target agent uid/gid has not been
 * resolved yet when the orchestrator calls `preArmEndpoints`/
 * `postArmEndpoints`. Returning `[]` here would trigger `verify.ts`'s own
 * fail-closed empty-list guard (abort/fast-disarm), which is the correct
 * outcome -- silently falling back to the CONSOLE owner's uid would instead
 * make the credential-readable probe check the WRONG identity and could
 * fail-open by reporting "readable" against an identity nothing was actually
 * re-homed to.
 */
function resolveEndpointProbes(
  newAccountHome: string,
  targetUidGid: { uid: number; gid: number } | undefined,
  movedCredentialDestPaths?: string[],
): EndpointProbeTarget[] {
  if (targetUidGid === undefined) {
    return [];
  }
  // FIX (round 5 / R6-5): pass the credentials re-home actually moved (or
  // undefined on the alreadyDedicated path, where the full adapter set is the
  // right expectation).
  return hermesEndpointProbes(newAccountHome, targetUidGid.uid, targetUidGid.gid, movedCredentialDestPaths);
}

/**
 * FIX R2 (HIGH, 2026-07-07 fix-round 2): the operator's resolved identity
 * when this process is running under `sudo` (which it must be, given the
 * root check just above every call site of this type). Under sudo,
 * `os.homedir()`/`os.userInfo()` report ROOT (`/var/root`, uid/gid 0), not
 * the operator who typed `sudo sanctuary protect --hermes` -- see
 * `resolveSudoIdentityDecision` below for the pure decision logic this
 * wraps.
 */
export interface OperatorIdentity {
  uid: number;
  gid: number;
  home: string;
}

/**
 * Pure decision logic behind sudo-aware operator-identity resolution (fix R2
 * chokepoint seam): given the raw env values `sudo` sets
 * (`SUDO_UID`/`SUDO_GID`/`SUDO_USER`) and a name-validity check, decide
 * whether the operator identity is resolvable and, if so, from which env
 * vars. Exported so the real-ops unit-test suite can drive every branch
 * (both present, one missing, malformed) without touching a real process
 * environment or `dscl`.
 *
 * FIX R2: the pre-fix-round-2 code called `homedir()`/`userInfo()`
 * unconditionally, which under `sudo sanctuary protect --hermes` (this
 * function's only supported invocation shape, per the root check above every
 * caller) resolves to root's own identity (`/var/root`, 0/0) -- NOT the
 * operator. Two concrete failures followed: (1) the re-home SOURCE path
 * resolved to `/var/root/.hermes/...`, which is never where the operator's
 * real Hermes config lives, so re-home silently found nothing to move and
 * the wall armed over un-re-homed secrets; (2) F3's custody handback chowned
 * restored secrets to root, leaving the operator unable to read their own
 * recovered `.env` after a failed/aborted run.
 *
 * Fail-closed: `SUDO_UID`/`SUDO_GID` must both be present and parse as
 * non-negative integers, and (when present) `SUDO_USER` must match a safe
 * account-name shape; any other combination resolves `undefined` (never a
 * fabricated or root-fallback identity).
 *
 * FIX G4 (MEDIUM, 2026-07-07 re-gate 3 / fix-round 3): a ROOT sudo context
 * (e.g. `sudo su -` then running `sanctuary protect --hermes` from that root
 * shell) sets `SUDO_UID=0`/`SUDO_GID=0` (and often `SUDO_USER=root`). The
 * pre-fix code accepted uid/gid `0` as a perfectly well-formed "operator"
 * identity, which resolves the operator's home to `/var/root` and custody
 * to `0:0` -- reintroducing the EXACT root-home path this whole R2 fix
 * exists to fail closed against (re-home would look for secrets under
 * `/var/root/.hermes/...`, never where they actually live, and any restored
 * secret would be chowned back to root instead of a real operator account).
 * Reject uid `0`, gid `0`, and `SUDO_USER === "root"` outright -- fail closed
 * to the same `undefined` the caller already treats as "abort at the
 * root-check stage", never silently resolving root as the operator.
 */
export function resolveSudoIdentityDecision(env: {
  SUDO_UID?: string;
  SUDO_GID?: string;
  SUDO_USER?: string;
}): { uid: number; gid: number; user?: string } | undefined {
  const { SUDO_UID, SUDO_GID, SUDO_USER } = env;
  if (SUDO_UID === undefined || SUDO_GID === undefined) {
    return undefined;
  }
  if (!/^\d+$/.test(SUDO_UID) || !/^\d+$/.test(SUDO_GID)) {
    return undefined;
  }
  const uid = Number(SUDO_UID);
  const gid = Number(SUDO_GID);
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid)) {
    return undefined;
  }
  // FIX G4: a root sudo context is never a valid "operator" -- fail closed
  // rather than resolve /var/root + custody 0:0.
  if (uid === 0 || gid === 0 || SUDO_USER === "root") {
    return undefined;
  }
  if (SUDO_USER !== undefined && !/^[a-zA-Z0-9._-]+$/.test(SUDO_USER)) {
    // A SUDO_USER value that fails the safe-name shape is refused outright
    // (fail-closed), even though uid/gid alone would be enough to chown
    // with: an unparseable SUDO_USER is a signal something about this
    // invocation is not a normal sudo call, and the home-directory lookup
    // below needs a trustworthy name to pass to `dscl`.
    return undefined;
  }
  return { uid, gid, user: SUDO_USER };
}

/**
 * Resolve the operator's identity + home directory, sudo-aware (fix R2).
 * Fails closed (returns `undefined`) if `SUDO_UID`/`SUDO_GID` are absent or
 * malformed, or if the operator's home directory cannot be looked up via
 * `dscl` -- callers must refuse to proceed rather than fall back to root's
 * own `homedir()`/`userInfo()`.
 */
async function resolveOperatorIdentity(): Promise<OperatorIdentity | undefined> {
  const sudoIdentity = resolveSudoIdentityDecision(process.env);
  if (sudoIdentity === undefined) {
    return undefined;
  }
  // Prefer resolving the home directory by NAME via dscl (matches the
  // established pattern in cli/castle-wall-boot.ts's `deriveOperatorHome`);
  // SUDO_USER may be absent on some invocations even when SUDO_UID/GID are
  // set, so fall back to looking the account up by uid.
  const home = await lookupHomeDirectory(sudoIdentity.user, sudoIdentity.uid);
  if (home === undefined) {
    return undefined;
  }
  return { uid: sudoIdentity.uid, gid: sudoIdentity.gid, home };
}

/**
 * FIX (round 5, item N4): parse the record names out of `dscl . -search
 * /Users UniqueID <n>` output. `dscl -search` emits the matched attribute in
 * the PARENTHESIZED, multi-line plist form, e.g.
 *
 *   eriknewton\t\tUniqueID = (
 *       501
 *   )
 *
 * The pre-fix parser was `/^(\S+)\s+UniqueID\s*=\s*\d+/m`, which requires the
 * uid digits on the SAME line as `UniqueID =` and therefore NEVER matched the
 * real `= (` form: every uid-fallback home lookup and every
 * `resolveAccountShapeVerdict` account-name check silently missed. This
 * parser matches the record-name line (`name  UniqueID =`) whether the value
 * is parenthesized-multiline or single-line, and returns ALL matched record
 * names (a `-search` can in principle return more than one record). Exported
 * so the seam can drive it against captured real dscl output.
 */
export function parseDsclSearchAccountNames(stdout: string): string[] {
  const names: string[] = [];
  const re = /^(\S+)\s+UniqueID\s*=/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(stdout)) !== null) {
    names.push(m[1]);
  }
  return names;
}

/** Look up a NFSHomeDirectory by account name (preferred) or uid, via dscl. Fail-closed: any error or unparsed output resolves undefined. */
async function lookupHomeDirectory(user: string | undefined, uid: number): Promise<string | undefined> {
  try {
    if (user !== undefined) {
      const { stdout } = await execFileAsync("/usr/bin/dscl", [".", "-read", `/Users/${user}`, "NFSHomeDirectory"]);
      const match = /NFSHomeDirectory:\s*(\S+)/.exec(stdout);
      if (match) return match[1];
    }
    const { stdout: searchOut } = await execFileAsync("/usr/bin/dscl", [
      ".",
      "-search",
      "/Users",
      "UniqueID",
      String(uid),
    ]);
    // FIX (round 5, item N4): parse the parenthesized dscl -search output
    // shape (the pre-fix same-line-digits regex never matched it).
    const [accountName] = parseDsclSearchAccountNames(searchOut);
    if (accountName === undefined) return undefined;
    const { stdout } = await execFileAsync("/usr/bin/dscl", [
      ".",
      "-read",
      `/Users/${accountName}`,
      "NFSHomeDirectory",
    ]);
    const match = /NFSHomeDirectory:\s*(\S+)/.exec(stdout);
    return match?.[1];
  } catch {
    return undefined;
  }
}

/** Options threaded in from `runWrap` for the Hermes v1 auto-provision call. */
export interface RunAutoProvisionForWrapOptions {
  /** Whether this run's stdin is a TTY (privileged sub-steps refuse otherwise, fix H4). */
  isTty: boolean;
  /** `--provision-agent-account[=name]` pre-answer (fix L2: pre-answers the CHOICE only). Undefined = not passed. */
  preAnsweredProvision?: boolean;
  /** Absolute path to the running Sanctuary CLI binary for install-boot's LaunchDaemon argv. */
  cliBinary?: string;
  /** Print function for operator-facing output (defaults to console.error, matching the rest of wrap/cli.ts's stderr convention). */
  print?: (line: string) => void;
  /** Stop the wrap-started transient Castle Wall daemon before installing the persistent boot service. */
  stopTransientCastleWallDaemon?: () => Promise<void>;
  /** Override for `process.getuid` (tests only; production leaves this undefined). */
  getuid?: () => number;
  /** Override for the resolved operator identity (tests only; production leaves this undefined and resolves via SUDO_UID/GID/USER). */
  resolveOperatorIdentity?: () => Promise<OperatorIdentity | undefined>;
  /**
   * Unified Protect Slice 5 S5-6: fine-grained (exclusive-egress) mode. The
   * harness is PARK-installed (S5-5 barrier form) and the exclusive-egress
   * arming stage (gate generation + release barrier) runs after the coarse
   * stages prove live. Off by default (coarse drill-proven path unchanged).
   */
  exclusiveEgress?: boolean;
}

/**
 * Result surfaced back to `runWrap` so it can fold a short status line into
 * its own success banner without ever claiming "protected" on anything less
 * than the existing armed-evidence honesty gate.
 */
export interface AutoProvisionSummary {
  ran: boolean;
  outcome?: ProvisionFlowOutcome;
}

export function policyDaemonInstallBootArgs(
  fortressPath: string,
  cliBinary: string | undefined,
): string[] {
  const args = ["--fortress", fortressPath];
  if (cliBinary !== undefined && cliBinary.length > 0) {
    args.push("--binary", cliBinary);
  }
  return args;
}

export interface AutoProvisionPolicyDaemonSignals {
  socketReachable: boolean;
  diskForThisFortress: boolean;
  readyForThisFortress: boolean;
  plistPresent: boolean;
  loadedState: { loaded: boolean; fortressPath: string | null };
  fortressPath: string;
}

export function resolvePolicyDaemonActionForAutoProvision(
  signals: AutoProvisionPolicyDaemonSignals,
): PolicyDaemonAction {
  const loadedForThisFortress =
    signals.loadedState.loaded && signals.loadedState.fortressPath === pathResolve(signals.fortressPath);
  const forThisFortress =
    signals.diskForThisFortress && (!signals.loadedState.loaded || loadedForThisFortress);
  const forAnyFortress = signals.plistPresent || signals.loadedState.loaded;
  return resolvePolicyDaemonAction({
    socketReachable: signals.socketReachable,
    bootServiceForThisFortress: forThisFortress,
    bootServiceReadyForThisFortress: signals.readyForThisFortress,
    bootServiceLoadedForThisFortress: signals.diskForThisFortress && loadedForThisFortress,
    bootServiceForAnyFortress: forAnyFortress,
  });
}

/**
 * Entry point called from `runWrap`. Gated by the caller to Hermes +
 * darwin; this function itself is defensive and no-ops (returns
 * `{ ran: false }`) on any other platform, matching D1's v1 = headless
 * agent runtime only scope.
 */
export async function runAutoProvisionForWrap(
  options: RunAutoProvisionForWrapOptions,
): Promise<AutoProvisionSummary> {
  if (osPlatform() !== "darwin") {
    return { ran: false };
  }

  // SAFETY: stderr is the operator-facing CLI channel for this subcommand;
  // this is only the default when no `print` override is supplied (the
  // production `runWrap` caller always supplies one). Never used to print
  // secrets or key material.
  const print = options.print ?? ((line: string) => console.error(line));
  const agentId = "hermes";
  const accountName = deriveAgentAccountName(agentId);
  const newAccountHome = `${NEW_ACCOUNT_HOME_BASE}/${accountName}`;

  // Privileged-path root check (matches the established pattern in
  // cli/castle-wall.ts's `setup-shared-dir` / `install-boot`: privileged
  // subcommands check `getuid?.() !== 0` up front and instruct the operator
  // to re-run with sudo, rather than let a root-only fs/exec op fail with a
  // raw, confusing EACCES deep in the flow). `sanctuary protect` itself runs
  // fine as the operator; only the PRIVILEGED sub-steps (create account,
  // re-home, install daemon, arm) need root. Checking here -- before the
  // plan-and-print / confirm ceremony, and BEFORE the operator-identity
  // resolution below (which only makes sense once we know we are actually
  // running as root under sudo) -- gives the operator the correct
  // instruction immediately instead of a failure after they have already
  // said yes.
  const getuid = options.getuid ?? process.getuid?.bind(process);
  if (getuid?.() !== 0) {
    print(
      "Provisioning a dedicated agent account requires root. Re-run: sudo sanctuary protect --hermes",
    );
    return {
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "root-check",
        reason: "auto-provisioning requires root; re-run with sudo.",
        rolledBack: false,
        // FIX (round 5 / R3-2): nothing was created or moved, so the CLI must
        // NOT print a "restore of your re-homed files FAILED / do not re-run"
        // alarm -- this is the common no-sudo first attempt.
        rehomeAttempted: false,
      },
    };
  }

  // FIX R2 (HIGH, 2026-07-07 fix-round 2): this flow only ever runs under
  // `sudo sanctuary protect --hermes` (just confirmed above). Under sudo,
  // `os.homedir()`/`os.userInfo()` report ROOT (`/var/root`, 0/0), not the
  // operator who typed the command. Resolve the operator's real identity
  // from SUDO_UID/SUDO_GID/SUDO_USER (or fail closed) BEFORE this function
  // does anything else that depends on "whose home directory" or "whose
  // uid/gid" -- re-home source resolution and F3 custody handback both
  // depend on this being right, not on root's own identity.
  const resolveIdentity = options.resolveOperatorIdentity ?? resolveOperatorIdentity;
  const operatorIdentity = await resolveIdentity();
  if (operatorIdentity === undefined) {
    print(
      "Could not determine the operator account under sudo (SUDO_UID/SUDO_GID unset or unresolvable). " +
        "Run via 'sudo sanctuary protect --hermes' from an interactive operator shell, not a raw root shell.",
    );
    return {
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "root-check",
        reason: "could not resolve the operator's identity under sudo; refusing to provision.",
        rolledBack: false,
        // FIX (round 5 / R3-2): nothing created or moved -> neutral CLI frame.
        rehomeAttempted: false,
      },
    };
  }
  const operatorHome = operatorIdentity.home;
  const consoleOwnerUid = operatorIdentity.uid;
  const consoleOwnerGid = operatorIdentity.gid;
  // Bug B: the fortress whose Castle Wall this flow ensures + arms. Resolved
  // sudo-aware (operator home, never root's /var/root) and threaded identically
  // into ensurePolicyDaemon, arm --fortress, and disarm --fortress.
  const wallFortressPath = resolveWallFortressPath(process.env, operatorHome);
  const harnessConfiguredUid = await readHarnessConfiguredUid();
  const runningAgentUid = await readRunningHermesGatewayUid();
  // FIX F6 (HIGH, Codex second family, 2026-07-07 fix-round): the resolved
  // uid alone is NOT enough to trust "already dedicated" -- a stale prior
  // service account, or Hermes running at some other non-console uid with
  // the wall disabled, used to satisfy the ceiling/console-owner test and
  // short-circuit this ENTIRE function to a bare "already dedicated" return
  // BEFORE runProvisionFlow ever ran daemon-install/verify/uid-gate/arm.
  // That short-circuit is now removed: this function ALWAYS calls
  // runProvisionFlow, and the orchestrator itself (not this caller) decides
  // whether to skip create+rehome based on a VERIFIED account shape.
  const candidateUid = harnessConfiguredUid ?? runningAgentUid;
  const accountShapeVerdict =
    candidateUid !== undefined && candidateUid >= PROVISION_CEILING && candidateUid !== consoleOwnerUid
      ? await resolveAccountShapeVerdict(accountName, candidateUid)
      : undefined;
  const detectResult = detectProvisionNeed({
    harnessConfiguredUid,
    runningAgentUid,
    consoleOwnerUid,
    ceiling: PROVISION_CEILING,
    accountShapeVerdict,
  });

  // FIX R1: `preArmEndpoints`/`postArmEndpoints` are nullary in
  // `ProvisionFlowOps` (the orchestrator calls them with no arguments), but
  // the credential-readable-by-uid probe needs to know the TARGET uid/gid to
  // check readability against. `installHarnessDaemon(uid)` is called by the
  // orchestrator on EVERY path (fresh-provision and already-dedicated alike)
  // strictly before either endpoint-probe call (steps 6 -> 7/10), so it is
  // the correct, always-populated capture point. `resolvedAgentUidGid`
  // starts undefined and is set exactly once per run.
  let resolvedAgentUidGid: { uid: number; gid: number } | undefined;
  // FIX (round 5 / R6-5): the dest-relative paths re-home ACTUALLY moved this
  // run (moved + isSecret entries). Threaded into the endpoint probes so a
  // legitimately-absent (skipped-absent) credential is never probed. Stays
  // undefined on the alreadyDedicated path (re-home did not run), where the
  // probe falls back to the full adapter set (the account is presumed
  // complete).
  let movedCredentialDestPaths: string[] | undefined;
  // S5-6: the REAL harness argv captured at parked-install time (the release
  // barrier's argv-digest source). Set exactly once, only in exclusive mode.
  let capturedHarnessArgv: string[] | undefined;

  // S5-6: the exclusive-egress arming stage's production wiring. Built
  // LAZILY: the agent uid + harness argv are only known after the parked
  // install ran, and the stage is only ever invoked after it (orchestrate
  // asserts the parked form first). A call before that state exists is a
  // contract violation and throws (fail-closed; the orchestrator maps it to
  // the degrade-loud outcome, which leaves the agent parked).
  const buildExclusiveWiringInput = (): ExclusiveEgressWiringInput => {
    if (resolvedAgentUidGid === undefined || capturedHarnessArgv === undefined) {
      throw new Error(
        "exclusive-egress stage invoked before the parked harness install resolved the agent uid/argv (contract violation)",
      );
    }
    const reloadPolicy = async (): Promise<{ ok: boolean; error?: string }> => {
      const { requestPolicyReload } = await import("../cli/castle-wall.js");
      const result = await requestPolicyReload(wallFortressPath, "darwin");
      return result.ok ? { ok: true } : { ok: false, error: result.error };
    };
    return {
      agentId,
      agentUid: resolvedAgentUidGid.uid,
      agentAccount: accountName,
      fortressPath: wallFortressPath,
      harnessArgv: capturedHarnessArgv,
      harnessLogDir: resolveHarnessDaemonLogDir(newAccountHome),
      agentTemplate: agentId,
      gateDaemonArgvPrefix:
        options.cliBinary !== undefined && options.cliBinary.length > 0
          ? [options.cliBinary]
          : [process.execPath, process.argv[1] ?? "sanctuary"],
      excludeUids: [consoleOwnerUid],
      gateAccountCeiling: PROVISION_CEILING,
      gateHomeDirectory: `${NEW_ACCOUNT_HOME_BASE}/${deriveGateAccountName(agentId)}`,
      reloadPolicy,
      publishProvisionedRules: async (routing) => {
        const published = await publishProvisionedEgressRules({
          fortressPath: wallFortressPath,
          endpointSet: HERMES_ENDPOINT_SET,
          reloadPolicy,
          routing,
        });
        return published.ok
          ? { ok: true as const, ruleIds: published.ruleIds }
          : { ok: false as const, error: published.error };
      },
      audit: async (operation, details) => {
        try {
          const { appendCastleWallCliAuditBestEffort } = await import("../cli/castle-wall.js");
          await appendCastleWallCliAuditBestEffort(
            operation,
            { source: "sanctuary-protect", ...details },
            wallFortressPath,
            process.env,
            process.stderr,
          );
        } catch {
          // Best-effort by contract.
        }
      },
      print,
      accountOps: realAccountProvisionOps(),
    };
  };
  let cachedExclusiveOps: ExclusiveEgressArmOps | undefined;
  const lazyExclusiveOps = (): ExclusiveEgressArmOps => {
    cachedExclusiveOps ??= createInstallExclusiveEgressOps(buildExclusiveWiringInput());
    return cachedExclusiveOps;
  };
  const exclusiveEgressOps: ExclusiveEgressArmOps | undefined =
    options.exclusiveEgress === true
      ? {
          bringUpGeneration: () => lazyExclusiveOps().bringUpGeneration(),
          runReleaseSequence: (committed) => lazyExclusiveOps().runReleaseSequence(committed),
          restoreCoarseComposition: (reason) => lazyExclusiveOps().restoreCoarseComposition(reason),
          startHarnessCoarse: () => lazyExclusiveOps().startHarnessCoarse(),
          audit: (operation, details) => lazyExclusiveOps().audit(operation, details),
          print,
        }
      : undefined;

  const ops: ProvisionFlowOps = {
    confirm: (promptText) => confirmOnTty(promptText),
    print,
    createAccount: async () => {
      const { planAndCreateAccount } = await import("../castle-wall/provision/account.js");
      // FIX F7: bind the account's home to the re-home target at create
      // time, so the confined harness resolves ~/.hermes to where the
      // secrets actually get moved.
      return planAndCreateAccount(
        { accountName, ceiling: PROVISION_CEILING, homeDirectory: newAccountHome },
        realAccountProvisionOps(),
      );
    },
    rehome: async (uid, gid) => {
      // FIX (round 5, item N1): the shared agent-home BASE
      // (`/var/sanctuary-agents`) must be root-owned and world-TRAVERSABLE
      // (0711) so each dedicated agent can reach its own home, but never
      // listable/writable by non-root. Normalize it BEFORE the moves --
      // `move()`'s recursive mkdir would otherwise create it 0700 root-owned,
      // leaving the agent unable to even traverse into its own home.
      await mkdir(NEW_ACCOUNT_HOME_BASE, { recursive: true, mode: 0o711 });
      await chmod(NEW_ACCOUNT_HOME_BASE, 0o711);
      const rehomeOps = realRehomeOps();
      const staleRuntimeConflictPath = await moveAsideStaleHermesRuntimeDestination(operatorHome, newAccountHome);
      if (staleRuntimeConflictPath !== undefined) {
        print(`Moved stale Hermes runtime destination aside at ${staleRuntimeConflictPath}.`);
      }
      const plan = planRehome(hermesRehomeAdapter, { operatorHome, newAccountHome });
      const results = await executeRehomePlan(plan, rehomeOps, { uid, gid });
      // FIX (round 5, item N1): chown the agent's WHOLE home tree (the home
      // dir + every intermediate credential dir `move()`'s mkdir created
      // root-owned + the leaves) to the agent, so it can traverse to and read
      // its re-homed secrets. Per-leaf chown only covered the leaves, never
      // the ancestor dirs, so the agent had no traverse bit on `.hermes/` etc.
      try {
        await rehomeOps.chown(newAccountHome, uid, gid);
      } catch (err) {
        // The moves ALREADY succeeded by now; a failure chowning the home
        // tree must NOT discard the moved results (the orchestrator's
        // `safeRestore` needs them to reverse the move). Re-throw as a
        // RehomeExecutionError carrying the completed `results`, exactly like
        // executeRehomePlan's own mid-loop throw (the G3 straddling-entry
        // pattern) -- otherwise a plain throw here would reach the
        // orchestrator as an empty-partialResults abort and strand the moved
        // secrets under the new account with nothing restored.
        throw new RehomeExecutionError(err instanceof Error ? err.message : String(err), results, { cause: err });
      }
      // FIX (round 5 / R6-5): capture exactly the secret credentials that
      // MOVED (never skipped-absent), so the endpoint probes verify only what
      // this run actually placed on the account -- a partial-credential
      // install (some sources legitimately absent) can still arm.
      movedCredentialDestPaths = results
        .filter((r) => r.status === "moved" && r.entry.isSecret)
        .map((r) => r.entry.destRelativePath);
      return { plan, results };
    },
    installHarnessDaemon: async (uid) => {
      // FIX R1: capture the target uid/gid here (see the comment above the
      // `ops` object) so the endpoint probes below can check
      // credential-readable-by-uid honestly instead of guessing. The new
      // account's uid and gid are the same value (see `rehome`'s call site
      // and `arm`'s `--agent-uid=<uid>` below, which both treat uid===gid
      // for this dedicated service account).
      resolvedAgentUidGid = { uid, gid: uid };
      // FIX (round 5 / R7-1, R8-1): report the honest daemon-presence signals
      // and NEVER throw -- return a discriminated result so the orchestrator's
      // teardown decision keys on "did this attempt stand the daemon up" for
      // both success and failure. Capture the pre-install status FIRST.
      const daemonOps = realHarnessDaemonOps();
      let before: { known: boolean; installed: boolean };
      try {
        before = await agentHarnessDaemonStatus(daemonOps);
      } catch {
        // Status probe itself failed: preserve any possible pre-existing daemon.
        // A fresh install cannot be proven when launchd state is unknown.
        before = { known: false, installed: false };
      }
      try {
        const resolved = await resolveHermesGatewayArgv({ pathExists: pathExists }, { agentHome: newAccountHome });
        const harnessLogDir = resolveHarnessDaemonLogDir(newAccountHome);
        await mkdir(harnessLogDir, { recursive: true, mode: 0o700 });
        await chmod(harnessLogDir, 0o700);
        await fsChown(harnessLogDir, uid, uid);
        if (options.exclusiveEgress === true) {
          // S5-6 fine-grained mode: the S5-5 PARKED install. The plist is the
          // barrier form (Disabled + RunAtLoad=false + wrapper argv), the job
          // is launchctl-disabled, any stale hold file is removed, and
          // NOTHING is bootstrapped: the release barrier starts the agent
          // strictly after the gate generation commits. The REAL harness argv
          // is captured for the barrier's argv-digest.
          capturedHarnessArgv = resolved.programArguments;
          const plan = planParkedHarnessInstall({
            agentAccount: accountName,
            agentUid: uid,
            harnessArgv: resolved.programArguments,
            fortressPath: process.env.SANCTUARY_STORAGE_PATH,
            logDir: harnessLogDir,
            environment: resolved.environment,
          });
          await executeParkedHarnessInstall(plan, {
            writeFile: daemonOps.writeFile,
            removeFile: daemonOps.removeFile,
            runLaunchctl: daemonOps.runLaunchctl,
            harnessStatus: () => agentHarnessDaemonStatus(daemonOps),
          });
          return { ok: true as const, bootstrappedThisRun: false, parked: true };
        }
        const plan = planAgentHarnessDaemonInstall({
          agentAccount: accountName,
          programArguments: resolved.programArguments,
          fortressPath: process.env.SANCTUARY_STORAGE_PATH,
          logDir: harnessLogDir,
          environment: resolved.environment,
        });
        await installAgentHarnessDaemon(plan, daemonOps);
        return { ok: true as const, bootstrappedThisRun: before.known && !before.installed };
      } catch (err) {
        return {
          ok: false as const,
          error: (err as Error).message,
          daemonPreexisted: before.installed || !before.known,
        };
      }
    },
    // FIX (round 5, item N3): tear the harness daemon back down on a
    // post-install abort. `installHarnessDaemon` bootstraps a LIVE root
    // LaunchDaemon (it runs `launchctl bootstrap system <plist>`); before
    // this op, the orchestrator's post-install abort branches restored the
    // re-home but left that daemon running under the dedicated account while
    // reporting a clean rollback. Reuses the shipped fail-loud uninstaller.
    uninstallHarnessDaemon: async () => {
      await uninstallAgentHarnessDaemon(realHarnessDaemonOps());
    },
    // Bug B (the one-flow gap): ensure a reachable Castle Wall POLICY daemon for
    // the target fortress BEFORE arming. Arming with no policy daemon deny-all-
    // locks the box, so on a box with no wall for this fortress the flow would
    // otherwise roll back at the arm's own refuse gate. This op stands the
    // policy daemon up (or refuses to swap a different fortress's wall) so arm
    // can proceed -- it NEVER arms the filter itself, and NEVER leaves the box
    // filter-on/daemon-down. The boot service is a SINGLETON (one launchd label,
    // one plist, per machine), which is exactly why "a boot service exists for a
    // DIFFERENT fortress" must REFUSE rather than swap.
    ensurePolicyDaemon: async (fortressPath) => {
      const socketPath = resolveCastleWallSocketPath({ platform: "darwin", fortressPath }).path;
      const { defaultDaemonProbe } = await import("../cli/castle-wall.js");
      const {
        runInstallBoot,
        bootServiceInstalled,
        bootServiceLoadState,
        bootServicePlistPresent,
        bootServiceReady,
        CASTLE_WALL_BOOT_PLIST_PATH,
      } = await import("../cli/castle-wall-boot.js");
      // 1. Probe the SAME socket the arm probes, then inspect the SINGLETON
      //    boot-service state. Bug D: a transient/manual daemon can answer the
      //    socket NOW while no persistent boot service exists, and the arm's
      //    reboot-survival guard correctly refuses that state. So reachability
      //    is necessary but not sufficient; the no-op case requires BOTH a
      //    reachable socket and a matching boot service for this fortress.
      //    `bootServiceInstalled(plist, fortress)` confirms a well-formed unit
      //    targets THIS fortress; `bootServiceLoadState` confirms the singleton
      //    launchd label is loaded for THIS fortress; `bootServiceReady`
      //    additionally confirms a stable pid. A matching-but-stopped plist must
      //    restart, not no-op. A matching loaded service whose socket already
      //    answers must NOT be destructively booted out just because the stable
      //    sample window missed. The occupancy check treats either a singleton
      //    plist path OR a loaded singleton launchd label as "some wall exists."
      //    If that state is unverifiable, treat it as a conflict rather than
      //    silently overwriting unknown wall state.
      const socketReachable = await defaultDaemonProbe(socketPath);
      const [diskForThisFortress, readyForThisFortress, plistPresent] = await Promise.all([
        bootServiceInstalled(CASTLE_WALL_BOOT_PLIST_PATH, fortressPath),
        bootServiceReady(CASTLE_WALL_BOOT_PLIST_PATH, fortressPath),
        bootServicePlistPresent(CASTLE_WALL_BOOT_PLIST_PATH),
      ]);
      const loadedState = bootServiceLoadState();
      const action = resolvePolicyDaemonActionForAutoProvision({
        socketReachable,
        diskForThisFortress,
        readyForThisFortress,
        plistPresent,
        loadedState,
        fortressPath,
      });
      if (action === "noop") {
        return { ok: true as const, freshlyInstalled: false };
      }
      if (action === "refuse-conflict") {
        // Single wall per machine: DO NOT silently stand the machine's existing
        // wall down. Refuse and let the flow roll back its prior steps.
        return {
          ok: false as const,
          freshlyInstalled: false,
          error:
            `a Castle Wall boot service already exists for a different or unverifiable fortress; one machine runs one wall -- ` +
            `arming ${fortressPath} would replace it. Stand the existing wall down first ` +
            `('sudo sanctuary castle-wall disable' then 'sudo sanctuary castle-wall uninstall-boot --yes'), then re-run.`,
        };
      }
      // "install-fresh" and "restart-existing" both drive install-boot for THIS
      // fortress: it stands one up from nothing AND is idempotent (re-bootstraps
      // a stopped unit that already matches). `freshlyInstalled` is true ONLY
      // when NO wall existed before this run, so an abort tears down exactly
      // what this run created and never a pre-existing wall.
      const freshlyInstalled = action === "install-fresh";
      try {
        await options.stopTransientCastleWallDaemon?.();
      } catch (err) {
        return {
          ok: false as const,
          freshlyInstalled: false,
          error:
            `could not stop the transient Castle Wall daemon before installing the persistent boot service: ` +
            `${err instanceof Error ? err.message : String(err)}`,
        };
      }
      const code = await runInstallBoot(
        policyDaemonInstallBootArgs(fortressPath, options.cliBinary),
        { env: process.env },
      );
      if (code !== 0) {
        // install-boot boots out its own crash-looping unit on a start failure,
        // so on a fresh box nothing is normally left live; `freshlyInstalled` is
        // still reported so the orchestrator's teardown is belt-and-suspenders
        // if a unit somehow lingers.
        return {
          ok: false as const,
          freshlyInstalled,
          error:
            `could not ${freshlyInstalled ? "install" : "restart"} the Castle Wall policy daemon for ${fortressPath} ` +
            `(install-boot exited ${code}); not arming (arming with no policy daemon would deny-all-lock this machine).`,
        };
      }
      if (!(await bootServiceReady(CASTLE_WALL_BOOT_PLIST_PATH, fortressPath))) {
        return {
          ok: false as const,
          freshlyInstalled,
          error:
            `install-boot exited 0 for ${fortressPath}, but no matching ready persistent Castle Wall boot service ` +
            `is installed; not arming (the arm reboot-survival guard would refuse, and arming without it ` +
            `would reintroduce the F1 boot-cut).`,
        };
      }
      // install-boot certified a STABLE pid; the daemon still needs a moment to
      // bind its socket. Poll (bounded) until it actually answers before
      // declaring the daemon ready -- fail-closed if it never does.
      const reachable = await pollSocketReachable(socketPath, defaultDaemonProbe, POLICY_DAEMON_SOCKET_BUDGET_MS);
      if (!reachable) {
        return {
          ok: false as const,
          freshlyInstalled,
          error:
            `the Castle Wall policy daemon for ${fortressPath} was ${freshlyInstalled ? "installed" : "restarted"} ` +
            `but its socket (${socketPath}) never became reachable within ` +
            `${Math.round(POLICY_DAEMON_SOCKET_BUDGET_MS / 1000)}s; not arming (fail-closed).`,
        };
      }
      return { ok: true as const, freshlyInstalled };
    },
    // Bug B: tear the FRESHLY-INSTALLED singleton boot (policy) service back
    // down on an abort after a fresh install (bootout + remove the plist),
    // restoring the prior "no wall" state. Only ever invoked by the orchestrator
    // when ensurePolicyDaemon reported `freshlyInstalled:true`; never for a
    // pre-existing wall. `--yes` confirms the (safe here: filter NOT armed)
    // removal. Fail-loud: a nonzero exit throws so the orchestrator surfaces it.
    teardownPolicyDaemon: async () => {
      const { runUninstallBoot } = await import("../cli/castle-wall-boot.js");
      const code = await runUninstallBoot(["--yes", "--fortress", wallFortressPath], { env: process.env });
      if (code !== 0) {
        throw new Error(`castle-wall uninstall-boot exited ${code}`);
      }
    },
    // Confined-agent egress (design section 5 layer 1): publish the Hermes
    // endpoint set as provenance-tagged signed allow rules through the
    // reachable policy daemon's pinned-signer reload path, then STATICALLY
    // verify each declared endpoint evaluates to an allow against the rules
    // READ BACK from the persisted signing source (never in-memory intent),
    // plus the #380 derived-DNS presence. Fail-closed: any publish, reload,
    // or verify failure returns ok:false and the orchestrator aborts before
    // arm.
    provisionEgress: async () => {
      const { requestPolicyReload } = await import("../cli/castle-wall.js");
      const reloadPolicy = async () => {
        const result = await requestPolicyReload(wallFortressPath, "darwin");
        return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
      };
      const published = await publishProvisionedEgressRules({
        fortressPath: wallFortressPath,
        endpointSet: HERMES_ENDPOINT_SET,
        reloadPolicy,
      });
      if (!published.ok) {
        return { ok: false as const, error: published.error };
      }
      let staticVerify;
      try {
        const persistedRules = await readEgressRulesFromDisk(wallFortressPath);
        // Same resolver enumeration the daemon signs with (a fresh
        // scutil --dns read on macOS, empty on failure): the static verify
        // must judge the derived DNS rule against the resolver set the
        // host's queries actually go to (2026-07-12 drill bug: Tailscale
        // MagicDNS was the live resolver but absent from the daemon's stale
        // dns.getServers() snapshot).
        const { collectSystemResolvers } = await import(
          "../castle-wall/runtime/system-resolvers.js"
        );
        staticVerify = verifyProvisionedEgressStatically(
          persistedRules,
          HERMES_ENDPOINT_SET,
          await collectSystemResolvers(),
          new Date().toISOString(),
        );
      } catch (err) {
        return {
          ok: false as const,
          error: `static egress verification could not read back the persisted ruleset: ${(err as Error).message}`,
        };
      }
      if (!staticVerify.ok) {
        const failed = staticVerify.checks.filter((c) => !c.allowed).map((c) => c.name);
        return {
          ok: false as const,
          error:
            `static egress verification failed: ` +
            (failed.length > 0 ? `no allow match for ${failed.join(", ")}; ` : "") +
            (staticVerify.dnsRulePresent
              ? ""
              : "the scoped DNS allow (#380) could not be derived (resolver set unknown or no hostname allows)"),
          checks: staticVerify.checks,
          dnsRulePresent: staticVerify.dnsRulePresent,
        };
      }
      return {
        ok: true as const,
        ruleIds: published.ruleIds,
        checks: staticVerify.checks,
        dnsRulePresent: staticVerify.dnsRulePresent,
      };
    },
    // Scrub every provisioned-hermes-* rule from the signing source (verified
    // read-back) and best-effort propagate to a still-running daemon. Used on
    // abort/rollback so a failed run never leaves orphan grants.
    scrubProvisionedEgress: async () => {
      const { requestPolicyReload } = await import("../cli/castle-wall.js");
      await scrubProvisionedEgressRules({
        fortressPath: wallFortressPath,
        harnessId: agentId,
        reloadPolicy: async () => {
          const result = await requestPolicyReload(wallFortressPath, "darwin");
          return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
        },
      });
    },
    // Post-arm as-uid egress verification (design section 5): spawn a probe
    // process under the AGENT uid (`sudo -n -u '#<uid>'`; the wall and the
    // classifier key on the REAL uid) that completes a TCP+TLS connect to
    // each declared endpoint through the ARMED wall, plus the non-listed
    // negative control which must stay BLOCKED. Fail-closed: a spawn error,
    // nonzero exit, or timeout reads as blocked, and an empty declared set
    // fails the report outright (F1 parity).
    verifyAgentEgressAfterArm: async (uid) => runAgentEgressProbesAsUid(uid, execFileAsync),
    // Egress audit records (distinct LOCAL operation strings) through the
    // same best-effort CLI audit path the arm/disarm records use. Never
    // throws: an audit-write failure must not mask the outcome it records.
    auditEgress: async (operation, details) => {
      try {
        const { appendCastleWallCliAuditBestEffort } = await import("../cli/castle-wall.js");
        await appendCastleWallCliAuditBestEffort(
          operation,
          { source: "sanctuary-protect", ...details },
          wallFortressPath,
          process.env,
          process.stderr,
        );
      } catch {
        // Best-effort by contract (the helper itself already warns; this
        // catch covers the dynamic import failing).
      }
    },
    // FIX R1 (BLOCKER, fix-round 2): honest, fail-closed probe list -- see
    // `hermesEndpointProbes` above. `resolvedAgentUidGid` is always set by
    // `installHarnessDaemon` before this is called (steps 6 -> 7); if it is
    // somehow still undefined, fail closed to an unreachable synthetic probe
    // rather than defaulting to the CONSOLE owner's uid, which would silently
    // check readability against the wrong identity.
    preArmEndpoints: () => resolveEndpointProbes(newAccountHome, resolvedAgentUidGid, movedCredentialDestPaths),
    checkUidExistence: async (uid) => {
      const { checkUidExistenceBeforeArm } = await import("../castle-wall/provision/uid-gate.js");
      return checkUidExistenceBeforeArm(accountName, uid, realUidExistenceOps());
    },
    arm: async (uid, ceiling) => {
      const { runEnable } = await import("../cli/castle-wall.js");
      // Bug B (consistency): target the SAME fortress the flow provisioned +
      // ensured a policy daemon for. Without `--fortress`, runEnable resolves
      // via resolveStoragePath(env), which under sudo is root's /var/root
      // fortress -- so a non-default fortress would be probed at the WRONG
      // socket and the arm's own daemon-reachability gate would refuse.
      const code = await runEnable([
        "--fortress",
        wallFortressPath,
        `--agent-uid=${uid}`,
        `--ceiling=${ceiling}`,
        "--no-ttl",
      ]);
      return code === 0 ? { ok: true } : { ok: false, error: `castle-wall enable exited ${code}` };
    },
    postArmEndpoints: () => resolveEndpointProbes(newAccountHome, resolvedAgentUidGid, movedCredentialDestPaths),
    // FIX G1 (HIGH, 2026-07-07 re-gate 3 / fix-round 3): see
    // `disarmExitCodeDecision` above for the full rationale -- `runDisable`
    // returns (does not throw) a nonzero code on failure, and this closure
    // must throw in that case so `orchestrate.ts`'s already-wired catch
    // routes it to `armed-rollback-failed` instead of silently falling
    // through to `armed-then-rolled-back`.
    disarm: async () => {
      const { runDisable } = await import("../cli/castle-wall.js");
      // Bug B (consistency): disarm the SAME fortress the arm targeted (see the
      // arm op above) so the fast post-arm rollback lever cannot miss the wall
      // it just armed on a non-default fortress.
      //
      // Bug B P1: capture whether the disable AFFIRMATIVELY confirmed the NE
      // preference is OFF, surfaced alongside the exit code via the
      // onDisableNeConfirmedOff out-callback (runDisable's numeric contract is
      // unchanged for every other caller). A non-throwing disarm alone is NOT
      // sufficient to remove a freshly-installed policy daemon -- the
      // fail-open-after-lease-revoke sub-case returns success while the NE
      // preference may still be enabled -- so the orchestrator tears the fresh
      // daemon down only when `neConfirmedOff === true`.
      let neConfirmedOff = false;
      const code = await runDisable(["--fortress", wallFortressPath], {
        onDisableNeConfirmedOff: (confirmed) => {
          neConfirmedOff = confirmed;
        },
      });
      throwIfDisarmFailed(code);
      return { neConfirmedOff };
    },
    restoreRehome: async (results: RehomeStepResult[]) => {
      // FIX F2/F3 (2026-07-07 fix-round): thread the OPERATOR's uid/gid
      // (the console-session owner this whole flow is provisioning away
      // from) so restored secrets are handed back with correct custody, and
      // report what ACTUALLY restored rather than assuming success.
      // FIX R2 (HIGH, fix-round 2): under sudo, `consoleOwnerUid`/
      // `consoleOwnerGid` (below) are resolved from the SUDO-aware operator
      // identity, not the raw root identity `userInfo()` would otherwise
      // report -- see the `operatorIdentity` resolution above.
      const restoreResult = await restoreRehomeSteps(results, realRehomeOps(), {
        uid: consoleOwnerUid,
        gid: consoleOwnerGid,
      });
      return {
        fullyRestored: restoreResult.fullyRestored,
        restoredCount: restoreResult.steps.filter((s) => s.status === "restored").length,
        attemptedCount: restoreResult.steps.filter((s) => s.status !== "skipped-absent").length,
        backupPaths: results.filter((r) => r.backupPath !== undefined).map((r) => r.backupPath!),
        // FIX (round 5 / R5-2): surface R6 conflict paths (recreated-source
        // restores) so the orchestrator/CLI report "recovered data is safe at
        // <conflictPath>; reconcile manually" instead of a false "restore
        // FAILED / overwrite from the stale backup".
        conflictPaths: restoreResult.steps
          .filter((s) => s.status === "conflict" && s.conflictPath !== undefined)
          .map((s) => s.conflictPath!),
        // FIX (round 5 / R6-2): the GENUINELY-failed source paths (status
        // "failed", distinct from a safe "conflict"), so the CLI keeps the
        // loud manual-recovery frame even when conflicts also occur.
        failedPaths: restoreResult.steps.filter((s) => s.status === "failed").map((s) => s.sourcePath),
      };
    },
  };

  const outcome = await withProvisionLock(PROVISION_LOCK_PATH, realLockOps(), () =>
    runProvisionFlow(
      {
        agentId,
        accountName,
        ceiling: PROVISION_CEILING,
        detectResult,
        isTty: options.isTty,
        preAnsweredProvision: options.preAnsweredProvision,
        fortressPath: wallFortressPath,
        // Confined-agent egress: the SAME endpoint set the provisioning +
        // probes consume, threaded for the Tier-1 confirm plan-print.
        harnessEndpoints: HERMES_ENDPOINT_SET,
        // S5-6: fine-grained (exclusive-egress) mode -- parked install +
        // exclusive arming stage after the coarse stages prove live.
        fineGrainedDeclared: options.exclusiveEgress === true,
      },
      { ...ops, ...(exclusiveEgressOps !== undefined ? { exclusiveEgress: exclusiveEgressOps } : {}) },
    ),
  );

  return { ran: true, outcome };
}

// ── Real op implementations (drill-only side effects; never exercised by CI) ──

/** Tuning + test seams for {@link runAgentEgressProbesAsUid}. */
export interface AgentEgressProbeOptions {
  /**
   * MED-3 (PR-905 review): max attempts for a POSITIVE-reachability probe
   * before declaring it failed. A single transient network flake against one
   * of the real endpoints must NOT roll back the whole provision, so the
   * reachability checks get a bounded retry. Default 3.
   */
  reachableAttempts?: number;
  /** Backoff between reachability retries (ms). Default 500. */
  backoffMs?: number;
  /** Sleep seam (tests inject a no-op so retries add no wall-clock delay). */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Run the post-arm as-uid egress probes (confined-agent egress design,
 * section 5): for each declared Hermes endpoint plus the negative control,
 * spawn `sudo -n -u '#<uid>' curl https://<host>:<port>/` and decide
 * reachability from the exit code (0 = reachable; anything else, including a
 * spawn failure, = blocked/unverified -- fail-closed). This whole module
 * runs as ROOT under `sudo sanctuary protect`, so `sudo -u` genuinely
 * changes the REAL uid the wall keys on; `-n` (non-interactive) means a
 * sudoers surprise fails loudly instead of hanging on a prompt. Exported for
 * the unit suite, which drives it with an injected execFile and never spawns
 * real processes.
 *
 * MED-3 (PR-905 review) asymmetric retry: the POSITIVE reachability checks
 * are flake-prone (one transient network blip against a real endpoint should
 * not brick the provision), so each gets a bounded retry (default 3 attempts,
 * short backoff). The NEGATIVE control (a non-listed host must be BLOCKED) is
 * a SECURITY assertion and is single-shot, NEVER retried: one reachable
 * observation of the negative control is a real confinement failure, and
 * retrying could only mask it.
 */
export async function runAgentEgressProbesAsUid(
  uid: number,
  execFileFn: (
    file: string,
    args: string[],
  ) => Promise<{ stdout: string; stderr: string }>,
  options: AgentEgressProbeOptions = {},
): Promise<AgentEgressVerifyReport> {
  const reachableAttempts = Math.max(1, options.reachableAttempts ?? 3);
  const backoffMs = options.backoffMs ?? 500;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const specs = buildAgentEgressProbeSpecs(HERMES_ENDPOINT_SET);
  const observed: boolean[] = [];
  for (const spec of specs) {
    const { file, args } = asUidTlsProbeArgv(uid, spec.host, spec.port);
    // MED-3: retry ONLY the flake-prone positive-reachability checks; the
    // negative control (expected "blocked") stays single-shot so a security
    // failure is never retried away.
    const attempts = spec.expected === "reachable" ? reachableAttempts : 1;
    let reachable = false;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        await execFileFn(file, args);
        // execFile resolves only on exit code 0.
        reachable = asUidProbeReachableDecision(0);
        break;
      } catch {
        // Nonzero exit, signal death, or spawn failure: blocked/unverified.
        reachable = false;
      }
      if (attempt < attempts) {
        await sleep(backoffMs);
      }
    }
    observed.push(reachable);
  }
  return buildAgentEgressReport(specs, observed);
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** Paths for the non-secret Hermes runtime tree that may be left behind by an aborted dedicated-account run. */
export function hermesRuntimeRehomePaths(
  operatorHome: string,
  newAccountHome: string,
): { sourcePath: string; destPath: string } {
  const operatorBase = operatorHome.replace(/\/+$/, "");
  const accountBase = newAccountHome.replace(/\/+$/, "");
  return {
    sourcePath: `${operatorBase}/.hermes/hermes-agent`,
    destPath: `${accountBase}/.hermes/hermes-agent`,
  };
}

/**
 * Retry cleanup for the Hermes runtime code tree only. If a previous aborted
 * run left a duplicate non-secret runtime at the dedicated-account
 * destination while the operator source is also present, move the stale
 * destination aside before `rename(source, dest)`.
 */
export async function moveAsideStaleHermesRuntimeDestination(
  operatorHome: string,
  newAccountHome: string,
): Promise<string | undefined> {
  const { sourcePath, destPath } = hermesRuntimeRehomePaths(operatorHome, newAccountHome);
  if (!(await pathExists(sourcePath)) || !(await pathExistsNoFollow(destPath))) {
    return undefined;
  }
  const conflictPath = await findUniqueConflictPath(destPath);
  await rename(destPath, conflictPath);
  return conflictPath;
}

/**
 * FIX (round 5, item b): no-follow existence check. `access()`/`stat()`
 * FOLLOW symlinks, so a DANGLING symlink (a symlink whose target does not
 * exist) reads as "does not exist" -- which let `findUniqueConflictPath` and
 * the restore-conflict guard treat a symlink-occupied path as free and then
 * clobber the symlink with a rename/copy. `lstat` does NOT follow the final
 * component, so ANY name present at `path` (a real file/dir, a live symlink,
 * or a dangling symlink) counts as occupied. Fail-closed: a name we cannot
 * even `lstat` for any reason other than ENOENT is treated as present (never
 * assume a path is free on an ambiguous error before we overwrite it).
 */
async function pathExistsNoFollow(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

async function readHarnessConfiguredUid(): Promise<number | undefined> {
  // v1: the Hermes gateway plist (a per-user LaunchAgent today) declares no
  // UserName/uid pin, so there is no config-declared identity to read yet.
  // This returns undefined until re-homing installs the root LaunchDaemon,
  // at which point a FUTURE run's harness-config probe (reading the
  // installed daemon's plist) would resolve it -- left as a documented
  // follow-up rather than guessed at here (fail-closed: absence, not a
  // fabricated value).
  return undefined;
}

async function readRunningHermesGatewayUid(): Promise<number | undefined> {
  try {
    const { stdout } = await execFileAsync("/bin/ps", ["-axo", "uid,command"]);
    const line = stdout.split("\n").find((l) => l.includes("hermes_cli.main gateway"));
    if (!line) return undefined;
    const match = /^\s*(\d+)/.exec(line);
    return match ? Number(match[1]) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * FIX F6 (HIGH, Codex second family, 2026-07-07 fix-round): verify that the
 * account at `candidateUid` is GENUINELY the expected `sanctuary-<agentId>`
 * dedicated service account, not merely some other non-console uid >=
 * ceiling (a stale prior service account, or any other daemon/service
 * account happens to satisfy the uid test). Checks, ALL of which must hold:
 *   - the account NAME at this uid is exactly `expectedAccountName`
 *     (`sanctuary-<agentId>`), read via `dscl . -search /Users UniqueID` so
 *     the name<->uid binding comes from the directory service, not assumed;
 *   - `IsHidden` is `1`;
 *   - the login shell is `/usr/bin/false` (no-login shape).
 * Any dscl failure, any missing field, or any mismatch resolves
 * `"indeterminate"`/`"not-dedicated"` -- fail-closed, never `"verified-dedicated"`
 * on an ambiguous read.
 */
async function resolveAccountShapeVerdict(
  expectedAccountName: string,
  candidateUid: number,
): Promise<"verified-dedicated" | "not-dedicated" | "indeterminate"> {
  try {
    const { stdout: searchOut } = await execFileAsync("/usr/bin/dscl", [
      ".",
      "-search",
      "/Users",
      "UniqueID",
      String(candidateUid),
    ]);
    // FIX (round 5, item N4): dscl -search emits the parenthesized multi-line
    // form (`<name>\t\tUniqueID = (\n  <uid>\n)`); the pre-fix same-line-digit
    // regex never matched it, so this verdict ALWAYS fell to "not-dedicated"
    // and the alreadyDedicated fast-path could never confirm a genuinely
    // dedicated account. Parse the real shape and require the expected account
    // name to be among the matched records.
    const searchedNames = parseDsclSearchAccountNames(searchOut);
    if (!searchedNames.includes(expectedAccountName)) {
      return "not-dedicated";
    }
    const { stdout: hiddenOut } = await execFileAsync("/usr/bin/dscl", [
      ".",
      "-read",
      `/Users/${expectedAccountName}`,
      "IsHidden",
    ]);
    if (!/IsHidden:\s*1/.test(hiddenOut)) {
      return "not-dedicated";
    }
    const { stdout: shellOut } = await execFileAsync("/usr/bin/dscl", [
      ".",
      "-read",
      `/Users/${expectedAccountName}`,
      "UserShell",
    ]);
    if (!/UserShell:\s*\/usr\/bin\/false/.test(shellOut)) {
      return "not-dedicated";
    }
    return "verified-dedicated";
  } catch {
    // Fail-closed: any probe error is indeterminate, never verified.
    return "indeterminate";
  }
}

async function confirmOnTty(promptText: string): Promise<boolean> {
  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(promptText);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

function realAccountProvisionOps() {
  return {
    lookupAccountUid: async (accountName: string): Promise<number | undefined> => {
      try {
        const { stdout } = await execFileAsync("/usr/bin/dscl", [".", "-read", `/Users/${accountName}`, "UniqueID"]);
        const match = /UniqueID:\s*(\d+)/.exec(stdout);
        return match ? Number(match[1]) : undefined;
      } catch {
        return undefined;
      }
    },
    highestAssignedUid: async (): Promise<number> => {
      const { stdout } = await execFileAsync("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]);
      let highest = PROVISION_CEILING - 1;
      for (const line of stdout.split("\n")) {
        const match = /\s(\d+)\s*$/.exec(line);
        if (match) highest = Math.max(highest, Number(match[1]));
      }
      return highest;
    },
    createUser: async (
      accountName: string,
      uid: number,
      comment: string | undefined,
      homeDirectory: string,
    ): Promise<void> => {
      // Drill-only: real account creation happens exclusively in an
      // Erik-present console ceremony on real hardware. This build never
      // invokes this path in CI or in any automated run; it exists so the
      // production ops object satisfies the AccountProvisionOps interface
      // for the orchestration to call end to end during the drill.
      //
      // FIX F7 (HIGH/PLAUSIBLE, Codex second family, 2026-07-07 fix-round):
      // `-home` binds NFSHomeDirectory to the re-home target at create
      // time, so the confined harness (running as this account) resolves
      // ~/.hermes to where the secrets actually get moved, instead of
      // whatever sysadminctl would otherwise default the home to. Verified
      // with an explicit `dscl -create NFSHomeDirectory` follow-up (belt
      // and suspenders: `-home` is documented sysadminctl behavior, but the
      // dscl write makes the binding explicit and independently checkable).
      await execFileAsync("/usr/sbin/sysadminctl", [
        "-addUser",
        accountName,
        "-UID",
        String(uid),
        "-shell",
        "/usr/bin/false",
        "-home",
        homeDirectory,
        ...(comment ? ["-fullName", comment] : []),
      ]);
      await execFileAsync("/usr/bin/dscl", [".", "-create", `/Users/${accountName}`, "IsHidden", "1"]);
      await execFileAsync("/usr/bin/dscl", [
        ".",
        "-create",
        `/Users/${accountName}`,
        "NFSHomeDirectory",
        homeDirectory,
      ]);
    },
  };
}

/**
 * FIX G2 (HIGH, 2026-07-07 re-gate 3 / fix-round 3): find a conflict-sibling
 * path that does NOT already exist, trying `${sourcePath}.restored-conflict`
 * first, then `.restored-conflict.1`, `.restored-conflict.2`, ... . The R6
 * fix (fix-round 2) stopped `restore` from overwriting a RECREATED
 * `sourcePath`, but the conflict-sibling target it restored into
 * (`${sourcePath}.restored-conflict`) was itself unguarded: a PRE-EXISTING
 * conflict sibling (left over from a prior aborted run, or planted by the
 * operator/some other process) was silently clobbered by the rename/copy --
 * the exact R6 defect, one path over, while still reporting a "handled
 * safely" `{ restored: false, conflictPath }` outcome. Bounded at 1000
 * suffixes (fail-closed: this is a real-ops path, not a place to spin
 * forever on a pathological directory full of stale conflict files).
 *
 * FIX (round 5, item b): existence is checked with {@link pathExistsNoFollow}
 * (`lstat`, no symlink follow), not `access()`. A DANGLING symlink at the
 * conflict target otherwise read as "free" under `access()` and got clobbered
 * by the rename/copy -- the exact G2 defect, one indirection over. Any
 * symlink at a candidate path (live or dangling) now counts as occupied, so
 * the moved data lands on a genuinely free name and never destroys a symlink
 * an operator or prior run left behind.
 */
async function findUniqueConflictPath(sourcePath: string): Promise<string> {
  const base = `${sourcePath}.restored-conflict`;
  if (!(await pathExistsNoFollow(base))) {
    return base;
  }
  const MAX_SUFFIX = 1000;
  for (let i = 1; i <= MAX_SUFFIX; i++) {
    const candidate = `${base}.${i}`;
    if (!(await pathExistsNoFollow(candidate))) {
      return candidate;
    }
  }
  throw new Error(
    `could not find a free conflict-sibling path for ${sourcePath} after ${MAX_SUFFIX} attempts; refusing to overwrite`,
  );
}

/**
 * Recursively chmod a file or directory tree (files 0600, dirs 0700),
 * matching custody mode for both shapes.
 *
 * FIX (round 5, item N2): symlink-safe. The pre-fix helper used `stat`
 * (follows symlinks) and `readdir` on a path that could itself be a
 * symlink-to-directory, so a symlink smuggled into a moved/restored secret
 * tree let a ROOT chmod escape the tree and alter an arbitrary operator file,
 * or recurse through the link's target. Now every entry is `lstat`'d first:
 * a symlink is SKIPPED entirely (its own permission bits are irrelevant on
 * Linux and must never be dereferenced), and recursion only descends into a
 * REAL directory, never a symlink-to-directory.
 */
async function chmodRecursive(path: string): Promise<void> {
  const st = await lstat(path);
  if (st.isSymbolicLink()) {
    // Never chmod a symlink's target, never recurse through it.
    return;
  }
  if (st.isDirectory()) {
    await chmod(path, 0o700);
    const { readdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const entries = await readdir(path);
    for (const entry of entries) {
      await chmodRecursive(join(path, entry));
    }
  } else {
    await chmod(path, 0o600);
  }
}

/**
 * Recursively chown a file or directory tree to uid/gid.
 *
 * FIX (round 5, item N2): symlink-safe. `fs.chown`/`fs.stat` FOLLOW symlinks,
 * so the pre-fix helper let a ROOT chown of a moved/restored tree dereference
 * a symlink and re-own an arbitrary operator file OUTSIDE the tree, or recurse
 * through a symlink-to-directory. Now every entry is `lstat`'d: a symlink is
 * chowned via `lchown` (the LINK itself, never its target) and never recursed
 * into; recursion only descends into a REAL directory.
 */
async function chownRecursive(path: string, uid: number, gid: number): Promise<void> {
  const st = await lstat(path);
  if (st.isSymbolicLink()) {
    // Chown the link itself (never its target); do not recurse through it.
    await lchown(path, uid, gid);
    return;
  }
  await fsChown(path, uid, gid);
  if (st.isDirectory()) {
    const { readdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const entries = await readdir(path);
    for (const entry of entries) {
      await chownRecursive(join(path, entry), uid, gid);
    }
  }
}

/**
 * Exported (fix chokepoint, 2026-07-07 fix-round 2) so the real-ops unit
 * suite can exercise the ACTUAL restore-conflict decision logic (R6) against
 * a real, disposable tmpdir -- not a mock standing in for it.
 *
 * FIX (round 5, item d): the backup root is injectable via `opts.backupRoot`,
 * defaulting to the production `/var/root/...` location. This is a test-only
 * seam: the real-ops unit suite points it at a disposable tmpdir so the
 * backup-copy FALLBACK conflict branch (destPath gone, backup present, source
 * recreated) can be exercised end-to-end WITHOUT root, which the previous seam
 * could only document as a non-root-testable boundary. Production callers pass
 * no argument and get the root-only backup root unchanged.
 */
export function realRehomeOps(opts?: { backupRoot?: string }) {
  const backupRoot = opts?.backupRoot ?? "/var/root/.sanctuary-rehome-backups";
  return {
    pathExists,
    backup: async (path: string): Promise<{ backupPath: string }> => {
      // Fix M4: the pre-re-home secrets backup MUST be root-only (0600 for
      // files, 0700 for directories) -- NEVER an operator-readable plaintext
      // copy whose mode is left to whatever the process umask happens to
      // produce (AGENTS.md invariant #6). `copyFile` does not accept a mode
      // argument, so the mode is set explicitly with `chmod` immediately
      // after the copy, closing the umask-dependent window.
      const backupPath = `${backupRoot}${path}.bak`;
      await mkdir(dirname(backupPath), { recursive: true, mode: 0o700 });
      // FIX (round 5 / R5-1, generalizing R4-1): remove any pre-existing name
      // at backupPath BEFORE writing, for ALL shapes. Nothing cleans up the
      // backup root, so a `.bak` from a prior aborted run survives; if it is a
      // stale SYMLINK, `copyFile`/`cp` (file/dir branches) FOLLOW it -- writing
      // the secret's plaintext THROUGH the link to its old (possibly
      // operator-readable) target and clobbering whatever lived there (M4 /
      // AGENTS.md #6 leak + data-loss), while `symlink()` throws EEXIST. A
      // single no-follow rm-first makes every branch idempotent AND never
      // follows a stale link. Safe: the backup is always re-derived from the
      // current source (which must exist for backup to run).
      await rm(backupPath, { force: true, recursive: true });
      // FIX (round 5 / R3-1): decide the shape by `lstat` (no-follow), not
      // `stat`. A symlinked secret must be backed up as the LINK itself, never
      // dereferenced -- otherwise `stat` reports a symlink-to-directory as a
      // directory and the recursive copy below would follow it into
      // operator-owned space (and `cp` with dereference:false would instead
      // produce a data-less symlink "backup"). This matches the PR's pervasive
      // lstat/no-follow symlink posture (N2, R2-1, R2-4).
      const st = await lstat(path);
      if (st.isSymbolicLink()) {
        // Preserve the link faithfully (target string only); a symlinked
        // credential is rejected at verify (R2-4) and reverse-moved as the
        // original link on abort (R2-1), so this backup only needs to restore
        // the link if destPath is ever gone. No chmod: a symlink's own mode is
        // irrelevant and must never be dereferenced.
        await symlink(await readlink(path), backupPath);
      } else if (st.isDirectory()) {
        // FIX F2 (2026-07-07 fix-round): the M4 custody copy for a
        // directory-shaped secret (e.g. `.hermes/google-mcp-creds/`,
        // `.workspace-mcp/cli-tokens/`) must be a REAL recursive copy, not
        // an empty placeholder directory -- an empty backup is not a backup.
        //
        // FIX (round 5 / R3-1): `cp`'s `mode` option is a COPYFILE_* copy-flag
        // bitmask constrained to 0-7, NOT a permission mode -- passing 0o700
        // (448) threw `ERR_OUT_OF_RANGE` synchronously before any bytes copied,
        // so the directory-backup branch was dead on every supported Node and
        // no real directory backup was ever produced. The mode is set by the
        // `chmodRecursive` immediately below (dirs 0700 / files 0600), which is
        // the documented M4 "explicit chmod after copy" intent, so the invalid
        // `mode` argument is simply dropped.
        await cp(path, backupPath, { recursive: true });
        await chmodRecursive(backupPath);
      } else {
        await copyFile(path, backupPath);
        await chmod(backupPath, 0o600);
      }
      return { backupPath };
    },
    move: async (sourcePath: string, destPath: string): Promise<void> => {
      await mkdir(dirname(destPath), { recursive: true, mode: 0o700 });
      await rename(sourcePath, destPath);
    },
    chown: async (path: string, uid: number, gid: number): Promise<void> => {
      await chownRecursive(path, uid, gid);
    },
    /**
     * FIX F2 (2026-07-07 fix-round): restore is a REVERSE-MOVE of `destPath`
     * (where `move`'s `rename` actually put the data) back to `sourcePath` --
     * correct for files AND directories, closing the defect where
     * `copyFile` on a directory threw and the M4 backup (previously an
     * empty placeholder dir) could not stand in for it either. Falls back
     * to the M4 backup copy ONLY if `destPath` itself is already gone
     * (e.g. a prior partial rollback already moved it), so a legitimate
     * custody copy is never left unused when it is the only remaining copy.
     * Reports whether data actually ended up at `sourcePath` -- never
     * assumes success.
     *
     * FIX R6 (HIGH, 2026-07-07 fix-round 2): `rename(destPath, sourcePath)`
     * SILENTLY overwrites a FILE that already exists at `sourcePath` -- if
     * the operator (or some other process) recreated a file at the original
     * path while it was re-homed, the prior code clobbered it without
     * warning and then reported a clean `restored: true`, because
     * `pathExists(sourcePath)` is trivially true after ANY successful
     * rename, overwrite or not. (A recreated DIRECTORY at `sourcePath` used
     * to fail loud via `rename`'s ENOTEMPTY instead of overwriting, which
     * was an acceptable stopgap; the fix below now handles files AND
     * directories the same, consistent way instead of relying on that
     * incidental ENOTEMPTY behavior.) The fix checks `sourcePath` for a
     * conflict BEFORE the rename and, on conflict, restores to a
     * `.restored-conflict` sibling path instead of overwriting -- the
     * operator's recreated data is never destroyed, and the caller can see
     * from the returned `conflictPath` that this needs manual reconciliation.
     *
     * FIX G2 (HIGH, 2026-07-07 re-gate 3 / fix-round 3): the R6 conflict-
     * sibling TARGET (`${sourcePath}.restored-conflict`) was itself
     * unguarded -- a PRE-EXISTING file at that exact path (a prior aborted
     * run's conflict copy, or anything else living there) was silently
     * overwritten by the rename/copy below, the exact R6 defect one path
     * over, while still reporting a "handled safely" outcome. Both the
     * rename branch and the backup-copy fallback branch now resolve a
     * UNIQUE, does-not-yet-exist conflict path via
     * {@link findUniqueConflictPath} before writing, so a pre-existing
     * conflict sibling is never clobbered either.
     */
    restore: async (destPath: string, sourcePath: string): Promise<{ restored: boolean; conflictPath?: string }> => {
      // FIX (round 5 / R2-1): no-follow. `pathExists` (access) FOLLOWS a
      // symlink, so a re-homed credential that is a DANGLING symlink at
      // destPath (a relative dotfile symlink whose target no longer resolves
      // once `rename`'d onto the agent home) read as "does not exist", the
      // F2 reverse-move was skipped, the symlink was stranded under the agent
      // home, and the backup-copy fallback restored a PLAIN FILE over the
      // operator's original symlink while reporting a clean restore. lstat
      // (no-follow) sees the moved name so the reverse-move faithfully
      // restores the original link. round-5(b) converted the sibling/conflict
      // checks; this destExists check was the one it missed.
      const destExists = await pathExistsNoFollow(destPath);
      await mkdir(dirname(sourcePath), { recursive: true, mode: 0o700 });
      if (destExists) {
        // FIX (round 5, item b): no-follow check -- a symlink recreated at
        // sourcePath (dangling or live) is a conflict, never a "free" path we
        // silently overwrite by following it elsewhere.
        const sourceConflict = await pathExistsNoFollow(sourcePath);
        if (sourceConflict) {
          // FIX R6: never overwrite operator data that was recreated at the
          // original path while it was re-homed. Restore the moved data to a
          // conflict path alongside it instead, and report the conflict
          // (never a bare "restored: true") so the caller surfaces loud
          // manual-recovery guidance.
          // FIX G2: the conflict path itself must not already be occupied.
          const conflictPath = await findUniqueConflictPath(sourcePath);
          await rename(destPath, conflictPath);
          return { restored: false, conflictPath };
        }
        await rename(destPath, sourcePath);
        // FIX (round 5 / R2-1): no-follow. The restore succeeds when a NAME
        // lands at sourcePath (the reverse-move/copy completed); whether a
        // restored symlink's target resolves is the operator's home's concern,
        // not restore's. `pathExists` (follow) would report a faithfully
        // restored-but-relative symlink as `restored: false`.
        return { restored: await pathExistsNoFollow(sourcePath) };
      }
      // destPath is already gone (unusual: implies a partial rollback
      // already ran). Fall back to the M4 backup copy, if this path had one.
      // FIX (round 5, item d): `backupRoot` is the injectable closure value
      // (defaults to the production /var/root location), so this fallback
      // branch is now reachable by the seam against a disposable tmpdir.
      const backupPath = `${backupRoot}${sourcePath}.bak`;
      // FIX (round 5 / R9-1): resolve the backup's shape with a SINGLE no-follow
      // `lstat`. If it cannot be lstat'd (absent, or unreadable -- e.g. the
      // production `/var/root/...` root-only backup root read as a non-root
      // test/process), there is no usable backup: return `{restored:false}`
      // cleanly (matching the pre-fix access()-fails-closed behavior) rather
      // than throwing. A symlink backup (which backup() deliberately stores for
      // a symlinked secret) is round-tripped faithfully via readlink/symlink --
      // the pre-fix `stat`/`copyFile` FOLLOWED the link and materialized the
      // target's contents as a PLAIN FILE at the restore target, silently
      // losing the link (contradicting backup()'s no-dereference contract and
      // the R2-1 faithful-link guarantee) while still reporting restored:true.
      // This was the last follow-semantics branch left after round-5(b)/R2-1.
      let backupStat;
      try {
        backupStat = await lstat(backupPath);
      } catch {
        return { restored: false };
      }
      const restoreBackupTo = async (target: string): Promise<void> => {
        if (backupStat.isSymbolicLink()) {
          await symlink(await readlink(backupPath), target);
        } else if (backupStat.isDirectory()) {
          await cp(backupPath, target, { recursive: true });
        } else {
          await copyFile(backupPath, target);
        }
      };
      const sourceConflict = await pathExistsNoFollow(sourcePath);
      if (sourceConflict) {
        // Same conflict guard for the backup-copy fallback: never overwrite a
        // recreated source (FIX R6) nor a pre-existing conflict sibling
        // (FIX G2) -- restore the backup to a fresh conflict path instead.
        const conflictPath = await findUniqueConflictPath(sourcePath);
        await restoreBackupTo(conflictPath);
        return { restored: false, conflictPath };
      }
      await restoreBackupTo(sourcePath);
      // FIX (round 5 / R2-1): no-follow -- the restore succeeds when a NAME
      // lands at sourcePath (the copy/link completed); whether a restored
      // symlink's target resolves is the operator's home's concern.
      return { restored: await pathExistsNoFollow(sourcePath) };
    },
    /** Fix F3: hand custody of a restored secret back to the operator. */
    restoreCustody: async (path: string, operatorUid: number, operatorGid: number): Promise<void> => {
      await chmodRecursive(path);
      await chownRecursive(path, operatorUid, operatorGid);
    },
  };
}

function realUidExistenceOps() {
  return {
    lookupAccountUid: async (accountName: string): Promise<number | undefined> => {
      try {
        const { stdout } = await execFileAsync("/usr/bin/id", ["-u", accountName]);
        const uid = Number(stdout.trim());
        return Number.isSafeInteger(uid) ? uid : undefined;
      } catch {
        return undefined;
      }
    },
  };
}

type BoundedLaunchctlExecFile = (
  file: string,
  args: string[],
  options: { timeout: number; killSignal: NodeJS.Signals },
) => Promise<{ stdout: string; stderr: string }>;

export async function runLaunchctlWithTimeout(
  args: readonly string[],
  execFileFn: BoundedLaunchctlExecFile = execFileAsync as BoundedLaunchctlExecFile,
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileFn("/bin/launchctl", [...args], {
      timeout: LAUNCHCTL_TIMEOUT_MS,
      killSignal: LAUNCHCTL_KILL_SIGNAL,
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code?: unknown; stdout?: string; stderr?: string; message?: string };
    const code = typeof e.code === "number" ? e.code : 1;
    const errorText = typeof e.code === "string" ? `${e.code}: ${e.message ?? String(err)}` : String(err);
    return { code, stdout: e.stdout ?? "", stderr: [e.stderr ?? "", errorText].filter(Boolean).join("\n") };
  }
}

function realHarnessDaemonOps(): HarnessDaemonOps {
  return {
    writeFile: async (path, content, mode) => {
      const { writeFile } = await import("node:fs/promises");
      await writeFile(path, content, { mode });
    },
    removeFile: async (path) => {
      const { unlink } = await import("node:fs/promises");
      await unlink(path).catch((err) => {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      });
    },
    runLaunchctl: async (args) => {
      return runLaunchctlWithTimeout(args);
    },
    sleepMs: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
  };
}

function realLockOps() {
  return {
    acquire: async (lockPath: string): Promise<void> => {
      const { open } = await import("node:fs/promises");
      const handle = await open(lockPath, "wx");
      await handle.close();
    },
    release: async (lockPath: string): Promise<void> => {
      const { unlink } = await import("node:fs/promises");
      await unlink(lockPath).catch((err) => {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      });
    },
  };
}

/** Exposed for the CLI `unprovision`/rollback surface (reuses this module's real ops). */
export async function uninstallAutoProvisionedHarnessDaemon(): Promise<void> {
  await uninstallAgentHarnessDaemon(realHarnessDaemonOps());
}

// ── S5-6/S5-7: the `--repair-egress-gate` / `--unprotect-egress-gate` CLI runners ──

/**
 * The shared production {@link ExclusiveEgressWiringInput} for the Hermes
 * exclusive-egress CLI verbs (repair + unprotect): one construction so the
 * two runners can never drift on gate-daemon argv, endpoint set, audit
 * plumbing, or account ops. `auditSource` distinguishes the verbs in the
 * audit trail.
 */
function buildHermesExclusiveCliWiring(input: {
  agentUid: number;
  accountName: string;
  newAccountHome: string;
  wallFortressPath: string;
  harnessArgv: string[];
  operatorUid: number;
  auditSource: string;
  print: (line: string) => void;
  accountOps: ReturnType<typeof realAccountProvisionOps>;
  cliBinary?: string;
  /** S5-7 MED-1: argv-unavailable fallback park (remove the plist, not restore). */
  parkPlistFallbackRemoval?: boolean;
}): ExclusiveEgressWiringInput {
  const agentId = "hermes";
  const reloadPolicy = async (): Promise<{ ok: boolean; error?: string }> => {
    const { requestPolicyReload } = await import("../cli/castle-wall.js");
    const result = await requestPolicyReload(input.wallFortressPath, "darwin");
    return result.ok ? { ok: true } : { ok: false, error: result.error };
  };
  return {
    agentId,
    agentUid: input.agentUid,
    agentAccount: input.accountName,
    fortressPath: input.wallFortressPath,
    harnessArgv: input.harnessArgv,
    harnessLogDir: resolveHarnessDaemonLogDir(input.newAccountHome),
    agentTemplate: agentId,
    gateDaemonArgvPrefix:
      input.cliBinary !== undefined && input.cliBinary.length > 0
        ? [input.cliBinary]
        : [process.execPath, process.argv[1] ?? "sanctuary"],
    excludeUids: [input.operatorUid],
    gateAccountCeiling: PROVISION_CEILING,
    gateHomeDirectory: `${NEW_ACCOUNT_HOME_BASE}/${deriveGateAccountName(agentId)}`,
    reloadPolicy,
    publishProvisionedRules: async (routing) => {
      const published = await publishProvisionedEgressRules({
        fortressPath: input.wallFortressPath,
        endpointSet: HERMES_ENDPOINT_SET,
        reloadPolicy,
        routing,
      });
      return published.ok
        ? { ok: true as const, ruleIds: published.ruleIds }
        : { ok: false as const, error: published.error };
    },
    audit: async (operation, details) => {
      try {
        const { appendCastleWallCliAuditBestEffort } = await import("../cli/castle-wall.js");
        await appendCastleWallCliAuditBestEffort(
          operation,
          { source: input.auditSource, ...details },
          input.wallFortressPath,
          process.env,
          process.stderr,
        );
      } catch {
        // Best-effort by contract.
      }
    },
    print: input.print,
    accountOps: input.accountOps,
    ...(input.parkPlistFallbackRemoval === true ? { parkPlistFallbackRemoval: true } : {}),
  };
}

/**
 * Run the exclusive-egress repair sequence for the already-provisioned
 * fine-grained Hermes agent (Unified Protect Slice 5 S5-6, design MED-7).
 * Drift-guard first (foreign transient pf rules REFUSE without the
 * interactive override), then recover -> bring-up -> release barrier.
 * Returns a process exit code (0 = repaired; 2 = refused/failed -- the agent
 * stays parked or coarse-only, loudly).
 */
export async function runEgressGateRepairForCli(options: {
  isTty: boolean;
  overrideTransientPfRules: boolean;
  print?: (line: string) => void;
  cliBinary?: string;
  getuid?: () => number;
  resolveOperatorIdentity?: () => Promise<OperatorIdentity | undefined>;
}): Promise<number> {
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand;
  // this is only the default when no `print` override is supplied (the CLI
  // caller always supplies one). Never used to print secrets or key material.
  const print = options.print ?? ((line: string) => console.error(`  ${line}`));
  if (osPlatform() !== "darwin") {
    print("--repair-egress-gate is macOS-only (the pf/launchd exclusive-egress stack).");
    return 2;
  }
  const getuid = options.getuid ?? process.getuid?.bind(process);
  if (getuid?.() !== 0) {
    print("Repairing the exclusive-egress gate requires root. Re-run: sudo sanctuary protect --repair-egress-gate");
    return 2;
  }
  const resolveIdentity = options.resolveOperatorIdentity ?? resolveOperatorIdentity;
  const operatorIdentity = await resolveIdentity();
  if (operatorIdentity === undefined) {
    print("Could not determine the operator account under sudo (SUDO_UID/SUDO_GID unset); refusing to repair.");
    return 2;
  }
  const wallFortressPath = resolveWallFortressPath(process.env, operatorIdentity.home);
  const agentId = "hermes";
  const accountName = deriveAgentAccountName(agentId);
  const newAccountHome = `${NEW_ACCOUNT_HOME_BASE}/${accountName}`;
  const accountOps = realAccountProvisionOps();
  const agentUid = await accountOps.lookupAccountUid(accountName);
  if (agentUid === undefined || agentUid === null) {
    print(
      `No dedicated agent account "${accountName}" exists; nothing to repair. ` +
        "Provision first: sudo sanctuary protect --hermes --exclusive-egress",
    );
    return 2;
  }
  let harnessArgv: string[];
  try {
    const resolved = await resolveHermesGatewayArgv({ pathExists }, { agentHome: newAccountHome });
    harnessArgv = resolved.programArguments;
  } catch (err) {
    print(`Could not resolve the harness argv for the repair (${(err as Error).message}); refusing.`);
    return 2;
  }
  const wiring = buildHermesExclusiveCliWiring({
    agentUid,
    accountName,
    newAccountHome,
    wallFortressPath,
    harnessArgv,
    operatorUid: operatorIdentity.uid,
    auditSource: "sanctuary-protect-repair",
    print,
    accountOps,
    ...(options.cliBinary !== undefined ? { cliBinary: options.cliBinary } : {}),
  });
  const outcome = await runEgressGateRepair(
    { agentUid, isTty: options.isTty, overrideTransientPfRules: options.overrideTransientPfRules },
    createRepairExclusiveEgressOps(wiring),
  );
  switch (outcome.kind) {
    case "repaired":
      print(`Exclusive-egress gate repaired: generation ${outcome.generationId} live; the agent harness was released.`);
      return 0;
    case "repaired-repark-failed":
      print(
        `Exclusive-egress gate repaired (generation ${outcome.generationId}) BUT the boot-state re-park failed ` +
          `(${outcome.reparkError}); the next boot could auto-start the agent before the gate re-arms. Re-run the repair.`,
      );
      return 2;
    case "refused-foreign-transient-rules":
    case "refused-non-tty-override":
    case "refused-diff-unavailable":
      // The repair sequence already printed the specific refusal + guidance.
      return 2;
    case "repair-failed":
      // BLOCKER-3 honesty, tightened by fix-round-2 HIGH-2: claim PARKED only
      // when the FULL persistent parked posture was verified (not running +
      // launchd job disabled + hold file absent + parked plist); otherwise
      // enumerate exactly which checks failed -- the agent may be startable
      // now or at the next boot (stale release material).
      print(
        `Exclusive-egress repair FAILED at ${outcome.stage}: ${outcome.reason}. ` +
          (outcome.parkedStateVerified
            ? "The agent harness remains PARKED (verified: not running, job disabled, hold file absent, " +
              "parked plist on disk; fail-closed). Investigate, then re-run the repair."
            : "WARNING: the agent's parked state could NOT be fully verified -- it may be startable now " +
              `or at the next boot. Failed checks: ${outcome.parkedStateProblems.join("; ") || "no probe detail"}. ` +
              "Investigate immediately."),
      );
      return 2;
  }
}

/**
 * Run the S5-7 per-agent exclusive-egress UNPROTECT for the provisioned
 * fine-grained Hermes agent (Unified Protect Slice 5 S5-7): verified
 * persistent park -> generation recovery -> gate daemon down -> credential +
 * oracle-token teardown -> provisioned-rule scrub -> policy surfaces off ->
 * registry remove (union re-render preserving every remaining confined uid;
 * the anchor is flushed ONLY when the last agent leaves). Returns a process
 * exit code (0 = unprotected; 2 = failed -- remaining protection intact, the
 * agent stays parked, loudly). Idempotent: a re-run after any failure
 * converges.
 *
 * SCOPE (matches the design's S5-7 row): the exclusive-egress teardown only.
 * It does NOT delete the agent/gate service accounts (Erik-present, separate
 * build by standing decision) and does NOT disarm the coarse wall or restore
 * re-homed files (the unprovision flow owns those).
 */
export async function runEgressGateUnprotectForCli(options: {
  print?: (line: string) => void;
  cliBinary?: string;
  getuid?: () => number;
  resolveOperatorIdentity?: () => Promise<OperatorIdentity | undefined>;
}): Promise<number> {
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand;
  // this is only the default when no `print` override is supplied (the CLI
  // caller always supplies one). Never used to print secrets or key material.
  const print = options.print ?? ((line: string) => console.error(`  ${line}`));
  if (osPlatform() !== "darwin") {
    print("--unprotect-egress-gate is macOS-only (the pf/launchd exclusive-egress stack).");
    return 2;
  }
  const getuid = options.getuid ?? process.getuid?.bind(process);
  if (getuid?.() !== 0) {
    print(
      "Removing the exclusive-egress gate requires root. Re-run: sudo sanctuary protect --unprotect-egress-gate",
    );
    return 2;
  }
  const resolveIdentity = options.resolveOperatorIdentity ?? resolveOperatorIdentity;
  const operatorIdentity = await resolveIdentity();
  if (operatorIdentity === undefined) {
    print("Could not determine the operator account under sudo (SUDO_UID/SUDO_GID unset); refusing to unprotect.");
    return 2;
  }
  const wallFortressPath = resolveWallFortressPath(process.env, operatorIdentity.home);
  const accountName = deriveAgentAccountName("hermes");
  const newAccountHome = `${NEW_ACCOUNT_HOME_BASE}/${accountName}`;
  const accountOps = realAccountProvisionOps();
  const agentUid = await accountOps.lookupAccountUid(accountName);
  if (agentUid === undefined || agentUid === null) {
    print(
      `No dedicated agent account "${accountName}" exists; nothing to unprotect. ` +
        "(Account removal is a separate, operator-present step and is never bundled here.)",
    );
    return 2;
  }
  // MED-1 (teardown wedge on a damaged install): argv resolution needs the
  // re-homed Hermes runtime tree (runtime files + system python + venv). If it
  // was damaged or deleted, REFUSING here would wedge the unprotect verb
  // permanently while pf rules + the registry entry + the gate daemon + the
  // credential all persist -- a fail-closed dead-end with no recovery path. The
  // argv is only needed to RE-RENDER the parked plist; an ABSENT plist is
  // equally unbootable (and `verifyHarnessParkedPersistent` accepts it), so we
  // fall back to a plist-REMOVAL park and still complete the teardown. A
  // harmless absolute placeholder keeps the parked-plan renderer from throwing;
  // it is never written to disk (the plist is removed on this path).
  let harnessArgv: string[];
  let parkPlistFallbackRemoval = false;
  try {
    const resolved = await resolveHermesGatewayArgv({ pathExists }, { agentHome: newAccountHome });
    harnessArgv = resolved.programArguments;
  } catch (err) {
    print(
      `Could not resolve the harness argv for the unprotect (${(err as Error).message}); ` +
        "falling back to a plist-removal park -- the harness will be left unbootable (no parked plist) and " +
        "the teardown will still complete. (The re-homed Hermes runtime tree looks damaged or removed.)",
    );
    harnessArgv = ["/usr/bin/false"];
    parkPlistFallbackRemoval = true;
  }
  const wiring = buildHermesExclusiveCliWiring({
    agentUid,
    accountName,
    newAccountHome,
    wallFortressPath,
    harnessArgv,
    operatorUid: operatorIdentity.uid,
    auditSource: "sanctuary-protect-unprotect",
    print,
    accountOps,
    parkPlistFallbackRemoval,
    ...(options.cliBinary !== undefined ? { cliBinary: options.cliBinary } : {}),
  });
  const outcome = await runEgressGateUnprotect(
    { agentUid },
    createUnprotectExclusiveEgressOps(wiring),
  );
  switch (outcome.kind) {
    case "unprotected":
      print(
        outcome.flushed
          ? `Exclusive-egress protection removed for uid ${agentUid}; no confined agents remain (pf anchor flushed).`
          : `Exclusive-egress protection removed for uid ${agentUid}; ${outcome.remainingUids.length} confined ` +
              "agent(s) remain with confinement re-verified live.",
      );
      // LOW-2 (UX honesty): unprotect removes the exclusive-egress GATE and
      // parks the harness DOWN -- it does NOT re-release the agent to run under
      // the coarse wall. The harness stays parked/unbootable until it is
      // explicitly re-provisioned or the operator releases it. (Account removal
      // and coarse-wall disarm are separate, operator-present steps.)
      print(
        "The agent harness is left PARKED (down / unbootable), not running coarse -- re-provision or " +
          "release it explicitly to bring it back up.",
      );
      if (outcome.registryDirty) {
        print(
          "NOTE: the registry still carries a repair-owed marker (posture stays non-green). " +
            "Run: sudo sanctuary protect --repair-egress-gate",
        );
        return 2;
      }
      return 0;
    case "unprotect-failed":
      print(
        `Exclusive-egress unprotect FAILED at ${outcome.stage}: ${outcome.reason}. ` +
          "Remaining protection is INTACT (fail-closed). " +
          (outcome.parkedStateVerified
            ? "The agent harness is PARKED (verified: not running, job disabled, hold file absent, " +
              "parked plist on disk). Investigate, then re-run the unprotect."
            : "WARNING: the agent's parked state could NOT be fully verified -- it may be startable now " +
              `or at the next boot. Failed checks: ${outcome.parkedStateProblems.join("; ") || "no probe detail"}. ` +
              "Investigate immediately."),
      );
      return 2;
    case "unprotect-refused":
      // Fail-closed refusal (S5-7 fix-round-2): the sole-exclusive-agent
      // invariant did not hold, the committed registry could not be read, or
      // another provisioning run held the lock. NOTHING was torn down.
      print(
        `Exclusive-egress unprotect REFUSED (nothing torn down; every surface INTACT): ${outcome.reason}.` +
          (outcome.conflictingUids.length > 0
            ? " Per-agent unprotect of a shared-fortress/harness config is not supported until the " +
              "multi-agent teardown lands."
            : ""),
      );
      return 2;
  }
}
