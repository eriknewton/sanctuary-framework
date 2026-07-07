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
import { mkdir, rename, copyFile, chmod, chown as fsChown, access, stat, cp } from "node:fs/promises";
import { dirname } from "node:path";
import { resolve as dnsResolve } from "node:dns/promises";

import {
  detectProvisionNeed,
  deriveAgentAccountName,
  hermesRehomeAdapter,
  planRehome,
  executeRehomePlan,
  restoreRehomeSteps,
  resolveHermesGatewayArgv,
  runProvisionFlow,
  withProvisionLock,
  type ProvisionFlowOps,
  type ProvisionFlowOutcome,
  type RehomeStepResult,
  type EndpointProbeTarget,
} from "../castle-wall/provision/index.js";
import {
  planAgentHarnessDaemonInstall,
  installAgentHarnessDaemon,
  uninstallAgentHarnessDaemon,
  type HarnessDaemonOps,
} from "../egress-gate/harness-daemon.js";

const execFileAsync = promisify(execFile);

const PROVISION_CEILING = 500;
const NEW_ACCOUNT_HOME_BASE = "/var/sanctuary-agents";
const PROVISION_LOCK_PATH = "/var/run/sanctuary-provision.lock";

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
const HERMES_ENDPOINT_HOSTS: ReadonlyArray<{ name: string; host: string }> = Object.freeze([
  { name: "LLM (Venice)", host: "api.venice.ai" },
  { name: "Telegram Bot API", host: "api.telegram.org" },
  { name: "Google MCP (Workspace APIs)", host: "www.googleapis.com" },
]);

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
 *   - owner uid matches AND the owner-read bit (0400) is set -> `true`.
 *   - owner uid does NOT match, but the file is world-readable (0004) or the
 *     target uid's group matches the file's gid and the group-read bit
 *     (0040) is set -> `true` (matches the real access(2) semantics closely
 *     enough for a fail-closed decision; production custody always chowns to
 *     the target uid, so the owner-match branch is the one that actually
 *     fires post-re-home -- this branch exists so the seam is honest about
 *     what POSIX permission bits actually allow, not merely what today's
 *     custody code happens to write).
 *   - anything else -> `false`.
 */
export function credentialReadableAsUidDecision(
  statResult: { uid: number; gid: number; mode: number } | undefined,
  targetUid: number,
  targetGid?: number,
): boolean {
  if (statResult === undefined) {
    return false;
  }
  const { uid, gid, mode } = statResult;
  const OWNER_READ = 0o400;
  const GROUP_READ = 0o040;
  const OTHER_READ = 0o004;
  if (uid === targetUid) {
    return (mode & OWNER_READ) !== 0;
  }
  if (targetGid !== undefined && gid === targetGid && (mode & GROUP_READ) !== 0) {
    return true;
  }
  return (mode & OTHER_READ) !== 0;
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
function credentialReadableProbe(path: string, targetUid: number, targetGid?: number): () => Promise<boolean> {
  return async () => {
    try {
      const st = await stat(path);
      return credentialReadableAsUidDecision(
        { uid: st.uid, gid: st.gid, mode: st.mode },
        targetUid,
        targetGid,
      );
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

/** Build the real, injected pre-arm/post-arm endpoint probe list for Hermes. */
function hermesEndpointProbes(newAccountHome: string, targetUid: number, targetGid: number): EndpointProbeTarget[] {
  const targets: EndpointProbeTarget[] = HERMES_ENDPOINT_HOSTS.map(({ name, host }) => ({
    name: `${name} (DNS-resolves)`,
    probe: dnsResolvesProbe(host),
  }));
  targets.push({
    name: "moved credentials present + readable by agent uid (.hermes/.env)",
    probe: credentialReadableProbe(`${newAccountHome}/.hermes/.env`, targetUid, targetGid),
  });
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
): EndpointProbeTarget[] {
  if (targetUidGid === undefined) {
    return [];
  }
  return hermesEndpointProbes(newAccountHome, targetUidGid.uid, targetUidGid.gid);
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
    const nameMatch = /^(\S+)\s+UniqueID\s*=\s*\d+/m.exec(searchOut);
    if (!nameMatch) return undefined;
    const { stdout } = await execFileAsync("/usr/bin/dscl", [
      ".",
      "-read",
      `/Users/${nameMatch[1]}`,
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
  /** Print function for operator-facing output (defaults to console.error, matching the rest of wrap/cli.ts's stderr convention). */
  print?: (line: string) => void;
  /** Override for `process.getuid` (tests only; production leaves this undefined). */
  getuid?: () => number;
  /** Override for the resolved operator identity (tests only; production leaves this undefined and resolves via SUDO_UID/GID/USER). */
  resolveOperatorIdentity?: () => Promise<OperatorIdentity | undefined>;
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
      },
    };
  }
  const operatorHome = operatorIdentity.home;
  const consoleOwnerUid = operatorIdentity.uid;
  const consoleOwnerGid = operatorIdentity.gid;
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
      const plan = planRehome(hermesRehomeAdapter, { operatorHome, newAccountHome });
      const results = await executeRehomePlan(plan, realRehomeOps(), { uid, gid });
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
      const resolved = await resolveHermesGatewayArgv({ pathExists: pathExists });
      const plan = planAgentHarnessDaemonInstall({
        agentAccount: accountName,
        programArguments: resolved.programArguments,
        fortressPath: process.env.SANCTUARY_STORAGE_PATH,
      });
      await installAgentHarnessDaemon(plan, realHarnessDaemonOps());
    },
    // FIX R1 (BLOCKER, fix-round 2): honest, fail-closed probe list -- see
    // `hermesEndpointProbes` above. `resolvedAgentUidGid` is always set by
    // `installHarnessDaemon` before this is called (steps 6 -> 7); if it is
    // somehow still undefined, fail closed to an unreachable synthetic probe
    // rather than defaulting to the CONSOLE owner's uid, which would silently
    // check readability against the wrong identity.
    preArmEndpoints: () => resolveEndpointProbes(newAccountHome, resolvedAgentUidGid),
    checkUidExistence: async (uid) => {
      const { checkUidExistenceBeforeArm } = await import("../castle-wall/provision/uid-gate.js");
      return checkUidExistenceBeforeArm(accountName, uid, realUidExistenceOps());
    },
    arm: async (uid, ceiling) => {
      const { runEnable } = await import("../cli/castle-wall.js");
      const code = await runEnable([`--agent-uid=${uid}`, `--ceiling=${ceiling}`, "--no-ttl"]);
      return code === 0 ? { ok: true } : { ok: false, error: `castle-wall enable exited ${code}` };
    },
    postArmEndpoints: () => resolveEndpointProbes(newAccountHome, resolvedAgentUidGid),
    disarm: async () => {
      const { runDisable } = await import("../cli/castle-wall.js");
      await runDisable([]);
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
      },
      ops,
    ),
  );

  return { ran: true, outcome };
}

// ── Real op implementations (drill-only side effects; never exercised by CI) ──

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
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
    // Output shape: "<accountName>  UniqueID = <uid>\n" per matching record.
    const nameMatch = /^(\S+)\s+UniqueID\s*=\s*\d+/m.exec(searchOut);
    if (!nameMatch || nameMatch[1] !== expectedAccountName) {
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

/** Recursively chmod a file or directory tree (files 0600, dirs 0700), matching custody mode for both shapes. */
async function chmodRecursive(path: string): Promise<void> {
  const st = await stat(path);
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

/** Recursively chown a file or directory tree to uid/gid. */
async function chownRecursive(path: string, uid: number, gid: number): Promise<void> {
  await fsChown(path, uid, gid);
  const st = await stat(path);
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
 * a real, disposable tmpdir -- not a mock standing in for it. `backup`/
 * `move`'s hardcoded root-owned backup path (`/var/root/...`) is untouched
 * by the restore-conflict test (it never reaches that fallback branch when
 * `destPath` exists), so this is safely testable without root.
 */
export function realRehomeOps() {
  return {
    pathExists,
    backup: async (path: string): Promise<{ backupPath: string }> => {
      // Fix M4: the pre-re-home secrets backup MUST be root-only (0600 for
      // files, 0700 for directories) -- NEVER an operator-readable plaintext
      // copy whose mode is left to whatever the process umask happens to
      // produce (AGENTS.md invariant #6). `copyFile` does not accept a mode
      // argument, so the mode is set explicitly with `chmod` immediately
      // after the copy, closing the umask-dependent window.
      const backupRoot = "/var/root/.sanctuary-rehome-backups";
      const backupPath = `${backupRoot}${path}.bak`;
      await mkdir(dirname(backupPath), { recursive: true, mode: 0o700 });
      const st = await stat(path);
      if (st.isDirectory()) {
        // FIX F2 (2026-07-07 fix-round): the M4 custody copy for a
        // directory-shaped secret (e.g. `.hermes/google-mcp-creds/`,
        // `.workspace-mcp/cli-tokens/`) must be a REAL recursive copy, not
        // an empty placeholder directory -- an empty backup is not a backup.
        await cp(path, backupPath, { recursive: true, mode: 0o700 });
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
     */
    restore: async (destPath: string, sourcePath: string): Promise<{ restored: boolean; conflictPath?: string }> => {
      const destExists = await pathExists(destPath);
      await mkdir(dirname(sourcePath), { recursive: true, mode: 0o700 });
      if (destExists) {
        const sourceConflict = await pathExists(sourcePath);
        if (sourceConflict) {
          // FIX R6: never overwrite operator data that was recreated at the
          // original path while it was re-homed. Restore the moved data to a
          // conflict path alongside it instead, and report the conflict
          // (never a bare "restored: true") so the caller surfaces loud
          // manual-recovery guidance.
          const conflictPath = `${sourcePath}.restored-conflict`;
          await rename(destPath, conflictPath);
          return { restored: false, conflictPath };
        }
        await rename(destPath, sourcePath);
        return { restored: await pathExists(sourcePath) };
      }
      // destPath is already gone (unusual: implies a partial rollback
      // already ran). Fall back to the M4 backup copy, if this path had one.
      const backupRoot = "/var/root/.sanctuary-rehome-backups";
      const backupPath = `${backupRoot}${sourcePath}.bak`;
      if (await pathExists(backupPath)) {
        const sourceConflict = await pathExists(sourcePath);
        if (sourceConflict) {
          // Same conflict guard for the backup-copy fallback: never
          // overwrite a recreated source with the backup copy either.
          const conflictPath = `${sourcePath}.restored-conflict`;
          const st = await stat(backupPath);
          if (st.isDirectory()) {
            await cp(backupPath, conflictPath, { recursive: true });
          } else {
            await copyFile(backupPath, conflictPath);
          }
          return { restored: false, conflictPath };
        }
        const st = await stat(backupPath);
        if (st.isDirectory()) {
          await cp(backupPath, sourcePath, { recursive: true });
        } else {
          await copyFile(backupPath, sourcePath);
        }
        return { restored: await pathExists(sourcePath) };
      }
      return { restored: false };
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
      try {
        const { stdout, stderr } = await execFileAsync("/bin/launchctl", [...args]);
        return { code: 0, stdout, stderr };
      } catch (err) {
        const e = err as { code?: number; stdout?: string; stderr?: string };
        return { code: e.code ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? String(err) };
      }
    },
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
