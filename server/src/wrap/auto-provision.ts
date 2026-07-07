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

import { platform as osPlatform, userInfo, homedir } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, rename, copyFile, chmod, chown as fsChown, access, stat, cp } from "node:fs/promises";
import { dirname } from "node:path";
import { connect as netConnect } from "node:net";

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

// FIX F1 (BLOCKER, 2026-07-07 fix-round): the real endpoint hosts Hermes
// needs to reach, so `preArmEndpoints`/`postArmEndpoints` below supply a
// non-empty, meaningful probe list instead of `[]`. `verify.ts`'s fail-closed
// empty-list guard means an empty list here would abort/disarm every real
// run, so this list must stay accurate as Hermes' real dependencies. TCP
// connect on 443 only -- this proves network reachability as the new uid,
// not HTTP-level auth; that matches what `verifyReachabilityBeforeArm` /
// `verifyReachabilityAfterArm` actually claim to prove (re-home + allow-list
// reachability, never application-level success).
const HERMES_ENDPOINT_HOSTS: ReadonlyArray<{ name: string; host: string; port: number }> = Object.freeze([
  { name: "LLM (Venice)", host: "api.venice.ai", port: 443 },
  { name: "Telegram Bot API", host: "api.telegram.org", port: 443 },
  { name: "Google MCP (Workspace APIs)", host: "www.googleapis.com", port: 443 },
]);

const PROBE_CONNECT_TIMEOUT_MS = 5000;

/** TCP-connect reachability probe for one host:port. Fail-closed: any error or timeout resolves false, never throws. */
function tcpConnectProbe(host: string, port: number): () => Promise<boolean> {
  return () =>
    new Promise<boolean>((resolve) => {
      let settled = false;
      const finish = (ok: boolean) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(ok);
      };
      const socket = netConnect({ host, port, timeout: PROBE_CONNECT_TIMEOUT_MS });
      socket.once("connect", () => finish(true));
      socket.once("timeout", () => finish(false));
      socket.once("error", () => finish(false));
    });
}

/**
 * "Moved credential files are readable as the new uid" probe (fix F1). Runs
 * `stat` as an unprivileged check from the CURRENT process (which, by the
 * time this is called post-re-home, is the harness daemon's already-dropped
 * uid in the real drill path); a file that exists but is not readable at the
 * calling uid throws EACCES, which this treats as unreachable (fail-closed).
 * A wholly absent path (nothing to check because the harness never used that
 * credential) is NOT treated as a failure -- only an existing-but-unreadable
 * path fails the probe.
 */
function credentialReadableProbe(path: string): () => Promise<boolean> {
  return async () => {
    try {
      await access(path);
      return true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      // Absence is not a reachability failure: not every optional credential
      // path is populated on every install (matches rehome.ts's own
      // skipped-absent handling). Only a genuine permission/access failure
      // on a path that DOES exist counts as unreachable.
      return code === "ENOENT";
    }
  };
}

/** Build the real, injected pre-arm/post-arm endpoint probe list for Hermes. */
function hermesEndpointProbes(newAccountHome: string): EndpointProbeTarget[] {
  const targets: EndpointProbeTarget[] = HERMES_ENDPOINT_HOSTS.map(({ name, host, port }) => ({
    name,
    probe: tcpConnectProbe(host, port),
  }));
  targets.push({
    name: "moved credentials readable (.hermes/.env)",
    probe: credentialReadableProbe(`${newAccountHome}/.hermes/.env`),
  });
  return targets;
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
  const operatorHome = homedir();
  const newAccountHome = `${NEW_ACCOUNT_HOME_BASE}/${accountName}`;

  const consoleOwnerInfo = userInfo();
  const consoleOwnerUid = consoleOwnerInfo.uid;
  const consoleOwnerGid = consoleOwnerInfo.gid;
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

  // Privileged-path root check (matches the established pattern in
  // cli/castle-wall.ts's `setup-shared-dir` / `install-boot`: privileged
  // subcommands check `getuid?.() !== 0` up front and instruct the operator
  // to re-run with sudo, rather than let a root-only fs/exec op fail with a
  // raw, confusing EACCES deep in the flow). `sanctuary protect` itself runs
  // fine as the operator; only the PRIVILEGED sub-steps (create account,
  // re-home, install daemon, arm) need root. Checking here -- before the
  // plan-and-print / confirm ceremony -- gives the operator the correct
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
      const resolved = await resolveHermesGatewayArgv({ pathExists: pathExists });
      const plan = planAgentHarnessDaemonInstall({
        agentAccount: accountName,
        programArguments: resolved.programArguments,
        fortressPath: process.env.SANCTUARY_STORAGE_PATH,
      });
      await installAgentHarnessDaemon(plan, realHarnessDaemonOps());
      // uid is accepted for interface symmetry with the orchestrator's
      // per-uid signature; the daemon plist itself pins the account NAME
      // (UserName), and the account name <-> uid binding was just verified
      // by the create step above and is re-verified by the uid-existence
      // gate before arming.
      void uid;
    },
    // FIX F1 (BLOCKER): non-empty, meaningful real probe list -- see
    // `hermesEndpointProbes` above. An empty list here would now abort/
    // fast-disarm every real run (verify.ts's fail-closed empty-list guard),
    // so this MUST stay wired to the real endpoints.
    preArmEndpoints: () => hermesEndpointProbes(newAccountHome),
    checkUidExistence: async (uid) => {
      const { checkUidExistenceBeforeArm } = await import("../castle-wall/provision/uid-gate.js");
      return checkUidExistenceBeforeArm(accountName, uid, realUidExistenceOps());
    },
    arm: async (uid, ceiling) => {
      const { runEnable } = await import("../cli/castle-wall.js");
      const code = await runEnable([`--agent-uid=${uid}`, `--ceiling=${ceiling}`, "--no-ttl"]);
      return code === 0 ? { ok: true } : { ok: false, error: `castle-wall enable exited ${code}` };
    },
    postArmEndpoints: () => hermesEndpointProbes(newAccountHome),
    disarm: async () => {
      const { runDisable } = await import("../cli/castle-wall.js");
      await runDisable([]);
    },
    restoreRehome: async (results: RehomeStepResult[]) => {
      // FIX F2/F3 (2026-07-07 fix-round): thread the OPERATOR's uid/gid
      // (the console-session owner this whole flow is provisioning away
      // from) so restored secrets are handed back with correct custody, and
      // report what ACTUALLY restored rather than assuming success.
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

function realRehomeOps() {
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
     */
    restore: async (destPath: string, sourcePath: string): Promise<{ restored: boolean }> => {
      const destExists = await pathExists(destPath);
      await mkdir(dirname(sourcePath), { recursive: true, mode: 0o700 });
      if (destExists) {
        await rename(destPath, sourcePath);
        return { restored: await pathExists(sourcePath) };
      }
      // destPath is already gone (unusual: implies a partial rollback
      // already ran). Fall back to the M4 backup copy, if this path had one.
      const backupRoot = "/var/root/.sanctuary-rehome-backups";
      const backupPath = `${backupRoot}${sourcePath}.bak`;
      if (await pathExists(backupPath)) {
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
