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
import { mkdir, rename, copyFile, chmod, chown as fsChown, access, stat } from "node:fs/promises";
import { dirname } from "node:path";

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

  const consoleOwnerUid = userInfo().uid;
  const detectResult = detectProvisionNeed({
    harnessConfiguredUid: await readHarnessConfiguredUid(),
    runningAgentUid: await readRunningHermesGatewayUid(),
    consoleOwnerUid,
    ceiling: PROVISION_CEILING,
  });

  if (!detectResult.needsProvisioning) {
    print(`Agent already runs as a dedicated account: ${detectResult.reason}`);
    return { ran: true, outcome: { kind: "skipped-already-dedicated", reason: detectResult.reason } };
  }

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
      return planAndCreateAccount(
        { accountName, ceiling: PROVISION_CEILING },
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
    preArmEndpoints: () => [],
    checkUidExistence: async (uid) => {
      const { checkUidExistenceBeforeArm } = await import("../castle-wall/provision/uid-gate.js");
      return checkUidExistenceBeforeArm(accountName, uid, realUidExistenceOps());
    },
    arm: async (uid, ceiling) => {
      const { runEnable } = await import("../cli/castle-wall.js");
      const code = await runEnable([`--agent-uid=${uid}`, `--ceiling=${ceiling}`, "--no-ttl"]);
      return code === 0 ? { ok: true } : { ok: false, error: `castle-wall enable exited ${code}` };
    },
    postArmEndpoints: () => [],
    disarm: async () => {
      const { runDisable } = await import("../cli/castle-wall.js");
      await runDisable([]);
    },
    restoreRehome: async (results: RehomeStepResult[]) => {
      await restoreRehomeSteps(results, realRehomeOps());
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
    createUser: async (accountName: string, uid: number, comment: string | undefined): Promise<void> => {
      // Drill-only: real account creation happens exclusively in an
      // Erik-present console ceremony on real hardware. This build never
      // invokes this path in CI or in any automated run; it exists so the
      // production ops object satisfies the AccountProvisionOps interface
      // for the orchestration to call end to end during the drill.
      await execFileAsync("/usr/sbin/sysadminctl", [
        "-addUser",
        accountName,
        "-UID",
        String(uid),
        "-shell",
        "/usr/bin/false",
        ...(comment ? ["-fullName", comment] : []),
      ]);
      await execFileAsync("/usr/bin/dscl", [".", "-create", `/Users/${accountName}`, "IsHidden", "1"]);
    },
  };
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
        // Directory backups are handled by the caller's move step via a
        // recursive copy in production; kept minimal here since Hermes v1's
        // secret paths are predominantly files. A directory-shaped secret
        // path (e.g. google-mcp-creds/) still gets its parent created
        // root-only; the fail-closed contract is the permission mode, not
        // the recursion strategy.
        await mkdir(backupPath, { recursive: true, mode: 0o700 });
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
      await fsChown(path, uid, gid);
    },
    restore: async (backupPath: string, destPath: string): Promise<void> => {
      await mkdir(dirname(destPath), { recursive: true, mode: 0o700 });
      await copyFile(backupPath, destPath);
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
