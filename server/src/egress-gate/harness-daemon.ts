/**
 * Agent-harness self-confinement LaunchDaemon plumbing (Unified Protect
 * Slice 4, Wave-A Q2 GO).
 *
 * The exclusive-egress posture requires the agent harness itself to run as
 * the dedicated agent service-account uid, so the kernel stamps every flow
 * the harness (or any child) opens with that ruid and the wall classifies
 * it `.agent` (a pure kernel-stamped ruid compare, unforgeable from user
 * space; verified in `OriginClassifier.classifyUid`). The mechanism is a
 * ROOT LaunchDaemon with `UserName=<agent_account>`: launchd (root) starts
 * the harness, drops it to the agent account, and the harness cannot
 * re-elevate.
 *
 * THIS MODULE IS PLUMBING ONLY: plist generation, install/uninstall step
 * planning + execution against injected ops, and status detection. The
 * actual ARMING on a real host is an Erik-present console ceremony; drill
 * acceptance (running harness ruid == agentUid, self-open socket denied,
 * child denied, no deputy egress; N>=3 plus 5/5 boot-survival) is PENDING.
 *
 * Fail-closed render rules mirror `cli/castle-wall-boot.ts`: absolute
 * program paths only, no control characters, and NEVER a secret in the
 * world-readable plist. `UserName` must be a plausible service account and
 * NEVER root (a root harness would defeat the entire confinement).
 */

import { isAbsolute, join } from "node:path";

/** The LaunchDaemon label for the confined agent harness. */
export const AGENT_HARNESS_DAEMON_LABEL = "ai.sanctuaryprotocol.agent-harness";

/** Canonical install path of the daemon plist. */
export const AGENT_HARNESS_DAEMON_PLIST_PATH = `/Library/LaunchDaemons/${AGENT_HARNESS_DAEMON_LABEL}.plist`;

const HARNESS_DAEMON_STABILITY_SAMPLES = 3;
const HARNESS_DAEMON_STARTUP_ATTEMPTS = 30;
const HARNESS_DAEMON_STABILITY_INTERVAL_MS = 500;

type LaunchctlResult = { code: number; stdout: string; stderr: string };

/**
 * Env names that must NEVER appear in a world-readable plist. Kept in
 * lockstep with `FORBIDDEN_PLIST_ENV` in `cli/castle-wall-boot.ts`
 * (duplicated, not imported: `egress-gate` is a library module and must not
 * depend on the CLI layer). A structural test pins the two lists equal.
 */
export const HARNESS_FORBIDDEN_PLIST_ENV = ["SANCTUARY_PASSPHRASE", "SANCTUARY_RECOVERY_KEY"];

/**
 * POSIX-ish service-account name: lowercase start, then a conservative
 * charset. Deliberately rejects anything that could smuggle plist markup or
 * spaces, and `root`/`_root` style privileged names are checked separately.
 */
const SAFE_ACCOUNT_RE = /^[a-z_][a-z0-9._-]{0,63}$/;

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function assertNoControlChars(value: string, what: string): void {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(value)) {
    throw new Error(`${what} contains control characters; refusing to render plist.`);
  }
}

/** Options for {@link renderAgentHarnessDaemonPlist}. */
export interface AgentHarnessDaemonPlistOptions {
  /**
   * The dedicated agent service account the harness runs as. MUST NOT be
   * root (uid-0 defeats the confinement) and must be a plain service
   * account name.
   */
  agentAccount: string;
  /**
   * Full argv of the harness, e.g. ["/usr/local/bin/node", "/path/harness.js"].
   * The program (first element) must be an absolute path.
   */
  programArguments: string[];
  /** Absolute fortress path, rendered as SANCTUARY_STORAGE_PATH. */
  fortressPath?: string;
  /** Absolute log directory; defaults to <fortressPath>/logs when set. */
  logDir?: string;
  /** Extra environment entries (validated against the forbidden list). */
  environment?: Record<string, string>;
  /** KeepAlive (restart on exit). Default true. */
  keepAlive?: boolean;
  /**
   * S5-5 barrier form: render `<key>Disabled</key><true/>`. Constraint: the
   * authoritative park state is launchd's override database (`launchctl
   * disable`), which takes precedence over this key after the first
   * enable/disable; the plist key documents the parked-by-default posture.
   * Default false (key absent; legacy output byte-identical).
   */
  disabled?: boolean;
  /**
   * RunAtLoad value. Default true (legacy). The S5-5 barrier form renders
   * false so a loaded job never auto-starts; the root supervisor starts it
   * with `kickstart` strictly after the release barrier passes.
   */
  runAtLoad?: boolean;
  /**
   * Render KeepAlive as `{Crashed:true}` (restart ONLY after a crash within a
   * bootstrapped session; no unconditional keep-running). Overrides
   * `keepAlive` when true. Used by the S5-5 barrier form: a bare
   * `KeepAlive=true` starts the job at load regardless of RunAtLoad, which
   * would defeat the park.
   *
   * WHY `Crashed` AND NOT `SuccessfulExit`: launchd.plist(5) documents that
   * the `SuccessfulExit` key IMPLIES `RunAtLoad=true` ("the job needs to run
   * at least once before an exit status can be considered"), which would
   * override the barrier form's explicit `RunAtLoad=false` and start the job
   * at bootstrap/boot-load -- and a refused wrapper (exit 78, an unsuccessful
   * exit) would be restarted indefinitely in a throttled refusal loop. The
   * `Crashed` key carries no RunAtLoad implication and does not restart on a
   * plain non-zero exit, so a wrapper refusal terminates instead of looping.
   * The no-start-at-load behavior of `{Crashed:true}` is an S5-DRILL-owed
   * launchd assertion (stated design intent, not a proven fact).
   */
  keepAliveCrashedOnly?: boolean;
}

/**
 * Render the agent-harness LaunchDaemon plist. Pure: no I/O. Throws on any
 * input that would produce an unconfined or unsafe unit (fail-closed at
 * render time, not at boot time).
 */
export function renderAgentHarnessDaemonPlist(options: AgentHarnessDaemonPlistOptions): string {
  const account = options.agentAccount;
  if (!SAFE_ACCOUNT_RE.test(account)) {
    throw new Error(`Agent account name is not a safe service-account name (got: ${JSON.stringify(account)}).`);
  }
  if (account === "root" || account === "_root" || account === "daemon" || account === "wheel") {
    // A privileged UserName would defeat the confinement this daemon exists
    // to provide: the wall classifies by ruid, and root can rewrite policy.
    throw new Error(`Refusing to render an agent-harness daemon running as "${account}".`);
  }
  if (options.programArguments.length === 0) {
    throw new Error("programArguments must not be empty.");
  }
  const program = options.programArguments[0]!;
  if (!isAbsolute(program)) {
    throw new Error(`Program path must be absolute (got: ${program}).`);
  }
  for (const arg of options.programArguments) {
    assertNoControlChars(arg, "program argument");
  }

  const envEntries: Array<[string, string]> = [];
  if (options.fortressPath !== undefined) {
    if (!isAbsolute(options.fortressPath)) {
      throw new Error(`Fortress path must be absolute (got: ${options.fortressPath}).`);
    }
    assertNoControlChars(options.fortressPath, "fortress path");
    envEntries.push(["SANCTUARY_STORAGE_PATH", options.fortressPath]);
  }
  for (const [name, value] of Object.entries(options.environment ?? {})) {
    assertNoControlChars(name, "environment name");
    assertNoControlChars(value, "environment value");
    envEntries.push([name, value]);
  }
  for (const [name] of envEntries) {
    if (HARNESS_FORBIDDEN_PLIST_ENV.includes(name)) {
      throw new Error(`Refusing to embed ${name} in a world-readable LaunchDaemon plist.`);
    }
  }

  const logDir =
    options.logDir ?? (options.fortressPath !== undefined ? join(options.fortressPath, "logs") : undefined);
  if (logDir !== undefined) {
    if (!isAbsolute(logDir)) {
      throw new Error(`Log dir must be absolute (got: ${logDir}).`);
    }
    assertNoControlChars(logDir, "log dir");
  }

  const argsXml = options.programArguments
    .map((a) => `\t\t<string>${xmlEscape(a)}</string>`)
    .join("\n");
  const envXml =
    envEntries.length > 0
      ? `\t<key>EnvironmentVariables</key>\n\t<dict>\n${envEntries
          .map(([k, v]) => `\t\t<key>${xmlEscape(k)}</key>\n\t\t<string>${xmlEscape(v)}</string>`)
          .join("\n")}\n\t</dict>\n`
      : "";
  const logXml =
    logDir !== undefined
      ? `\t<key>StandardOutPath</key>\n\t<string>${xmlEscape(join(logDir, "agent-harness.out.log"))}</string>\n` +
        `\t<key>StandardErrorPath</key>\n\t<string>${xmlEscape(join(logDir, "agent-harness.err.log"))}</string>\n`
      : "";

  const disabledXml = options.disabled === true ? `\t<key>Disabled</key>\n\t<true/>\n` : "";
  const keepAliveXml =
    options.keepAliveCrashedOnly === true
      ? `\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>Crashed</key>\n\t\t<true/>\n\t</dict>`
      : `\t<key>KeepAlive</key>\n\t<${(options.keepAlive ?? true) ? "true" : "false"}/>`;

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${xmlEscape(AGENT_HARNESS_DAEMON_LABEL)}</string>
${disabledXml}\t<key>UserName</key>
\t<string>${xmlEscape(account)}</string>
\t<key>ProgramArguments</key>
\t<array>
${argsXml}
\t</array>
${envXml}${logXml}\t<key>RunAtLoad</key>
\t<${(options.runAtLoad ?? true) ? "true" : "false"}/>
${keepAliveXml}
</dict>
</plist>
`;
}

/** Filesystem + launchctl operations, injected so tests never touch the host. */
export interface HarnessDaemonOps {
  /** Write `content` at `path` with the given mode (root-owned in prod). */
  writeFile(path: string, content: string, mode: number): Promise<void>;
  /** Remove the file at `path` (ENOENT is not an error). */
  removeFile(path: string): Promise<void>;
  /** Run launchctl with argv (never a shell). */
  runLaunchctl(args: readonly string[]): Promise<LaunchctlResult>;
  /** Sleep between launchd stability samples. Tests inject a no-op. */
  sleepMs?: (ms: number) => Promise<void>;
}

/** A planned install: the plist content plus where it goes. Pure. */
export interface HarnessDaemonInstallPlan {
  plistPath: string;
  plistContent: string;
  bootstrapArgs: string[];
}

/** Build the install plan (pure; rendering validates fail-closed). */
export function planAgentHarnessDaemonInstall(
  options: AgentHarnessDaemonPlistOptions,
): HarnessDaemonInstallPlan {
  return {
    plistPath: AGENT_HARNESS_DAEMON_PLIST_PATH,
    plistContent: renderAgentHarnessDaemonPlist(options),
    bootstrapArgs: ["bootstrap", "system", AGENT_HARNESS_DAEMON_PLIST_PATH],
  };
}

/**
 * Execute an install plan: write the plist (0o644: launchd requires it
 * readable, and it carries no secret by construction), then bootstrap it
 * into the system domain.
 *
 * IDEMPOTENT RE-INSTALL: `launchctl bootstrap` exits non-zero when the
 * service is ALREADY bootstrapped (a routine retry / re-run of the
 * ceremony). A naive write-then-rollback would overwrite the working unit
 * file and then delete it -- the running confined harness keeps running
 * until reboot, but its unit is gone and confinement silently does NOT
 * survive the next boot. So: when launchd already knows the service, this
 * refreshes the plist bytes and succeeds WITHOUT a second bootstrap
 * (applying changed plist content to the LIVE service still requires an
 * explicit uninstall + install ceremony).
 *
 * Rollback on a genuine bootstrap failure removes the plist ONLY when
 * launchd (re-checked after the failure) does not know the service, so the
 * "no half-installed unit left behind" promise can never strand a
 * bootstrapped service without its unit file.
 */
export async function installAgentHarnessDaemon(
  plan: HarnessDaemonInstallPlan,
  ops: HarnessDaemonOps,
): Promise<void> {
  const existing = await agentHarnessDaemonStatus(ops);
  if (!existing.known) {
    throw new Error(
      `launchctl print system/${AGENT_HARNESS_DAEMON_LABEL} did not return a trustworthy status; refusing to install or remove plist`,
    );
  }
  await ops.writeFile(plan.plistPath, plan.plistContent, 0o644);
  if (existing.installed) {
    if (!(await agentHarnessDaemonStableRunning(ops))) {
      throw new Error(
        `launchctl print system/${AGENT_HARNESS_DAEMON_LABEL} did not report a stable running pid`,
      );
    }
    return;
  }
  const result = await ops.runLaunchctl(plan.bootstrapArgs);
  if (result.code !== 0) {
    // Belt-and-suspenders for the pre-check racing or erring fail-closed:
    // if launchd NOW reports the service bootstrapped, the plist we just
    // wrote is the unit a live service depends on -- leave it in place.
    const after = await agentHarnessDaemonStatus(ops);
    if (after.known && !after.installed) {
      await ops.removeFile(plan.plistPath).catch(() => undefined);
    }
    throw new Error(
      `launchctl ${plan.bootstrapArgs.join(" ")} exited ${result.code}: ${result.stderr.trim()}`,
    );
  }
  if (!(await agentHarnessDaemonStableRunning(ops))) {
    const message = `launchctl ${plan.bootstrapArgs.join(" ")} accepted the job, but system/${AGENT_HARNESS_DAEMON_LABEL} did not report a stable running pid`;
    try {
      await uninstallAgentHarnessDaemon(ops);
    } catch (cleanupError) {
      throw new Error(
        `${message}; cleanup failed: ${
          cleanupError instanceof Error ? cleanupError.message : String(cleanupError)
        }; leaving ${plan.plistPath} installed for manual recovery`,
        { cause: cleanupError },
      );
    }
    throw new Error(message);
  }
}

/**
 * Tear down: boot out of the system domain, then remove the plist.
 *
 * `launchctl bootout` exits non-zero with ESRCH (3, "No such process") when
 * the service is simply not loaded; that is fine for an idempotent
 * teardown. Any OTHER bootout failure means the service may STILL BE
 * RUNNING, and removing the plist anyway would leave a live confined
 * harness with no unit file behind it while the ceremony reports success --
 * a silently-failed teardown. Fail loudly instead, before touching the
 * plist (same fail-closed teardown semantics as `disarmPfAnchor`).
 */
export async function uninstallAgentHarnessDaemon(ops: HarnessDaemonOps): Promise<void> {
  const label = `system/${AGENT_HARNESS_DAEMON_LABEL}`;
  const result = await ops.runLaunchctl(["bootout", label]);
  const notLoaded =
    result.code === 3 || /no such (process|service)|service not loaded/i.test(result.stderr);
  if (result.code !== 0 && !notLoaded) {
    throw new Error(
      `launchctl bootout ${label} exited ${result.code}: ${result.stderr.trim()}`,
    );
  }
  await ops.removeFile(AGENT_HARNESS_DAEMON_PLIST_PATH);
}

/**
 * Set the harness job's persistent launchd enable/disable override state
 * (S5-5 release barrier). Constraint: `disable` is the durable park (a
 * disabled job is not bootstrapped at boot and cannot be bootstrapped until
 * enabled); `enable` PERSISTS across boots, so the release sequence must
 * re-disable after a successful bootstrap. Throws on a non-zero exit.
 */
export async function setAgentHarnessJobDisabled(ops: HarnessDaemonOps, disabled: boolean): Promise<void> {
  const verb = disabled ? "disable" : "enable";
  const result = await ops.runLaunchctl([verb, `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  if (result.code !== 0) {
    throw new Error(
      `launchctl ${verb} system/${AGENT_HARNESS_DAEMON_LABEL} exited ${result.code}: ${result.stderr.trim()}`,
    );
  }
}

/**
 * Start the (already-bootstrapped) harness job. The S5-5 barrier plist renders
 * `RunAtLoad=false`, so a bootstrap alone does not start it; the root
 * supervisor kickstarts strictly after the release barrier passes. Throws on
 * a non-zero exit AND when the job does not reach a stable running pid
 * afterwards: a kickstart whose process immediately exits (e.g. the release
 * wrapper refusing with exit 78) is a FAILED start, not a silent green --
 * accepting the launchctl exit code alone would report "started" for a
 * harness that never execs (same stability bar as the install path).
 */
export async function kickstartAgentHarnessDaemon(ops: HarnessDaemonOps): Promise<void> {
  const result = await ops.runLaunchctl(["kickstart", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  if (result.code !== 0) {
    throw new Error(
      `launchctl kickstart system/${AGENT_HARNESS_DAEMON_LABEL} exited ${result.code}: ${result.stderr.trim()}`,
    );
  }
  if (!(await agentHarnessDaemonStableRunning(ops))) {
    throw new Error(
      `launchctl kickstart system/${AGENT_HARNESS_DAEMON_LABEL} was accepted, but the job did not report a stable running pid (the release wrapper may be refusing to exec)`,
    );
  }
}

/** Status of the harness daemon as launchd reports it. */
export interface HarnessDaemonStatus {
  /** False when launchctl itself failed or timed out and status is unknowable. */
  known: boolean;
  /** True when launchd knows the service (bootstrapped). */
  installed: boolean;
  /** True when the service has a running pid. */
  running: boolean;
  pid?: number;
}

/**
 * Query `launchctl print system/<label>` and parse the state. Fail-closed
 * for POSTURE purposes: an absent service is known-not-installed, but a
 * launchctl error/timeout is unknown so callers preserve existing state rather
 * than booting out or deleting a possibly live unit.
 */
export async function agentHarnessDaemonStatus(ops: HarnessDaemonOps): Promise<HarnessDaemonStatus> {
  let result: LaunchctlResult;
  try {
    result = await ops.runLaunchctl(["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  } catch {
    return { known: false, installed: false, running: false };
  }
  if (result.code !== 0) {
    return launchctlPrintWasNotLoaded(result)
      ? { known: true, installed: false, running: false }
      : { known: false, installed: false, running: false };
  }
  const pidMatch = /^\s*pid\s*=\s*(\d+)\s*$/m.exec(result.stdout);
  if (pidMatch) {
    return { known: true, installed: true, running: true, pid: Number(pidMatch[1]) };
  }
  return { known: true, installed: true, running: false };
}

/**
 * Sample `launchctl print` until the job shows the SAME running pid for
 * {@link HARNESS_DAEMON_STABILITY_SAMPLES} consecutive samples (a process
 * that starts and immediately exits -- a refusing release wrapper, a
 * crash-looping harness -- never passes). Exported so the S5-5 release
 * sequence's `harnessStatus` op can reuse the exact stability bar the
 * install path enforces. Fail-closed: unknown status returns false.
 */
export async function agentHarnessDaemonStableRunning(ops: HarnessDaemonOps): Promise<boolean> {
  const sleep = ops.sleepMs ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  let expectedPid: number | undefined;
  let stableSamples = 0;
  for (let i = 0; i < HARNESS_DAEMON_STARTUP_ATTEMPTS; i++) {
    if (i > 0) await sleep(HARNESS_DAEMON_STABILITY_INTERVAL_MS);
    const status = await agentHarnessDaemonStatus(ops);
    if (!status.known) {
      return false;
    }
    if (!status.running || status.pid === undefined) {
      if (expectedPid !== undefined) return false;
      continue;
    }
    if (expectedPid !== undefined && status.pid !== expectedPid) {
      return false;
    }
    expectedPid = status.pid;
    stableSamples += 1;
    if (stableSamples >= HARNESS_DAEMON_STABILITY_SAMPLES) return true;
  }
  return false;
}

function launchctlPrintWasNotLoaded(result: LaunchctlResult): boolean {
  if (result.code === 0) return false;
  const text = `${result.stdout}\n${result.stderr}`.toLowerCase();
  return (
    result.code === 3 ||
    result.code === 113 ||
    text.includes("no such process") ||
    text.includes("no such service") ||
    text.includes("could not find service") ||
    text.includes("service not loaded") ||
    text.includes("not loaded") ||
    text.includes("does not exist")
  );
}
