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

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${xmlEscape(AGENT_HARNESS_DAEMON_LABEL)}</string>
\t<key>UserName</key>
\t<string>${xmlEscape(account)}</string>
\t<key>ProgramArguments</key>
\t<array>
${argsXml}
\t</array>
${envXml}${logXml}\t<key>RunAtLoad</key>
\t<true/>
\t<key>KeepAlive</key>
\t<${(options.keepAlive ?? true) ? "true" : "false"}/>
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
  runLaunchctl(args: readonly string[]): Promise<{ code: number; stdout: string; stderr: string }>;
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
  await ops.writeFile(plan.plistPath, plan.plistContent, 0o644);
  if (existing.installed) {
    return;
  }
  const result = await ops.runLaunchctl(plan.bootstrapArgs);
  if (result.code !== 0) {
    // Belt-and-suspenders for the pre-check racing or erring fail-closed:
    // if launchd NOW reports the service bootstrapped, the plist we just
    // wrote is the unit a live service depends on -- leave it in place.
    const after = await agentHarnessDaemonStatus(ops);
    if (!after.installed) {
      await ops.removeFile(plan.plistPath).catch(() => undefined);
    }
    throw new Error(
      `launchctl ${plan.bootstrapArgs.join(" ")} exited ${result.code}: ${result.stderr.trim()}`,
    );
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

/** Status of the harness daemon as launchd reports it. */
export interface HarnessDaemonStatus {
  /** True when launchd knows the service (bootstrapped). */
  installed: boolean;
  /** True when the service has a running pid. */
  running: boolean;
  pid?: number;
}

/**
 * Query `launchctl print system/<label>` and parse the state. Fail-closed
 * for POSTURE purposes: any error or unparseable output reports
 * `{ installed: false, running: false }`; never guess "running".
 */
export async function agentHarnessDaemonStatus(ops: HarnessDaemonOps): Promise<HarnessDaemonStatus> {
  let result: { code: number; stdout: string; stderr: string };
  try {
    result = await ops.runLaunchctl(["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  } catch {
    return { installed: false, running: false };
  }
  if (result.code !== 0) {
    return { installed: false, running: false };
  }
  const pidMatch = /^\s*pid\s*=\s*(\d+)\s*$/m.exec(result.stdout);
  if (pidMatch) {
    return { installed: true, running: true, pid: Number(pidMatch[1]) };
  }
  return { installed: true, running: false };
}
