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

// The account-name contract is single-sourced: the safe charset and the
// reserved privileged names this renderer refuses come from the zero-import
// policy module every refusal site consumes, so this plist renderer stays
// dependency-light (the module imports nothing) while a stale local copy of
// the list is impossible by construction. Enforced by
// `server/test/structure/cross-file-contract-pins.test.ts`.
import {
  RESERVED_ACCOUNT_NAMES,
  SAFE_SERVICE_ACCOUNT_RE,
} from "../castle-wall/provision/account-name-policy.js";

/** The LaunchDaemon label for the confined agent harness. */
export const AGENT_HARNESS_DAEMON_LABEL = "ai.sanctuaryprotocol.agent-harness";

/** Canonical install path of the daemon plist. */
export const AGENT_HARNESS_DAEMON_PLIST_PATH = `/Library/LaunchDaemons/${AGENT_HARNESS_DAEMON_LABEL}.plist`;

const HARNESS_DAEMON_STABILITY_SAMPLES = 3;
const HARNESS_DAEMON_STARTUP_ATTEMPTS = 30;
const HARNESS_DAEMON_STABILITY_INTERVAL_MS = 500;

/**
 * THE ONE stopped-settle bound (fix-round 3, 2026-07-19). Every site that has
 * to prove a booted-out job actually STOPPED uses these numbers via {@link
 * awaitHarnessStoppedVia}: the parked install's stand-down, the `unprotect`
 * teardown, the release sequence's reassert-parked, and the changed-plist
 * reload. They were three separately-tuned checks (one of them a single
 * sample) and they disagreed about how long "stopped" takes to become true.
 */
export const HARNESS_STOP_SETTLE_SAMPLES = 20;
export const HARNESS_STOP_SETTLE_INTERVAL_MS = 250;

type LaunchctlResult = { code: number; stdout: string; stderr: string };

/**
 * Env names that must NEVER appear in a world-readable plist. Kept in
 * lockstep with `FORBIDDEN_PLIST_ENV` in `cli/castle-wall-boot.ts`
 * (duplicated, not imported: `egress-gate` is a library module and must not
 * depend on the CLI layer). A structural test pins the two lists equal.
 */
export const HARNESS_FORBIDDEN_PLIST_ENV = [
  "SANCTUARY_PASSPHRASE",
  "SANCTUARY_RECOVERY_KEY",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "https_proxy",
  "http_proxy",
];

const CREDENTIALED_URL_VALUE_RE = /:\/\/[^/@\s]*:[^/@\s]*@/;

// ---------------------------------------------------------------------------
// FIX F-HARNESSENV (HIGH, Mini1 confined-Hermes re-drill 2026-07-26)
// ---------------------------------------------------------------------------
//
// The park install rendered the harness plist WITH the resolved environment
// (`HOME`, `PYTHONPATH`, `HERMES_ACCEPT_HOOKS`); every LATER re-render -- the
// release plist, the park re-render, the degraded coarse restore, the
// parked-form comparison -- rendered it WITHOUT, because the arming-wiring
// context carried `harnessArgv: string[]` and nothing else. The released
// gateway then started with no `PYTHONPATH`, fell through to Hermes' editable
// -install meta-path finder, stat'd the operator's pre-re-home path, and died
// with `PermissionError [Errno 13]`. Four independent writers, one missing
// field each; measured 3/3 on direct arms and 1/1 on `--repair-egress-gate`.
//
// THE FIX IS A CHOKEPOINT, NOT FOUR STRING EDITS. A harness launch is ONE
// value: the argv AND the environment that argv needs, resolved together and
// travelling together. {@link HarnessLaunchSpec} is that value. It is BRANDED
// with a module-private symbol, so the ONLY way to obtain one is
// {@link harnessLaunchSpec}, which validates both halves. Every carrier that
// used to hold a bare `harnessArgv` now holds a spec, so a writer literally
// has no argv to render without the environment beside it, and a FIFTH writer
// added later inherits the property for free rather than having to remember it.
declare const HARNESS_LAUNCH_SPEC_BRAND: unique symbol;

/**
 * A complete, validated harness launch descriptor: the absolute argv plus the
 * environment that argv needs to run. Constructible ONLY via
 * {@link harnessLaunchSpec} (the brand is module-private), so an argv can
 * never reach a plist writer without its environment.
 */
export type HarnessLaunchSpec = {
  readonly programArguments: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
} & { readonly [HARNESS_LAUNCH_SPEC_BRAND]: "harness-launch" };

/**
 * Environment names a harness launch MUST carry.
 *
 * HONEST SCOPE: v1 confines exactly one harness, the Hermes gateway, and its
 * argv is resolved by `castle-wall/provision/harness-argv.ts`, whose BOTH
 * branches set `HOME` and `PYTHONPATH` (a re-homed editable install cannot
 * import `hermes_cli` without them -- that is precisely F-HARNESSENV). These
 * are therefore facts about the only launch the product can build today, not a
 * guess about a future one. A non-Python harness must extend this to a
 * per-harness required set; it must NEVER be relaxed to "optional", because
 * optional is the shape the bug had.
 */
export const REQUIRED_HARNESS_LAUNCH_ENV = ["HOME", "PYTHONPATH"] as const;

/**
 * Build a {@link HarnessLaunchSpec}, fail-closed. Throws when the argv is
 * empty / relative, or when any {@link REQUIRED_HARNESS_LAUNCH_ENV} name is
 * missing or empty -- at RESOLUTION time, with the missing names listed,
 * rather than as a launchd start that dies on an import error nobody sees.
 */
export function harnessLaunchSpec(input: {
  programArguments: readonly string[];
  environment: Readonly<Record<string, string>>;
}): HarnessLaunchSpec {
  const argv = [...input.programArguments];
  if (argv.length === 0) {
    throw new Error("A harness launch needs a non-empty argv; refusing to build an unlaunchable harness spec.");
  }
  if (!isAbsolute(argv[0]!)) {
    throw new Error(
      `A harness launch needs an ABSOLUTE program path (got: ${argv[0]!}); LaunchDaemons do not search PATH.`,
    );
  }
  const environment: Record<string, string> = { ...input.environment };
  const missing = REQUIRED_HARNESS_LAUNCH_ENV.filter((name) => (environment[name] ?? "") === "");
  if (missing.length > 0) {
    throw new Error(
      `A harness launch is missing required environment: ${missing.join(", ")}. ` +
        "Refusing to build a launch spec whose plist would start the harness without the environment " +
        "its interpreter needs (FIX F-HARNESSENV: the released gateway then resolves imports from the " +
        "operator's pre-re-home path and dies on a permission error).",
    );
  }
  return Object.freeze({
    programArguments: Object.freeze(argv),
    environment: Object.freeze(environment),
  }) as HarnessLaunchSpec;
}

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

function assertNoCredentialedPlistValue(name: string, value: string): void {
  if (CREDENTIALED_URL_VALUE_RE.test(value)) {
    throw new Error(
      `Refusing to embed ${name} value containing URL credentials in a world-readable LaunchDaemon plist.`,
    );
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
  environment?: Readonly<Record<string, string>>;
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
  if (!SAFE_SERVICE_ACCOUNT_RE.test(account)) {
    throw new Error(`Agent account name is not a safe service-account name (got: ${JSON.stringify(account)}).`);
  }
  // INVARIANT: a privileged UserName would defeat the confinement this daemon
  // exists to provide. The wall classifies flows by ruid, so a shared
  // privileged uid erases the per-agent attribution; and root -- or an `admin`
  // account, which on macOS conventionally carries sudo -- can rewrite the
  // policy that confines it, making the confinement self-revocable.
  if (RESERVED_ACCOUNT_NAMES.has(account)) {
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
    assertNoCredentialedPlistValue("program argument", arg);
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
  for (const [name, value] of envEntries) {
    assertNoCredentialedPlistValue(name, value);
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
  /**
   * Read a file's contents, or `undefined` when it does not exist.
   *
   * REQUIRED, not optional (fix-round 3, 2026-07-19). {@link
   * installAgentHarnessDaemon} needs the CURRENT on-disk plist to decide
   * whether writing the new bytes changed the unit -- and therefore whether
   * launchd is still running the OLD configuration. An optional op would let a
   * caller opt out of that check and get the fail-open the round-3 gate found.
   */
  readFile(path: string): Promise<string | undefined>;
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
 * FIX F-HARNESSENV: the ONLY way the provisioning/arming paths plan a PLAIN
 * (coarse) harness install. It takes the whole {@link HarnessLaunchSpec} and
 * derives BOTH the argv and the environment from it, so the coarse install and
 * the degraded coarse RESTORE cannot disagree about what the harness needs to
 * run. `planAgentHarnessDaemonInstall` stays as the low-level renderer plan for
 * generic/unit use; a structural test pins the arming + provisioning modules to
 * this function so a future writer cannot reintroduce the bare-argv shape.
 */
export function planCoarseHarnessDaemonInstall(options: {
  agentAccount: string;
  harnessLaunch: HarnessLaunchSpec;
  fortressPath?: string;
  logDir?: string;
}): HarnessDaemonInstallPlan {
  return planAgentHarnessDaemonInstall({
    agentAccount: options.agentAccount,
    programArguments: [...options.harnessLaunch.programArguments],
    environment: options.harnessLaunch.environment,
    ...(options.fortressPath !== undefined ? { fortressPath: options.fortressPath } : {}),
    ...(options.logDir !== undefined ? { logDir: options.logDir } : {}),
  });
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
 * survive the next boot. So: when launchd already knows the service and the
 * plist bytes are UNCHANGED, this succeeds without a second bootstrap.
 *
 * ...AND WHEN THE BYTES CHANGED IT RELOADS (fix-round 3, 2026-07-19). The
 * round-3 gate found the fail-open in the branch above: writing a plist FILE
 * does not reload launchd, so an `existing.installed` re-install used to write
 * new bytes, observe "a stable pid exists", and return -- while the process it
 * observed was still running the OLD unit. On the parked-install revert path
 * that is exactly wrong: the disk holds the operator's restored plist, launchd
 * holds the confined barrier job, and the operator is told the harness "is
 * running again". A pid existing is not evidence that the RESTORED
 * configuration is what is loaded. So when the on-disk bytes differ from the
 * bytes being written, the job is booted out and bootstrapped afresh; only
 * then can the stable-pid check be a statement about the unit we just wrote.
 *
 * Rollback on a genuine bootstrap failure removes the plist ONLY when
 * launchd (re-checked after the failure) does not know the service, so the
 * "no half-installed unit left behind" promise can never strand a
 * bootstrapped service without its unit file.
 *
 * IT RETURNING IS AN OBSERVATION -- OF THE UNIT IT WROTE. Every exit path
 * either throws or has just seen `agentHarnessDaemonStableRunning` come back
 * true for a job whose loaded configuration is the plist this call put on
 * disk. That is the basis on which the parked-install revert may claim
 * `harnessRestarted: true`.
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
  // DRILL D2 FIX-ROUND (2026-07-18): clear any PERSISTENT launchd disable
  // before installing. `launchctl disable` survives reboots and plist
  // rewrites, and the S5-5 parked install (and the persistent-park helpers)
  // deliberately set it. Without this, the operator-facing recovery
  // instruction -- "re-run 'sanctuary protect --hermes'" -- could not work:
  // the coarse install would write the normal plist, bootstrap a still-
  // disabled label, and fail its own stable-pid check. A coarse install
  // exists precisely to RUN the harness, so clearing the park's disable is
  // the correct semantics here, not a relaxation: the fine-grained release
  // barrier keeps its own park through `executeParkedHarnessInstall` and the
  // wrapper/hold-file checks, neither of which routes through this function.
  // Done BEFORE the plist write so a failed enable leaves the plist untouched.
  await setAgentHarnessJobDisabled(ops, false);
  // Read BEFORE the write: after it, the two are equal by construction and
  // the question "did this call change the unit?" is unanswerable.
  const onDiskBefore = await ops.readFile(plan.plistPath);
  await ops.writeFile(plan.plistPath, plan.plistContent, 0o644);
  if (existing.installed) {
    if (onDiskBefore === plan.plistContent) {
      // Unchanged bytes: the loaded job IS this plist, so a stable pid is an
      // observation about the right subject.
      if (!(await agentHarnessDaemonStableRunning(ops))) {
        throw new Error(
          `launchctl print system/${AGENT_HARNESS_DAEMON_LABEL} did not report a stable running pid`,
        );
      }
      return;
    }
    // Changed bytes: launchd is still running the OLD unit. Boot it out so the
    // bootstrap below loads what we just wrote. `uninstallAgentHarnessDaemon`
    // is not reusable here -- it removes the plist, which is the file we need.
    const bootout = await ops.runLaunchctl(["bootout", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
    if (bootout.code !== 0 && !launchctlBootoutWasNotLoaded(bootout) && !launchctlBootoutWasInProgress(bootout)) {
      throw new Error(
        `the harness plist changed but launchctl bootout system/${AGENT_HARNESS_DAEMON_LABEL} exited ` +
          `${bootout.code}: ${bootout.stderr.trim()}; refusing to report an install whose new unit was never loaded`,
      );
    }
    const stopped = await awaitAgentHarnessDaemonStopped(ops);
    if (!stopped.known || stopped.running) {
      throw new Error(
        `the harness plist changed but system/${AGENT_HARNESS_DAEMON_LABEL} is ${
          stopped.known ? "STILL RUNNING" : "in an untrustworthy launchd state"
        } after bootout; refusing to report an install whose new unit was never loaded`,
      );
    }
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
 *
 * THE AUTHORITATIVE POST-CHECK (fix-round 2, 2026-07-18). The shared
 * {@link launchctlBootoutWasNotLoaded} predicate justifies its generous match
 * with "no caller relies on it alone: every one re-reads `launchctl print`
 * afterwards and refuses if the job is still running". This function is the
 * first site that comment names and was the one site where it was NOT true --
 * it went from the predicate straight to `removeFile`. The gate lens was right
 * that this is the fail-open direction (a teardown reporting success over a
 * live harness whose unit file is now gone), and right that the argument
 * should be made true rather than narrowed. The status re-read below is that
 * check: an unknown status or a still-running job refuses BEFORE the plist is
 * touched.
 *
 * IT SETTLES, BECAUSE A SINGLE SAMPLE IS WRONG (fix-round 3, 2026-07-19). The
 * round-2 fix took one sample and its comment claimed it refused "exactly as
 * the parked install's stopped-settle assertion does". It did not: that
 * assertion samples {@link HARNESS_STOP_SETTLE_SAMPLES} times *because this
 * branch learned on Mini1 that a bootout's zero exit does not prove the
 * process is reaped*. A single sample turned a job one sample away from gone
 * into a refusal -- on stock `sanctuary unprotect`, whose plist is KeepAlive,
 * so the refusal leaves the harness to return at next boot. The same settle
 * loop and the same EINPROGRESS tolerance now run here, so the comment and the
 * code say the same thing and the two bootout sites are symmetric.
 */
export async function uninstallAgentHarnessDaemon(ops: HarnessDaemonOps): Promise<void> {
  const label = `system/${AGENT_HARNESS_DAEMON_LABEL}`;
  const result = await ops.runLaunchctl(["bootout", label]);
  if (result.code !== 0 && !launchctlBootoutWasNotLoaded(result) && !launchctlBootoutWasInProgress(result)) {
    throw new Error(
      `launchctl bootout ${label} exited ${result.code}: ${result.stderr.trim()}`,
    );
  }
  const after = await awaitAgentHarnessDaemonStopped(ops);
  if (!after.known) {
    throw new Error(
      `launchctl print ${label} did not return a trustworthy status after bootout; refusing to remove ` +
        `${AGENT_HARNESS_DAEMON_PLIST_PATH} against unknown launchd state`,
    );
  }
  if (after.running) {
    throw new Error(
      `${label} is STILL RUNNING after bootout; refusing to remove ${AGENT_HARNESS_DAEMON_PLIST_PATH} and ` +
        "leave a live harness with no unit file behind it",
    );
  }
  await ops.removeFile(AGENT_HARNESS_DAEMON_PLIST_PATH);
}

/**
 * THE ONE not-loaded predicate for `launchctl bootout` (drill D2 fix-round,
 * 2026-07-18). Three call sites -- this module's teardown, the S5-5 parked
 * install's stand-down, and the persistent-park helpers -- previously each
 * carried a hand-maintained phrase list, and they disagreed: the narrowest
 * dropped a standalone `code === 3` and `"service not loaded"`. On a clean
 * host NOTHING is loaded, so every first-ever install depends on this
 * matching; a miss reintroduces a D1-shaped clean-host blocker. One
 * predicate, no second list to keep in sync.
 *
 * WHY A GENEROUS MATCH IS SAFE HERE. Calling a genuinely-failed bootout
 * "already stopped" would be a fail-open on its own, so no caller may rely on
 * this alone: every one of them re-reads `launchctl print` afterwards and
 * refuses if the job is still running (see
 * `executeParkedHarnessInstall`'s stopped-settle assertion and
 * `verifyHarnessParkedPersistent`). This predicate decides only whether to
 * refuse EARLY with a launchctl error or to proceed to that authoritative
 * check.
 */
export function launchctlBootoutWasNotLoaded(result: LaunchctlResult): boolean {
  if (result.code === 0) return true;
  const text = `${result.stdout}\n${result.stderr}`.toLowerCase();
  return (
    result.code === 3 ||
    result.code === 113 ||
    text.includes("no such process") ||
    text.includes("no such service") ||
    text.includes("could not find") ||
    text.includes("not find service") ||
    text.includes("service not loaded") ||
    text.includes("not loaded") ||
    text.includes("does not exist")
  );
}

/**
 * `launchctl bootout` returning EINPROGRESS: the stop was ACCEPTED and is
 * still running down. Distinct from both success and failure -- the job is
 * on its way out but is not gone yet, so a caller must SETTLE (re-sample
 * `launchctl print` until the job is not running) rather than either throw or
 * assume it stopped. Before this it matched no tolerance and threw, which on
 * the parked-install path meant refusing AFTER the plist had already been
 * overwritten.
 */
export function launchctlBootoutWasInProgress(result: LaunchctlResult): boolean {
  if (result.code === 0) return false;
  const text = `${result.stdout}\n${result.stderr}`.toLowerCase();
  return result.code === 36 || text.includes("operation now in progress") || text.includes("einprogress");
}

/**
 * Set the harness job's persistent launchd enable/disable override state
 * (S5-5 release barrier). Constraint: `disable` is the durable park (a
 * disabled job is not bootstrapped at boot and cannot be bootstrapped until
 * enabled); `enable` PERSISTS across boots, so the release sequence must
 * re-disable after a successful bootstrap.
 *
 * IT RETURNING IS AN OBSERVATION (fix-round 3, 2026-07-19). Through round 2
 * this checked the `launchctl enable`/`disable` EXIT CODE and never re-read
 * the override database, while callers -- `setJobDisabled`, the parked
 * install, the release sequence's re-park -- wrote the word "confirmed" around
 * it. Both round-3 lenses named it. The readback below closes it with the
 * mechanism the codebase already had (`print-disabled system`, the same table
 * `verifyHarnessJobDisabled` reads), so the claim is gated on state rather
 * than disclosed as a bound. Fail-closed: an unreadable override table throws,
 * because "I could not tell" must never pass for "it is set".
 */
export async function setAgentHarnessJobDisabled(ops: HarnessDaemonOps, disabled: boolean): Promise<void> {
  const verb = disabled ? "disable" : "enable";
  const result = await ops.runLaunchctl([verb, `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  if (result.code !== 0) {
    throw new Error(
      `launchctl ${verb} system/${AGENT_HARNESS_DAEMON_LABEL} exited ${result.code}: ${result.stderr.trim()}`,
    );
  }
  const override = await readAgentHarnessJobDisabledOverride(ops);
  if (!override.known) {
    throw new Error(
      `launchctl ${verb} system/${AGENT_HARNESS_DAEMON_LABEL} exited 0, but launchd's persistent override ` +
        `state could not be read back (${override.reason}); refusing to report the job ${verb}d`,
    );
  }
  if (override.disabled !== disabled) {
    throw new Error(
      `launchctl ${verb} system/${AGENT_HARNESS_DAEMON_LABEL} exited 0, but launchd's persistent override ` +
        `database still reports the job ${override.disabled ? "DISABLED" : "ENABLED"}; refusing to report the ` +
        `job ${verb}d`,
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
      `launchctl kickstart system/${AGENT_HARNESS_DAEMON_LABEL} was accepted, but the job did not report a stable running pid; this probe did not determine whether the wrapper refused or the process exited after exec`,
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

export interface HarnessStopSettleResult {
  /** The final launchd status sample. */
  status: HarnessDaemonStatus;
  /** Number of status samples taken. */
  samples: number;
  /** Measured wall-clock time spent in the settle loop. */
  elapsedMs: number;
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

/**
 * Sample a harness status until launchd stops reporting it running, bounded by
 * {@link HARNESS_STOP_SETTLE_SAMPLES}. Returns the LAST sample either way, so
 * the caller's fail-closed assertions (unknown status / still running) are
 * unchanged -- this only decides how long to wait before making them. Sampling
 * can only ever DELAY a refusal: a job that never stops still refuses.
 *
 * Takes the sampler rather than the ops so the release sequence (whose ops
 * expose `harnessStatus()` rather than `runLaunchctl`) shares this exact loop
 * instead of carrying a second copy of it.
 */
export async function awaitHarnessStoppedVia(
  sample: () => Promise<HarnessDaemonStatus>,
  sleepMs?: (ms: number) => Promise<void>,
): Promise<HarnessStopSettleResult> {
  const sleep = sleepMs ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const stillAlive = (s: HarnessDaemonStatus): boolean => s.known && (s.running || s.pid !== undefined);
  const startedAt = Date.now();
  let samples = 1;
  let status = await sample();
  for (let i = 1; i < HARNESS_STOP_SETTLE_SAMPLES && stillAlive(status); i++) {
    await sleep(HARNESS_STOP_SETTLE_INTERVAL_MS);
    samples += 1;
    status = await sample();
  }
  return { status, samples, elapsedMs: Date.now() - startedAt };
}

/** {@link awaitHarnessStoppedVia} bound to `launchctl print` through `ops`. */
export async function awaitAgentHarnessDaemonStopped(ops: HarnessDaemonOps): Promise<HarnessDaemonStatus> {
  return (await awaitHarnessStoppedVia(() => agentHarnessDaemonStatus(ops), ops.sleepMs)).status;
}

/**
 * Read launchd's PERSISTENT override database for the harness label
 * (`launchctl print-disabled system`).
 *
 * Fail-closed and three-valued on purpose (fix-round 3, 2026-07-19): a
 * non-zero exit means the override state is UNKNOWABLE, which is not the same
 * as "not disabled". Absence of the label from a successfully-read table IS
 * evidence of not-disabled -- launchd lists only labels carrying an override.
 */
export async function readAgentHarnessJobDisabledOverride(
  ops: HarnessDaemonOps,
): Promise<{ known: true; disabled: boolean } | { known: false; reason: string }> {
  let result: LaunchctlResult;
  try {
    result = await ops.runLaunchctl(["print-disabled", "system"]);
  } catch (err) {
    return { known: false, reason: `launchctl print-disabled system errored: ${(err as Error).message}` };
  }
  if (result.code !== 0) {
    return {
      known: false,
      reason: `launchctl print-disabled system exited ${result.code}: ${result.stderr.trim()}`,
    };
  }
  // macOS prints either `"<label>" => disabled` (newer) or `"<label>" => true`.
  const label = AGENT_HARNESS_DAEMON_LABEL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (new RegExp(`"${label}"\\s*=>\\s*(disabled|true)\\b`).test(result.stdout)) {
    return { known: true, disabled: true };
  }
  return { known: true, disabled: false };
}

/**
 * Exported (fix-round 3, 2026-07-24) so the peer-resolver reload's own
 * settle loop (`arming-wiring.ts`'s `reloadPeerResolverDaemonForBringUp`) can
 * parse `launchctl print system/<label>` with the SAME predicate this
 * module's own {@link agentHarnessDaemonStatus} uses, rather than carrying a
 * second hand-maintained phrase list for a different label -- the exact
 * one-predicate rationale {@link launchctlBootoutWasNotLoaded} documents
 * above for bootout.
 */
export function launchctlPrintWasNotLoaded(result: LaunchctlResult): boolean {
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
