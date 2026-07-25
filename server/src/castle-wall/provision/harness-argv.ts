/**
 * Auto-provision Step 2 (Build 1): resolve the confined harness's argv.
 *
 * D1 RESOLVED (scope doc, live Mini2 inspection 2026-07-06): the
 * confinement target is the headless egress-making runtime, NOT any GUI
 * `.app`. For Hermes that is the `ai.hermes.gateway` process -- today a
 * PER-USER LaunchAgent (`~/Library/LaunchAgents/ai.hermes.gateway.plist`,
 * `python -m hermes_cli.main gateway`) -- which this build re-homes to a ROOT
 * LaunchDaemon running as the dedicated agent uid (egress-gate/harness-daemon.ts's
 * model). GUI `.app`s (Claude.app, Telegram.app) stay operator-side, unconfined,
 * correct: a non-login LaunchDaemon cannot host an Aqua GUI app, and they are
 * not the egress path anyway (live lsof showed Claude.app makes no
 * Hermes-related egress). v1 = headless agent runtime only; this module resolves
 * ONLY that argv, never a GUI app path.
 *
 * The runnable Hermes tree lives under `~/.hermes/hermes-agent`; after re-home
 * the LaunchDaemon needs an absolute interpreter that can import both
 * `hermes_cli` (from that source tree) and every compiled dependency in the
 * venv, otherwise launchd accepts the job but it crash-loops before a stable
 * pid exists.
 *
 * FIX F-INTERP (HIGH, Mini1 confined-Hermes drill 2026-07-26). This module
 * used to hard-prefer a SYSTEM python and pair it with the venv's
 * site-packages on `PYTHONPATH`, justified by a guess: "Hermes's venv python
 * may be an absolute symlink back into the operator's home (not traversable by
 * the dedicated uid)". Measured on hardware that guess was false -- the agent
 * uid executed the venv interpreter fine -- while the system python was 3.14
 * against a 3.11 venv, so CPython's version-specific C-extension ABI made
 * every compiled dependency fail to import (`ModuleNotFoundError: No module
 * named '_cffi_backend'`) and NO real Hermes install could be confined at all.
 * Two rules now hold, and both are measurements rather than guesses:
 *
 *   1. RESOLVE BY CAPABILITY, NOT EXISTENCE. The predicate this module depends
 *      on is "the AGENT uid can execute this interpreter", so that is what
 *      `probeInterpreterAsUid` measures -- it runs the candidate as that uid
 *      and reads the version back out of the interpreter itself. `pathExists`
 *      answers a different question and is no longer used to decide.
 *   2. NEVER PAIR MISMATCHED ABIs. A system interpreter is only accepted when
 *      its own reported (major, minor) equals the version encoded in the venv
 *      site-packages directory it would be pointed at. A mismatch throws HERE,
 *      at provision time, with both versions named -- never as a launchd
 *      crash-loop discovered halfway through an arm.
 *
 * SECURITY, stated because preferring the venv interpreter looks like a
 * weakening and is not. The re-homed venv lives under the AGENT's own home and
 * is agent-writable, so the agent can replace `venv/bin/python` and can make
 * the probe report any version it likes. That crosses no boundary: the harness
 * LaunchDaemon runs as the AGENT uid, and `${hermesAgentDir}` (agent-owned,
 * carrying `hermes_cli`) is on `PYTHONPATH` in BOTH branches, so arbitrary
 * agent-owned code already executes as the agent uid either way. The probe
 * likewise runs as the agent uid, never as root. What must never happen is
 * this module resolving an interpreter for a ROOT-run program; it does not,
 * and `renderAgentHarnessDaemonPlist` (egress-gate/harness-daemon.ts) pins the
 * daemon's `UserName` to the agent account.
 *
 * `renderAgentHarnessDaemonPlist` also already fail-closes on a relative
 * program path, so this module's job is purely to FIND the absolute program +
 * args -- validation is the daemon module's job, not duplicated here.
 */

/** A CPython feature version, as reported by the interpreter itself. */
export interface InterpreterVersion {
  major: number;
  minor: number;
}

/** Injected probes so resolution is unit-testable without touching the host. */
export interface HarnessArgvOps {
  /** True when `path` exists and is readable enough to resolve. Never used to decide executability. */
  pathExists(path: string): Promise<boolean>;
  /**
   * Execute `path` AS `uid` and return the CPython feature version it reports,
   * or `undefined` when that uid cannot execute it at all (missing, not
   * executable, an untraversable ancestor on the symlink's resolved chain, a
   * broken interpreter, or a probe timeout).
   *
   * This is the ONLY predicate `resolveHermesGatewayArgv` decides on. It
   * deliberately answers executability and version in one measured fact, so
   * the two can never be inferred from each other.
   */
  probeInterpreterAsUid(path: string, uid: number): Promise<InterpreterVersion | undefined>;
}

/** Resolved harness invocation, ready to pass into `AgentHarnessDaemonPlistOptions.programArguments`. */
export interface ResolvedHarnessArgv {
  harnessId: string;
  programArguments: string[];
  environment?: Record<string, string>;
}

export interface ResolveHermesGatewayArgvOptions {
  /** Dedicated account home after re-home, e.g. /var/sanctuary-agents/sanctuary-hermes. */
  agentHome: string;
  /**
   * The uid the harness LaunchDaemon will run as. Every interpreter candidate
   * is probed AS this uid, because "root can execute it" is not the question
   * the confined daemon's start-up depends on.
   */
  agentUid: number;
}

/**
 * Candidate absolute interpreter paths to probe, in preference order. Kept
 * explicit (not PATH search) because LaunchDaemons do not source shell profiles.
 *
 * Exported as the single source of truth for the "system python interpreters to
 * probe" list: the Hermes config.yaml parse-parity guard
 * (wrap/hermes-yaml-parse-parity.ts) reuses this same ordered list so the two
 * python-resolution paths never drift.
 */
export const SYSTEM_PYTHON3_CANDIDATES = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"];

const VENV_SITE_PACKAGES_CANDIDATES = [
  "venv/lib/python3.14/site-packages",
  "venv/lib/python3.13/site-packages",
  "venv/lib/python3.12/site-packages",
  "venv/lib/python3.11/site-packages",
  "venv/lib/python3.10/site-packages",
];

/** The venv's own interpreter, relative to the re-homed Hermes runtime tree. */
const VENV_PYTHON_RELATIVE = "venv/bin/python";

/**
 * The one-liner the version probe executes. `-I` (isolated) is deliberate:
 * it drops the inherited `PYTHON*` environment, the user site directory, and
 * the script directory from `sys.path`, so a `sitecustomize.py` or a stray
 * `PYTHONPATH` on the invoking environment cannot influence what this probe
 * reports (the subprocess-parser import-hardening rule).
 */
export const INTERPRETER_VERSION_PROBE_SOURCE = 'import sys; print("%d.%d" % sys.version_info[:2])';

/**
 * Parse the `major.minor` line the probe prints. Pure + strict: anything that
 * is not exactly two non-negative integers reads as "no version" (which the
 * caller treats as "this interpreter could not be measured", fail-closed),
 * so noise on stdout can never be mistaken for a version match.
 */
export function parseInterpreterVersion(stdout: string): InterpreterVersion | undefined {
  const match = /^\s*(\d+)\.(\d+)\s*$/.exec(stdout);
  if (match === null) return undefined;
  return { major: Number(match[1]), minor: Number(match[2]) };
}

/**
 * Read the CPython feature version encoded in a venv site-packages path
 * (`.../venv/lib/python3.11/site-packages` -> 3.11). Pure. This is the ABI
 * the compiled extensions in that directory were built for, and therefore the
 * only interpreter version that may be pointed at it.
 */
export function parseVenvSitePackagesVersion(sitePackagesPath: string): InterpreterVersion | undefined {
  const match = /\/python(\d+)\.(\d+)\/site-packages\/?$/.exec(sitePackagesPath);
  if (match === null) return undefined;
  return { major: Number(match[1]), minor: Number(match[2]) };
}

function sameVersion(a: InterpreterVersion, b: InterpreterVersion): boolean {
  return a.major === b.major && a.minor === b.minor;
}

function renderVersion(v: InterpreterVersion): string {
  return `${v.major}.${v.minor}`;
}

/**
 * Resolve the Hermes gateway's absolute argv from the re-homed runtime tree.
 *
 * Preference order, each step a measurement:
 *   1. the venv's OWN interpreter, when the agent uid can execute it. It is
 *      ABI-consistent with the venv's site-packages by construction, so this
 *      is the only branch that needs no version reasoning.
 *   2. a system interpreter whose self-reported version EQUALS the venv
 *      site-packages version, paired with those site-packages on PYTHONPATH.
 *
 * Fail closed (throws) when neither holds: a guessed interpreter may bootstrap
 * cleanly under launchd and then crash-loop, which is exactly the failure this
 * function exists to make impossible.
 */
export async function resolveHermesGatewayArgv(
  ops: HarnessArgvOps,
  options: ResolveHermesGatewayArgvOptions,
): Promise<ResolvedHarnessArgv> {
  const agentUid = options.agentUid;
  if (!Number.isSafeInteger(agentUid) || agentUid <= 0) {
    throw new Error(
      `Resolving the Hermes gateway argv requires the positive integer uid the harness will run as, got ${String(agentUid)}. ` +
        "Refusing to install the harness daemon with an interpreter nothing measured the agent could execute.",
    );
  }
  const agentHome = options.agentHome.replace(/\/+$/, "");
  const hermesAgentDir = `${agentHome}/.hermes/hermes-agent`;
  const mainModule = `${hermesAgentDir}/hermes_cli/main.py`;
  if (!(await ops.pathExists(mainModule))) {
    throw new Error(
      `Could not resolve the re-homed Hermes runtime for the gateway (checked ${mainModule}). ` +
        "Refusing to install the harness daemon with a guessed global python/module path.",
    );
  }

  // Why each rejected candidate was rejected, so a refusal names the actual
  // host condition instead of a generic "could not resolve".
  const rejections: string[] = [];

  // 1. The venv's own interpreter, IF the agent uid can run it. Capability,
  //    not existence: the pre-fix code assumed this was unreachable and never
  //    checked, which is the whole of F-INTERP.
  const venvPython = `${hermesAgentDir}/${VENV_PYTHON_RELATIVE}`;
  const venvVersion = await ops.probeInterpreterAsUid(venvPython, agentUid);
  if (venvVersion !== undefined) {
    return {
      harnessId: "hermes",
      // The venv interpreter puts its OWN site-packages on sys.path, so
      // PYTHONPATH carries only the source tree `hermes_cli` lives in.
      programArguments: [venvPython, "-m", "hermes_cli.main", "gateway", "run", "--accept-hooks"],
      environment: {
        HERMES_ACCEPT_HOOKS: "1",
        HOME: agentHome,
        PYTHONPATH: hermesAgentDir,
      },
    };
  }
  rejections.push(`${venvPython} could not be executed as uid ${agentUid}`);

  // 2. A system interpreter, but ONLY one whose ABI matches the venv it would
  //    be pointed at.
  const sitePackages = await firstExisting(
    ops,
    VENV_SITE_PACKAGES_CANDIDATES.map((rel) => `${hermesAgentDir}/${rel}`),
  );
  if (sitePackages === undefined) {
    throw new Error(
      `Could not resolve an interpreter for the Hermes gateway: the venv interpreter is not executable by the ` +
        `agent uid (${rejections.join("; ")}) and no re-homed site-packages directory exists under ` +
        `${hermesAgentDir}/venv/lib. Refusing to install the harness daemon with a guessed global python/module path. ` +
        `Repair the re-homed Hermes runtime (reinstall Hermes as the operator, then re-run 'sudo sanctuary protect --hermes').`,
    );
  }
  const requiredVersion = parseVenvSitePackagesVersion(sitePackages);
  if (requiredVersion === undefined) {
    // Unreachable through VENV_SITE_PACKAGES_CANDIDATES, kept as a fail-closed
    // guard: an unparseable site-packages path means the ABI is UNKNOWN, and
    // an unknown ABI must never be paired with a system interpreter.
    throw new Error(
      `Could not determine the CPython ABI of the re-homed site-packages at ${sitePackages}; ` +
        "refusing to pair it with a system interpreter (an ABI mismatch crash-loops the harness under launchd).",
    );
  }
  for (const candidate of SYSTEM_PYTHON3_CANDIDATES) {
    const version = await ops.probeInterpreterAsUid(candidate, agentUid);
    if (version === undefined) {
      rejections.push(`${candidate} could not be executed as uid ${agentUid}`);
      continue;
    }
    if (!sameVersion(version, requiredVersion)) {
      rejections.push(
        `${candidate} is Python ${renderVersion(version)} but the re-homed site-packages at ${sitePackages} ` +
          `are Python ${renderVersion(requiredVersion)} (C-extension ABI mismatch)`,
      );
      continue;
    }
    return {
      harnessId: "hermes",
      programArguments: [candidate, "-m", "hermes_cli.main", "gateway", "run", "--accept-hooks"],
      environment: {
        HERMES_ACCEPT_HOOKS: "1",
        HOME: agentHome,
        PYTHONPATH: `${hermesAgentDir}:${sitePackages}`,
      },
    };
  }
  throw new Error(
    `No interpreter usable by the confined Hermes gateway could be resolved as uid ${agentUid}: ` +
      `${rejections.join("; ")}. Refusing to install the harness daemon with an interpreter that would ` +
      `crash-loop under launchd. Fix: install a Python ${renderVersion(requiredVersion)} interpreter the agent uid ` +
      `can execute, or reinstall Hermes as the operator so its venv interpreter is re-homed onto the account, ` +
      `then re-run 'sudo sanctuary protect --hermes'.`,
  );
}

async function firstExisting(ops: HarnessArgvOps, candidates: readonly string[]): Promise<string | undefined> {
  for (const candidate of candidates) {
    if (await ops.pathExists(candidate)) return candidate;
  }
  return undefined;
}

/**
 * The argv for one as-uid interpreter version probe. The whole protect flow
 * (and the root boot supervisor) runs as root, so `sudo -n -u '#<uid>'`
 * genuinely changes the REAL uid -- which is the identity whose traversal and
 * execute permissions decide whether the LaunchDaemon can start. Pure +
 * exported so the argv shape is asserted in unit tests without spawning.
 */
export function interpreterVersionProbeArgv(uid: number, interpreterPath: string): { file: string; args: string[] } {
  if (!Number.isSafeInteger(uid) || uid <= 0) {
    throw new Error(`as-uid interpreter probe requires a positive integer uid, got ${String(uid)}`);
  }
  if (!interpreterPath.startsWith("/")) {
    throw new Error(`as-uid interpreter probe requires an absolute interpreter path, got ${interpreterPath}`);
  }
  return {
    file: "/usr/bin/sudo",
    args: ["-n", "-u", `#${uid}`, interpreterPath, "-I", "-c", INTERPRETER_VERSION_PROBE_SOURCE],
  };
}

/** Bound on one probe. A hung interpreter must never hang a boot-time argv resolution. */
export const INTERPRETER_PROBE_TIMEOUT_MS = 10_000;

/**
 * Production {@link HarnessArgvOps}. The single construction point for every
 * caller (protect, repair, unprotect, and the safe-mode boot supervisor), so
 * the four of them can never drift into probing the host differently.
 */
export function realHarnessArgvOps(): HarnessArgvOps {
  return {
    pathExists: async (path) => {
      const { access } = await import("node:fs/promises");
      try {
        await access(path);
        return true;
      } catch {
        return false;
      }
    },
    probeInterpreterAsUid: async (path, uid) => {
      let argv: { file: string; args: string[] };
      try {
        argv = interpreterVersionProbeArgv(uid, path);
      } catch {
        return undefined;
      }
      try {
        const { execFile } = await import("node:child_process");
        const { promisify } = await import("node:util");
        const run = promisify(execFile);
        const { stdout } = await run(argv.file, argv.args, {
          timeout: INTERPRETER_PROBE_TIMEOUT_MS,
          encoding: "utf8",
        });
        return parseInterpreterVersion(stdout);
      } catch {
        // Any spawn error, nonzero exit, signal death, or timeout reads as
        // "this uid cannot execute this interpreter" (fail-closed).
        return undefined;
      }
    },
  };
}
