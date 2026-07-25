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

import { harnessLaunchSpec, type HarnessLaunchSpec } from "../../egress-gate/harness-daemon.js";

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

/**
 * Resolved harness invocation.
 *
 * FIX F-HARNESSENV: the argv and the environment it needs are ONE value
 * ({@link HarnessLaunchSpec}), not two sibling fields one of which is
 * optional. Every plist writer downstream consumes the whole `launch`, so no
 * consumer can carry the argv forward and drop the environment.
 */
export interface ResolvedHarnessArgv {
  harnessId: string;
  launch: HarnessLaunchSpec;
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
      launch: harnessLaunchSpec({
        programArguments: [venvPython, "-m", "hermes_cli.main", "gateway", "run", "--accept-hooks"],
        // The venv interpreter puts its OWN site-packages on sys.path, so
        // PYTHONPATH carries only the source tree `hermes_cli` lives in.
        environment: {
          HERMES_ACCEPT_HOOKS: "1",
          HOME: agentHome,
          PYTHONPATH: hermesAgentDir,
        },
      }),
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
      launch: harnessLaunchSpec({
        programArguments: [candidate, "-m", "hermes_cli.main", "gateway", "run", "--accept-hooks"],
        environment: {
          HERMES_ACCEPT_HOOKS: "1",
          HOME: agentHome,
          PYTHONPATH: `${hermesAgentDir}:${sitePackages}`,
        },
      }),
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

/** Cap on probe stdout kept in memory; a version line is 8 bytes. */
const INTERPRETER_PROBE_STDOUT_CAP = 4096;

/**
 * Run ONE as-uid interpreter probe under a HARD deadline, and return whatever
 * the child printed to stdout by the deadline (`undefined` on spawn failure,
 * non-zero exit, signal death, or timeout).
 *
 * FIX (Codex adversarial review, HIGH, 2026-07-26). This was
 * `promisify(execFile)(file, args, { timeout })`, and that bound is NOT hard:
 * Node's `timeout` sends the default `SIGTERM` and then keeps waiting for the
 * child to exit, so a candidate that IGNORES `SIGTERM` hangs the caller
 * indefinitely. The reviewer reproduced it: with a `trap "" TERM` child and a
 * 200ms timeout, the callback did not fire until an external `SIGKILL` at
 * 1200ms. That matters here because the FIRST candidate is the agent-home venv
 * interpreter, which this module's own header documents as AGENT-WRITABLE --
 * so a hostile or corrupted interpreter could hang `protect` and, worse, the
 * root boot supervisor's argv resolution, instead of failing closed to a
 * parked agent.
 *
 * Four properties, all deliberate:
 *
 *  1. HARD DEADLINE. The returned promise settles at the deadline, whatever
 *     the child does. It is a race between "child closed" and "deadline", NOT
 *     a wait-for-exit after a signal.
 *  2. `SIGKILL`, NOT `SIGTERM`. `SIGKILL` cannot be trapped or ignored.
 *  3. PROCESS GROUP, NOT PROCESS. The direct child is `/usr/bin/sudo` and the
 *     interpreter is ITS child, so killing only the direct child can leave the
 *     interpreter running (and holding the inherited stdout pipe). `detached:
 *     true` puts the child in its own process group and the timeout kills the
 *     GROUP (`kill(-pid)`), which reaches sudo's descendants.
 *  4. HANDLE RELEASE. The deadline also destroys our end of the inherited
 *     stdout pipe and `unref`s the child handle, so nothing the probe leaves
 *     behind can hold the provisioning process's event loop open past the
 *     bound.
 *
 * FIX F-PROBE-PGROUP-ESCAPE (Codex re-review, HIGH, 2026-07-26). Property 3
 * was gated on a `child.on("exit")` flag: if the direct child had exited, the
 * deadline skipped `kill(-pid)` entirely. That flag is the DIRECT CHILD's
 * exit and says NOTHING about the process group. A hostile interpreter forks a
 * descendant into the same group (which inherits the stdout pipe) and exits
 * immediately; `exit` fires, the deadline declines to signal, and the
 * descendant runs on. The reviewer reproduced it standalone: the promise
 * settled at the 300ms deadline but the forked descendant was still alive and
 * still writing afterwards. The gate is now `close`, and the difference is the
 * whole fix:
 *
 *   - `exit`  = the direct child was reaped. Says nothing about the group.
 *   - `close` = every writer of the inherited stdout pipe is gone.
 *
 * `close` is also what makes the group id safe to signal. A pid is not recycled
 * while it is still in use as the id of a NON-EMPTY process group (Linux holds
 * the `struct pid` for `PIDTYPE_PGID`; XNU's pid allocator skips pids that
 * `pgfind()` resolves). So "a descendant still holds the pipe" implies "the
 * group is non-empty" implies "`-pid` still addresses OUR group". Conversely,
 * once `close` has fired we do not signal at all -- not because the group is
 * PROVEN empty (a descendant could close its own stdout and stay alive), but
 * because a probe that closed cleanly is the normal path and an
 * already-detached-from-our-pipe survivor is the same out-of-scope case as the
 * session escapee below, for the same reason. Residual, documented rather than
 * eliminated: a descendant that has already left the group while holding the
 * pipe could leave the group empty, and a pid-space wraparound inside one probe
 * deadline could then point `-pid` at an unrelated group.
 *
 * SCOPE OF THE KILL, STATED HONESTLY. Process-group kill reaches same-group
 * descendants. It cannot reach a descendant that calls `setsid(2)` (or is
 * spawned `detached`) before the deadline, because that descendant is no longer
 * in the group; POSIX offers no portable handle on it, and macOS has no cgroup
 * or pid-namespace equivalent to bound it with. That case is deliberately OUT
 * OF SCOPE for cleanup, and it costs no security property: the probe already
 * runs as the AGENT's own uid, so agent-uid code that wants a surviving process
 * can simply spawn one without going near this probe. The property this
 * function must hold, and does hold in that case, is the CALLER's bound: the
 * promise still settles at the deadline and we still drop every handle, so a
 * session-escaping descendant cannot hang `protect` or the root boot
 * supervisor. It survives; it does not stall us, and it gains nothing.
 *
 * Exported for the regression tests, which drive real processes (`/bin/sh` and
 * `node`, no sudo, nothing outside a private tmpdir): a `SIGTERM`-ignoring
 * child, a same-group descendant whose parent exits immediately, and a
 * session-escaping descendant.
 */
export async function runInterpreterProbeBounded(
  argv: { file: string; args: string[] },
  timeoutMs: number,
): Promise<string | undefined> {
  const { spawn } = await import("node:child_process");
  return new Promise<string | undefined>((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(argv.file, argv.args, {
        // Own process group, so the deadline can kill sudo AND the interpreter
        // it spawned rather than only the direct child.
        detached: true,
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch {
      resolve(undefined);
      return;
    }

    let settled = false;
    let stdout = "";
    // `close`, NOT `exit`. `close` means every writer of the inherited stdout
    // pipe is gone, which is the only evidence available here that the process
    // group is empty. `exit` is the direct child only, and gating the kill on
    // it was F-PROBE-PGROUP-ESCAPE (see the doc comment).
    let closed = false;

    // THE BOUND. Created before the handlers below and deliberately NOT
    // `unref`ed: an unref'd deadline could be skipped if every other handle
    // went away, which is the one thing this function must never do. Its
    // callback runs asynchronously, so referring to `settle`/`abandon`
    // (declared just below) is safe.
    const timer = setTimeout(() => {
      // Settle FIRST, then clean up: the caller is bounded even if the cleanup
      // itself fails (an unkillable/uninterruptible child must not extend the
      // bound).
      settle(undefined);
      abandon();
    }, timeoutMs);

    const settle = (value: string | undefined): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    /**
     * Deadline cleanup: drop OUR handles on the probe, then `SIGKILL` its
     * process group. In that order, because the handle release is the half that
     * protects THIS process and must happen even if the kill throws.
     */
    const abandon = (): void => {
      // (1) Stop a surviving descendant from holding this process open through
      //     the stdout pipe it inherited, and stop the child handle itself from
      //     keeping the event loop ref'd.
      const out = child.stdout;
      if (out !== null && out !== undefined) {
        out.removeAllListeners("data");
        try {
          out.destroy();
        } catch {
          // Already torn down; nothing to release.
        }
      }
      try {
        child.unref();
      } catch {
        // Already reaped; nothing to unref.
      }

      // (2) Kill the GROUP. Skipped only when `close` has fired, i.e. when no
      //     writer of the pipe is left and there is nothing to kill; see the
      //     doc comment for why that, and not `exit`, is the safe gate.
      if (closed) return;
      const pid = child.pid;
      if (pid === undefined) return;
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {
          // Already reaped; nothing to kill.
        }
      }
    };

    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      if (stdout.length < INTERPRETER_PROBE_STDOUT_CAP) {
        stdout += chunk;
      }
    });
    child.stdout?.on("error", () => undefined);
    child.on("error", () => {
      // A spawn failure has no process and no group; settling clears the
      // deadline, so `abandon` never runs and never signals a stale pid.
      settle(undefined);
    });
    child.on("close", (code, signal) => {
      closed = true;
      settle(code === 0 && signal === null ? stdout : undefined);
    });
  });
}

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
      // Any spawn error, nonzero exit, signal death, or timeout reads as
      // "this uid cannot execute this interpreter" (fail-closed) -- and the
      // timeout is a HARD, process-group-wide deadline (see
      // {@link runInterpreterProbeBounded}).
      const stdout = await runInterpreterProbeBounded(argv, INTERPRETER_PROBE_TIMEOUT_MS);
      if (stdout === undefined) return undefined;
      return parseInterpreterVersion(stdout);
    },
  };
}
