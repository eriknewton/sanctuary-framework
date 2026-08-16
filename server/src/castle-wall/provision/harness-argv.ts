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
 * Preferred layout: the runnable Hermes tree lives under
 * `~/.hermes/hermes-agent`; after re-home the LaunchDaemon needs an absolute
 * interpreter that can import both `hermes_cli` (from that source tree) and
 * every compiled dependency in the venv, otherwise launchd accepts the job but
 * it crash-loops before a stable pid exists.
 *
 * FIX F-PIPX (Mini2 first real install 2026-07-27). Hermes's documented
 * install path can be `pipx install hermes-agent`, which creates no
 * `~/.hermes/hermes-agent` source tree at all. The fallback now probes the
 * operator's pipx venv (`PIPX_HOME` / `PIPX_BIN_DIR`, default
 * `~/.local/pipx/venvs/hermes-agent`) and accepts it only when the venv
 * interpreter can import `hermes_cli` from its own site-packages. The launched
 * process still gets `HOME=<agentHome>`, so secrets/config remain re-homed to
 * the confined account while code import comes from pipx.
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

import { dirname, normalize as normalizePath } from "node:path";

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
  /** Resolve symlinks for a path, or `undefined` when the path cannot be resolved. */
  realpath(path: string): Promise<string | undefined>;
  /** Read one symlink without following it, or `undefined` when `path` is not a readable symlink. */
  readlink(path: string): Promise<string | undefined>;
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
  /**
   * Execute `path` AS `uid` and prove it can import `hermes_cli` with the
   * supplied import roots inserted into `sys.path`, returning the imported
   * package origin on success. This is a capability probe, not an existence
   * probe: a candidate that cannot import the package it will launch is not a
   * candidate.
   */
  probeHermesCliImportAsUid(path: string, uid: number, pythonPathEntries: readonly string[]): Promise<string | undefined>;
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

type PipxResolutionEnv = Readonly<{
  PIPX_HOME?: string;
  PIPX_BIN_DIR?: string;
  HOME?: string;
}>;

export interface ResolveHermesGatewayArgvOptions {
  /** Dedicated account home after re-home, e.g. /var/sanctuary-agents/sanctuary-hermes. */
  agentHome: string;
  /**
   * The sudo operator's real home directory, used to expand pipx defaults.
   * When omitted, pipx probing falls back to `env.HOME` and then `agentHome`.
   */
  operatorHome?: string;
  /**
   * Environment used only for pipx discovery (`PIPX_HOME`, `PIPX_BIN_DIR`,
   * and `HOME`). Injectable so tests can use temp-dir pipx fixtures without
   * observing the developer machine.
   */
  env?: PipxResolutionEnv;
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

const PYTHON_SITE_PACKAGES_RELATIVES = [
  "lib/python3.14/site-packages",
  "lib/python3.13/site-packages",
  "lib/python3.12/site-packages",
  "lib/python3.11/site-packages",
  "lib/python3.10/site-packages",
];

const VENV_SITE_PACKAGES_CANDIDATES = PYTHON_SITE_PACKAGES_RELATIVES.map((rel) => `venv/${rel}`);

/** The venv's own interpreter, relative to the re-homed Hermes runtime tree. */
const VENV_PYTHON_RELATIVE = "venv/bin/python";
const PIPX_HERMES_PACKAGE = "hermes-agent";
const PIPX_HERMES_COMMAND = "hermes";
const PIPX_VENV_PYTHON_RELATIVE = "bin/python";

/**
 * The one-liner the version probe executes. `-I` (isolated) is deliberate:
 * it drops the inherited `PYTHON*` environment, the user site directory, and
 * the script directory from `sys.path`, so a `sitecustomize.py` or a stray
 * `PYTHONPATH` on the invoking environment cannot influence what this probe
 * reports (the subprocess-parser import-hardening rule).
 */
export const INTERPRETER_VERSION_PROBE_SOURCE = 'import sys; print("%d.%d" % sys.version_info[:2])';

/**
 * Render the importability probe for `hermes_cli`. The probe mutates
 * `sys.path` inside isolated mode instead of trusting inherited PYTHONPATH,
 * so the caller controls exactly which source tree or site-packages directory
 * is being measured.
 */
export function renderHermesCliImportProbeSource(pythonPathEntries: readonly string[]): string {
  return [
    "import importlib.util, sys",
    `for entry in reversed(${JSON.stringify([...pythonPathEntries])}):`,
    "    if entry and entry not in sys.path:",
    "        sys.path.insert(0, entry)",
    "spec = importlib.util.find_spec('hermes_cli')",
    "if spec is None:",
    "    raise SystemExit(42)",
    "origin = spec.origin or ''",
    "if not origin:",
    "    module = __import__('hermes_cli')",
    "    origin = getattr(module, '__file__', '') or ''",
    "if not origin:",
    "    raise SystemExit(43)",
    "print(origin)",
  ].join("\n");
}

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

/** Parse the import probe's single absolute origin path. Any extra output fails closed. */
export function parseHermesCliImportProbeOutput(stdout: string): string | undefined {
  const match = /^\s*(\/[^\n\r]+)\s*$/.exec(stdout);
  return match?.[1];
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

function stripTrailingSlashes(path: string): string {
  return path.replace(/\/+$/, "");
}

function isPathAtOrWithin(path: string, base: string): boolean {
  const normalizedBase = stripTrailingSlashes(base);
  return path === normalizedBase || path.startsWith(`${normalizedBase}/`);
}

/**
 * Hermes installed by uv currently makes `venv/bin/python` an absolute
 * symlink into the operator-owned `~/.hermes/python` tree. Re-home moves that
 * managed-Python tree beside `hermes-agent`, but the symlink text necessarily
 * still names the old operator home. Map only the suffix below the exact
 * `.hermes/python/` marker into the dedicated account home. A normalized
 * escape is rejected, so an agent-controlled symlink can never select an
 * unrelated host interpreter through this compatibility path.
 */
function relocatedHermesManagedPython(linkTarget: string | undefined, agentHome: string): string | undefined {
  if (linkTarget === undefined || !linkTarget.startsWith("/")) return undefined;
  const marker = "/.hermes/python/";
  const markerIndex = linkTarget.lastIndexOf(marker);
  if (markerIndex <= 0) return undefined;
  const suffix = linkTarget.slice(markerIndex + marker.length);
  if (suffix.length === 0) return undefined;
  const managedPythonBase = `${stripTrailingSlashes(agentHome)}/.hermes/python`;
  const candidate = normalizePath(`${managedPythonBase}/${suffix}`);
  return isPathAtOrWithin(candidate, managedPythonBase) ? candidate : undefined;
}

function expandHomePath(path: string, home: string): string | undefined {
  if (path.startsWith("/")) return stripTrailingSlashes(path);
  if (path === "~") return stripTrailingSlashes(home);
  if (path.startsWith("~/")) return `${stripTrailingSlashes(home)}${path.slice(1)}`;
  return undefined;
}

interface PipxCandidate {
  readonly source: string;
  readonly venvDir: string;
  readonly python: string;
}

interface PipxProbePlan {
  readonly candidates: readonly PipxCandidate[];
  readonly probePaths: readonly string[];
  readonly rejections: readonly string[];
}

async function buildPipxProbePlan(
  ops: HarnessArgvOps,
  operatorHome: string,
  env: PipxResolutionEnv,
): Promise<PipxProbePlan> {
  const candidates = new Map<string, PipxCandidate>();
  const probePaths: string[] = [];
  const rejections: string[] = [];
  const addVenv = (source: string, venvDir: string): void => {
    const normalizedVenv = stripTrailingSlashes(venvDir);
    if (!normalizedVenv.startsWith("/")) {
      rejections.push(`${source} resolved to non-absolute pipx venv path ${normalizedVenv}`);
      return;
    }
    if (candidates.has(normalizedVenv)) return;
    const python = `${normalizedVenv}/${PIPX_VENV_PYTHON_RELATIVE}`;
    candidates.set(normalizedVenv, { source, venvDir: normalizedVenv, python });
    probePaths.push(python);
  };

  const home = stripTrailingSlashes(operatorHome);
  const pipxHomeSource = env.PIPX_HOME === undefined ? "default PIPX_HOME" : "PIPX_HOME";
  const pipxHome =
    env.PIPX_HOME === undefined
      ? `${home}/.local/pipx`
      : expandHomePath(env.PIPX_HOME, home);
  if (pipxHome === undefined) {
    rejections.push(`PIPX_HOME=${env.PIPX_HOME} is not an absolute or home-relative path`);
  } else {
    addVenv(`${pipxHomeSource} (${pipxHome})`, `${pipxHome}/venvs/${PIPX_HERMES_PACKAGE}`);
  }

  if (env.PIPX_BIN_DIR !== undefined) {
    const pipxBinDir = expandHomePath(env.PIPX_BIN_DIR, home);
    if (pipxBinDir === undefined) {
      rejections.push(`PIPX_BIN_DIR=${env.PIPX_BIN_DIR} is not an absolute or home-relative path`);
    } else {
      const commandPath = `${pipxBinDir}/${PIPX_HERMES_COMMAND}`;
      probePaths.push(commandPath);
      const resolvedCommand = await ops.realpath(commandPath);
      if (resolvedCommand === undefined) {
        rejections.push(`${commandPath} did not resolve to a pipx command`);
      } else if (resolvedCommand.endsWith(`/${PIPX_VENV_PYTHON_RELATIVE.replace("python", PIPX_HERMES_COMMAND)}`)) {
        addVenv(`PIPX_BIN_DIR command (${commandPath} -> ${resolvedCommand})`, dirname(dirname(resolvedCommand)));
      } else {
        rejections.push(`${commandPath} resolved to ${resolvedCommand}, not a pipx venv command`);
      }
    }
  }

  return { candidates: [...candidates.values()], probePaths, rejections };
}

async function resolvePipxHermesRuntime(
  ops: HarnessArgvOps,
  input: {
    agentHome: string;
    agentUid: number;
    operatorHome: string;
    env: PipxResolutionEnv;
  },
): Promise<
  | { resolved: ResolvedHarnessArgv; probePaths: readonly string[] }
  | { resolved?: undefined; probePaths: readonly string[]; rejections: readonly string[] }
> {
  const plan = await buildPipxProbePlan(ops, input.operatorHome, input.env);
  const pipxRejections = [...plan.rejections];
  const probePaths = [...plan.probePaths];
  for (const candidate of plan.candidates) {
    const version = await ops.probeInterpreterAsUid(candidate.python, input.agentUid);
    if (version === undefined) {
      pipxRejections.push(`${candidate.python} (${candidate.source}) could not be executed as uid ${input.agentUid}`);
      continue;
    }
    const sitePackages = `${candidate.venvDir}/lib/python${renderVersion(version)}/site-packages`;
    probePaths.push(sitePackages);
    const importOrigin = await ops.probeHermesCliImportAsUid(candidate.python, input.agentUid, [sitePackages]);
    if (importOrigin === undefined) {
      pipxRejections.push(`${candidate.python} could not import hermes_cli from ${sitePackages}`);
      continue;
    }
    if (!isPathAtOrWithin(importOrigin, `${sitePackages}/hermes_cli`)) {
      pipxRejections.push(
        `${candidate.python} imported hermes_cli from ${importOrigin}, not from the pipx site-packages at ${sitePackages}`,
      );
      continue;
    }
    return {
      resolved: {
        harnessId: "hermes",
        launch: harnessLaunchSpec({
          programArguments: [candidate.python, "-m", "hermes_cli.main", "gateway", "run", "--accept-hooks"],
          environment: {
            HERMES_ACCEPT_HOOKS: "1",
            HOME: input.agentHome,
            PYTHONPATH: sitePackages,
          },
        }),
      },
      probePaths,
    };
  }
  return { probePaths, rejections: pipxRejections };
}

/**
 * Resolve the Hermes gateway's absolute argv from the re-homed runtime tree,
 * falling back to the operator's pipx hermes-agent venv.
 *
 * Preference order, each step a measurement:
 *   1. the venv's OWN interpreter, when the agent uid can execute it. It is
 *      ABI-consistent with the venv's site-packages by construction, so this
 *      is the only branch that needs no version reasoning.
 *   2. a system interpreter whose self-reported version EQUALS the venv
 *      site-packages version, paired with those site-packages on PYTHONPATH.
 *   3. a pipx venv interpreter whose own site-packages can import
 *      `hermes_cli`.
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
  const rehomedLayout = `${mainModule} plus ${hermesAgentDir}/${VENV_PYTHON_RELATIVE}`;

  // Why each rejected candidate was rejected, so a refusal names the actual
  // host condition instead of a generic "could not resolve".
  const rejections: string[] = [];
  const rehomedRuntimePresent = await ops.pathExists(mainModule);
  const venvPython = `${hermesAgentDir}/${VENV_PYTHON_RELATIVE}`;

  if (rehomedRuntimePresent) {
    // 1. The venv's own interpreter, IF the agent uid can run it and import
    //    `hermes_cli` from the re-homed source tree. Capability, not
    //    existence: the pre-fix code assumed this was unreachable and never
    //    checked, which is the whole of F-INTERP.
    const venvVersion = await ops.probeInterpreterAsUid(venvPython, agentUid);
    if (venvVersion !== undefined) {
      const importOrigin = await ops.probeHermesCliImportAsUid(venvPython, agentUid, [hermesAgentDir]);
      if (importOrigin !== undefined && isPathAtOrWithin(importOrigin, `${hermesAgentDir}/hermes_cli`)) {
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
      rejections.push(
        importOrigin === undefined
          ? `${venvPython} could not import hermes_cli from ${hermesAgentDir}`
          : `${venvPython} imported hermes_cli from ${importOrigin}, not from ${hermesAgentDir}/hermes_cli`,
      );
    } else {
      rejections.push(`${venvPython} could not be executed as uid ${agentUid}`);
    }

    // 2. A system interpreter, but ONLY one whose ABI matches the venv it
    //    would be pointed at and can import `hermes_cli` from this runtime.
    const sitePackages = await firstExisting(
      ops,
      VENV_SITE_PACKAGES_CANDIDATES.map((rel) => `${hermesAgentDir}/${rel}`),
    );
    if (sitePackages === undefined) {
      rejections.push(`no re-homed site-packages directory exists under ${hermesAgentDir}/venv/lib`);
    } else {
      const requiredVersion = parseVenvSitePackagesVersion(sitePackages);
      if (requiredVersion === undefined) {
        // Unreachable through VENV_SITE_PACKAGES_CANDIDATES, kept as a
        // fail-closed guard: an unparseable site-packages path means the ABI
        // is UNKNOWN, and an unknown ABI must never be paired with a system
        // interpreter.
        rejections.push(
          `could not determine the CPython ABI of the re-homed site-packages at ${sitePackages}; ` +
            "refusing to pair it with a system interpreter",
        );
      } else {
        // Mini1 hardware regression (2026-08-15): uv's venv interpreter was
        // an absolute symlink into `~/.hermes/python`. The runtime re-home now
        // moves that managed CPython tree too, but cannot preserve an absolute
        // operator-home symlink as executable by the dedicated uid. Probe the
        // relocated target itself, still pairing it only with the exact ABI's
        // site-packages and proving the real hermes_cli import as the agent.
        const originalVenvTarget = await ops.readlink(venvPython);
        const relocatedManagedPython = relocatedHermesManagedPython(originalVenvTarget, agentHome);
        if (relocatedManagedPython !== undefined) {
          const relocatedVersion = await ops.probeInterpreterAsUid(relocatedManagedPython, agentUid);
          if (relocatedVersion === undefined) {
            rejections.push(`${relocatedManagedPython} could not be executed as uid ${agentUid}`);
          } else if (!sameVersion(relocatedVersion, requiredVersion)) {
            rejections.push(
              `${relocatedManagedPython} is Python ${renderVersion(relocatedVersion)} but the re-homed site-packages at ` +
                `${sitePackages} are Python ${renderVersion(requiredVersion)} (C-extension ABI mismatch)`,
            );
          } else {
            const importOrigin = await ops.probeHermesCliImportAsUid(relocatedManagedPython, agentUid, [
              hermesAgentDir,
              sitePackages,
            ]);
            if (importOrigin !== undefined && isPathAtOrWithin(importOrigin, `${hermesAgentDir}/hermes_cli`)) {
              return {
                harnessId: "hermes",
                launch: harnessLaunchSpec({
                  programArguments: [
                    relocatedManagedPython,
                    "-m",
                    "hermes_cli.main",
                    "gateway",
                    "run",
                    "--accept-hooks",
                  ],
                  environment: {
                    HERMES_ACCEPT_HOOKS: "1",
                    HOME: agentHome,
                    PYTHONPATH: `${hermesAgentDir}:${sitePackages}`,
                  },
                }),
              };
            }
            rejections.push(
              importOrigin === undefined
                ? `${relocatedManagedPython} could not import hermes_cli from ${hermesAgentDir}:${sitePackages}`
                : `${relocatedManagedPython} imported hermes_cli from ${importOrigin}, not from ${hermesAgentDir}/hermes_cli`,
            );
          }
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
          const importOrigin = await ops.probeHermesCliImportAsUid(candidate, agentUid, [
            hermesAgentDir,
            sitePackages,
          ]);
          if (importOrigin === undefined) {
            rejections.push(`${candidate} could not import hermes_cli from ${hermesAgentDir}:${sitePackages}`);
            continue;
          }
          if (!isPathAtOrWithin(importOrigin, `${hermesAgentDir}/hermes_cli`)) {
            rejections.push(
              `${candidate} imported hermes_cli from ${importOrigin}, not from ${hermesAgentDir}/hermes_cli`,
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
      }
    }
  } else {
    rejections.push(`re-homed Hermes runtime entrypoint not found at ${mainModule}`);
  }

  const env = options.env ?? process.env;
  const operatorHome = stripTrailingSlashes(options.operatorHome ?? env.HOME ?? agentHome);
  const pipx = await resolvePipxHermesRuntime(ops, { agentHome, agentUid, operatorHome, env });
  if (pipx.resolved !== undefined) return pipx.resolved;
  rejections.push(...pipx.rejections);

  throw new Error(
    `No Hermes gateway runtime usable by uid ${agentUid} could be resolved. Acceptable layouts: ` +
      `re-homed runtime (${rehomedLayout}); pipx runtime (` +
      `${operatorHome}/.local/pipx/venvs/${PIPX_HERMES_PACKAGE}/${PIPX_VENV_PYTHON_RELATIVE} or ` +
      `PIPX_HOME/venvs/${PIPX_HERMES_PACKAGE}/${PIPX_VENV_PYTHON_RELATIVE}, with hermes_cli importable from ` +
      `that venv's site-packages). Pipx probe paths tried: ${pipx.probePaths.join(", ") || "(none)"}. ` +
      `Rejections: ${rejections.join("; ")}. Refusing to install the harness daemon with a guessed global ` +
      `python/module path. Repair the re-homed Hermes runtime or install Hermes with pipx, then re-run ` +
      `'sudo sanctuary protect --hermes'.`,
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

/**
 * The argv for one as-uid `hermes_cli` importability probe. Pure + exported
 * so tests can pin that this probe stays isolated and uid-scoped like the
 * version probe.
 */
export function hermesCliImportProbeArgv(
  uid: number,
  interpreterPath: string,
  pythonPathEntries: readonly string[],
): { file: string; args: string[] } {
  if (!Number.isSafeInteger(uid) || uid <= 0) {
    throw new Error(`as-uid hermes_cli import probe requires a positive integer uid, got ${String(uid)}`);
  }
  if (!interpreterPath.startsWith("/")) {
    throw new Error(`as-uid hermes_cli import probe requires an absolute interpreter path, got ${interpreterPath}`);
  }
  return {
    file: "/usr/bin/sudo",
    args: ["-n", "-u", `#${uid}`, interpreterPath, "-I", "-c", renderHermesCliImportProbeSource(pythonPathEntries)],
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
    realpath: async (path) => {
      const { realpath } = await import("node:fs/promises");
      try {
        return await realpath(path);
      } catch {
        return undefined;
      }
    },
    readlink: async (path) => {
      const { readlink } = await import("node:fs/promises");
      try {
        return await readlink(path);
      } catch {
        return undefined;
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
    probeHermesCliImportAsUid: async (path, uid, pythonPathEntries) => {
      let argv: { file: string; args: string[] };
      try {
        argv = hermesCliImportProbeArgv(uid, path, pythonPathEntries);
      } catch {
        return undefined;
      }
      const stdout = await runInterpreterProbeBounded(argv, INTERPRETER_PROBE_TIMEOUT_MS);
      if (stdout === undefined) return undefined;
      return parseHermesCliImportProbeOutput(stdout);
    },
  };
}
