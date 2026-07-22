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
 * Bug E drill follow-up: Mini1 proved `hermes_cli` is NOT necessarily globally
 * importable from `/opt/homebrew/bin/python3`, and Hermes's venv python may be
 * an absolute symlink back into the operator's home (not traversable by the
 * dedicated uid). The runnable Hermes tree lives under `~/.hermes/hermes-agent`;
 * after re-home the LaunchDaemon must use a system Python with that source tree
 * and its venv site-packages on `PYTHONPATH`, otherwise launchd accepts the job
 * but it crash-loops before a stable pid exists.
 *
 * `renderAgentHarnessDaemonPlist` (egress-gate/harness-daemon.ts) already
 * fail-closes on a relative program path, so this module's job is purely to
 * FIND the absolute program + args -- validation is the daemon module's
 * job, not duplicated here.
 */

/** Injected filesystem probe so resolution is unit-testable without touching the host. */
export interface HarnessArgvOps {
  /** True when `path` exists and is executable/readable enough to resolve. */
  pathExists(path: string): Promise<boolean>;
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

/**
 * Resolve the Hermes gateway's absolute argv from the re-homed runtime tree.
 * Fail closed if the tree is absent: a guessed system Python may bootstrap
 * cleanly yet crash immediately because `hermes_cli` is not importable.
 */
export async function resolveHermesGatewayArgv(
  ops: HarnessArgvOps,
  options: ResolveHermesGatewayArgvOptions,
): Promise<ResolvedHarnessArgv> {
  const agentHome = options.agentHome.replace(/\/+$/, "");
  const hermesAgentDir = `${agentHome}/.hermes/hermes-agent`;
  const mainModule = `${hermesAgentDir}/hermes_cli/main.py`;
  if (!(await ops.pathExists(mainModule))) {
    throw new Error(
      `Could not resolve the re-homed Hermes runtime for the gateway (checked ${mainModule}). ` +
        "Refusing to install the harness daemon with a guessed global python/module path.",
    );
  }

  const python = await firstExisting(ops, SYSTEM_PYTHON3_CANDIDATES);
  const sitePackages = await firstExisting(
    ops,
    VENV_SITE_PACKAGES_CANDIDATES.map((rel) => `${hermesAgentDir}/${rel}`),
  );
  if (python !== undefined && sitePackages !== undefined) {
    return {
      harnessId: "hermes",
      programArguments: [python, "-m", "hermes_cli.main", "gateway", "run", "--accept-hooks"],
      environment: {
        HERMES_ACCEPT_HOOKS: "1",
        HOME: agentHome,
        PYTHONPATH: `${hermesAgentDir}:${sitePackages}`,
      },
    };
  }
  throw new Error(
    `Could not resolve a system Python plus re-homed Hermes site-packages for the gateway ` +
      `(checked python: ${SYSTEM_PYTHON3_CANDIDATES.join(", ")}; site-packages under ${hermesAgentDir}/venv/lib). ` +
      "Refusing to install the harness daemon with a guessed global python/module path.",
  );
}

async function firstExisting(ops: HarnessArgvOps, candidates: readonly string[]): Promise<string | undefined> {
  for (const candidate of candidates) {
    if (await ops.pathExists(candidate)) return candidate;
  }
  return undefined;
}
