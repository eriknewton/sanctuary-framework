/**
 * Auto-provision Step 2 (Build 1): resolve the confined harness's argv.
 *
 * D1 RESOLVED (scope doc, live Mini2 inspection 2026-07-06): the
 * confinement target is the headless egress-making runtime, NOT any GUI
 * `.app`. For Hermes that is the `ai.hermes.gateway` process -- today a
 * PER-USER LaunchAgent (`~/Library/LaunchAgents/ai.hermes.gateway.plist`,
 * `python -m hermes_cli.main gateway`) -- which this build re-homes to a
 * ROOT LaunchDaemon running as the dedicated agent uid
 * (egress-gate/harness-daemon.ts's model). GUI `.app`s (Claude.app,
 * Telegram.app) stay operator-side, unconfined, correct: a non-login
 * LaunchDaemon cannot host an Aqua GUI app, and they are not the egress
 * path anyway (live lsof showed Claude.app makes no Hermes-related
 * egress). v1 = headless agent runtime only; this module resolves ONLY
 * that argv, never a GUI app path.
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
}

/**
 * Candidate absolute interpreter paths to probe, in preference order. Kept
 * as a short, explicit list (not a PATH search) so the resolved program is
 * always an absolute path, matching the daemon plist's fail-closed
 * requirement; a PATH-relative resolution would be meaningless inside a
 * LaunchDaemon anyway (launchd does not source shell profiles).
 */
const PYTHON3_CANDIDATES = ["/usr/local/bin/python3", "/opt/homebrew/bin/python3", "/usr/bin/python3"];

/**
 * Resolve the Hermes gateway's absolute argv. Probes the known python3
 * install locations in order and returns the first that exists; throws if
 * none resolve (fail-closed -- the caller must not proceed to install a
 * daemon with a guessed, possibly-relative program path).
 */
export async function resolveHermesGatewayArgv(ops: HarnessArgvOps): Promise<ResolvedHarnessArgv> {
  for (const candidate of PYTHON3_CANDIDATES) {
    if (await ops.pathExists(candidate)) {
      return {
        harnessId: "hermes",
        programArguments: [candidate, "-m", "hermes_cli.main", "gateway"],
      };
    }
  }
  throw new Error(
    `Could not resolve an absolute python3 interpreter path for the Hermes gateway (checked: ${PYTHON3_CANDIDATES.join(", ")}). ` +
      "Refusing to install the harness daemon with a guessed or relative program path.",
  );
}
