/**
 * Linux Castle Wall binary-upgrade ROUTES, plus the installed-manifest
 * admission report the doctor path prints.
 *
 * # Why the order is fixed
 *
 * Replacing the Linux daemon binary changes which installed manifests THIS host
 * will admit: the new binary refuses an agent or gate uid it cannot attest. An
 * operator who replaces the binary first and learns that afterwards is left with
 * a daemon that will not load the manifest already on disk. So the product's
 * install and upgrade path is one of two complete ROUTES, each a fixed order of
 * steps that aborts on the first failure, and each one asks the NEW binary about
 * the installed manifest BEFORE the unit is stopped or the file is replaced.
 *
 * - ROUTE A, `disarm`: (1) run `--preflight-manifest` with the NEW binary,
 *   (2) `systemctl stop` the unit, (3) run `--disarm` with the OLD binary,
 *   (4) replace the binary, (5) `systemctl start`.
 * - ROUTE B, `reboot`: (1) run `--preflight-manifest` with the NEW binary,
 *   (2) `systemctl stop` the unit, (3) replace the binary, (4) reboot.
 *
 * The reboot IS route B's start boundary, so route B has NO start step at all.
 * A plain stop preserves the owned table and the ownership journal for adoption,
 * so starting the new binary in the SAME boot over the prior record is the
 * unknown-history shape, whose net covers every uid on the host instead of the
 * confined identity. Route B never issues a start, and
 * `assertRouteHasNoSameBootStart` re-checks that at execution time so a future
 * edit to the route table cannot quietly add one.
 *
 * A bare copy over the installed path followed by a restart skips steps 1 and 3
 * of either route and lands in that same host-wide shape. The CHANGELOG states
 * that as the upgrade bound.
 *
 * # The one asymmetry with the publisher
 *
 * The TypeScript publisher (`../allowlist/agent-origin.ts`) refuses the
 * unattestable uid values it can know without a host, so a descriptor signed
 * from now on is not one the daemon refuses. The daemon additionally reads THIS
 * host's configured `kernel.overflowuid`, which no publisher can know, and that
 * host-specific check is the ONE asymmetry between the two sides. It is why the
 * daemon's verb, and never this module, is the oracle: nothing here
 * re-implements an admission bound. This module runs the verb and reports its
 * exit code and its text verbatim.
 */

import { CASTLE_WALL_DAEMON_BINARY_DEFAULT, CASTLE_WALL_SYSTEMD_UNIT } from "./linux-daemon.js";
import { CASTLE_WALL_LINUX_STATE_ROOT } from "./producer-signature.js";

/**
 * The daemon's pre-replacement check.
 *
 * Must match `run_preflight_manifest` in `castle-wall-daemon/src/main.rs`: the
 * verb takes `--fortress-id`, or both `--policy-dir` and `--pinned-public-key`,
 * takes no host lock, touches no kernel state (so it is safe while the daemon is
 * up), and exits zero ONLY when this host admits the installed manifest.
 */
export const PREFLIGHT_MANIFEST_FLAG = "--preflight-manifest";

/**
 * The daemon's one table-deleting verb.
 *
 * Must match `run_disarm` in `castle-wall-daemon/src/main.rs`. Route A runs it
 * with the OLD binary, after the stop, because the old binary is the one whose
 * ownership record and table shape are on the host at that moment.
 */
export const DISARM_FLAG = "--disarm";

/** `systemctl` subcommand for the stop step. */
const SYSTEMCTL_STOP = "stop";
/** `systemctl` subcommand for route A's start step. Route B never uses it. */
const SYSTEMCTL_START = "start";
/** `systemctl` subcommand for route B's start boundary. */
const SYSTEMCTL_REBOOT = "reboot";

/**
 * Wall-clock budget for one upgrade command.
 *
 * Derivation: the same 5 s budget `realSystemctlRunner` in `linux-daemon.ts`
 * gives one `systemctl` call. The preflight verb is bounded by reading two files
 * and one signature verification with no lock and no kernel call, so it is the
 * cheaper of the two commands this budget covers.
 */
const UPGRADE_COMMAND_TIMEOUT_MS = 5_000;

/**
 * Accepted fortress-id shape for argv.
 *
 * Must match the `fortress_id` validation in `./installer.ts`. An id validated
 * here can never be read by the daemon as another flag, which is why the check
 * is at the argv builder and not at the caller.
 */
const FORTRESS_ID_PATTERN = /^[a-f0-9]{8,64}$/;

/** The two routes. Both are permanent product shapes. */
export type LinuxUpgradeRoute = "disarm" | "reboot";

/** One step of a route, named so a route reads as its own diagram. */
export type LinuxUpgradeStepKind =
  | "preflight_manifest_new_binary"
  | "stop_unit"
  | "disarm_old_binary"
  | "replace_binary"
  | "start_unit"
  | "reboot_host";

/**
 * ROUTE A in order. The disarm sits AFTER the stop and BEFORE the replacement:
 * it runs with the old binary, and the unit must not be running when it takes
 * the host lock the disarm verb needs.
 */
export const LINUX_UPGRADE_ROUTE_A_STEPS: readonly LinuxUpgradeStepKind[] = [
  "preflight_manifest_new_binary",
  "stop_unit",
  "disarm_old_binary",
  "replace_binary",
  "start_unit",
] as const;

/**
 * ROUTE B in order. There is deliberately NO `start_unit` entry: the reboot is
 * the start boundary, and a same-boot start over the preserved record would give
 * the host-wide net instead of the confined one.
 */
export const LINUX_UPGRADE_ROUTE_B_STEPS: readonly LinuxUpgradeStepKind[] = [
  "preflight_manifest_new_binary",
  "stop_unit",
  "replace_binary",
  "reboot_host",
] as const;

/** Which manifest the preflight verb is asked about. */
export type PreflightManifestTarget =
  | { kind: "fortress_id"; fortressId: string }
  | { kind: "explicit_paths"; policyDir: string; pinnedPublicKeyPath: string };

/** One command's captured result. Exit code and text, never a re-interpretation. */
export interface UpgradeCommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * The process runner every route step goes through, injected so route order is
 * testable with no real `systemctl` and no real daemon. Its shape matches
 * `SystemctlRunner` in `linux-daemon.ts` with the command added, because these
 * steps run two different binaries.
 */
export interface UpgradeCommandRunner {
  run(command: string, args: readonly string[]): Promise<UpgradeCommandResult>;
}

/** What the caller supplies to run one route. */
export interface LinuxUpgradeRouteInput {
  route: LinuxUpgradeRoute;
  /** The binary that will be installed. The preflight step runs THIS one. */
  newBinaryPath: string;
  /** The binary currently at the unit's `ExecStart` path. Route A disarms with it. */
  installedBinaryPath?: string;
  target: PreflightManifestTarget;
  runner: UpgradeCommandRunner;
  /** Put the new binary at the installed path. Supplied by the privileged caller. */
  replaceBinary: () => Promise<void>;
  systemctlBinary?: string;
}

/** Why a route stopped, with the failing command's own text. */
export interface LinuxUpgradeAbort {
  step: LinuxUpgradeStepKind;
  /** The command's exit code, or null for the step that runs no command. */
  exit_code: number | null;
  /**
   * The failing command's own output, verbatim. The preflight verb's text names
   * the remediation (reissue the manifest through the publisher), so rewording it
   * would drop the one instruction the operator needs.
   */
  output: string;
}

/** The result of one route execution. */
export interface LinuxUpgradeRouteResult {
  route: LinuxUpgradeRoute;
  unit: string;
  planned_steps: readonly LinuxUpgradeStepKind[];
  completed_steps: readonly LinuxUpgradeStepKind[];
  outcome: "completed" | "aborted";
  abort?: LinuxUpgradeAbort;
}

/** The step list for a route. */
export function linuxUpgradeRouteSteps(route: LinuxUpgradeRoute): readonly LinuxUpgradeStepKind[] {
  return route === "disarm" ? LINUX_UPGRADE_ROUTE_A_STEPS : LINUX_UPGRADE_ROUTE_B_STEPS;
}

/**
 * Refuse a reboot route that carries a start step.
 *
 * INVARIANT: the reboot IS route B's start boundary. A start in the old boot
 * would run the new binary over the preserved ownership record, which resolves
 * to the host-wide net rather than the confined identity, so the route table and
 * this assertion both have to say no start.
 */
export function assertRouteHasNoSameBootStart(
  route: LinuxUpgradeRoute,
  steps: readonly LinuxUpgradeStepKind[],
): void {
  if (route !== "reboot") return;
  if (steps.includes("start_unit")) {
    throw new Error(
      "the reboot upgrade route must have no start step: the reboot is its start boundary",
    );
  }
}

/**
 * Build the preflight verb's argv.
 *
 * The fortress id is validated here rather than at the call site so no caller can
 * hand the daemon a value that parses as another flag.
 */
export function preflightManifestArgs(target: PreflightManifestTarget): string[] {
  if (target.kind === "fortress_id") {
    if (!FORTRESS_ID_PATTERN.test(target.fortressId)) {
      throw new Error("fortress id must be 8..64 lowercase hexadecimal characters");
    }
    return [PREFLIGHT_MANIFEST_FLAG, "--fortress-id", target.fortressId];
  }
  return [
    PREFLIGHT_MANIFEST_FLAG,
    "--policy-dir",
    target.policyDir,
    "--pinned-public-key",
    target.pinnedPublicKeyPath,
  ];
}

/** Prefer the channel the daemon writes its verdict on, and never invent text. */
function commandOutput(result: UpgradeCommandResult): string {
  const stderr = result.stderr.trim();
  if (stderr.length > 0) return stderr;
  return result.stdout.trim();
}

/**
 * Run one complete route, aborting on the first failing step.
 *
 * FAILURE MODE an operator would otherwise meet at 2am: a failing preflight that
 * only warns. Every step below returns on failure, and the preflight step is
 * first, so a host that will not admit the installed manifest still has its old
 * binary, its unit running and nothing replaced.
 */
export async function executeLinuxUpgradeRoute(
  input: LinuxUpgradeRouteInput,
): Promise<LinuxUpgradeRouteResult> {
  const steps = linuxUpgradeRouteSteps(input.route);
  assertRouteHasNoSameBootStart(input.route, steps);
  // The unit name is fixed, matching `linux-daemon.ts`: a user-facing upgrade
  // path does not get to choose which service it stops.
  const unit = CASTLE_WALL_SYSTEMD_UNIT;
  const systemctl = input.systemctlBinary ?? "systemctl";
  const completed: LinuxUpgradeStepKind[] = [];
  const aborted = (abort: LinuxUpgradeAbort): LinuxUpgradeRouteResult => ({
    route: input.route,
    unit,
    planned_steps: steps,
    completed_steps: completed,
    outcome: "aborted",
    abort,
  });

  for (const step of steps) {
    try {
    switch (step) {
      case "preflight_manifest_new_binary": {
        // The NEW binary answers, because it carries the bounds that will apply
        // after the replacement. Asking the old one proves nothing about it.
        const result = await input.runner.run(
          input.newBinaryPath,
          preflightManifestArgs(input.target),
        );
        if (result.code !== 0) {
          return aborted({ step, exit_code: result.code, output: commandOutput(result) });
        }
        break;
      }
      case "stop_unit": {
        const result = await input.runner.run(systemctl, [SYSTEMCTL_STOP, unit]);
        if (result.code !== 0) {
          return aborted({ step, exit_code: result.code, output: commandOutput(result) });
        }
        break;
      }
      case "disarm_old_binary": {
        // Route A only. The OLD binary deletes the table it armed and clears its
        // own ownership journal, which is what lets the new binary create fresh
        // instead of adopting a record it did not write.
        const result = await input.runner.run(
          input.installedBinaryPath ?? CASTLE_WALL_DAEMON_BINARY_DEFAULT,
          [DISARM_FLAG],
        );
        if (result.code !== 0) {
          return aborted({ step, exit_code: result.code, output: commandOutput(result) });
        }
        break;
      }
      case "replace_binary": {
        try {
          await input.replaceBinary();
        } catch (err) {
          return aborted({
            step,
            exit_code: null,
            output: err instanceof Error ? err.message : String(err),
          });
        }
        break;
      }
      case "start_unit": {
        const result = await input.runner.run(systemctl, [SYSTEMCTL_START, unit]);
        if (result.code !== 0) {
          return aborted({ step, exit_code: result.code, output: commandOutput(result) });
        }
        break;
      }
      case "reboot_host": {
        const result = await input.runner.run(systemctl, [SYSTEMCTL_REBOOT]);
        if (result.code !== 0) {
          return aborted({ step, exit_code: result.code, output: commandOutput(result) });
        }
        break;
      }
    }
    completed.push(step);
    } catch (err) {
      return aborted({
        step,
        exit_code: null,
        output: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return {
    route: input.route,
    unit,
    planned_steps: steps,
    completed_steps: completed,
    outcome: "completed",
  };
}

/** How the admission question was answered on this host. */
export type InstalledManifestAdmissionProbe = "ran" | "binary_absent" | "unavailable";

/** What the doctor path prints about the installed manifest. */
export interface InstalledManifestAdmissionReport {
  probe: InstalledManifestAdmissionProbe;
  /**
   * True ONLY on a completed run that exited zero. An absent binary or a probe
   * that could not complete is never reported as admitted, because an unanswered
   * question is not a passing answer.
   */
  admitted: boolean;
  exit_code: number | null;
  /** The verb's own line, verbatim, including its remediation when it refused. */
  daemon_output: string;
}

/** Inputs for the doctor path's admission report. */
export interface InstalledManifestAdmissionInput {
  target: PreflightManifestTarget;
  runner: UpgradeCommandRunner;
  /** Defaults to the installed daemon path, which is the host this report is about. */
  binaryPath?: string;
}

/**
 * Ask the installed daemon whether THIS host admits the manifest on disk.
 *
 * INVARIANT: the daemon's verb is the oracle. This function runs it and reports
 * its exit code and its text; it never re-implements an admission bound, because
 * one of those bounds is the host's own configured overflow uid, which only the
 * daemon reads.
 */
export async function reportInstalledManifestAdmission(
  input: InstalledManifestAdmissionInput,
): Promise<InstalledManifestAdmissionReport> {
  const binary = input.binaryPath ?? CASTLE_WALL_DAEMON_BINARY_DEFAULT;
  let result: UpgradeCommandResult;
  try {
    result = await input.runner.run(binary, preflightManifestArgs(input.target));
  } catch (err) {
    const absent = (err as { code?: string } | null)?.code === "ENOENT";
    return {
      probe: absent ? "binary_absent" : "unavailable",
      admitted: false,
      exit_code: null,
      daemon_output: err instanceof Error ? err.message : String(err),
    };
  }
  return {
    probe: "ran",
    admitted: result.code === 0,
    exit_code: result.code,
    daemon_output: commandOutput(result),
  };
}

/**
 * The installed Linux fortress ids under the canonical state root.
 *
 * The doctor path needs an id to ask the verb about, and the Linux layout puts
 * one directory per fortress under the state root. Only names matching the
 * canonical id grammar are returned, which is the same grammar
 * `preflightManifestArgs` validates, so a stray directory name can never reach
 * the daemon's argv.
 *
 * FAILURE MODE: the per-fortress directory is root-owned mode 0700, so an
 * unprivileged reader can list these NAMES and still not read what is inside.
 * An empty list therefore means "nothing installed here", never "nothing wrong".
 */
export async function discoverInstalledLinuxFortressIds(
  readDir: (path: string) => Promise<string[]>,
  stateRoot: string = CASTLE_WALL_LINUX_STATE_ROOT,
): Promise<string[]> {
  let entries: readonly string[];
  try {
    entries = await readDir(stateRoot);
  } catch {
    return [];
  }
  return entries.filter((entry) => FORTRESS_ID_PATTERN.test(entry)).sort();
}

/**
 * Production runner for the upgrade and doctor paths.
 *
 * Capture and timeout shape must match `realSystemctlRunner` in
 * `linux-daemon.ts`: exit code plus both streams, a killed child on timeout, and
 * a spawn error surfaced to the caller rather than read as an exit code. The
 * doctor path relies on that last property to tell an absent binary apart from a
 * refusal.
 */
export function realUpgradeCommandRunner(
  timeoutMs: number = UPGRADE_COMMAND_TIMEOUT_MS,
): UpgradeCommandRunner {
  return {
    run: async (command, args) => {
      const { spawn } = await import("node:child_process");
      return await new Promise<UpgradeCommandResult>((resolvePromise, reject) => {
        const child = spawn(command, [...args], { stdio: ["ignore", "pipe", "pipe"] });
        let stdout = "";
        let stderr = "";
        let settled = false;
        const finish = (result: UpgradeCommandResult): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolvePromise(result);
        };
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          finish({
            code: -1,
            stdout,
            stderr: `${stderr}${stderr ? "; " : ""}${command} timed out after ${timeoutMs}ms`,
          });
        }, timeoutMs);
        child.stdout.on("data", (d: Buffer) => {
          stdout += d.toString();
        });
        child.stderr.on("data", (d: Buffer) => {
          stderr += d.toString();
        });
        child.on("error", (err) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(err);
        });
        child.on("close", (code) => finish({ code, stdout, stderr }));
      });
    },
  };
}
