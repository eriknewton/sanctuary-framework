/**
 * Operator-side harness twin stand-down for `sanctuary protect`.
 *
 * This is the per-user LaunchAgent sibling of the SYSTEM harness stand-down in
 * `egress-gate/release-barrier.ts`. The system snapshot covers Sanctuary's
 * confined LaunchDaemon; it does not cover the OPERATOR-uid LaunchAgent that
 * the protected harness supersedes. Leaving that twin loaded lets the
 * unconfined process answer provider polls and creates a false "works through
 * the wall" result.
 */

import {
  awaitHarnessStoppedVia,
  launchctlBootoutWasInProgress,
  launchctlBootoutWasNotLoaded,
  launchctlPrintWasNotLoaded,
  type HarnessDaemonStatus,
} from "../../egress-gate/harness-daemon.js";
import { stripTrailingSlashes } from "../../strings.js";

type LaunchctlResult = { code: number; stdout: string; stderr: string };

export interface OperatorTwinDescriptor {
  /** Per-user launchd domain, e.g. `gui/501`. */
  domain: string;
  /** LaunchAgent label, e.g. `ai.hermes.gateway`. */
  label: string;
  /** Absolute path to the operator-owned LaunchAgent plist. */
  plistPath: string;
}

export interface OperatorTwinStandDownSnapshot {
  plistPath: string;
  priorPlistBytes?: string;
  domain: string;
  label: string;
  serviceName: string;
  disabledBefore: boolean;
  wasLoaded: boolean;
  wasRunning: boolean;
  /**
   * True when this run actually changed pre-existing operator-side launchd
   * state and a later refusal owes a restore.
   */
  preexistingTwinModified: boolean;
}

export interface OperatorTwinStandDownOps {
  readFile(path: string): Promise<string | undefined>;
  writeFile(path: string, content: string, mode: number): Promise<void>;
  removeFile(path: string): Promise<void>;
  runLaunchctl(args: readonly string[]): Promise<LaunchctlResult>;
  sleepMs?: (ms: number) => Promise<void>;
  notify(message: string): void;
}

export interface OperatorTwinRestoreReport {
  restored: boolean;
  plistRestored: boolean;
  disabledStateRestored: boolean;
  loadedStateRestored: boolean;
  runningStateRestored: boolean;
  problems: string[];
}

export class OperatorTwinStandDownError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(`operator twin stand-down: ${message}`, options);
    this.name = "OperatorTwinStandDownError";
  }
}

export function operatorTwinServiceName(descriptor: OperatorTwinDescriptor): string {
  return `${descriptor.domain}/${descriptor.label}`;
}

export function hermesOperatorTwinDescriptor(input: {
  operatorHome: string;
  operatorUid: number;
}): OperatorTwinDescriptor {
  const home = stripTrailingSlashes(input.operatorHome);
  const label = "ai.hermes.gateway";
  return {
    domain: `gui/${input.operatorUid}`,
    label,
    plistPath: `${home}/Library/LaunchAgents/${label}.plist`,
  };
}

export async function readOperatorTwinLaunchdStatus(
  descriptor: OperatorTwinDescriptor,
  ops: Pick<OperatorTwinStandDownOps, "runLaunchctl">,
): Promise<HarnessDaemonStatus> {
  const serviceName = operatorTwinServiceName(descriptor);
  let result: LaunchctlResult;
  try {
    result = await ops.runLaunchctl(["print", serviceName]);
  } catch {
    return { known: false, installed: false, running: false };
  }
  if (result.code !== 0) {
    return launchctlPrintWasNotLoaded(result)
      ? { known: true, installed: false, running: false }
      : { known: false, installed: false, running: false };
  }
  const pidMatch = /^\s*pid\s*=\s*(\d+)\s*$/m.exec(result.stdout);
  if (pidMatch !== null) {
    return { known: true, installed: true, running: true, pid: Number(pidMatch[1]) };
  }
  return { known: true, installed: true, running: false };
}

async function readOperatorTwinDisabledOverride(
  descriptor: OperatorTwinDescriptor,
  ops: Pick<OperatorTwinStandDownOps, "runLaunchctl">,
): Promise<{ known: true; disabled: boolean } | { known: false; reason: string }> {
  let result: LaunchctlResult;
  try {
    result = await ops.runLaunchctl(["print-disabled", descriptor.domain]);
  } catch (err) {
    return {
      known: false,
      reason: `launchctl print-disabled ${descriptor.domain} errored: ${(err as Error).message}`,
    };
  }
  if (result.code !== 0) {
    return {
      known: false,
      reason: `launchctl print-disabled ${descriptor.domain} exited ${result.code}: ${result.stderr.trim()}`,
    };
  }
  const label = descriptor.label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (new RegExp(`"${label}"\\s*=>\\s*(disabled|true)\\b`).test(result.stdout)) {
    return { known: true, disabled: true };
  }
  return { known: true, disabled: false };
}

async function setOperatorTwinDisabled(
  descriptor: OperatorTwinDescriptor,
  ops: Pick<OperatorTwinStandDownOps, "runLaunchctl">,
  disabled: boolean,
): Promise<void> {
  const verb = disabled ? "disable" : "enable";
  const serviceName = operatorTwinServiceName(descriptor);
  const result = await ops.runLaunchctl([verb, serviceName]);
  if (result.code !== 0) {
    throw new OperatorTwinStandDownError(
      `launchctl ${verb} ${serviceName} exited ${result.code}: ${result.stderr.trim()}`,
    );
  }
  const observed = await readOperatorTwinDisabledOverride(descriptor, ops);
  if (!observed.known) {
    throw new OperatorTwinStandDownError(
      `launchctl ${verb} ${serviceName} exited 0, but launchd's persistent override state ` +
        `could not be read back (${observed.reason})`,
    );
  }
  if (observed.disabled !== disabled) {
    throw new OperatorTwinStandDownError(
      `launchctl ${verb} ${serviceName} exited 0, but launchd still reports the job ` +
        `${observed.disabled ? "DISABLED" : "ENABLED"}`,
    );
  }
}

async function confirmPlistBytes(
  ops: Pick<OperatorTwinStandDownOps, "readFile">,
  path: string,
  expected: string | undefined,
): Promise<boolean> {
  try {
    return (await ops.readFile(path)) === expected;
  } catch {
    return false;
  }
}

function describeError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Stop and persistently disable the operator-side LaunchAgent this protect run
 * supersedes. The order is disable FIRST, bootout SECOND, then a settled
 * launchd readback. A still-running job is a hard failure.
 */
export async function standDownOperatorTwinLaunchAgent(
  descriptor: OperatorTwinDescriptor,
  ops: OperatorTwinStandDownOps,
): Promise<OperatorTwinStandDownSnapshot> {
  const serviceName = operatorTwinServiceName(descriptor);
  const priorPlistBytes = await ops.readFile(descriptor.plistPath);
  const disabledBefore = await readOperatorTwinDisabledOverride(descriptor, ops);
  if (!disabledBefore.known) {
    throw new OperatorTwinStandDownError(
      `launchd disabled state is unknown before mutation (${disabledBefore.reason}); refusing to stand down ${serviceName}`,
    );
  }
  const before = await readOperatorTwinLaunchdStatus(descriptor, ops);
  if (!before.known) {
    throw new OperatorTwinStandDownError(
      `launchctl did not return a trustworthy status for ${serviceName}; refusing to stand down an unknown job`,
    );
  }
  const beforeLive = before.running || before.pid !== undefined;
  if (beforeLive && priorPlistBytes === undefined) {
    throw new OperatorTwinStandDownError(
      `${serviceName} is running but no plist exists at ${descriptor.plistPath}; refusing a stand-down this run cannot restore`,
    );
  }

  const shouldStandDown = priorPlistBytes !== undefined || before.installed;
  const snapshot: OperatorTwinStandDownSnapshot = {
    plistPath: descriptor.plistPath,
    ...(priorPlistBytes !== undefined ? { priorPlistBytes } : {}),
    domain: descriptor.domain,
    label: descriptor.label,
    serviceName,
    disabledBefore: disabledBefore.disabled,
    wasLoaded: before.installed,
    wasRunning: beforeLive,
    preexistingTwinModified: shouldStandDown && (!disabledBefore.disabled || before.installed || beforeLive),
  };
  if (!shouldStandDown) {
    return snapshot;
  }

  try {
    await setOperatorTwinDisabled(descriptor, ops, true);
    const bootout = await ops.runLaunchctl(["bootout", descriptor.domain, descriptor.plistPath]);
    const bootoutInProgress = launchctlBootoutWasInProgress(bootout);
    if (bootout.code === 0) {
      ops.notify(
        `Disabled and unloaded the operator-side ${descriptor.label} LaunchAgent before checking agent liveness. ` +
          "This prevents the unconfined operator-uid twin from answering provider polls while the confined agent is verified.",
      );
    } else if (!launchctlBootoutWasNotLoaded(bootout) && !bootoutInProgress) {
      throw new OperatorTwinStandDownError(
        `launchctl bootout ${descriptor.domain} ${descriptor.plistPath} exited ${bootout.code}: ` +
          `${bootout.stderr.trim()}; refusing to claim the operator twin is down`,
      );
    }

    const settled = await awaitHarnessStoppedVia(
      () => readOperatorTwinLaunchdStatus(descriptor, ops),
      ops.sleepMs,
    );
    const after = settled.status;
    if (!after.known) {
      throw new OperatorTwinStandDownError(
        `launchctl status for ${serviceName} was untrustworthy after bootout; refusing to claim the operator twin is down`,
      );
    }
    if (after.running || after.pid !== undefined) {
      throw new OperatorTwinStandDownError(
        `${serviceName} is STILL RUNNING after disable + bootout; refusing to verify liveness while the unconfined twin can answer`,
      );
    }
    return snapshot;
  } catch (err) {
    const restore = await restoreOperatorTwinStandDown(snapshot, ops);
    throw new OperatorTwinStandDownError(
      `${describeError(err)}. The operator-side twin stand-down failed after mutation; restore ` +
        `${restore.restored ? "succeeded" : `did NOT fully succeed (${restore.problems.join("; ") || "no detail"})`}.`,
      { cause: err },
    );
  }
}

/**
 * Restore a prior operator-side LaunchAgent snapshot. Never throws: this runs
 * on paths that are already refusing for another reason, so failures are
 * returned for the single outcome chokepoint to surface.
 */
export async function restoreOperatorTwinStandDown(
  snapshot: OperatorTwinStandDownSnapshot,
  ops: OperatorTwinStandDownOps,
): Promise<OperatorTwinRestoreReport> {
  const problems: string[] = [];
  const descriptor: OperatorTwinDescriptor = {
    domain: snapshot.domain,
    label: snapshot.label,
    plistPath: snapshot.plistPath,
  };

  let plistRestored = false;
  try {
    if (snapshot.priorPlistBytes !== undefined) {
      await ops.writeFile(snapshot.plistPath, snapshot.priorPlistBytes, 0o644);
    } else {
      await ops.removeFile(snapshot.plistPath);
    }
    plistRestored = await confirmPlistBytes(ops, snapshot.plistPath, snapshot.priorPlistBytes);
    if (!plistRestored) {
      problems.push(`plist ${snapshot.plistPath} did not read back as the pre-run bytes`);
    }
  } catch (err) {
    problems.push(`could not restore plist ${snapshot.plistPath}: ${describeError(err)}`);
  }

  let loadedStateRestored = !snapshot.wasLoaded;
  let runningStateRestored = !snapshot.wasRunning;
  if ((snapshot.wasLoaded || snapshot.wasRunning) && snapshot.priorPlistBytes !== undefined) {
    try {
      await setOperatorTwinDisabled(descriptor, ops, false);
      const bootstrap = await ops.runLaunchctl(["bootstrap", snapshot.domain, snapshot.plistPath]);
      if (bootstrap.code !== 0 && !/already bootstrapped/i.test(bootstrap.stderr)) {
        problems.push(
          `launchctl bootstrap ${snapshot.domain} ${snapshot.plistPath} exited ${bootstrap.code}: ` +
            bootstrap.stderr.trim(),
        );
      }
      if (snapshot.wasRunning) {
        const kickstart = await ops.runLaunchctl(["kickstart", snapshot.serviceName]);
        if (kickstart.code !== 0) {
          problems.push(
            `launchctl kickstart ${snapshot.serviceName} exited ${kickstart.code}: ${kickstart.stderr.trim()}`,
          );
        }
      }
      const status = await readOperatorTwinLaunchdStatus(descriptor, ops);
      loadedStateRestored = status.known && status.installed === snapshot.wasLoaded;
      runningStateRestored = status.known && (status.running || status.pid !== undefined) === snapshot.wasRunning;
      if (!status.known) {
        problems.push(`could not verify restored launchd state for ${snapshot.serviceName}`);
      } else {
        if (!loadedStateRestored) problems.push(`${snapshot.serviceName} loaded state did not match the pre-run state`);
        if (!runningStateRestored) problems.push(`${snapshot.serviceName} running state did not match the pre-run state`);
      }
    } catch (err) {
      problems.push(`could not reload restored operator LaunchAgent ${snapshot.serviceName}: ${describeError(err)}`);
    }
  }

  let disabledStateRestored = false;
  try {
    await setOperatorTwinDisabled(descriptor, ops, snapshot.disabledBefore);
    disabledStateRestored = true;
  } catch (err) {
    problems.push(
      `could not restore launchd disabled state for ${snapshot.serviceName} to ` +
        `${snapshot.disabledBefore ? "disabled" : "enabled"}: ${describeError(err)}`,
    );
  }

  const restored =
    plistRestored &&
    disabledStateRestored &&
    loadedStateRestored &&
    runningStateRestored &&
    problems.length === 0;
  return {
    restored,
    plistRestored,
    disabledStateRestored,
    loadedStateRestored,
    runningStateRestored,
    problems,
  };
}
