/**
 * Auto-provision Step 2 (Build 1): shared-account detection.
 *
 * Decides whether `sanctuary protect` needs to provision a dedicated agent
 * OS account before it can arm the wall. Pure and testable: every input is a
 * plain value or an injected probe, so the fail-closed default (fix H3) is
 * exercised without touching a real host.
 *
 * FIX H3 (folded from the adversarial review): detection has two real
 * signals and a fallback.
 *   1. PRIMARY: the harness config's configured run-as identity, when the
 *      harness declares one. This works BEFORE the agent has ever run, so it
 *      is the preferred signal at first-install time.
 *   2. SECONDARY: a currently-running agent's real uid (ruid) compared
 *      against the console-session owner. Only meaningful once the agent
 *      has actually started.
 *   3. FALLBACK: when neither signal resolves a uid, PROVISION BY DEFAULT.
 *      Skipping provisioning is the fail-OPEN direction (it reproduces the
 *      boot-cut class of bug where an agent silently keeps running at the
 *      operator's own uid and is never confined); provisioning by default is
 *      the safe direction because provisioning itself is reversible
 *      (backup-first, `unprovision`) while an unconfined agent is not a
 *      recoverable state once egress has already happened.
 *
 * If the agent already runs at a DEDICATED non-login uid >= ceiling, this
 * reports `alreadyDedicated: true` so the orchestrator can skip straight to
 * daemon-install + arm (step 1 of the target flow) without re-provisioning.
 */

/** A resolved run-as identity, however it was determined. */
export interface RunAsIdentity {
  uid: number;
  source: "harness-config" | "running-process";
}

/** Inputs to {@link detectProvisionNeed}, every field independently mockable. */
export interface DetectProvisionNeedInput {
  /**
   * The harness's configured run-as uid, if the harness config declares one
   * (e.g. a LaunchAgent/LaunchDaemon plist already pins `UserName`/uid, or a
   * harness-specific config field). `undefined` when the harness declares
   * none (Hermes v1 today: the gateway plist has no UserName pin, so this is
   * always `undefined` for Hermes pre-provision).
   */
  harnessConfiguredUid?: number;
  /**
   * The ruid of a currently-running agent process, if one is running and
   * its ruid could be read. `undefined` when the agent is not running or
   * the ruid could not be determined.
   */
  runningAgentUid?: number;
  /** The uid that owns the current console/login session (the operator). */
  consoleOwnerUid: number;
  /** The ceiling below which uids are reserved for system/operator use. */
  ceiling: number;
}

/** Result of {@link detectProvisionNeed}. */
export interface ProvisionNeedResult {
  /**
   * True when the flow should provision (or re-provision) a dedicated
   * account. False only when the agent is confirmed already dedicated.
   */
  needsProvisioning: boolean;
  /**
   * True when an existing run-as uid was resolved and it is ALREADY a
   * dedicated non-login uid >= ceiling: the orchestrator can skip create +
   * re-home and go straight to daemon-install + arm.
   */
  alreadyDedicated: boolean;
  /** The identity that was resolved, when one was. */
  resolved?: RunAsIdentity;
  /** Human-readable reason, safe to print (no secrets, no paths beyond uids). */
  reason: string;
}

/**
 * Decide whether provisioning is needed. Fail-closed default = provision
 * (fix H3): only an AFFIRMATIVELY resolved dedicated uid >= ceiling skips
 * provisioning. Any ambiguity, absence of signal, or a resolved uid that is
 * NOT dedicated (shared with the operator, or below ceiling) provisions.
 */
export function detectProvisionNeed(input: DetectProvisionNeedInput): ProvisionNeedResult {
  const { harnessConfiguredUid, runningAgentUid, consoleOwnerUid, ceiling } = input;

  // Primary signal: harness config declares a run-as identity.
  if (harnessConfiguredUid !== undefined) {
    const dedicated = harnessConfiguredUid >= ceiling && harnessConfiguredUid !== consoleOwnerUid;
    return {
      needsProvisioning: !dedicated,
      alreadyDedicated: dedicated,
      resolved: { uid: harnessConfiguredUid, source: "harness-config" },
      reason: dedicated
        ? `harness config already runs as dedicated uid ${harnessConfiguredUid} (>= ceiling ${ceiling}, distinct from console owner ${consoleOwnerUid}).`
        : `harness config runs as uid ${harnessConfiguredUid}, which is not a dedicated account (ceiling ${ceiling}, console owner ${consoleOwnerUid}).`,
    };
  }

  // Secondary signal: a running agent's ruid vs the console owner.
  if (runningAgentUid !== undefined) {
    const dedicated = runningAgentUid >= ceiling && runningAgentUid !== consoleOwnerUid;
    return {
      needsProvisioning: !dedicated,
      alreadyDedicated: dedicated,
      resolved: { uid: runningAgentUid, source: "running-process" },
      reason: dedicated
        ? `running agent already runs as dedicated uid ${runningAgentUid} (>= ceiling ${ceiling}, distinct from console owner ${consoleOwnerUid}).`
        : `running agent runs as uid ${runningAgentUid}, which matches or is below the console/ceiling boundary (ceiling ${ceiling}, console owner ${consoleOwnerUid}) -- treating as shared with the operator.`,
    };
  }

  // Fallback: undetermined. Fix H3: provision by default (fail-closed
  // direction). Skipping here is the fail-OPEN direction that reproduces the
  // boot-cut class of bug.
  return {
    needsProvisioning: true,
    alreadyDedicated: false,
    reason:
      "could not determine the agent's run-as identity from harness config or a running process; provisioning by default (fail-closed: skipping would risk an unconfined agent).",
  };
}
