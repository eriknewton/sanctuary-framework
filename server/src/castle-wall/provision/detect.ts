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
 * FIX F6 (HIGH, Codex second family, 2026-07-07 fix-round): a uid alone was
 * too loose a signal for "already dedicated". A stale prior service account,
 * or Hermes simply running at some other non-console uid with the wall
 * DISABLED, satisfied the old `uid >= ceiling && uid !== consoleOwnerUid`
 * test and made the orchestrator skip straight to "done" -- reporting
 * "already a dedicated account" while nothing was actually confined (no
 * daemon, no verify, no uid-gate, no arm). `alreadyDedicated` is now trusted
 * ONLY when the resolved uid's account NAME matches the expected dedicated
 * service-account shape (`sanctuary-<agentId>`, hidden / no-login /
 * non-admin); this requires an injected probe (`resolveAccountShape`) run by
 * the caller, since name/shape resolution needs directory-service access
 * this pure module does not perform itself. Any other non-console uid >=
 * ceiling is now `dedicatedAccountVerified: false` -- NOT already-dedicated
 * -- and provisions. `alreadyDedicated` in the result still means "the
 * orchestrator may skip create + re-home", but the orchestrator (see
 * orchestrate.ts) NEVER short-circuits past daemon-install + uid-gate +
 * verify + arm even when this is true -- skipping straight to "done" was
 * exactly the defect. Fail-closed: when in doubt (name/shape probe
 * indeterminate), treat as NOT dedicated and run the full flow.
 */

/** A resolved run-as identity, however it was determined. */
export interface RunAsIdentity {
  uid: number;
  source: "harness-config" | "running-process";
}

/**
 * The account-name/shape verdict for a resolved uid (fix F6). Only a
 * `verified-dedicated` shape counts as genuinely already-provisioned; any
 * other shape (or indeterminate) means the uid, however plausible, is NOT
 * trusted as the dedicated service account.
 */
export type AccountShapeVerdict = "verified-dedicated" | "not-dedicated" | "indeterminate";

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
  /**
   * FIX F6: the account-name/shape verdict for whichever uid was resolved
   * (harness-config or running-process), supplied by the caller's directory-
   * service probe (e.g. does the account at this uid have the name
   * `sanctuary-<agentId>`, a truthy hidden flag, a no-login shell, and no admin
   * group membership?). Only called by the caller when a uid was actually
   * resolved AND that uid clears the ceiling/console-owner test; leave
   * `undefined` (or omit) to get the fail-closed `"indeterminate"` default,
   * which this function treats as NOT dedicated.
   */
  accountShapeVerdict?: AccountShapeVerdict;
}

/** Result of {@link detectProvisionNeed}. */
export interface ProvisionNeedResult {
  /**
   * True when the flow should provision (or re-provision) a dedicated
   * account. False only when the agent is confirmed already dedicated
   * (fix F6: confirmed by NAME/SHAPE, not uid alone).
   */
  needsProvisioning: boolean;
  /**
   * True when an existing run-as uid was resolved, is >= ceiling and
   * distinct from the console owner, AND (fix F6) the account-shape probe
   * VERIFIED it is the genuine `sanctuary-<agentId>` dedicated service
   * account. The orchestrator may then skip create + re-home, but MUST
   * still run daemon-install + uid-gate + verify + arm (see orchestrate.ts)
   * -- this field never means "skip straight to done".
   */
  alreadyDedicated: boolean;
  /** The identity that was resolved, when one was. */
  resolved?: RunAsIdentity;
  /** Human-readable reason, safe to print (no secrets, no paths beyond uids). */
  reason: string;
}

/**
 * Decide whether provisioning is needed. Fail-closed default = provision
 * (fix H3): only an AFFIRMATIVELY resolved dedicated uid >= ceiling AND
 * (fix F6) a VERIFIED account name/shape skips provisioning. Any ambiguity,
 * absence of signal, a resolved uid that is NOT dedicated (shared with the
 * operator, or below ceiling), or a uid that clears the ceiling test but
 * whose account shape is NOT verified (or indeterminate) provisions.
 */
export function detectProvisionNeed(input: DetectProvisionNeedInput): ProvisionNeedResult {
  const { harnessConfiguredUid, runningAgentUid, consoleOwnerUid, ceiling, accountShapeVerdict } = input;

  // Primary signal: harness config declares a run-as identity.
  if (harnessConfiguredUid !== undefined) {
    const uidLooksDedicated = harnessConfiguredUid >= ceiling && harnessConfiguredUid !== consoleOwnerUid;
    const verified = uidLooksDedicated && accountShapeVerdict === "verified-dedicated";
    return {
      needsProvisioning: !verified,
      alreadyDedicated: verified,
      resolved: { uid: harnessConfiguredUid, source: "harness-config" },
      reason: verified
        ? `harness config already runs as VERIFIED dedicated uid ${harnessConfiguredUid} (>= ceiling ${ceiling}, distinct from console owner ${consoleOwnerUid}, account name/shape confirmed).`
        : uidLooksDedicated
          ? `harness config runs as uid ${harnessConfiguredUid} (>= ceiling ${ceiling}, distinct from console owner ${consoleOwnerUid}), but the account name/shape is NOT verified as the dedicated service account (fix F6: uid alone is not trusted) -- provisioning.`
          : `harness config runs as uid ${harnessConfiguredUid}, which is not a dedicated account (ceiling ${ceiling}, console owner ${consoleOwnerUid}).`,
    };
  }

  // Secondary signal: a running agent's ruid vs the console owner.
  if (runningAgentUid !== undefined) {
    const uidLooksDedicated = runningAgentUid >= ceiling && runningAgentUid !== consoleOwnerUid;
    const verified = uidLooksDedicated && accountShapeVerdict === "verified-dedicated";
    return {
      needsProvisioning: !verified,
      alreadyDedicated: verified,
      resolved: { uid: runningAgentUid, source: "running-process" },
      reason: verified
        ? `running agent already runs as VERIFIED dedicated uid ${runningAgentUid} (>= ceiling ${ceiling}, distinct from console owner ${consoleOwnerUid}, account name/shape confirmed).`
        : uidLooksDedicated
          ? `running agent runs as uid ${runningAgentUid} (>= ceiling ${ceiling}, distinct from console owner ${consoleOwnerUid}), but the account name/shape is NOT verified as the dedicated service account (fix F6: a stale or foreign uid is not trusted) -- provisioning.`
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
