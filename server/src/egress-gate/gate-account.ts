/**
 * Dedicated `sanctuary-gate` service-account provisioning (Unified Protect
 * Slice 5 S5-3, part 1 of the gate-as-TCB fold; review HIGH-5a).
 *
 * WHY A DEDICATED UID (the TCB reframe, design 4b). An unauthenticated
 * loopback proxy is a machine-local open relay and a new trusted-computing-base
 * member. The gate must NOT run as the operator (that would let any local
 * process proxy through it under operator allow-all egress) and must NOT run as
 * the confined agent (kernel-denied). So it runs as its OWN hidden, no-login
 * service account, provisioned alongside the agent account in the same install
 * ceremony, so S5-4 can register it as a SECOND confined principal
 * (S5-0 two-confined-uid model) whose kernel-bounded allow-list is exactly the
 * declared endpoint set.
 *
 * PER-AGENT NAMING (conservative default; the wiring slice confirms). The gate
 * account name is derived PER AGENT (`sanctuary-gate-<agentId>`), not a single
 * shared `sanctuary-gate`. Rationale (fail-closed): under the S5-0 model each
 * confined uid is kernel-bounded to ONE endpoint set. A single gate uid shared
 * across N agents would be bounded to the UNION of all their endpoints, so a
 * compromised gate serving agent A could reach agent B's endpoints -- widening
 * the design's stated compromise bound ("bounded to the gate uid's
 * kernel-constrained endpoint set") from per-agent to per-box. Per-agent naming
 * keeps each gate uid bounded to exactly its own agent's endpoints. This is a
 * naming choice the arming slices (S5-4/S5-6) finalize; it arms nothing here and
 * forecloses nothing (a caller that wants one shared gate can pass a fixed
 * name). It is called out in the S5-3 lane report as a decision to confirm.
 *
 * THIS MODULE IS PLUMBING ONLY. Like `provision/account.ts`, the real
 * `sysadminctl -addUser` / `dscl` account creation is drill-only (Erik-present
 * console ceremony); this module is pure planning + injected ops so every branch
 * is unit-testable against mocks, touching no host. It deliberately REUSES the
 * shipped `provision/account.ts` planning machinery (`planAccountCreate`) for
 * service-account safety (the reserved-name set, the safe charset, the
 * uid-ceiling logic) so the gate account can never drift from the agent
 * account's hardening. Creation is wrapped here with gate-specific observed
 * record verification and rollback, because a partial gate account must never
 * be treated as an idempotent success.
 */

import {
  describeServiceAccountRecord,
  planAccountCreate,
  rollbackCreatedServiceAccount,
  SAFE_SERVICE_ACCOUNT_RE,
  serviceAccountRepairGuidance,
  serviceAccountRecordProblems,
  type AccountProvisionOptions,
  type AccountProvisionOps,
  type AccountProvisionPlan,
  type ServiceAccountRecord,
} from "../castle-wall/provision/account.js";

/** The canonical prefix for a per-agent gate service account. */
export const GATE_ACCOUNT_NAME_PREFIX = "sanctuary-gate-";

/**
 * Derive the canonical dedicated gate service-account name for an agent id,
 * e.g. `"hermes"` -> `"sanctuary-gate-hermes"`. Throws if the resulting name is
 * not a safe service-account name (the same conservative charset the shipped
 * agent-account machinery enforces), so a hostile agent id can never smuggle a
 * shell metacharacter or an over-long name into a `dscl`/`sysadminctl` argv.
 */
export function deriveGateAccountName(agentId: string): string {
  const name = `${GATE_ACCOUNT_NAME_PREFIX}${agentId}`;
  if (!SAFE_SERVICE_ACCOUNT_RE.test(name)) {
    throw new Error(
      `Derived gate account name is not a safe service-account name (got: ${JSON.stringify(name)} from agent id ${JSON.stringify(agentId)}).`,
    );
  }
  return name;
}

/** Inputs for planning/creating the gate service account. */
export interface GateAccountProvisionOptions {
  /** The agent id the gate serves (the gate account name is derived from it). */
  agentId: string;
  /**
   * The confined agent's uid. REQUIRED and ALWAYS excluded from the gate uid
   * (Codex round-3 HIGH): the gate must never run as the agent it serves (that
   * uid is kernel-denied), so the fail-closed exclusion is structural here, not
   * a caller-remembered `excludeUids` entry. A gate uid landing on this uid is
   * refused ({@link GateUidCollisionError}) even if the caller passes no
   * `excludeUids`.
   */
  agentUid: number;
  /** The lowest uid the gate account may be assigned (the arm-time ceiling). */
  ceiling: number;
  /**
   * The gate account's `NFSHomeDirectory`. The gate is a no-login service
   * account; this is a directory it owns (never the agent's re-home target).
   * Required for the same F7 reason the agent account is: `sysadminctl` would
   * otherwise default the home to somewhere unowned.
   */
  homeDirectory: string;
  /** Optional human-readable comment for the account record. */
  comment?: string;
  /**
   * ADDITIONAL uids to refuse for the gate account (Codex F2 fix-round). The
   * confined {@link agentUid} is ALWAYS excluded (see its doc); this is for
   * OPERATOR/console uids (e.g. 501, the first console user) the module cannot
   * enumerate itself -- else the gate could take the operator allow-all fast
   * path, the open-relay the whole TCB reframe exists to prevent. Operator uids
   * SHOULD be included when known; the agent uid does not need to be repeated.
   */
  excludeUids?: number[];
}

/** The directory-service fields that settle whether a gate account is complete. */
export type GateAccountRecord = ServiceAccountRecord;

/** Gate-account ops must be able to observe and roll back a just-created record. */
export interface GateAccountProvisionOps extends AccountProvisionOps {
  /**
   * Delete a Sanctuary gate account that this provisioning path may have just
   * created. This is NOT the routine unprovision account-removal flow; it is
   * bounded rollback of a fresh failed create. Pre-existing records are never
   * deleted here.
   */
  deleteCreatedUser(accountName: string): Promise<void>;
}

/**
 * Build the shared {@link AccountProvisionOptions} for the gate account from the
 * gate-specific options. Pure; exported so a caller can inspect the derived
 * name/ceiling before executing.
 */
export function gateAccountProvisionOptions(
  options: GateAccountProvisionOptions,
): AccountProvisionOptions {
  return {
    accountName: deriveGateAccountName(options.agentId),
    ceiling: options.ceiling,
    homeDirectory: options.homeDirectory,
    comment: options.comment ?? `Sanctuary exclusive-egress gate service account for agent ${options.agentId}`,
  };
}

/** Thrown when a planned gate uid collides with an excluded (agent/operator) uid. */
export class GateUidCollisionError extends Error {
  constructor(uid: number, kind: "agent-or-operator") {
    super(
      `Refusing to provision the gate service account at uid ${uid}: it collides with an excluded ` +
        `${kind} uid. The gate must run as neither the confined agent (kernel-denied) nor an operator ` +
        `(allow-all open relay); choose a ceiling/name that yields a distinct dedicated uid.`,
    );
    this.name = "GateUidCollisionError";
  }
}

/** Thrown when a gate account record exists but its uid/home could not be verified. */
export class GateAccountVerificationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "GateAccountVerificationError";
  }
}

async function rollbackIncompleteGateAccount(
  ops: GateAccountProvisionOps,
  accountName: string,
  input: { readonly plannedUid: number | undefined },
): Promise<string> {
  if (input.plannedUid === undefined) {
    return "rollback NOT attempted: account record existed before this run; leaving it for inspection";
  }
  return (await rollbackCreatedServiceAccount(ops, accountName, input.plannedUid)).message;
}

/**
 * Plan gate-account provisioning: pure decision over the two probe results,
 * delegating to the shipped {@link planAccountCreate} for the `skip`/`conflict`/
 * `create` semantics, THEN applying the fail-closed uid exclusion (Codex F2):
 * a `skip` or `create` whose uid lands on the agent uid or an operator uid is
 * refused ({@link GateUidCollisionError}) rather than silently accepted. A
 * `conflict` already refuses, so it passes through unchanged.
 */
export function planGateAccountProvision(
  options: GateAccountProvisionOptions,
  probe: { existingUid: number | undefined; highestAssignedUid: number },
): AccountProvisionPlan {
  if (!Number.isInteger(options.agentUid) || options.agentUid <= 0) {
    throw new Error(
      `planGateAccountProvision: agentUid must be a positive integer (got ${String(options.agentUid)}); ` +
        "the confined agent uid is required so the gate uid can be structurally excluded from it.",
    );
  }
  const plan = planAccountCreate(gateAccountProvisionOptions(options), probe);
  // The agent uid is ALWAYS excluded; excludeUids adds operator/console uids.
  const excluded = new Set<number>([options.agentUid, ...(options.excludeUids ?? [])]);
  if ((plan.action === "skip" || plan.action === "create") && excluded.has(plan.uid)) {
    throw new GateUidCollisionError(plan.uid, "agent-or-operator");
  }
  return plan;
}

/**
 * Probe + plan + execute the gate service account in one call, over injected
 * ops (the real `sysadminctl`/`dscl` side effects are drill-only). Returns the
 * gate account's uid and the plan that produced it. The gate uid MUST differ
 * from both the operator and the agent uid; that separation is enforced by the
 * ceiling (the gate uid lands strictly above every assigned uid) and re-checked
 * by the arming slice before the gate is registered as a confined principal.
 */
export async function planAndCreateGateAccount(
  options: GateAccountProvisionOptions,
  ops: GateAccountProvisionOps,
): Promise<{ plan: AccountProvisionPlan; uid: number; accountName: string; observed: string }> {
  const provisionOptions = gateAccountProvisionOptions(options);
  const existingRecord = await ops.lookupAccountRecord(provisionOptions.accountName);
  const existingUid = existingRecord?.uid;
  const highestAssignedUid = await ops.highestAssignedUid();
  // planGateAccountProvision applies the fail-closed agent/operator uid exclusion
  // (Codex F2) BEFORE any create side effect runs.
  const plan = planGateAccountProvision(options, { existingUid, highestAssignedUid });
  if (plan.action === "conflict") {
    throw new Error(plan.reason);
  }

  const expected = { uid: plan.uid, homeDirectory: provisionOptions.homeDirectory };
  if (plan.action === "skip") {
    const problems = await serviceAccountRecordProblems(existingRecord, expected, ops);
    if (problems.length === 0) {
      return {
        plan,
        uid: plan.uid,
        accountName: provisionOptions.accountName,
        observed: describeServiceAccountRecord(existingRecord),
      };
    }
    const rollback = await rollbackIncompleteGateAccount(ops, provisionOptions.accountName, {
      plannedUid: undefined,
    });
    throw new GateAccountVerificationError(
      `Existing gate account "${provisionOptions.accountName}" is incomplete (${problems.join("; ")}). ` +
        `${rollback}. Refusing to proceed with a partial gate account. ` +
        serviceAccountRepairGuidance(provisionOptions.accountName, expected),
    );
  }

  try {
    await ops.createUser(
      plan.accountName,
      plan.uid,
      provisionOptions.comment,
      provisionOptions.homeDirectory,
    );
    await ops.hardenCreatedUser(plan.accountName);
  } catch (err) {
    const rollback = await rollbackIncompleteGateAccount(ops, provisionOptions.accountName, {
      plannedUid: plan.uid,
    });
    throw new GateAccountVerificationError(
      `Creating gate account "${provisionOptions.accountName}" failed ` +
        `(${err instanceof Error ? err.message : String(err)}). ${rollback}. ` +
        serviceAccountRepairGuidance(provisionOptions.accountName, expected),
      { cause: err },
    );
  }

  let observed: GateAccountRecord | undefined;
  try {
    observed = await ops.lookupAccountRecord(provisionOptions.accountName);
  } catch (err) {
    const rollback = await rollbackIncompleteGateAccount(ops, provisionOptions.accountName, {
      plannedUid: plan.uid,
    });
    throw new GateAccountVerificationError(
      `Gate account "${provisionOptions.accountName}" create returned, but the post-create record could not be read ` +
        `(${err instanceof Error ? err.message : String(err)}). ${rollback}. ` +
        serviceAccountRepairGuidance(provisionOptions.accountName, expected),
      { cause: err },
    );
  }
  const problems = await serviceAccountRecordProblems(observed, expected, ops);
  if (problems.length > 0) {
    const rollback = await rollbackIncompleteGateAccount(ops, provisionOptions.accountName, {
      plannedUid: plan.uid,
    });
    throw new GateAccountVerificationError(
      `Gate account "${provisionOptions.accountName}" create did not verify (${problems.join("; ")}). ` +
        `Observed ${describeServiceAccountRecord(observed)}. ${rollback}. ` +
        serviceAccountRepairGuidance(provisionOptions.accountName, expected),
    );
  }
  return {
    plan,
    uid: plan.uid,
    accountName: provisionOptions.accountName,
    observed: describeServiceAccountRecord(observed),
  };
}
