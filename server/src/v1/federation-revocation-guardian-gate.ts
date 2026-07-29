/**
 * Optional M-of-N guardian sign-off gate for the federation revoke/kill path.
 *
 * COMPOSITION ONLY. This module reuses, without reimplementing, two existing
 * primitives:
 *   - the M-of-N guardian threshold evaluator
 *     ({@link enforceThreshold} from `recovery/threshold-evaluator.ts`), and
 *   - the operator-signed node-eviction revocation primitive
 *     (`v1/federation-revocation.ts`, invoked by the caller after this gate
 *     passes).
 *
 * It adds NO new cryptography: every signature check is delegated to the
 * threshold evaluator's real `@noble/curves` Ed25519 verification. It does NOT
 * weaken or bypass any existing check on the revoke path; it can only ADD a
 * required pre-condition (the M-of-N guardian quorum) before a revocation is
 * minted.
 *
 * TRUST BOUNDARY (kill/revoke): this gate guards an irreversible,
 * grow-only revocation. It is therefore:
 *   - DEFAULT-OFF. When no requirement is configured the caller skips this
 *     module entirely and the revoke path is byte-for-byte the legacy
 *     single-operator path.
 *   - FAIL-CLOSED. When a requirement IS configured, any defect in the supplied
 *     guardian approvals (too few valid, invalid signature, forged guardian,
 *     duplicate guardian counted once, stale roster, malformed input) results in
 *     REFUSAL. The evaluator never throws "allow" on ambiguity; this module
 *     converts every error into a structured deny decision.
 *
 * Binding: the guardian approvals are bound to the SPECIFIC revocation by the
 * canonical signing input the evaluator already verifies over. We bind:
 *   - `fortress_id`        -> the fortress whose node is being revoked,
 *   - `recovery_action`    -> the constant {@link GUARDIAN_SIGN_OFF_ACTION},
 *   - `cascade_id`         -> a deterministic id derived from the revoked
 *                             node id, so a quorum collected for node A cannot
 *                             be replayed to revoke node B, and
 *   - `roster_version`     -> the pinned roster version (stale-roster guard).
 */

import type { GuardianRoster } from "../mesh/guardian/types.js";
import {
  buildApprovalSigningInput,
  enforceThreshold,
  type GuardianApproval,
} from "../recovery/index.js";

/**
 * The recovery-action token guardians sign over when approving a federation
 * node revocation. Distinct from the recovery cascade's own action tokens; the
 * threshold evaluator treats this purely as opaque signed bytes, so binding a
 * dedicated token keeps a revocation quorum from being interchangeable with a
 * cascade quorum.
 */
export const GUARDIAN_SIGN_OFF_ACTION = "federation_node_eviction" as const;

// ── Lowered effective-M authorization (data types + effective-M accessor) ────
//
// These live HERE, co-located with `GuardianRevocationRequirement`, so this
// module never imports from `federation-guardian-disable-gate.ts` (which owns
// the sign/verify crypto + the chokepoint). That keeps the two a single
// directed edge (disable-gate -> this module) rather than an import cycle. A
// lowering of the effective kill threshold below the roster's issued `m` is
// operational state that can legitimately move down, but the roster's signed
// body is immutable authorization material (its `master_signature` covers `m`).
// Rewriting `m` inside the roster body to represent a lowering forges the roster
// and self-invalidates it on the next reboot (fail-open #2). Instead the
// effective threshold is carried as its OWN separately master-signed sibling
// record next to the (byte-for-byte unchanged) roster (INV-B).

/** Domain-separated signing context for a LOWERED effective-M authorization. */
export const LOWERED_THRESHOLD_AUTHORIZATION_DOMAIN =
  "sanctuary.federation.guardian-requirement.lowered-threshold.v1" as const;

/**
 * The canonical body a fortress-master key signs to authorize a lowered
 * effective kill threshold. Binds the fortress, the roster version the lowering
 * is scoped to (so a lowering minted for roster v7 cannot survive a rotate to
 * v8), the lowered effective M (a strict LOWERING: 1 <= effective_m <= roster.m
 * at mint time), and the anti-replay nonce burned by the transition that
 * produced it (folded into the boot nonce floor so a stale lowering below the
 * floor is refused - OR-2).
 */
export interface LoweredThresholdAuthorizationBody {
  domain: typeof LOWERED_THRESHOLD_AUTHORIZATION_DOMAIN;
  fortress_id: string;
  roster_version: number;
  effective_m: number;
  disable_nonce: number;
}

/**
 * A master-key-signed authorization carrying the lowered effective threshold.
 * The value that feeds the kill threshold MUST come from inside the signed
 * `body` ({@link effectiveThresholdM} reads `body.effective_m`), so there is no
 * unsigned copy of the effective M anywhere.
 */
export interface LoweredThresholdAuthorization {
  body: LoweredThresholdAuthorizationBody;
  /** base64url Ed25519 over `canonicalizeToBytes(body)`, by the fortress master. */
  signature: string;
}

/**
 * The EFFECTIVE kill threshold M for a requirement: the master-signed lowered
 * record's `effective_m` when present, else the roster's issued `m`. The value
 * always comes from inside a signed body (`roster.m` is covered by the roster's
 * `master_signature`; `loweredThreshold.body.effective_m` by its own). This is
 * the single source of truth the kill path and the disable-gate quorum eval
 * threshold on - the roster's signed `m` is NEVER mutated to represent a lower
 * threshold (INV-B).
 */
export function effectiveThresholdM(req: GuardianRevocationRequirement): number {
  return req.loweredThreshold?.body.effective_m ?? req.roster.m;
}

/**
 * Operator-configured requirement for guardian sign-off on a node revocation.
 *
 * Produced by the host (e.g. the dashboard `V1FederationDeps`) ONLY when the
 * operator has opted in. `null`/absent means the requirement is disabled and the
 * revoke path runs unchanged.
 */
export interface GuardianRevocationRequirement {
  /** The pinned, fortress-master-signed guardian roster (carries m and n). */
  roster: GuardianRoster;
  /**
   * The roster version the supplied approvals MUST match. Defaults to
   * `roster.version` when omitted; supplying it explicitly lets the host pin a
   * specific expected version for an extra stale-roster guard.
   */
  expectedRosterVersion?: number;
  /**
   * OPTIONAL master-signed lowered effective-M record. When present the kill
   * path thresholds on `loweredThreshold.body.effective_m` instead of
   * `roster.m` ({@link effectiveThresholdM}). The roster's signed body is NEVER
   * mutated to represent the lowering (INV-B): the lowered threshold rides in
   * this sibling record, so the roster's `master_signature` stays valid forever
   * and the lowering carries its own reboot verification. Absent -> effective M
   * = `roster.m` (the default; a pre-lower record decodes with this absent).
   */
  loweredThreshold?: LoweredThresholdAuthorization;
}

/**
 * Deterministic cascade id binding a guardian quorum to one specific node
 * revocation. Including the node id means approvals collected to revoke one node
 * cannot be replayed against another.
 */
export function revocationCascadeId(fortressId: string, nodeId: string): string {
  return `federation-node-eviction:${fortressId}:${nodeId}`;
}

export type GuardianRevocationGateDecision =
  | { allowed: true; validGuardianIds: string[] }
  | { allowed: false; reason: GuardianRevocationGateDenyReason; detail: string };

export type GuardianRevocationGateDenyReason =
  /** Approvals were required but none (or a non-array) were supplied. */
  | "guardian_approvals_required"
  /** Fewer than M valid, distinct, verified guardian signatures. */
  | "guardian_threshold_not_met"
  /** Supplied roster version did not match the pinned expectation. */
  | "guardian_roster_stale"
  /** Any other malformed-input / evaluation error. Fail-closed catch-all. */
  | "guardian_signoff_invalid";

/**
 * Evaluate the optional guardian sign-off gate for a node revocation.
 *
 * Returns `{ allowed: true }` ONLY when at least M distinct guardian signatures
 * verify against the pinned roster over the canonical signing input bound to
 * this exact (fortress, node) revocation. Every other outcome is a fail-closed
 * deny. The caller MUST refuse the revocation on any `allowed: false`.
 *
 * This function performs no I/O and no mutation; it is a pure decision over the
 * supplied roster + approvals.
 */
export function evaluateGuardianRevocationSignOff(params: {
  requirement: GuardianRevocationRequirement;
  fortressId: string;
  nodeId: string;
  approvals: unknown;
}): GuardianRevocationGateDecision {
  const { requirement, fortressId, nodeId } = params;

  if (!Array.isArray(params.approvals) || params.approvals.length === 0) {
    return {
      allowed: false,
      reason: "guardian_approvals_required",
      detail: "guardian sign-off is required for this revocation",
    };
  }

  const expectedRosterVersion =
    requirement.expectedRosterVersion ?? requirement.roster.version;

  const signingInput = buildApprovalSigningInput({
    cascade_id: revocationCascadeId(fortressId, nodeId),
    recovery_action: GUARDIAN_SIGN_OFF_ACTION,
    fortress_id: fortressId,
    roster_version: expectedRosterVersion,
  });

  try {
    const result = enforceThreshold({
      approvals: params.approvals as GuardianApproval[],
      roster: requirement.roster,
      signing_input: signingInput,
      expected_roster_version: expectedRosterVersion,
      // Threshold on the EFFECTIVE M (a master-signed lowered record when
      // present, else roster.m). The signed roster is never mutated; only the
      // integer the valid-signature count is compared against changes.
      effective_m: effectiveThresholdM(requirement),
    });
    return { allowed: true, validGuardianIds: result.valid_guardian_ids };
  } catch (err) {
    const reason = classifyGuardianGateError(err);
    return {
      allowed: false,
      reason,
      detail: errorDetail(err),
    };
  }
}

function classifyGuardianGateError(err: unknown): GuardianRevocationGateDenyReason {
  const code = readErrorCode(err);
  if (code === "threshold_not_met") return "guardian_threshold_not_met";
  if (code === "roster_stale") return "guardian_roster_stale";
  return "guardian_signoff_invalid";
}

function readErrorCode(err: unknown): string | null {
  if (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    typeof (err as { code: unknown }).code === "string"
  ) {
    return (err as { code: string }).code;
  }
  return null;
}

function errorDetail(err: unknown): string {
  if (err instanceof Error && err.message.length > 0) return err.message;
  return "guardian sign-off verification failed";
}
