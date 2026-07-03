/**
 * F1 - Guardian requirement DISABLE-gate (E1 slice).
 *
 * COMPOSITION ONLY. This module closes the "off-switch" gap left by
 * `federation-revocation-guardian-gate.ts`: the M-of-N guardian quorum on the
 * federation KILL path (`GUARDIAN_SIGN_OFF_ACTION` /
 * `evaluateGuardianRevocationSignOff`) is real, but turning that guard OFF (or
 * weakening it) was still a single operator's own authority. This module adds
 * a required precondition to the DECREASING directions only (disable, lower
 * M): an M-of-N guardian quorum, OR (per the ratified two-posture model) a
 * master-key instant authorization, OR a 72h loudly-audited, guardian-vetoable
 * break-glass countdown for the case where guardians have genuinely gone dark
 * and there is no master key available.
 *
 * Reused, not reimplemented: {@link enforceThreshold} and
 * {@link buildApprovalSigningInput} from `recovery/threshold-evaluator.ts` (the
 * SAME real `@noble/curves` Ed25519 M-of-N verification the kill gate uses),
 * and {@link verifyGuardianRoster} from `mesh/guardian/guardian-roster.ts`. No
 * new signature algorithm, no new key material.
 *
 * ── Ratified two-posture model (2026-07-03) ─────────────────────────────────
 *
 *   - DEFAULT posture: no guardian requirement is configured
 *     (`_federationGuardianRevocationRequirement === null`). The kill path and
 *     this disable-gate are both no-ops; a single master-key holder (there IS
 *     no separate "operator" key concept in this posture) controls everything
 *     instantly. Nothing in this module fires.
 *   - UPGRADE posture: once a guardian requirement exists, BOTH the kill path
 *     and this disable-gate are ON. The operator key alone can never weaken or
 *     disable the guard (the core protection against a stolen operator key /
 *     rogue agent). Three paths can still change/clear the requirement:
 *       1. MASTER-KEY instant toggle/retune - the fortress trust root. Verified
 *          by an Ed25519 signature over a canonical authorization body bound to
 *          the SAME anti-replay nonce as the quorum path, checked against the
 *          pinned fortress-master public key. No quorum needed, no delay: the
 *          owner of the fortress is never caged by their own feature.
 *       2. M-of-N GUARDIAN QUORUM - instant, requires the CURRENT roster's
 *          M signatures (reuses `enforceThreshold`).
 *       3. BREAK-GLASS - a 72h (default; 24h floor), loudly-audited,
 *          posture-surfaced, 1-of-N-guardian-vetoable countdown that
 *          auto-completes if unvetoed. The deep, non-master, non-quorum escape
 *          hatch so a fortress whose guardians AND master key are both
 *          unavailable is never permanently wedged.
 *
 * FAIL-CLOSED throughout: every ambiguity (missing/short/duplicate/forged
 * signatures, stale nonce, stale roster version, wrong action token) is a
 * deny. This module never throws "allow" on ambiguous input.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";
import type { FortressMasterPublicKey } from "../mesh/types.js";
import {
  buildApprovalSigningInput,
  enforceThreshold,
  type GuardianApproval,
} from "../recovery/index.js";
import type { GuardianRevocationRequirement } from "./federation-revocation-guardian-gate.js";

/**
 * The recovery-action token guardians sign over when authorizing an INSTANT
 * disable/lower of the guardian revocation requirement. Distinct from the kill
 * path's {@link GUARDIAN_SIGN_OFF_ACTION} (`"federation_node_eviction"`,
 * imported by callers from `federation-revocation-guardian-gate.ts`) and from
 * every `RECOVERY_ACTIONS` cascade token. The threshold evaluator treats
 * `recovery_action` as opaque signed bytes (verified: `enforceThreshold` never
 * checks it against the `RECOVERY_ACTIONS` enum), so this new token needs no
 * enum widening - but because the token DIFFERS from the kill token, a kill
 * sign-off's canonical signed bytes can never verify as a disable authorization,
 * and vice versa. This is the first of three replay firewalls (see module doc).
 */
export const GUARDIAN_DISABLE_SIGN_OFF_ACTION =
  "federation_guardian_requirement_disable" as const;

/**
 * The action token a guardian signs over when VETOING an in-flight break-glass
 * countdown. Distinct from both the disable-authorize token above and the kill
 * token, so a veto signature can never be replayed as an authorize (or vice
 * versa) even though both are guardian-signed over similar-looking inputs.
 */
export const GUARDIAN_BREAK_GLASS_VETO_ACTION =
  "federation_guardian_break_glass_veto" as const;

/** Default break-glass countdown length: 72 hours (Erik-ratified default). */
export const DEFAULT_BREAK_GLASS_DELAY_MS = 72 * 60 * 60 * 1000;
/** Hard floor: a break-glass delay may never be configured below 24 hours. */
export const MIN_BREAK_GLASS_DELAY_MS = 24 * 60 * 60 * 1000;

/**
 * Deterministic id binding a guardian quorum (or a master-key authorization) to
 * one specific disable/lower attempt. Three independent bindings ride inside
 * it, each closing a distinct replay path (see module doc + design 8.2):
 *
 *   - `disableNonce`: a monotonic per-fortress counter that BURNS (advances)
 *     on every terminal transition (instant-authorize success, break-glass
 *     vetoed, break-glass cancelled, break-glass completed). A quorum or
 *     master-key signature collected for nonce K can never be replayed once K
 *     is consumed, because any later attempt demands a strictly higher nonce.
 *   - `intent` + `targetM`: a quorum/signature gathered to "lower to m=2"
 *     cannot be reused to "disable entirely" and vice versa.
 */
export function disableCascadeId(
  fortressId: string,
  disableNonce: number,
  intent: "disable" | "lower",
  targetM: number | null,
): string {
  return `federation-guardian-requirement-disable:${fortressId}:${disableNonce}:${intent}:${targetM ?? "off"}`;
}

/**
 * Deterministic id binding a guardian veto signature to one specific in-flight
 * break-glass countdown. Distinct prefix from {@link disableCascadeId} so a
 * veto signature's canonical bytes can never verify as a disable-authorize
 * approval (the cascade_id itself differs, on top of the distinct action
 * token).
 */
export function breakGlassVetoCascadeId(
  fortressId: string,
  disableNonce: number,
): string {
  return `federation-guardian-break-glass-veto:${fortressId}:${disableNonce}`;
}

/**
 * Classify a proposed transition of the guardian revocation requirement
 * against the CURRENTLY-persisted one. Only `"decrease"` requires the new
 * gate; `"increase"` and `"noop"` stay operator-only (unchanged, frictionless
 * tightening).
 *
 * Rules (design 4.1, OQ-2 answer):
 *   - `current === null && next !== null` -> increase (enable).
 *   - `current !== null && next === null` -> decrease (disable).
 *   - both non-null: compare `next.roster.m` vs `current.roster.m`. A strictly
 *     lower M is a decrease; a strictly higher M is an increase; an EQUAL M is
 *     a noop for gate purposes (a guardian re-pin at equal M is a
 *     roster-integrity concern already covered by the master-signed roster
 *     verification, not a threshold weakening - gating it would reintroduce a
 *     lockout: an operator who lost a guardian's key could never re-pin a
 *     replacement without the very quorum that is now short a member).
 */
export function classifyRequirementTransition(
  current: GuardianRevocationRequirement | null,
  next: GuardianRevocationRequirement | null,
): "increase" | "decrease" | "noop" {
  if (current === null && next === null) return "noop";
  if (current === null && next !== null) return "increase";
  if (current !== null && next === null) return "decrease";
  // both non-null
  const currentM = current!.roster.m;
  const nextM = next!.roster.m;
  if (nextM < currentM) return "decrease";
  if (nextM > currentM) return "increase";
  return "noop";
}

// ── Instant quorum-authorized disable/lower ─────────────────────────────────

export type GuardianDisableGateDecision =
  | { allowed: true; validGuardianIds: string[] }
  | { allowed: false; reason: GuardianDisableGateDenyReason; detail: string };

export type GuardianDisableGateDenyReason =
  | "guardian_approvals_required"
  | "guardian_threshold_not_met"
  | "guardian_roster_stale"
  | "guardian_signoff_invalid";

/**
 * Evaluate the M-of-N guardian quorum required for an INSTANT disable/lower.
 * The quorum is evaluated against the roster of the requirement BEING TORN
 * DOWN (M and N as they stand now) - you need M of the CURRENT guardians to
 * authorize weakening the current rule; lowering to a smaller M' still needs
 * the current (larger) M's worth of signatures. Pure decision, no I/O.
 */
export function evaluateGuardianDisableSignOff(params: {
  /** The CURRENT (pinned) requirement being disabled/lowered. */
  requirement: GuardianRevocationRequirement;
  fortressId: string;
  disableNonce: number;
  intent: "disable" | "lower";
  targetM: number | null;
  approvals: unknown;
}): GuardianDisableGateDecision {
  const { requirement, fortressId, disableNonce, intent, targetM } = params;

  if (!Array.isArray(params.approvals) || params.approvals.length === 0) {
    return {
      allowed: false,
      reason: "guardian_approvals_required",
      detail: "guardian sign-off is required to disable/lower this requirement",
    };
  }

  const expectedRosterVersion =
    requirement.expectedRosterVersion ?? requirement.roster.version;

  const signingInput = buildApprovalSigningInput({
    cascade_id: disableCascadeId(fortressId, disableNonce, intent, targetM),
    recovery_action: GUARDIAN_DISABLE_SIGN_OFF_ACTION,
    fortress_id: fortressId,
    roster_version: expectedRosterVersion,
  });

  try {
    const result = enforceThreshold({
      approvals: params.approvals as GuardianApproval[],
      roster: requirement.roster,
      signing_input: signingInput,
      expected_roster_version: expectedRosterVersion,
    });
    return { allowed: true, validGuardianIds: result.valid_guardian_ids };
  } catch (err) {
    return {
      allowed: false,
      reason: classifyDisableGateError(err),
      detail: errorDetail(err),
    };
  }
}

/**
 * Sign a disable/lower authorization as a guardian. Test/CLI fixture helper
 * mirroring `signApproval` from `recovery/threshold-evaluator.ts`, but bound to
 * the disable action token instead of a recovery cascade action.
 */
export function signGuardianDisableApproval(params: {
  guardianId: string;
  guardianPrivateKey: Uint8Array;
  fortressId: string;
  disableNonce: number;
  intent: "disable" | "lower";
  targetM: number | null;
  rosterVersion: number;
}): GuardianApproval {
  const signingInput = buildApprovalSigningInput({
    cascade_id: disableCascadeId(
      params.fortressId,
      params.disableNonce,
      params.intent,
      params.targetM,
    ),
    recovery_action: GUARDIAN_DISABLE_SIGN_OFF_ACTION,
    fortress_id: params.fortressId,
    roster_version: params.rosterVersion,
  });
  const signedBytes = canonicalizeToBytes(signingInput);
  const sig = ed25519.sign(signedBytes, params.guardianPrivateKey);
  return {
    guardian_id: params.guardianId,
    // `recovery_action` is typed as the closed `RecoveryAction` union upstream,
    // but the threshold evaluator treats it as opaque signed bytes (never
    // checked against `RECOVERY_ACTIONS`); the kill gate does the identical
    // cast for its own out-of-enum token.
    recovery_action: GUARDIAN_DISABLE_SIGN_OFF_ACTION as GuardianApproval["recovery_action"],
    cascade_id: signingInput.cascade_id,
    approved_at: new Date().toISOString(),
    signature: toBase64url(sig),
    signature_scheme: SIGNATURE_SCHEME_V1,
  };
}

/**
 * Sign a break-glass veto as a guardian. One signature from ANY guardian in
 * the current pinned roster is sufficient (1-of-N, the deliberate asymmetry:
 * easy to stop a teardown, hard to perform one).
 */
export function signGuardianBreakGlassVeto(params: {
  guardianId: string;
  guardianPrivateKey: Uint8Array;
  fortressId: string;
  disableNonce: number;
  rosterVersion: number;
}): GuardianApproval {
  const signingInput = buildApprovalSigningInput({
    cascade_id: breakGlassVetoCascadeId(params.fortressId, params.disableNonce),
    recovery_action: GUARDIAN_BREAK_GLASS_VETO_ACTION,
    fortress_id: params.fortressId,
    roster_version: params.rosterVersion,
  });
  const signedBytes = canonicalizeToBytes(signingInput);
  const sig = ed25519.sign(signedBytes, params.guardianPrivateKey);
  return {
    guardian_id: params.guardianId,
    recovery_action: GUARDIAN_BREAK_GLASS_VETO_ACTION as GuardianApproval["recovery_action"],
    cascade_id: signingInput.cascade_id,
    approved_at: new Date().toISOString(),
    signature: toBase64url(sig),
    signature_scheme: SIGNATURE_SCHEME_V1,
  };
}

export type BreakGlassVetoDecision =
  | { vetoed: true; guardianId: string }
  | { vetoed: false; reason: GuardianDisableGateDenyReason; detail: string };

/**
 * Evaluate a single guardian veto signature against the current pinned roster.
 * Effective threshold of 1 (any ONE current guardian's valid signature is
 * sufficient) - reuses the SAME `enforceThreshold` verification path with the
 * roster's real `m`; a veto only needs ONE valid signer so we accept as soon as
 * the supplied approval verifies against ANY roster member, which we implement
 * by evaluating against a synthetic single-guardian quorum requirement (m=1)
 * so the exact same fail-closed signature/roster-version/duplicate checks
 * apply. Fail-closed: an empty, malformed, forged, wrong-action, wrong-nonce,
 * or stale-roster-version signature is REFUSED (does not veto).
 */
export function evaluateGuardianBreakGlassVeto(params: {
  requirement: GuardianRevocationRequirement;
  fortressId: string;
  disableNonce: number;
  approval: unknown;
}): BreakGlassVetoDecision {
  const { requirement, fortressId, disableNonce } = params;
  if (
    params.approval === null ||
    params.approval === undefined ||
    typeof params.approval !== "object"
  ) {
    return {
      vetoed: false,
      reason: "guardian_approvals_required",
      detail: "a guardian veto signature is required",
    };
  }

  const expectedRosterVersion =
    requirement.expectedRosterVersion ?? requirement.roster.version;

  const signingInput = buildApprovalSigningInput({
    cascade_id: breakGlassVetoCascadeId(fortressId, disableNonce),
    recovery_action: GUARDIAN_BREAK_GLASS_VETO_ACTION,
    fortress_id: fortressId,
    roster_version: expectedRosterVersion,
  });

  // A veto needs only ONE valid guardian signature (1-of-N), regardless of the
  // requirement's own M. We evaluate against a roster clone with m=1 so the
  // exact same signature/duplicate/version verification machinery applies but
  // a single valid signer is sufficient.
  const vetoRoster = { ...requirement.roster, m: 1 };

  try {
    const result = enforceThreshold({
      approvals: [params.approval as GuardianApproval],
      roster: vetoRoster,
      signing_input: signingInput,
      expected_roster_version: expectedRosterVersion,
    });
    const guardianId = result.valid_guardian_ids[0];
    if (guardianId === undefined) {
      // Should be unreachable given threshold_met above, but stay fail-closed.
      return {
        vetoed: false,
        reason: "guardian_signoff_invalid",
        detail: "veto verification produced no valid guardian id",
      };
    }
    return { vetoed: true, guardianId };
  } catch (err) {
    return {
      vetoed: false,
      reason: classifyDisableGateError(err),
      detail: errorDetail(err),
    };
  }
}

// ── Master-key instant toggle/reconfigure ───────────────────────────────────

/**
 * The domain-separated signing context for a master-key disable/lower/toggle
 * authorization. A master key holder can retune the requirement (including
 * disabling it) INSTANTLY, no quorum, no break-glass delay - the fortress
 * trust root is never caged by its own feature (ratified 2026-07-03). This is
 * a DIFFERENT action token from both the guardian-quorum disable token and the
 * break-glass veto token, so a master signature can never be replayed as a
 * guardian approval or vice versa, and the two verification paths (Ed25519
 * against the guardian roster vs. Ed25519 against the pinned fortress-master
 * key) are structurally distinct.
 */
export const MASTER_DISABLE_AUTHORIZATION_DOMAIN =
  "sanctuary.federation.guardian-requirement.master-authorization.v1" as const;

/** The canonical body a master key signs to authorize an instant retune. */
export interface MasterDisableAuthorizationBody {
  domain: typeof MASTER_DISABLE_AUTHORIZATION_DOMAIN;
  fortress_id: string;
  disable_nonce: number;
  intent: "disable" | "lower";
  target_m: number | null;
}

/** A master-key-signed authorization to instantly disable/lower/retune. */
export interface MasterDisableAuthorization {
  body: MasterDisableAuthorizationBody;
  /** Base64url Ed25519 signature over the canonical body. */
  signature: string;
}

export function buildMasterDisableAuthorizationBody(params: {
  fortressId: string;
  disableNonce: number;
  intent: "disable" | "lower";
  targetM: number | null;
}): MasterDisableAuthorizationBody {
  return {
    domain: MASTER_DISABLE_AUTHORIZATION_DOMAIN,
    fortress_id: params.fortressId,
    disable_nonce: params.disableNonce,
    intent: params.intent,
    target_m: params.targetM,
  };
}

/** Sign a master-key disable/lower/toggle authorization. */
export function signMasterDisableAuthorization(params: {
  fortressId: string;
  disableNonce: number;
  intent: "disable" | "lower";
  targetM: number | null;
  masterPrivateKey: Uint8Array;
}): MasterDisableAuthorization {
  const body = buildMasterDisableAuthorizationBody(params);
  const signedBytes = canonicalizeToBytes(body);
  const sig = ed25519.sign(signedBytes, params.masterPrivateKey);
  return { body, signature: toBase64url(sig) };
}

export type MasterDisableAuthorizationDecision =
  | { allowed: true }
  | { allowed: false; reason: string };

/**
 * Verify a master-key disable/lower/toggle authorization, fail-closed. Checks,
 * in order: domain tag, fortress id match, nonce match (anti-replay - a
 * signature for a burned nonce is refused), intent + targetM match (an
 * authorization signed for "lower to m=2" cannot be replayed as "disable"),
 * and the Ed25519 signature itself against the PINNED fortress-master public
 * key. Any failure is a deny; never throws "allow" on ambiguity.
 */
export function verifyMasterDisableAuthorization(params: {
  authorization: unknown;
  fortressId: string;
  disableNonce: number;
  intent: "disable" | "lower";
  targetM: number | null;
  pinnedMaster: FortressMasterPublicKey;
}): MasterDisableAuthorizationDecision {
  const auth = params.authorization;
  if (auth === null || auth === undefined || typeof auth !== "object") {
    return { allowed: false, reason: "master_authorization_required" };
  }
  const candidate = auth as Partial<MasterDisableAuthorization>;
  const body = candidate.body;
  const signature = candidate.signature;
  if (
    body === undefined ||
    typeof body !== "object" ||
    typeof signature !== "string" ||
    signature.length === 0
  ) {
    return { allowed: false, reason: "master_authorization_malformed" };
  }
  if (body.domain !== MASTER_DISABLE_AUTHORIZATION_DOMAIN) {
    return { allowed: false, reason: "master_authorization_wrong_domain" };
  }
  if (body.fortress_id !== params.fortressId) {
    return { allowed: false, reason: "master_authorization_wrong_fortress" };
  }
  if (body.disable_nonce !== params.disableNonce) {
    return { allowed: false, reason: "master_authorization_stale_nonce" };
  }
  if (body.intent !== params.intent || (body.target_m ?? null) !== params.targetM) {
    return { allowed: false, reason: "master_authorization_wrong_target" };
  }
  try {
    const signedBytes = canonicalizeToBytes(
      buildMasterDisableAuthorizationBody({
        fortressId: body.fortress_id,
        disableNonce: body.disable_nonce,
        intent: body.intent,
        targetM: body.target_m ?? null,
      }),
    );
    const ok = ed25519.verify(
      fromBase64url(signature),
      signedBytes,
      fromBase64url(params.pinnedMaster.public_key),
    );
    if (!ok) {
      return { allowed: false, reason: "master_authorization_signature_invalid" };
    }
    return { allowed: true };
  } catch {
    return { allowed: false, reason: "master_authorization_signature_invalid" };
  }
}

/**
 * The authorization a caller supplies to `setFederationGuardianRevocationRequirement`
 * for a DECREASING transition (disable, or lower M). Exactly one of the two
 * paths is evaluated (master-key checked first since it is the top authority);
 * supplying neither, or an authorization that fails verification, is a deny.
 */
export interface GuardianDisableAuthorization {
  /** M-of-N guardian quorum approvals for the instant quorum path. */
  quorumApprovals?: unknown;
  /** A master-key-signed instant authorization (top authority, no delay). */
  masterAuthorization?: MasterDisableAuthorization;
}

// ── Break-glass state machine (pure helpers; dashboard owns the timer/store) ─

export interface BreakGlassState {
  nonce: number;
  intent: "disable" | "lower";
  targetM: number | null;
  initiatedAt: string;
  completesAt: string;
  /** The delay actually used for this countdown (ms), for posture display. */
  delayMs: number;
}

/**
 * Compute the completion timestamp for a break-glass countdown initiated now,
 * given a delay in ms. Clamped to the hard floor {@link
 * MIN_BREAK_GLASS_DELAY_MS} so a caller cannot construct a sub-24h countdown
 * even if a config value were to slip through unvalidated upstream (defense in
 * depth; the primary validation lives at the operator-config boundary).
 */
export function computeBreakGlassCompletion(
  initiatedAtMs: number,
  delayMs: number = DEFAULT_BREAK_GLASS_DELAY_MS,
): { initiatedAt: string; completesAt: string; delayMs: number } {
  const clampedDelay = Math.max(delayMs, MIN_BREAK_GLASS_DELAY_MS);
  return {
    initiatedAt: new Date(initiatedAtMs).toISOString(),
    completesAt: new Date(initiatedAtMs + clampedDelay).toISOString(),
    delayMs: clampedDelay,
  };
}

/**
 * Has an armed break-glass countdown durably elapsed? Pure comparison against
 * the persisted `completesAt`; the caller (the dashboard's poll tick) is
 * responsible for re-checking the F3 sync-state latch before acting on `true`
 * (a latched/unavailable record must NOT auto-complete - see dashboard.ts).
 */
export function breakGlassElapsed(state: BreakGlassState, nowMs: number): boolean {
  return nowMs >= Date.parse(state.completesAt);
}

function classifyDisableGateError(err: unknown): GuardianDisableGateDenyReason {
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
  return "guardian disable-gate verification failed";
}
