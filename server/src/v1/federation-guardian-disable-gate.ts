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
import { verifyGuardianRoster } from "../mesh/guardian/guardian-roster.js";
import type { FortressMasterPublicKey } from "../mesh/types.js";
import {
  buildApprovalSigningInput,
  enforceThreshold,
  type GuardianApproval,
} from "../recovery/index.js";
import {
  effectiveThresholdM,
  LOWERED_THRESHOLD_AUTHORIZATION_DOMAIN,
  type GuardianRevocationRequirement,
  type LoweredThresholdAuthorization,
  type LoweredThresholdAuthorizationBody,
} from "./federation-revocation-guardian-gate.js";

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
 *     a noop for THIS gate's threshold-weakening purposes (no quorum/master-
 *     disable-authorization is demanded) - gating it too would reintroduce a
 *     lockout: an operator who lost a guardian's key could never re-pin a
 *     replacement without the very quorum that is now short a member.
 *     Roster-integrity for EVERY non-null transition (increase, noop, AND
 *     decrease) - including this one - is enforced separately, by the caller
 *     (`setFederationGuardianRevocationRequirement` in `principal-policy/
 *     dashboard.ts`) verifying the new roster's fortress-master signature via
 *     `verifyGuardianRoster` before any install, the same check the boot
 *     rehydrate path runs. That check is what actually makes an equal-M
 *     re-pin safe: an attacker cannot install an unsigned/forged roster
 *     through this "noop" classification, because the caller refuses it
 *     before this classifier's result is ever acted on.
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
 * DOWN, at its CURRENT EFFECTIVE M (`effectiveThresholdM(requirement)`), NOT the
 * issued `roster.m`.
 *
 * FIX 5: the CHOSEN threshold is the current EFFECTIVE M, so that disabling or
 * lowering the guard demands exactly the same quorum strength that currently
 * guards the KILL path (`evaluateGuardianRevocationSignOff` already thresholds
 * on `effectiveThresholdM`). A fortress already lowered to effective M=2 needs 2
 * signatures to weaken it further, not the issued 3 - anything else would demand
 * MORE authority to tear the guard down than the guard itself currently
 * enforces, an internal inconsistency. This aligns the code with the authorizer
 * comment at {@link authorizeGuardianRequirementTransition} ("the quorum is over
 * the CURRENT effective roster") and the §4 invariant table ("M-of-N quorum over
 * CURRENT effective roster"). Pure decision, no I/O.
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
      // FIX 5: threshold on the current EFFECTIVE M (bounded to roster.m by
      // enforceThreshold), matching the kill-path threshold and the authorizer.
      effective_m: effectiveThresholdM(requirement),
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

// ── Reboot-survivable lowered-M authorization (F1 chokepoint slice) ──────────
//
// The lowered-threshold DATA TYPES + `effectiveThresholdM` live in
// `federation-revocation-guardian-gate.ts` (co-located with the
// `GuardianRevocationRequirement` they describe) so that module never needs to
// import from THIS one - which keeps the two modules a single directed edge
// (disable-gate -> revocation-gate), not an import cycle. This module keeps the
// CRYPTO helpers (build / sign / verify) since they are disable-gate concerns
// (they mirror `MASTER_DISABLE_AUTHORIZATION_DOMAIN`'s sign/verify next door).

export function buildLoweredThresholdAuthorizationBody(params: {
  fortressId: string;
  rosterVersion: number;
  effectiveM: number;
  disableNonce: number;
}): LoweredThresholdAuthorizationBody {
  return {
    domain: LOWERED_THRESHOLD_AUTHORIZATION_DOMAIN,
    fortress_id: params.fortressId,
    roster_version: params.rosterVersion,
    effective_m: params.effectiveM,
    disable_nonce: params.disableNonce,
  };
}

/** Sign a lowered-effective-threshold authorization with the fortress master key. */
export function signLoweredThresholdAuthorization(params: {
  fortressId: string;
  rosterVersion: number;
  effectiveM: number;
  disableNonce: number;
  masterPrivateKey: Uint8Array;
}): LoweredThresholdAuthorization {
  const body = buildLoweredThresholdAuthorizationBody(params);
  const signedBytes = canonicalizeToBytes(body);
  const sig = ed25519.sign(signedBytes, params.masterPrivateKey);
  return { body, signature: toBase64url(sig) };
}

export type LoweredThresholdAuthorizationDecision =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Verify a lowered-threshold authorization, FAIL-CLOSED, mirroring
 * {@link verifyMasterDisableAuthorization}. Checks, in order: domain tag,
 * fortress id, roster version binding, `1 <= effective_m <= rosterM` (a lowering
 * never exceeds the issued ceiling), and the Ed25519 signature over the
 * canonical body against the PINNED fortress-master public key. Any failure is
 * a deny; never returns valid on ambiguity. A lowered record that does not
 * verify is exactly the tamper case and must latch invalid on reboot.
 */
export function verifyLoweredThresholdAuthorization(params: {
  authorization: unknown;
  fortressId: string;
  rosterVersion: number;
  rosterM: number;
  pinnedMaster: FortressMasterPublicKey;
}): LoweredThresholdAuthorizationDecision {
  const auth = params.authorization;
  if (auth === null || auth === undefined || typeof auth !== "object") {
    return { valid: false, reason: "lowered_threshold_required" };
  }
  const candidate = auth as Partial<LoweredThresholdAuthorization>;
  const body = candidate.body;
  const signature = candidate.signature;
  if (
    body === undefined ||
    typeof body !== "object" ||
    typeof signature !== "string" ||
    signature.length === 0
  ) {
    return { valid: false, reason: "lowered_threshold_malformed" };
  }
  if (body.domain !== LOWERED_THRESHOLD_AUTHORIZATION_DOMAIN) {
    return { valid: false, reason: "lowered_threshold_wrong_domain" };
  }
  if (body.fortress_id !== params.fortressId) {
    return { valid: false, reason: "lowered_threshold_wrong_fortress" };
  }
  if (body.roster_version !== params.rosterVersion) {
    return { valid: false, reason: "lowered_threshold_stale_roster_version" };
  }
  if (
    typeof body.effective_m !== "number" ||
    !Number.isSafeInteger(body.effective_m) ||
    body.effective_m < 1 ||
    body.effective_m > params.rosterM
  ) {
    return { valid: false, reason: "lowered_threshold_out_of_range" };
  }
  if (
    typeof body.disable_nonce !== "number" ||
    !Number.isSafeInteger(body.disable_nonce) ||
    body.disable_nonce < 0
  ) {
    return { valid: false, reason: "lowered_threshold_bad_nonce" };
  }
  try {
    const signedBytes = canonicalizeToBytes(
      buildLoweredThresholdAuthorizationBody({
        fortressId: body.fortress_id,
        rosterVersion: body.roster_version,
        effectiveM: body.effective_m,
        disableNonce: body.disable_nonce,
      }),
    );
    const ok = ed25519.verify(
      fromBase64url(signature),
      signedBytes,
      fromBase64url(params.pinnedMaster.public_key),
    );
    if (!ok) {
      return { valid: false, reason: "lowered_threshold_signature_invalid" };
    }
    return { valid: true };
  } catch {
    return { valid: false, reason: "lowered_threshold_signature_invalid" };
  }
}

// ── The single chokepoint: transition -> authorized effect ──────────────────

/**
 * The read-only view of the live guardian-requirement state the pure authorizer
 * decides against. The dashboard snapshots these fields (no writes) before
 * calling {@link authorizeGuardianRequirementTransition}, then applies the
 * returned effect atomically. Crucially the authorizer sees the LATCH, so a
 * `set(null)` against a latched-invalid fortress classifies as a real decrease
 * (fail-open #1) rather than a benign noop keyed only off the nulled live req.
 */
export interface GuardianRequirementState {
  /** The live requirement, or null when none is configured. */
  requirement: GuardianRevocationRequirement | null;
  /** The fail-closed latch: true when a persisted roster failed to re-verify. */
  latchInvalid: boolean;
  /** The pinned fortress-master public key, or null when unprovisioned. */
  pinnedMaster: FortressMasterPublicKey | null;
  /** The fortress id, or null when unprovisioned. */
  fortressId: string | null;
  /** True when the durable sync-state record is unavailable/unverified. */
  syncStateUnavailable: boolean;
  /** The nonce a NEW authorization must target (current disable nonce + 1). */
  nextDisableNonce: number;
  /**
   * Finding #5: the dedicated superseded-lowering high-water. Every non-null
   * install that carries a lowered-threshold record must refuse a record whose
   * `disable_nonce` is at-or-below this floor (a replayed, already-dropped
   * lowering), enforcing at RUNTIME the exact `disable_nonce <= loweredHighWater`
   * rule the boot rehydrate already enforces. Closes the runtime/boot asymmetry
   * where a stale-but-signature-valid lowered record could be installed at
   * runtime and only fail on the next reboot.
   */
  guardianLoweredHighWater: number;
}

/** Every distinct way the guardian requirement / latch may transition. */
export type GuardianRequirementTransition =
  /** Operator sets the requirement to a new value (or null). Latch-aware. */
  | {
      kind: "operator_set";
      next: GuardianRevocationRequirement | null;
      /** Present only for a decrease (disable / lower); absent for increase / noop. */
      auth?: GuardianDisableAuthorization | null;
      /**
       * A master-signed lowered-threshold record for the `next` requirement,
       * required when the effective M strictly decreases via the master path.
       */
      loweredThreshold?: LoweredThresholdAuthorization | null;
    }
  /** Break-glass countdown completed (disable-only; lower is refused at initiate). */
  | { kind: "break_glass_complete"; intent: "disable"; targetM: number | null };

/**
 * The exact post-state the chokepoint applies atomically. `requirement === null`
 * and `clearsLatch === true` is unrepresentable by construction on the operator
 * path (INV-A): a null-install never clears the latch except the one carve-out,
 * a MASTER-signed disable (OR-3), which sets `masterAuthorizedNull`.
 */
export interface GuardianRequirementEffect {
  requirement: GuardianRevocationRequirement | null;
  /** Clear the fail-closed latch. Only ever true when installing a verified roster. */
  clearsLatch: boolean;
  /**
   * OR-3 carve-out: a MASTER-signed disable of a latched-invalid fortress
   * positively authorizes the absence of a guard, so it clears the latch even
   * though it installs null. Operator/quorum/break-glass disable leave it as-is.
   */
  masterAuthorizedNull: boolean;
  /** The auth method that carried a decrease, for the audit trail. */
  authMethod: "operator" | "quorum" | "master" | "break_glass" | null;
  /** The nonce burned by this transition (a decrease/completion), else null. */
  burnedNonce: number | null;
  /**
   * FIX 1 (A3 replay, reboot leg): the disable_nonce of a lowered-threshold
   * record this transition SUPERSEDES (a raise/re-pin that drops a prior
   * lowering), else null. The chokepoint folds it into a DEDICATED lowered-
   * record high-water (`_federationGuardianLoweredHighWater`), distinct from the
   * general disable nonce, that ONLY advances when a lowering is actually
   * dropped. Rehydrate then REJECTS a persisted lowered record whose nonce is
   * below that high-water. It must NOT key off the general disable nonce, which
   * also advances on a break-glass INITIATE that leaves a present lowered record
   * intact (a legitimately-lowered fortress mid-countdown would be falsely
   * rejected by a bare `nonce < disableNonce`).
   */
  supersedesLoweredNonce: number | null;
  /** Classification for the audit trail. */
  classification: "increase" | "decrease" | "noop";
}

export type GuardianRequirementCommit =
  | { ok: true; effect: GuardianRequirementEffect }
  | { ok: false; reason: GuardianRequirementRefusalReason; detail: string };

export type GuardianRequirementRefusalReason =
  | "federation_not_provisioned"
  | "federation_sync_state_unavailable"
  | "guardian_disable_authorization_required"
  | "guardian_roster_signature_invalid"
  | "lowered_threshold_invalid"
  | "no_requirement_configured";

/**
 * The single PURE authorizer for every guardian-requirement / latch transition.
 * Decides authorization + validates the roster/lowered record BEFORE any state
 * write and returns the exact effect the caller applies atomically. FAIL-CLOSED:
 * any missing auth, verification failure, or ambiguity is `{ ok: false }`.
 *
 * This encodes the §4 invariant table. Two structural invariants it guarantees:
 *   - INV-A: the latch clears ONLY by installing a positively-verified roster,
 *     NEVER by removing the requirement - EXCEPT a master-signed disable (OR-3),
 *     which positively authorizes the absence. An operator `set(null)` never
 *     clears the latch (fail-open #1 closed).
 *   - INV-B: no signed-body field is mutated; a lowering rides in a sibling
 *     master-signed record, never by rewriting `roster.m`.
 */
export function authorizeGuardianRequirementTransition(
  state: GuardianRequirementState,
  t: GuardianRequirementTransition,
): GuardianRequirementCommit {
  if (t.kind === "break_glass_complete") {
    // Completion is authorized by the elapsed, unvetoed countdown. It is
    // disable-only (lower is refused at initiate - OR-1), so it installs null
    // and, being NON-master, leaves the latch as-is (the caller only completes
    // when the latch is clear anyway; belt-and-suspenders here).
    //
    // Finding #4: completion DROPS any present lowered record (it disables the
    // whole requirement), so it MUST advance the dedicated lowered high-water
    // past that record's nonce, exactly like the raise/re-pin and decrease
    // supersede paths do. The pre-fix branch returned supersedesLoweredNonce:
    // null, so an attacker could lower to M', arm+complete break-glass, re-enable
    // a guard, then inject the old still-signed lowered-M' record and have it
    // accepted on reboot (its nonce was never folded into the high-water). Read
    // the dropped lowered nonce directly from the live state (the completion
    // branch runs BEFORE next/live are derived below).
    const supersededLoweredNonce =
      state.requirement?.loweredThreshold?.body.disable_nonce ?? null;
    return {
      ok: true,
      effect: {
        requirement: null,
        clearsLatch: false,
        masterAuthorizedNull: false,
        authMethod: "break_glass",
        burnedNonce: null,
        supersedesLoweredNonce: supersededLoweredNonce,
        classification: "decrease",
      },
    };
  }

  const next = t.next;
  const live = state.requirement;
  // A latched-invalid fortress is "a guard IS configured but unverifiable": for
  // classification it counts as a non-null current requirement (this is the
  // #1 fix - a `set(null)` against it is a decrease, not a noop).
  const guardConfigured = live !== null || state.latchInvalid;

  // Effective-M comparison uses the effective threshold on both sides so a
  // lowered record participates correctly.
  const currentEffectiveM =
    live !== null ? effectiveThresholdM(live) : null;
  const nextEffectiveM = next !== null ? effectiveThresholdM(next) : null;

  let classification: "increase" | "decrease" | "noop";
  if (!guardConfigured && next === null) {
    classification = "noop"; // genuinely nothing configured
  } else if (!guardConfigured && next !== null) {
    classification = "increase"; // enable
  } else if (guardConfigured && next === null) {
    classification = "decrease"; // disable (incl. set(null) on a latched fortress)
  } else if (currentEffectiveM === null) {
    // Recovery from latched-invalid (live req nulled by rehydrate) by installing
    // a verified roster is an increase (it positively re-asserts a guard).
    classification = "increase";
  } else {
    // both effective-M defined
    const nm = nextEffectiveM as number;
    if (nm < currentEffectiveM) classification = "decrease";
    else if (nm > currentEffectiveM) classification = "increase";
    else classification = "noop";
  }

  // A decrease demands the durable record be trustworthy (same latch/unavailable
  // guard the pre-chokepoint decrease branch enforced) BEFORE any auth check, so
  // we never tear down a guard whose state we could not trust on boot. The one
  // exception is the master path: a master-signed disable of a latched-invalid
  // fortress is the OR-3 carve-out and is allowed to run (it positively clears
  // the latch). We special-case that below after the auth decision.
  if (classification === "decrease") {
    const intent: "disable" | "lower" = next === null ? "disable" : "lower";
    const targetM = next === null ? null : effectiveThresholdM(next);
    const auth = t.auth ?? null;

    // Decide the auth method first (master checked first: top authority).
    let authMethod: "quorum" | "master" | null = null;
    let detail = "guardian_disable_authorization_required";
    const pinnedMaster = state.pinnedMaster;
    const fortressId = state.fortressId;

    if (auth?.masterAuthorization !== undefined && auth.masterAuthorization !== null) {
      if (pinnedMaster === null || fortressId === null) {
        detail = "federation_not_provisioned";
      } else {
        const decision = verifyMasterDisableAuthorization({
          authorization: auth.masterAuthorization,
          fortressId,
          disableNonce: state.nextDisableNonce,
          intent,
          targetM,
          pinnedMaster,
        });
        if (decision.allowed) authMethod = "master";
        else detail = decision.reason;
      }
    } else if (
      auth?.quorumApprovals !== undefined &&
      auth.quorumApprovals !== null &&
      live !== null
    ) {
      // The quorum is over the CURRENT effective roster: lowering to a smaller M'
      // still needs the current effective M's worth of signatures. This path is
      // only reachable when a LIVE roster exists (`live !== null`): a
      // latched-invalid fortress has `live === null` (rehydrate nulled it), so a
      // quorum has no live roster to verify against - it falls through to the
      // no-auth refusal below, then the latch guard. Only a MASTER key (OR-3) can
      // decrease a latched fortress.
      const decision = evaluateGuardianDisableSignOff({
        requirement: live,
        fortressId: live.roster.fortress_id,
        disableNonce: state.nextDisableNonce,
        intent,
        targetM,
        approvals: auth.quorumApprovals,
      });
      if (decision.allowed) authMethod = "quorum";
      else detail = decision.detail;
    }

    if (authMethod === null) {
      return {
        ok: false,
        reason: "guardian_disable_authorization_required",
        detail,
      };
    }

    // The sync-state guard: a decrease of EITHER auth method must refuse while
    // the durable record itself is unavailable (corrupt/deleted) - we cannot
    // durably commit against a record the store will throw on, and a master
    // authorization does not repair a corrupt blob. This applies to master too.
    if (state.syncStateUnavailable) {
      return {
        ok: false,
        reason: "federation_sync_state_unavailable",
        detail:
          "the durable federation sync-state is unavailable; refusing to disable/lower the guardian requirement until the operator recovers the record",
      };
    }
    // The LATCH guard (roster failed to re-verify on boot): a NON-master decrease
    // must refuse while latched. A MASTER decrease is the OR-3 carve-out: the
    // trust root positively authorizes the transition and, on a disable, clears
    // the latch. This lets the fortress owner re-assert authoritatively while
    // still refusing a stolen-operator-key quorum against a latched fortress.
    if (authMethod !== "master" && state.latchInvalid) {
      return {
        ok: false,
        reason: "federation_sync_state_unavailable",
        detail:
          "the durable guardian requirement is unverified (latched invalid); refusing to disable/lower via quorum until the operator re-pins a valid roster, or the master key authorizes it directly",
      };
    }

    // A LOWER (next !== null on the decrease branch) must always verify its
    // roster. There are two shapes of a legitimate lower:
    //   (i)  the installed roster's OWN issued `m` IS the lower threshold (a
    //        genuinely NEW master-signed roster re-issued at a lower m). Its own
    //        signature covers the lower m, so it survives reboot with no sibling
    //        record - no lowered-threshold record is needed or expected.
    //   (ii) the effective M is pushed BELOW the installed roster's issued m
    //        WITHOUT re-issuing the roster. That MUST ride in a master-signed
    //        lowered-threshold record (INV-B: never mutate `roster.m`), bound to
    //        this transition's nonce + target, else the lowering could not
    //        survive reboot (fail-open #2).
    // The discriminator is `loweredThreshold` presence: absent -> shape (i);
    // present -> shape (ii). A DISABLE (next === null) never carries one.
    let installedNext: GuardianRevocationRequirement | null = next;
    if (next !== null) {
      const rosterCheck = verifyNextRoster(next, pinnedMaster);
      if (!rosterCheck.ok) return rosterCheck;
      const lowered = t.loweredThreshold ?? next.loweredThreshold ?? null;
      if (lowered !== null) {
        const loweredCheck = requireLoweredThresholdForNext(next, lowered, state);
        if (!loweredCheck.ok) return loweredCheck;
        // Bind the lowered record to THIS transition: effective_m == target and
        // nonce == the nonce being burned (anti-replay / anti-outliving).
        if (lowered.body.effective_m !== targetM) {
          return {
            ok: false,
            reason: "lowered_threshold_invalid",
            detail:
              "lowered-threshold effective_m does not match the transition target",
          };
        }
        if (lowered.body.disable_nonce !== state.nextDisableNonce) {
          return {
            ok: false,
            reason: "lowered_threshold_invalid",
            detail:
              "lowered-threshold disable_nonce does not match the transition nonce",
          };
        }
        installedNext = { ...next, loweredThreshold: lowered };
      }
    }

    // OR-3: a MASTER disable of a latched-invalid fortress clears the latch;
    // every other disable leaves it as-is (moot once requirement is null).
    const masterAuthorizedNull =
      next === null && authMethod === "master";
    // FIX 1: a decrease that REPLACES a prior lowered record (a disable that
    // drops one, or a lower whose new record carries a DIFFERENT nonce)
    // supersedes it - fold the prior record's nonce into the lowered high-water
    // so it can never be replayed on reboot. (A lower whose new record reuses
    // the same nonce cannot happen: the new record binds the fresh nonce being
    // burned, so any prior lowered record's nonce is strictly older.)
    const priorLoweredNonce = live?.loweredThreshold?.body.disable_nonce ?? null;
    const nextInstalledLoweredNonce =
      installedNext?.loweredThreshold?.body.disable_nonce ?? null;
    const decreaseSupersedesLoweredNonce =
      priorLoweredNonce !== null && priorLoweredNonce !== nextInstalledLoweredNonce
        ? priorLoweredNonce
        : null;
    return {
      ok: true,
      effect: {
        requirement: installedNext,
        // INV-A: installing a positively-verified roster clears the latch. A
        // decrease that installs a non-null requirement (a master-LOWER, the
        // only decrease that reaches here with a latched fortress since a quorum
        // has no live roster to verify against) installs a verified roster, so
        // it clears the latch. A disable (next === null) never clears via this
        // flag - the master-disable carve-out uses masterAuthorizedNull instead.
        clearsLatch: next !== null && state.latchInvalid,
        masterAuthorizedNull,
        authMethod,
        burnedNonce: state.nextDisableNonce,
        supersedesLoweredNonce: decreaseSupersedesLoweredNonce,
        classification,
      },
    };
  }

  // increase / noop: operator-only. A non-null install MUST verify its roster
  // (and its lowered record, if any) against the pinned master. The latch clears
  // ONLY by installing such a positively-verified roster (INV-A).
  if (next !== null) {
    const rosterCheck = verifyNextRoster(next, state.pinnedMaster);
    if (!rosterCheck.ok) return rosterCheck;
    const loweredCheck = requireLoweredThresholdForNext(
      next,
      next.loweredThreshold ?? null,
      state,
    );
    if (!loweredCheck.ok) return loweredCheck;
    // Anti-replay of a superseded lowered record (A3): if the PRIOR live
    // requirement carried a lowered record that the NEXT state does NOT carry
    // (a raise/re-pin that drops the lowering), advance the disable-nonce floor
    // PAST that dropped record's nonce. Otherwise a same-roster raise would
    // leave the floor at the dropped record's nonce, letting an attacker who can
    // re-encrypt the blob re-inject the stale lowered record at nonce == floor.
    // Burning here pushes the floor strictly above it so the replay is stale.
    const priorLoweredNonce = live?.loweredThreshold?.body.disable_nonce ?? null;
    const nextLoweredNonce = next.loweredThreshold?.body.disable_nonce ?? null;
    const supersedesLowered =
      priorLoweredNonce !== null && priorLoweredNonce !== nextLoweredNonce;
    return {
      ok: true,
      effect: {
        requirement: next,
        // Installing a verified roster is the ONLY way to clear the latch.
        clearsLatch: state.latchInvalid,
        masterAuthorizedNull: false,
        authMethod: "operator",
        burnedNonce: supersedesLowered ? state.nextDisableNonce : null,
        // FIX 1: fold the DROPPED lowered record's nonce into the dedicated
        // lowered high-water so a reboot rejects a re-injection of it.
        supersedesLoweredNonce: supersedesLowered ? priorLoweredNonce : null,
        classification,
      },
    };
  }

  // next === null && !guardConfigured -> genuine noop; nothing configured, no
  // latch to clear (there is none by definition when !guardConfigured).
  return {
    ok: true,
    effect: {
      requirement: null,
      clearsLatch: false,
      masterAuthorizedNull: false,
      authMethod: null,
      burnedNonce: null,
      supersedesLoweredNonce: null,
      classification: "noop",
    },
  };
}

/**
 * Verify the roster of a non-null install against the pinned master, fail-closed
 * (mirrors the boot rehydrate check). No pinned master -> refuse the whole call.
 */
function verifyNextRoster(
  next: GuardianRevocationRequirement,
  pinnedMaster: FortressMasterPublicKey | null,
):
  | { ok: true }
  | { ok: false; reason: GuardianRequirementRefusalReason; detail: string } {
  if (pinnedMaster === null) {
    return {
      ok: false,
      reason: "federation_not_provisioned",
      detail:
        "no pinned fortress-master public key is available to verify the supplied guardian roster; refusing to install it",
    };
  }
  try {
    verifyGuardianRoster(next.roster, pinnedMaster);
    return { ok: true };
  } catch {
    return {
      ok: false,
      reason: "guardian_roster_signature_invalid",
      detail:
        "the supplied guardian roster does not verify against the pinned fortress-master public key; refusing to install it",
    };
  }
}

/**
 * When a non-null requirement carries a lowered-threshold record, verify it
 * against the pinned master (domain, fortress, roster-version binding, range,
 * signature). A requirement WITHOUT a lowered record is fine (effective M =
 * roster.m). FAIL-CLOSED: a present-but-invalid lowered record refuses the
 * install.
 */
function requireLoweredThresholdForNext(
  next: GuardianRevocationRequirement,
  lowered: LoweredThresholdAuthorization | null,
  state: GuardianRequirementState,
):
  | { ok: true }
  | { ok: false; reason: GuardianRequirementRefusalReason; detail: string } {
  if (lowered === null) return { ok: true };
  if (state.pinnedMaster === null || state.fortressId === null) {
    return {
      ok: false,
      reason: "federation_not_provisioned",
      detail:
        "no pinned fortress-master public key is available to verify the supplied lowered-threshold record",
    };
  }
  const decision = verifyLoweredThresholdAuthorization({
    authorization: lowered,
    fortressId: state.fortressId,
    rosterVersion: next.roster.version,
    rosterM: next.roster.m,
    pinnedMaster: state.pinnedMaster,
  });
  if (!decision.valid) {
    return {
      ok: false,
      reason: "lowered_threshold_invalid",
      detail: decision.reason,
    };
  }
  // Finding #5: even a SIGNATURE-VALID lowered record must be refused at RUNTIME
  // when its nonce is at-or-below the superseded-lowering high-water (a replayed,
  // already-dropped lowering). The boot rehydrate already enforces this; without
  // it here, a stale lowered record whose signature still verifies could be
  // installed via a runtime re-pin and only fail on the NEXT reboot (or not at
  // all, if the floor were meanwhile rolled back per finding #1). `<=` matches
  // the rehydrate semantics (the high-water is the EXACT nonce of a dropped
  // record), so every runtime path now enforces the identical floor as boot.
  if (lowered.body.disable_nonce <= state.guardianLoweredHighWater) {
    return {
      ok: false,
      reason: "lowered_threshold_invalid",
      detail:
        "lowered-threshold disable_nonce is at or below the superseded-lowering high-water (a replayed, already-dropped lowering)",
    };
  }
  return { ok: true };
}
