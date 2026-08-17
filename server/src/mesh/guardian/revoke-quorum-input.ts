/**
 * C12-REPLAY — v2 guardian quorum-input freshness.
 *
 * This module is the SINGLE source of truth for the canonical bytes a guardian
 * quorum signs, plus the relying-side freshness enforcement (AGENTS.md rule 10)
 * and the element-level parser (rules 5/11). Despite the file name it is NOT
 * revoke-only: the collection context and the freshness assertion are
 * input-agnostic by construction, and three ceremonies now share them — node
 * revoke (C12-REPLAY), device-recovery intent (QI-SIBLING-01), and master
 * rotation (QI-SIBLING-02). The `Revoke`-flavored names below are kept
 * deliberately: renaming them would churn every call site and both T9 structure
 * pins without changing a single byte of behavior, and the pins are what keep
 * the second implementation from appearing.
 *
 * Why it lives under `mesh/guardian/`: `lifecycle/mesh-node.ts` and
 * `recovery-flows/*` both already import `verifyGuardianQuorum` from here, so
 * this module sits BELOW the import cycle (`recovery-flows` -> `lifecycle`)
 * that previously forced a hand-mirrored verifier copy. One builder, one
 * parser, one freshness assertion — no mirror to drift (rule 5).
 *
 * Design of record: Review/Sanctuary/C12_REPLAY_Quorum_Freshness_Design_2026-08-16.md.
 *
 * The v1 shape (a `MasterRotationQuorumInput` overload with the target id
 * stuffed into the timestamp slots) carried NO freshness: a harvested quorum
 * authorized revoking a target forever. This v2 shape binds an
 * `initiated_at`/`expires_at` window into the SIGNED bytes so a relying party
 * can refuse a stale bearer capability. The signer cannot select its own trust
 * duration: the generating side clamps the lifetime it will sign, and every
 * relying site independently enforces the cap with its own clock.
 */

import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "../../core/random.js";
import { GuardianQuorumError } from "./errors.js";
// Type-only import: `mesh/types.ts` carries no runtime code, so this adds no
// module edge that could reintroduce the recovery-flows -> lifecycle cycle this
// module was placed below.
import type { FortressMasterPublicKey } from "../types.js";

// ═══════════════════════════════════════════════════════════════════════
// Schema literals (frozen wire/at-rest contract — reorg-surface-manifest.md)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Domain separator for the v2 revoke quorum input. It rides inside the signed
 * bytes AND is echoed on the wire in `NodeRevokePayload.quorum_context`; a
 * verifier compares it as an EXACT literal, never a prefix. Frozen once shipped
 * (design §8 Q5); a byte change silently breaks verification of every existing
 * v2 revoke.
 *
 * Must match the `input_schema` literal in `parseGuardianRevokeQuorumContext`
 * and the `quorum_context.input_schema` type in `mesh/types.ts`.
 */
export const GUARDIAN_REVOKE_QUORUM_SCHEMA_V2 =
  "sanctuary.guardian-revoke-quorum.v2" as const;

/**
 * Domain separator for the v2 device-recovery INTENT quorum input
 * (QI-SIBLING-01, rides this build). Distinct from the revoke schema so a
 * recovery-intent quorum can never be spliced into a revoke and vice versa.
 * Never rides the wire — verified only at `DeviceRecoveryCeremony.propose`.
 */
export const GUARDIAN_DEVICE_RECOVERY_QUORUM_SCHEMA_V2 =
  "sanctuary.guardian-device-recovery-quorum.v2" as const;

/**
 * Domain separator for the v2 MASTER-ROTATION quorum input (QI-SIBLING-02).
 * Distinct from the revoke and device-recovery separators so a quorum collected
 * for one ceremony can never be spliced into another. It rides inside the signed
 * bytes AND is echoed on the wire in `MasterRotationPayload.quorum_context`; a
 * verifier compares it as an EXACT literal, never a prefix. Frozen once shipped;
 * a byte change silently breaks verification of every existing v2 rotation.
 *
 * Must match the `input_schema` literal accepted by
 * `parseMasterRotationQuorumContext` and the
 * `MasterRotationPayload.quorum_context.input_schema` type in `mesh/types.ts`.
 */
export const GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2 =
  "sanctuary.guardian-master-rotation-quorum.v2" as const;

// ═══════════════════════════════════════════════════════════════════════
// Freshness constants (rule 10 — relying party constrains signer freshness)
// ═══════════════════════════════════════════════════════════════════════

const MS_PER_SECOND = 1_000;
const SECONDS_PER_MINUTE = 60;
const MINUTES_PER_HOUR = 60;
/** 3_600_000 = 60 min * 60 s * 1000 ms. */
const MS_PER_HOUR = MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND;
/** 300_000 = 5 min * 60 s * 1000 ms. */
const MS_PER_FIVE_MINUTES = 5 * SECONDS_PER_MINUTE * MS_PER_SECOND;

/**
 * Hard cap on a signed revoke quorum's lifetime. Guardians are humans on
 * separate devices; collection latency is hours, not seconds, so 24h bounds the
 * abandoned-ceremony exposure to one day instead of the forever the v1 shape
 * allowed. 86_400_000 = 24 h. Enforced by EVERY relying site, not only the
 * generator, because an attacker crafting a payload IS the generator (rule 10).
 *
 * QI-SIBLING-02 reuses this cap for master rotation rather than minting a second
 * constant, because the latency being bounded is identical: the window has to
 * cover collection-opens -> guardians sign -> operator proposes -> operator
 * confirms -> execute's local accept. Everything AFTER local accept (per-peer
 * bundle unicast, broadcast, receiver install, ack collection) runs inside
 * `DEFAULT_BROADCAST_ACK_TIMEOUT_MS` = 10 s, four orders of magnitude inside the
 * cap, so a receiver never races the window a slow ceremony consumed. One
 * constant also means one thing to change if real ceremony timing disagrees.
 */
export const REVOKE_QUORUM_MAX_LIFETIME_MS = 24 * MS_PER_HOUR;

/**
 * Default lifetime the collection context requests when the operator does not
 * widen it (never beyond the cap). 14_400_000 = 4 h.
 */
export const REVOKE_QUORUM_DEFAULT_LIFETIME_MS = 4 * MS_PER_HOUR;

/**
 * Bounded clock-skew allowance for the future-dated / lower-bound checks.
 * Wider than the 60s v1-operator precedent (`v1/operator-signed.ts`) because
 * ceremony devices are ad-hoc hardware, but still small against the lifetime.
 * 300_000 = 5 min. Spent on the `initiated_at`/lower-bound check only; expiry
 * gets no grace, so the effective window is never silently widened on both ends
 * (design §2.2 check 4).
 */
export const REVOKE_QUORUM_CLOCK_SKEW_MS = MS_PER_FIVE_MINUTES;

/** ceremony_id = 128 bits of CSPRNG rendered as 32 lowercase hex chars. */
const CEREMONY_ID_BYTES = 16;
const CEREMONY_ID_HEX_CHARS = CEREMONY_ID_BYTES * 2;
const CEREMONY_ID_HEX_RE = /^[0-9a-f]{32}$/;

// ═══════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════

/**
 * The freshness fields a collection context mints once and every guardian
 * signs. Minted BEFORE any guardian signs (design §2.3) so the signatures bind
 * the ceremony_id — signatures cannot exist before the context that names them.
 *
 * Shared verbatim by all three ceremonies (revoke, device-recovery intent,
 * master rotation); the `Revoke` in the name is history, not scope.
 */
export interface GuardianRevokeQuorumContext {
  /** 32 lowercase hex chars (128-bit CSPRNG). */
  ceremony_id: string;
  /** ISO 8601 UTC — set by the collection context when collection opens. */
  initiated_at: string;
  /** ISO 8601 UTC — initiated_at + requested lifetime, clamped signer-side. */
  expires_at: string;
}

/**
 * The canonical bytes a guardian signs to authorize a node revocation (v2).
 * `schema` is the domain separator. Recomputed by every verifier from the
 * payload's echoed context plus target/reason/fortress, so all three freshness
 * fields must ride the wire in `NodeRevokePayload.quorum_context`.
 */
export interface GuardianRevokeQuorumInput {
  schema: typeof GUARDIAN_REVOKE_QUORUM_SCHEMA_V2;
  fortress_id: string;
  target_node_id: string;
  reason: string;
  ceremony_id: string;
  initiated_at: string;
  expires_at: string;
}

/**
 * The canonical bytes a guardian signs to authorize a device-recovery INTENT
 * (lost -> replacement). Carries the SAME freshness fields as the revoke input
 * (the same collection session signs both), so `assertQuorumContextFresh`
 * applies unchanged (design §7 — the context struct is input-agnostic).
 */
export interface GuardianDeviceRecoveryQuorumInput {
  schema: typeof GUARDIAN_DEVICE_RECOVERY_QUORUM_SCHEMA_V2;
  fortress_id: string;
  lost_node_id: string;
  replacement_node_pubkey: string;
  ceremony_id: string;
  initiated_at: string;
  expires_at: string;
}

/**
 * The canonical bytes a guardian signs to authorize a MASTER ROTATION (v2,
 * QI-SIBLING-02). Carries the SAME freshness fields as the revoke input (one
 * collection context shape for every ceremony), so `assertQuorumContextFresh`
 * applies unchanged.
 *
 * Distinct from the retired-for-this-path `MasterRotationQuorumInput` in
 * `guardian/types.ts`, which has no `schema` and no window and now serves only
 * the canonical-audit-promotion ceremony. The two field sets are disjoint and
 * `canonicalizeToBytes` is field-name-bearing, so their bytes cannot collide.
 */
export interface GuardianMasterRotationQuorumInput {
  schema: typeof GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2;
  fortress_id: string;
  old_master_pubkey: string;
  /**
   * The WHOLE new-master object, not just its `public_key`. The v1 shape signed
   * the object, and narrowing to the bare key would quietly drop `created_at`
   * out of quorum coverage while it still rides the wire and still lands in the
   * receiver's pinned master record.
   */
  new_master_pubkey: FortressMasterPublicKey;
  /**
   * The operator-visible "this rotation took effect at" stamp. Signed so it
   * cannot be edited in flight, but it is NOT the freshness field: the relying
   * side decides freshness from `initiated_at`/`expires_at` and separately
   * constrains `rotated_at` to sit inside that window.
   */
  rotated_at: string;
  ceremony_id: string;
  initiated_at: string;
  expires_at: string;
}

/**
 * The wire echo of the freshness fields, carried on `NodeRevokePayload`. Present
 * iff `quorum_signatures` is (design §2.1 presence pairing). `input_schema` is
 * checked as the EXACT literal.
 */
export interface NodeRevokeQuorumContextWire {
  input_schema: typeof GUARDIAN_REVOKE_QUORUM_SCHEMA_V2;
  ceremony_id: string;
  initiated_at: string;
  expires_at: string;
}

/**
 * The wire echo carried on `MasterRotationPayload`. Same three freshness fields,
 * different domain separator, so a harvested revoke context cannot be presented
 * as a rotation context (and vice versa) even before signature verification.
 *
 * Must match `MasterRotationPayload.quorum_context` in `mesh/types.ts`.
 */
export interface MasterRotationQuorumContextWire {
  input_schema: typeof GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2;
  ceremony_id: string;
  initiated_at: string;
  expires_at: string;
}

/**
 * Result of the element-level parser. The typed `ok:true` branch IS the
 * cross-stage agreement (rule 11): a verifier and a consumer that both funnel
 * through this one function agree by construction, so a malformed shape fails
 * closed HERE, never as a downstream `TypeError`.
 */
export type QuorumContextParseResult =
  | { ok: true; context: ParsedQuorumContext }
  | { ok: false; reason: QuorumContextParseFailure };

/** Named failure classes — a typed reason, never a bare throw or boolean. */
export type QuorumContextParseFailure =
  | "context_absent"
  | "context_not_object"
  | "schema_missing_or_wrong"
  | "ceremony_id_malformed"
  | "initiated_at_not_iso"
  | "expires_at_not_iso"
  | "expires_not_after_initiated";

/**
 * Every domain separator that can legally appear in a wire `quorum_context`.
 * A parse always names ONE expected member; the union exists so the single
 * parser can serve every ceremony without a hand-mirrored copy per ceremony.
 */
export type QuorumContextSchema =
  | typeof GUARDIAN_REVOKE_QUORUM_SCHEMA_V2
  | typeof GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2;

/** A context that passed element-level validation, with parsed ms cached. */
export interface ParsedQuorumContext {
  input_schema: QuorumContextSchema;
  ceremony_id: string;
  initiated_at: string;
  expires_at: string;
  initiated_at_ms: number;
  expires_at_ms: number;
}

/**
 * The freshness channel threaded through the ONE shared assertion (design §3.1,
 * review F-3). NON-DEFAULTABLE and discriminated: omitting it is a type error,
 * and `strict` never silently degrades to `sync_anchored`. Only `applySync`
 * passes `sync_anchored` (pinned by the T9 structure test); every live path
 * passes `strict`.
 */
export type FreshnessMode =
  | { mode: "strict"; now: Date }
  | { mode: "sync_anchored"; now: Date; effective_at: string };

/** Thrown by the freshness assertion. A subclass of the quorum error family so
 *  callers already catching quorum failures catch freshness failures too. */
export class QuorumFreshnessError extends GuardianQuorumError {
  constructor(message: string) {
    super(message);
    this.name = "QuorumFreshnessError";
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Collection-context minting (generating side, §2.2/§2.3)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Mint a fresh collection context on the ceremony device. FAILS CLOSED: the
 * ceremony_id is 128 bits of `core/random` CSPRNG (Node OpenSSL), and there is
 * NO `Math.random` fallback path — the retired v1 `generateCeremonyId` copies
 * degraded silently to a non-CSPRNG, which this build deletes (design §2.1,
 * review F-6). Clamps the requested lifetime to the hard cap so the signer
 * cannot select its own trust duration (rule 10).
 */
export function mintRevokeCollectionContext(params: {
  requested_lifetime_ms?: number;
  now?: Date;
} = {}): GuardianRevokeQuorumContext {
  const now = params.now ?? new Date();
  const requested =
    params.requested_lifetime_ms ?? REVOKE_QUORUM_DEFAULT_LIFETIME_MS;
  // Clamp: a caller asking for a decades-long window gets the cap. A
  // non-positive request is meaningless; floor it at the default rather than
  // minting an already-expired context.
  const lifetime =
    requested > 0
      ? Math.min(requested, REVOKE_QUORUM_MAX_LIFETIME_MS)
      : REVOKE_QUORUM_DEFAULT_LIFETIME_MS;
  const initiatedMs = now.getTime();
  return {
    ceremony_id: mintCeremonyId(),
    initiated_at: new Date(initiatedMs).toISOString(),
    expires_at: new Date(initiatedMs + lifetime).toISOString(),
  };
}

/**
 * The ONE ceremony-id minter under `server/src` (QI-SIBLING-02 fix round). Every
 * ceremony that needs a 128-bit forensic nonce calls this rather than keeping a
 * local copy: the four hand-written copies that existed before all shared the
 * same `Math.random` fallback, and a structure scan (not a hand-listed file set)
 * now pins that no second copy can reappear.
 */
export function mintCeremonyId(): string {
  // randomBytes throws if the platform CSPRNG is unavailable; we never fall
  // back to a weaker source (rule 5: no silent degradation of a security
  // primitive). A predictable ceremony_id would not break the signature
  // binding but would falsify the randomness claim and weaken the forensic hook.
  const bytes = randomBytes(CEREMONY_ID_BYTES);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

// ═══════════════════════════════════════════════════════════════════════
// Builders (ONE source of the canonical bytes — rule 5)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build the v2 revoke quorum input. The ONLY constructor of these bytes; the
 * retired `revokeQuorumInput`/`nodeRevokeQuorumInput` hand-mirror is deleted,
 * and a T9 structure test pins that no other file under `mesh/` builds this
 * shape.
 */
export function buildGuardianRevokeQuorumInput(params: {
  context: GuardianRevokeQuorumContext;
  target_node_id: string;
  reason: string;
  fortress_id: string;
}): GuardianRevokeQuorumInput {
  return {
    schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
    fortress_id: params.fortress_id,
    target_node_id: params.target_node_id,
    reason: params.reason,
    ceremony_id: params.context.ceremony_id,
    initiated_at: params.context.initiated_at,
    expires_at: params.context.expires_at,
  };
}

/** Build the v2 device-recovery INTENT quorum input (QI-SIBLING-01). */
export function buildGuardianDeviceRecoveryQuorumInput(params: {
  context: GuardianRevokeQuorumContext;
  lost_node_id: string;
  replacement_node_pubkey: string;
  fortress_id: string;
}): GuardianDeviceRecoveryQuorumInput {
  return {
    schema: GUARDIAN_DEVICE_RECOVERY_QUORUM_SCHEMA_V2,
    fortress_id: params.fortress_id,
    lost_node_id: params.lost_node_id,
    replacement_node_pubkey: params.replacement_node_pubkey,
    ceremony_id: params.context.ceremony_id,
    initiated_at: params.context.initiated_at,
    expires_at: params.context.expires_at,
  };
}

/**
 * Build the v2 MASTER-ROTATION quorum input (QI-SIBLING-02). The ONLY
 * constructor of these bytes; a T9 structure pin asserts no other file under
 * `server/src` hand-builds the shape.
 */
export function buildGuardianMasterRotationQuorumInput(params: {
  context: GuardianRevokeQuorumContext;
  old_master_pubkey: string;
  new_master_pubkey: FortressMasterPublicKey;
  rotated_at: string;
  fortress_id: string;
}): GuardianMasterRotationQuorumInput {
  return {
    schema: GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
    fortress_id: params.fortress_id,
    old_master_pubkey: params.old_master_pubkey,
    new_master_pubkey: params.new_master_pubkey,
    rotated_at: params.rotated_at,
    ceremony_id: params.context.ceremony_id,
    initiated_at: params.context.initiated_at,
    expires_at: params.context.expires_at,
  };
}

/** Project the wire echo from a full context (producer side). */
export function toWireQuorumContext(
  context: GuardianRevokeQuorumContext
): NodeRevokeQuorumContextWire {
  return {
    input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
    ceremony_id: context.ceremony_id,
    initiated_at: context.initiated_at,
    expires_at: context.expires_at,
  };
}

/** Project the master-rotation wire echo from a full context (producer side). */
export function toWireMasterRotationQuorumContext(
  context: GuardianRevokeQuorumContext
): MasterRotationQuorumContextWire {
  return {
    input_schema: GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
    ceremony_id: context.ceremony_id,
    initiated_at: context.initiated_at,
    expires_at: context.expires_at,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Element-level parser (rules 5/11) — the ONE typed parse result
// ═══════════════════════════════════════════════════════════════════════

/**
 * Validate a wire `quorum_context` FIELD BY FIELD. Never a container-level
 * presence check (the §LD5 EXIT-STRUCT-02 lesson): a `quorum_context: null` or
 * a context missing `expires_at` fails closed HERE with a typed reason, so no
 * downstream dereference ever throws a raw `TypeError`. The typed `ok:true`
 * result is the cross-stage agreement every consumer shares (rule 11).
 */
export function parseGuardianRevokeQuorumContext(
  value: unknown
): QuorumContextParseResult {
  return parseQuorumContextForSchema(value, GUARDIAN_REVOKE_QUORUM_SCHEMA_V2);
}

/**
 * The master-rotation entry point into the SAME parser (QI-SIBLING-02). Separate
 * function, not a separate implementation: the only difference is which domain
 * separator is demanded, and demanding the wrong one is what stops a harvested
 * revoke context from being presented as a rotation context.
 */
export function parseMasterRotationQuorumContext(
  value: unknown
): QuorumContextParseResult {
  return parseQuorumContextForSchema(
    value,
    GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2
  );
}

/**
 * The one element-level parse. Every ceremony's entry point funnels here with
 * its own expected separator, so a new ceremony adds a literal and an entry
 * point, never a second validator that can drift from this one (rule 5).
 */
function parseQuorumContextForSchema(
  value: unknown,
  expectedSchema: QuorumContextSchema
): QuorumContextParseResult {
  if (value === undefined || value === null) {
    return { ok: false, reason: "context_absent" };
  }
  if (typeof value !== "object") {
    return { ok: false, reason: "context_not_object" };
  }
  const raw = value as Record<string, unknown>;

  // EXACT literal — never a prefix / startsWith (design §2.1, review F-10).
  if (raw.input_schema !== expectedSchema) {
    return { ok: false, reason: "schema_missing_or_wrong" };
  }
  const ceremonyId = raw.ceremony_id;
  if (typeof ceremonyId !== "string" || !CEREMONY_ID_HEX_RE.test(ceremonyId)) {
    return { ok: false, reason: "ceremony_id_malformed" };
  }
  const initiatedAt = raw.initiated_at;
  if (typeof initiatedAt !== "string") {
    return { ok: false, reason: "initiated_at_not_iso" };
  }
  const initiatedMs = Date.parse(initiatedAt);
  if (!Number.isFinite(initiatedMs)) {
    return { ok: false, reason: "initiated_at_not_iso" };
  }
  const expiresAt = raw.expires_at;
  if (typeof expiresAt !== "string") {
    return { ok: false, reason: "expires_at_not_iso" };
  }
  const expiresMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiresMs)) {
    return { ok: false, reason: "expires_at_not_iso" };
  }
  if (expiresMs <= initiatedMs) {
    return { ok: false, reason: "expires_not_after_initiated" };
  }
  return {
    ok: true,
    context: {
      input_schema: expectedSchema,
      ceremony_id: ceremonyId,
      initiated_at: initiatedAt,
      expires_at: expiresAt,
      initiated_at_ms: initiatedMs,
      expires_at_ms: expiresMs,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Freshness assertion (relying side, §2.2) — ONE implementation, all sites
// ═══════════════════════════════════════════════════════════════════════

/**
 * Enforce the relying-side freshness bounds with the caller's OWN clock. HARD
 * FAIL (throws), never a warning — the §LD5 SHR-FRESH-01 lesson: a warning here
 * is a bypass.
 *
 * Checks common to both modes:
 *   - lifetime cap: expires_at - initiated_at <= MAX_LIFETIME. This is the line
 *     that makes a decades-long signed window worthless; enforced even though
 *     the generator also clamps, because an attacker crafting a payload IS the
 *     generator (rule 10).
 *
 * strict (every live site): the verifier's own clock decides freshness.
 *   - initiated_at <= now + SKEW  (bounded-skew hard-fail on future-dated input)
 *   - now <= expires_at           (no skew grace on expiry — see §2.2 check 4)
 *   Derivation: these two together imply now - initiated_at <= MAX_LIFETIME,
 *   which IS the rule-10 max-age bound, so no separate max-age constant exists.
 *
 * sync_anchored (applySync ONLY): a COMMITTED revoke must outlive its collection
 * window for a late joiner, so freshness anchors to the emitter-stamped
 * `effective_at` instead of the joiner's clock (design §3.2 option S2). The two
 * timestamps come from two different clocks, so the bounds are directional:
 *   - lower: effective_at >= initiated_at - SKEW  (skew-tolerant; a STRICT lower
 *     bound would permanently refuse a legitimate revoke whose emitter clock
 *     lagged the ceremony device — fail-open trust of a revoked node, the exact
 *     failure S1 was rejected for).
 *   - upper: effective_at <= expires_at            (strict, no grace; the
 *     emitter's own pre-broadcast strict gate already implies this for any
 *     legitimate emission, so grace would only widen the back-dated forgery
 *     window).
 */
export function assertQuorumContextFresh(
  context: ParsedQuorumContext,
  freshness: FreshnessMode
): void {
  // Refusal-diagnosability invariant (QI-SIBLING-02 fix round): the message
  // names the ceremony it is ACTUALLY refusing, derived from the parsed
  // context's own domain separator rather than a hand-written label. Three
  // ceremonies share this assertion, so a hardcoded "revoke quorum context"
  // string told a master-rotation operator the wrong ceremony had failed, which
  // is the opposite of the "tell version skew from clock skew" property the
  // clean break exists to give them. Deriving it means a fourth ceremony's
  // messages are correct the day it adopts this function, with nothing to
  // remember.
  const ceremony = context.input_schema;
  const lifetimeMs = context.expires_at_ms - context.initiated_at_ms;
  if (lifetimeMs > REVOKE_QUORUM_MAX_LIFETIME_MS) {
    throw new QuorumFreshnessError(
      `quorum context (${ceremony}) lifetime ${lifetimeMs}ms exceeds max ${REVOKE_QUORUM_MAX_LIFETIME_MS}ms`
    );
  }

  if (freshness.mode === "strict") {
    const nowMs = freshness.now.getTime();
    if (context.initiated_at_ms > nowMs + REVOKE_QUORUM_CLOCK_SKEW_MS) {
      throw new QuorumFreshnessError(
        `quorum context (${ceremony}) is future-dated beyond ${REVOKE_QUORUM_CLOCK_SKEW_MS}ms skew (initiated_at ahead of now)`
      );
    }
    if (nowMs > context.expires_at_ms) {
      throw new QuorumFreshnessError(
        `quorum context (${ceremony}) expired (now past expires_at; no skew grace on expiry)`
      );
    }
    return;
  }

  // sync_anchored
  const effectiveMs = Date.parse(freshness.effective_at);
  if (!Number.isFinite(effectiveMs)) {
    throw new QuorumFreshnessError(
      `sync-anchored freshness for (${ceremony}) requires a parseable effective_at`
    );
  }
  if (effectiveMs < context.initiated_at_ms - REVOKE_QUORUM_CLOCK_SKEW_MS) {
    // Skew-tolerant lower bound: a strict lower bound here would be permanent
    // fail-open trust of a revoked node whenever the emitter clock lagged.
    throw new QuorumFreshnessError(
      `sync-anchored effective_at for (${ceremony}) precedes initiated_at by more than ${REVOKE_QUORUM_CLOCK_SKEW_MS}ms skew`
    );
  }
  if (effectiveMs > context.expires_at_ms) {
    // Strict upper bound, no grace: grace would only widen the window for a
    // back-dated effective_at forged by the sync-channel attacker.
    throw new QuorumFreshnessError(
      `sync-anchored effective_at for (${ceremony}) is past expires_at (no grace)`
    );
  }
}

/**
 * Constrain a master-rotation's operator-visible `rotated_at` to the collection
 * window it was signed under (QI-SIBLING-02).
 *
 * Why this exists at all, given the window is already enforced: `rotated_at` is
 * a signed field a CONSUMER treats as meaning "the rotation happened then" — it
 * keys the receiver's pending/installed maps, correlates the install acks, and
 * is written verbatim into the `master_rotation_boundary` audit entry. A valid
 * signature over it proves who signed it, not that it describes a real moment
 * (rule 7). Without this bound a legitimate quorum could stamp a rotation into
 * the far past or future and the audit trail would faithfully record the lie.
 *
 * Bounds are directional because the two stamps come from two devices:
 *   - lower: rotated_at >= initiated_at - SKEW (skew-tolerant; a strict lower
 *     bound would refuse a legitimate ceremony whose initiator clock lagged the
 *     ceremony device, which is a fail-CLOSED denial of a real rotation).
 *   - upper: rotated_at <= expires_at (strict, no grace; grace would only widen
 *     the forward-dating window an attacker can select).
 */
export function assertRotatedAtWithinContext(params: {
  context: ParsedQuorumContext;
  rotated_at: string;
}): void {
  const rotatedMs = Date.parse(params.rotated_at);
  if (!Number.isFinite(rotatedMs)) {
    throw new QuorumFreshnessError(
      `master-rotation rotated_at is not a parseable ISO timestamp`
    );
  }
  if (
    rotatedMs <
    params.context.initiated_at_ms - REVOKE_QUORUM_CLOCK_SKEW_MS
  ) {
    throw new QuorumFreshnessError(
      `master-rotation rotated_at precedes initiated_at by more than ${REVOKE_QUORUM_CLOCK_SKEW_MS}ms skew`
    );
  }
  if (rotatedMs > params.context.expires_at_ms) {
    throw new QuorumFreshnessError(
      `master-rotation rotated_at is past expires_at (no grace)`
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Authorization-key derivation (SYNC-APPEND-01 dedupe, §3.3 point 4)
// ═══════════════════════════════════════════════════════════════════════

/**
 * The dedupe key for an ACCEPTED revoke. NEVER `event_id` (which rides inside
 * the emitter-signed body and is therefore attacker-chosen and free to vary):
 * key on the AUTHORIZATION the attacker cannot mint fresh while holding one
 * harvested proof.
 *   - quorum revoke:    `(target, ceremony_id)` — ceremony_id is inside the
 *     signed quorum bytes, invariant under replay.
 *   - principal revoke: `(target, sha256(DECODED principal-signature bytes))` —
 *     hashed over the decoded raw bytes, NOT the base64url wire string, so an
 *     encoding-variant duplicate cannot re-enter through a lenient decoder
 *     (re-gate RG3-2). Canonical-scalar enforcement in `@noble/curves/ed25519`
 *     (envelope verification) forecloses malleability-minted duplicates; a
 *     signature-library swap must re-assert that property (T9 note).
 *
 * `decodeSignature` decodes the base64url wire string to raw bytes.
 */
export function computeRevokeAuthorizationKey(params: {
  target_node_id: string;
  ceremony_id?: string;
  principal_signature_bytes?: Uint8Array;
}): string {
  if (params.ceremony_id !== undefined) {
    return `q:${params.target_node_id}:${params.ceremony_id}`;
  }
  if (params.principal_signature_bytes !== undefined) {
    const digest = sha256(params.principal_signature_bytes);
    let hex = "";
    for (const b of digest) hex += b.toString(16).padStart(2, "0");
    return `p:${params.target_node_id}:${hex}`;
  }
  throw new GuardianQuorumError(
    "computeRevokeAuthorizationKey requires a ceremony_id or a principal signature"
  );
}

export { CEREMONY_ID_HEX_CHARS };
