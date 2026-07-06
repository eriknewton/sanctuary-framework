/**
 * Durable federation peer-sync security state (Federation 3/3b P0).
 *
 * BEFORE this module the three pieces of federation security state were
 * in-memory ONLY and reset to empty on every daemon restart:
 *
 *   - the per-sender accepted high-water map (the whole-envelope rollback
 *     guard: "the highest sync point I have already accepted from each peer"),
 *   - this daemon's OWN outbound (reciprocal) high-water counter, and
 *   - the folded node-revocation projection (the revoked-node set + the highest
 *     accepted eviction serial), which was re-projected on boot from the
 *     event log, but the event log itself was in-memory, so the projection
 *     came up EMPTY.
 *
 * The blast radius of that ephemerality: after a restart a receiver would
 * re-accept previously-applied (validly-signed) envelopes (the rollback guard
 * saw "no prior high-water" and waved them through), and would TEMPORARILY
 * FORGET which nodes it had revoked until those evictions re-synced: a
 * standing security weakness independent of the peer-auth route relaxation.
 *
 * This store closes that window by persisting the SMALL DERIVED security state
 * (NOT the unbounded event log) the same way #741 made the single-use replay
 * stores durable: ONE AES-256-GCM record under a custody-master purpose key,
 * mirroring {@link FederationTrustRootStore}. Distinctions from the #741 spent
 * sets:
 *
 *   - The persisted blob is the already-DERIVED projection, not raw log events.
 *     There is no compaction problem because the accepted high-water is a
 *     fixed-width number per sender and the revocation projection is a set of
 *     node ids; neither grows with log length. The unbounded event log is NOT
 *     persisted (gossip re-serve is out of P0 scope; a restarted daemon answers
 *     reciprocal slices from its own freshly-appended events only).
 *
 *   - [CC-2 boot-reproject integrity] The revocation projection is the SOLE
 *     guarantor of who is revoked once it is loaded from disk. Its integrity is
 *     the AEAD tag of THIS record. On boot we load the already-verified
 *     projection DIRECTLY; we do NOT re-verify the underlying eviction
 *     signatures under the CURRENT principal certificate (that would resurrect
 *     nodes evicted under a PRIOR principal after a legitimate root rotation;
 *     see {@link foldAcceptedFederationNodeEvictionEvent}). An at-rest-tampered
 *     or truncated record fails AEAD decryption -> `load` THROWS -> the caller
 *     FAILS CLOSED (never silently un-revokes, never resets-to-empty-and-
 *     accepts). The acceptance path still verifies the operator signature on a
 *     NEW eviction before it is folded in and persisted; this record only
 *     carries forward already-accepted state.
 *
 * [DUR-4] Fail-CLOSED contract, carried verbatim from #741: `load` returns the
 * empty/zero state ONLY when no record exists yet (`raw === null`, a fresh
 * fortress). A record that is present but undecryptable/unparseable THROWS so
 * the caller denies rather than booting with empty anti-replay + empty
 * revocation memory.
 */

import type { StorageBackend } from "../storage/interface.js";
import { withCrossProcessLock } from "../storage/cross-process-lock.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import {
  bytesToString,
  stringToBytes,
  toBase64url,
  fromBase64url,
  constantTimeEqual,
} from "../core/encoding.js";
import { canonicalJson } from "../audit/chain.js";
import type { FederationAppliedPolicyVersion } from "./federation-policy-bundle.js";
import type { FederationNodeView } from "./federation.js";
import {
  deriveNodePosture,
  type NodeModeForPosture,
} from "../mesh/node-posture.js";
import {
  decodeGuardianRevocationRequirement,
  encodeGuardianRevocationRequirement,
  type PersistedGuardianRevocationRequirement,
} from "./federation-guardian-revocation-policy.js";
import type { GuardianRevocationRequirement } from "./federation-revocation-guardian-gate.js";
import type { BreakGlassState } from "./federation-guardian-disable-gate.js";

/**
 * At-rest location + HKDF label for the durable sync-state record. ADDITIVE and
 * FROZEN: the namespace + key name the on-disk blob; the HKDF label derives its
 * encryption key. All three MUST be registered in the master-rotation
 * `_federation` recipe `infos[]`, the frozen-surfaces guard, the
 * hkdf-label-classification fixture, and the HKDF info-string registry, or
 * `rotate-master` hard-aborts on a fortress that ever persisted sync-state
 * (the #741 strand defect on a new path). The HKDF label string MUST equal the
 * recipe entry (asserted in master-rotation.test).
 */
export const FEDERATION_SYNC_STATE_STORE_NAMESPACE = "_federation";
export const FEDERATION_SYNC_STATE_STORE_KEY = "sync-state-v1";
export const FEDERATION_SYNC_STATE_STORE_HKDF_INFO =
  "federation-sync-state" as const;

/**
 * Lockfile name (in the `_federation` namespace directory) for the cross-process
 * advisory lock that serializes the read-modify-write in {@link
 * FederationSyncStateStore.writeNow}. Not encrypted/at-rest state, just a
 * transient coordination file (PID + acquired_at), removed once the write
 * completes. The leading dot keeps it out of normal record enumeration.
 */
export const FEDERATION_SYNC_STATE_LOCK_FILE = ".sync-state.lock";

/**
 * FIX 2 (P0): the tamper-evident "a guardian revocation requirement was EVER
 * configured" sentinel. Written under `_meta` when the operator first ENABLES a
 * guardian requirement; NEVER cleared (a guard having once existed is a
 * grow-only fact). On boot, if this sentinel is present but the sync-state
 * record is ABSENT, the record was DELETED to strip a configured guard - the
 * caller fails closed (latches the sync state unavailable) REGARDLESS of whether
 * the fortress has independent root-revocation history. This closes the
 * fail-open where a fortress that configured a guardian requirement but never
 * performed a root revocation had its record deleted -> boot did NOT latch ->
 * the requirement cleared -> single-operator kill restored.
 *
 * It mirrors the audit head-anchor "established marker" pattern
 * (`audit-head-anchor-established-v1`): the marker's PRESENCE is the signal, and
 * it is MAC'd under the fortress master (via the store's existing purpose key -
 * NO new HKDF label) so it cannot be forged by an attacker without the master
 * key, and a stale marker from a PRIOR master (after a legitimate rotation) does
 * not verify and so does not falsely brick. Residual (documented, matches the
 * audit-anchor residual): an attacker who deletes BOTH the sync-state record AND
 * this `_meta` sentinel is again indistinguishable from a fresh fortress; the
 * marker raises the bar from "delete one file" to "delete two", and the second
 * deletion is itself the established->gone signature for any future ceremony
 * that carries an off-host witness.
 */
export const FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY =
  "federation-guardian-requirement-established-v1";
/**
 * Domain-separated HMAC input for the established sentinel. The MAC is over this
 * fixed string using the store's existing purpose key (the same key that
 * encrypts the sync-state blob) - no new key material, no new HKDF label.
 */
const FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_MAC_DOMAIN =
  "sanctuary.federation.guardian-requirement.established.v1";

/**
 * F1 re-gate (§1): the EXTERNAL, MAC'd, monotonic anti-rollback ANCHOR for the
 * security-load-bearing guardian sync-state floors. It lives in `_meta` (a
 * SEPARATE deletable namespace from the `_federation/sync-state-v1` blob it
 * protects), so a KEYLESS filesystem attacker who captures an OLD copy of the
 * sync-state blob and restores it AFTER the operator raised the threshold back
 * up cannot silently regress the floor: on load we take `Math.max(blob, anchor)`
 * and LATCH fail-closed on any regression. Mirrors the shipped
 * `core/anti-rollback.ts` epoch-witness precedent (`custody-epoch-witness-v1`):
 * the `{marker,data,mac}` record shape, the tri-state read (valid/absent/
 * invalid), and the non-decreasing write are copied verbatim; NO new crypto
 * scheme is invented.
 *
 * HONEST RESIDUAL (§8.3, round 2, do not over-claim): Anti-rollback covers a
 * KEYLESS same-master filesystem attacker. A single-record rollback (the
 * sync-state blob alone) is caught by the external `_meta` anchor; a two-record
 * restore (blob + anchor BOTH rolled back) is caught by the guardian AUDIT-trail
 * floor, which is derived WINDOW-INDEPENDENTLY over the WHOLE verified chain (not
 * a bounded tail, §8.6 P0), so a surviving guardian raise entry is always found
 * regardless of how much unrelated audit volume was appended after it. The
 * irreducible residual is therefore specifically a coordinated restore that ALSO
 * truncates or removes the guardian audit entries themselves (together with the
 * audit head anchor + its established marker and the checkpoints), i.e. a
 * wholesale guardian-audit-coverage destruction. That truncation is surfaced as a
 * coverage integrity finding (empty/truncated chain) that fails the floor TOWARD
 * latch UNLESS the attacker ALSO rolls the audit head anchor (`__head_anchor`, a
 * single overwrite-in-place key with no on-disk rollback protection of its own)
 * back to the MAC-valid OLD head that matches the truncated tail: with the head
 * anchor consistently rolled back the truncated chain re-verifies with ZERO
 * findings, so no coverage finding fires and the restore is on-disk-undetectable.
 * That fully-coordinated case (blob + anchor + old head anchor + established
 * marker rolled back AND the raise entry deleted) is bounded only by an OFF-HOST
 * or HARDWARE witness (anti-rollback Stage 2b / Stage 4). Do NOT claim on-disk
 * detection of a full self-consistent tree+audit restore that ALSO removes the
 * guardian audit trail and rolls the head anchor back consistently.
 */
export const FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY =
  "federation-guardian-antirollback-anchor-v1";
const FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MARKER =
  "__sanctuary_federation_guardian_antirollback_anchor_v1";
const FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MAC_DOMAIN =
  "sanctuary.federation.guardian-antirollback-anchor.v1\n";

/**
 * The monotonic floors carried in the anti-rollback anchor. Each mirrors a
 * `Math.max` floor that also lives inside the rollbackable sync-state blob; the
 * anchor is the external witness that keeps the blob from silently regressing
 * them. `updated_at` is advisory provenance only (NOT compared).
 */
export interface GuardianAntiRollbackAnchorData {
  /** Floor for `guardianLoweredHighWater` (the superseded-lowering replay floor). */
  lowered_high_water: number;
  /** Floor for `guardianDisableNonce` (the general burned-nonce floor). */
  disable_nonce: number;
  /** Floor for `guardianRevocationRequirementGeneration` (the config generation). */
  requirement_generation: number;
  /** Advisory provenance only (never part of the monotonic comparison). */
  updated_at: string;
}

/**
 * Tri-state read of the anti-rollback anchor, mirroring `readEpochWitness`
 * (`core/anti-rollback.ts`):
 *  - "valid": authenticates under the store's purpose key -> a trustworthy floor.
 *  - "absent": no anchor record at all (pre-fix fortress, or first boot).
 *  - "invalid": present but tampered/malformed/wrong-key -> the caller LATCHES
 *    fail-closed (present-but-untrusted is a positively-detected tamper, never
 *    read as absent).
 */
export type GuardianAntiRollbackAnchorRead =
  | { status: "valid"; data: GuardianAntiRollbackAnchorData }
  | { status: "absent" }
  | { status: "invalid" };

/** The derived security state this store persists and rehydrates. */
export interface FederationSyncStateSnapshot {
  /** Per-sender accepted high-water: senderNodeId -> highest accepted value. */
  acceptedHighWater: Map<string, number>;
  /** This daemon's own monotonic outbound (reciprocal) high-water. */
  outboundHighWater: number;
  /** Folded node-revocation projection: the grow-only revoked-node set. */
  revokedNodeIds: Set<string>;
  /** Highest accepted operator-authority eviction serial (replay floor). */
  highestEvictionSerial: number;
  /**
   * Folded ROOT-revocation projection (Slice 3c-1): the grow-only set of
   * revoked fortress-master (root) pubkeys, base64url. Persisted in the SAME
   * record/blob as the node revocations (no new at-rest HKDF label) so a
   * compromise rotate's revocation of the old root K1 survives a daemon restart
   * exactly like a node eviction does.
   */
  revokedRootPubkeys: Set<string>;
  /** Highest accepted operator-authority revocation serial (replay floor). */
  highestRevocationSerial: number;
  /** Highest verified operator policy bundle accepted by this daemon. */
  operatorPolicy: FederationAppliedPolicyVersion | null;
  /** Per-node applied policy version markers: nodeId -> verified applied marker. */
  appliedPolicyVersions: Map<string, FederationAppliedPolicyVersion>;
  /**
   * PR-A (durable fleet membership): the GROW-ONLY node roster
   * (`_federationState.nodes`), the authoritative source of the paid
   * node-count. BEFORE this field the roster was in-memory ONLY: it was
   * rebuilt from the event log, but the event log is not persisted, so the
   * roster came up EMPTY on every restart and the count reset to zero.
   *
   * Persisting it here makes membership SURVIVE A REBOOT so the count
   * (active-non-revoked = this roster MINUS the already-durable
   * {@link revokedNodeIds}) is stable across restarts. A node LEAVES the fleet
   * only by eviction/revocation (added to {@link revokedNodeIds}); the roster
   * itself is never deleted from (verified: no `nodes.delete` anywhere in the
   * dashboard), so grow-only-roster minus grow-only-revoked is the correct,
   * non-over-counting active set. Its integrity is the AEAD tag of THIS record
   * (the SAME operator-master purpose key as every other field), so a
   * disk-level attacker cannot forge extra nodes to inflate the count / claim a
   * higher grandfather baseline. Absent on an OLD-code snapshot -> decodes to
   * the empty roster (today's behavior), never a crash.
   */
  nodes: Map<string, FederationNodeView>;
  /**
   * OPTIONAL M-of-N guardian sign-off requirement on the revoke/kill path
   * (competitor-readiness item 6). `null` = no requirement configured (legacy
   * single-operator revoke). Persisting it here makes the requirement SURVIVE A
   * RESTART, so "no single person can kill the fleet" holds across reboots
   * instead of silently reverting to single-operator kill. The at-rest roster's
   * master signature is re-verified against the pinned master on rehydrate
   * (fail-closed; see {@link FederationSyncStateStore} consumers).
   */
  guardianRevocationRequirement: GuardianRevocationRequirement | null;
  /**
   * Monotonic generation counter for {@link guardianRevocationRequirement}. The
   * dashboard setter increments it on EVERY set (including `set(null)`), so the
   * merge can pick the value with the HIGHER generation and a STALE writer can
   * never clobber a fresher requirement. This is REQUIRED because the requirement
   * is NOT grow-only (it can be cleared), and a SECOND writer of this blob (the
   * `rotate-root --compromised` CLI in {@link
   * federation-rotate-root.ts}) does an unlocked `load()` then `persist()`
   * carrying a STALE copy of this field; without a generation the CLI's stale
   * `persist` would silently revert a concurrently-set requirement to its old
   * value (a Tier-1 downgrade). Defaults to 0 (fresh fortress / no requirement
   * ever set).
   */
  guardianRevocationRequirementGeneration: number;
  /**
   * F1 E1: monotonic anti-replay counter for the guardian DISABLE-gate (distinct
   * from {@link guardianRevocationRequirementGeneration}, which tracks the
   * requirement's own config generation). Burns (advances) on every terminal
   * disable-gate transition (instant quorum/master-key authorize, break-glass
   * vetoed, break-glass cancelled, break-glass completed) so a quorum or
   * master-key signature collected for a consumed nonce can never be replayed.
   * Merged by `Math.max` (same treatment as `highestEvictionSerial`) AS A FLOOR;
   * the authoritative live value while a break-glass is armed is
   * `guardianBreakGlass.nonce` (see that field's doc for why the two can never
   * disagree). Defaults to 0 (fresh fortress / gate never used).
   */
  guardianDisableNonce: number;
  /**
   * FIX 1 (A3 replay, reboot leg): a DEDICATED monotonic high-water for
   * SUPERSEDED lowered-threshold records, distinct from {@link
   * guardianDisableNonce}. It advances ONLY when a lowering is actually dropped
   * (a raise/re-pin that removes a prior lowered record, or a decrease that
   * replaces one) - NOT on a break-glass initiate (which advances the general
   * disable nonce while leaving a present lowered record intact). On reboot the
   * consumer REJECTS a persisted lowered record whose `disable_nonce` is below
   * this high-water (a replayed, already-superseded lowering). Keying it off the
   * general disable nonce would falsely reject a legitimately-lowered fortress
   * that armed break-glass and rebooted mid-countdown. Merged by `Math.max` (a
   * floor that never regresses). Defaults to 0 (no lowering ever superseded).
   */
  guardianLoweredHighWater: number;
  /**
   * F1 E1: the in-flight break-glass countdown, or `null` when IDLE (no
   * countdown armed). NOT grow-only (it is set on initiate and cleared on
   * veto/cancel/complete), so - exactly like {@link guardianRevocationRequirement}
   * - it CANNOT be merged by union or `Math.max`. It travels under the SAME
   * generation counter as the requirement
   * ({@link guardianRevocationRequirementGeneration}), and it is a HARD,
   * TESTED invariant that EVERY break-glass transition (initiate, veto, cancel,
   * complete) bumps that shared generation exactly like the dashboard setter
   * already does for the requirement itself. This is required so the
   * sub-object and the generation integer can never decouple: if a transition
   * changed `guardianBreakGlass` without bumping the generation, two on-disk
   * states could tie at the same generation with different break-glass
   * payloads, and the `nextGen > baseGen` merge could not tell them apart. With
   * the shared-bump invariant held, the existing generation-selector logic
   * (`selectGuardianRevocationRequirementByGeneration`, extended below to also
   * carry this field) is sufficient: a stale writer's lower generation can
   * never clobber a fresher armed-or-cleared break-glass state, and the
   * `guardianBreakGlass.nonce` it carries is therefore always the authoritative
   * live nonce (never behind the `guardianDisableNonce` floor).
   */
  guardianBreakGlass: BreakGlassState | null;
}

interface PersistedSyncState {
  /** Format version for forward-compatibility. */
  v: 1;
  /** [senderNodeId, highWater] pairs. */
  accepted_high_water: Array<[string, number]>;
  /** This daemon's own outbound high-water. */
  outbound_high_water: number;
  /** Folded revoked-node ids. */
  revoked_node_ids: string[];
  /** Highest accepted eviction serial. */
  highest_eviction_serial: number;
  /**
   * Folded revoked-root pubkeys (Slice 3c-1). Optional on read for
   * forward/backward field-compatibility within v1: a pre-3c-1 record (written
   * before this field existed) decodes to the empty set; a fresh write always
   * includes it. Adding a field to an existing v1 blob is additive - the AEAD
   * tag still authenticates the whole record, so a tampered/truncated blob still
   * fails closed.
   */
  revoked_root_pubkeys?: string[];
  /** Highest accepted revocation serial (optional for the same back-compat reason). */
  highest_revocation_serial?: number;
  /** Highest verified operator policy bundle accepted by this daemon. */
  operator_policy?: PersistedAppliedPolicyVersion | null;
  /** Per-node applied policy version markers. */
  applied_policy_versions?: Array<[string, PersistedAppliedPolicyVersion]>;
  /**
   * PR-A (durable fleet membership). The persisted grow-only node roster:
   * `[nodeId, minimalDurableNode]` pairs. Optional on read for back-compat
   * within v1 (a pre-PR-A record omits it -> the empty roster, exactly today's
   * post-reboot behavior). ADDITIVE within the existing v1 record: the
   * enclosing AEAD tag authenticates it, so a tampered/truncated blob (incl. a
   * forged extra node) still fails closed at decrypt. Only the MINIMAL fields
   * needed to reconstruct the `FederationNodeView` the roster + count consume
   * are stored; the posture (trust boundary, tee, drill status) is DERIVED from
   * `node_mode` on rehydrate, and NO secret / private key is ever persisted.
   */
  nodes?: Array<[string, PersistedFederationNode]>;
  /**
   * OPTIONAL persisted guardian revocation requirement. Absent (a pre-item-6
   * record) OR null both decode to "no requirement configured"; present decodes
   * to the fortress-master-signed roster verbatim so its signature can be
   * re-verified on load. Additive within the v1 record: the enclosing AEAD tag
   * authenticates it, so a tampered blob still fails closed at decrypt.
   */
  guardian_revocation_requirement?: PersistedGuardianRevocationRequirement | null;
  /**
   * Monotonic generation for `guardian_revocation_requirement`. Optional on read
   * (a pre-item-6 record omits it -> 0). The merge keeps the value with the
   * higher generation so a stale writer cannot clobber a fresher requirement.
   */
  guardian_revocation_requirement_generation?: number;
  /**
   * F1 E1. Optional on read (a pre-E1 record omits it -> 0). Merged as a
   * `Math.max` floor; see {@link FederationSyncStateSnapshot.guardianDisableNonce}.
   */
  guardian_disable_nonce?: number;
  /**
   * FIX 1. Optional on read (a pre-fix record omits it -> 0). Merged as a
   * `Math.max` floor; see {@link
   * FederationSyncStateSnapshot.guardianLoweredHighWater}. ADDITIVE within the
   * existing v1 record (the enclosing AEAD tag still authenticates it), NO `v`
   * bump, NO new HKDF label, NO migration.
   */
  guardian_lowered_high_water?: number;
  /**
   * F1 E1. Optional on read (a pre-E1 record omits it, or a fresh IDLE state,
   * both decode to `null`: no countdown armed). Rides under the SAME generation
   * as `guardian_revocation_requirement_generation`; see
   * {@link FederationSyncStateSnapshot.guardianBreakGlass}.
   */
  guardian_break_glass?: PersistedBreakGlassState | null;
}

interface PersistedBreakGlassState {
  nonce: number;
  intent: "disable" | "lower";
  target_m: number | null;
  initiated_at: string;
  completes_at: string;
  delay_ms: number;
}

/**
 * PR-A (durable fleet membership): the MINIMAL durable representation of a
 * roster node. Only the fields that {@link buildFederationNodeUpsert} carries
 * as sticky state are persisted; the trust-boundary posture (`trust_boundary`,
 * `tee_attested`, `host_provider`, `drill_status`) is RE-DERIVED from
 * `node_mode` on rehydrate, so it is not stored. NO secret / private key is
 * ever included: node trust for the count is membership-minus-revocation, and
 * the per-node pubkey/attestation is verified at JOIN + sync time, never
 * re-checked at count time from this record.
 */
interface PersistedFederationNode {
  node_id: string;
  label: string | null;
  attestation_status: FederationNodeView["attestation_status"];
  node_mode: FederationNodeView["node_mode"];
  first_seen: string;
  last_seen: string;
  last_sync: {
    received_at: string | null;
    sent_at: string | null;
    last_sequence: number;
  };
  applied_policy: {
    version: number | null;
    hash: string | null;
    hash_algorithm: string | null;
    applied_at: string | null;
    source_event_id: string | null;
  };
}

interface PersistedAppliedPolicyVersion {
  version: number;
  hash: string;
  hash_algorithm: FederationAppliedPolicyVersion["hash_algorithm"];
  applied_at: string;
  source_event_id: string;
}

export class FederationSyncStateStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FederationSyncStateStoreError";
  }
}

/** An empty/zero snapshot: the only legitimate "no record yet" result. */
export function emptyFederationSyncState(): FederationSyncStateSnapshot {
  return {
    acceptedHighWater: new Map(),
    outboundHighWater: 0,
    revokedNodeIds: new Set(),
    highestEvictionSerial: 0,
    revokedRootPubkeys: new Set(),
    highestRevocationSerial: 0,
    operatorPolicy: null,
    appliedPolicyVersions: new Map(),
    nodes: new Map(),
    guardianRevocationRequirement: null,
    guardianRevocationRequirementGeneration: 0,
    guardianDisableNonce: 0,
    guardianLoweredHighWater: 0,
    guardianBreakGlass: null,
  };
}

/**
 * Encrypted persistence for the federation peer-sync security state. ONE record
 * at (`namespace`, `recordKey`) holds the whole snapshot. `load` returns the
 * decrypted snapshot (THROWS on a corrupt record so the caller fails closed);
 * `persist` re-encrypts and writes the whole snapshot (THROWS on a write failure
 * so the caller denies rather than acting on un-committed state).
 */
export class FederationSyncStateStore {
  private readonly storage: StorageBackend;
  private readonly namespace: string;
  private readonly recordKey: string;
  private readonly encryptionKey: Uint8Array;
  /**
   * Serializes persists so two concurrent whole-snapshot rewrites cannot land
   * out of order (an earlier, less-complete snapshot completing last would drop
   * a just-recorded high-water / eviction (replayable / un-revoked after a
   * restart). Each persist awaits the prior and SNAPSHOTS the caller-supplied
   * state at write time. A failed write still rejects THAT caller's promise
   * (caller fails closed) without poisoning the chain for later writes. Mirrors
   * {@link DurableSpentSetStore}.
   */
  private writeChain: Promise<void> = Promise.resolve();

  constructor(params: {
    storage: StorageBackend;
    masterKey: Uint8Array;
    namespace?: string;
    recordKey?: string;
    hkdfLabel?: string;
  }) {
    this.storage = params.storage;
    this.namespace = params.namespace ?? FEDERATION_SYNC_STATE_STORE_NAMESPACE;
    this.recordKey = params.recordKey ?? FEDERATION_SYNC_STATE_STORE_KEY;
    this.encryptionKey = derivePurposeKey(
      params.masterKey,
      params.hkdfLabel ?? FEDERATION_SYNC_STATE_STORE_HKDF_INFO,
    );
  }

  /**
   * Existence probe for the at-rest sync-state record, WITHOUT decrypting it.
   * Returns true when the record blob is physically present at (`namespace`,
   * `recordKey`), false when it is absent (`read` yields null).
   *
   * This exists to let the caller DISTINGUISH the two cases {@link load}
   * deliberately collapses into `emptyFederationSyncState()`:
   *
   *   - a genuinely fresh fortress that has NEVER persisted sync-state, versus
   *   - a fortress whose record was DELETED out of band (an attacker with local
   *     storage write erasing the blob to reset revocation memory).
   *
   * `load`'s `raw === null -> empty` contract is FROZEN and unchanged (a fresh
   * fortress still loads empty). The provisioned-vs-not decision about whether an
   * ABSENT record is anomalous is made by the caller, which alone knows whether
   * the fortress is federation-provisioned; the store only reports presence.
   * A read error (not a null) propagates so the caller fails closed rather than
   * mis-reading a transient backend fault as "absent".
   */
  async recordExists(): Promise<boolean> {
    const raw = await this.storage.read(this.namespace, this.recordKey);
    return raw !== null;
  }

  /** The MAC bytes over the fixed established-sentinel domain, base64url. */
  private guardianRequirementEstablishedMac(): string {
    return toBase64url(
      hmacSha256(
        this.encryptionKey,
        stringToBytes(FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_MAC_DOMAIN),
      ),
    );
  }

  /**
   * FIX 2: idempotently record that a guardian revocation requirement was EVER
   * configured on this fortress. Called when the operator first ENABLES a
   * requirement (the enable transition), BEFORE/at the first persist. Writes a
   * small MAC'd marker under `_meta` that is NEVER cleared. Best-effort within
   * the enable path's own fail-closed persist: the caller awaits it so a write
   * fault surfaces. Writing again with the same key is harmless (same bytes).
   */
  async markGuardianRequirementEstablished(): Promise<void> {
    const envelope = { v: 1, mac: this.guardianRequirementEstablishedMac() };
    await this.storage.write(
      "_meta",
      FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
      stringToBytes(JSON.stringify(envelope)),
    );
  }

  /**
   * FIX 2 + Finding #6 (tri-state, tamper-evident): has a guardian requirement
   * EVER been configured on this fortress (per the tamper-evident `_meta`
   * sentinel)? The return contract distinguishes ABSENT from PRESENT-BUT-INVALID
   * so the hydrate path can fail closed on tamper instead of booting fresh.
   *
   *   - "absent": no marker at all (fresh fortress, or a fortress that never
   *     enabled a guard). Not anomalous on its own; a guard-in-record still
   *     backfills per finding #3.
   *   - "established": present AND its MAC verifies under the current master's
   *     purpose key. A guard was configured; if the sync-state record is now
   *     absent, the caller fails closed.
   *   - "invalid": present but unparseable, malformed, OR MAC-mismatched. The
   *     MAC-mismatch case is EITHER tamper OR a stale marker from a PRIOR master
   *     after a legitimate rotation; we CANNOT distinguish the two here (doing so
   *     would brick a rotated fortress), so we return "invalid" and let the
   *     CALLER combine it with `recordPresent`: record-ABSENT + marker-invalid is
   *     the attack (LATCH); record-PRESENT + marker-invalid is the rotation case
   *     (re-stamp a clean marker). This is the same combine-with-independent-
   *     evidence move the epoch-witness uses.
   *
   * A read fault (not a clean absence) PROPAGATES so the caller can fail closed
   * rather than mis-read a transient backend error as "never established".
   */
  async guardianRequirementEstablished(): Promise<
    { status: "absent" } | { status: "established" } | { status: "invalid" }
  > {
    const raw = await this.storage.read(
      "_meta",
      FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
    );
    if (raw === null) return { status: "absent" };
    let parsed: { mac?: unknown };
    try {
      parsed = JSON.parse(bytesToString(raw)) as { mac?: unknown };
    } catch {
      // Present-but-unparseable = tamper (a legit marker is always well-formed
      // JSON). NOT read as absent: the caller latches when the record is gone.
      return { status: "invalid" };
    }
    if (typeof parsed.mac !== "string") return { status: "invalid" };
    if (parsed.mac === this.guardianRequirementEstablishedMac()) {
      return { status: "established" };
    }
    // Present, well-formed, but the MAC mismatches under the CURRENT master:
    // tamper OR a stale marker from a prior master (legit rotation). We cannot
    // hard-latch on mismatch alone (that would brick a rotated fortress), so we
    // return "invalid" and let the caller key the fail-closed decision on
    // recordPresent (see the hydrate rule in dashboard.ts).
    return { status: "invalid" };
  }

  /** The MAC bytes over the anti-rollback anchor `data`, base64url. */
  private guardianAntiRollbackAnchorMac(
    data: GuardianAntiRollbackAnchorData,
  ): string {
    return toBase64url(
      hmacSha256(
        this.encryptionKey,
        stringToBytes(
          FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MAC_DOMAIN + canonicalJson(data),
        ),
      ),
    );
  }

  /**
   * F1 re-gate (§1): read + authenticate the external anti-rollback anchor,
   * tri-state, mirroring `readEpochWitness`. "invalid" (present-but-tampered)
   * makes the caller LATCH fail-closed; "absent" is neutral (pre-fix / first
   * boot). A read FAULT (storage throws) is treated as "invalid" (fail toward
   * latch), never as "absent": an anchor we cannot read is one we cannot trust.
   */
  async readGuardianAntiRollbackAnchor(): Promise<GuardianAntiRollbackAnchorRead> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(
        "_meta",
        FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
      );
    } catch {
      // Unreadable storage is an anchor we cannot trust -> suspected, not absent.
      return { status: "invalid" };
    }
    if (raw === null) return { status: "absent" };
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      return { status: "invalid" };
    }
    if (
      !parsed ||
      typeof parsed !== "object" ||
      (parsed as Record<string, unknown>)[
        FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MARKER
      ] !== true
    ) {
      return { status: "invalid" };
    }
    const obj = parsed as Record<string, unknown>;
    const data = obj.data as Partial<GuardianAntiRollbackAnchorData> | undefined;
    const mac = obj.mac;
    if (
      !data ||
      typeof data !== "object" ||
      !isNonNegSafeInt(data.lowered_high_water) ||
      !isNonNegSafeInt(data.disable_nonce) ||
      !isNonNegSafeInt(data.requirement_generation) ||
      typeof data.updated_at !== "string" ||
      typeof mac !== "string"
    ) {
      return { status: "invalid" };
    }
    const fullData: GuardianAntiRollbackAnchorData = {
      lowered_high_water: data.lowered_high_water,
      disable_nonce: data.disable_nonce,
      requirement_generation: data.requirement_generation,
      updated_at: data.updated_at,
    };
    let provided: Uint8Array;
    try {
      provided = fromBase64url(mac);
    } catch {
      return { status: "invalid" };
    }
    if (
      !constantTimeEqual(
        provided,
        fromBase64url(this.guardianAntiRollbackAnchorMac(fullData)),
      )
    ) {
      return { status: "invalid" };
    }
    return { status: "valid", data: fullData };
  }

  /**
   * F1 re-gate (§1): persist (or RAISE) the anti-rollback anchor. The anchor is
   * MONOTONIC: it NEVER regresses. Each field is folded `Math.max` over the
   * currently-authenticated anchor, so a caller passing floors LOWER than what is
   * already anchored leaves the higher values in place (a lower write can never
   * launder a rollback). Mirrors `writeEpochWitness`'s non-decreasing guard. An
   * "invalid" current anchor is treated as absent for the raise (we re-establish
   * a clean anchor at the supplied floors); the hydrate-side latch is what
   * catches a tampered anchor, not this writer.
   */
  async writeGuardianAntiRollbackAnchor(floors: {
    loweredHighWater: number;
    disableNonce: number;
    requirementGeneration: number;
    now?: () => Date;
  }): Promise<void> {
    const current = await this.readGuardianAntiRollbackAnchor();
    const prior =
      current.status === "valid"
        ? current.data
        : { lowered_high_water: 0, disable_nonce: 0, requirement_generation: 0 };
    const data: GuardianAntiRollbackAnchorData = {
      lowered_high_water: Math.max(prior.lowered_high_water, floors.loweredHighWater),
      disable_nonce: Math.max(prior.disable_nonce, floors.disableNonce),
      requirement_generation: Math.max(
        prior.requirement_generation,
        floors.requirementGeneration,
      ),
      updated_at: (floors.now ?? (() => new Date()))().toISOString(),
    };
    const record = {
      [FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MARKER]: true,
      data,
      mac: this.guardianAntiRollbackAnchorMac(data),
    };
    await this.storage.write(
      "_meta",
      FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
      stringToBytes(JSON.stringify(record)),
    );
  }

  /**
   * Load the persisted sync-state snapshot. Returns {@link
   * emptyFederationSyncState} ONLY when no record exists yet (`raw === null`, a
   * fresh fortress). THROWS {@link FederationSyncStateStoreError} when a record
   * exists but cannot be decrypted/parsed: the caller MUST fail closed (deny
   * sync + keep federation provisioned-but-not-serving), NEVER silently reset to
   * empty (that resurrects the replay window AND un-revokes evicted nodes).
   */
  async load(): Promise<FederationSyncStateSnapshot> {
    const raw = await this.storage.read(this.namespace, this.recordKey);
    if (raw === null) return emptyFederationSyncState();

    let plaintext: Uint8Array | null = null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      plaintext = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(plaintext)) as unknown;
      return decodeSyncState(parsed);
    } catch (err) {
      throw new FederationSyncStateStoreError(
        `durable federation sync-state failed to load: ${publicErrorReason(err)}`,
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  /**
   * Persist the snapshot, serialized cross-process and MONOTONICALLY MERGED over
   * whatever is already at rest.
   *
   * [LOST-UPDATE close, cross-process] The caller's live state is NOT a complete
   * source of truth: another process (the `rotate-root --compromised` CLI) writes
   * the SAME blob out-of-band, and the daemon's in-memory state never learns of
   * that write. A blind whole-blob overwrite by the daemon (a high-water advance
   * built purely from stale in-memory fields) would CLOBBER a root revocation the
   * CLI committed, silently un-revoking a compromised root after the next restart.
   *
   * Two layers close the window, each covering what the other cannot:
   *
   *   1. A CROSS-PROCESS advisory lock ({@link withCrossProcessLock}) spans the
   *      WHOLE read-modify-write in {@link writeNow}, so the merge-read and the
   *      write are atomic with respect to ANOTHER process's read-modify-write.
   *      This closes the genuine write-OVERLAP race (two processes both reading
   *      before either writes); the lock is bounded and FAILS CLOSED (throws with a
   *      manual-`rm` recovery hint) on sustained contention. It has NO auto-stale-
   *      break (that read-then-unlink is a TOCTOU double-acquire; see the #871 lock
   *      lesson), so a crashed holder wedges this path until a one-time operator
   *      `rm` - fail-SAFE, never a fail-open double-acquire on revocation state.
   *   2. A strictly MONOTONIC merge: writeNow RE-READS the at-rest blob and UNIONs
   *      the grow-only security fields (revoked node ids, revoked root pubkeys) +
   *      takes `Math.max` of the monotonic floors (eviction serial, revocation
   *      serial, every per-peer high-water, the outbound high-water) before
   *      encrypting. This keeps single-process and non-filesystem rigs (where the
   *      lock degrades to a direct call) correct, and converges any residual
   *      interleaving to the union.
   *
   * Together: on filesystem backends no committed revocation/floor can be lost
   * regardless of interleaving (the lock serializes the read-modify-write across
   * processes); on single-process rigs the monotonic merge alone suffices.
   *
   * THROWS on any lock/read/encrypt/write failure so the caller can fail closed:
   * a write whose persist throws MUST deny rather than act on state that was not
   * durably committed. A present-but-corrupt at-rest blob makes the merge-read
   * THROW (never silently reset-to-empty-then-overwrite), preserving the
   * fail-closed contract for the read leg too.
   */
  async persist(snapshot: FederationSyncStateSnapshot): Promise<void> {
    const copy = cloneSnapshot(snapshot);
    const run = this.writeChain.then(() => this.writeNow(copy));
    this.writeChain = run.catch(() => {});
    return run;
  }

  private async writeNow(snapshot: FederationSyncStateSnapshot): Promise<void> {
    // Hold a cross-process lock across the ENTIRE read-modify-write so another
    // process's read-modify-write cannot interleave between our load and our
    // write (the write-OVERLAP lost-update). On non-filesystem backends the lock
    // degrades to a direct call (single process; the monotonic merge suffices).
    // The in-process writeChain already serializes this process's own writers, so
    // we never block on a lock this process holds (the lock is not reentrant).
    await withCrossProcessLock(
      this.storage,
      this.namespace,
      FEDERATION_SYNC_STATE_LOCK_FILE,
      async () => {
        // Re-read the at-rest blob and fold this snapshot OVER it monotonically,
        // so a concurrent cross-process writer's committed revocations/floors
        // survive this write. `load` returns empty on a fresh fortress and THROWS
        // on a corrupt record (fail closed); either way we never overwrite
        // committed state with a stale subset.
        const onDisk = await this.load();
        const merged = mergeSyncStateMonotonic(onDisk, snapshot);
        // F1 re-gate (§1 / §3A write-ordering): ADVANCE the external anti-rollback
        // anchor to the merged floors BEFORE writing the blob, inside this same
        // cross-process lock. The anchor is non-decreasing (never lowers), so this
        // is idempotent and safe under the lock. Ordering matters: the only
        // interrupted-crash state (anchor advanced, blob not yet written) is the
        // SAFE direction, a higher anchor over a lower blob, which the hydrate
        // reconcile LATCHES fail-closed (the operator's next persist re-writes the
        // blob at the anchor floor and clears the latch). The dangerous direction
        // (blob advanced past the anchor) is impossible because the anchor is
        // written first and never lowered. Mirrors the epoch-witness "witness leads
        // the protected record" ordering.
        await this.writeGuardianAntiRollbackAnchor({
          loweredHighWater: merged.guardianLoweredHighWater,
          disableNonce: merged.guardianDisableNonce,
          requirementGeneration: merged.guardianRevocationRequirementGeneration,
        });
        const persisted: PersistedSyncState = {
          v: 1,
          accepted_high_water: [...merged.acceptedHighWater],
          outbound_high_water: merged.outboundHighWater,
          revoked_node_ids: [...merged.revokedNodeIds],
          highest_eviction_serial: merged.highestEvictionSerial,
          revoked_root_pubkeys: [...merged.revokedRootPubkeys],
          highest_revocation_serial: merged.highestRevocationSerial,
          operator_policy: merged.operatorPolicy
            ? encodeAppliedPolicyVersion(merged.operatorPolicy)
            : null,
          applied_policy_versions: [...merged.appliedPolicyVersions].map(
            ([nodeId, marker]) => [nodeId, encodeAppliedPolicyVersion(marker)],
          ),
          nodes: [...merged.nodes].map(([nodeId, node]) => [
            nodeId,
            encodeFederationNode(node),
          ]),
          guardian_revocation_requirement: merged.guardianRevocationRequirement
            ? encodeGuardianRevocationRequirement(
                merged.guardianRevocationRequirement,
              )
            : null,
          guardian_revocation_requirement_generation:
            merged.guardianRevocationRequirementGeneration,
          guardian_disable_nonce: merged.guardianDisableNonce,
          guardian_lowered_high_water: merged.guardianLoweredHighWater,
          guardian_break_glass: merged.guardianBreakGlass
            ? encodeBreakGlassState(merged.guardianBreakGlass)
            : null,
        };
        const serialized = stringToBytes(JSON.stringify(persisted));
        try {
          const encrypted = encrypt(serialized, this.encryptionKey);
          await this.storage.write(
            this.namespace,
            this.recordKey,
            stringToBytes(JSON.stringify(encrypted)),
          );
        } finally {
          serialized.fill(0);
        }
      },
    );
  }
}

function cloneSnapshot(
  snapshot: FederationSyncStateSnapshot,
): FederationSyncStateSnapshot {
  const operatorPolicy =
    (snapshot as Partial<FederationSyncStateSnapshot>).operatorPolicy ?? null;
  const appliedPolicyVersions =
    (snapshot as Partial<FederationSyncStateSnapshot>).appliedPolicyVersions ??
    new Map<string, FederationAppliedPolicyVersion>();
  return {
    acceptedHighWater: new Map(snapshot.acceptedHighWater),
    outboundHighWater: snapshot.outboundHighWater,
    revokedNodeIds: new Set(snapshot.revokedNodeIds),
    highestEvictionSerial: snapshot.highestEvictionSerial,
    revokedRootPubkeys: new Set(snapshot.revokedRootPubkeys),
    highestRevocationSerial: snapshot.highestRevocationSerial,
    operatorPolicy: operatorPolicy ? { ...operatorPolicy } : null,
    appliedPolicyVersions: new Map(
      [...appliedPolicyVersions].map(([nodeId, marker]) => [
        nodeId,
        { ...marker },
      ]),
    ),
    nodes: cloneNodeRoster(
      (snapshot as Partial<FederationSyncStateSnapshot>).nodes ??
        new Map<string, FederationNodeView>(),
    ),
    guardianRevocationRequirement: cloneGuardianRevocationRequirement(
      (snapshot as Partial<FederationSyncStateSnapshot>)
        .guardianRevocationRequirement ?? null,
    ),
    guardianRevocationRequirementGeneration:
      (snapshot as Partial<FederationSyncStateSnapshot>)
        .guardianRevocationRequirementGeneration ?? 0,
    guardianDisableNonce:
      (snapshot as Partial<FederationSyncStateSnapshot>).guardianDisableNonce ?? 0,
    guardianLoweredHighWater:
      (snapshot as Partial<FederationSyncStateSnapshot>).guardianLoweredHighWater ?? 0,
    guardianBreakGlass: cloneBreakGlassState(
      (snapshot as Partial<FederationSyncStateSnapshot>).guardianBreakGlass ?? null,
    ),
  };
}

function cloneBreakGlassState(
  state: BreakGlassState | null | undefined,
): BreakGlassState | null {
  if (state === null || state === undefined) return null;
  return { ...state };
}

/**
 * PR-A: deep-clone the node roster so a persisted snapshot never aliases the
 * caller's live `_federationState.nodes` (mirrors the defensive clone every
 * other reference-typed field in {@link cloneSnapshot} gets). Nested objects
 * (`last_sync`, `applied_policy`, `trust_boundary`) are copied so a later live
 * mutation cannot retroactively change the queued write.
 */
function cloneNodeRoster(
  nodes: Map<string, FederationNodeView>,
): Map<string, FederationNodeView> {
  return new Map(
    [...nodes].map(([nodeId, node]) => [nodeId, cloneNodeView(node)]),
  );
}

function cloneNodeView(node: FederationNodeView): FederationNodeView {
  return {
    ...node,
    trust_boundary: { ...node.trust_boundary },
    last_sync: { ...node.last_sync },
    applied_policy: { ...node.applied_policy },
  };
}

function cloneGuardianRevocationRequirement(
  requirement: GuardianRevocationRequirement | null | undefined,
): GuardianRevocationRequirement | null {
  if (requirement === null || requirement === undefined) return null;
  const cloned: GuardianRevocationRequirement = {
    roster: {
      ...requirement.roster,
      guardians: requirement.roster.guardians.map((g) => ({ ...g })),
    },
  };
  if (requirement.expectedRosterVersion !== undefined) {
    cloned.expectedRosterVersion = requirement.expectedRosterVersion;
  }
  if (requirement.loweredThreshold !== undefined) {
    cloned.loweredThreshold = {
      body: { ...requirement.loweredThreshold.body },
      signature: requirement.loweredThreshold.signature,
    };
  }
  return cloned;
}

/**
 * Fold `next` OVER `base` with strictly MONOTONIC, grow-only semantics for every
 * security field, producing the snapshot to persist. This is the lost-update
 * close: `base` is the freshly-loaded at-rest state (which may include a
 * cross-process writer's committed revocations the live caller never saw) and
 * `next` is the caller's live snapshot. The result:
 *
 *   - revoked node ids / revoked root pubkeys: UNION (never drops either side's
 *     revocations),
 *   - eviction serial / revocation serial: `Math.max` (a replay floor never
 *     lowers),
 *   - per-peer accepted high-water: `Math.max` per sender, union of senders (an
 *     anti-replay high-water never regresses, and a sender known to only one side
 *     is kept),
 *   - outbound high-water: `Math.max` (the reciprocal counter never re-emits).
 *
 * Because every field can only grow, this merge can never lower a floor or drop a
 * revocation it has already read: folding a stale `next` over a fresher `base`
 * keeps the fresher value. It is the SECOND of the two lost-update layers; the
 * cross-process lock in {@link FederationSyncStateStore.writeNow} provides the
 * atomicity that guarantees `base` is the latest committed state (closing the
 * write-OVERLAP window), and this monotonic fold then makes the combine safe and
 * keeps single-process / non-filesystem rigs (lock-free) correct. This does NOT
 * change the trust model or the revocation semantics; it only makes the persist
 * incapable of LOSING a committed revocation/floor.
 */
function mergeSyncStateMonotonic(
  base: FederationSyncStateSnapshot,
  next: FederationSyncStateSnapshot,
): FederationSyncStateSnapshot {
  const acceptedHighWater = new Map(base.acceptedHighWater);
  for (const [senderNodeId, highWater] of next.acceptedHighWater) {
    const prior = acceptedHighWater.get(senderNodeId) ?? 0;
    acceptedHighWater.set(senderNodeId, Math.max(prior, highWater));
  }
  const revokedNodeIds = new Set(base.revokedNodeIds);
  for (const nodeId of next.revokedNodeIds) revokedNodeIds.add(nodeId);
  const revokedRootPubkeys = new Set(base.revokedRootPubkeys);
  for (const pubkey of next.revokedRootPubkeys) revokedRootPubkeys.add(pubkey);
  const appliedPolicyVersions = new Map(base.appliedPolicyVersions);
  for (const [nodeId, marker] of next.appliedPolicyVersions) {
    const prior = appliedPolicyVersions.get(nodeId);
    if (!prior || marker.version > prior.version) {
      appliedPolicyVersions.set(nodeId, { ...marker });
    }
  }
  // PR-A (durable fleet membership): GROW-ONLY union of the node roster. A node
  // id present on EITHER side is kept, so folding a stale/older `next` over a
  // fresher `base` (or vice versa) can NEVER DROP a node -> the paid node-count
  // never spuriously shrinks across a merge/restart. This mirrors the revoked-
  // set union above; the billing-correct active count is this grow-only roster
  // MINUS the grow-only `revokedNodeIds`. On a per-id collision we keep the
  // entry with the higher `last_sync.last_sequence` (the more-recently-advanced
  // view), preferring `next` on a tie, so the merge is deterministic and never
  // regresses a node's freshness. Node departure is ONLY via eviction (union
  // into `revokedNodeIds`), so grow-only here does not over-count.
  const nodes = new Map(
    [...base.nodes].map(([nodeId, node]) => [nodeId, cloneNodeView(node)]),
  );
  for (const [nodeId, nextNode] of next.nodes) {
    const priorNode = nodes.get(nodeId);
    if (!priorNode || nextNode.last_sync.last_sequence >= priorNode.last_sync.last_sequence) {
      nodes.set(nodeId, cloneNodeView(nextNode));
    }
  }
  return {
    acceptedHighWater,
    outboundHighWater: Math.max(base.outboundHighWater, next.outboundHighWater),
    revokedNodeIds,
    highestEvictionSerial: Math.max(
      base.highestEvictionSerial,
      next.highestEvictionSerial,
    ),
    revokedRootPubkeys,
    highestRevocationSerial: Math.max(
      base.highestRevocationSerial,
      next.highestRevocationSerial,
    ),
    operatorPolicy: newerPolicy(base.operatorPolicy, next.operatorPolicy),
    appliedPolicyVersions,
    nodes,
    // The guardian revocation requirement is operator CONFIG, not grow-only
    // security state: it can be upgraded, re-pinned, OR cleared (disable). A
    // grow-only union would wrongly make it un-clearable, so we cannot union it.
    // But it is NOT single-writer: the `rotate-root --compromised` CLI (in
    // federation-rotate-root.ts) ALSO persists this blob, doing an unlocked
    // load() then persist() that carries a STALE copy of this field (it only
    // mutates the revoked-root set + serial). A naive last-writer-wins here would
    // let that stale CLI persist silently CLOBBER a requirement the dashboard set
    // concurrently, reverting a Tier-1 setting (down to null, or back to an old
    // roster). We resolve with a MONOTONIC GENERATION counter (mirrors the serial
    // floors): keep the value carrying the HIGHER generation. A stale writer's
    // lower generation can never lower or clobber a fresher on-disk value; the
    // store's locked read-modify-write re-reads the on-disk generation, so the
    // fresher value always wins the merge regardless of interleaving.
    //
    // F1 E1: guardianBreakGlass travels under the SAME generation (see that
    // field's doc for why every break-glass transition MUST bump it), so the
    // exact same selector resolves both fields atomically - they can never
    // diverge across a rotate-root merge (H1 fix).
    ...selectGuardianRevocationRequirementByGeneration(base, next),
    // F1 E1: guardianDisableNonce is a Math.max FLOOR (same treatment as
    // highestEvictionSerial), independent of the generation selector. It exists
    // so a burned nonce can never regress even if a break-glass sub-object is
    // momentarily absent (e.g. just after completion, before the next
    // generation-carried write); the AUTHORITATIVE live nonce while a
    // break-glass is armed is `guardianBreakGlass.nonce` (H2 fix - the two
    // cannot disagree because both derive from the same monotonically-bumped
    // source of truth in the dashboard).
    guardianDisableNonce: Math.max(base.guardianDisableNonce, next.guardianDisableNonce),
    // FIX 1: the dedicated superseded-lowering high-water is a Math.max FLOOR,
    // independent of the generation selector, exactly like guardianDisableNonce.
    // A stale cross-process writer can never regress it below an already-
    // superseded lowering's nonce.
    guardianLoweredHighWater: Math.max(
      base.guardianLoweredHighWater,
      next.guardianLoweredHighWater,
    ),
  };
}

/**
 * Choose the guardian revocation requirement + its generation + its in-flight
 * break-glass state, ALL THREE, by the HIGHER generation counter. On a tie
 * (neither writer bumped the generation) the values are identical, so `base`
 * is kept deterministically. This is the stale-clobber guard: `base` is the
 * freshly re-read on-disk state and `next` is the caller's (possibly stale)
 * snapshot; a stale `next` carries an OLD generation and loses.
 *
 * F1 E1 (H1 fix): `guardianBreakGlass` is folded into this SAME selector
 * rather than merged independently, because it is not grow-only either (armed
 * -> cleared is a valid transition) and it must never decouple from the
 * generation integer. Every break-glass-mutating call site in dashboard.ts
 * (initiate/veto/cancel/complete) bumps
 * `_federationGuardianRevocationRequirementGeneration` in the SAME set as it
 * mutates `_federationGuardianBreakGlass`, exactly mirroring how the setter
 * already bumps the generation on every requirement change - so a rotate-root
 * CLI persist carrying a stale (lower-generation) break-glass snapshot always
 * loses to a concurrently-committed dashboard transition, and can never revive
 * a cancelled/completed countdown nor silently drop an armed one.
 */
function selectGuardianRevocationRequirementByGeneration(
  base: FederationSyncStateSnapshot,
  next: FederationSyncStateSnapshot,
): {
  guardianRevocationRequirement: GuardianRevocationRequirement | null;
  guardianRevocationRequirementGeneration: number;
  guardianBreakGlass: BreakGlassState | null;
} {
  const baseGen = base.guardianRevocationRequirementGeneration;
  const nextGen = next.guardianRevocationRequirementGeneration;
  const winner = nextGen > baseGen ? next : base;
  return {
    guardianRevocationRequirement: cloneGuardianRevocationRequirement(
      winner.guardianRevocationRequirement,
    ),
    guardianRevocationRequirementGeneration: Math.max(baseGen, nextGen),
    guardianBreakGlass: cloneBreakGlassState(winner.guardianBreakGlass),
  };
}

function decodeSyncState(value: unknown): FederationSyncStateSnapshot {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new FederationSyncStateStoreError("record is not an object");
  }
  const obj = value as Record<string, unknown>;
  if (obj.v !== 1) {
    throw new FederationSyncStateStoreError(
      `unsupported record version: ${String(obj.v)}`,
    );
  }

  const acceptedHighWater = decodeAcceptedHighWater(obj.accepted_high_water);
  const outboundHighWater = decodeNonNegativeInt(
    obj.outbound_high_water,
    "outbound_high_water",
  );
  const revokedNodeIds = decodeRevokedNodeIds(obj.revoked_node_ids);
  const highestEvictionSerial = decodeNonNegativeInt(
    obj.highest_eviction_serial,
    "highest_eviction_serial",
  );
  // Slice 3c-1 fields are OPTIONAL on read (a pre-3c-1 v1 record omits them);
  // absent -> empty/zero (NOT a corruption). PRESENT-but-malformed THROWS (the
  // same fail-closed-on-corrupt contract: never accept a half-decoded blob).
  const revokedRootPubkeys = decodeRevokedRootPubkeys(obj.revoked_root_pubkeys);
  const highestRevocationSerial =
    obj.highest_revocation_serial === undefined
      ? 0
      : decodeNonNegativeInt(
          obj.highest_revocation_serial,
          "highest_revocation_serial",
        );
  const operatorPolicy = decodeOptionalAppliedPolicyVersion(obj.operator_policy);
  const appliedPolicyVersions = decodeAppliedPolicyVersions(
    obj.applied_policy_versions,
  );
  // PR-A: OPTIONAL on read (a pre-PR-A v1 record omits it) -> the empty roster,
  // exactly today's post-reboot behavior. PRESENT-but-malformed THROWS (the
  // same fail-closed-on-corrupt contract every other optional field honors).
  const nodes = decodeNodeRoster(obj.nodes);
  // Item-6 field is OPTIONAL on read (a pre-item-6 v1 record omits it). Absent OR
  // null -> no requirement configured. PRESENT-but-malformed THROWS via
  // decodeGuardianRevocationRequirement (same fail-closed-on-corrupt contract).
  // The at-rest form carries the SIGNED roster verbatim; the master-signature
  // re-verification against the pinned master is done by the consumer on
  // rehydrate (the pinned master is not available at pure-decode time).
  const persistedRequirement = decodeGuardianRevocationRequirement(
    obj.guardian_revocation_requirement,
  );
  const guardianRevocationRequirement =
    persistedRequirement === undefined
      ? null
      : projectPersistedRequirement(persistedRequirement);
  // Optional on read: a pre-item-6 record omits the generation -> 0.
  // PRESENT-but-malformed THROWS (same fail-closed-on-corrupt contract).
  const guardianRevocationRequirementGeneration =
    obj.guardian_revocation_requirement_generation === undefined
      ? 0
      : decodeNonNegativeInt(
          obj.guardian_revocation_requirement_generation,
          "guardian_revocation_requirement_generation",
        );
  // F1 E1 fields. Optional on read (a pre-E1 record omits them). Absent ->
  // nonce 0 / no break-glass armed (NOT a corruption). PRESENT-but-malformed
  // THROWS (same fail-closed-on-corrupt contract as every other optional field
  // in this record).
  const guardianDisableNonce =
    obj.guardian_disable_nonce === undefined
      ? 0
      : decodeNonNegativeInt(obj.guardian_disable_nonce, "guardian_disable_nonce");
  // FIX 1: optional on read (a pre-fix record omits it -> 0). PRESENT-but-
  // malformed THROWS (same fail-closed-on-corrupt contract as every other
  // optional field in this record).
  const guardianLoweredHighWater =
    obj.guardian_lowered_high_water === undefined
      ? 0
      : decodeNonNegativeInt(
          obj.guardian_lowered_high_water,
          "guardian_lowered_high_water",
        );
  const guardianBreakGlass = decodeBreakGlassState(obj.guardian_break_glass);

  return {
    acceptedHighWater,
    outboundHighWater,
    revokedNodeIds,
    highestEvictionSerial,
    revokedRootPubkeys,
    highestRevocationSerial,
    operatorPolicy,
    appliedPolicyVersions,
    nodes,
    guardianRevocationRequirement,
    guardianRevocationRequirementGeneration,
    guardianDisableNonce,
    guardianLoweredHighWater,
    guardianBreakGlass,
  };
}

function encodeBreakGlassState(state: BreakGlassState): PersistedBreakGlassState {
  return {
    nonce: state.nonce,
    intent: state.intent,
    target_m: state.targetM,
    initiated_at: state.initiatedAt,
    completes_at: state.completesAt,
    delay_ms: state.delayMs,
  };
}

function decodeBreakGlassState(value: unknown): BreakGlassState | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new FederationSyncStateStoreError("guardian_break_glass is not an object");
  }
  const obj = value as Record<string, unknown>;
  const nonce = obj.nonce;
  const intent = obj.intent;
  const targetM = obj.target_m;
  const initiatedAt = obj.initiated_at;
  const completesAt = obj.completes_at;
  const delayMs = obj.delay_ms;
  if (typeof nonce !== "number" || !Number.isSafeInteger(nonce) || nonce < 0) {
    throw new FederationSyncStateStoreError("guardian_break_glass nonce is invalid");
  }
  if (intent !== "disable" && intent !== "lower") {
    throw new FederationSyncStateStoreError("guardian_break_glass intent is invalid");
  }
  if (targetM !== null && (typeof targetM !== "number" || !Number.isSafeInteger(targetM))) {
    throw new FederationSyncStateStoreError("guardian_break_glass target_m is invalid");
  }
  if (typeof initiatedAt !== "string" || initiatedAt.length === 0) {
    throw new FederationSyncStateStoreError(
      "guardian_break_glass initiated_at is invalid",
    );
  }
  if (typeof completesAt !== "string" || completesAt.length === 0) {
    throw new FederationSyncStateStoreError(
      "guardian_break_glass completes_at is invalid",
    );
  }
  if (typeof delayMs !== "number" || !Number.isSafeInteger(delayMs) || delayMs < 0) {
    throw new FederationSyncStateStoreError("guardian_break_glass delay_ms is invalid");
  }
  return {
    nonce,
    intent,
    targetM: targetM ?? null,
    initiatedAt,
    completesAt,
    delayMs,
  };
}

/**
 * Project a structurally-decoded persisted requirement into the live
 * {@link GuardianRevocationRequirement} shape WITHOUT verifying the master
 * signature (the pinned master is not available here). The consumer
 * re-verifies the roster on rehydrate and FAILS CLOSED if it does not verify;
 * carrying the roster verbatim through the snapshot is what lets that
 * re-verification happen. The signature bytes ride along in `roster`.
 */
function projectPersistedRequirement(
  persisted: PersistedGuardianRevocationRequirement,
): GuardianRevocationRequirement {
  const requirement: GuardianRevocationRequirement = {
    roster: { ...persisted.roster },
  };
  if (persisted.expected_roster_version !== undefined) {
    requirement.expectedRosterVersion = persisted.expected_roster_version;
  }
  // Carry the lowered-threshold record verbatim (its own master signature rides
  // along) so the consumer can re-verify it against the pinned master on
  // rehydrate, exactly like the roster's `master_signature`. Absent -> effective
  // M = roster.m.
  if (persisted.lowered_threshold !== undefined) {
    requirement.loweredThreshold = {
      body: { ...persisted.lowered_threshold.body },
      signature: persisted.lowered_threshold.signature,
    };
  }
  return requirement;
}

function newerPolicy(
  base: FederationAppliedPolicyVersion | null,
  next: FederationAppliedPolicyVersion | null,
): FederationAppliedPolicyVersion | null {
  if (!base) return next ? { ...next } : null;
  if (!next) return { ...base };
  return next.version > base.version ? { ...next } : { ...base };
}

function encodeAppliedPolicyVersion(
  marker: FederationAppliedPolicyVersion,
): PersistedAppliedPolicyVersion {
  return { ...marker };
}

function decodeOptionalAppliedPolicyVersion(
  value: unknown,
): FederationAppliedPolicyVersion | null {
  if (value === undefined || value === null) return null;
  return decodeAppliedPolicyVersion(value);
}

function decodeAppliedPolicyVersions(
  value: unknown,
): Map<string, FederationAppliedPolicyVersion> {
  if (value === undefined) return new Map();
  if (!Array.isArray(value)) {
    throw new FederationSyncStateStoreError(
      "applied_policy_versions is not an array",
    );
  }
  const out = new Map<string, FederationAppliedPolicyVersion>();
  for (const pair of value) {
    if (!Array.isArray(pair) || pair.length !== 2) {
      throw new FederationSyncStateStoreError(
        "applied_policy_versions entry is not a [string, object] pair",
      );
    }
    const [nodeId, marker] = pair as [unknown, unknown];
    if (typeof nodeId !== "string" || nodeId.length === 0) {
      throw new FederationSyncStateStoreError(
        "applied_policy_versions node id is invalid",
      );
    }
    out.set(nodeId, decodeAppliedPolicyVersion(marker));
  }
  return out;
}

function decodeAppliedPolicyVersion(
  value: unknown,
): FederationAppliedPolicyVersion {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new FederationSyncStateStoreError("applied policy marker is not an object");
  }
  const obj = value as Record<string, unknown>;
  const version = decodeNonNegativeInt(obj.version, "applied policy version");
  const hash = obj.hash;
  const hashAlgorithm = obj.hash_algorithm;
  const appliedAt = obj.applied_at;
  const sourceEventId = obj.source_event_id;
  if (version < 1) {
    throw new FederationSyncStateStoreError("applied policy version is invalid");
  }
  if (typeof hash !== "string" || hash.length === 0) {
    throw new FederationSyncStateStoreError("applied policy hash is invalid");
  }
  if (hashAlgorithm !== "sha256-base64url") {
    throw new FederationSyncStateStoreError(
      "applied policy hash_algorithm is invalid",
    );
  }
  if (typeof appliedAt !== "string" || appliedAt.length === 0) {
    throw new FederationSyncStateStoreError("applied policy applied_at is invalid");
  }
  if (typeof sourceEventId !== "string" || sourceEventId.length === 0) {
    throw new FederationSyncStateStoreError(
      "applied policy source_event_id is invalid",
    );
  }
  return {
    version,
    hash,
    hash_algorithm: hashAlgorithm,
    applied_at: appliedAt,
    source_event_id: sourceEventId,
  };
}

/**
 * PR-A: encode a live {@link FederationNodeView} into the MINIMAL durable form.
 * The trust-boundary posture is dropped (re-derived from `node_mode` on load),
 * and no secret / private key is ever present in a node view to begin with.
 */
function encodeFederationNode(node: FederationNodeView): PersistedFederationNode {
  return {
    node_id: node.node_id,
    label: node.label,
    attestation_status: node.attestation_status,
    node_mode: node.node_mode,
    first_seen: node.first_seen,
    last_seen: node.last_seen,
    last_sync: {
      received_at: node.last_sync.received_at,
      sent_at: node.last_sync.sent_at,
      last_sequence: node.last_sync.last_sequence,
    },
    applied_policy: {
      version: node.applied_policy.version,
      hash: node.applied_policy.hash,
      hash_algorithm: node.applied_policy.hash_algorithm,
      applied_at: node.applied_policy.applied_at,
      source_event_id: node.applied_policy.source_event_id,
    },
  };
}

/**
 * PR-A: decode the persisted grow-only node roster back into
 * `Map<nodeId, FederationNodeView>`. Absent (a pre-PR-A v1 record) -> the empty
 * roster, the legitimate back-compat default (today's post-reboot behavior).
 * PRESENT-but-malformed THROWS (fail-closed-on-corrupt, same as every other
 * optional field). Each node's trust-boundary posture is RE-DERIVED from its
 * `node_mode` so the roster the count + console consume is byte-consistent with
 * a live upsert.
 */
function decodeNodeRoster(value: unknown): Map<string, FederationNodeView> {
  if (value === undefined) return new Map();
  if (!Array.isArray(value)) {
    throw new FederationSyncStateStoreError("nodes is not an array");
  }
  const out = new Map<string, FederationNodeView>();
  for (const pair of value) {
    if (!Array.isArray(pair) || pair.length !== 2) {
      throw new FederationSyncStateStoreError(
        "nodes entry is not a [string, object] pair",
      );
    }
    const [nodeId, node] = pair as [unknown, unknown];
    if (typeof nodeId !== "string" || nodeId.length === 0) {
      throw new FederationSyncStateStoreError("nodes node id is invalid");
    }
    out.set(nodeId, decodeFederationNode(nodeId, node));
  }
  return out;
}

const VALID_ATTESTATION_STATUS = new Set<FederationNodeView["attestation_status"]>([
  "verified",
  "pending",
  "failed",
  "unknown",
]);

const VALID_NODE_MODE = new Set<NodeModeForPosture>([
  "local",
  "operator_cloud",
  "sovereign_tee",
  "unknown",
]);

function decodeFederationNode(
  nodeId: string,
  value: unknown,
): FederationNodeView {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new FederationSyncStateStoreError("node is not an object");
  }
  const obj = value as Record<string, unknown>;
  const label = obj.label;
  if (label !== null && typeof label !== "string") {
    throw new FederationSyncStateStoreError("node label is invalid");
  }
  const attestationStatus = obj.attestation_status;
  if (
    typeof attestationStatus !== "string" ||
    !VALID_ATTESTATION_STATUS.has(
      attestationStatus as FederationNodeView["attestation_status"],
    )
  ) {
    throw new FederationSyncStateStoreError("node attestation_status is invalid");
  }
  const nodeMode = obj.node_mode;
  if (
    typeof nodeMode !== "string" ||
    !VALID_NODE_MODE.has(nodeMode as NodeModeForPosture)
  ) {
    throw new FederationSyncStateStoreError("node node_mode is invalid");
  }
  const firstSeen = obj.first_seen;
  if (typeof firstSeen !== "string" || firstSeen.length === 0) {
    throw new FederationSyncStateStoreError("node first_seen is invalid");
  }
  const lastSeen = obj.last_seen;
  if (typeof lastSeen !== "string" || lastSeen.length === 0) {
    throw new FederationSyncStateStoreError("node last_seen is invalid");
  }
  const lastSync = decodeNodeLastSync(obj.last_sync);
  const appliedPolicy = decodeNodeAppliedPolicy(obj.applied_policy);
  // Re-derive the trust-boundary posture from node_mode, exactly like a live
  // upsert (buildFederationNodeUpsert). verifiedTeeEvidence is false here (the
  // durable record never carries TEE evidence; a sovereign_tee node re-attests
  // at runtime), so the rehydrated posture is the honest "unverified" shape.
  const posture = deriveNodePosture({
    nodeMode: nodeMode as NodeModeForPosture,
    verifiedTeeEvidence: false,
  });
  return {
    node_id: nodeId,
    label: label ?? null,
    attestation_status: attestationStatus as FederationNodeView["attestation_status"],
    ...posture,
    first_seen: firstSeen,
    last_seen: lastSeen,
    last_sync: lastSync,
    applied_policy: appliedPolicy,
  };
}

function decodeNodeLastSync(value: unknown): FederationNodeView["last_sync"] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new FederationSyncStateStoreError("node last_sync is not an object");
  }
  const obj = value as Record<string, unknown>;
  const receivedAt = obj.received_at;
  if (receivedAt !== null && typeof receivedAt !== "string") {
    throw new FederationSyncStateStoreError("node last_sync.received_at is invalid");
  }
  const sentAt = obj.sent_at;
  if (sentAt !== null && typeof sentAt !== "string") {
    throw new FederationSyncStateStoreError("node last_sync.sent_at is invalid");
  }
  const lastSequence = obj.last_sequence;
  if (
    typeof lastSequence !== "number" ||
    !Number.isSafeInteger(lastSequence) ||
    lastSequence < 0
  ) {
    throw new FederationSyncStateStoreError("node last_sync.last_sequence is invalid");
  }
  return {
    received_at: receivedAt ?? null,
    sent_at: sentAt ?? null,
    last_sequence: lastSequence,
  };
}

function decodeNodeAppliedPolicy(
  value: unknown,
): FederationNodeView["applied_policy"] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new FederationSyncStateStoreError("node applied_policy is not an object");
  }
  const obj = value as Record<string, unknown>;
  const version = obj.version;
  if (
    version !== null &&
    (typeof version !== "number" || !Number.isSafeInteger(version) || version < 0)
  ) {
    throw new FederationSyncStateStoreError("node applied_policy.version is invalid");
  }
  const hash = obj.hash;
  if (hash !== null && typeof hash !== "string") {
    throw new FederationSyncStateStoreError("node applied_policy.hash is invalid");
  }
  const hashAlgorithm = obj.hash_algorithm;
  if (hashAlgorithm !== null && typeof hashAlgorithm !== "string") {
    throw new FederationSyncStateStoreError(
      "node applied_policy.hash_algorithm is invalid",
    );
  }
  const appliedAt = obj.applied_at;
  if (appliedAt !== null && typeof appliedAt !== "string") {
    throw new FederationSyncStateStoreError("node applied_policy.applied_at is invalid");
  }
  const sourceEventId = obj.source_event_id;
  if (sourceEventId !== null && typeof sourceEventId !== "string") {
    throw new FederationSyncStateStoreError(
      "node applied_policy.source_event_id is invalid",
    );
  }
  return {
    version: version ?? null,
    hash: hash ?? null,
    hash_algorithm: hashAlgorithm ?? null,
    applied_at: appliedAt ?? null,
    source_event_id: sourceEventId ?? null,
  };
}

function decodeAcceptedHighWater(value: unknown): Map<string, number> {
  if (!Array.isArray(value)) {
    throw new FederationSyncStateStoreError("accepted_high_water is not an array");
  }
  const out = new Map<string, number>();
  for (const pair of value) {
    if (!Array.isArray(pair) || pair.length !== 2) {
      throw new FederationSyncStateStoreError(
        "accepted_high_water entry is not a [string, number] pair",
      );
    }
    const [nodeId, highWater] = pair as [unknown, unknown];
    if (typeof nodeId !== "string" || nodeId.length === 0) {
      throw new FederationSyncStateStoreError(
        "accepted_high_water sender id is invalid",
      );
    }
    if (
      typeof highWater !== "number" ||
      !Number.isSafeInteger(highWater) ||
      highWater < 0
    ) {
      throw new FederationSyncStateStoreError(
        "accepted_high_water value is invalid",
      );
    }
    out.set(nodeId, highWater);
  }
  return out;
}

function decodeRevokedNodeIds(value: unknown): Set<string> {
  if (!Array.isArray(value)) {
    throw new FederationSyncStateStoreError("revoked_node_ids is not an array");
  }
  const out = new Set<string>();
  for (const nodeId of value) {
    if (typeof nodeId !== "string" || nodeId.length === 0) {
      throw new FederationSyncStateStoreError("revoked node id is invalid");
    }
    out.add(nodeId);
  }
  return out;
}

function decodeRevokedRootPubkeys(value: unknown): Set<string> {
  // Absent (pre-3c-1 record) -> empty, the legitimate back-compat default.
  if (value === undefined) return new Set();
  if (!Array.isArray(value)) {
    throw new FederationSyncStateStoreError("revoked_root_pubkeys is not an array");
  }
  const out = new Set<string>();
  for (const pubkey of value) {
    if (typeof pubkey !== "string" || pubkey.length === 0) {
      throw new FederationSyncStateStoreError("revoked root pubkey is invalid");
    }
    out.add(pubkey);
  }
  return out;
}

function decodeNonNegativeInt(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new FederationSyncStateStoreError(`${label} is invalid`);
  }
  return value;
}

/** Non-throwing non-negative-safe-integer check for the anchor tri-state read. */
function isNonNegSafeInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function publicErrorReason(err: unknown): string {
  if (err instanceof FederationSyncStateStoreError) return err.message;
  if (err instanceof SyntaxError) return "malformed JSON";
  return "decrypt_or_parse_failed";
}
