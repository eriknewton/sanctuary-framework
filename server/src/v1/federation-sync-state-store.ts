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
import { bytesToString, stringToBytes } from "../core/encoding.js";
import type { FederationAppliedPolicyVersion } from "./federation-policy-bundle.js";
import {
  decodeGuardianRevocationRequirement,
  encodeGuardianRevocationRequirement,
  type PersistedGuardianRevocationRequirement,
} from "./federation-guardian-revocation-policy.js";
import type { GuardianRevocationRequirement } from "./federation-revocation-guardian-gate.js";

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
 * At-rest key (in the SAME `_federation` namespace, encrypted under the SAME
 * `federation-sync-state` purpose key as the main sync-state record) for the
 * durable PROVISIONING BASELINE SENTINEL (F3 residual close).
 *
 * ADDITIVE + FROZEN at-rest key. It carries NO secret material and NO grow-only
 * security state - only a tiny "this fortress was federation-provisioned and its
 * sync-state baseline was written" marker (a format version + an ISO timestamp).
 * It is written ONCE, idempotently, when the durable sync-state store is first
 * wired on a provisioned fortress, and is never mutated afterward.
 *
 * Why a SEPARATE record from the sync-state blob: it is the independent,
 * per-fortress witness that a baseline WAS provisioned. It lets the boot path
 * distinguish the two cases the main record's `raw === null -> empty` contract
 * collapses:
 *
 *   - sentinel ABSENT + main record absent -> genuinely fresh first boot: write
 *     BOTH (baseline record + sentinel) and serve empty (NEVER brick the first
 *     sync);
 *   - sentinel PRESENT + main record absent -> the main record was DELETED out of
 *     band AFTER a baseline was provisioned: fail closed (this now covers a
 *     node-eviction-only history, which has no independent trust-root witness).
 *
 * It is encrypted under the EXISTING `federation-sync-state` label (NO new HKDF
 * label, NO new store, NO new rotation-recipe entry): the master-rotation
 * `_federation` recipe re-wraps every purpose-encrypted record under that label,
 * so this second record rotates with the first. Being a proper AES-256-GCM
 * payload (not a plaintext marker) is REQUIRED - the rotation preflight rejects
 * any non-encrypted record under `_federation`.
 */
export const FEDERATION_SYNC_STATE_BASELINE_SENTINEL_KEY =
  "sync-state-baseline-v1";

/**
 * Lockfile name for the cross-process advisory lock that serializes the
 * idempotent read-check-write of the baseline sentinel + baseline record in
 * {@link FederationSyncStateStore.provisionBaselineIfAbsent}. Distinct from the
 * sync-state write lock so a boot-time provisioning write never contends with a
 * concurrent sync persist on the SAME lock (which is non-reentrant).
 */
export const FEDERATION_SYNC_STATE_BASELINE_LOCK_FILE =
  ".sync-state-baseline.lock";

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
}

/**
 * At-rest form of the provisioning baseline sentinel. Carries NO security state,
 * only a format version + the ISO timestamp the baseline was provisioned. Its
 * mere PRESENCE (decrypted or not) is the signal; the fields are informational.
 */
interface PersistedBaselineSentinel {
  v: 1;
  provisioned_at: string;
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
    guardianRevocationRequirement: null,
    guardianRevocationRequirementGeneration: 0,
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

  /**
   * Existence probe for the durable PROVISIONING BASELINE SENTINEL, WITHOUT
   * decrypting it. Returns true when the sentinel blob is physically present at
   * (`namespace`, `FEDERATION_SYNC_STATE_BASELINE_SENTINEL_KEY`), false when it
   * is absent. A read error propagates so the caller fails closed rather than
   * mis-reading a transient backend fault as "no baseline provisioned".
   *
   * This is the independent witness the F3 deletion latch consults: a sentinel
   * that is PRESENT while the main sync-state record is ABSENT proves the record
   * was deleted AFTER a baseline was provisioned (the two records are written
   * together and only an out-of-band delete can separate them), so the caller
   * fails closed even when the only prior revocation history is node evictions
   * (which leave no independent trust-root witness).
   */
  async baselineSentinelExists(): Promise<boolean> {
    const raw = await this.storage.read(
      this.namespace,
      FEDERATION_SYNC_STATE_BASELINE_SENTINEL_KEY,
    );
    return raw !== null;
  }

  /**
   * Idempotently establish the provisioning baseline: under a cross-process
   * lock, if EITHER the sentinel or the main sync-state record is absent, write
   * whichever is missing (the sentinel marker AND an empty baseline sync-state
   * record). A no-op when both are already present.
   *
   * Returns `true` when this call WROTE the baseline (the first-boot provisioning
   * case), `false` when both records already existed (nothing written). The
   * caller uses the return to distinguish "I just provisioned the baseline on a
   * genuinely fresh fortress" (serve empty, never brick the first sync) from
   * "the baseline was already there" (normal load).
   *
   * FAIL-SAFE ORDERING (non-destructive): the empty baseline sync-state record is
   * written FIRST, then the sentinel. So the sentinel is never present without a
   * sync-state record behind it; a crash between the two writes leaves
   * "record-present, sentinel-absent", which the next boot repairs (writes the
   * missing sentinel) rather than mis-latching. The baseline sync-state write
   * goes through the normal locked, MONOTONIC-MERGE {@link persist} of an EMPTY
   * snapshot, so if a real record somehow already exists it is folded over (never
   * clobbered) - the empty snapshot cannot lower any floor or drop any revocation.
   *
   * THROWS on any lock/read/write/encrypt failure so the caller fails closed
   * rather than proceeding as if a baseline were durably committed.
   */
  async provisionBaselineIfAbsent(): Promise<boolean> {
    let wrote = false;
    await withCrossProcessLock(
      this.storage,
      this.namespace,
      FEDERATION_SYNC_STATE_BASELINE_LOCK_FILE,
      async () => {
        const recordPresent =
          (await this.storage.read(this.namespace, this.recordKey)) !== null;
        const sentinelPresent =
          (await this.storage.read(
            this.namespace,
            FEDERATION_SYNC_STATE_BASELINE_SENTINEL_KEY,
          )) !== null;
        if (recordPresent && sentinelPresent) return;
        // Record first (fail-safe ordering: never a sentinel without a record).
        // persist() re-reads + monotonically merges under its OWN lock, so an
        // empty baseline written over a pre-existing real record is a no-op fold,
        // never a downgrade. We only need to (re)write the record if it is
        // absent; if it is present we leave the committed state untouched.
        if (!recordPresent) {
          await this.persist(emptyFederationSyncState());
        }
        if (!sentinelPresent) {
          await this.writeBaselineSentinel();
        }
        wrote = true;
      },
    );
    return wrote;
  }

  /**
   * Encrypt + write the baseline sentinel marker (format version + provisioning
   * timestamp) under the shared `federation-sync-state` purpose key. Internal to
   * {@link provisionBaselineIfAbsent} (called while the baseline lock is held).
   * A proper AES-256-GCM payload so the master-rotation `_federation` recipe
   * re-wraps it under the same label as the main record.
   */
  private async writeBaselineSentinel(): Promise<void> {
    const marker: PersistedBaselineSentinel = {
      v: 1,
      provisioned_at: new Date().toISOString(),
    };
    const serialized = stringToBytes(JSON.stringify(marker));
    try {
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        this.namespace,
        FEDERATION_SYNC_STATE_BASELINE_SENTINEL_KEY,
        stringToBytes(JSON.stringify(encrypted)),
      );
    } finally {
      serialized.fill(0);
    }
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
   *      before either writes); the lock is bounded + breaks provably-stale holders
   *      so it cannot deadlock, and FAILS CLOSED (throws) on sustained contention.
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
          guardian_revocation_requirement: merged.guardianRevocationRequirement
            ? encodeGuardianRevocationRequirement(
                merged.guardianRevocationRequirement,
              )
            : null,
          guardian_revocation_requirement_generation:
            merged.guardianRevocationRequirementGeneration,
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
    guardianRevocationRequirement: cloneGuardianRevocationRequirement(
      (snapshot as Partial<FederationSyncStateSnapshot>)
        .guardianRevocationRequirement ?? null,
    ),
    guardianRevocationRequirementGeneration:
      (snapshot as Partial<FederationSyncStateSnapshot>)
        .guardianRevocationRequirementGeneration ?? 0,
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
    ...selectGuardianRevocationRequirementByGeneration(base, next),
  };
}

/**
 * Choose the guardian revocation requirement + its generation by the HIGHER
 * generation counter. On a tie (neither writer bumped the generation) the values
 * are identical, so `base` is kept deterministically. This is the stale-clobber
 * guard: `base` is the freshly re-read on-disk state and `next` is the caller's
 * (possibly stale) snapshot; a stale `next` carries an OLD generation and loses.
 */
function selectGuardianRevocationRequirementByGeneration(
  base: FederationSyncStateSnapshot,
  next: FederationSyncStateSnapshot,
): {
  guardianRevocationRequirement: GuardianRevocationRequirement | null;
  guardianRevocationRequirementGeneration: number;
} {
  const baseGen = base.guardianRevocationRequirementGeneration;
  const nextGen = next.guardianRevocationRequirementGeneration;
  const winner = nextGen > baseGen ? next : base;
  return {
    guardianRevocationRequirement: cloneGuardianRevocationRequirement(
      winner.guardianRevocationRequirement,
    ),
    guardianRevocationRequirementGeneration: Math.max(baseGen, nextGen),
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

  return {
    acceptedHighWater,
    outboundHighWater,
    revokedNodeIds,
    highestEvictionSerial,
    revokedRootPubkeys,
    highestRevocationSerial,
    operatorPolicy,
    appliedPolicyVersions,
    guardianRevocationRequirement,
    guardianRevocationRequirementGeneration,
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

function publicErrorReason(err: unknown): string {
  if (err instanceof FederationSyncStateStoreError) return err.message;
  if (err instanceof SyntaxError) return "malformed JSON";
  return "decrypt_or_parse_failed";
}
