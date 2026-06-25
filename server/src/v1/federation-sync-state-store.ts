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
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { bytesToString, stringToBytes } from "../core/encoding.js";

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
   * includes it. Adding a field to an existing v1 blob is additive — the AEAD
   * tag still authenticates the whole record, so a tampered/truncated blob still
   * fails closed.
   */
  revoked_root_pubkeys?: string[];
  /** Highest accepted revocation serial (optional for the same back-compat reason). */
  highest_revocation_serial?: number;
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
   * Persist the whole snapshot (the caller's live state is the source of truth).
   * THROWS on any encrypt/write failure so the caller can fail closed: a write
   * whose persist throws MUST deny rather than act on state that was not durably
   * committed.
   */
  async persist(snapshot: FederationSyncStateSnapshot): Promise<void> {
    const copy = cloneSnapshot(snapshot);
    const run = this.writeChain.then(() => this.writeNow(copy));
    this.writeChain = run.catch(() => {});
    return run;
  }

  private async writeNow(snapshot: FederationSyncStateSnapshot): Promise<void> {
    const persisted: PersistedSyncState = {
      v: 1,
      accepted_high_water: [...snapshot.acceptedHighWater],
      outbound_high_water: snapshot.outboundHighWater,
      revoked_node_ids: [...snapshot.revokedNodeIds],
      highest_eviction_serial: snapshot.highestEvictionSerial,
      revoked_root_pubkeys: [...snapshot.revokedRootPubkeys],
      highest_revocation_serial: snapshot.highestRevocationSerial,
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
  }
}

function cloneSnapshot(
  snapshot: FederationSyncStateSnapshot,
): FederationSyncStateSnapshot {
  return {
    acceptedHighWater: new Map(snapshot.acceptedHighWater),
    outboundHighWater: snapshot.outboundHighWater,
    revokedNodeIds: new Set(snapshot.revokedNodeIds),
    highestEvictionSerial: snapshot.highestEvictionSerial,
    revokedRootPubkeys: new Set(snapshot.revokedRootPubkeys),
    highestRevocationSerial: snapshot.highestRevocationSerial,
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

  return {
    acceptedHighWater,
    outboundHighWater,
    revokedNodeIds,
    highestEvictionSerial,
    revokedRootPubkeys,
    highestRevocationSerial,
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
