/**
 * Encrypted persistence for the v1 HTTP federation JOINER trust root.
 *
 * A JOINER is the second machine in a federation: it ran a real join ceremony
 * against an issuer fortress and holds ONLY what that ceremony legitimately
 * yields. Unlike the issuer store (`federation-trust-root-store.ts`), a joiner
 * record is a strict NON-ISSUER record: it carries the pinned master PUBLIC
 * key it must trust, the issuing principal cert (public), and this joiner's OWN
 * node cert + node private key. It NEVER carries the fortress master secret,
 * the master private key, or the issuing principal private key. Peer sync is
 * cert-chain-verified (`/v1/federation/sync/peer`), so a joiner derives no
 * issuer transport proofs and needs none of the issuing material.
 *
 * The `_federation/joiner-trust-root-v1` record is always stored as AES-GCM
 * ciphertext under a purpose-derived custody key (HKDF label
 * `federation-joiner-trust-root`, additive and distinct from the issuer
 * store's `federation-trust-root`). Cross-operator isolation and AEAD
 * tamper-evidence come for free from the master-derived purpose key.
 *
 * The pinned master is an OUT-OF-BAND trust anchor: it is supplied by the
 * caller, never inferred from a server response (CLAUDE.md constraint 4). The
 * store refuses to persist or load a joiner cert that does not chain to the
 * pinned master.
 *
 * Slice 3c-2 (planned-rotation joiner-adopt): `adoptFederationJoinerPlannedRoot`
 * moves a joiner from pinning K1 to pinning K2 across a PLANNED rotate-root,
 * anchoring the trust decision on the K1-signed rotation certificate (which only
 * an honest K1 could produce) and re-verifying the reissued chain against the K2
 * learned from THAT cert, never from the server response. The compromise class
 * is handled by a manual re-join (see `sanctuary federation rejoin`), which reuses
 * the shipped join ceremony and records the dead K1 into `revoked_root_pubkeys`;
 * there is deliberately NO joiner-side "adopt a compromised root" verb, because a
 * K1 holder could forge any old-key-signed adoption artifact.
 */

import { ed25519 } from "@noble/curves/ed25519";
import type { StorageBackend } from "../storage/interface.js";
import { withCrossProcessLock } from "../storage/cross-process-lock.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import {
  verifyCertChain,
  verifyPrincipalCertificate,
  verifyFederationRootRotationCertificate,
} from "./trust-root.js";
import type {
  FederationRootRotationCertificate,
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "./types.js";

export const FEDERATION_JOINER_TRUST_ROOT_NAMESPACE = "_federation";
export const FEDERATION_JOINER_TRUST_ROOT_KEY = "joiner-trust-root-v1";
export const FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO =
  "federation-joiner-trust-root";
/**
 * Advisory cross-process lock file (dotfile, NOT a `.enc` at-rest record, so it
 * never appears in `list()`) that serializes the grow-only persist
 * read-modify-write across processes. Mirrors the sync-state store's
 * `.sync-state.lock` in the same `_federation` namespace.
 */
export const FEDERATION_JOINER_TRUST_ROOT_LOCK_FILE = ".joiner-trust-root.lock";

/**
 * Field names that MUST NEVER appear in a joiner record. Their presence in a
 * decoded blob is a load-time failure, not a silent drop: a joiner that holds
 * any of these is a latent issuer-authority escalation. This is the defense-in
 * -depth check that makes "a joiner accidentally minted with issuer material"
 * a hard refusal.
 */
const FORBIDDEN_ISSUER_FIELDS: readonly string[] = [
  "master_secret",
  "master_private_key",
  "issuing_principal_private_key",
];

/**
 * The NON-ISSUER joiner record. By construction it holds NONE of the issuing
 * material (no `master_secret`, no `master_private_key`, no
 * `issuing_principal_private_key`). Even a build bug that tried to construct an
 * issuer context from this record would find the issuer accessors empty.
 */
export interface FederationJoinerTrustRootRecord {
  /** The JOINED fortress id (from the issued cert + pinned master). */
  fortress_id: string;
  /** This joiner's node id (from the issued cert). */
  node_id: string;
  /** The out-of-band trust anchor this joiner pins (PUBLIC key only). */
  pinned_master_pubkey: FortressMasterPublicKey;
  /** The issuing principal cert received from the join (PUBLIC). */
  issuing_principal_cert: PrincipalCertificate;
  /** The cert issued TO this joiner. */
  local_node_cert: NodeIdentityCertificate;
  /** This joiner's OWN node private key (generated locally at join). */
  local_node_private_key: Uint8Array;
  /**
   * Grow-only roots this joiner has cryptographically accepted as revoked.
   * Additive 3c-2 state: pre-3c-2 records omit it and decode to an empty set.
   */
  revoked_root_pubkeys?: Set<string>;
  /**
   * Highest accepted compromise root-revocation serial. Additive anti-rollback
   * floor; absent on a never-compromise-adopted joiner (zero implicitly).
   */
  highest_revocation_serial?: number;
  /**
   * Highest planned rotation-certificate serial this joiner has adopted.
   * Additive 3c-2 anti-rollback floor for the PLANNED auto-adopt path; absent on
   * a joiner that has never planned-adopted (decodes to zero). Distinct from
   * `highest_revocation_serial`: the issuer advances `rotation_serial` on a
   * planned `rotate-root --renew` and a SEPARATE revocation serial on a
   * compromise rotate, so the two floors must never be conflated. Optional so it
   * can later carry richer rotation-lineage attribution without a breaking change
   * (multi-principal headroom, design section 9.5).
   */
  adopted_rotation_serial?: number;
}

interface PersistedFederationJoinerTrustRootRecord {
  fortress_id: string;
  node_id: string;
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  local_node_cert: NodeIdentityCertificate;
  local_node_private_key: string;
  revoked_root_pubkeys?: string[];
  highest_revocation_serial?: number;
  adopted_rotation_serial?: number;
}

export class FederationJoinerTrustRootStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FederationJoinerTrustRootStoreError";
  }
}

export class FederationJoinerTrustRootStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(
      masterKey,
      FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO,
    );
  }

  async load(): Promise<FederationJoinerTrustRootRecord | null> {
    const raw = await this.storage.read(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
    );
    if (raw === null) return null;

    let plaintext: Uint8Array | null = null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      plaintext = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(plaintext)) as unknown;
      return decodePersistedRecord(parsed);
    } catch (err) {
      throw new FederationJoinerTrustRootStoreError(
        `federation joiner trust root failed to load: ${publicErrorReason(err)}`,
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  /**
   * The ONLY write path for the joiner record. There is deliberately NO public
   * raw writer: the grow-only anti-rollback invariant is STRUCTURALLY enforced,
   * not merely conventional. Under the `.joiner-trust-root.lock` cross-process
   * lock it:
   *   1. Loads the CURRENT record fail-closed (MED-1): `load()` returns null ONLY
   *      for a genuinely-absent record; a decode/transient throw is RE-THROWN,
   *      never treated as "absent" (which would let a lower floor overwrite -
   *      AGENTS.md rule 5).
   *   2. Applies the caller's `mutate(current)` to get the intended next record.
   *   3. ALWAYS enforces the grow-only anti-rollback invariant against the CURRENT
   *      on-disk record loaded UNDER THE LOCK: the revoked-root set is `current
   *      UNION next` and the compromise floor is `max(current, next)` - never
   *      dropped or lowered; a mutation that tries to LOWER the floor is refused
   *      loudly. The planned `adopted_rotation_serial` gets the SAME under-lock
   *      floor, SCOPED to the pinned lineage (F1, re-gate 2026-07-30): while the
   *      `pinned_master_pubkey` identity is unchanged the planned floor is
   *      `max(current, next)` and a strictly-lower positive serial is refused
   *      loudly; a write that MOVES the pinned master (a planned adopt's K1->K2
   *      re-pin, or a fresh join/rejoin onto a new root) is a legitimate lineage
   *      change and carries the mutator's serial verbatim, so a fresh-join
   *      reset-to-0 is never mistaken for a rollback. Read "structural" as
   *      SAME-LINEAGE monotonicity: a trusted in-process caller holding
   *      `storage` + `masterKey` can still legitimately move to a new pinned
   *      lineage (that IS a fresh join); no writer can lower the floor while
   *      keeping the pin.
   *   4. Raw-writes the merged record (`#writeRaw` re-runs full validation) and
   *      releases the lock in `finally`.
   *
   * SERIALIZATION ACCURACY: the lock is real only on a FilesystemStorage backend
   * (`withCrossProcessLock` engages the O_EXCL lockfile). On a non-filesystem
   * backend (in-memory / tests) it DEGRADES to a direct, NON-serialized run - two
   * overlapping calls there are NOT mutually excluded. That is acceptable because
   * the shipped production writer is a one-shot CLI process on FilesystemStorage;
   * non-fs rigs are single-caller test harnesses. (An in-process async mutex would
   * add defense-in-depth for non-fs multi-caller rigs but is not required.)
   */
  async lockedUpdate(
    mutate: (
      current: FederationJoinerTrustRootRecord | null,
    ) => FederationJoinerTrustRootRecord,
  ): Promise<FederationJoinerTrustRootRecord> {
    return withCrossProcessLock(
      this.storage,
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_LOCK_FILE,
      async () => {
        let current: FederationJoinerTrustRootRecord | null;
        try {
          current = await this.load();
        } catch (err) {
          throw new FederationJoinerTrustRootStoreError(
            `refusing to update the joiner trust root over an unreadable ` +
              `existing record (${publicErrorReason(err)}): the grow-only ` +
              `revoked-root set and anti-rollback floor cannot be safely merged ` +
              `when the existing record cannot be decoded`,
          );
        }

        const next = mutate(current);

        const currentRevoked = normalizeRevokedRootPubkeys(
          current?.revoked_root_pubkeys,
        );
        const currentFloor = normalizeHighestRevocationSerial(
          current?.highest_revocation_serial,
        );
        const nextFloor = normalizeHighestRevocationSerial(
          next.highest_revocation_serial,
        );
        if (nextFloor > 0 && nextFloor < currentFloor) {
          throw new FederationJoinerTrustRootStoreError(
            `revocation serial ${nextFloor} is below the recorded anti-rollback ` +
              `floor ${currentFloor}; refusing to lower the monotonic floor`,
          );
        }
        const mergedRevoked = new Set<string>(currentRevoked);
        for (const pubkey of normalizeRevokedRootPubkeys(
          next.revoked_root_pubkeys,
        )) {
          mergedRevoked.add(pubkey);
        }
        const mergedFloor = Math.max(currentFloor, nextFloor);

        // F1 (re-gate 2026-07-30): the planned adopted_rotation_serial gets a
        // SYMMETRIC under-lock floor, scoped to the pinned lineage. An executing
        // probe drove this floor backwards (9 -> 2) through this very chokepoint
        // while its docstring claimed the grow-only invariant was structurally
        // enforced; this guard makes the claim literally true. The scope: only a
        // write that KEEPS the pinned-master identity is held to the floor. A
        // write that MOVES the pinned master is a legitimate lineage change (a
        // planned adopt re-pins K1 -> K2 at that cert's serial; a fresh
        // join/rejoin resets to a new root at 0) and carries the mutator's
        // serial verbatim, so a fresh-join reset-to-0 never reads as a rollback.
        const currentPlannedFloor = normalizeAdoptedRotationSerial(
          current?.adopted_rotation_serial,
        );
        const nextPlannedSerial = normalizeAdoptedRotationSerial(
          next.adopted_rotation_serial,
        );
        const samePinnedLineage =
          current !== null &&
          current.pinned_master_pubkey.public_key ===
            next.pinned_master_pubkey.public_key &&
          current.pinned_master_pubkey.fortress_id ===
            next.pinned_master_pubkey.fortress_id;
        if (
          samePinnedLineage &&
          nextPlannedSerial > 0 &&
          nextPlannedSerial < currentPlannedFloor
        ) {
          throw new FederationJoinerTrustRootStoreError(
            `adopted rotation serial ${nextPlannedSerial} is below the recorded ` +
              `planned anti-rollback floor ${currentPlannedFloor} for the same ` +
              `pinned master; refusing to lower the monotonic floor`,
          );
        }
        const mergedPlannedSerial = samePinnedLineage
          ? Math.max(currentPlannedFloor, nextPlannedSerial)
          : nextPlannedSerial;

        const merged: FederationJoinerTrustRootRecord = {
          ...next,
          revoked_root_pubkeys:
            mergedRevoked.size > 0 ? mergedRevoked : undefined,
          highest_revocation_serial: mergedFloor > 0 ? mergedFloor : undefined,
          adopted_rotation_serial:
            mergedPlannedSerial > 0 ? mergedPlannedSerial : undefined,
        };
        await this.#writeRaw(merged);
        return merged;
      },
    );
  }

  /**
   * Raw encrypt-and-write. TRUE PRIVATE (`#`): reachable ONLY from
   * {@link lockedUpdate}, so NO code path (public API, other module code, or a
   * test) can write this record without the cross-process lock + grow-only merge.
   * Validates before any ciphertext is produced.
   */
  async #writeRaw(record: FederationJoinerTrustRootRecord): Promise<void> {
    validateJoinerRecord(record);
    const serialized = stringToBytes(
      JSON.stringify(encodePersistedRecord(record)),
    );
    try {
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
        FEDERATION_JOINER_TRUST_ROOT_KEY,
        stringToBytes(JSON.stringify(encrypted)),
      );
    } finally {
      serialized.fill(0);
    }
  }
}

export interface FederationJoinerTrustRootAuditEvent {
  operation:
    | "federation_joiner_trust_root_load"
    | "federation_joiner_trust_root_save"
    | "federation_joiner_planned_root_adopt";
  result: "success" | "failure";
  details: Record<string, unknown>;
}

export interface ProvisionOrLoadFederationJoinerTrustRootOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  audit?: (
    event: FederationJoinerTrustRootAuditEvent,
  ) => Promise<void> | void;
}

export interface ProvisionedFederationJoinerTrustRoot {
  record: FederationJoinerTrustRootRecord;
  context: ReturnType<typeof joinerContextFromRecord>;
  source: "persisted";
}

/**
 * Load a persisted joiner trust root, if present, into a NON-ISSUER context.
 *
 * There is NO mint path. A joiner record can only be created from a real join
 * ceremony result (a joiner has no master to mint from). Absence -> null
 * (federation honestly off). A malformed / tampered / cross-operator blob ->
 * fail-closed null (audited), never a crash, never a minted replacement.
 */
export async function loadFederationJoinerTrustRoot(
  opts: ProvisionOrLoadFederationJoinerTrustRootOptions,
): Promise<ProvisionedFederationJoinerTrustRoot | null> {
  const store = new FederationJoinerTrustRootStore(opts.storage, opts.masterKey);
  let record: FederationJoinerTrustRootRecord | null;
  try {
    record = await store.load();
  } catch (err) {
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_trust_root_load",
      result: "failure",
      details: { reason: "load_failed", error_class: errorName(err) },
    });
    return null;
  }

  if (record === null) return null;

  await auditJoinerTrustRoot(opts.audit, {
    operation: "federation_joiner_trust_root_load",
    result: "success",
    details: {
      fortress_id: record.pinned_master_pubkey.fortress_id,
      node_id: record.node_id,
    },
  });
  return {
    record,
    context: joinerContextFromRecord(record),
    source: "persisted",
  };
}

/**
 * Module-level convenience seam for the single locked, grow-only-enforcing write
 * CHOKEPOINT (`FederationJoinerTrustRootStore.lockedUpdate`). EVERY writer routes
 * through this one path - `persistFederationJoinerTrustRoot` (join/rejoin) and the
 * planned-adopt re-pin - so no unlocked writer can race a locked one and drop the
 * anti-rollback state. The raw encrypt-and-write is a TRUE-PRIVATE method
 * (`#writeRaw`) reachable ONLY from `lockedUpdate`, so the grow-only invariant is
 * STRUCTURALLY enforced (there is no public raw writer to bypass it), not merely
 * conventional. See `lockedUpdate` for the full step-by-step contract.
 */
async function lockedUpdateJoinerTrustRoot(
  storage: StorageBackend,
  masterKey: Uint8Array,
  mutate: (
    current: FederationJoinerTrustRootRecord | null,
  ) => FederationJoinerTrustRootRecord,
): Promise<FederationJoinerTrustRootRecord> {
  return new FederationJoinerTrustRootStore(storage, masterKey).lockedUpdate(
    mutate,
  );
}

/**
 * Persist a joiner record obtained from a real join ceremony.
 *
 * The `pinnedMasterPubkey` is the out-of-band trust anchor: the issued cert
 * MUST chain to it or this refuses to persist (CLAUDE.md constraint 4: no
 * implicit trust across the boundary; the server's response is never the trust
 * source). `validateJoinerRecord` re-runs the full cert-chain verification
 * before any ciphertext is written.
 *
 * The optional `revokedRootPubkeys` / `highestRevocationSerial` let a COMPROMISE
 * manual re-join (`sanctuary federation rejoin`) record the now-dead old root
 * (K1) into the fresh K2 record with an anti-rollback floor. PRECISION on what
 * consumes that record (M3, re-gate 2026-07-30): a later K1-signed rotation
 * cert is refused on this machine by (a) the planned-adopt cross-class guard in
 * this module (reason `rotation_signer_revoked`, checked both pre-lock and
 * under-lock), and (b) at the sync surface, by the dashboard boot-wire
 * (`setFederationContext` folds the record's revoked set + floor into the
 * revoked-root projection backing the sync-envelope `root_revoked` refusals).
 * Independently of the revocation, a stale K1-chained artifact ALSO fails the
 * pin itself once this joiner pins K2 (chain/cert checks terminate at the
 * pinned master) - the recorded revocation is what keeps refusing K1 even if a
 * K1 holder tries to re-anchor the pin. This routes through the single
 * `lockedUpdateJoinerTrustRoot` chokepoint, so the supplied roots are UNIONed
 * into any existing record's revoked set (never replace it), the floor is
 * `Math.max(existing, supplied)` (never lowered), a strictly-below-floor serial
 * is REFUSED loudly, and the new pinned master must NOT itself be in the merged
 * set (`validateJoinerRecord` fails closed).
 */
export async function persistFederationJoinerTrustRoot(opts: {
  storage: StorageBackend;
  masterKey: Uint8Array;
  pinnedMasterPubkey: FortressMasterPublicKey;
  issuingPrincipalCert: PrincipalCertificate;
  localNodeCert: NodeIdentityCertificate;
  localNodePrivateKey: Uint8Array;
  revokedRootPubkeys?: readonly string[];
  highestRevocationSerial?: number;
  audit?: ProvisionOrLoadFederationJoinerTrustRootOptions["audit"];
}): Promise<ProvisionedFederationJoinerTrustRoot> {
  // The node private key is copied once here so it can be zeroed on ANY failure
  // (lock, load-error, below-floor, or save throw) without touching the caller's.
  const localNodePrivateKey = Uint8Array.from(opts.localNodePrivateKey);

  let record: FederationJoinerTrustRootRecord;
  try {
    // Route through the single locked chokepoint. The mutation produces a FRESH
    // record from the join result (a fresh join is a NEW lineage, so the planned
    // `adopted_rotation_serial` resets to 0); the chokepoint UNIONs any existing
    // revoked set and MAXes the compromise floor, so this can never drop a
    // concurrent writer's anti-rollback state, and a strictly-below-floor supplied
    // serial is refused.
    record = await lockedUpdateJoinerTrustRoot(
      opts.storage,
      opts.masterKey,
      () => ({
        fortress_id: opts.pinnedMasterPubkey.fortress_id,
        node_id: opts.localNodeCert.node_id,
        pinned_master_pubkey: { ...opts.pinnedMasterPubkey },
        issuing_principal_cert: clonePrincipalCert(opts.issuingPrincipalCert),
        local_node_cert: cloneNodeCert(opts.localNodeCert),
        local_node_private_key: localNodePrivateKey,
        ...(opts.revokedRootPubkeys && opts.revokedRootPubkeys.length > 0
          ? { revoked_root_pubkeys: new Set(opts.revokedRootPubkeys) }
          : {}),
        ...(opts.highestRevocationSerial !== undefined &&
        opts.highestRevocationSerial > 0
          ? { highest_revocation_serial: opts.highestRevocationSerial }
          : {}),
      }),
    );
  } catch (err) {
    localNodePrivateKey.fill(0);
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_trust_root_save",
      result: "failure",
      details: { reason: "persist_failed", error_class: errorName(err) },
    });
    throw err;
  }

  await auditJoinerTrustRoot(opts.audit, {
    operation: "federation_joiner_trust_root_save",
    result: "success",
    details: {
      fortress_id: record.pinned_master_pubkey.fortress_id,
      node_id: record.node_id,
    },
  });
  return {
    record,
    context: joinerContextFromRecord(record),
    source: "persisted",
  };
}

/**
 * Build a NON-ISSUER federation context from a joiner record.
 *
 * The returned context exposes NO `getIssuingPrincipalPrivateKey`, NO
 * `getFortressMasterSecret`, NO `getMasterPrivateKey`, and NO `approver`. It is
 * a `nodeMode` context (the node mode of this joiner) that can present its cert
 * on `/sync/peer` but structurally cannot mint bootstrap tokens or issue certs.
 *
 * Field-consumption honesty (M3, re-gate 2026-07-30): `revokedRootPubkeys` and
 * `highestRevocationSerial` ARE consumed - the dashboard boot-wire
 * (`setFederationContext`) folds them into its revoked-root projection, which
 * backs the sync-envelope `root_revoked` refusals and the reissue endpoint's
 * revoked-root denial. `adoptedRotationSerial` is currently CARRIED ONLY: no
 * consumer reads it off the context today; the planned-rotation anti-replay
 * floor is enforced inside this module from the persisted record
 * (`adoptFederationJoinerPlannedRoot` + the locked chokepoint), not from the
 * context. It stays on the context for consumers that later need to surface or
 * gate on the adopted lineage without re-opening custody storage.
 */
export function joinerContextFromRecord(
  record: FederationJoinerTrustRootRecord,
) {
  validateJoinerRecord(record);
  const revokedRootPubkeys = normalizeRevokedRootPubkeys(
    record.revoked_root_pubkeys,
  );
  return {
    fortressId: record.pinned_master_pubkey.fortress_id,
    nodeId: record.node_id,
    nodeMode: record.local_node_cert.node_mode,
    pinnedMasterPubkey: { ...record.pinned_master_pubkey },
    issuingPrincipalCert: clonePrincipalCert(record.issuing_principal_cert),
    localNodeCert: cloneNodeCert(record.local_node_cert),
    getLocalNodePrivateKey: () => Uint8Array.from(record.local_node_private_key),
    isNodeRevoked: () => false,
    revokedRootPubkeys,
    highestRevocationSerial: normalizeHighestRevocationSerial(
      record.highest_revocation_serial,
    ),
    adoptedRotationSerial: normalizeAdoptedRotationSerial(
      record.adopted_rotation_serial,
    ),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Planned-rotation joiner auto-adopt (rotate-root --renew, Slice 3c-2)
// ═══════════════════════════════════════════════════════════════════════

export type FederationJoinerPlannedRootAdoptRejectionReason =
  | "joiner_trust_root_missing"
  | "joiner_trust_root_unavailable"
  | "hybrid_rotation_unsupported"
  | "rotation_signer_revoked"
  | "rotation_cert_invalid"
  | "adopted_root_mismatch_operator_pin"
  | "reissue_denied"
  | "reissue_unreachable"
  | "server_root_mismatch"
  | "reissued_identity_mismatch"
  | "reissued_chain_invalid"
  | "persist_failed";

/**
 * The proof-of-possession round the planned-adopt driver runs against the
 * EXISTING `/v1/federation/rotate/reissue-node-cert` endpoint (no new route).
 * Injected so the pure adopt core stays host-free and unit-testable; the CLI
 * verb supplies the real HTTP implementation.
 */
export interface FederationJoinerPlannedRootAdoptReissueRequest {
  current: FederationJoinerTrustRootRecord;
  rotationCert: FederationRootRotationCertificate;
  /** K2, learned from the K1-VERIFIED rotation cert (never the server response). */
  newPinnedMaster: FortressMasterPublicKey;
}

export type FederationJoinerPlannedRootAdoptReissueResult =
  | {
      ok: true;
      certificate: NodeIdentityCertificate;
      issuingPrincipalCert: PrincipalCertificate;
      /** The pinned master the server ECHOED; used only for a mismatch check. */
      serverPinnedMaster: FortressMasterPublicKey;
    }
  | {
      ok: false;
      reason: "denied" | "unreachable";
      /**
       * The issuer's opaque correlation id for the denied request, when it sent
       * one. The issuer never tells the joiner WHICH check failed (no membership
       * oracle); this id is what lets an operator who can read the ISSUER's
       * fortress recover the precise reason from its audit log. Carried through
       * so the joiner-side refusal can print it instead of leaving the operator
       * with a four-cause message and nothing to look up.
       */
      issuerRequestId?: string;
    };

export type FederationJoinerPlannedRootAdoptResult =
  | {
      adopted: true;
      state: "adopted";
      previousPinnedMaster: FortressMasterPublicKey;
      pinnedMaster: FortressMasterPublicKey;
      rotationSerial: number;
      record: FederationJoinerTrustRootRecord;
      context: ReturnType<typeof joinerContextFromRecord>;
    }
  | {
      adopted: false;
      state: "held_old_trust";
      reason: FederationJoinerPlannedRootAdoptRejectionReason;
      currentPinnedMaster: FortressMasterPublicKey | null;
      rotationSerial?: number;
      detail?: string;
      /**
       * Set only for an issuer-side refusal (`reissue_denied`): the issuer's
       * correlation id for that request, for the operator's audit lookup on the
       * ISSUER. Absent for every joiner-side refusal, which already names its
       * own precise reason locally.
       */
      issuerRequestId?: string;
    };

/**
 * Adopt a PLANNED-rotated issuer root on a JOINER.
 *
 * A-FULL trust model (ratified 2026-07-24): the adopted anchor is confirmed by
 * the OPERATOR out of band, NOT inferred from the K1-signed rotation cert alone.
 * Verifying a K1-signed cert proves K1 AUTHORIZED the succession and lets us run
 * the lighter reissue-not-rejoin ceremony, but a K1 signature is NOT sufficient
 * TRUST when K1 may be COMPROMISED (a K1 holder can forge a valid K1->K2' cert).
 * So every planned adopt REQUIRES `expectedPinnedMaster`: the operator's
 * out-of-band expected NEW root. The cert's `new_master` must byte-match it or
 * the adopt fails closed. This is the SAME "never infer the anchor from the
 * network" discipline (constraint 4) the compromise re-join uses; planned adopt
 * now anchors on it too, so a forged K2' cert fails even against an UNDETECTED
 * compromise. The fully hands-off convenience is intentionally dropped for the
 * unconditional guarantee. The steps, in order:
 *
 *   1. Load the current (K1-pinned) record; missing/unavailable -> held.
 *   2. Refuse a HYBRID rotation cert LOUDLY (classical-only slice; no silent
 *      post-quantum downgrade).
 *   3. Refuse if the cert's signer (or the currently pinned master) is in this
 *      joiner's local revoked-root set (the cross-class guard: a K1 that a prior
 *      compromise re-join marked dead can never re-anchor this joiner, even
 *      though a K1 holder could still SIGN a cert).
 *   4. Verify the rotation cert under the CURRENTLY pinned master with the
 *      monotonic adopted-serial floor (rejects wrong-master, bad signature,
 *      fortress mismatch, and a stale/replayed serial).
 *   5. Learn K2 from THAT verified cert (`rotationCert.new_master`) and assert it
 *      byte-matches the OPERATOR-supplied `expectedPinnedMaster`; a mismatch (a
 *      forged K2' cert, even one K1 legitimately signed) -> held, adopt nothing.
 *   6. Run the injected reissue proof-of-possession round, and confirm the server
 *      echoed the same K2 (defense-in-depth; the trust source is the cert +
 *      operator pin, never the response).
 *   7. Re-verify the reissued chain terminates at K2, then atomically re-pin K2
 *      via the store save (which re-runs the FULL chain verification).
 *
 * Any failure leaves the old record untouched and surfaces
 * `state:"held_old_trust"` with a loud, key-material-free reason, so a live node
 * is never silently evicted or stranded.
 */
export async function adoptFederationJoinerPlannedRoot(opts: {
  storage: StorageBackend;
  masterKey: Uint8Array;
  rotationCert: FederationRootRotationCertificate;
  /**
   * A-FULL: the operator's OUT-OF-BAND expected NEW root (K2). The cert's
   * `new_master` MUST byte-match this or the adopt fails closed. This is what
   * defeats a forged K1->K2' cert under an UNDETECTED compromise: the attacker
   * cannot make the operator carry K2' by hand.
   */
  expectedPinnedMaster: FortressMasterPublicKey;
  reissue: (
    req: FederationJoinerPlannedRootAdoptReissueRequest,
  ) => Promise<FederationJoinerPlannedRootAdoptReissueResult>;
  audit?: ProvisionOrLoadFederationJoinerTrustRootOptions["audit"];
}): Promise<FederationJoinerPlannedRootAdoptResult> {
  const store = new FederationJoinerTrustRootStore(opts.storage, opts.masterKey);
  let current: FederationJoinerTrustRootRecord | null;
  try {
    current = await store.load();
  } catch (err) {
    await auditPlannedAdoptFailure(opts.audit, "joiner_trust_root_unavailable", {
      error_class: errorName(err),
    });
    return held("joiner_trust_root_unavailable", null);
  }
  if (current === null) {
    await auditPlannedAdoptFailure(opts.audit, "joiner_trust_root_missing", {});
    return held("joiner_trust_root_missing", null);
  }

  const currentPinned = { ...current.pinned_master_pubkey };
  const rotationSerial = opts.rotationCert.rotation_serial;

  // Classical-only: a hybrid rotation cert cannot be verified on this path.
  // Refuse LOUDLY rather than verify only the classical Ed25519 half (a silent
  // post-quantum downgrade). Hybrid planned-adopt is a deferred follow-on.
  //
  // LOW-1 (review 2026-07-24), REFUSAL-REASON IMPRECISION IS ACCEPTABLE: this
  // guard keys on `hybrid_rotation`, which the frozen rotation-cert signed body
  // EXCLUDES (`trust-root.ts::rotationCertSignedBody`). An attacker can strip the
  // field from a public hybrid cert to defeat this LOUD refusal. Binding the
  // hybrid determination to a signed field would require a wire change to a
  // frozen surface, so we keep this best-effort loud refusal and rely on the
  // downstream fail-closed guarantees, which HOLD even when the field is
  // stripped: (a) A-FULL requires the cert's `new_master` to byte-match the
  // operator's out-of-band pin, and an operator following the classical-only
  // guidance never pins a hybrid root as a full classical trust anchor; (b) the
  // honest issuer's reissue endpoint refuses a hybrid fortress outright
  // (`v1/federation.ts` `hybrid_reissue_unsupported`) -> `reissue_denied`; and
  // (c) against a malicious server the returned chain cannot terminate at the
  // genuine K2 without K2's private key -> `reissued_chain_invalid`. So a
  // classical adopt can NEVER silently downgrade a hybrid root; the only loss on
  // a stripped field is that the operator sees `reissue_denied` /
  // `reissued_chain_invalid` instead of the loud `hybrid_rotation_unsupported`.
  if (
    (opts.rotationCert as { hybrid_rotation?: unknown }).hybrid_rotation !==
    undefined
  ) {
    await auditPlannedAdoptFailure(opts.audit, "hybrid_rotation_unsupported", {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return held("hybrid_rotation_unsupported", currentPinned, rotationSerial);
  }

  // Cross-class guard: never re-anchor on a locally-revoked root. A K1 that a
  // prior compromise re-join marked dead is refused even though its holder could
  // still forge a K1-signed rotation cert. The cert's ATTESTED NEW root (K2) is
  // checked here too (L2, re-gate 2026-07-30): a locally-revoked K2 would
  // otherwise only be caught by the save-time validation AFTER the network
  // reissue round, surfacing as a vague `persist_failed` instead of this honest
  // refusal, and would leak a pointless reissue round-trip to the server.
  const revoked = normalizeRevokedRootPubkeys(current.revoked_root_pubkeys);
  if (
    revoked.has(opts.rotationCert.old_master_pubkey) ||
    revoked.has(currentPinned.public_key) ||
    revoked.has(opts.rotationCert.new_master.public_key)
  ) {
    await auditPlannedAdoptFailure(opts.audit, "rotation_signer_revoked", {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return held("rotation_signer_revoked", currentPinned, rotationSerial);
  }

  // Verify under the CURRENTLY pinned master with the monotonic adopted-serial
  // floor. Covers wrong-master, bad signature, fortress mismatch, and replay.
  const serialFloor = normalizeAdoptedRotationSerial(
    current.adopted_rotation_serial,
  );
  try {
    verifyFederationRootRotationCertificate(opts.rotationCert, currentPinned, {
      minSerial: serialFloor,
    });
  } catch (err) {
    await auditPlannedAdoptFailure(opts.audit, "rotation_cert_invalid", {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return {
      adopted: false,
      state: "held_old_trust",
      reason: "rotation_cert_invalid",
      currentPinnedMaster: currentPinned,
      rotationSerial,
      detail: publicMeshErrorReason(err),
    };
  }

  // K2 is learned from the K1-VERIFIED cert, NEVER from the server response.
  // L1 (re-gate 2026-07-30): copy ONLY the K1-SIGNED fields into the trust
  // anchor. `rotationCertSignedBody` covers exactly `public_key`, `fortress_id`,
  // and `created_at`; a wholesale spread would persist any UNSIGNED extra field
  // a future `FortressMasterPublicKey` widening might carry, letting attacker
  // -controlled unsigned bytes ride into the pinned anchor.
  const newPinnedMaster: FortressMasterPublicKey = {
    public_key: opts.rotationCert.new_master.public_key,
    fortress_id: opts.rotationCert.new_master.fortress_id,
    created_at: opts.rotationCert.new_master.created_at,
  };

  // A-FULL (HIGH fix 2026-07-24): the trust anchor is OPERATOR-CONFIRMED. Even a
  // valid K1-signed cert is insufficient when K1 may be compromised (a K1 holder
  // can forge a K1->K2' cert). The cert's `new_master` MUST byte-match the
  // operator's out-of-band expected root, so a forged K2' fails closed here even
  // against an undetected compromise. The attacker cannot make the operator
  // carry K2' by hand.
  //
  // LOW (re-gate 2026-07-24): the CLI makes `--pinned-master` required, but a
  // DIRECT JS caller could pass an absent/malformed pin. Guard it structurally
  // FIRST (short-circuit before `samePinnedMasterExact` dereferences its fields)
  // so an absent pin returns the clean held-old-trust result, never a TypeError.
  if (
    !isValidFortressMasterPublicKey(opts.expectedPinnedMaster) ||
    !samePinnedMasterExact(newPinnedMaster, opts.expectedPinnedMaster)
  ) {
    await auditPlannedAdoptFailure(
      opts.audit,
      "adopted_root_mismatch_operator_pin",
      { fortress_id: current.fortress_id, node_id: current.node_id },
    );
    return held(
      "adopted_root_mismatch_operator_pin",
      currentPinned,
      rotationSerial,
    );
  }

  let reissued: FederationJoinerPlannedRootAdoptReissueResult;
  try {
    reissued = await opts.reissue({
      current,
      rotationCert: opts.rotationCert,
      newPinnedMaster,
    });
  } catch {
    await auditPlannedAdoptFailure(opts.audit, "reissue_unreachable", {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return held("reissue_unreachable", currentPinned, rotationSerial);
  }
  if (!reissued.ok) {
    const reason =
      reissued.reason === "unreachable" ? "reissue_unreachable" : "reissue_denied";
    // The issuer's correlation id (when it sent one) goes into BOTH the joiner's
    // own audit entry and the returned result, so the operator can find it
    // whether they are reading the log or the terminal.
    await auditPlannedAdoptFailure(opts.audit, reason, {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
      ...(reissued.issuerRequestId !== undefined
        ? { issuer_request_id: reissued.issuerRequestId }
        : {}),
    });
    return held(reason, currentPinned, rotationSerial, reissued.issuerRequestId);
  }

  // Constraint 4: the server response is never the trust source. The pinned
  // master the server echoed MUST equal the K2 we learned from the cert.
  if (!samePinnedIdentity(reissued.serverPinnedMaster, newPinnedMaster)) {
    await auditPlannedAdoptFailure(opts.audit, "server_root_mismatch", {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return held("server_root_mismatch", currentPinned, rotationSerial);
  }

  // Same node identity: the reissue must be for THIS node's existing key.
  if (
    reissued.certificate.node_id !== current.node_id ||
    reissued.certificate.node_pubkey !== current.local_node_cert.node_pubkey ||
    reissued.certificate.node_mode !== current.local_node_cert.node_mode
  ) {
    await auditPlannedAdoptFailure(opts.audit, "reissued_identity_mismatch", {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return held("reissued_identity_mismatch", currentPinned, rotationSerial);
  }

  // Re-verify the returned chain terminates at K2 (from the cert) BEFORE
  // persisting, so a bad chain is a clean held result, not a thrown save.
  try {
    verifyPrincipalCertificate(reissued.issuingPrincipalCert, newPinnedMaster);
    verifyCertChain(
      reissued.certificate,
      reissued.issuingPrincipalCert,
      newPinnedMaster,
    );
  } catch {
    await auditPlannedAdoptFailure(opts.audit, "reissued_chain_invalid", {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return held("reissued_chain_invalid", currentPinned, rotationSerial);
  }

  // Final re-pin: route the SAVE through the single locked chokepoint, expressed
  // as a mutation over the CURRENT-under-lock record. The network reissue above
  // is already complete, so the cross-process lock is NEVER held across a network
  // call. The chokepoint merge-preserves the current revoked set + floor, so a
  // concurrent rejoin's anti-rollback update can never be clobbered by adopt's
  // stale earlier load. Under the lock we RE-CHECK two things against the
  // CURRENT-under-lock record: (a) the cross-class guard - a concurrent
  // compromise re-join may have revoked K1 (the rotation signer) or even this
  // cert's K2 AFTER our unlocked decision, in which case re-pinning through a
  // now-dead root is refused; and (b) that the pinned master is STILL the
  // cert's old_master - a concurrent writer moving the pin invalidates our
  // pre-lock verification, so the save is refused rather than allowed to roll
  // the anchor onto a sibling lineage (F1, re-gate 2026-07-30).
  const repinNodeKey = Uint8Array.from(current.local_node_private_key);
  let repinned: FederationJoinerTrustRootRecord;
  try {
    repinned = await lockedUpdateJoinerTrustRoot(
      opts.storage,
      opts.masterKey,
      (underLock) => {
        if (underLock === null) {
          throw new JoinerPlannedAdoptConflictError("joiner_trust_root_missing");
        }
        const revokedUnderLock = normalizeRevokedRootPubkeys(
          underLock.revoked_root_pubkeys,
        );
        if (
          revokedUnderLock.has(opts.rotationCert.old_master_pubkey) ||
          revokedUnderLock.has(underLock.pinned_master_pubkey.public_key) ||
          revokedUnderLock.has(newPinnedMaster.public_key)
        ) {
          throw new JoinerPlannedAdoptConflictError("rotation_signer_revoked");
        }
        // F1 (re-gate 2026-07-30): the rotation cert was verified against OUR
        // pre-lock pin (its old_master). If a concurrent writer moved the pin
        // since (another adopt won the lock first, or a rejoin re-anchored),
        // that verification no longer speaks for the record we would overwrite:
        // re-pinning now could roll the anchor (and its serial) backwards onto
        // a sibling lineage. Refuse under the lock; the operator re-runs adopt
        // against the CURRENT pin and the cert either verifies there or is
        // honestly refused. FULL pinned identity (pubkey AND fortress_id, codex
        // gate 2026-07-31): a same-pubkey/different-fortress move would fail
        // `#writeRaw` validation anyway, but as the vague `persist_failed`; the
        // identity check here keeps the refusal reason honest.
        if (
          underLock.pinned_master_pubkey.public_key !==
            opts.rotationCert.old_master_pubkey ||
          underLock.pinned_master_pubkey.fortress_id !==
            opts.rotationCert.fortress_id
        ) {
          throw new JoinerPlannedAdoptConflictError("rotation_cert_invalid");
        }
        return {
          fortress_id: underLock.fortress_id,
          node_id: underLock.node_id,
          pinned_master_pubkey: newPinnedMaster,
          issuing_principal_cert: clonePrincipalCert(
            reissued.issuingPrincipalCert,
          ),
          local_node_cert: cloneNodeCert(reissued.certificate),
          local_node_private_key: repinNodeKey,
          // Planned floor advances to this cert's serial; the chokepoint keeps
          // the (compromise) revoked set + floor from the current-under-lock
          // record, so adopt never drops a concurrent rejoin's revocation.
          adopted_rotation_serial: rotationSerial,
        };
      },
    );
  } catch (err) {
    repinNodeKey.fill(0);
    if (err instanceof JoinerPlannedAdoptConflictError) {
      await auditPlannedAdoptFailure(opts.audit, err.reason, {
        fortress_id: current.fortress_id,
        node_id: current.node_id,
      });
      return held(err.reason, currentPinned, rotationSerial);
    }
    await auditPlannedAdoptFailure(opts.audit, "persist_failed", {
      error_class: errorName(err),
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return held("persist_failed", currentPinned, rotationSerial);
  }

  await auditJoinerTrustRoot(opts.audit, {
    operation: "federation_joiner_planned_root_adopt",
    result: "success",
    details: {
      fortress_id: repinned.fortress_id,
      node_id: repinned.node_id,
      previous_master_pubkey: currentPinned.public_key,
      new_master_pubkey: newPinnedMaster.public_key,
      rotation_serial: rotationSerial,
    },
  });

  return {
    adopted: true,
    state: "adopted",
    previousPinnedMaster: currentPinned,
    pinnedMaster: { ...newPinnedMaster },
    rotationSerial,
    record: repinned,
    context: joinerContextFromRecord(repinned),
  };
}

/**
 * Internal refusal thrown by the planned-adopt mutation to signal an under-lock
 * conflict (a concurrent write changed the record between adopt's unlocked
 * decision and its locked save). Carries the held-old-trust reason the caller
 * surfaces. Never leaves this module.
 */
class JoinerPlannedAdoptConflictError extends Error {
  constructor(readonly reason: FederationJoinerPlannedRootAdoptRejectionReason) {
    super(reason);
    this.name = "JoinerPlannedAdoptConflictError";
  }
}

function held(
  reason: FederationJoinerPlannedRootAdoptRejectionReason,
  currentPinnedMaster: FortressMasterPublicKey | null,
  rotationSerial?: number,
  issuerRequestId?: string,
): FederationJoinerPlannedRootAdoptResult {
  return {
    adopted: false,
    state: "held_old_trust",
    reason,
    currentPinnedMaster,
    ...(rotationSerial !== undefined ? { rotationSerial } : {}),
    ...(issuerRequestId !== undefined ? { issuerRequestId } : {}),
  };
}

async function auditPlannedAdoptFailure(
  audit: ProvisionOrLoadFederationJoinerTrustRootOptions["audit"],
  reason: FederationJoinerPlannedRootAdoptRejectionReason,
  details: Record<string, unknown>,
): Promise<void> {
  await auditJoinerTrustRoot(audit, {
    operation: "federation_joiner_planned_root_adopt",
    result: "failure",
    details: { reason, ...details },
  });
}

/** Identity match on the trust-bearing fields (metadata `created_at` ignored). */
function samePinnedIdentity(
  a: FortressMasterPublicKey,
  b: FortressMasterPublicKey,
): boolean {
  return a.public_key === b.public_key && a.fortress_id === b.fortress_id;
}

/**
 * Byte-exact match across ALL fields (including `created_at`) for the A-FULL
 * operator-pin assertion. The honest issuer treats a rotation cert's `new_master`
 * and the pinned master it prints as byte-identical (the reissue endpoint's own
 * `samePinnedMaster` compares all three fields), so an operator who pastes the
 * exact `rotate-root` output matches exactly; any discrepancy fails closed.
 */
function samePinnedMasterExact(
  a: FortressMasterPublicKey,
  b: FortressMasterPublicKey,
): boolean {
  return (
    a.public_key === b.public_key &&
    a.fortress_id === b.fortress_id &&
    a.created_at === b.created_at
  );
}

/** Structural guard so a direct caller passing an absent/malformed pin fails closed. */
function isValidFortressMasterPublicKey(
  value: unknown,
): value is FortressMasterPublicKey {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.public_key === "string" &&
    candidate.public_key.length > 0 &&
    typeof candidate.fortress_id === "string" &&
    candidate.fortress_id.length > 0 &&
    typeof candidate.created_at === "string" &&
    candidate.created_at.length > 0
  );
}

/** A rotation-cert verify error message is PUBLIC (no key material). */
function publicMeshErrorReason(err: unknown): string {
  return err instanceof Error ? err.message : "rotation cert invalid";
}

function encodePersistedRecord(
  record: FederationJoinerTrustRootRecord,
): PersistedFederationJoinerTrustRootRecord {
  const revokedRootPubkeys = normalizeRevokedRootPubkeys(
    record.revoked_root_pubkeys,
  );
  const highestRevocationSerial = normalizeHighestRevocationSerial(
    record.highest_revocation_serial,
  );
  const adoptedRotationSerial = normalizeAdoptedRotationSerial(
    record.adopted_rotation_serial,
  );
  return {
    fortress_id: record.fortress_id,
    node_id: record.node_id,
    pinned_master_pubkey: { ...record.pinned_master_pubkey },
    issuing_principal_cert: clonePrincipalCert(record.issuing_principal_cert),
    local_node_cert: cloneNodeCert(record.local_node_cert),
    local_node_private_key: encodeKey(
      record.local_node_private_key,
      "local_node_private_key",
    ),
    ...(revokedRootPubkeys.size > 0
      ? { revoked_root_pubkeys: [...revokedRootPubkeys].sort() }
      : {}),
    ...(highestRevocationSerial > 0
      ? { highest_revocation_serial: highestRevocationSerial }
      : {}),
    ...(adoptedRotationSerial > 0
      ? { adopted_rotation_serial: adoptedRotationSerial }
      : {}),
  };
}

function decodePersistedRecord(
  value: unknown,
): FederationJoinerTrustRootRecord {
  if (!isObject(value)) {
    throw new FederationJoinerTrustRootStoreError("record is not an object");
  }
  // Defense in depth: a blob carrying ANY issuer field is REFUSED, not
  // silently dropped. A joiner holding issuer material is an escalation.
  for (const forbidden of FORBIDDEN_ISSUER_FIELDS) {
    if (forbidden in value) {
      throw new FederationJoinerTrustRootStoreError(
        `joiner record must not contain issuer material (${forbidden})`,
      );
    }
  }
  const record: FederationJoinerTrustRootRecord = {
    fortress_id: readString(value, "fortress_id"),
    node_id: readString(value, "node_id"),
    pinned_master_pubkey: readObject(
      value,
      "pinned_master_pubkey",
    ) as unknown as FortressMasterPublicKey,
    issuing_principal_cert: readObject(
      value,
      "issuing_principal_cert",
    ) as unknown as PrincipalCertificate,
    local_node_cert: readObject(
      value,
      "local_node_cert",
    ) as unknown as NodeIdentityCertificate,
    local_node_private_key: decodeKey(
      readString(value, "local_node_private_key"),
      "local_node_private_key",
    ),
    revoked_root_pubkeys: decodeRevokedRootPubkeys(value.revoked_root_pubkeys),
    highest_revocation_serial:
      value.highest_revocation_serial === undefined
        ? 0
        : decodeSerial(value.highest_revocation_serial, "highest_revocation_serial"),
    adopted_rotation_serial:
      value.adopted_rotation_serial === undefined
        ? 0
        : decodeSerial(value.adopted_rotation_serial, "adopted_rotation_serial"),
  };
  validateJoinerRecord(record);
  return record;
}

/**
 * Validate a joiner record. Runs the same cert-chain checks the issuer store
 * runs, MINUS the issuer-key checks (a joiner has none). Plus a HARD assertion
 * that no issuer material is present at the runtime-object level.
 */
export function validateJoinerRecord(
  record: FederationJoinerTrustRootRecord,
): void {
  // Defense in depth: a runtime record object carrying any issuer field is
  // refused. This catches a build bug that constructs a joiner record from an
  // issuer record before it can be persisted or turned into a context.
  const candidate = record as unknown as Record<string, unknown>;
  for (const forbidden of FORBIDDEN_ISSUER_FIELDS) {
    if (forbidden in candidate) {
      throw new FederationJoinerTrustRootStoreError(
        `joiner record must not contain issuer material (${forbidden})`,
      );
    }
  }

  if (record.fortress_id !== record.pinned_master_pubkey.fortress_id) {
    throw new FederationJoinerTrustRootStoreError(
      "record fortress_id does not match pinned master fortress_id",
    );
  }
  if (record.issuing_principal_cert.fortress_id !== record.fortress_id) {
    throw new FederationJoinerTrustRootStoreError(
      "issuing principal cert fortress_id mismatch",
    );
  }
  if (record.local_node_cert.fortress_id !== record.fortress_id) {
    throw new FederationJoinerTrustRootStoreError(
      "local node cert fortress_id mismatch",
    );
  }
  if (record.local_node_cert.node_id !== record.node_id) {
    throw new FederationJoinerTrustRootStoreError(
      "local node cert node_id mismatch",
    );
  }
  const revokedRootPubkeys = normalizeRevokedRootPubkeys(
    record.revoked_root_pubkeys,
  );
  const highestRevocationSerial = normalizeHighestRevocationSerial(
    record.highest_revocation_serial,
  );
  if (revokedRootPubkeys.has(record.pinned_master_pubkey.public_key)) {
    throw new FederationJoinerTrustRootStoreError(
      "current pinned master is marked revoked",
    );
  }
  if (highestRevocationSerial === 0 && revokedRootPubkeys.size > 0) {
    throw new FederationJoinerTrustRootStoreError(
      "revoked roots require a positive revocation serial floor",
    );
  }
  // Normalizes + range-checks the planned floor even though it has no
  // cross-field invariant of its own (rejects a corrupt at-rest value).
  normalizeAdoptedRotationSerial(record.adopted_rotation_serial);
  assertKeyLength(record.local_node_private_key, "local_node_private_key");
  assertPrivateKeyMatchesPublic(
    record.local_node_private_key,
    record.local_node_cert.node_pubkey,
    "local_node_private_key",
  );
  // The whole point of the pinned master: the chain MUST terminate at it.
  verifyPrincipalCertificate(
    record.issuing_principal_cert,
    record.pinned_master_pubkey,
  );
  verifyCertChain(
    record.local_node_cert,
    record.issuing_principal_cert,
    record.pinned_master_pubkey,
  );
}

function assertKeyLength(value: Uint8Array, label: string): void {
  if (value.length !== 32) {
    throw new FederationJoinerTrustRootStoreError(`${label} must be 32 bytes`);
  }
}

function assertPrivateKeyMatchesPublic(
  privateKey: Uint8Array,
  publicKey: string,
  label: string,
): void {
  const derived = ed25519.getPublicKey(privateKey);
  const expected = fromBase64url(publicKey);
  try {
    if (!bytesEqual(derived, expected)) {
      throw new FederationJoinerTrustRootStoreError(
        `${label} does not match cert`,
      );
    }
  } finally {
    derived.fill(0);
    expected.fill(0);
  }
}

function encodeKey(value: Uint8Array, label: string): string {
  assertKeyLength(value, label);
  return toBase64url(value);
}

function decodeKey(value: string, label: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = fromBase64url(value);
  } catch {
    throw new FederationJoinerTrustRootStoreError(`${label} is not base64url`);
  }
  assertKeyLength(decoded, label);
  return decoded;
}

function readString(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) {
    throw new FederationJoinerTrustRootStoreError(`${key} is required`);
  }
  return field;
}

function readObject(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const field = value[key];
  if (!isObject(field)) {
    throw new FederationJoinerTrustRootStoreError(`${key} is required`);
  }
  return field;
}

function decodeRevokedRootPubkeys(value: unknown): Set<string> {
  if (value === undefined) return new Set();
  if (!Array.isArray(value)) {
    throw new FederationJoinerTrustRootStoreError(
      "revoked_root_pubkeys is not an array",
    );
  }
  const out = new Set<string>();
  for (const pubkey of value) {
    if (typeof pubkey !== "string" || pubkey.length === 0) {
      throw new FederationJoinerTrustRootStoreError(
        "revoked root pubkey is invalid",
      );
    }
    out.add(pubkey);
  }
  return out;
}

function decodeSerial(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new FederationJoinerTrustRootStoreError(`${label} is invalid`);
  }
  return value;
}

function normalizeRevokedRootPubkeys(value: unknown): Set<string> {
  if (value === undefined) return new Set();
  if (!(value instanceof Set)) {
    throw new FederationJoinerTrustRootStoreError(
      "revoked_root_pubkeys must be a Set",
    );
  }
  const out = new Set<string>();
  for (const pubkey of value) {
    if (typeof pubkey !== "string" || pubkey.length === 0) {
      throw new FederationJoinerTrustRootStoreError(
        "revoked root pubkey is invalid",
      );
    }
    out.add(pubkey);
  }
  return out;
}

function normalizeHighestRevocationSerial(value: unknown): number {
  if (value === undefined) return 0;
  return decodeSerial(value, "highest_revocation_serial");
}

function normalizeAdoptedRotationSerial(value: unknown): number {
  if (value === undefined) return 0;
  return decodeSerial(value, "adopted_rotation_serial");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function clonePrincipalCert(cert: PrincipalCertificate): PrincipalCertificate {
  return { ...cert };
}

function cloneNodeCert(cert: NodeIdentityCertificate): NodeIdentityCertificate {
  return {
    ...cert,
    parent_chain: { ...cert.parent_chain },
    ...(cert.delegated_grants
      ? { delegated_grants: [...cert.delegated_grants] }
      : {}),
    ...(cert.attestation_lineage_chain
      ? { attestation_lineage_chain: [...cert.attestation_lineage_chain] }
      : {}),
  };
}

async function auditJoinerTrustRoot(
  audit: ProvisionOrLoadFederationJoinerTrustRootOptions["audit"],
  event: FederationJoinerTrustRootAuditEvent,
): Promise<void> {
  if (!audit) return;
  await audit(event);
}

function publicErrorReason(err: unknown): string {
  if (err instanceof FederationJoinerTrustRootStoreError) return err.message;
  if (err instanceof SyntaxError) return "malformed JSON";
  return "decrypt_or_parse_failed";
}

function errorName(err: unknown): string {
  return err instanceof Error ? err.name : "Error";
}
