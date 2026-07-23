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

  async save(record: FederationJoinerTrustRootRecord): Promise<void> {
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
 * (K1) into the fresh K2 record with an anti-rollback floor, so a later K1 (or
 * K1-signed artifact) is refused locally. They are additive and GROW-ONLY: the
 * supplied roots are UNIONed into any existing record's revoked set (never
 * replace it), the persisted floor is `Math.max(existing, supplied)` (never
 * lowered), a strictly-below-floor serial is REFUSED loudly, the new pinned
 * master must NOT itself be in the merged set (`validateJoinerRecord` fails
 * closed), and a non-empty revoked set REQUIRES a positive serial floor.
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
  const store = new FederationJoinerTrustRootStore(opts.storage, opts.masterKey);

  // Grow-only merge (MED fix 2026-07-24): the joiner's revoked-root set and its
  // monotonic revocation floor are GROW-ONLY. A re-join (or any re-persist) must
  // UNION the supplied revoked roots into whatever the existing record already
  // recorded and NEVER lower the floor. Without this, a stale/lower-serial re-join
  // would shrink the set (fresh `[K1]` replacing a larger set) or roll the floor
  // back, re-enabling replay of revocations between the old and new floor. Mirrors
  // the issuer-side Math.max merge (`v1/federation-sync-state-store.ts`). A
  // corrupt/unreadable existing record cannot supply a floor, so recovery is not
  // blocked (it decodes to an empty floor); under a custody compromise the attacker
  // already controls the store, which is out of scope for this floor.
  let existing: FederationJoinerTrustRootRecord | null;
  try {
    existing = await store.load();
  } catch {
    existing = null;
  }
  const existingRevoked = normalizeRevokedRootPubkeys(
    existing?.revoked_root_pubkeys,
  );
  const existingFloor = normalizeHighestRevocationSerial(
    existing?.highest_revocation_serial,
  );
  const suppliedFloor =
    opts.highestRevocationSerial !== undefined && opts.highestRevocationSerial > 0
      ? opts.highestRevocationSerial
      : 0;
  // Reject a strictly-below-floor serial LOUDLY (fail-closed) rather than
  // persisting it; an equal serial (idempotent re-run) or a higher one proceeds.
  if (suppliedFloor > 0 && suppliedFloor < existingFloor) {
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_trust_root_save",
      result: "failure",
      details: {
        reason: "revocation_serial_below_floor",
        supplied: suppliedFloor,
        floor: existingFloor,
      },
    });
    throw new FederationJoinerTrustRootStoreError(
      `revocation serial ${suppliedFloor} is below the recorded anti-rollback ` +
        `floor ${existingFloor}; refusing to lower the monotonic floor`,
    );
  }
  const mergedRevoked = new Set<string>(existingRevoked);
  for (const pubkey of opts.revokedRootPubkeys ?? []) mergedRevoked.add(pubkey);
  const mergedFloor = Math.max(existingFloor, suppliedFloor);

  const record: FederationJoinerTrustRootRecord = {
    fortress_id: opts.pinnedMasterPubkey.fortress_id,
    node_id: opts.localNodeCert.node_id,
    pinned_master_pubkey: { ...opts.pinnedMasterPubkey },
    issuing_principal_cert: clonePrincipalCert(opts.issuingPrincipalCert),
    local_node_cert: cloneNodeCert(opts.localNodeCert),
    local_node_private_key: Uint8Array.from(opts.localNodePrivateKey),
    ...(mergedRevoked.size > 0 ? { revoked_root_pubkeys: mergedRevoked } : {}),
    ...(mergedFloor > 0 ? { highest_revocation_serial: mergedFloor } : {}),
  };
  try {
    await store.save(record);
  } catch (err) {
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_trust_root_save",
      result: "failure",
      details: { reason: "persist_failed", error_class: errorName(err) },
    });
    record.local_node_private_key.fill(0);
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
  | { ok: false; reason: "denied" | "unreachable" };

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
  // still forge a K1-signed rotation cert.
  const revoked = normalizeRevokedRootPubkeys(current.revoked_root_pubkeys);
  if (
    revoked.has(opts.rotationCert.old_master_pubkey) ||
    revoked.has(currentPinned.public_key)
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
  const newPinnedMaster: FortressMasterPublicKey = {
    ...opts.rotationCert.new_master,
  };

  // A-FULL (HIGH fix 2026-07-24): the trust anchor is OPERATOR-CONFIRMED. Even a
  // valid K1-signed cert is insufficient when K1 may be compromised (a K1 holder
  // can forge a K1->K2' cert). The cert's `new_master` MUST byte-match the
  // operator's out-of-band expected root, so a forged K2' fails closed here even
  // against an undetected compromise. The attacker cannot make the operator
  // carry K2' by hand.
  if (!samePinnedMasterExact(newPinnedMaster, opts.expectedPinnedMaster)) {
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
    await auditPlannedAdoptFailure(opts.audit, reason, {
      fortress_id: current.fortress_id,
      node_id: current.node_id,
    });
    return held(reason, currentPinned, rotationSerial);
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

  const highestRevocationSerial = normalizeHighestRevocationSerial(
    current.highest_revocation_serial,
  );
  const next: FederationJoinerTrustRootRecord = {
    fortress_id: current.fortress_id,
    node_id: current.node_id,
    pinned_master_pubkey: newPinnedMaster,
    issuing_principal_cert: clonePrincipalCert(reissued.issuingPrincipalCert),
    local_node_cert: cloneNodeCert(reissued.certificate),
    local_node_private_key: Uint8Array.from(current.local_node_private_key),
    // Carry the grow-only revoked-root set + revocation floor forward unchanged.
    ...(revoked.size > 0 ? { revoked_root_pubkeys: new Set(revoked) } : {}),
    ...(highestRevocationSerial > 0
      ? { highest_revocation_serial: highestRevocationSerial }
      : {}),
    adopted_rotation_serial: rotationSerial,
  };

  try {
    await store.save(next);
  } catch (err) {
    next.local_node_private_key.fill(0);
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
      fortress_id: next.fortress_id,
      node_id: next.node_id,
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
    record: next,
    context: joinerContextFromRecord(next),
  };
}

function held(
  reason: FederationJoinerPlannedRootAdoptRejectionReason,
  currentPinnedMaster: FortressMasterPublicKey | null,
  rotationSerial?: number,
): FederationJoinerPlannedRootAdoptResult {
  return {
    adopted: false,
    state: "held_old_trust",
    reason,
    currentPinnedMaster,
    ...(rotationSerial !== undefined ? { rotationSerial } : {}),
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
