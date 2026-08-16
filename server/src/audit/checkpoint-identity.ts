/**
 * Fortress-identity binding for audit checkpoint signing and verification
 * (IC-05 closure).
 *
 * Before this module, `AuditLog`'s `checkpointSigner` and
 * `checkpointPublicKeyResolver` were optional constructor dependencies that
 * every test supplied and every production call site omitted, so shipped
 * fortresses wrote unsigned checkpoints and could not verify signed ones
 * (AGENTS.md assurance rule 3's exact defect shape). This module is the ONE
 * shared production implementation: given the storage backend and the
 * identity-encryption purpose key (both derivable from what every `AuditLog`
 * constructor already receives), it signs checkpoints with the fortress's own
 * identity and resolves checkpoint signer keys through the authenticated
 * identity record and its signed rotation history, mirroring how the state
 * store resolves writer keys (`resolveWriterPublicKeys`, PR #1166): trust
 * flows from fortress-held, master-key-encrypted identity material, never
 * from anything carried inside the record being verified.
 *
 * Failure semantics (IC-05-DG): proven identity ABSENCE and identity-material
 * FAILURE are different states and must never collapse. A store that provably
 * holds no identity yields `null`/`undefined` (the audit log serializes that
 * as an honest `unsigned` checkpoint, and reports an unresolved signer as an
 * explicit integrity finding). A store whose identity material exists but
 * cannot be read, parsed, or decrypted, or whose signing operation fails,
 * throws `CheckpointSignerUnavailableError` carrying a closed `reasonClass`
 * discriminant: treating corruption as "no identity" was empirically a silent
 * fail-open (a corrupted identity record demoted checkpoints to unsigned with
 * zero findings). The audit log converts the throw into a loud, distinct,
 * master-key-authenticated incident in the signing head, never into the
 * honest-absence path.
 */
import type { StorageBackend } from "../storage/interface.js";
import { decrypt, type EncryptedPayload } from "../core/encryption.js";
import { bytesToString, toBase64url } from "../core/encoding.js";
import { sign, type StoredIdentity } from "../core/identity.js";
import { resolveAuthenticatedIdentityWriterPublicKeys } from "../cognitive/state-store.js";
import {
  checkpointSigningBytes,
  type AuditCheckpointSignature,
  type AuditCheckpointSigningPayload,
} from "./chain.js";

/**
 * Namespace holding master-key-encrypted `StoredIdentity` records.
 * Must match the `"_identities"` literal used by `IdentityManager` in
 * `cognitive/tools.ts` and `resolveStoredIdentity` in
 * `cognitive/state-store.ts`.
 */
const IDENTITY_NAMESPACE = "_identities";

/**
 * `_meta` key naming the fortress's primary identity.
 * Must match `metadataKey` in `IdentityManager` (`cognitive/tools.ts`).
 */
const PRIMARY_IDENTITY_META_KEY = "primary_identity_id";

/**
 * Shape of a fortress identity id: 32 lowercase hex chars = the first 16
 * bytes of SHA-256(public key), hex-encoded (see `generateIdentityId` in
 * `core/identity.ts`). A checkpoint's `signer_kid` is read back from a
 * persisted record, so it is attacker-influenceable by anyone with storage
 * write access; this pattern keeps such a kid from shaping a storage key
 * beyond a fixed-namespace lookup, and bounds the work a forged kid can
 * cause to one rejected regex test.
 */
const IDENTITY_ID_PATTERN = /^[0-9a-f]{32}$/;

/**
 * Closed discriminant of WHY the checkpoint signer failed. This is the shared
 * signer-failure taxonomy: the signing head's incident ring persists exactly
 * these values as `reason_class`, so the set here must match
 * `SIGNING_INCIDENT_REASON_CLASSES` in `operational/audit-log.ts` (contract
 * pin, both sides).
 *  - `identity_unreadable`: an IO/listing/pointer READ failed — identity
 *    material may exist but could not be reached.
 *  - `identity_undecryptable`: a record EXISTS but does not parse, decrypt
 *    under this fortress's identity-encryption key, or claim the id it is
 *    stored under.
 *  - `signing_failed`: a resolved identity's signing operation threw.
 */
export type CheckpointSignerFailureReasonClass =
  | "identity_unreadable"
  | "identity_undecryptable"
  | "signing_failed";

/**
 * Thrown when identity material that SHOULD be usable is not: a record that
 * exists but cannot be read/parsed/decrypted, an unreadable primary pointer
 * or identity listing, or a failing signing operation. Distinct from plain
 * absence by design: the consumer (the audit log) must fail LOUDLY on this
 * error — recording a master-key-authenticated incident in the signing head —
 * and must reserve the honest `unsigned` path for proven absence.
 */
export class CheckpointSignerUnavailableError extends Error {
  readonly reasonClass: CheckpointSignerFailureReasonClass;
  constructor(reasonClass: CheckpointSignerFailureReasonClass, message: string) {
    super(message);
    this.name = "CheckpointSignerUnavailableError";
    this.reasonClass = reasonClass;
  }
}

/**
 * A storage backend that CANNOT hold identity records by construction (the
 * daemon audit-store adapter allowlists only the audit namespaces) refuses
 * the namespace with this machine-readable code. That refusal is proven
 * STRUCTURAL absence, not corruption: the daemon chain legitimately writes
 * honest unsigned checkpoints. Must match the code set on the refusal error
 * in `remapNamespace` (`operational/audit-store-split.ts`). Checked by code,
 * not error class, because importing the adapter's module from here would
 * close an import cycle through the audit log. The carve-out is deliberately
 * constructional-only (IC-05-DG review finding 2): the real
 * `FilesystemStorage` has no code path that throws this code, so an
 * operator-uid attacker cannot induce it by corrupting, deleting, or
 * chmod-ing anything; every OTHER runtime failure to reach `_identities` on
 * a fortress is a FINDING, never a softening.
 */
const STRUCTURAL_NAMESPACE_REFUSAL_CODE = "SANCTUARY_AUDIT_NAMESPACE_UNSUPPORTED";

export function isStructuralNamespaceRefusal(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { code?: unknown }).code === STRUCTURAL_NAMESPACE_REFUSAL_CODE
  );
}

/**
 * The production checkpoint signer/resolver pair for one fortress store.
 * Spread into `AuditLogConfig`, or consumed by `AuditLog`'s constructor
 * default (the IC-05 enforcement site in `operational/audit-log.ts`).
 */
export interface FortressCheckpointIdentityBinding {
  checkpointSigner: (
    payload: AuditCheckpointSigningPayload
  ) => Promise<AuditCheckpointSignature | null>;
  checkpointPublicKeyResolver: (
    signerKid: string
  ) => Promise<readonly string[] | undefined>;
}

type StoredIdentityRead =
  | { status: "absent" }
  | {
      status: "unreadable";
      reasonClass: CheckpointSignerFailureReasonClass;
      detail: string;
    }
  | { status: "ok"; identity: StoredIdentity };

/**
 * Read and decrypt one stored identity by id, with absence and failure kept
 * distinct. "absent" means the id cannot name an identity (malformed shape)
 * or no record exists under it; "unreadable" means a record EXISTS but could
 * not be reached (`identity_unreadable`) or does not parse, decrypt under
 * this fortress's identity-encryption key, or claim the id it is stored under
 * (`identity_undecryptable`). An unreadable record proves nothing about the
 * signer and must not contribute verification keys, but it equally must not
 * masquerade as an identity-less store.
 */
async function readStoredIdentity(
  storage: StorageBackend,
  identityEncryptionKey: Uint8Array,
  kid: string
): Promise<StoredIdentityRead> {
  if (!IDENTITY_ID_PATTERN.test(kid)) return { status: "absent" };
  let raw: Uint8Array | null;
  try {
    raw = await storage.read(IDENTITY_NAMESPACE, kid);
  } catch (err) {
    if (isStructuralNamespaceRefusal(err)) return { status: "absent" };
    return {
      status: "unreadable",
      reasonClass: "identity_unreadable",
      detail: `identity record ${kid} could not be read: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  if (raw === null) return { status: "absent" };
  try {
    const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
    const decrypted = decrypt(encrypted, identityEncryptionKey);
    const identity = JSON.parse(bytesToString(decrypted)) as StoredIdentity;
    // The record must claim the kid it is stored under; a mismatched record
    // would let a copied identity file answer for a different signer_kid.
    if (identity.identity_id !== kid) {
      return {
        status: "unreadable",
        reasonClass: "identity_undecryptable",
        detail: `identity record ${kid} claims a different identity_id`,
      };
    }
    return { status: "ok", identity };
  } catch {
    return {
      status: "unreadable",
      reasonClass: "identity_undecryptable",
      detail: `identity record ${kid} exists but does not parse/decrypt under this fortress's identity-encryption key`,
    };
  }
}

/**
 * Pick the identity that signs this fortress's checkpoints: the stored
 * primary identity when it resolves, else the oldest identity in the store
 * (ISO-8601 `created_at` compares lexicographically; ties break on
 * `identity_id`) so the choice is deterministic across restarts rather than
 * dependent on storage listing order.
 *
 * Returns `null` ONLY for proven absence (no identity records at all, or a
 * stale primary pointer whose record is gone and no other identity exists);
 * the caller serializes that as an honest `unsigned` checkpoint. Every
 * failure mode that is not proven absence (unreadable pointer, unreadable
 * listing, an existing-but-corrupt identity record) throws
 * `CheckpointSignerUnavailableError` instead: on those, "unsigned" would be
 * a silent downgrade, not an honest state.
 */
async function resolveSigningIdentity(
  storage: StorageBackend,
  identityEncryptionKey: Uint8Array
): Promise<StoredIdentity | null> {
  let pointerRaw: Uint8Array | null;
  try {
    pointerRaw = await storage.read("_meta", PRIMARY_IDENTITY_META_KEY);
  } catch (err) {
    if (isStructuralNamespaceRefusal(err)) {
      pointerRaw = null;
    } else {
      throw new CheckpointSignerUnavailableError(
        "identity_unreadable",
        `primary identity pointer could not be read: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
    }
  }
  if (pointerRaw !== null) {
    let primaryId: unknown;
    try {
      primaryId = JSON.parse(bytesToString(pointerRaw));
    } catch {
      throw new CheckpointSignerUnavailableError(
        "identity_undecryptable",
        "primary identity pointer exists but is not valid JSON"
      );
    }
    if (typeof primaryId !== "string") {
      throw new CheckpointSignerUnavailableError(
        "identity_undecryptable",
        "primary identity pointer exists but does not name an identity id"
      );
    }
    const primary = await readStoredIdentity(
      storage,
      identityEncryptionKey,
      primaryId
    );
    if (primary.status === "ok") return primary.identity;
    if (primary.status === "unreadable") {
      // The R2-a probe: a valid pointer to a corrupted record. Falling
      // through to the scan (or to null) here is exactly the silent
      // fail-open; the record exists, so absence is disproven.
      throw new CheckpointSignerUnavailableError(
        primary.reasonClass,
        primary.detail
      );
    }
    // status "absent": a stale pointer to a removed record mirrors
    // IdentityManager.load's fallback and continues to the deterministic
    // scan.
  }

  let entries;
  try {
    entries = await storage.list(IDENTITY_NAMESPACE);
  } catch (err) {
    // A backend that structurally cannot hold identities (the daemon audit
    // adapter) is proven absence: its chain honestly writes unsigned. Any
    // OTHER listing failure could be hiding real identities and fails loud.
    if (isStructuralNamespaceRefusal(err)) return null;
    throw new CheckpointSignerUnavailableError(
      "identity_unreadable",
      `identity listing failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  let oldest: StoredIdentity | null = null;
  for (const entry of entries) {
    // Keys that cannot be identity ids are skipped (they cannot be
    // identities); a WELL-FORMED key whose record is unreadable is
    // corruption and fails loudly below.
    if (!IDENTITY_ID_PATTERN.test(entry.key)) continue;
    const read = await readStoredIdentity(
      storage,
      identityEncryptionKey,
      entry.key
    );
    if (read.status === "unreadable") {
      throw new CheckpointSignerUnavailableError(read.reasonClass, read.detail);
    }
    if (read.status !== "ok") continue;
    const identity = read.identity;
    if (
      !oldest ||
      identity.created_at < oldest.created_at ||
      (identity.created_at === oldest.created_at &&
        identity.identity_id < oldest.identity_id)
    ) {
      oldest = identity;
    }
  }
  return oldest;
}

/**
 * Build the production checkpoint signer/resolver pair for one fortress
 * store.
 *
 * The signer re-resolves the signing identity at each checkpoint write
 * (checkpoints are written once per checkpoint interval, so the extra reads
 * are cheap) rather than caching it, so an identity created after boot signs
 * the very next checkpoint and no stale cache can outlive a key rotation.
 * It returns `null` only for proven identity absence and throws
 * `CheckpointSignerUnavailableError` for unreadable identity material or a
 * failed signing operation; the audit log maps the two outcomes to the
 * honest-unsigned and the loud signer-incident paths respectively.
 *
 * The resolver returns the signer's full authenticated key set: the current
 * public key plus every retired key whose signed rotation chain verifies
 * (single source: `resolveAuthenticatedIdentityWriterPublicKeys`, shared
 * with the state store's writer-key resolution). Checkpoints signed before a
 * key rotation therefore keep verifying after it. Proven absence (or a
 * verified rotation chain yielding no keys) resolves to `undefined`, which
 * the audit log reports as an integrity finding rather than falling back to
 * the checkpoint's own embedded key; an unreadable record throws, which the
 * audit log's verify path also surfaces as a finding, never as silence.
 */
export function createFortressCheckpointIdentityBinding(
  storage: StorageBackend,
  identityEncryptionKey: Uint8Array
): FortressCheckpointIdentityBinding {
  return {
    checkpointSigner: async (payload) => {
      const identity = await resolveSigningIdentity(
        storage,
        identityEncryptionKey
      );
      if (!identity) return null;
      try {
        const signature = sign(
          checkpointSigningBytes(payload),
          identity.encrypted_private_key,
          identityEncryptionKey
        );
        return {
          signer_kid: identity.identity_id,
          // The embedded public_key is carried for export tooling and
          // explicit self-check opt-ins only; the verify path resolves keys
          // through this module and never trusts the embedded copy by
          // default.
          public_key: identity.public_key,
          signature: toBase64url(signature),
        };
      } catch (err) {
        // A resolved identity that fails to SIGN is a failure, not absence:
        // collapsing it into the honest `unsigned` record was the silent
        // fail-open this error type exists to prevent.
        throw new CheckpointSignerUnavailableError(
          "signing_failed",
          `checkpoint signing failed for identity ${identity.identity_id}: ${
            err instanceof Error ? err.message : String(err)
          }`
        );
      }
    },
    checkpointPublicKeyResolver: async (signerKid) => {
      const read = await readStoredIdentity(
        storage,
        identityEncryptionKey,
        signerKid
      );
      if (read.status === "unreadable") {
        // Surfaced by the audit log's verify path as an unverifiable-signer
        // integrity finding (its resolver guard treats a throw as
        // unresolved, never as verified).
        throw new CheckpointSignerUnavailableError(read.reasonClass, read.detail);
      }
      if (read.status !== "ok") return undefined;
      const keys = resolveAuthenticatedIdentityWriterPublicKeys(read.identity);
      if (keys.length === 0) return undefined;
      return keys.map((key) => key.publicKeyBase64url);
    },
  };
}
