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
 * Every lookup here fails soft to "no key material" (`null`/`undefined`),
 * never to a throw: the audit log's verify path converts an unresolved signer
 * into an explicit integrity finding, and its write path converts a missing
 * signer into an honest `unsigned` checkpoint. A store with no identities
 * (fresh fortress before bootstrap, the Castle Wall safe-mode boot store, the
 * daemon split store whose adapter refuses non-audit namespaces) therefore
 * behaves exactly as it did before this module existed.
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

/**
 * Read and decrypt one stored identity by id. Returns `null` for anything
 * short of a well-formed record that decrypts under this fortress's
 * identity-encryption key and claims the id it is stored under: an identity
 * that fails custody-key decryption proves nothing about the signer and must
 * not contribute verification keys.
 */
async function readStoredIdentity(
  storage: StorageBackend,
  identityEncryptionKey: Uint8Array,
  kid: string
): Promise<StoredIdentity | null> {
  if (!IDENTITY_ID_PATTERN.test(kid)) return null;
  try {
    const raw = await storage.read(IDENTITY_NAMESPACE, kid);
    if (!raw) return null;
    const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
    const decrypted = decrypt(encrypted, identityEncryptionKey);
    const identity = JSON.parse(bytesToString(decrypted)) as StoredIdentity;
    // The record must claim the kid it is stored under; a mismatched record
    // would let a copied identity file answer for a different signer_kid.
    return identity.identity_id === kid ? identity : null;
  } catch {
    return null;
  }
}

/**
 * Pick the identity that signs this fortress's checkpoints: the stored
 * primary identity when it resolves, else the oldest identity in the store
 * (ISO-8601 `created_at` compares lexicographically; ties break on
 * `identity_id`) so the choice is deterministic across restarts rather than
 * dependent on storage listing order. Returns `null` when the store holds no
 * identity this key can decrypt; the caller serializes that as an honest
 * `unsigned` checkpoint.
 */
async function resolveSigningIdentity(
  storage: StorageBackend,
  identityEncryptionKey: Uint8Array
): Promise<StoredIdentity | null> {
  try {
    const metaRaw = await storage.read("_meta", PRIMARY_IDENTITY_META_KEY);
    if (metaRaw) {
      const primaryId: unknown = JSON.parse(bytesToString(metaRaw));
      if (typeof primaryId === "string") {
        const primary = await readStoredIdentity(
          storage,
          identityEncryptionKey,
          primaryId
        );
        if (primary) return primary;
      }
    }
  } catch {
    // A broken primary pointer falls through to the deterministic scan; it
    // must not make checkpoints silently unsigned while identities exist.
  }

  try {
    const entries = await storage.list(IDENTITY_NAMESPACE);
    let oldest: StoredIdentity | null = null;
    for (const entry of entries) {
      const identity = await readStoredIdentity(
        storage,
        identityEncryptionKey,
        entry.key
      );
      if (!identity) continue;
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
  } catch {
    return null;
  }
}

/**
 * Build the production checkpoint signer/resolver pair for one fortress
 * store.
 *
 * The signer re-resolves the signing identity at each checkpoint write
 * (checkpoints are written once per checkpoint interval, so the extra reads
 * are cheap) rather than caching it, so an identity created after boot signs
 * the very next checkpoint and no stale cache can outlive a key rotation.
 *
 * The resolver returns the signer's full authenticated key set: the current
 * public key plus every retired key whose signed rotation chain verifies
 * (single source: `resolveAuthenticatedIdentityWriterPublicKeys`, shared
 * with the state store's writer-key resolution). Checkpoints signed before a
 * key rotation therefore keep verifying after it. An unresolvable, missing,
 * or undecryptable identity yields `undefined`, which the audit log reports
 * as an integrity finding rather than falling back to the checkpoint's own
 * embedded key.
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
      } catch {
        // A signing failure degrades to the honest `unsigned` record; it
        // must never abort the checkpoint write itself.
        return null;
      }
    },
    checkpointPublicKeyResolver: async (signerKid) => {
      const identity = await readStoredIdentity(
        storage,
        identityEncryptionKey,
        signerKid
      );
      if (!identity) return undefined;
      const keys = resolveAuthenticatedIdentityWriterPublicKeys(identity);
      if (keys.length === 0) return undefined;
      return keys.map((key) => key.publicKeyBase64url);
    },
  };
}
