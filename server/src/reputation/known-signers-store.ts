/**
 * Sanctuary Exit V2 - known-signer key persistence (drill F2, Erik-ratified
 * option a, 2026-08-22/23).
 *
 * A fortress that imports another fortress's reputation attestations
 * verifies each attestation signer's public key AT IMPORT TIME - either
 * because it is the exporting bundle's own identity, or because the bundle
 * carried a signed `known_signers` table the importer resolved (see
 * `../exit/verifier.ts` `resolveKnownSigners`). That verified DID -> public
 * key mapping is durably recorded here so a LATER export from this fortress
 * can rebuild a `known_signers` table of its own, letting a re-exported
 * (second-hop) bundle stay verifiable. Without this store, a second-hop
 * export has no record of what it verified and cannot vouch for a signer it
 * did not itself mint.
 *
 * Reserved namespace: `_known_signers` is listed in
 * `RESERVED_NAMESPACE_PREFIXES` (server/src/cognitive/state-store.ts) - the
 * single source of truth - so it is refused to every external read/write/
 * import path the same way `_reputation` is.
 *
 * GROWTH BOUND (AGENTS.md rule 8): entries are written only for DIDs that
 * appear as an attestation signer in a bundle that has already passed
 * `ReputationStore.importBundle`'s own quota check
 * (`assertRecordQuotaForCount`, MAX_REPUTATION_RECORDS /
 * MAX_REPUTATION_RECORDS_PER_ORIGIN) - one entry per unique signer DID, never
 * more entries than admitted attestations in a single import, and a DID
 * already recorded is never rewritten (first-seen wins), so repeated imports
 * of overlapping attestation sets do not grow this namespace further.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  bytesToString,
  stringToBytes,
  toBase64url,
  fromBase64url,
} from "../core/encoding.js";
import { hashToString } from "../core/hashing.js";

/** Reserved namespace for persisted known-signer entries. CONTRACT PIN: must match the `"_known_signers"` literal in `RESERVED_NAMESPACE_PREFIXES` (server/src/cognitive/state-store.ts). */
export const KNOWN_SIGNERS_NAMESPACE = "_known_signers";

/** One persisted, previously-verified signer DID -> public key mapping. */
export interface StoredKnownSigner {
  did: string;
  /** base64url raw Ed25519 public key. */
  public_key: string;
  /** The `_exit_imports` import id at which this fortress first verified this signer. */
  first_seen_import_id: string;
}

/**
 * Storage key for a DID's known-signer record. Hashed rather than the raw
 * DID (MEDIUM-2 pattern, server/src/exit/bundle.ts `postImageRecordKey`):
 * `did:web:...` DIDs can be arbitrarily long operator-influenced strings,
 * and an unbounded raw key risks a filesystem path-component limit whose
 * ENAMETOOLONG failure would otherwise be misread as "never persisted".
 */
export function knownSignerStorageKey(did: string): string {
  return hashToString(stringToBytes(did));
}

/**
 * Persists a fortress's verified DID -> public key mappings, encrypted at
 * rest under a dedicated purpose key (mirrors ReputationStore's
 * `l4-reputation` derivation). Never overwrites an existing record: the
 * first import that verified a DID's key is authoritative for this
 * fortress, and a later, possibly-conflicting claim for the same DID is
 * simply not trusted over it.
 */
export class KnownSignersStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l4-known-signers");
  }

  /**
   * Persist every `(did, publicKey)` pair not already recorded. `importId`
   * is stamped as `first_seen_import_id` on every NEWLY written record only
   * - an already-persisted DID keeps its original import id.
   *
   * `recordPostImage`, when supplied, is called synchronously with the
   * exact on-disk bytes each new write persists - the same post-image
   * hook `ReputationStore.importBundle` and `rekeyState` use
   * (server/src/exit/bundle.ts `recordPostImage`), so the exit-import
   * journal's divergence check covers this namespace identically to
   * `_reputation`.
   */
  async persistIfAbsent(
    entries: Array<{ did: string; publicKey: Uint8Array }>,
    importId: string,
    recordPostImage?: (
      namespace: string,
      key: string,
      bytes: Uint8Array
    ) => Promise<void>
  ): Promise<void> {
    for (const { did, publicKey } of entries) {
      const key = knownSignerStorageKey(did);
      const existing = await this.storage.read(KNOWN_SIGNERS_NAMESPACE, key);
      if (existing !== null) continue;
      const stored: StoredKnownSigner = {
        did,
        public_key: toBase64url(publicKey),
        first_seen_import_id: importId,
      };
      const encrypted = encrypt(
        stringToBytes(JSON.stringify(stored)),
        this.encryptionKey
      );
      const onDiskBytes = stringToBytes(JSON.stringify(encrypted));
      await this.storage.write(KNOWN_SIGNERS_NAMESPACE, key, onDiskBytes);
      if (recordPostImage) {
        try {
          await recordPostImage(KNOWN_SIGNERS_NAMESPACE, key, onDiskBytes);
        } catch {
          // Intentionally swallowed - mirrors ReputationStore.importBundle's
          // matching call: a failed post-image record must never turn "the
          // known-signer entry landed" into "this write failed".
        }
      }
    }
  }

  /** Look up one persisted signer by DID, or null if never recorded. */
  async lookup(did: string): Promise<StoredKnownSigner | null> {
    const raw = await this.storage.read(
      KNOWN_SIGNERS_NAMESPACE,
      knownSignerStorageKey(did)
    );
    if (!raw) return null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(decrypted)) as Record<
        string,
        unknown
      >;
      if (
        typeof parsed.did !== "string" ||
        typeof parsed.public_key !== "string" ||
        typeof parsed.first_seen_import_id !== "string"
      ) {
        return null;
      }
      return {
        did: parsed.did,
        public_key: parsed.public_key,
        first_seen_import_id: parsed.first_seen_import_id,
      };
    } catch {
      return null;
    }
  }

  /**
   * Resolve every DID in `dids` that has a persisted record, decoding
   * `public_key` to raw bytes. DIDs with no record (never verified by this
   * fortress, or the record failed to decrypt/parse) are simply omitted -
   * this is a best-effort export-time lookup, not a verification gate.
   */
  async resolveMany(
    dids: Iterable<string>
  ): Promise<Array<{ did: string; publicKey: Uint8Array; first_seen_import_id: string }>> {
    const resolved: Array<{
      did: string;
      publicKey: Uint8Array;
      first_seen_import_id: string;
    }> = [];
    for (const did of dids) {
      const stored = await this.lookup(did);
      if (!stored) continue;
      try {
        resolved.push({
          did: stored.did,
          publicKey: fromBase64url(stored.public_key),
          first_seen_import_id: stored.first_seen_import_id,
        });
      } catch {
        // Malformed persisted key: skip rather than throw. Persisted by
        // this same module's persistIfAbsent, so this should not happen in
        // practice; defensive only.
      }
    }
    return resolved;
  }
}
