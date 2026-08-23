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
 * GROWTH BOUND (AGENTS.md rule 8): a per-IMPORT bound alone is not a
 * STORE-WIDE bound. Each import individually stays under
 * `ReputationStore.importBundle`'s own quota
 * (`assertRecordQuotaForCount`), but a caller-controlled attestation_id and
 * fresh signer DIDs mean a sequence of otherwise-legitimate, individually
 * quota-respecting imports over time could still grow `_known_signers`
 * without limit - each hop of a re-export chain can also carry the SAME
 * signer DIDs forward, so unbounded growth is reachable indirectly through
 * repeated import, not only through one oversized import): `persistIfAbsent`
 * now enforces an explicit STORE-WIDE cap (`MAX_KNOWN_SIGNERS`, derived from
 * `MAX_REPUTATION_RECORDS`) computed from NET-NEW keys (entries already
 * present cost nothing) and checked BEFORE any write in the batch - the
 * whole batch is refused, atomically, with NOTHING written, if it would
 * push the store over the cap. This store has exactly one writer today
 * (the exit-import path, server/src/exit/bundle.ts), which already runs the
 * WHOLE persist call inside the fortress-wide exit-admission lock
 * (`withExitAdmissionLock`), so the check-then-write here is race-free
 * against every OTHER exit-import/rotation/recovery operation without a
 * second lock of its own; a future second writer would need to either
 * share that lock or add one here.
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
import { MAX_REPUTATION_RECORDS } from "./reputation-store.js";

/** Reserved namespace for persisted known-signer entries. CONTRACT PIN: must match the `"_known_signers"` literal in `RESERVED_NAMESPACE_PREFIXES` (server/src/cognitive/state-store.ts). */
export const KNOWN_SIGNERS_NAMESPACE = "_known_signers";

/**
 * The store-wide ceiling on total persisted `_known_signers` records,
 * checked by `persistIfAbsent`
 * before every write batch. Equal to `MAX_REPUTATION_RECORDS` (not a
 * fraction of it, unlike the global/per-origin 10x ratio elsewhere in this
 * file family): in the worst case every one of up to `MAX_REPUTATION_RECORDS`
 * admitted attestations names a DISTINCT signer DID, so a known-signers
 * store that must be able to represent that worst case needs the SAME
 * ceiling as the attestation store it derives from, not a smaller one.
 */
export const MAX_KNOWN_SIGNERS = MAX_REPUTATION_RECORDS;

/**
 * Thrown by `persistIfAbsent` when persisting the given batch would push
 * `_known_signers` over `MAX_KNOWN_SIGNERS`. The whole batch is refused -
 * nothing is written, including entries that would themselves have fit -
 * so a caller never has to reason about a partially-admitted batch.
 */
export class KnownSignersQuotaError extends Error {
  readonly currentCount: number;
  readonly netNewCount: number;
  readonly limit: number;

  constructor(currentCount: number, netNewCount: number, limit: number) {
    super(
      `_known_signers is at ${currentCount} record(s); persisting ${netNewCount} ` +
        `net-new signer(s) would exceed the ${limit}-record store-wide cap. ` +
        "Refusing the whole batch; nothing was written."
    );
    this.name = "KnownSignersQuotaError";
    this.currentCount = currentCount;
    this.netNewCount = netNewCount;
    this.limit = limit;
  }
}

/** One persisted, previously-verified signer DID -> public key mapping. */
export interface StoredKnownSigner {
  did: string;
  /** base64url raw Ed25519 public key. */
  public_key: string;
  /**
   * The `_exit_imports` import id at which THIS fortress first verified
   * this signer. Informational and diagnostic ONLY - see the matching
   * field doc on
   * `KnownSignersEntry` (exit/verifier.ts) for the full hearsay-bound
   * statement. Once this value crosses a re-export hop it is the relaying
   * fortress's own self-report about ITS import history, not this
   * fortress's, and is never treated as verified provenance by any
   * consumer here.
   */
  first_seen_import_id: string;
}

/**
 * Storage key for a DID's known-signer record. Hashed rather than the raw
 * DID (same pattern as server/src/exit/bundle.ts `postImageRecordKey`):
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
  private readonly maxKnownSigners: number;

  /**
   * `testOverrides.maxKnownSigners` mirrors
   * `ReputationStoreTestOverrides.maxReputationRecords` (reputation-store.ts)
   * - production call sites never set this. It exists solely so a
   * capacity-refusal test can drive a small cap instead of performing
   * thousands of real writes to reach the production ceiling.
   */
  constructor(
    storage: StorageBackend,
    masterKey: Uint8Array,
    testOverrides?: { maxKnownSigners?: number }
  ) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l4-known-signers");
    this.maxKnownSigners = testOverrides?.maxKnownSigners ?? MAX_KNOWN_SIGNERS;
  }

  /**
   * Persist every `(did, publicKey)` pair not already recorded. `importId`
   * is stamped as `first_seen_import_id` on every NEWLY written record only
   * - an already-persisted DID keeps its original import id.
   *
   * The STORE-WIDE cap (`MAX_KNOWN_SIGNERS`) is checked ONCE, atomically,
   * before any write in
   * this batch - `currentCount` (a single `storage.list` call) plus the
   * NET-NEW count (candidates not already present; an already-persisted DID
   * costs nothing) is compared against the cap, and the WHOLE batch is
   * refused (`KnownSignersQuotaError`, nothing written) if it would exceed
   * it. This two-phase shape (count net-new first, THEN write) is what
   * makes "nothing written" true even for the entries that would
   * individually have fit under the cap - a caller never has to reconcile
   * a partially-admitted batch. Race-free against every OTHER writer of
   * this fortress because the sole caller (server/src/exit/bundle.ts)
   * already runs this whole method inside the exit-admission lock - see
   * this file's module-level doc comment for the bound that statement
   * relies on.
   *
   * `recordPostImage`, when supplied, is called synchronously with the
   * exact on-disk bytes each new write persists - the same post-image
   * hook `ReputationStore.importBundle` and `rekeyState` use
   * (server/src/exit/bundle.ts `recordPostImage`), so the exit-import
   * journal's divergence check covers this namespace identically to
   * `_reputation`.
   */
  /**
   * Phase 1 of the quota-check-then-write shape, shared by
   * `wouldExceedCapacity` and `persistIfAbsent` so the two can never
   * disagree about which candidates are net-new (AGENTS.md rule 5).
   * Dedupes by storage key - the caller's `entries` array is not itself
   * guaranteed deduplicated - without writing anything.
   */
  private async computeNetNew(
    entries: Array<{ did: string; publicKey: Uint8Array }>
  ): Promise<Map<string, { did: string; publicKey: Uint8Array }>> {
    const netNew = new Map<string, { did: string; publicKey: Uint8Array }>();
    for (const { did, publicKey } of entries) {
      const key = knownSignerStorageKey(did);
      if (netNew.has(key)) continue;
      const existing = await this.storage.read(KNOWN_SIGNERS_NAMESPACE, key);
      if (existing !== null) continue;
      netNew.set(key, { did, publicKey });
    }
    return netNew;
  }

  /**
   * A READ-ONLY capacity dry-run - writes nothing, throws nothing. Lets a
   * caller (importExitBundle, server/src/exit/bundle.ts) preflight the
   * capacity decision BEFORE any OTHER write in the same activation
   * (specifically, before `ReputationStore.importBundle`'s `_reputation`
   * writes), so a batch that would exceed the cap is refused with NOTHING
   * written anywhere - not even the reputation attestations that would
   * themselves have been admitted. `persistIfAbsent` below re-runs the
   * SAME check as the authoritative second line immediately before it
   * writes, so a caller that skips this preflight (or a state change
   * between the two calls) still cannot write past the cap.
   */
  async wouldExceedCapacity(
    entries: Array<{ did: string; publicKey: Uint8Array }>
  ): Promise<{
    exceeds: boolean;
    // `undefined`, not a `-1` sentinel, when nothing net-new means the
    // store-wide count was never read - a caller that (incorrectly) read
    // `currentCount` without first checking `exceeds` would otherwise see
    // a fabricated negative number that looks like real data instead of
    // "not computed".
    currentCount: number | undefined;
    netNewCount: number;
    limit: number;
  }> {
    const netNew = await this.computeNetNew(entries);
    if (netNew.size === 0) {
      return {
        exceeds: false,
        currentCount: undefined,
        netNewCount: 0,
        limit: this.maxKnownSigners,
      };
    }
    const currentCount = (await this.storage.list(KNOWN_SIGNERS_NAMESPACE))
      .length;
    return {
      exceeds: currentCount + netNew.size > this.maxKnownSigners,
      currentCount,
      netNewCount: netNew.size,
      limit: this.maxKnownSigners,
    };
  }

  async persistIfAbsent(
    entries: Array<{ did: string; publicKey: Uint8Array }>,
    importId: string,
    recordPostImage?: (
      namespace: string,
      key: string,
      bytes: Uint8Array
    ) => Promise<void>
  ): Promise<void> {
    // Phase 1 (shared with wouldExceedCapacity - see computeNetNew).
    const netNew = await this.computeNetNew(entries);
    if (netNew.size === 0) return;

    // Phase 2: the store-wide cap check, BEFORE any write. This is the
    // AUTHORITATIVE, second-line check - callers are expected to have
    // already preflighted with `wouldExceedCapacity` before doing anything
    // else that would need rolling back, but this method never trusts that
    // they did.
    const currentCount = (await this.storage.list(KNOWN_SIGNERS_NAMESPACE))
      .length;
    if (currentCount + netNew.size > this.maxKnownSigners) {
      throw new KnownSignersQuotaError(
        currentCount,
        netNew.size,
        this.maxKnownSigners
      );
    }

    // Phase 3: write. Nothing above this point wrote anything, so a thrown
    // KnownSignersQuotaError above always leaves the store byte-unchanged.
    for (const [key, { did, publicKey }] of netNew) {
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
