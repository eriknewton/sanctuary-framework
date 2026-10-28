/** Shared Exit recovery record validation; moved unchanged from exit/bundle.ts. */
import { fromBase64urlStrict } from "../core/encoding.js";

// Must match the named constants in cognitive/state-store.ts and
// reputation/known-signers-store.ts. The storage layer cannot import those
// consumers; sdw-exit-admission.test.ts pins every value and membership arm.
const STATE_ENVELOPE_PUBLIC_KEYS_KEY = "state-envelope-public-keys-v1";
const STATE_ENVELOPE_VERSION_ANCHORS_KEY = "state-envelope-version-anchors-v1";
const KNOWN_SIGNERS_NAMESPACE = "_known_signers";
// Must match isReservedNamespace in cognitive/state-store.ts (full-set witness).
function isReservedNamespace(namespace: string): boolean {
  return namespace.startsWith("_");
}

export const EXIT_IMPORT_NAMESPACE = "_exit_imports";
export const EXIT_PUBLIC_IDENTITIES_NAMESPACE = "_exit_public_identities";
export const EXIT_AUDIT_RECEIPTS_NAMESPACE = "_exit_audit_receipts";
export const EXIT_POLICY_SETS_NAMESPACE = "_exit_policy_sets";
export const EXIT_COMMITMENTS_NAMESPACE = "_exit_commitments";
export const EXIT_PLACEHOLDER_METADATA_NAMESPACE = "_exit_placeholder_metadata";
/**
 * MEDIUM-C (Codex gate, 2026-08-22): caps how many journal-set locations a
 * single import may snapshot/journal, so a crafted or absurd bundle stays
 * bounded to a fixed number of per-location post-image records (one small
 * durable write per location - see recordPostImage) and a fixed-size
 * pre-image snapshot array in the main journal record. 100_000 = two
 * orders of magnitude above the largest real fortress this format has
 * been exercised against (low thousands of state entries plus
 * attestations in the F1 drill's stress bundles), chosen as a safety
 * bound, not a usage estimate - a legitimate export this large is not
 * expected, and a bundle claiming to be is refused before any journal
 * write, not partway through.
 */
export const MAX_EXIT_IMPORT_JOURNAL_LOCATIONS = 100_000;

/** On-disk (JSON-safe) form of a {@link StorageSnapshot}: `data` base64url'd. */
export interface SerializedStorageSnapshot {
  namespace: string;
  key: string;
  data: string | null;
}

/**
 * F1 (Exit V2 drill D1, 2026-08-22; hardened HIGH-1, Codex gate,
 * 2026-08-22, register id EXIT-JOURNAL-DIVERGE-01): the durable rollback
 * record `writeImportJournal` persists and `recoverInterruptedExitImports`
 * replays, confirmed by post-image before any restore write (see
 * classifyRestoreSafety). A parsed record failing its shape check
 * (`isWellFormedExitImportJournalRecord`, exact key-set equality) is
 * routed to `failed`, never partially trusted.
 */
export interface ExitImportJournalRecord {
  import_id: string;
  identity_id: string;
  started_at: string;
  snapshots: SerializedStorageSnapshot[];
}

/**
 * CONTRACT PIN (AGENTS.md rule 11; register id EXIT-JOURNAL-SHAPE-01): the
 * ONE shape check every journal entry passes through before its bytes are
 * trusted. A journal entry this function cannot fully vouch for is routed
 * to the caller's `failed` list - never a crash, and never a silent
 * partial trust.
 */
// ITEM-4 (coordinator gate, 2026-08-22): exact key-set equality per
// element, same reasoning as the top-level record's N7 check - a denylist
// of named fields only ever covers the ONE shape someone thought to name.
const SERIALIZED_STORAGE_SNAPSHOT_KEYS = new Set([
  "namespace",
  "key",
  "data",
]);

function isWellFormedSerializedStorageSnapshot(
  value: unknown
): value is SerializedStorageSnapshot {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (
    keys.length !== SERIALIZED_STORAGE_SNAPSHOT_KEYS.size ||
    !keys.every((k) => SERIALIZED_STORAGE_SNAPSHOT_KEYS.has(k))
  ) {
    return false;
  }
  if (typeof record.namespace !== "string") return false;
  if (typeof record.key !== "string") return false;
  // Codex gate finding (2026-08-22): a `data` string that merely TYPE-checks
  // is not enough - the lenient `fromBase64url` decoder silently accepts
  // non-canonical input (stray characters skipped, odd padding tolerated),
  // so a corrupted or crafted `data` field would decode to SOMETHING rather
  // than being caught here. Round-trip through the strict decoder
  // (`fromBase64urlStrict`) so any non-canonical string routes this whole
  // record to `failed`, not a best-effort decode.
  // `null` (explicit absence - the pre-image did not exist) is distinct
  // from `""` (the pre-image existed and was zero-length) and both are
  // valid; only `null` skips the decode check.
  if (record.data !== null) {
    if (typeof record.data !== "string") return false;
    try {
      fromBase64urlStrict(record.data);
    } catch {
      return false;
    }
  }
  return true;
}

/**
 * CONFINEMENT (register id EXIT-JOURNAL-CONFINE-01): a journal entry is
 * only ever trusted if every location it names is one the exit-import
 * path could actually have produced for SOME import - the exit staging
 * namespaces, the reputation namespace, the two named `_meta` keys a
 * state re-key touches, or the operator's own non-reserved state.
 *
 * CAPABILITY BOUND: this is a shape/membership check, not an
 * authenticator - it proves a location is the RIGHT KIND of thing an
 * import writes, not that THIS SPECIFIC journal is the one an import
 * actually wrote. There is no cryptographic authenticator (MAC) over the
 * journal record itself; that is not implemented this change.
 */
function isLocationWithinImportWriteSet(
  namespace: string,
  key: string
): boolean {
  switch (namespace) {
    case EXIT_PUBLIC_IDENTITIES_NAMESPACE:
    case EXIT_POLICY_SETS_NAMESPACE:
    case EXIT_AUDIT_RECEIPTS_NAMESPACE:
    case EXIT_COMMITMENTS_NAMESPACE:
    case EXIT_PLACEHOLDER_METADATA_NAMESPACE:
    case EXIT_IMPORT_NAMESPACE:
    case "_reputation":
    // Exit V2 drill F2 (2026-08-22/23, falls through to the same `return
    // true` as "_reputation" above): known-signer persistence writes
    // (server/src/reputation/known-signers-store.ts) are part of THIS
    // import's own write set, journaled exactly like `_reputation` -
    // see `activationSnapshotLocations`'s known_signers loop (bundle.ts).
    // falls through
    case KNOWN_SIGNERS_NAMESPACE:
    case "_sdw_document_corpus":
      return true;
    case "_meta":
      return (
        key === STATE_ENVELOPE_PUBLIC_KEYS_KEY ||
        key === STATE_ENVELOPE_VERSION_ANCHORS_KEY
      );
    default:
      // Any OTHER reserved (underscore-prefixed) namespace is never a
      // legitimate import-write location; a non-reserved namespace is the
      // operator's own state and is always in bounds (any key).
      return !isReservedNamespace(namespace);
  }
}

/**
 * N7 (coordinator gate, 2026-08-22): the journal's field set is checked by
 * EXACT equality against this allowlist, not by rejecting one named
 * unsupported key - a denylist of one key only ever covers the ONE shape
 * someone thought to name; an allowlist covers every shape, named or not,
 * by construction (mirrors the Unicode-denylist lesson elsewhere in this
 * codebase: invert to an allowlist).
 */
const EXIT_IMPORT_JOURNAL_RECORD_KEYS = new Set([
  "import_id",
  "identity_id",
  "started_at",
  "snapshots",
]);

export function isWellFormedExitImportJournalRecord(
  value: unknown
): value is ExitImportJournalRecord {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (
    keys.length !== EXIT_IMPORT_JOURNAL_RECORD_KEYS.size ||
    !keys.every((k) => EXIT_IMPORT_JOURNAL_RECORD_KEYS.has(k))
  ) {
    return false;
  }
  if (typeof record.import_id !== "string") return false;
  if (typeof record.identity_id !== "string") return false;
  if (typeof record.started_at !== "string") return false;
  if (!Array.isArray(record.snapshots)) return false;
  if (!record.snapshots.every(isWellFormedSerializedStorageSnapshot)) return false;
  if (
    !record.snapshots.every((snapshot) =>
      isLocationWithinImportWriteSet(
        (snapshot as SerializedStorageSnapshot).namespace,
        (snapshot as SerializedStorageSnapshot).key
      )
    )
  ) {
    return false;
  }
  return true;
}

/**
 * Codex gate MEDIUM (2026-08-23): a SHALLOW pre-check run BEFORE
 * `isWellFormedExitImportJournalRecord`'s full per-element traversal
 * (`snapshots.every(isWellFormedSerializedStorageSnapshot)`, plus the
 * namespace-membership check on every element). The cap this function
 * enforces exists precisely so a journal record cannot force unbounded
 * per-element work; running the full validation FIRST and only checking
 * the cap afterward means the length itself already bought an attacker
 * the full O(N) traversal it was supposed to bound. This function only
 * trusts `typeof`/`Array.isArray`/`.length` - never a well-formed
 * element - so it stays cheap regardless of what the array contains.
 */
export function hasOversizedSnapshotsArray(value: unknown): boolean {
  if (value === null || typeof value !== "object") return false;
  const snapshots = (value as Record<string, unknown>).snapshots;
  return Array.isArray(snapshots) && snapshots.length > MAX_EXIT_IMPORT_JOURNAL_LOCATIONS;
}
