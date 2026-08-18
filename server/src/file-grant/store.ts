/**
 * Governed File-Grant v1 -- StateStore persistence (build spec section 3.1).
 *
 * A `FileGrant` is a first-class encrypted state object in the reserved
 * `_file_grants` namespace. This thin wrapper is the ONLY place that knows
 * how a `FileGrant` is serialized into a StateStore entry; `mint.ts` /
 * `revoke.ts` / the CLI all go through it. Because it calls the StateStore's
 * own `write`/`read`/`list`/`delete` methods directly, a grant round-trips
 * through the exact same encrypted, signed, monotonic-versioned, Merkle-
 * verified machinery every other piece of Sanctuary state does (AGENTS.md
 * Invariant #2), even though the reserved `_`-prefix namespace firewall in
 * `cognitive/tools.ts` correctly keeps the agent-facing `state_read`/
 * `state_list`/`state_delete` MCP tools from reaching it directly -- the same
 * posture as `_audit`, `_identities`, and every other internal namespace.
 */

import type { EncryptedPayload } from "../core/encryption.js";
import type { StateStore } from "../cognitive/state-store.js";
import { scanNamespaceEntries } from "../cognitive/namespace-scan.js";
import {
  FILE_GRANT_NAMESPACE,
  FileGrantUnreadableEntriesError,
  type FileGrant,
  type FileGrantListing,
} from "./types.js";

/**
 * Decode one persisted `_file_grants` record, ASSERTING the shape the reconcile
 * pass will act on rather than casting to it.
 *
 * WHY A VALIDATION AND NOT A CAST. The consumer of this decode plans a set of
 * tree-entry REMOVALS out of these fields and then executes them. A cast lets a
 * record that is valid JSON but not a grant travel into that planner, where
 * reading a field off it is the first thing that happens -- and a throw THERE
 * lands outside the per-entry isolation this scan exists to provide, so one
 * such record can take down every other grant's scrub, which is precisely the
 * loss the tolerant listing was built to end. Throwing HERE is inside the
 * isolation: the record is recorded as unreadable, its own tree entry is left
 * alone (its state is genuinely unknown), the caller is told which record it
 * was, and every other grant reconciles normally. The pattern is the one
 * `evidence-pack/observe-candidates.ts` already applies at its own persisted
 * boundary; this is the same boundary with a different policy attached.
 *
 * WHY THESE FOUR FIELDS AND NOT THE WHOLE SCHEMA. They are exactly the fields
 * the reconcile reads to decide whether to TAKE ACCESS AWAY: which record this
 * is, which tree entry it owns, and the two the expiry verdict is computed
 * from. Checking fewer would let a record with no usable `expires_at` compute
 * as "not expired" and keep its entry placed for good; checking the rest of the
 * schema here would refuse records over fields this path never consults, which
 * turns a display concern into an access-reduction refusal.
 *
 * WHY IT THROWS AND NEVER RETURNS `null`. The shared scan documents `null` as
 * "not one of mine, skip it without recording a failure". Nothing in the
 * reserved grant namespace is somebody else's row, so a record that does not
 * decode is a LOSS, and a loss reported as a skip is the absence-reads-as-a-
 * pass shape this module refuses everywhere else.
 */
function decodeFileGrantRecord(value: string, key: string): FileGrant {
  const parsed: unknown = JSON.parse(value);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`grant record ${key} did not decode to a grant object`);
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.grant_id !== "string" || record.grant_id.length === 0) {
    throw new Error(`grant record ${key} carries no grant_id`);
  }
  if (typeof record.tree_entry !== "string" || record.tree_entry.length === 0) {
    throw new Error(`grant record ${key} carries no tree_entry`);
  }
  if (
    record.status !== "active" &&
    record.status !== "revoked" &&
    record.status !== "expired"
  ) {
    throw new Error(`grant record ${key} carries no recognized status`);
  }
  if (record.expires_at !== null && typeof record.expires_at !== "string") {
    throw new Error(`grant record ${key} carries no usable expires_at`);
  }
  return parsed as FileGrant;
}

/** The signing identity a `FileGrantStore` writes under. */
export interface FileGrantWriteIdentity {
  identityId: string;
  encryptedPrivateKey: EncryptedPayload;
  identityEncryptionKey: Uint8Array;
}

export class FileGrantStore {
  constructor(
    private readonly stateStore: StateStore,
    private readonly identity: FileGrantWriteIdentity
  ) {}

  async put(grant: FileGrant): Promise<void> {
    await this.stateStore.write(
      FILE_GRANT_NAMESPACE,
      grant.grant_id,
      JSON.stringify(grant),
      this.identity.identityId,
      this.identity.encryptedPrivateKey,
      this.identity.identityEncryptionKey,
      { content_type: "application/json", tags: ["file-grant"] }
    );
  }

  async get(grantId: string): Promise<FileGrant | null> {
    const result = await this.stateStore.read(FILE_GRANT_NAMESPACE, grantId);
    if (!result) return null;
    return JSON.parse(result.value) as FileGrant;
  }

  /**
   * The per-entry-tolerant listing: every grant that reads back, plus the ids
   * of the ones that do not.
   *
   * WHY THE FAN-OUT MUST TOLERATE A PER-ENTRY FAILURE. This is the read that
   * feeds `reconcileFileGrantTree`, whose whole job is to scrub the tree
   * entries of grants that must no longer be readable. If one unreadable record
   * takes the listing down, reconcile never reaches its scrub loop, and the
   * scrub's own carefully best-effort-per-entry structure is worth nothing: an
   * expired grant's tree entry and read ACE survive its TTL because a DIFFERENT
   * grant could not be read. Tolerating here is what makes the scrub reachable;
   * the caller is still handed `unreadable` so a partial set can never be
   * mistaken for a complete one.
   *
   * WHAT COUNTS AS "DOES NOT READ BACK" HERE. Both a read that rejects and a
   * record that comes back but does not carry a grant's shape. The second half
   * is `decodeFileGrantRecord` below, and it is not a nicety: the isolation the
   * scan provides ends at this decode, so a record admitted by a cast fails
   * later, in the caller, outside the isolation, where it takes every other
   * grant's reconcile down with it.
   *
   * Paging is delegated to `scanNamespaceEntries`, which pages to exhaustion.
   * `stateStore.list` caps each call at `limit`, so an unpaged call would
   * silently drop grants past the cap -- leaving them not merely unlisted but
   * UNRECONCILED (an expired grant beyond the cap would never be scrubbed).
   * (R2-6.)
   */
  async listEntries(): Promise<FileGrantListing> {
    const { items, failures } = await scanNamespaceEntries<FileGrant>(
      this.stateStore,
      FILE_GRANT_NAMESPACE,
      decodeFileGrantRecord
    );
    return {
      grants: items,
      unreadable: failures.map((failure) => ({
        grant_id: failure.key,
        cause: failure.error,
      })),
    };
  }

  /**
   * The strict listing: every grant, or a throw.
   *
   * This is the shape the DISPLAY path wants (`listFileGrants`). Rendering a
   * grant table that silently omits an unreadable grant would tell an operator
   * that access does not exist when the truth is that it could not be read, so
   * this path stays fail-closed. Reconcile uses `listEntries()` instead,
   * because there the tolerant read is what lets the safety-critical scrub run
   * at all.
   */
  async list(): Promise<FileGrant[]> {
    const listing = await this.listEntries();
    if (listing.unreadable.length > 0) {
      throw new FileGrantUnreadableEntriesError(
        listing.unreadable.map((entry) => entry.grant_id),
        listing.unreadable[0]!.cause
      );
    }
    return listing.grants;
  }

  async remove(grantId: string): Promise<void> {
    await this.stateStore.delete(FILE_GRANT_NAMESPACE, grantId);
  }
}
