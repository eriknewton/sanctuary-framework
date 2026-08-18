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
      (value) => JSON.parse(value) as FileGrant
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
