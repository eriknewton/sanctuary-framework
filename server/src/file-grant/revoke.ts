/**
 * Governed File-Grant v1 -- revoke orchestration (build spec sections 3, 5, 7).
 *
 * Revoke is safe-direction (it only ever REDUCES access), so unlike mint it
 * is not gated behind Tier-1 approval -- it is Tier-3 auto-allow+audit. The
 * ordering here still protects the one invariant that matters for a
 * safe-direction op: the persisted record is marked `revoked` BEFORE the
 * tree scrub is attempted, so a scrub failure can never leave the
 * authoritative record showing `active` while the operator believes the
 * grant is gone. If the scrub throws, the error propagates (the caller
 * learns the tree entry may still be present) but the store record stays
 * revoked -- it is never resurrected.
 *
 * Double-revoke is a no-op-success: revoking an already-revoked grant
 * re-attempts the (idempotent) scrub and returns `alreadyRevoked: true`
 * rather than erroring.
 *
 * THROW CONTRACT (round 4, opus LOW-2): `removeEntry` may, in the rare
 * concurrent-place-then-reapply-fails path, throw
 * `FileGrantFortressAceReapplyError` (the shared fortress traverse ACE could
 * not be re-applied for a grant a concurrent mint placed mid-removal). This
 * propagates here as a scrub error, is audited (`tree_scrub_failed`), and is
 * re-thrown to the caller -- FAIL-CLOSED: by the time it can throw, THIS
 * grant's access is already gone (the record was marked `revoked` first, and
 * `removeEntry` removed the tree entry + source-inode ACE before it reached
 * the shared-ACE step). The unreachable grant is the CONCURRENT mint's, which
 * a later `reconcileFileGrantTree` (or the next mint's idempotent re-apply)
 * re-converges. Callers must treat the throw as "revoke succeeded in reducing
 * access; the shared-ACE cleanup needs a retry," never as "access may still
 * be live."
 */

import type { AuditLog } from "../operational/audit-log.js";
import { reviseGrantForRevoke } from "./lifecycle.js";
import type { FileGrant, FileGrantRemoveEntryResult, FsOps } from "./types.js";

export interface FileGrantRevokeStore {
  get(grantId: string): Promise<FileGrant | null>;
  put(grant: FileGrant): Promise<void>;
}

export interface RevokeFileGrantDeps {
  fsOps: Pick<FsOps, "removeEntry">;
  store: FileGrantRevokeStore;
  /** Injected clock reading. Never `new Date()` inside this module. */
  now: Date;
  auditLog?: AuditLog;
}

export interface RevokeFileGrantResult {
  found: boolean;
  alreadyRevoked: boolean;
  grant: FileGrant | null;
  treeEntryRemoved: boolean;
  scrubbed: boolean;
  aclRemoval: FileGrantRemoveEntryResult["aclRemoval"] | null;
}

export async function revokeFileGrant(
  grantId: string,
  revokedBy: string,
  deps: RevokeFileGrantDeps
): Promise<RevokeFileGrantResult> {
  const existing = await deps.store.get(grantId);
  if (!existing) {
    await deps.auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant_revoke",
      identity_id: revokedBy,
      result: "failure",
      details: { grant_id: grantId, reason: "not_found" },
    });
    return {
      found: false,
      alreadyRevoked: false,
      grant: null,
      treeEntryRemoved: false,
      scrubbed: false,
      aclRemoval: null,
    };
  }

  const alreadyRevoked = existing.status === "revoked";
  const revised = reviseGrantForRevoke(existing, deps.now);
  if (!alreadyRevoked) {
    await deps.store.put(revised);
  }

  let removeResult: FileGrantRemoveEntryResult;
  try {
    removeResult = await deps.fsOps.removeEntry(existing.tree_entry, {
      grantedReadAce: existing.granted_read_ace ?? null,
    });
  } catch (scrubErr) {
    await deps.auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant_revoke",
      identity_id: revokedBy,
      result: "failure",
      details: {
        grant_id: grantId,
        already_revoked: alreadyRevoked,
        reason: "tree_scrub_failed",
      },
    });
    throw scrubErr;
  }

  let resultGrant = revised;
  if (removeResult.scrubbed && revised.granted_read_ace) {
    const clearedGrant = { ...revised, granted_read_ace: null };
    try {
      await deps.store.put(clearedGrant);
      resultGrant = clearedGrant;
    } catch (persistErr) {
      await deps.auditLog?.appendCritical({
        layer: "l1",
        operation: "file_grant_revoke",
        identity_id: revokedBy,
        result: "failure",
        details: {
          grant_id: grantId,
          already_revoked: alreadyRevoked,
          reason: "ace_metadata_clear_persist_failed",
          retryable: true,
          tree_entry_removed: removeResult.treeEntryRemoved,
          acl_removal: removeResult.aclRemoval,
        },
      });
      throw persistErr;
    }
  }

  if (!removeResult.scrubbed) {
    await deps.auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant_revoke",
      identity_id: revokedBy,
      result: "failure",
      details: {
        grant_id: grantId,
        already_revoked: alreadyRevoked,
        reason: "acl_removal_failed",
        retryable: true,
        tree_entry_removed: removeResult.treeEntryRemoved,
        acl_removal: removeResult.aclRemoval,
      },
    });
    return {
      found: true,
      alreadyRevoked,
      grant: revised,
      treeEntryRemoved: removeResult.treeEntryRemoved,
      scrubbed: false,
      aclRemoval: removeResult.aclRemoval,
    };
  }

  await deps.auditLog?.appendCritical({
    layer: "l1",
    operation: "file_grant_revoke",
    identity_id: revokedBy,
    result: "success",
    details: {
      grant_id: grantId,
      already_revoked: alreadyRevoked,
      tree_entry_removed: removeResult.treeEntryRemoved,
      acl_removal: removeResult.aclRemoval,
    },
  });

  return {
    found: true,
    alreadyRevoked,
    grant: resultGrant,
    treeEntryRemoved: removeResult.treeEntryRemoved,
    scrubbed: true,
    aclRemoval: removeResult.aclRemoval,
  };
}
