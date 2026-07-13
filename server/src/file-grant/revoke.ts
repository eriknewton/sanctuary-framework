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
 */

import type { AuditLog } from "../operational/audit-log.js";
import { reviseGrantForRevoke } from "./lifecycle.js";
import type { FileGrant, FsOps } from "./types.js";

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
    return { found: false, alreadyRevoked: false, grant: null };
  }

  const alreadyRevoked = existing.status === "revoked";
  const revised = reviseGrantForRevoke(existing, deps.now);
  if (!alreadyRevoked) {
    await deps.store.put(revised);
  }

  try {
    await deps.fsOps.removeEntry(existing.tree_entry, {
      canonicalAclTarget: existing.scope.path,
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

  await deps.auditLog?.appendCritical({
    layer: "l1",
    operation: "file_grant_revoke",
    identity_id: revokedBy,
    result: "success",
    details: { grant_id: grantId, already_revoked: alreadyRevoked },
  });

  return { found: true, alreadyRevoked, grant: revised };
}
