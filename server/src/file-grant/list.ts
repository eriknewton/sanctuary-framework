/**
 * Governed File-Grant v1 -- list projection (build spec section 3.2).
 *
 * Read-only: projects each persisted grant's EFFECTIVE status at `now`
 * (`projectGrantStatus`) without mutating the store, so a grant whose TTL
 * has passed renders as "expired" immediately, even before any sweep
 * updates the persisted record. Tier-3 (auto-allow, no approval gate).
 */

import type { AuditLog } from "../operational/audit-log.js";
import { projectGrantStatus } from "./lifecycle.js";
import type { FileGrant } from "./types.js";

export interface FileGrantListStore {
  list(): Promise<FileGrant[]>;
}

export interface ProjectedFileGrant extends FileGrant {
  /** Effective status at the time of listing; may differ from the persisted `status`. */
  projected_status: FileGrant["status"];
}

export async function listFileGrants(
  store: FileGrantListStore,
  now: Date,
  filter?: { subjectAgentId?: string }
): Promise<ProjectedFileGrant[]> {
  const grants = await store.list();
  const filtered = filter?.subjectAgentId
    ? grants.filter((g) => g.subject_agent_id === filter.subjectAgentId)
    : grants;
  return filtered
    .map((grant) => ({ ...grant, projected_status: projectGrantStatus(grant, now) }))
    .sort((a, b) => a.grant_id.localeCompare(b.grant_id));
}

/**
 * Append the `file_grant_list` access audit (Fix 6 / build spec section 3.2:
 * `list` is Tier-3 auto-allow AND audited). Records who listed, the agent
 * filter applied (or "all"), and the count returned -- never the grant paths
 * themselves. Called by the CLI list handler after projecting the grants.
 * Best-effort: a read-only list must not fail because the audit line could not
 * be written.
 */
export async function recordFileGrantListAudit(
  auditLog: AuditLog | undefined,
  listedBy: string,
  filter: { subjectAgentId?: string } | undefined,
  count: number
): Promise<void> {
  try {
    await auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant_list",
      identity_id: listedBy,
      result: "success",
      details: {
        agent_filter: filter?.subjectAgentId ?? "all",
        count,
      },
    });
  } catch {
    // Best-effort: listing is read-only; an audit-write failure must not turn
    // a successful list into a failure.
  }
}
