/**
 * Governed File-Grant v1 -- list projection (build spec section 3.2).
 *
 * Read-only: projects each persisted grant's EFFECTIVE status at `now`
 * (`projectGrantStatus`) without mutating the store, so a grant whose TTL
 * has passed renders as "expired" immediately, even before any sweep
 * updates the persisted record. Tier-3 (auto-allow, no approval gate).
 */

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
