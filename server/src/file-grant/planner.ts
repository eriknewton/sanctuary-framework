/**
 * Governed File-Grant v1 -- pure grant-tree planner (build spec section 6).
 *
 * `planGrantTree` takes the live grant set and a clock reading and returns
 * the tree contents the grant tree SHOULD have right now: entries to place
 * (active, unexpired grants) and entries to scrub (revoked or expired
 * grants). No I/O. Fully deterministic so the injected-`FsOps` tree manager
 * can diff its actual state against this plan and reconcile.
 */

import { isGrantExpired } from "./lifecycle.js";
import type { FileGrant, TreePlan, TreePlanEntry } from "./types.js";

/**
 * Compute the desired grant-tree contents for a set of live grants at time
 * `now`. Deterministic ordering (sorted by `grant_id`) and de-duplicated by
 * `tree_entry` so a caller never issues two placements for the same path.
 */
export function planGrantTree(grants: readonly FileGrant[], now: Date): TreePlan {
  const toPlace: TreePlanEntry[] = [];
  const toScrub: TreePlanEntry[] = [];
  const placedTreeEntries = new Set<string>();

  const sorted = [...grants].sort((a, b) => a.grant_id.localeCompare(b.grant_id));

  for (const grant of sorted) {
    const entry: TreePlanEntry = {
      grant_id: grant.grant_id,
      relative_tree_entry: grant.tree_entry,
    };

    const expired = isGrantExpired(grant, now);

    if (grant.status === "active" && !expired) {
      if (!placedTreeEntries.has(grant.tree_entry)) {
        placedTreeEntries.add(grant.tree_entry);
        toPlace.push(entry);
      }
      continue;
    }

    // status === "revoked", status === "expired", or a live grant whose
    // computed expiry has passed but whose persisted status has not caught
    // up yet: the tree must not hold it.
    toScrub.push(entry);
  }

  return { toPlace, toScrub };
}
