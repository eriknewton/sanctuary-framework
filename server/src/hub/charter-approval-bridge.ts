/**
 * Sanctuary v1.1. Charter approval bridge
 *
 * The Charter approval queue (the runtime human-in-the-loop gate in
 * `principal-policy`) and the v1.1 operator inbox are two different stores of
 * two different things. The Charter queue holds the LIVE, blocking Tier 1 /
 * Tier 2 requests an agent's tool call is waiting on; the hub inbox holds the
 * operator-attention cards the v1.1 dashboard renders. A fortress started by a
 * generic `sanctuary protect` raises only the first kind: it registers no named
 * agent and enqueues no hub-side control action, so every one of its holds
 * lives exclusively in the Charter queue.
 *
 * This module is the projection between them. It exists so a live Charter hold
 * appears on the same v1.1 surfaces (`GET /api/hub/inbox`, and therefore the
 * Overview approvals tile and the Talk-screen "Waiting on you" rail) that
 * `GET /api/pending` and the `/m` companion already show, and so the rail's
 * Approve / Deny reaches the blocked call rather than only marking a card.
 *
 * Ownership invariant: the Charter queue stays the sole owner of these holds.
 * The projection is read-through on every list, and resolution delegates to the
 * queue. Nothing here is written into `HubInboxStore`, because a hold that
 * leaves the queue (approved elsewhere, denied elsewhere, or auto-denied on
 * timeout) must vanish from the inbox in the same breath. Upserting these into
 * the store would instead retain one unresolved phantom card per agent-raised
 * approval, forever, driven by agent-controlled call volume.
 */

import type { HubApprovalPendingItem } from "../contracts/v1.1/hub-events.js";
import { HUB_INBOX_TEMPLATE_NAMESPACES } from "./constants.js";

/**
 * One live Charter hold, in the shape the approval channel already exposes to
 * `GET /api/pending`. Must match the `PendingApproval` fields assembled in
 * `server/src/principal-policy/dashboard.ts` (`aggregatorSources`), which are
 * in turn the `PendingApproval` interface in
 * `server/src/dashboard/aggregator.ts`.
 */
export interface CharterApprovalRecord {
  id: string;
  operation: string;
  tier: 1 | 2;
  created_at: string;
}

/**
 * The read-through + resolve contract a Charter approval channel installs on
 * the hub. `resolve` returns false when the hold is no longer live (already
 * decided through another surface, or auto-denied on timeout), which the hub
 * reports as a not-found rather than silently marking a card resolved.
 *
 * Every method is bounded on purpose. The queue's population is driven by
 * agent call volume (one entry per blocked tool call) and is bounded only in
 * TIME, by the approval channel's own timeout: admission itself has no count
 * cap (register row `defect.approval-queue-admission-has-no-count-cap`). So a
 * list that walked the whole queue would make an operator page cost O(live
 * holds) and a resolution that scanned for its id would make one click cost
 * the same. The implementor MUST honor `limit` by stopping the walk, not by
 * building the full array and slicing it, and MUST answer `get` by key.
 */
export interface CharterApprovalBridge {
  /**
   * At most `limit` live holds. `limit` is the page size the caller will
   * actually render, so records past it are work whose result is discarded.
   * A `limit` of zero or less yields nothing; `Number.POSITIVE_INFINITY` is
   * how a caller with no page to render asks for the complete set.
   */
  list(limit: number): CharterApprovalRecord[];
  /** One live hold by id, by direct key lookup. Null when it is not live. */
  get(approvalId: string): CharterApprovalRecord | null;
  resolve(approvalId: string, decision: "approve" | "deny"): boolean;
}

/**
 * Item-id namespace for projected Charter holds. It must not collide with the
 * hub's own enqueued ids (`task.review.*`, `agent.*`), because the id is the
 * routing key: `HubService.resolveInboxItem` sends anything under this prefix
 * to the bridge and everything else to `HubInboxStore`.
 */
export const CHARTER_APPROVAL_ITEM_ID_PREFIX = "charter.approval.";

export function charterApprovalItemId(approvalId: string): string {
  return `${CHARTER_APPROVAL_ITEM_ID_PREFIX}${approvalId}`;
}

/**
 * True for ANY id under the reserved prefix, including a prefix with an empty
 * or malformed remainder.
 *
 * The namespace is reserved unconditionally, whether or not a bridge is
 * installed, because it is a routing key and not merely a naming convention.
 * `HubInboxStore` refuses these ids (`upsertFromSource`, `enqueueTier1`) and
 * `HubService.resolveInboxItem` refuses them when no bridge is installed:
 * without that, a source-supplied item wearing this id would land in the store
 * and resolve `resolved: true` with no Charter queue decision behind it, which
 * is a card that claims an operator approved something nobody approved.
 */
export function isCharterApprovalItemId(itemId: string): boolean {
  return itemId.startsWith(CHARTER_APPROVAL_ITEM_ID_PREFIX);
}

/** The Charter approval id inside a projected item id, or null if not one. */
export function charterApprovalIdFromItemId(itemId: string): string | null {
  if (!isCharterApprovalItemId(itemId)) return null;
  const id = itemId.slice(CHARTER_APPROVAL_ITEM_ID_PREFIX.length);
  return id.length > 0 ? id : null;
}

/**
 * Operation names that are also `HubApprovalPendingItem.operation_category`
 * members. The category is a coarse grouping enum, NOT the operation name, so
 * only an exact member may be carried across; every other operation is
 * `other`. Widening this map means adding the name to the category union in
 * `server/src/contracts/v1.1/hub-events.ts` AND to the Tier 1 set in
 * `server/src/principal-policy/loader.ts` in the same change.
 */
const OPERATION_NAME_CATEGORIES = [
  "state_export",
  "state_import",
  "state_delete",
  "identity_rotate",
  "reputation_export",
  "reputation_import",
  "sanctuary_export_identity_bundle",
] as const satisfies readonly HubApprovalPendingItem["operation_category"][];

const OPERATION_NAME_CATEGORY_SET: ReadonlySet<string> = new Set(
  OPERATION_NAME_CATEGORIES,
);

function categoryFor(
  operation: string,
): HubApprovalPendingItem["operation_category"] {
  return OPERATION_NAME_CATEGORY_SET.has(operation)
    ? (operation as HubApprovalPendingItem["operation_category"])
    : "other";
}

/**
 * Project one live Charter hold into an inbox card.
 *
 * The card carries NO argument detail. `HubDisplayTemplateArg` is a closed
 * typed union with no free-text member precisely so a backend cannot smuggle
 * raw tool arguments into operator copy, and a Charter hold's context is raw
 * tool arguments. The card therefore says which tier is waiting and on which
 * identity; `GET /api/pending` remains the surface that carries the redacted
 * argument summary.
 */
export function projectCharterApproval(
  record: CharterApprovalRecord,
  identityId: string,
): HubApprovalPendingItem {
  const tier = record.tier === 1 ? "tier1" : "tier2";
  const category = categoryFor(record.operation);
  return {
    version: "1.1",
    item_id: charterApprovalItemId(record.id),
    kind: "approval_pending",
    created_at: record.created_at,
    identity_id: identityId,
    // Template ids are `<namespace>.<tier>.<category>`; `.other` is the
    // catalog's registered fallback, so an unmapped operation still renders
    // real copy instead of "[unrecognized template: ...]" on a live card.
    display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.${tier}.${category}`,
    display_template_args: [{ kind: "identity_id", value: identityId }],
    resolved: false,
    tier,
    operation_category: category,
  };
}
