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
 * approval, forever, driven by agent-controlled call volume. The hub keeps a
 * separate, capped list of cards IT decided (`HubService.rememberCharterDecision`)
 * so the Decided view can show them; those entries are resolved cards admitted
 * only by an accepted operator decision, so they never read as open holds.
 */

import type {
  HubApprovalPendingItem,
  HubDisplayTemplateArg,
} from "../contracts/v1.1/hub-events.js";
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
  /**
   * The hub agent id of the agent this server process is configured for
   * (its wrap-time `SANCTUARY_AGENT_ID`), when the gate knew it: the agent
   * whose call was held. It is the REQUESTER, never the operation's target; the
   * target is whatever the held call's own arguments name. Must match
   * `ApprovalRequest.requesting_agent_id` in server/src/principal-policy/types.ts,
   * whose only writer is `ApprovalGate.requestingAgentId` (never a tool
   * argument). Absent means unattributed.
   */
  requesting_agent_id?: string;
  /**
   * The gate's own reason for the hold, verbatim. Must match
   * `ApprovalRequest.reason` in server/src/principal-policy/types.ts, whose
   * production writer is `ApprovalGate.requestApproval` (its classification
   * and anomaly strings). Absent means the queue served none.
   */
  reason?: string;
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
 *
 * Must match CHARTER_APPROVAL_ITEM_ID_PREFIX in server/src/dashboard/v1_1/client.ts,
 * which uses it to say where a decision on a held item is recorded.
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
export const OPERATION_NAME_CATEGORIES = [
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
 * Categories whose catalog sentence, given no `agent_id` argument, still names
 * a definite subject: `identity_rotate` reads "Rotate the identity key for this
 * fortress." and `sanctuary_export_identity_bundle` reads as the operator's
 * bundle, while both tools take an `identity_id` that can name another
 * identity. A Charter card carries no verified target, so for these the card
 * renders the tier's catch-all sentence, which names no target, while
 * `operation_category` still says what is held. Must match the `agent_id`
 * fallbacks in the approval_pending.* entries of
 * server/src/dashboard/v1_1/templates.ts; a full-set test renders every
 * category in OPERATION_NAME_CATEGORIES to keep this list complete.
 */
const TARGET_DEFAULTING_CATEGORIES: ReadonlySet<HubApprovalPendingItem["operation_category"]> =
  new Set(["identity_rotate", "sanctuary_export_identity_bundle"]);

/**
 * Display bound on `hold_reason`, in UTF-16 code units. The gate's fixed reason
 * templates are all under 200 characters; the rest is room for the identifier
 * some of them quote (a namespace name or a counterparty DID), whose length the
 * gate does not bound. 512 keeps one card, and the capped decided history that
 * retains cards, at a known size whatever the held call named.
 */
export const HOLD_REASON_MAX_CHARS = 512;
const HOLD_REASON_TRUNCATION_MARK = " (truncated)";

function boundedHoldReason(reason: string): string {
  if (reason.length <= HOLD_REASON_MAX_CHARS) return reason;
  return (
    reason.slice(0, HOLD_REASON_MAX_CHARS - HOLD_REASON_TRUNCATION_MARK.length) +
    HOLD_REASON_TRUNCATION_MARK
  );
}

/**
 * Project one live Charter hold into an inbox card.
 *
 * The card carries NO argument detail in its template arguments.
 * `HubDisplayTemplateArg` is a closed typed union with no free-text member
 * precisely so a backend cannot smuggle raw tool arguments into operator copy,
 * and a Charter hold's context is raw tool arguments. The card therefore says
 * which tier is waiting, which operation is held, on which identity, and (when
 * the gate stamped it) which configured agent asked; it names no target. The
 * gate's own reason rides beside the template as `hold_reason`, never inside
 * it. `GET /api/pending` remains the surface that carries the redacted
 * argument summary.
 */
export function projectCharterApproval(
  record: CharterApprovalRecord,
  identityId: string,
): HubApprovalPendingItem {
  const tier = record.tier === 1 ? "tier1" : "tier2";
  const category = categoryFor(record.operation);
  // The approval_pending.tier2.* catalog has no sentence for any category this
  // bridge maps (only `policy_change`, which it never emits, and `other`), so a
  // Tier 2 hold always uses the Tier 2 catch-all rather than an unregistered id.
  const templateCategory =
    tier === "tier2" || TARGET_DEFAULTING_CATEGORIES.has(category) ? "other" : category;
  // Rule 7: `requesting_agent_id` is the agent this server process is configured
  // for, stamped by the gate; it says who ASKED, never what the operation acts
  // on. It is therefore carried only as the card's top-level `agent_id`, which
  // the console renders as the requester (approvalAgentId in
  // server/src/dashboard/v1_1/client.ts: the Agent column and "Requested by"),
  // and NEVER as a template `agent_id` argument, because the approval_pending.*
  // sentences read that argument as the operation's TARGET ("Rotate the identity
  // key for <agent_id>"). A Charter card has no verified target, so its sentence
  // gets none. `identity_id` stays the hub identity because the inbox scopes by it.
  const agentId = record.requesting_agent_id;
  // The operation name is the gate's own `operation` (the tool it classified),
  // not an argument of the call, so the catch-all `.other` sentence and the
  // console's Operation column can name what is held instead of "other".
  const displayArgs: HubDisplayTemplateArg[] = [
    { kind: "identity_id", value: identityId },
    { kind: "operation", value: record.operation },
  ];
  // Must-never #7 bounds what the AGENT learns from a denial: the gate returns
  // it a generic reason. This card is OPERATOR copy, served only to
  // operator-authenticated reads (a loopback-position read drops every approval
  // item), so it carries the gate's reason verbatim and nothing beyond it: the
  // same string the gate already sends the operator on `GET /api/pending` and
  // writes to its decision audit row, with no policy rule or tier logic added.
  const holdReason =
    typeof record.reason === "string" && record.reason.length > 0
      ? boundedHoldReason(record.reason)
      : undefined;
  return {
    version: "1.1",
    item_id: charterApprovalItemId(record.id),
    kind: "approval_pending",
    created_at: record.created_at,
    identity_id: identityId,
    ...(agentId ? { agent_id: agentId } : {}),
    // Template ids are `<namespace>.<tier>.<category>`; `.other` is the
    // catalog's registered fallback, so an unmapped operation still renders
    // real copy instead of "[unrecognized template: ...]" on a live card.
    display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.${tier}.${templateCategory}`,
    display_template_args: displayArgs,
    resolved: false,
    tier,
    operation_category: category,
    ...(holdReason ? { hold_reason: holdReason } : {}),
  };
}
