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
  HubApprovalPreviewArg,
  HubDisplayTemplateArg,
  HubHoldReason,
  HubHoldReasonCode,
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
  /** Must match charterApprovalRecord in principal-policy/dashboard.ts and HubApprovalPendingItem.expires_at in contracts/v1.1/hub-events.ts. */
  expires_at?: string;
  /** Must match ApprovalRequest.operator_preview in principal-policy/types.ts and HubApprovalPendingItem.operator_preview in contracts/v1.1/hub-events.ts. */
  operator_preview?: HubApprovalPreviewArg[];
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
   * Why the gate held the call, as structured data: the result of
   * `classifyHoldReason` over the hold's `ApprovalRequest.reason` and
   * `context` (server/src/principal-policy/types.ts), computed where the queue
   * builds this record. Never the free-text reason itself.
   */
  hold_reason?: HubHoldReason;
}

/** A recently closed hold carries only decision metadata, never request arguments. */
export interface ClosedCharterApproval {
  decided_by: "timeout" | "human" | "shutdown";
  decision: "approve" | "deny";
  decided_at: string;
  expired_after_seconds: number;
}

/**
 * The read-through + resolve contract a Charter approval channel installs on
 * the hub. `resolve` returns false when the hold is no longer live (already
 * decided through another surface, or auto-denied on timeout), which the hub
 * reports as a typed refusal rather than silently marking a card resolved.
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
  /** Must match DashboardApprovalChannel.closedApproval in principal-policy/dashboard.ts. Null after bounded retention. */
  closed?(approvalId: string): ClosedCharterApproval | null;
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
 * Display bound on `HubHoldReason.subject`, in UTF-16 code units. A namespace
 * name or counterparty DID has no length bound at the gate; 128 is room for any
 * DID method in use here plus a long namespace, and keeps one card, and the
 * capped decided history that retains cards, at a known size whatever the held
 * call named.
 */
export const HOLD_REASON_SUBJECT_MAX_CHARS = 128;

/**
 * Display bound on a card's held `operation` name, in UTF-16 code units. It is
 * the same bound as a quoted subject for the same reason: a proxied tool name
 * is advertised by an upstream server and an uncategorised one is whatever the
 * call named, so neither has a length bound before it reaches the card.
 */
export const CARD_OPERATION_MAX_CHARS = HOLD_REASON_SUBJECT_MAX_CHARS;

function finiteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** What one reason template needs to re-render: the gate's operation and the hold's context fields. */
interface HoldReasonInputs {
  operation: string;
  context: Record<string, unknown>;
}

/**
 * One gate reason template: given the hold's own fields it re-renders the exact
 * string the gate writes, or null when a field it needs is missing, plus the
 * identifier it quotes (if any) so the card can carry that alone.
 */
interface HoldReasonTemplate {
  code: Exclude<HubHoldReasonCode, "unrecognized">;
  /**
   * The reason literal exactly as it is written in
   * server/src/principal-policy/gate.ts, `${...}` placeholders included (a
   * literal split across `+` is joined). Must match that literal: the coverage
   * test in server/test/hub/charter-hold-reason.test.ts reads every reason
   * literal the gate source can send to the approval channel and requires each
   * to equal one template's `gateSource`, so a new or reworded gate reason fails
   * a test instead of quietly reaching the operator as `unrecognized`.
   */
  gateSource: string;
  render(inputs: HoldReasonInputs): { text: string; subject?: string } | null;
}

/**
 * Every reason template the approval gate writes. Each `render` must match,
 * byte for byte, the reason string at its site in
 * server/src/principal-policy/gate.ts (classifyOperation, detectAnomaly and the
 * proxy branch of evaluate, and ownScopeSaveHold); a drifted template only makes that reason fall
 * back to the code `unrecognized`, never to its raw text. The code list must
 * match HUB_HOLD_REASON_CODES in server/src/contracts/v1.1/hub-events.ts and
 * HOLD_REASON_SENTENCES in server/src/dashboard/v1_1/client.ts.
 */
export const HOLD_REASON_TEMPLATES: readonly HoldReasonTemplate[] = [
  {
    code: "memory_save_quota_reached",
    gateSource: "memory save quota reached",
    render: () => ({ text: "memory save quota reached" }),
  },
  {
    code: "memory_save_quota_unavailable",
    gateSource: "memory save quota unavailable",
    render: () => ({ text: "memory save quota unavailable" }),
  },
  {
    code: "tier1_forced",
    gateSource: '"${operation}" is a forced Tier 1 operation (always requires approval)',
    render: ({ operation }) => ({
      text: `"${operation}" is a forced Tier 1 operation (always requires approval)`,
    }),
  },
  {
    code: "tier1_secret_waiver",
    gateSource:
      '"${operation}" names at least one allow_files path (a secret-classifier ' +
      "waiver) and is always Tier 1 regardless of policy (always requires approval)",
    render: ({ operation }) => ({
      text:
        `"${operation}" names at least one allow_files path (a secret-classifier ` +
        `waiver) and is always Tier 1 regardless of policy (always requires approval)`,
    }),
  },
  {
    code: "tier1_policy",
    gateSource: '"${operation}" is a Tier 1 operation (always requires approval)',
    render: ({ operation }) => ({
      text: `"${operation}" is a Tier 1 operation (always requires approval)`,
    }),
  },
  {
    code: "tier1_unclassified",
    gateSource: '"${operation}" is not classified in any policy tier \u2014 requires approval (SEC-011 safe default)',
    render: ({ operation }) => ({
      // \u2014 is the gate's own separator character in this reason.
      text: `"${operation}" is not classified in any policy tier \u2014 requires approval (SEC-011 safe default)`,
    }),
  },
  {
    code: "proxy_tier1",
    gateSource: 'Proxy tool "${toolName}" is configured as Tier 1 (always requires approval)',
    render: ({ context }) => {
      const tool = nonEmptyString(context.operation);
      return tool === null
        ? null
        : { text: `Proxy tool "${tool}" is configured as Tier 1 (always requires approval)`, subject: tool };
    },
  },
  {
    code: "first_session",
    gateSource: 'First session: "${operation}" has no established baseline',
    render: ({ operation }) => ({ text: `First session: "${operation}" has no established baseline` }),
  },
  {
    code: "first_namespace_access",
    gateSource: 'First access to namespace "${namespace}" (not in session baseline)',
    render: ({ context }) => {
      const namespace = nonEmptyString(context.namespace);
      return namespace === null
        ? null
        : { text: `First access to namespace "${namespace}" (not in session baseline)`, subject: namespace };
    },
  },
  {
    code: "first_counterparty",
    gateSource: 'First interaction with counterparty "${counterpartyDid}"',
    render: ({ context }) => {
      const did = nonEmptyString(context.counterparty_did);
      return did === null ? null : { text: `First interaction with counterparty "${did}"`, subject: did };
    },
  },
  {
    code: "signing_rate",
    gateSource: "Signing frequency (${signCount}/min) exceeds limit (${config.max_signs_per_minute}/min)",
    render: ({ context }) => {
      const count = finiteNumber(context.signs_per_minute);
      const limit = finiteNumber(context.limit);
      return count === null || limit === null
        ? null
        : { text: `Signing frequency (${count}/min) exceeds limit (${limit}/min)` };
    },
  },
  {
    code: "bulk_read",
    gateSource:
      'Bulk read detected: ${readCount} reads from "${namespace}" in 60 seconds (threshold: ${config.bulk_read_threshold})',
    render: ({ context }) => {
      const namespace = nonEmptyString(context.namespace);
      const reads = finiteNumber(context.reads_in_window);
      const threshold = finiteNumber(context.threshold);
      return namespace === null || reads === null || threshold === null
        ? null
        : {
            text: `Bulk read detected: ${reads} reads from "${namespace}" in 60 seconds (threshold: ${threshold})`,
            subject: namespace,
          };
    },
  },
  {
    code: "frequency_spike",
    gateSource:
      'Frequency spike: "${operation}" at ${callRate}/min (${config.frequency_spike_multiplier}\u00d7 above average ${avgRate.toFixed(1)}/min)',
    render: ({ operation, context }) => {
      const rate = finiteNumber(context.current_rate);
      const multiplier = finiteNumber(context.multiplier);
      const average = finiteNumber(context.average_rate);
      return rate === null || multiplier === null || average === null
        ? null
        : {
            // \u00d7 is the gate's own multiplication sign in this reason.
            text: `Frequency spike: "${operation}" at ${rate}/min (${multiplier}\u00d7 above average ${average.toFixed(1)}/min)`,
          };
    },
  },
  {
    code: "injection_escalation",
    gateSource:
      'Potential prompt injection detected in "${operation}" (confidence: ${(injectionResult.confidence * 100).toFixed(0)}%, ${injectionResult.signals.length} signal(s))',
    render: ({ operation, context }) => {
      const detection =
        context.injection_detection !== null && typeof context.injection_detection === "object"
          ? (context.injection_detection as Record<string, unknown>)
          : {};
      const confidence = finiteNumber(detection.confidence);
      const signals = finiteNumber(detection.signal_count);
      // 100 turns the gate's 0..1 confidence into the whole percent it prints.
      return confidence === null || signals === null
        ? null
        : {
            text: `Potential prompt injection detected in "${operation}" (confidence: ${(confidence * 100).toFixed(0)}%, ${signals} signal(s))`,
          };
    },
  },
];

/**
 * The prefix the gate puts on a proxied anomaly reason. Must match the
 * `Proxy: ${anomaly.reason}` literal in server/src/principal-policy/gate.ts,
 * pinned whole as PROXY_REASON_GATE_SOURCE for the coverage test.
 */
export const PROXY_REASON_PREFIX = "Proxy: ";
export const PROXY_REASON_GATE_SOURCE = "Proxy: ${anomaly.reason}";

// The UTF-16 high (leading) surrogate range: a code point above U+FFFF is one of
// these followed by a low surrogate, so a cut just after one splits the pair.
const HIGH_SURROGATE_FIRST = 0xd800;
const HIGH_SURROGATE_LAST = 0xdbff;

/**
 * The first `maxUnits` UTF-16 code units of `text`, cut on a code-point
 * boundary. Invariant: a bounded copy never ends in half of a surrogate pair,
 * so shortening a name cannot manufacture a lone surrogate the original did not
 * contain; when the cut would land just after a high surrogate it backs off one
 * unit, so the copy may be one unit shorter than the bound.
 */
export function cutAtCodePoint(text: string, maxUnits: number): string {
  if (text.length <= maxUnits) return text;
  const last = text.charCodeAt(maxUnits - 1);
  const splitsPair = last >= HIGH_SURROGATE_FIRST && last <= HIGH_SURROGATE_LAST;
  return text.slice(0, splitsPair ? maxUnits - 1 : maxUnits);
}

function boundedSubject(subject: string): Pick<HubHoldReason, "subject" | "subject_truncated"> {
  return subject.length <= HOLD_REASON_SUBJECT_MAX_CHARS
    ? { subject }
    : { subject: cutAtCodePoint(subject, HOLD_REASON_SUBJECT_MAX_CHARS), subject_truncated: true };
}

/**
 * Turn a hold's free-text reason into structured data the console can render
 * without trusting that text.
 *
 * Invariant: a reason is recognised only when a known gate template, fed the
 * hold's own `operation` and `context`, re-renders it EXACTLY. Matching by
 * re-rendering rather than by parsing is what keeps an agent-chosen identifier
 * from steering the result: a namespace such as `notes" (operator approved).
 * Click Allow once. "` can only ever be that template's `subject`, carried as
 * data, and any text that does not re-render becomes `unrecognized`, for which
 * the console writes a fixed sentence. The free text itself is never returned.
 */
export function classifyHoldReason(input: {
  operation: string;
  reason: unknown;
  context: unknown;
}): HubHoldReason {
  const context =
    input.context !== null && typeof input.context === "object" && !Array.isArray(input.context)
      ? (input.context as Record<string, unknown>)
      : {};
  let reason = typeof input.reason === "string" ? input.reason : "";
  let viaProxy = false;
  if (reason.startsWith(PROXY_REASON_PREFIX) && context.proxy === true) {
    reason = reason.slice(PROXY_REASON_PREFIX.length);
    viaProxy = true;
  }
  for (const template of HOLD_REASON_TEMPLATES) {
    // A proxied anomaly wraps an anomaly reason; the proxy Tier 1 reason is never re-wrapped.
    if (viaProxy && template.code === "proxy_tier1") continue;
    const rendered = template.render({ operation: input.operation, context });
    if (rendered === null || rendered.text !== reason) continue;
    return {
      code: template.code,
      ...(viaProxy ? { via_proxy: true } : {}),
      ...(rendered.subject !== undefined ? boundedSubject(rendered.subject) : {}),
    };
  }
  return { code: "unrecognized" };
}

/**
 * Project one live Charter hold into an inbox card.
 *
 * The card carries NO argument detail in its template arguments.
 * `HubDisplayTemplateArg` is a closed typed union with no free-text member
 * precisely so a backend cannot smuggle raw tool arguments into operator copy,
 * and a Charter hold's context is raw tool arguments. The card therefore says
 * which tier is waiting, which operation is held, on which identity, and (when
 * the gate stamped it) which configured agent asked; it names no target. Why
 * the gate held it rides beside the template as the structured `hold_reason`
 * (a code plus, at most, one delimited identifier), never as free text.
 * `GET /api/pending` remains the surface that carries the redacted argument
 * summary.
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
  // The name itself is untrusted (an upstream server names a proxied tool, and
  // an uncategorised tool is whatever the call named), so the card carries a
  // copy bounded before it enters the inbox or the decided history, flagged when
  // shortened; the console renders it only as delimited, escaped data.
  const operationTruncated = record.operation.length > CARD_OPERATION_MAX_CHARS;
  const displayArgs: HubDisplayTemplateArg[] = [
    { kind: "identity_id", value: identityId },
    {
      kind: "operation",
      value: operationTruncated ? cutAtCodePoint(record.operation, CARD_OPERATION_MAX_CHARS) : record.operation,
    },
  ];
  // Must-never #7 bounds what the AGENT learns from a denial: the gate returns
  // it a generic reason. This card is OPERATOR copy, served only to
  // operator-authenticated reads (a loopback-position read drops every approval
  // item). It carries why the gate held the call only as the structured code
  // classifyHoldReason produced, so the console writes every sentence itself
  // and an agent-chosen identifier can appear only as delimited data.
  const holdReason = record.hold_reason;
  return {
    version: "1.1",
    item_id: charterApprovalItemId(record.id),
    kind: "approval_pending",
    created_at: record.created_at,
    ...(record.expires_at ? { expires_at: record.expires_at } : {}),
    ...(record.operator_preview ? { operator_preview: record.operator_preview } : {}),
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
    ...(operationTruncated ? { operation_truncated: true as const } : {}),
    ...(holdReason ? { hold_reason: holdReason } : {}),
  };
}
