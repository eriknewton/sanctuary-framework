/**
 * Sanctuary v1.1 Operator Hub API Constants
 *
 * Routes, prefixes, and small enums shared across the hub modules.
 * The hub API surface is consumed by the v1.1 dashboard UI (Prompt 8).
 *
 * Local-only invariant:
 * Every route here describes activity inside a single fortress on a single
 * operator's machine. Cross-fortress, fleet, and public-federation routes
 * are out of scope.
 */

import type { LocalHarnessKind } from "../contracts/v1.1/local-agent-records.js";

/**
 * Hub API product version. Tracks the v1.1 contract surface; bumps require
 * coordinator approval.
 */
export const HUB_VERSION = "1.1.0" as const;

/**
 * All hub API routes live under this prefix.
 */
export const HUB_API_PREFIX = "/api/hub" as const;

/**
 * Hub API route map. Each maps to a handler in api-router.
 *
 * `:id` placeholders are filled by URL parameter extraction in the router;
 * the constant strings are the canonical patterns for documentation and the
 * acceptance-checklist conformance check.
 */
export const HUB_ROUTES = {
  INBOX_LIST: "/api/hub/inbox",
  INBOX_RESOLVE: "/api/hub/inbox/:id/:action",
  AGENTS_LIST: "/api/hub/agents",
  AGENT_GET: "/api/hub/agents/:id",
  AGENT_CONTROL: "/api/hub/agents/:id/:action",
  AGENT_POLICY: "/api/hub/agents/:id/policy",
  AGENT_TEMPLATE: "/api/hub/agents/:id/template",
  ACTIVITY_LIST: "/api/hub/activity",
  POLICIES_LIST: "/api/hub/policies",
  BUDGETS_LIST: "/api/hub/budgets",
  /**
   * Fortress-scope Tier 1 control routes (closes binding addendum 8.1).
   * One inbox item per call, fortress-scope iteration on approve.
   */
  FORTRESS_LOCKDOWN: "/api/hub/fortress/lockdown",
  FORTRESS_EXIT_BUNDLE_EXPORT: "/api/hub/fortress/exit-bundle/export",
  /**
   * Operator concierge chat routes (WP-V1.2-4). Concierge is fortress-
   * scoped; the direct-agent chat surface was removed in the v1.2
   * reshape and replaced with the click-to-inspect panel below.
   */
  CHAT_CONCIERGE_SEND: "/api/hub/chat/concierge",
  CHAT_CONCIERGE_HISTORY: "/api/hub/chat/concierge/history",
  /**
   * Click-to-inspect panel (WP-V1.2 reshape). Returns the agent's
   * recent activity feed, pending Tier 1 approvals routed through this
   * agent, and policy summary. Replaces the `/api/hub/chat/agents/:id/
   * session/*` direct-agent routes.
   */
  AGENT_INSPECT_OPEN: "/api/hub/agents/:id/inspect/open",
} as const;

/**
 * Sentinel agent_id the v1.1 dashboard sends on the per-agent control
 * routes when it intends fortress-scope. The router treats the sentinel as
 * an alias for the canonical fortress route so the dashboard's existing
 * 404 toast workaround retires automatically once these endpoints land.
 *
 * The sentinel is a routing-layer alias only; the canonical paths in
 * `HUB_ROUTES.FORTRESS_*` remain the documented surface.
 */
export const HUB_FORTRESS_AGENT_ID_SENTINEL = "all" as const;

/**
 * Inbox-resolve actions. The router rejects any other action token.
 */
export const HUB_INBOX_ACTIONS = ["approve", "deny", "dismiss"] as const;
export type HubInboxAction = (typeof HUB_INBOX_ACTIONS)[number];

/**
 * Agent-control actions surfaced by `POST /api/hub/agents/:id/:action`.
 *
 * `pause` / `resume` / `restart` are control-plane operations that the
 * underlying harness may execute immediately; they are not Tier 1.
 *
 * `unwrap` and `lockdown` are Tier 1 operations per the Principal Policy
 * loader. Hub endpoints for these MUST enqueue an `approval_pending` inbox
 * item rather than execute directly. Tier 1 approval gates remain in force
 * from the dashboard. The dashboard never auto-approves Tier 1 work.
 */
export const HUB_AGENT_CONTROL_ACTIONS = [
  "pause",
  "resume",
  "restart",
  "unwrap",
  "lockdown",
] as const;
export type HubAgentControlAction =
  (typeof HUB_AGENT_CONTROL_ACTIONS)[number];

/**
 * The subset of agent-control actions classified as Tier 1 by the canonical
 * Principal Policy. Hub endpoints for these MUST go through the inbox
 * approval flow rather than execute synchronously.
 *
 * Mirrors the names enrolled in `principal-policy/loader.ts`
 * `tier1_always_approve`. Drift between the two lists is a release blocker.
 */
export const HUB_TIER_1_AGENT_CONTROL_ACTIONS = [
  "unwrap",
  "lockdown",
] as const;
export type HubTier1AgentControlAction =
  (typeof HUB_TIER_1_AGENT_CONTROL_ACTIONS)[number];

/**
 * Default + max page size for activity feed responses.
 */
export const HUB_ACTIVITY_DEFAULT_LIMIT = 50;
export const HUB_ACTIVITY_MAX_LIMIT = 500;

/**
 * Default + max inbox-list page size.
 */
export const HUB_INBOX_DEFAULT_LIMIT = 100;
export const HUB_INBOX_MAX_LIMIT = 500;

/**
 * Default + max agents-list page size.
 */
export const HUB_AGENTS_DEFAULT_LIMIT = 100;
export const HUB_AGENTS_MAX_LIMIT = 500;

/**
 * Maximum JSON request body size for any hub mutation.
 */
export const HUB_MAX_REQUEST_BODY_BYTES = 256 * 1024;

/**
 * Maximum length (chars) of a single operator chat message body. Set
 * conservatively at v1.2; the substrate selector's per-surface request
 * envelope caps will narrow further. Operator-typed bodies above this
 * threshold are rejected at the route layer with `HubValidationError`.
 */
export const HUB_CHAT_MESSAGE_MAX_CHARS = 4000;

/**
 * Display-template-id namespaces. Backends emit ids drawn from these
 * namespaces. The dashboard owns the actual render strings (Prompt 8).
 *
 * No raw display copy ever crosses the API surface from backend to
 * frontend. See `server/src/contracts/v1.1/hub-events.ts`
 * `HubInboxItemHeader.display_template_id`.
 */
export const HUB_INBOX_TEMPLATE_NAMESPACES = {
  approval_pending: "approval_pending",
  blocked_egress: "blocked_egress",
  privacy_event: "privacy_event",
  budget_warning: "budget_warning",
  recovery_prompt: "recovery_prompt",
  agent_error: "agent_error",
} as const;

export const HUB_ACTIVITY_TEMPLATE_NAMESPACES = {
  policy_decision: "activity.policy_decision",
  approval: "activity.approval",
  denial: "activity.denial",
  egress: "activity.egress",
  privacy: "activity.privacy",
  handoff: "activity.handoff",
  lifecycle: "activity.lifecycle",
  config: "activity.config",
  other: "activity.other",
} as const;

/**
 * Re-export the canonical local harness enum so hub consumers don't need a
 * second import path.
 */
export type { LocalHarnessKind };
