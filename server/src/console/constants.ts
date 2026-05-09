/**
 * Sanctuary Operator Console v1.0 -- Constants
 *
 * View names, API routes, polling intervals, consumed event prefixes.
 * Browser-primary HTML reference surface; six views + persistent header.
 *
 * WP-MVP-2: Key 4 Console + Q5 Option A (single console artifact).
 * Scope lock: Review/Sanctuary/Sanctuary_MVP_Scope_Lock_2026-04-21.md
 */

import { SIGNATURE_SCHEME_V1, type SignatureScheme } from "../mesh/constants.js";

// Re-export for console module consumers
export { SIGNATURE_SCHEME_V1 };
export type { SignatureScheme };

// -----------------------------------------------------------------------
// Console product version
// -----------------------------------------------------------------------

export const CONSOLE_VERSION = "1.0.0" as const;

// -----------------------------------------------------------------------
// View names (six primary views per spawn prompt)
// -----------------------------------------------------------------------

export const VIEW_NAMES = [
  "fortress",
  "agent_roster",
  "policy_editor",
  "chat",
  "recovery",
  "audit_log",
] as const;

export type ViewName = (typeof VIEW_NAMES)[number];

export function isViewName(s: string): s is ViewName {
  return (VIEW_NAMES as readonly string[]).includes(s);
}

/**
 * Operator-facing labels for each view. Fortress vocabulary.
 * No em-dashes. No competitor names.
 */
export const VIEW_LABELS: Record<ViewName, string> = {
  fortress: "Fortress Mode",
  agent_roster: "Agent Roster",
  policy_editor: "Policy Editor",
  chat: "Secure Chat",
  recovery: "Recovery",
  audit_log: "Audit Log",
};

// -----------------------------------------------------------------------
// API route prefix
// -----------------------------------------------------------------------

/** All console API routes live under this prefix. */
export const CONSOLE_API_PREFIX = "/api/console" as const;

/** SSE event stream endpoint. */
export const CONSOLE_EVENTS_PATH = "/api/console/events" as const;

/** Static asset root (relative to server/public/). */
export const CONSOLE_STATIC_ROOT = "console" as const;

/** Console HTML entry point path. */
export const CONSOLE_HTML_PATH = "/console" as const;

/**
 * Console API route map. Each maps to a handler in api-router.
 */
export const API_ROUTES = {
  // Fortress view
  FORTRESS_MODE: "/api/console/fortress/mode",
  FORTRESS_TRANSITION: "/api/console/fortress/transition",

  // Agent roster view
  AGENT_LIST: "/api/console/agents",
  AGENT_BADGE: "/api/console/agents/badge",
  AGENT_RETRY_RESET: "/api/console/agents/retry-reset",

  // Policy editor view
  POLICY_COMPILE: "/api/console/policy/compile",
  POLICY_TEMPLATES: "/api/console/policy/templates",

  // Chat view
  CHAT_GROUPS: "/api/console/chat/groups",
  CHAT_MESSAGES: "/api/console/chat/messages",
  CHAT_SEND: "/api/console/chat/send",
  CHAT_PRESENCE: "/api/console/chat/presence",

  // Recovery view
  RECOVERY_STATUS: "/api/console/recovery/status",
  RECOVERY_GUARDIANS: "/api/console/recovery/guardians",
  RECOVERY_DMSWITCH: "/api/console/recovery/dmswitch",

  // Audit log view
  AUDIT_EVENTS: "/api/console/audit/events",

  // Header (persistent attestation badge)
  HEADER_BADGE: "/api/console/header/badge",

  // SSE stream
  EVENTS: "/api/console/events",
} as const;

// -----------------------------------------------------------------------
// Polling intervals (browser fallback; SSE is primary)
// -----------------------------------------------------------------------

export const POLLING_INTERVALS = {
  FORTRESS_STATUS_MS: 10_000,
  AGENT_ROSTER_MS: 15_000,
  CHAT_PRESENCE_MS: 5_000,
  RECOVERY_STATUS_MS: 10_000,
  HEADER_BADGE_MS: 5_000,
  AUDIT_LOG_MS: 10_000,
} as const;

// -----------------------------------------------------------------------
// Auth
// -----------------------------------------------------------------------

export const SESSION_TTL_LOCAL_MS = 24 * 60 * 60 * 1000;
export const SESSION_TTL_REMOTE_MS = 5 * 60 * 1000;
export const MAX_SESSIONS = 100;

// -----------------------------------------------------------------------
// Rate limiting
// -----------------------------------------------------------------------

export const RATE_LIMIT = {
  WINDOW_MS: 60_000,
  MAX_REQUESTS: 120,
  MAX_MUTATIONS: 20,
} as const;

// -----------------------------------------------------------------------
// Reserved event-type namespaces the console CONSUMES (not emits)
// -----------------------------------------------------------------------

/**
 * Event-type prefixes the console's audit-log view filters on.
 * Per spawn prompt hard rule: console does NOT emit new event types.
 */
export const CONSUMED_EVENT_PREFIXES = [
  "policy_",
  "chat_",
  "mesh_",
  "recovery_",
  "fortress_",
  "attestation_",
  "identity_",
] as const;

export type ConsumedEventPrefix = (typeof CONSUMED_EVENT_PREFIXES)[number];

// -----------------------------------------------------------------------
// Legal fortress transitions (display matrix for the view)
// -----------------------------------------------------------------------

/**
 * Legal transition matrix from fortress/constants.ts.
 * 1->2, 2->1, 2->3, 3->2, 3->1. NOT 1->3 (must pass through 2).
 */
export const CONSOLE_LEGAL_TRANSITIONS: Record<string, readonly string[]> = {
  tier_1_private: ["tier_2_federated"],
  tier_2_federated: ["tier_1_private", "tier_3_interop"],
  tier_3_interop: ["tier_2_federated", "tier_1_private"],
};

export const TIER_LABELS: Record<string, string> = {
  tier_1_private: "Tier 1: Private",
  tier_2_federated: "Tier 2: Federated",
  tier_3_interop: "Tier 3: Interop",
};

// -----------------------------------------------------------------------
// SSE keepalive
// -----------------------------------------------------------------------

export const SSE_KEEPALIVE_MS = 25_000;
