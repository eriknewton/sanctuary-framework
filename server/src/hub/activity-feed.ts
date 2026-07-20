/**
 * Sanctuary v1.1. Operator Hub Activity Feed
 *
 * Projects audit-chain entries into `HubActivityFeedEntry` shape per
 * `server/src/contracts/v1.1/hub-events.ts`.
 *
 * Integrity model:
 * Activity feed entries are read-from-storage projections. They are NOT
 * signed envelopes themselves; integrity derives from the underlying audit
 * entry. Consumers that need to verify the feed entry MUST resolve to the
 * source audit entry by `entry_id` and verify there.
 *
 * Safe-metadata model:
 * Each entry carries `display_template_id` + typed `display_template_args`.
 * No raw audit `details` content crosses the API surface. The dashboard
 * resolves the template id against its catalog (Prompt 8).
 */

import { createHash } from "node:crypto";

import type { AuditEntry } from "../operational/audit-log.js";
import type {
  HubActivityFeedEntry,
  HubDisplayTemplateArg,
} from "../contracts/v1.1/hub-events.js";
import {
  auditEntryAgentId,
  isCastleWallAttributionSensitiveEntry,
  verifiedCastleWallAuditAttribution,
} from "../castle-wall/audit-attribution.js";
import type { HubActivitySources } from "./types.js";
import {
  HUB_ACTIVITY_DEFAULT_LIMIT,
  HUB_ACTIVITY_MAX_LIMIT,
  HUB_ACTIVITY_TEMPLATE_NAMESPACES,
} from "./constants.js";

export type HubActivityCategory = HubActivityFeedEntry["category"];

interface ActivityFilter {
  /** ISO8601 lower bound (inclusive). */
  since?: string;
  /** Max entries to return. Defaults + clamps applied. */
  limit?: number;
  /** Restrict to one agent_id. */
  agent_id?: string;
  /** Restrict to one category. */
  category?: HubActivityCategory;
}

/**
 * Coarse audit-operation → activity category map. Operation names are
 * stable strings emitted by the various enforcement layers.
 *
 * Anything not classified maps to "other".
 *
 * Lifecycle bucket per dashboard binding addendum §1.2: covers
 * `wrap`, `unwrap`, `lockdown`, `pause`, `resume`, `restart`, plus
 * fortress-scope and per-agent suffixed forms emitted by the hub Tier 1
 * control handlers (e.g. `fortress_lockdown_engaged`,
 * `agent_lockdown_engaged`, `agent_policy_change_engaged`,
 * `fortress_lockdown_lifted`).
 */
const LIFECYCLE_VERBS = [
  "wrap",
  "unwrap",
  "lockdown",
  "pause",
  "resume",
  "restart",
] as const;

function categorizeOperation(
  layer: AuditEntry["layer"],
  operation: string,
): HubActivityCategory {
  const op = operation.toLowerCase();
  if (op === "privacy_event" || op.startsWith("privacy_")) return "privacy";
  if (op.includes("approval") || op.includes("approved")) return "approval";
  if (
    op.includes("denied") ||
    op.endsWith("_deny") ||
    op === "policy_deny"
  ) {
    return "denial";
  }
  if (op.includes("egress") || op.includes("upstream_call")) return "egress";
  if (op.startsWith("handoff_") || op === "handoff") return "handoff";
  if ((LIFECYCLE_VERBS as readonly string[]).includes(op)) return "lifecycle";
  if (op.startsWith("agent_")) return "lifecycle";
  if (
    op.startsWith("fortress_") &&
    LIFECYCLE_VERBS.some((verb) => op.includes(verb))
  ) {
    return "lifecycle";
  }
  if (op.startsWith("policy_")) return "policy_decision";
  if (op.startsWith("config_") || op === "policy_change") return "config";
  if (layer === "l2") return "policy_decision";
  return "other";
}

/**
 * Map a category to its template namespace. The actual template id is
 * `<namespace>.<operation>` so the dashboard can scope display strings
 * per operation while keeping the namespace stable.
 */
function templateIdFor(
  category: HubActivityCategory,
  operation: string,
): string {
  const namespace = HUB_ACTIVITY_TEMPLATE_NAMESPACES[category];
  return `${namespace}.${operation}`;
}

/**
 * Build the typed args array. Only safe-shape values are added; raw
 * `details` content is never copied into args. The dashboard renders the
 * template using these typed args.
 */
function buildTemplateArgs(
  entry: AuditEntry,
  agentIdHint?: string,
): HubDisplayTemplateArg[] {
  const args: HubDisplayTemplateArg[] = [
    { kind: "iso8601", value: entry.timestamp },
    { kind: "identity_id", value: entry.identity_id },
  ];
  if (agentIdHint) {
    args.push({ kind: "agent_id", value: agentIdHint });
  }
  const details = entry.details as Record<string, unknown> | undefined;
  if (details) {
    const proposed = details.proposed_template;
    const current = details.current_template;
    if (typeof current === "string" && current.length > 0) {
      args.push({ kind: "channel_template_id", value: current });
    }
    if (typeof proposed === "string" && proposed.length > 0) {
      args.push({ kind: "policy_id", value: proposed });
    }
  }
  return args;
}

/**
 * Pull a safe `agent_id` hint out of the audit entry. Castle Wall attribution
 * is projected only when the persisted producer signature re-verifies and the
 * subject is derived from the signed canonical body. Non-Castle-Wall rows keep
 * the legacy details hint behavior.
 */
function extractAgentIdHint(
  entry: AuditEntry,
  sources: HubActivitySources,
): string | undefined {
  return (
    auditEntryAgentId(entry, {
      pinnedProducerKeyB64url: sources.pinnedProducerKeyB64url ?? null,
      subjectFortressId: sources.subjectFortressId ?? null,
    }) ?? undefined
  );
}

/**
 * Derive a short visible hex fragment from the audit-chain entry id.
 *
 * Shape is `<4hex>..<2hex>` (6 hex chars total) to match the Sprint Piece 2
 * attestation gallery example (`9c7d..2a`). Deterministic: same entry id
 * always derives the same fragment. NOT a per-event signature; the audit
 * chain itself is the integrity claim.
 */
function deriveAttestationFragment(entryId: string): string {
  const hash = createHash("sha256").update(entryId).digest("hex");
  return `${hash.slice(0, 4)}..${hash.slice(4, 6)}`;
}

/**
 * Map an audit-entry result onto an attestation render state.
 *
 * Castle Wall attribution-sensitive entries render `verified` only when the
 * persisted producer signature re-verifies. Other audit families keep the
 * legacy success/failure projection.
 */
function deriveAttestationState(
  entry: AuditEntry,
  sources: HubActivitySources,
): "verified" | "degraded" {
  if (isCastleWallAttributionSensitiveEntry(entry)) {
    return verifiedCastleWallAuditAttribution(entry, {
      pinnedProducerKeyB64url: sources.pinnedProducerKeyB64url ?? null,
      subjectFortressId: sources.subjectFortressId ?? null,
    }) !== null
      ? "verified"
      : "degraded";
  }
  return entry.result === "success" ? "verified" : "degraded";
}

function projectEntry(
  entry: AuditEntry,
  sources: HubActivitySources,
): HubActivityFeedEntry {
  const agentIdHint = extractAgentIdHint(entry, sources);
  const category = categorizeOperation(entry.layer, entry.operation);
  const entryId = `${entry.timestamp}|${entry.operation}|${entry.identity_id}`;
  return {
    version: "1.1",
    entry_id: entryId,
    emitted_at: entry.timestamp,
    ...(agentIdHint ? { agent_id: agentIdHint } : {}),
    identity_id: entry.identity_id,
    category,
    display_template_id: templateIdFor(category, entry.operation),
    display_template_args: buildTemplateArgs(entry, agentIdHint),
    attestation: {
      state: deriveAttestationState(entry, sources),
      fragment: deriveAttestationFragment(entryId),
    },
  };
}

/**
 * Pull a filtered, paginated activity feed projection from the audit log.
 */
export async function aggregateActivity(
  sources: HubActivitySources,
  filter: ActivityFilter = {},
): Promise<HubActivityFeedEntry[]> {
  const limit = Math.min(
    Math.max(0, filter.limit ?? HUB_ACTIVITY_DEFAULT_LIMIT),
    HUB_ACTIVITY_MAX_LIMIT,
  );

  // Pull a generous window from the audit log so post-projection filters
  // still leave enough rows to honor the requested limit.
  const queryResult = await sources.auditLog.query({
    limit: Math.max(limit * 4, limit),
    ...(filter.since !== undefined ? { since: filter.since } : {}),
  });

  const projected = queryResult.entries
    .filter((e) => e.identity_id === sources.identityId)
    .map((entry) => projectEntry(entry, sources));

  let filtered = projected;
  if (filter.agent_id) {
    filtered = filtered.filter((e) => e.agent_id === filter.agent_id);
  }
  if (filter.category) {
    filtered = filtered.filter((e) => e.category === filter.category);
  }

  return filtered.slice(0, limit);
}
