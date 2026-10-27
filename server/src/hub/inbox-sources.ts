/** Read-only inbox projections of the local agent registry. */
import { createHash } from "node:crypto";
import type {
  HubAgentErrorItem,
  HubBudgetWarningItem,
  HubInboxItemHeader,
} from "../contracts/v1.1/hub-events.js";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import { parseIsoInstantWithOffset } from "../core/time.js";
import type { InMemoryLocalAgentRegistry } from "./agent-registry.js";
import { HUB_AGENTS_MAX_LIMIT, HUB_INBOX_DEFAULT_LIMIT } from "./constants.js";
import type { HubInboxSources } from "./types.js";

// One default inbox page per class bounds new upserts per aggregation.
export const HUB_BUDGET_WARNING_SOURCE_CAP = HUB_INBOX_DEFAULT_LIMIT;
export const HUB_AGENT_ERROR_SOURCE_CAP = HUB_INBOX_DEFAULT_LIMIT;
// One maximum registry page bounds projection work, including both budget buckets.
export const HUB_INBOX_REGISTRY_SCAN_CAP = HUB_AGENTS_MAX_LIMIT;
// Allow at most four SHA-256 hex identifiers (64 characters each) per source field.
const SOURCE_FIELD_MAX_CHARS = 4 * 64;
const BUDGET_BUCKETS = ["daily", "monthly"] as const;

// Must match LocalAgentRecord.status_reason_class in contracts/v1.1/local-agent-records.ts
// and its event projection in contracts/v1.1/hub-events.ts; persisted JSON is not a type witness.
const STATUS_REASON_CLASSES: ReadonlySet<string> = new Set([
  "operator_lockdown", "policy_breach", "budget_hard_cap", "harness_error",
  "harness_unreachable", "passphrase_required", "config_drift", "other",
] satisfies NonNullable<LocalAgentRecord["status_reason_class"]>[]);

/** Namespace used by source producers and reconciliation to identify one card kind. */
export function hubInboxSourceIdPrefix(kind: HubInboxItemHeader["kind"]): string {
  // Must match aggregateInbox in inbox-aggregator.ts; only these source namespaces may clear.
  return `source.${kind}.`;
}

/** Closed namespaces accepted by HubInboxStore.reconcileSourceItems. */
// Must match the prefix validation in inbox-store.ts; approvals retain their own lifecycle.
export const HUB_INBOX_SOURCE_RECONCILE_PREFIXES: ReadonlySet<string> = new Set(([
  "blocked_egress", "privacy_event", "budget_warning", "recovery_prompt", "agent_error",
] as const).map(hubInboxSourceIdPrefix));

/** A permanently empty source; the aggregator can skip its store reconciliation. */
// Must match the callback-identity check in inbox-aggregator.ts; replacing a stub opts into reconciliation.
export function emptyHubInboxSource(): never[] { return []; }

/** Supply the local registry and the hub's identity scope. */
export interface HubInboxSourceDeps {
  identityId: string;
  agentRegistry: InMemoryLocalAgentRegistry;
}

function identifier(value: unknown): value is string {
  // Reject oversized input before scanning it, so validation also respects the field cap.
  return typeof value === "string" && value.length <= SOURCE_FIELD_MAX_CHARS &&
    value.trim().length > 0;
}

function timestampOrder(value: unknown): number {
  // Invalid or oversized timestamps sort last; timestamps never decide whether a condition holds.
  if (typeof value !== "string" || value.length > SOURCE_FIELD_MAX_CHARS) return Number.NEGATIVE_INFINITY;
  return parseIsoInstantWithOffset(value) ?? Number.NEGATIVE_INFINITY;
}

function newestFirst(a: HubInboxItemHeader, b: HubInboxItemHeader): number {
  const aTime = timestampOrder(a.created_at);
  const bTime = timestampOrder(b.created_at);
  return aTime === bTime ? a.item_id.localeCompare(b.item_id) : aTime > bTime ? -1 : 1;
}

function projection<T extends HubInboxItemHeader>(items: T[], cap: number) {
  // Must match reconcile() in inbox-aggregator.ts and HubInboxSources in types.ts:
  // a card dropped by the cap is still present; only absence from the present set clears it.
  const presentIds: ReadonlySet<string> = new Set(items.map((item) => item.item_id));
  return { presentIds, items: items.sort(newestFirst).slice(0, cap) };
}

/**
 * Read current memory only. No polling, I/O, or retained adapter history.
 * Registry projections inspect one capped agent-id page and sort eligible cards
 * newest first within that page; timestamps never gate presence and the registry owns listing cost.
 * Dismiss hides this incident while its condition holds; a condition that stops holding and holds again is a new incident.
 */
export function createHubInboxSources(deps: HubInboxSourceDeps): HubInboxSources {
  function header(
    kind: HubInboxItemHeader["kind"],
    keys: string[],
    createdAt: string,
    template: string,
    agentId?: string,
  ): HubInboxItemHeader {
    // Derive ids from source keys, not read time, so store resolutions survive refresh.
    const digest = createHash("sha256").update(JSON.stringify(keys)).digest("hex");
    return {
      version: "1.1",
      item_id: `${hubInboxSourceIdPrefix(kind)}${digest}`,
      kind,
      created_at: createdAt,
      identity_id: deps.identityId,
      ...(agentId ? { agent_id: agentId } : {}),
      display_template_id: `${kind}.${template}`,
      display_template_args: [
        { kind: "identity_id", value: deps.identityId },
        ...(agentId ? [{ kind: "agent_id" as const, value: agentId }] : []),
      ],
      resolved: false,
    };
  }

  function agents(statuses?: LocalAgentRecord["status"][]): LocalAgentRecord[] {
    // Bound the adapter even if a replacement source accidentally ignores limit.
    return deps.agentRegistry.list({
      identity_id: deps.identityId,
      ...(statuses ? { statuses } : {}),
      limit: HUB_INBOX_REGISTRY_SCAN_CAP,
    }).slice(0, HUB_INBOX_REGISTRY_SCAN_CAP).filter((record) =>
      record.identity_id === deps.identityId && identifier(record.agent_id));
  }

  function budgetProjection() {
    const items: HubBudgetWarningItem[] = [];
    for (const record of agents()) {
      const summary = record.budget_summary;
      if (!summary) continue;
      for (const bucket of BUDGET_BUCKETS) {
        const budget = summary[bucket];
        if (!budget || !Number.isFinite(budget.cap) || budget.cap <= 0 ||
            !Number.isFinite(budget.used) || budget.used < 0) continue;
        const fraction = budget.used / budget.cap;
        const softWarn = budget.soft_warn;
        // A fraction threshold is in (0, 1]: zero/negative means no warning threshold, and 1 is the hard cap.
        const validSoftWarn = softWarn !== undefined && Number.isFinite(softWarn) && softWarn > 0 && softWarn <= 1;
        const severity = budget.used >= budget.cap ? "hard_cap" :
          validSoftWarn && fraction >= softWarn ? "soft_warn" : null;
        if (!severity) continue;
        // Attribution names the registry record's subject, never a parsed display string.
        items.push({
          ...header("budget_warning", [record.agent_id, bucket, severity],
            summary.last_refreshed_at, severity, record.agent_id),
          kind: "budget_warning",
          bucket,
          severity,
          used_fraction: Math.max(0, Math.min(1, fraction)),
        });
      }
    }
    return projection(items, HUB_BUDGET_WARNING_SOURCE_CAP);
  }

  function errorProjection() {
    const items: HubAgentErrorItem[] = [];
    for (const record of agents(["error"])) {
      // operator_lockdown belongs to locked_down status, already excluded by this error filter.
      if (record.status !== "error") continue;
      const reason = record.status_reason_class;
      const errorClass = identifier(reason) && STATUS_REASON_CLASSES.has(reason) ? reason : "other";
      // Budget hard caps are owned by the budget-warning source, avoiding duplicate cards.
      if (errorClass === "budget_hard_cap") continue;
      // Passphrase requests belong to recovery prompts, not agent-error cards.
      if (errorClass === "passphrase_required") continue;
      items.push({
        ...header("agent_error", [record.agent_id, errorClass],
          record.last_activity_at,
            ["harness_error", "harness_unreachable", "policy_breach", "config_drift"].includes(errorClass)
              ? errorClass : "other", record.agent_id),
        kind: "agent_error",
        error_class: errorClass,
        agent_still_active: false,
      });
    }
    return projection(items, HUB_AGENT_ERROR_SOURCE_CAP);
  }

  return {
    listPendingApprovals: () => [],
    // Castle Wall stores a destination host, not PrivacyDestinationCategory; the bridge keeps only prose.
    // The audit consumer accepts unverified producer signatures, so neither category nor attribution has a card witness.
    listRecentBlockedEgress: emptyHubInboxSource,
    // aggregateRhoDailyPrivacyEvents has no production caller at this base.
    listRecentPrivacyEvents: emptyHubInboxSource,
    listActiveBudgetWarnings: () => budgetProjection().items,
    // firePostRecoveryPrompt has no production caller supplying an inbox bridge at this base.
    listActiveRecoveryPrompts: emptyHubInboxSource,
    listRecentAgentErrors: () => errorProjection().items,
    listPresentSourceIds: (kind) => {
      if (kind === "budget_warning") return budgetProjection().presentIds;
      if (kind === "agent_error") return errorProjection().presentIds;
      return new Set<string>();
    },
  };
}
