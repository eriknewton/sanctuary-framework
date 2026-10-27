/**
 * Sanctuary v1.1. Operator Hub Inbox Aggregator
 *
 * Merges live source-callback output with the hub's own resolution state
 * into a single discriminated union of `HubInboxItem`.
 *
 * Aggregation order:
 *  1. Pull fresh items from each `HubInboxSources` callback.
 *  2. Upsert each into the inbox store, preserving resolution while present.
 *  3. Clear absent source conditions so a recurrence opens a fresh incident.
 *  4. List the merged set from the store.
 *
 * Why aggregate in pull form rather than push:
 * The hub is read-side; source workstreams (privacy core, egress gate,
 * budget tracker, recovery flow) emit signed audit events as their primary
 * record. The hub draws inbox cards from those events on demand, which
 * keeps the hub from owning a parallel write path that could drift.
 */

import type { HubInboxItem } from "../contracts/v1.1/hub-events.js";
import type { HubInboxSources } from "./types.js";
import { emptyHubInboxSource, hubInboxSourceIdPrefix } from "./inbox-sources.js";
import { HubInboxStore } from "./inbox-store.js";

/**
 * Aggregate the current inbox state. Mutates `store` to reflect any
 * source-side items not yet seen.
 */
export function aggregateInbox(
  sources: HubInboxSources,
  store: HubInboxStore,
  nowIso: string,
): HubInboxItem[] {
  for (const item of sources.listPendingApprovals()) {
    store.upsertFromSource(item);
  }
  function reconcile(kind: HubInboxItem["kind"], listItems: () => HubInboxItem[]): void {
    // Must match emptyHubInboxSource in inbox-sources.ts: permanent stubs cannot leave a condition to clear.
    if (listItems === emptyHubInboxSource) return;
    const items = listItems.call(sources);
    const emittedIds = new Set<string>();
    for (const item of items) {
      store.upsertFromSource(item);
      emittedIds.add(item.item_id);
    }
    // Must match projection() in inbox-sources.ts and HubInboxSources in types.ts:
    // a card dropped by the cap is still present; only absence from the present set clears it.
    const presentIds = sources.listPresentSourceIds?.(kind);
    // A source that reports its present set as unknown (a truncated registry page) has shown no
    // absence; clearing on it would resolve live cards past the page, so this call clears nothing.
    if (sources.listPresentSourceIds && presentIds === undefined) return;
    const liveIds = presentIds ?? emittedIds;
    // An ordinary empty callback can mean its last condition stopped; only permanent stubs skip above.
    // Must match header() in inbox-sources.ts via hubInboxSourceIdPrefix; approvals are never reconciled.
    store.reconcileSourceItems(hubInboxSourceIdPrefix(kind), liveIds, nowIso);
  }
  reconcile("blocked_egress", sources.listRecentBlockedEgress);
  reconcile("privacy_event", sources.listRecentPrivacyEvents);
  reconcile("budget_warning", sources.listActiveBudgetWarnings);
  reconcile("recovery_prompt", sources.listActiveRecoveryPrompts);
  reconcile("agent_error", sources.listRecentAgentErrors);
  return store.list();
}
