/**
 * Sanctuary v1.1. Operator Hub Inbox Aggregator
 *
 * Merges live source-callback output with the hub's own resolution state
 * into a single discriminated union of `HubInboxItem`.
 *
 * Aggregation order:
 *  1. Pull fresh items from each `HubInboxSources` callback.
 *  2. Upsert each into the inbox store. Existing resolution state is
 *     preserved; a re-emitted source item never reverts a resolution.
 *  3. List the merged set from the store.
 *
 * Why aggregate in pull form rather than push:
 * The hub is read-side; source workstreams (privacy core, egress gate,
 * budget tracker, recovery flow) emit signed audit events as their primary
 * record. The hub draws inbox cards from those events on demand, which
 * keeps the hub from owning a parallel write path that could drift.
 */

import type { HubInboxItem } from "../contracts/v1.1/hub-events.js";
import type { HubInboxSources } from "./types.js";
import { HubInboxStore } from "./inbox-store.js";

/**
 * Aggregate the current inbox state. Mutates `store` to reflect any
 * source-side items not yet seen.
 */
export function aggregateInbox(
  sources: HubInboxSources,
  store: HubInboxStore,
): HubInboxItem[] {
  for (const item of sources.listPendingApprovals()) {
    store.upsertFromSource(item);
  }
  for (const item of sources.listRecentBlockedEgress()) {
    store.upsertFromSource(item);
  }
  for (const item of sources.listRecentPrivacyEvents()) {
    store.upsertFromSource(item);
  }
  for (const item of sources.listActiveBudgetWarnings()) {
    store.upsertFromSource(item);
  }
  for (const item of sources.listActiveRecoveryPrompts()) {
    store.upsertFromSource(item);
  }
  for (const item of sources.listRecentAgentErrors()) {
    store.upsertFromSource(item);
  }
  return store.list();
}
