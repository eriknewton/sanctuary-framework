/**
 * Sanctuary v1.1. Hub inbox resolution store
 *
 * Tracks operator-side resolution state for inbox items, plus the small set
 * of Tier 1 control actions enqueued through the hub control endpoints.
 *
 * The aggregator pulls fresh items from source callbacks each list call;
 * this store overlays:
 *  (a) `resolved` / `resolved_at` on items the operator has acted on.
 *  (b) The pending Tier 1 control actions the hub itself created when an
 *      operator hit `POST /api/hub/agents/:id/{unwrap|lockdown|policy}`.
 *
 * No raw secret content ever transits this store. Items are header + typed
 * args; the contract type enforces that.
 */

import type {
  HubApprovalPendingItem,
  HubInboxItem,
} from "../contracts/v1.1/hub-events.js";
import { HubConflictError, HubNotFoundError } from "./errors.js";

/**
 * Callback the store invokes when an enqueued Tier 1 inbox item is approved.
 * The hub-service registers a handler at enqueue time so the store stays
 * decoupled from the agent controller.
 *
 * The handler MAY return a `Tier1HandlerResult` carrying a
 * `resolution_payload` to attach to the inbox item before the store flips
 * `resolved`. Used by fortress-scope `exit_bundle_export` to surface
 * `bundle_dir` + `manifest_hash` to the dashboard exit-drill wizard.
 * Returning `void` is equivalent to no payload.
 */
export type Tier1ResolutionHandler = (
  item: HubApprovalPendingItem,
  decision: "approve" | "deny",
) => Promise<Tier1HandlerResult | void>;

export interface Tier1HandlerResult {
  resolution_payload?: HubApprovalPendingItem["resolution_payload"];
}

interface StoredEntry {
  item: HubInboxItem;
  resolved: boolean;
  resolved_at?: string;
  /** Set when the entry is a hub-enqueued Tier 1 control action. */
  tier1Handler?: Tier1ResolutionHandler;
}

export class HubInboxStore {
  private entries: Map<string, StoredEntry> = new Map();

  /**
   * Record a fresh inbox item the aggregator pulled from a source. If the
   * item already exists, the resolution state is preserved; the underlying
   * shape is refreshed.
   */
  upsertFromSource(item: HubInboxItem): void {
    const prior = this.entries.get(item.item_id);
    if (prior) {
      prior.item = {
        ...item,
        resolved: prior.resolved,
        ...(prior.resolved_at ? { resolved_at: prior.resolved_at } : {}),
      };
      return;
    }
    this.entries.set(item.item_id, {
      item: { ...item, resolved: false },
      resolved: false,
    });
  }

  /**
   * Enqueue a hub-side Tier 1 inbox item. Used by the hub-service when the
   * operator triggers `unwrap`, `lockdown`, or `policy_change` from a
   * control endpoint. The handler is invoked when the item is resolved.
   */
  enqueueTier1(
    item: HubApprovalPendingItem,
    handler: Tier1ResolutionHandler,
  ): void {
    if (this.entries.has(item.item_id)) {
      throw new HubConflictError(`inbox item ${item.item_id} already exists`);
    }
    this.entries.set(item.item_id, {
      item: { ...item, resolved: false },
      resolved: false,
      tier1Handler: handler,
    });
  }

  /**
   * Snapshot every item the aggregator + hub know about.
   * The aggregator merges this with fresh source pulls each list call.
   */
  list(): HubInboxItem[] {
    return Array.from(this.entries.values()).map((e) => e.item);
  }

  get(itemId: string): HubInboxItem | null {
    return this.entries.get(itemId)?.item ?? null;
  }

  /**
   * Mark an item resolved. For Tier 1 hub-enqueued items, invokes the
   * registered handler with the operator decision before flipping state.
   *
   * Returns the post-resolution item.
   */
  async resolve(
    itemId: string,
    decision: "approve" | "deny" | "dismiss",
    nowIso: string,
  ): Promise<HubInboxItem> {
    const entry = this.entries.get(itemId);
    if (!entry) throw new HubNotFoundError(`inbox item ${itemId}`);
    if (entry.resolved) {
      throw new HubConflictError(`inbox item ${itemId} already resolved`);
    }

    let handlerResult: Tier1HandlerResult | void = undefined;
    if (entry.tier1Handler && entry.item.kind === "approval_pending") {
      if (decision === "dismiss") {
        throw new HubConflictError(
          "tier 1 approval items cannot be dismissed; use approve or deny",
        );
      }
      handlerResult = await entry.tier1Handler(
        entry.item as HubApprovalPendingItem,
        decision,
      );
    }

    entry.resolved = true;
    entry.resolved_at = nowIso;
    const resolutionPayload =
      handlerResult && handlerResult.resolution_payload
        ? handlerResult.resolution_payload
        : undefined;
    if (entry.item.kind === "approval_pending" && resolutionPayload) {
      entry.item = {
        ...(entry.item as HubApprovalPendingItem),
        resolved: true,
        resolved_at: nowIso,
        resolution_payload: resolutionPayload,
      };
    } else {
      entry.item = {
        ...entry.item,
        resolved: true,
        resolved_at: nowIso,
      };
    }
    return entry.item;
  }

  /**
   * Clear resolved entries older than `maxAgeMs`. Long-lived sessions
   * accumulate resolved entries otherwise; v1.1 ships with a default
   * trim policy in the service layer; this is just the primitive.
   */
  pruneResolvedOlderThan(nowMs: number, maxAgeMs: number): number {
    let removed = 0;
    for (const [id, entry] of this.entries) {
      if (!entry.resolved || !entry.resolved_at) continue;
      const ageMs = nowMs - new Date(entry.resolved_at).getTime();
      if (ageMs > maxAgeMs) {
        this.entries.delete(id);
        removed++;
      }
    }
    return removed;
  }

  size(): number {
    return this.entries.size;
  }
}
