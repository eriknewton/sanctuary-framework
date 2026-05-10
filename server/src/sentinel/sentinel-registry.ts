/**
 * Sanctuary v1.3 WP-V1.3-1 Sentinel Registry.
 *
 * Tracks two things for one fortress:
 *  1. The catalog of sentinel CLASSES the fortress can subscribe to
 *     (registered at process boot).
 *  2. Which sentinels the operator has actually opted IN.
 *
 * Default subscription set is empty: the operator must opt in. This
 * keeps the no-outbound-by-default rule and the "operator pulls
 * features" UX pattern from CLAUDE.md.
 *
 * Multi-fortress isolation: one registry instance per fortress. The
 * dispatcher consults the registry and never crosses fortress
 * boundaries.
 */

import type { Sentinel } from "./sentinel.js";
import type { SentinelContext } from "./types.js";

export interface SentinelCatalogEntry {
  sentinelId: string;
  description: string;
  factory: () => Sentinel;
}

/**
 * Coordinator-CTO defaults: the registry ships with the Phi-1 catalog
 * pre-loaded but with zero subscriptions. Tests inject custom catalogs
 * via `register()`.
 */
export class SentinelRegistry {
  private readonly catalog = new Map<string, SentinelCatalogEntry>();
  private readonly subscribed = new Map<string, Sentinel>();

  register(entry: SentinelCatalogEntry): void {
    if (this.catalog.has(entry.sentinelId)) {
      throw new Error(
        `sentinel-registry: ${entry.sentinelId} already registered`,
      );
    }
    this.catalog.set(entry.sentinelId, entry);
  }

  /**
   * Available sentinels (catalog view). Operator UI lists this so the
   * operator can pick what to subscribe to.
   */
  listCatalog(): Array<{ sentinelId: string; description: string }> {
    return [...this.catalog.values()].map((entry) => ({
      sentinelId: entry.sentinelId,
      description: entry.description,
    }));
  }

  /** Currently subscribed sentinel ids. */
  listSubscribed(): string[] {
    return [...this.subscribed.keys()];
  }

  /** Has the fortress opted into this sentinel? */
  isSubscribed(sentinelId: string): boolean {
    return this.subscribed.has(sentinelId);
  }

  /**
   * Subscribe a sentinel to a fortress context. Idempotent: a second
   * subscribe call on an already-subscribed sentinel returns the
   * existing instance without re-running `subscribe()`.
   */
  async subscribe(
    sentinelId: string,
    context: SentinelContext,
  ): Promise<Sentinel> {
    const existing = this.subscribed.get(sentinelId);
    if (existing) return existing;
    const entry = this.catalog.get(sentinelId);
    if (!entry) {
      throw new Error(`sentinel-registry: unknown sentinel ${sentinelId}`);
    }
    const instance = entry.factory();
    await instance.subscribe(context);
    this.subscribed.set(sentinelId, instance);
    return instance;
  }

  /**
   * Unsubscribe. Idempotent: unsubscribing an unsubscribed sentinel
   * returns false without throwing. Returns true when an active
   * subscription was torn down.
   */
  async unsubscribe(sentinelId: string): Promise<boolean> {
    const instance = this.subscribed.get(sentinelId);
    if (!instance) return false;
    try {
      await instance.unsubscribe();
    } finally {
      this.subscribed.delete(sentinelId);
    }
    return true;
  }

  /**
   * Snapshot of subscribed sentinels for the dispatcher's tick path.
   * Returned as an array so the dispatcher can iterate without holding
   * the map under modification.
   */
  snapshotSubscribed(): Array<{ sentinelId: string; sentinel: Sentinel }> {
    return [...this.subscribed.entries()].map(([sentinelId, sentinel]) => ({
      sentinelId,
      sentinel,
    }));
  }

  /**
   * Tear down every subscription. Called by the dispatcher on
   * fortress-shutdown. Best-effort: a failing unsubscribe does not
   * abort the rest.
   */
  async unsubscribeAll(): Promise<void> {
    const ids = [...this.subscribed.keys()];
    for (const id of ids) {
      try {
        await this.unsubscribe(id);
      } catch {
        // Continue draining.
      }
    }
  }
}
