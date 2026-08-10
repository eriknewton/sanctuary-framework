/**
 * Sanctuary MCP Server — Bounded Map
 *
 * CLASS-LEVEL CHOKEPOINT (AGENTS.md rule 8 / register LD2-03, LD2-04):
 * "an attacker-writable collection with no cap, no eviction, and O(all)
 * listing work" recurred across three separate in-memory maps (handshake
 * sessions, handshake results, federation peers) after the same class was
 * already closed once in the honeypot activation buffer (#1190). This
 * primitive makes cap + eviction + bounded listing STRUCTURAL for any new
 * caller, rather than a convention each site has to remember to reinvent.
 *
 * Deliberately a thin wrapper, not a policy framework: it owns capacity
 * ENFORCEMENT only. The eviction DECISION is always supplied by the caller,
 * because the three sites this closes have genuinely different correct
 * semantics (prefer-evict-unverified for handshake results, refuse-on-
 * all-active for federation peers, TTL/terminal-state sweep for sessions) —
 * hard-coding one policy here would silently mismatch two of the three.
 */

/**
 * The caller's answer to "a new key needs room; what do I do?" — either name
 * an existing key to evict (making room for the incoming entry), or refuse
 * the incoming insert outright and leave every existing entry untouched.
 * `selectEviction` is the ONLY place this decision is made, so the trust
 * semantics for a given map live in one function a reviewer can read next to
 * the map's construction, not scattered across every call site that
 * happens to insert into it.
 */
export type EvictionDecision<K> = { evict: K } | { refuse: true };

export interface BoundedMapOptions<K, V> {
  /**
   * Hard cap on entry count. Each call site names and derives its own
   * constant (the right number depends on what is being capped); this
   * primitive only enforces whatever value it is given.
   */
  maxSize: number;
  /**
   * Called ONLY when a `set()` for a key NOT already present would exceed
   * `maxSize` (an update to an existing key never grows the map, so it never
   * reaches this callback — replacing a value in place cannot be a growth
   * vector for an attacker-writable collection).
   */
  selectEviction: (
    entries: ReadonlyMap<K, V>,
    incomingKey: K,
    incomingValue: V,
  ) => EvictionDecision<K>;
  /** Fired once an eviction has actually happened (capacity-driven). */
  onEvict?: (evictedKey: K, evictedValue: V) => void;
  /** Fired when an insert is refused because `selectEviction` refused. */
  onRefuse?: (incomingKey: K, incomingValue: V) => void;
}

export class BoundedMap<K, V> {
  private readonly map = new Map<K, V>();
  private readonly opts: BoundedMapOptions<K, V>;

  constructor(opts: BoundedMapOptions<K, V>) {
    if (!Number.isInteger(opts.maxSize) || opts.maxSize <= 0) {
      throw new Error("BoundedMap: maxSize must be a positive integer");
    }
    this.opts = opts;
  }

  get size(): number {
    return this.map.size;
  }

  get(key: K): V | undefined {
    return this.map.get(key);
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  /**
   * Insert or update `key`. Returns `true` when the entry is present in the
   * map afterward (a plain update, a plain insert under the cap, or an
   * insert admitted by evicting another entry), `false` when the insert was
   * refused (at cap, and `selectEviction` declined to name a victim — every
   * existing entry is left exactly as it was).
   */
  set(key: K, value: V): boolean {
    if (!this.map.has(key) && this.map.size >= this.opts.maxSize) {
      const decision = this.opts.selectEviction(this.map, key, value);
      if ("refuse" in decision) {
        this.opts.onRefuse?.(key, value);
        return false;
      }
      const evictedValue = this.map.get(decision.evict);
      const removed = this.map.delete(decision.evict);
      if (removed && evictedValue !== undefined) {
        this.opts.onEvict?.(decision.evict, evictedValue);
      }
    }
    this.map.set(key, value);
    return true;
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }

  /**
   * Remove every entry for which `predicate` returns true. This is the
   * sweep primitive TTL/terminal-state call sites run at the top of every
   * handler (mirroring #1190's `pruneExpiredActivations` placement), so a
   * collection is bounded to LIVE entries on the request path, not only by
   * the capacity cap. Returns the number of entries removed.
   */
  sweep(predicate: (value: V, key: K) => boolean): number {
    let removed = 0;
    for (const [key, value] of this.map) {
      if (predicate(value, key)) {
        this.map.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  keys(): IterableIterator<K> {
    return this.map.keys();
  }

  values(): IterableIterator<V> {
    return this.map.values();
  }

  entries(): IterableIterator<[K, V]> {
    return this.map.entries();
  }

  /**
   * Bounded-iteration accessor: at most `limit` values, without a consumer
   * having to materialize or scan the whole map first. Order is Map
   * insertion order (oldest key first among entries never re-inserted).
   */
  boundedList(limit: number): V[] {
    const out: V[] = [];
    for (const value of this.map.values()) {
      if (out.length >= limit) break;
      out.push(value);
    }
    return out;
  }

  /**
   * Read-only view for consumers that must never mutate — mirrors the
   * `ReadonlyMap` contract `handshakeResults` already exposes externally
   * (register §Z RECHECK: `recordHandshakeResult` is the only writer).
   */
  asReadonlyMap(): ReadonlyMap<K, V> {
    return this.map;
  }
}
