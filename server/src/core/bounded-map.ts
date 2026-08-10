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
 * semantics (prefer-evict-unverified-then-expired for handshake results,
 * refuse-on-all-active for federation peers, TTL/terminal-state sweep for
 * sessions) — hard-coding one policy here would silently mismatch two of
 * the three.
 *
 * PER-ORIGIN QUOTA (AGENTS.md rule 8, RECHECK — a GLOBAL-only cap let one
 * flooding caller consume the whole cap and evict/lock out every other
 * caller; a HIGH gate finding on the first cut of this primitive). When a
 * caller supplies `origin` to `set()` and `maxPerOrigin` in the options, a
 * NEW key whose origin already holds `maxPerOrigin` entries is REFUSED —
 * never evicted, and never by evicting a DIFFERENT origin's entry to make
 * room. This is deliberately a REFUSE-only rule, not "evict this origin's
 * own oldest entry": the class this map protects (handshake sessions,
 * handshake results, federation peers) treats "a live entry was evicted"
 * as a trust event with its own audited meaning (a verified peer's trust
 * state disappearing), and that meaning must not depend on WHOSE flood
 * caused the pressure. Refusing keeps every existing entry — this origin's
 * and every other origin's — untouched, so the eviction-safety guarantee
 * `selectEviction` already provides (never evict a verified/active entry)
 * is never bypassed by routing pressure through the per-origin path
 * instead of the global one. `selectEviction` is consulted only when the
 * map is at the GLOBAL cap and the incoming origin is still within its own
 * quota — i.e., the pressure comes from OTHER origins collectively, not
 * from this insert.
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

/** Why a `set()` call was refused — origin-quota refusals never touch a
 * different origin's entries or the global eviction policy; capacity
 * refusals ran the caller-supplied `selectEviction` and it declined to
 * name a victim. Distinguishing the two lets an audit consumer tell "this
 * one caller is flooding" apart from "the whole collection is genuinely
 * saturated with entries nothing may evict." */
export type BoundedMapRefuseReason = "origin_quota" | "capacity";

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
   * vector for an attacker-writable collection), AND the incoming entry's
   * own origin (if any) is still within its per-origin quota (see the
   * module doc above — an over-quota origin is refused before this ever
   * runs, so `selectEviction` never has to reason about origin fairness).
   */
  selectEviction: (
    entries: ReadonlyMap<K, V>,
    incomingKey: K,
    incomingValue: V,
  ) => EvictionDecision<K>;
  /** Fired once a GLOBAL-capacity eviction has actually happened. Called
   * BEFORE the entry is removed from the map (see `set()`): a crash between
   * the audit call and the physical delete must never leave "the entry is
   * gone with no audit trail" as the observable outcome, so the audit
   * intent is recorded first. The callback itself is the same fire-and-
   * forget `void auditLog.append(...)` shape used throughout this codebase
   * (see AGENTS.md rule 6/7's audit conventions) — ordering the call before
   * the delete is the fix this primitive owns; making the audit write
   * itself durable end-to-end is the audit log's contract, not this one. */
  onEvict?: (evictedKey: K, evictedValue: V) => void;
  /** Fired when an insert is refused — either because the incoming origin
   * was already at `maxPerOrigin`, or because the map is at the global cap
   * and `selectEviction` refused. */
  onRefuse?: (
    incomingKey: K,
    incomingValue: V,
    reason: BoundedMapRefuseReason,
  ) => void;
  /**
   * Per-origin quota (AGENTS.md rule 8): the maximum number of entries a
   * SINGLE origin (the string passed as `set()`'s third argument) may hold,
   * independent of `maxSize`. Omit to disable per-origin accounting
   * entirely (a `set()` call that never passes `origin` behaves exactly as
   * before — global-cap-only). Required alongside `maxPerOrigin` for the
   * quota to do anything; a `set()` call that omits `origin` on a map
   * configured with `maxPerOrigin` simply skips the per-origin check for
   * that one entry (it is accounted under no origin, so no future entry can
   * ever be evicted or refused "because of" it).
   */
  maxPerOrigin?: number;
}

export class BoundedMap<K, V> {
  private readonly map = new Map<K, V>();
  /** origin accounting (rule 8) — only ever populated for keys whose `set()`
   * call supplied an `origin`; see `maxPerOrigin` above. Kept as a sibling
   * map (rather than folding origin into V) so callers never have to widen
   * their stored value's TYPE just to get per-origin fairness. */
  private readonly origins = new Map<K, string>();
  private readonly opts: BoundedMapOptions<K, V>;

  constructor(opts: BoundedMapOptions<K, V>) {
    if (!Number.isInteger(opts.maxSize) || opts.maxSize <= 0) {
      throw new Error("BoundedMap: maxSize must be a positive integer");
    }
    if (
      opts.maxPerOrigin !== undefined &&
      (!Number.isInteger(opts.maxPerOrigin) || opts.maxPerOrigin <= 0)
    ) {
      throw new Error("BoundedMap: maxPerOrigin must be a positive integer");
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

  /** Origin recorded for `key`, or undefined if the key does not exist or
   * was inserted without an origin. Exposed so a consumer that needs to
   * attribute an entry to its origin (e.g. federation peer registration
   * reading which local identity recorded the underlying handshake result)
   * does not need a second parallel bookkeeping map of its own. */
  originOf(key: K): string | undefined {
    return this.origins.get(key);
  }

  /** Read-only view of the key -> origin accounting, for a consumer that
   * needs to look up many origins (e.g. federation/tools.ts resolving the
   * origin for a `peer_id` before delegating to the registry). */
  originsView(): ReadonlyMap<K, string> {
    return this.origins;
  }

  /** How many entries the given origin currently holds. O(map size), which
   * is bounded by `maxSize` — cheap at the scale this primitive is used at
   * (hundreds to low thousands of entries), and only ever called from
   * `set()`'s own growth path (bounded work per request, AGENTS.md rule
   * 8(d)), never from a hot read path. */
  originSize(origin: string): number {
    let count = 0;
    for (const value of this.origins.values()) {
      if (value === origin) count += 1;
    }
    return count;
  }

  /**
   * Insert or update `key`. Returns `true` when the entry is present in the
   * map afterward (a plain update, a plain insert under the cap, or an
   * insert admitted by evicting another entry), `false` when the insert was
   * refused (every existing entry is left exactly as it was).
   *
   * `origin` is optional and only meaningful when the map was constructed
   * with `maxPerOrigin` — see the class doc and `BoundedMapOptions.maxPerOrigin`.
   * Passing a DIFFERENT origin on a later `set()` for the same existing key
   * re-attributes that key's origin going forward (an update never grows
   * the map, so it is never subject to the per-origin refusal check either
   * way).
   */
  set(key: K, value: V, origin?: string): boolean {
    if (this.map.has(key)) {
      this.map.set(key, value);
      if (origin !== undefined) this.origins.set(key, origin);
      return true;
    }

    // Per-origin quota FIRST (rule 8): a new key whose origin is already at
    // its own quota is refused outright, before the global-capacity path
    // (and therefore before `selectEviction`) ever runs. This is what
    // guarantees a flooding origin can neither evict nor starve any OTHER
    // origin — it hits its own wall first, every time, regardless of how
    // much headroom the global cap still has.
    if (
      origin !== undefined &&
      this.opts.maxPerOrigin !== undefined &&
      this.originSize(origin) >= this.opts.maxPerOrigin
    ) {
      this.opts.onRefuse?.(key, value, "origin_quota");
      return false;
    }

    if (this.map.size >= this.opts.maxSize) {
      const decision = this.opts.selectEviction(this.map, key, value);
      if ("refuse" in decision) {
        this.opts.onRefuse?.(key, value, "capacity");
        return false;
      }
      const evictedValue = this.map.get(decision.evict);
      if (evictedValue !== undefined) {
        // Audit BEFORE delete (see onEvict's doc) — a crash between these
        // two lines must never leave "vanished, no audit record" as the
        // outcome a reviewer sees later.
        this.opts.onEvict?.(decision.evict, evictedValue);
      }
      this.map.delete(decision.evict);
      this.origins.delete(decision.evict);
    }

    this.map.set(key, value);
    if (origin !== undefined) this.origins.set(key, origin);
    return true;
  }

  delete(key: K): boolean {
    this.origins.delete(key);
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
        this.origins.delete(key);
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
