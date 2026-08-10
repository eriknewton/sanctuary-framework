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
 * name a victim (including a victim that no longer qualifies once
 * re-checked after an audit await — see the trust-property re-validation
 * in `set()`); audit-unavailable refusals mean eviction was DECIDED but
 * the durable audit write for it did not complete (rejected or timed
 * out). Distinguishing all three lets an audit consumer tell "this one
 * caller is flooding" apart from "the whole collection is genuinely
 * saturated with entries nothing may evict" apart from "the audit trail
 * itself is unavailable right now" (MUST-FIX 3, fix-round-3) — the third
 * case is an availability problem with the AUDIT LOG, not with the
 * collection's capacity, and conflating it with "capacity" hides that
 * distinction from an operator trying to diagnose which one is true. */
export type BoundedMapRefuseReason =
  | "origin_quota"
  | "capacity"
  | "audit_unavailable";

/**
 * `set()`'s result (MUST-FIX 3, fix-round-3 — replaces a plain boolean).
 * A caller that needs to distinguish "this identity is flooding" from
 * "the store is genuinely saturated" from "the audit trail is
 * unavailable" reads `reason` directly off its OWN call's result, rather
 * than relying on a shared `onRefuse` callback and a variable read after
 * the fact — the latter would race against a QUEUED next admission for
 * the same map (`admissionQueue`) starting before this call's continuation
 * gets to read a shared variable. `onRefuse` still fires (synchronously,
 * inside the same admission) for callers that want a callback-shaped
 * side effect at the exact point of refusal; the two mechanisms are
 * independent and a caller may use either, both, or neither.
 */
export type BoundedMapSetResult =
  | { ok: true }
  | { ok: false; reason: BoundedMapRefuseReason };

/**
 * Bounds the await on a caller-supplied `onEvict` critical-audit write
 * (MUST-FIX 3, fix-round-3 — Opus availability note): `onEvict` runs
 * inside the per-map admission lock (see `admissionQueue`), so a HANGING
 * audit write would otherwise stall every later `set()` call for this map
 * indefinitely, turning an audit-log availability problem into a total
 * admission stall for the whole collection. 10_000 = 2x
 * operational/audit-log.ts's own `AUDIT_WRITE_LOCK_TIMEOUT_MS` (5s): long
 * enough that a write merely blocked behind the audit log's OWN internal
 * lock still completes inside this window, short enough that a genuinely
 * hung write fails closed (refused, reason `audit_unavailable`) in
 * bounded time rather than never — see AGENTS.md rule 8(d), bounded work
 * per request.
 */
const ON_EVICT_AUDIT_TIMEOUT_MS = 10_000;

/**
 * Race `promise` against a timer that rejects after `ms`. Used ONLY to
 * bound the `onEvict` critical-audit await (see
 * `ON_EVICT_AUDIT_TIMEOUT_MS`'s doc) — a timeout is reported to the
 * caller identically to an explicit audit rejection (both land in the
 * same `catch` in `admitNewKey` and refuse with reason
 * `audit_unavailable`), since from the eviction's perspective "the audit
 * never confirmed" is the same fail-closed condition either way.
 */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`bounded-map: onEvict audit did not settle within ${ms}ms`));
    }, ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    );
  });
}

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
  /**
   * Fired once a GLOBAL-capacity eviction decision has been made, AWAITED
   * and BEFORE the entry is removed from the map (see `set()`). RECHECK
   * (MUST-FIX 6, fix-round-2): the three maps this primitive protects
   * (handshake sessions, handshake results, federation peers) evict a
   * TRUST-BEARING entry — a verified peer's trust state disappearing is a
   * critical state change, not low-risk telemetry, so `onEvict` MUST call
   * `auditLog.appendCritical(...)` (durable, round-trip-verified) and
   * return the awaited promise, not `void auditLog.append(...)`
   * fire-and-forget. If the returned promise REJECTS (e.g. an
   * integrity-locked audit chain), `set()` ABORTS the whole eviction: the
   * evicted entry is never deleted and the incoming insert is refused,
   * exactly as if `selectEviction` had itself returned `{ refuse: true }`.
   * "Audit before delete" alone (the fix-round-1 shape) only fixes
   * ORDERING; it does not stop a crash or a rejected write from producing
   * "the entry is gone, no durable record" — only awaiting AND aborting on
   * failure closes that. A map whose evicted entries are not trust-bearing
   * (e.g. the honeypot coalescing tracker) may omit `onEvict` entirely, or
   * supply a fire-and-forget non-critical callback — this contract only
   * binds a caller that DOES supply one.
   */
  onEvict?: (evictedKey: K, evictedValue: V) => void | Promise<void>;
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
  /**
   * Serializes the NEW-KEY admission critical section (MUST-FIX 1,
   * fix-round-3 — see `admitNewKey`'s doc). A single promise chain per
   * MAP INSTANCE, not per key or per origin: the origin-quota and
   * capacity CHECKS both read state (`this.map.size`, `this.originSize`)
   * that spans every key and every origin, so a lock scoped narrower than
   * the whole map could not stop two concurrent evictors targeting
   * different origins from both observing the same pre-eviction global
   * size and both proceeding. Reuses the self-cleaning keyed-mutex SHAPE
   * `ToolCallTrapRuntime.runExclusive` established
   * (honeypot/tool-call-trap-runtime.ts) — chain the next call onto the
   * settled tail of the previous one — but does not need that method's
   * per-key cleanup: there is exactly one admission queue per BoundedMap
   * instance for the instance's whole lifetime, never one per key, so
   * there is nothing here that could grow unboundedly the way a per-key
   * map would.
   */
  private admissionQueue: Promise<void> = Promise.resolve();

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
   * Insert or update `key`. Resolves `{ ok: true }` when the entry is
   * present in the map afterward (a plain update, a plain insert under the
   * cap, or an insert admitted by evicting another entry), `{ ok: false,
   * reason }` when the insert was refused (every existing entry is left
   * exactly as it was, including the entry `selectEviction` had picked, if
   * any — see the ABORT-ON-AUDIT-FAILURE note below).
   *
   * ASYNC (MUST-FIX 6 RECHECK): a GLOBAL-capacity eviction must durably
   * audit the evicted entry BEFORE deleting it (see `onEvict`'s doc) — that
   * requires awaiting the audit write, so `set()` itself is async. A `set()`
   * call that never reaches the eviction branch (plain update, or insert
   * under both caps) still returns a promise for API uniformity, but
   * resolves on the same microtask with no real awaited work.
   *
   * `origin` is optional and only meaningful when the map was constructed
   * with `maxPerOrigin` — see the class doc and `BoundedMapOptions.maxPerOrigin`.
   *
   * NO REATTRIBUTION ON UPDATE (MUST-FIX 3, fix-round-2 RECHECK): a `set()`
   * for an EXISTING key never touches `origins` — the origin recorded at
   * INSERT time is permanent for that key's lifetime (until `delete()`).
   * The prior behavior (re-attributing the origin on every update) was a
   * framing/evasion primitive: since an update never grows the map, it
   * never re-enters the per-origin refusal check above, so an attacker who
   * can trigger an "update" of an existing key (e.g. two different sessions
   * both producing an unverified handshake preview for the same
   * counterparty_id) could silently move that key's accounting from their
   * own origin onto ANY other origin string of their choosing — inflating a
   * victim origin's count toward its quota (framing) while freeing their
   * own (evasion), all without ever creating a new key. Because origin is
   * now fixed at insertion, an update can never change what it counts
   * against, so there is nothing for a "quota re-check on update" to do —
   * the accounting an update could possibly affect is exactly the
   * accounting this rule keeps untouched.
   *
   * UPDATE PATH DELIBERATELY BYPASSES THE ADMISSION LOCK (MUST-FIX 1,
   * fix-round-3): an existing-key update runs immediately, synchronously,
   * never queued behind `admissionQueue`. This is not an oversight — it is
   * what lets a genuine update WIN a race against a slower concurrent
   * eviction of the SAME key that is still awaiting its critical audit
   * write (see `admitNewKey`'s post-await re-validation). If updates were
   * serialized behind the same lock as new-key admission, an update
   * queued behind an in-flight eviction would always lose: by the time it
   * ran, the eviction's delete would already have removed the very entry
   * the update meant to refresh. Because the update path is unlocked, it
   * can complete WHILE the eviction is still awaiting, and the eviction's
   * post-await re-check then sees the change and refuses to delete —
   * which is the behavior the "a live verified entry is never evicted"
   * invariant requires.
   */
  async set(key: K, value: V, origin?: string): Promise<BoundedMapSetResult> {
    if (this.map.has(key)) {
      this.map.set(key, value);
      return { ok: true };
    }
    return this.runAdmissionExclusive(() => this.admitNewKey(key, value, origin));
  }

  /**
   * Chains `fn` onto this map's single admission queue so at most one
   * new-key admission for THIS map runs at a time, start to finish
   * (including any `await` inside `fn`) — see `admissionQueue`'s doc for
   * why the lock is scoped to the whole map rather than to a key or
   * origin. Mirrors `ToolCallTrapRuntime.runExclusive`
   * (honeypot/tool-call-trap-runtime.ts): chain onto the prior call's
   * SETTLED tail (`.then(ok, ok)`, never left rejected) so one admission's
   * failure can never wedge every later admission behind a permanently
   * rejected promise.
   */
  private async runAdmissionExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.admissionQueue.then(fn, fn);
    this.admissionQueue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * The full new-key admission critical section (MUST-FIX 1, fix-round-3
   * TOCTOU fix): origin-quota check -> capacity check -> victim selection
   * -> awaited critical audit -> post-await re-validation -> delete ->
   * insert, run end to end under `admissionQueue` for this map. Pre-fix,
   * `set()` was async (to await `onEvict`, see that option's doc) with NO
   * serialization at all: two concurrent evicting `set()` calls could both
   * read the same pre-eviction map/origin state, both call
   * `selectEviction` and land on the SAME victim, both durably audit it,
   * and both proceed to delete-then-insert — collapsing one real delete
   * into two inserts (size overshoots `maxSize` by one per extra racer)
   * and firing `onEvict` twice for one logical eviction. Running the WHOLE
   * section (not just the delete/insert tail) inside the lock closes that:
   * the origin-quota and capacity CHECKS themselves read `this.map`/
   * `this.origins`, and a second admission reading them before the first
   * admission's decision has been fully applied is the same race as two
   * admissions reaching the delete/insert tail together — so the lock has
   * to start before the first read, not just before the first write.
   */
  private async admitNewKey(
    key: K,
    value: V,
    origin?: string,
  ): Promise<BoundedMapSetResult> {
    // Re-check: a concurrent admission for this SAME new key could have
    // been queued ahead of this one and already inserted it while this
    // call was waiting for the lock.
    if (this.map.has(key)) {
      this.map.set(key, value);
      return { ok: true };
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
      return { ok: false, reason: "origin_quota" };
    }

    if (this.map.size >= this.opts.maxSize) {
      const decision = this.opts.selectEviction(this.map, key, value);
      if ("refuse" in decision) {
        this.opts.onRefuse?.(key, value, "capacity");
        return { ok: false, reason: "capacity" };
      }
      const evictedValue = this.map.get(decision.evict);
      if (evictedValue !== undefined) {
        // Audit BEFORE delete, AWAITED and TIMEOUT-BOUNDED (see onEvict's
        // doc and ON_EVICT_AUDIT_TIMEOUT_MS's doc): a crash, a rejected
        // audit write, OR a hung audit write between these two steps must
        // never leave "vanished, no durable audit record" as the outcome a
        // reviewer sees later. On rejection or timeout, ABORT the eviction
        // entirely — the evicted entry is never deleted and this insert is
        // refused (reason `audit_unavailable`, distinct from a genuine
        // capacity refusal — MUST-FIX 3), rather than proceeding to mutate
        // state with no durable trail of why.
        try {
          await withTimeout(
            Promise.resolve(this.opts.onEvict?.(decision.evict, evictedValue)),
            ON_EVICT_AUDIT_TIMEOUT_MS,
          );
        } catch {
          this.opts.onRefuse?.(key, value, "audit_unavailable");
          return { ok: false, reason: "audit_unavailable" };
        }
        // POST-AWAIT TRUST-PROPERTY RE-VALIDATION (MUST-FIX 1, fix-round-3):
        // the update path above deliberately bypasses `admissionQueue`
        // (see `set()`'s doc), so a concurrent `set()` call for
        // `decision.evict` could have replaced its value WHILE this call
        // awaited the audit write above — e.g. an unverified preview
        // upgraded to a verified, liveness-proven, unexpired result mid-
        // eviction. Re-comparing against the exact value object this call
        // captured and audited (never re-fetching and re-checking a
        // caller-specific "is this still evictable" predicate, which this
        // generic primitive has no way to know) is a reliable "did
        // anything change since I decided to evict this" signal: every
        // production caller of `set()` replaces the WHOLE value on update
        // (`recordHandshakeResult` and `registerFromHandshake` both
        // construct a fresh object; neither mutates an existing one in
        // place), so a reference mismatch here can only mean a concurrent
        // `set()` won the race. A verified, live entry must NEVER be
        // evicted (see the class doc's PER-ORIGIN QUOTA section and each
        // call site's `selectEviction`) — refusing here is the fail-closed
        // choice over deleting state this call no longer has an accurate,
        // freshly-audited record of.
        if (this.map.get(decision.evict) !== evictedValue) {
          this.opts.onRefuse?.(key, value, "capacity");
          return { ok: false, reason: "capacity" };
        }
      }
      this.map.delete(decision.evict);
      this.origins.delete(decision.evict);
    }

    this.map.set(key, value);
    if (origin !== undefined) this.origins.set(key, origin);
    return { ok: true };
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
