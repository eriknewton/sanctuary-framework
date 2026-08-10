/**
 * BoundedMap concurrency + refusal-reason tests (fix-round-3, MUST-FIX 1 and
 * MUST-FIX 3 of the resource-governance security branch).
 *
 * Fix-round-2 made `set()` async so a global-capacity eviction could
 * durably audit an evicted entry BEFORE deleting it (see bounded-map.ts's
 * `onEvict` doc). That introduced a TOCTOU: the admission critical section
 * (origin-quota check -> capacity check -> victim selection -> audit ->
 * delete -> insert) ran with NO serialization between concurrent `set()`
 * calls, so two overlapping evicting calls could both observe the same
 * pre-eviction state, both decide, both audit, and both mutate — and,
 * separately, a concurrent UPDATE to the very entry being evicted could
 * race the audit await and still get deleted despite having just been
 * upgraded to a trust-bearing state (verified/live). This file proves the
 * fix-round-3 remediation: a per-map admission lock
 * (`BoundedMap.runAdmissionExclusive`, reusing the promise-chain shape
 * `ToolCallTrapRuntime.runExclusive` established) serializes new-key
 * admission end to end, and a post-await reference re-check protects a
 * concurrently-updated victim even though updates deliberately bypass that
 * same lock (see bounded-map.ts's `set()` doc for why bypassing is
 * required, not a gap).
 *
 * Every test here drives the REAL `BoundedMap` class directly (no MCP tool
 * layer) so the exact interleaving under test — which await resolves when,
 * relative to which synchronous continuation — is fully controlled via
 * manually-resolved deferred promises, not timing-dependent `setTimeout`
 * races.
 */

import { describe, it, expect } from "vitest";
import { BoundedMap, type EvictionDecision } from "../../src/core/bounded-map.js";

/** A promise this test can resolve/reject on demand, to pin exactly when a
 * caller-supplied `onEvict` callback settles relative to other code the
 * test runs in between starting and settling it. */
function createDeferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (err: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("BoundedMap admission concurrency (MUST-FIX 1, fix-round-3)", () => {
  it(
    "MUTATION-PROOF TARGET (serialized admission): two concurrent set() calls that would both evict the SAME victim under the pre-fix unserialized set() are admitted one at a time — onEvict fires exactly ONCE (not twice) for one logical eviction, and the map never exceeds maxSize",
    async () => {
      type Entry = { evictable: boolean };
      const evictCalls: string[] = [];
      const deferred = createDeferred();

      const map = new BoundedMap<string, Entry>({
        maxSize: 2,
        // Deterministic: always evicts the first EVICTABLE entry found in
        // iteration order. Two concurrent calls reading the SAME
        // unmodified snapshot (the pre-fix race window) would both land
        // on this exact victim — that determinism is what makes the
        // "would both pick the same victim without serialization" claim
        // provable rather than assumed.
        selectEviction: (entries): EvictionDecision<string> => {
          for (const [key, value] of entries) {
            if (value.evictable) return { evict: key };
          }
          return { refuse: true };
        },
        onEvict: async (evictedKey) => {
          evictCalls.push(evictedKey);
          // Blocks here until the test explicitly resolves `deferred` —
          // this is the exact async gap fix-round-2 introduced and
          // fix-round-3's admission lock now serializes callers around.
          await deferred.promise;
        },
      });

      // Fill to maxSize=2: one evictable "victim", one permanently-live
      // "keeper" that selectEviction will never choose.
      expect((await map.set("victim", { evictable: true })).ok).toBe(true);
      expect((await map.set("keeper", { evictable: false })).ok).toBe(true);
      expect(map.size).toBe(2);

      // Two concurrent NEW-key admissions, both requiring an eviction to
      // fit (map is at maxSize with exactly one evictable entry). Neither
      // is awaited yet — both start executing up to their own await point.
      const p1 = map.set("new-1", { evictable: false });
      const p2 = map.set("new-2", { evictable: false });

      // Let both admissions reach (or queue for) their eviction decision,
      // then release the shared audit gate. If admission were NOT
      // serialized, BOTH calls would already have called `selectEviction`
      // by this point (both against the untouched "victim"+"keeper"
      // snapshot) and both would be blocked on `deferred.promise` —
      // `evictCalls` would already read `["victim", "victim"]` here. With
      // serialization, the SECOND call cannot even run `selectEviction`
      // until the FIRST call's entire critical section (including this
      // very `onEvict` await) has resolved, so at most one call has
      // reached `onEvict` at this point.
      await Promise.resolve(); // let both p1/p2 run to their first await
      await Promise.resolve();
      expect(evictCalls.length).toBeLessThanOrEqual(1);

      deferred.resolve();
      const [r1, r2] = await Promise.all([p1, p2]);

      // Exactly ONE of the two admissions succeeded (the other found
      // nothing left to evict once "victim" was already gone, since
      // "keeper" is never evictable) — never both, never neither.
      const results = [r1, r2];
      const succeeded = results.filter((r) => r.ok);
      const refused = results.filter((r) => !r.ok);
      expect(succeeded.length).toBe(1);
      expect(refused.length).toBe(1);
      expect(refused[0]).toMatchObject({ ok: false, reason: "capacity" });

      // THE MUTATION-PROOF ASSERTION: onEvict fired for "victim" exactly
      // ONCE. Removing the admission lock (reverting `set()` to call
      // `admitNewKey`'s logic directly, unserialized) makes this 2 — both
      // concurrent calls would independently decide to evict "victim" and
      // both would call onEvict for it, even though only one delete can
      // ever actually happen.
      expect(evictCalls).toEqual(["victim"]);

      // Never overshoots maxSize, regardless of which of the two calls won.
      expect(map.size).toBe(2);
      expect(map.has("victim")).toBe(false);
      expect(map.has("keeper")).toBe(true);
    }
  );

  it(
    "MUTATION-PROOF TARGET (trust property): a victim UPGRADED to live by a concurrent update DURING an in-flight eviction's audit await is NOT deleted — the eviction is refused instead",
    async () => {
      type Entry = { live: boolean };
      let onEvictCalls = 0;
      const deferred = createDeferred();
      // Signals the exact instant `onEvict` has been INVOKED (i.e.,
      // `selectEviction` has already run and captured "victim" as the
      // victim) — without this, awaiting `map.set("newkey", ...)`'s mere
      // CREATION is not enough: `admitNewKey` for "newkey" is only
      // QUEUED as a microtask at that point, not yet running, so a
      // concurrent update issued immediately afterward could land
      // BEFORE `selectEviction` ever runs (making "victim" already live
      // by the time eviction is even decided — a different, uninteresting
      // scenario that doesn't exercise the reference re-check at all).
      // Waiting on this signal pins the update to strictly AFTER the
      // eviction has captured its victim and is genuinely in-flight.
      const onEvictStarted = createDeferred();

      const map = new BoundedMap<string, Entry>({
        maxSize: 1,
        selectEviction: (entries): EvictionDecision<string> => {
          for (const [key, value] of entries) {
            if (!value.live) return { evict: key };
          }
          return { refuse: true };
        },
        onEvict: async () => {
          onEvictCalls += 1;
          onEvictStarted.resolve();
          await deferred.promise;
        },
      });

      await map.set("victim", { live: false });
      expect(map.size).toBe(1);

      // Starts an eviction of "victim" to admit "newkey" — blocks on the
      // audit await (deferred), exactly like a real critical-audit write
      // in flight.
      const evictingPromise = map.set("newkey", { live: false });
      await onEvictStarted.promise;

      // WHILE the eviction is still pending (onEvict has been called and
      // is blocked on `deferred`), a concurrent caller UPGRADES "victim"
      // to live — e.g. a real verified handshake completing for an entry
      // a moment ago only an unverified preview. This is the UPDATE path,
      // which deliberately bypasses the admission lock (see set()'s
      // doc), so it can and does run to completion immediately, before
      // the pending eviction resumes.
      const updateResult = await map.set("victim", { live: true });
      expect(updateResult.ok).toBe(true);
      expect(map.get("victim")).toEqual({ live: true });

      // Now let the eviction's audit resolve and observe the outcome.
      deferred.resolve();
      const evictionResult = await evictingPromise;

      // THE MUTATION-PROOF ASSERTION: the eviction is REFUSED (never
      // deletes "victim") because the post-await reference re-check
      // detects the value changed since it was captured for audit.
      // Removing that re-check (reverting to "delete unconditionally
      // after the audit resolves") makes this assertion fail: "victim"
      // would be deleted despite having just been upgraded to live.
      expect(evictionResult).toMatchObject({ ok: false, reason: "capacity" });
      expect(map.has("victim")).toBe(true);
      expect(map.get("victim")).toEqual({ live: true });
      expect(map.has("newkey")).toBe(false);
      // onEvict was attempted once (the audit itself succeeded — the
      // refusal happens AFTER, at the re-check, not because the audit
      // failed).
      expect(onEvictCalls).toBe(1);
    }
  );
});

describe("BoundedMap refusal reasons (MUST-FIX 3, fix-round-3)", () => {
  it("a rejected onEvict audit refuses with reason 'audit_unavailable', DISTINCT from a genuine capacity refusal, and never deletes the would-be-evicted entry", async () => {
    type Entry = { tag: string };
    const refusals: { key: string; reason: string }[] = [];

    const map = new BoundedMap<string, Entry>({
      maxSize: 1,
      selectEviction: (entries): EvictionDecision<string> => {
        const first = entries.keys().next();
        if (first.done) return { refuse: true };
        return { evict: first.value };
      },
      onEvict: async () => {
        throw new Error("simulated audit-log outage");
      },
      onRefuse: (key, _value, reason) => {
        refusals.push({ key, reason });
      },
    });

    await map.set("existing", { tag: "original" });
    expect(map.size).toBe(1);

    const result = await map.set("incoming", { tag: "new" });

    expect(result).toEqual({ ok: false, reason: "audit_unavailable" });
    expect(refusals).toEqual([{ key: "incoming", reason: "audit_unavailable" }]);

    // Fail-closed exactly like a capacity refusal: the entry that WOULD
    // have been evicted is untouched, and the incoming entry never enters
    // the map.
    expect(map.has("existing")).toBe(true);
    expect(map.get("existing")).toEqual({ tag: "original" });
    expect(map.has("incoming")).toBe(false);
    expect(map.size).toBe(1);
  });

  it("a genuine capacity refusal (selectEviction declines) still reports reason 'capacity', not 'audit_unavailable' — the two reasons are not conflated in either direction", async () => {
    type Entry = { live: boolean };
    const refusals: string[] = [];

    const map = new BoundedMap<string, Entry>({
      maxSize: 1,
      selectEviction: (entries): EvictionDecision<string> => {
        for (const [key, value] of entries) {
          if (!value.live) return { evict: key };
        }
        return { refuse: true };
      },
      onRefuse: (_key, _value, reason) => {
        refusals.push(reason);
      },
    });

    await map.set("live-entry", { live: true });
    const result = await map.set("incoming", { live: false });

    expect(result).toEqual({ ok: false, reason: "capacity" });
    expect(refusals).toEqual(["capacity"]);
  });

  it("an origin-quota refusal still reports reason 'origin_quota', unaffected by the audit_unavailable addition", async () => {
    type Entry = { n: number };
    const map = new BoundedMap<string, Entry>({
      maxSize: 100,
      maxPerOrigin: 1,
      selectEviction: () => ({ refuse: true }),
    });

    const first = await map.set("k1", { n: 1 }, "origin-a");
    expect(first.ok).toBe(true);
    const second = await map.set("k2", { n: 2 }, "origin-a");
    expect(second).toEqual({ ok: false, reason: "origin_quota" });
  });
});
