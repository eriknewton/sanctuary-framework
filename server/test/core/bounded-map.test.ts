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

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  BoundedMap,
  ON_EVICT_AUDIT_TIMEOUT_MS,
  type EvictionDecision,
} from "../../src/core/bounded-map.js";

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

describe("BoundedMap admission-waiter cap (AGENTS.md rule 8 on the fix's OWN state, fix-round-6)", () => {
  it(
    "MUTATION-PROOF TARGET (waiter cap): concurrent admissions past maxPendingAdmissionWaiters are refused immediately with reason 'admission_busy', never queued — the waiter count never exceeds the configured cap",
    async () => {
      // maxSize: 1 so every NEW-key admission after the seed requires an
      // eviction (and therefore actually reaches `runAdmissionExclusive`
      // and blocks on `onEvict`, rather than resolving on the same
      // microtask the way an under-cap plain insert would) — this is what
      // lets the test hold the admission lock open long enough to prove
      // callers queue up BEHIND it, not just that a single call succeeds.
      const deferred = createDeferred();
      const WAITER_CAP = 2;
      const busyRefusals: string[] = [];
      const map = new BoundedMap<string, { n: number }>({
        maxSize: 1,
        maxPendingAdmissionWaiters: WAITER_CAP,
        selectEviction: (entries) => {
          for (const [key] of entries) return { evict: key };
          return { refuse: true };
        },
        onEvict: async () => {
          await deferred.promise;
        },
        onRefuse: (key, _value, reason) => {
          if (reason === "admission_busy") busyRefusals.push(key);
        },
      });

      // Fill to maxSize=1 uncontended — no eviction needed yet.
      expect((await map.set("seed", { n: 0 })).ok).toBe(true);

      // Fire THREE concurrent new-key admissions, none awaited yet. Each
      // requires evicting "seed" (map is at maxSize=1), so each must pass
      // through the admission-waiter check in `set()` BEFORE it can even
      // attempt to join `admissionQueue`.
      const p1 = map.set("a", { n: 1 }); // occupies waiter slot 1, becomes
      // the running admission (blocks on `deferred` inside onEvict).
      const p2 = map.set("b", { n: 2 }); // occupies waiter slot 2, queues
      // behind p1's still-in-flight admission.
      const p3 = map.set("c", { n: 3 }); // waiter count is already AT the
      // cap (2) by the time this synchronous call runs — refused
      // immediately, never touching `admissionQueue` at all.

      // THE MUTATION-PROOF ASSERTION: p3 resolves to a busy refusal WITHOUT
      // waiting on `deferred` — proving it never joined the queue behind
      // p1/p2. Removing the cap (or defaulting it to something larger than
      // 2) would instead let p3 queue and eventually succeed once
      // `deferred` resolves, evicting "a" — this assertion catches exactly
      // that mutation.
      const r3 = await p3;
      // `busyAudit` (fix-round-7) rides along on every busy refusal; its
      // coalescing semantics have their own describe block below — here it
      // only matters that the refusal reason itself is unchanged.
      expect(r3).toMatchObject({ ok: false, reason: "admission_busy" });
      expect(busyRefusals).toEqual(["c"]);

      // p1 and p2 are still genuinely pending (blocked on `deferred`) —
      // the cap refused p3 WITHOUT touching the two admissions already
      // queued ahead of it.
      let p1Settled = false;
      let p2Settled = false;
      void p1.then(() => {
        p1Settled = true;
      });
      void p2.then(() => {
        p2Settled = true;
      });
      await Promise.resolve();
      await Promise.resolve();
      expect(p1Settled).toBe(false);
      expect(p2Settled).toBe(false);

      // Release the gate: p1 evicts "seed" and inserts "a"; p2 then runs,
      // evicts "a", and inserts "b".
      deferred.resolve();
      const [r1, r2] = await Promise.all([p1, p2]);
      expect(r1.ok).toBe(true);
      expect(r2.ok).toBe(true);
      expect(map.size).toBe(1);
      expect(map.has("b")).toBe(true);

      // The waiter counter correctly returned to 0 once every admission
      // settled — a fresh admission is neither spuriously refused nor
      // able to exceed the cap on its own. (If the counter had leaked —
      // e.g. a missing `finally` decrement — this call would incorrectly
      // read as busy even with no concurrent admission in flight.)
      const p4 = map.set("d", { n: 4 });
      const r4 = await p4;
      expect(r4.ok).toBe(true);
    }
  );

  it("maxPendingAdmissionWaiters must be a positive integer", () => {
    expect(
      () =>
        new BoundedMap<string, number>({
          maxSize: 10,
          maxPendingAdmissionWaiters: 0,
          selectEviction: () => ({ refuse: true }),
        })
    ).toThrow(/maxPendingAdmissionWaiters must be a positive integer/);
  });
});

describe("BoundedMap busy-audit coalescing (fix-round-7 — once per saturation episode, never per refusal)", () => {
  /** Harness shared by both tests below: maxSize 1 + a re-armable onEvict
   * gate, so every post-seed admission blocks inside its eviction's audit
   * await and the test controls exactly when the running admission settles
   * (ending the saturation episode). Cap 1 means the single running
   * admission IS the whole waiter queue — every concurrent call during it
   * is a busy refusal. */
  function makeGatedMap() {
    let gate = createDeferred();
    const onRefuseDecisions: {
      key: string;
      emit: boolean | undefined;
      suppressed: number | undefined;
    }[] = [];
    const map = new BoundedMap<string, { n: number }>({
      maxSize: 1,
      maxPendingAdmissionWaiters: 1,
      selectEviction: (entries) => {
        for (const [key] of entries) return { evict: key };
        return { refuse: true };
      },
      onEvict: async () => {
        await gate.promise;
      },
      onRefuse: (key, _value, reason, busyAudit) => {
        if (reason !== "admission_busy") return;
        onRefuseDecisions.push({
          key,
          emit: busyAudit?.emit,
          suppressed: busyAudit?.suppressedSinceLastAudit,
        });
      },
    });
    return {
      map,
      onRefuseDecisions,
      openGate: () => gate.resolve(),
      rearmGate: () => {
        gate = createDeferred();
      },
    };
  }

  it(
    "MUTATION-PROOF TARGET (busy-audit coalescing): a flood of busy refusals in ONE saturation episode gets emit:true on exactly the FIRST refusal — every later refusal in the episode is emit:false, while the refusal RESULT itself still comes back on every call",
    async () => {
      const { map, onRefuseDecisions, openGate } = makeGatedMap();
      expect((await map.set("seed", { n: 0 })).ok).toBe(true);

      // Occupies the single waiter slot and blocks inside onEvict — the
      // saturation episode starts with the first refusal below.
      const running = map.set("occupant", { n: 1 });

      // Five-call busy flood while the queue is saturated.
      const refusals = await Promise.all(
        ["b1", "b2", "b3", "b4", "b5"].map((k) => map.set(k, { n: 9 }))
      );

      // AGENT-FACING behavior is per-call and uncoalesced: every one of
      // the five calls got its own typed busy refusal.
      for (const r of refusals) {
        expect(r).toMatchObject({ ok: false, reason: "admission_busy" });
      }

      // THE MUTATION-PROOF ASSERTION (audit half): only the FIRST refusal
      // of the episode carries emit:true; the other four are suppressed.
      // Mutating AdmissionBusyAuditCoalescer.onBusyRefusal to always
      // return emit:true (coalescing disabled) makes every consumer's
      // audit append fire per refusal again — this assertion catches
      // exactly that mutation.
      expect(onRefuseDecisions.map((d) => d.emit)).toEqual([
        true,
        false,
        false,
        false,
        false,
      ]);
      // The emitted (first) decision reports 0 suppressed since the last
      // audit — nothing was suppressed before it.
      expect(onRefuseDecisions[0]!.suppressed).toBe(0);

      // The same decision object rides on the RESULT channel (the one
      // handshake/tools.ts consumes), not only the onRefuse channel.
      const first = refusals[0]!;
      const second = refusals[1]!;
      if (first.ok || first.reason !== "admission_busy") {
        throw new Error("expected a busy refusal");
      }
      if (second.ok || second.reason !== "admission_busy") {
        throw new Error("expected a busy refusal");
      }
      expect(first.busyAudit).toEqual({
        emit: true,
        suppressedSinceLastAudit: 0,
      });
      expect(second.busyAudit.emit).toBe(false);

      openGate();
      await expect(running).resolves.toEqual({ ok: true });
    }
  );

  it(
    "a NEW saturation episode after the queue drains re-audits (emit:true again), and the emitted decision carries the count of refusals suppressed since the LAST emitted audit",
    async () => {
      const { map, onRefuseDecisions, openGate, rearmGate } = makeGatedMap();
      expect((await map.set("seed", { n: 0 })).ok).toBe(true);

      // Episode 1: one running admission, four busy refusals (1 emitted,
      // 3 suppressed).
      const running1 = map.set("occupant-1", { n: 1 });
      await Promise.all(
        ["e1-a", "e1-b", "e1-c", "e1-d"].map((k) => map.set(k, { n: 9 }))
      );
      expect(onRefuseDecisions.map((d) => d.emit)).toEqual([
        true,
        false,
        false,
        false,
      ]);

      // Drain: the running admission settles, dropping the waiter count
      // below the cap — the episode ends here (BoundedMap.set()'s
      // settlement `finally`), NOT at any timer or explicit reset.
      openGate();
      await expect(running1).resolves.toEqual({ ok: true });

      // Episode 2: saturate again.
      rearmGate();
      const running2 = map.set("occupant-2", { n: 2 });
      const r = await map.set("e2-a", { n: 9 });

      // THE MUTATION-PROOF ASSERTION (re-audit half): the first refusal of
      // the NEW episode audits again — a coalescer that never re-arms
      // (episodeActive stuck true, e.g. a dropped onBelowCap call in the
      // settlement `finally`) would leave this emit:false and silence the
      // busy audit for the instance's whole lifetime.
      if (r.ok || r.reason !== "admission_busy") {
        throw new Error("expected a busy refusal");
      }
      expect(r.busyAudit.emit).toBe(true);
      // ...and it reports the 3 refusals suppressed since the last emitted
      // audit (episode 1's b/c/d), so the coalesced trail still reflects
      // the flood's volume honestly.
      expect(r.busyAudit.suppressedSinceLastAudit).toBe(3);

      openGate();
      await expect(running2).resolves.toEqual({ ok: true });
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

describe("BoundedMap onEvict timeout + onEvicted authority (fix-round-4, MUST-FIX 1 / F1)", () => {
  // Real timers, driven synchronously via `vi.advanceTimersByTimeAsync`
  // rather than a real multi-second wait — mirrors the established pattern
  // in test/v1/federation-guardian-disable-gate.test.ts and
  // test/transparency/scheduler.test.ts. `withTimeout` (bounded-map.ts)
  // uses a real `setTimeout`, so fake timers let this test exercise
  // `ON_EVICT_AUDIT_TIMEOUT_MS`'s ACTUAL value deterministically and fast,
  // rather than accepting the "not tested at real-time scale" residual the
  // fix-round-3 build disclosed (and which the gate finding this file
  // closes flagged as the exact area the disclosed residual got wrong).
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it(
    "a slow-but-successful onEvict that resolves BEFORE ON_EVICT_AUDIT_TIMEOUT_MS (e.g. 35s, which would have crossed the OLD 10s timeout) never spuriously refuses — the eviction succeeds normally, once, and onEvicted fires for the real delete",
    async () => {
      type Entry = { tag: string };
      const onEvictedCalls: string[] = [];
      let onEvictCalls = 0;
      let resolveAudit!: () => void;

      const map = new BoundedMap<string, Entry>({
        maxSize: 1,
        selectEviction: (entries) => {
          const first = entries.keys().next();
          if (first.done) return { refuse: true };
          return { evict: first.value };
        },
        onEvict: async () => {
          onEvictCalls += 1;
          // Models a slow-but-successful `appendCritical`: its own I/O
          // takes 35s (past the OLD, WRONG 10s derivation, but comfortably
          // inside the CORRECTED derivation — AUDIT_WRITE_LOCK_TIMEOUT_MS +
          // DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS + margin — since
          // audit-log.ts itself guarantees `appendCritical` settles within
          // that same bound).
          await new Promise<void>((resolve) => {
            resolveAudit = resolve;
          });
        },
        onEvicted: (evictedKey) => {
          onEvictedCalls.push(evictedKey);
        },
      });

      await map.set("existing", { tag: "original" });

      const setPromise = map.set("incoming", { tag: "new" });
      await vi.advanceTimersByTimeAsync(35_000);
      // Let the resolved audit's continuation (and admitNewKey's own
      // post-await steps) actually run before releasing the promise below.
      resolveAudit();
      const result = await setPromise;

      expect(onEvictCalls).toBe(1);
      // THE MUTATION-PROOF ASSERTION (availability half of F1): a write
      // that legitimately takes 35s — well past the OLD 10s timeout, well
      // inside the CORRECTED one — must succeed, not spuriously refuse.
      // Reverting `ON_EVICT_AUDIT_TIMEOUT_MS` to its old (wrong) 10s
      // derivation makes this assertion fail: `result` would be
      // `{ ok: false, reason: "audit_unavailable" }` instead.
      expect(result).toEqual({ ok: true });
      expect(map.has("existing")).toBe(false);
      expect(map.has("incoming")).toBe(true);
      // onEvicted fires exactly once, for the entry that was REALLY
      // evicted — this eviction was genuine (not timed out), so the
      // caller's sibling-state cleanup runs exactly when it should.
      expect(onEvictedCalls).toEqual(["existing"]);
    },
  );

  it(
    "MUTATION-PROOF TARGET (F1): an onEvict promise that resolves AFTER set() has already timed out and refused never fires onEvicted — a detached, timed-out audit continuation can never trigger a caller's sibling-state side effect",
    async () => {
      type Entry = { tag: string };
      const onEvictedCalls: string[] = [];
      const refusals: { reason: string }[] = [];
      let resolveAudit!: () => void;

      const map = new BoundedMap<string, Entry>({
        maxSize: 1,
        selectEviction: (entries) => {
          const first = entries.keys().next();
          if (first.done) return { refuse: true };
          return { evict: first.value };
        },
        onEvict: async () => {
          // Never resolves within the test's own control — simulates a
          // write that is still genuinely in flight when
          // ON_EVICT_AUDIT_TIMEOUT_MS elapses (a true outage/hang, not the
          // "merely slow" case the prior test covers), and resolves LATER,
          // after `set()` has already given up.
          await new Promise<void>((resolve) => {
            resolveAudit = resolve;
          });
        },
        onEvicted: (evictedKey) => {
          onEvictedCalls.push(evictedKey);
        },
        onRefuse: (_key, _value, reason) => {
          refusals.push({ reason });
        },
      });

      await map.set("existing", { tag: "original" });

      const setPromise = map.set("incoming", { tag: "new" });
      await vi.advanceTimersByTimeAsync(ON_EVICT_AUDIT_TIMEOUT_MS);
      const result = await setPromise;

      // `set()` has already given up and refused — the victim is untouched.
      expect(result).toEqual({ ok: false, reason: "audit_unavailable" });
      expect(refusals).toEqual([{ reason: "audit_unavailable" }]);
      expect(map.has("existing")).toBe(true);
      expect(map.has("incoming")).toBe(false);
      expect(onEvictedCalls).toEqual([]);

      // NOW let the detached onEvict promise finally resolve — modeling the
      // F1 repro exactly: a write that was merely slow, not truly hung,
      // finally landing after the caller already stopped listening.
      resolveAudit();
      // Flush every microtask the late resolution's continuation could
      // possibly run on, including inside bounded-map.ts's own internals.
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();

      // THE MUTATION-PROOF ASSERTION: onEvicted NEVER fires for this late
      // resolution. Reverting to the fix-round-3 shape (writerOrigins
      // cleanup living inside `onEvict` itself, guarded only by a
      // post-hoc "does the map still hold this value" re-check) would let
      // a caller's sibling-state mutation run right here, from the
      // detached continuation, for an eviction that never actually
      // happened — exactly the F1 defect. With the fix, there is no code
      // path left that could call `onEvicted` for this settled admission.
      expect(onEvictedCalls).toEqual([]);
      expect(map.has("existing")).toBe(true);
      expect(map.has("incoming")).toBe(false);
    },
  );
});

describe("bounded-map.ts <-> operational/audit-log.ts cross-file pin (F1 derivation)", () => {
  it("ON_EVICT_AUDIT_TIMEOUT_MS is derived STRICTLY ABOVE the audit log's own worst-case appendCritical settle time (acquisition timeout + write-lock hold deadline) — the exact bound the F1 finding proved was violated by the prior 10s value", async () => {
    const { AUDIT_WRITE_LOCK_TIMEOUT_MS, DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS } =
      await import("../../src/operational/audit-log.js");
    const auditLogWorstCaseSettleMs =
      AUDIT_WRITE_LOCK_TIMEOUT_MS + DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS;
    expect(ON_EVICT_AUDIT_TIMEOUT_MS).toBeGreaterThan(auditLogWorstCaseSettleMs);
    // The OLD (wrong) derivation was 2x AUDIT_WRITE_LOCK_TIMEOUT_MS = 10_000,
    // which is LESS than the audit log's real worst case (35_000 with
    // today's defaults) — pin that the corrected value is not a
    // coincidental pass but is actually anchored to both source constants.
    expect(ON_EVICT_AUDIT_TIMEOUT_MS).toBe(
      AUDIT_WRITE_LOCK_TIMEOUT_MS + DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS + 5_000,
    );
  });
});
