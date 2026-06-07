/**
 * Monotonic counter store (lifecycle orchestrator).
 *
 * Counters MUST strictly advance across process restarts. A counter that resets
 * is indistinguishable from a rolled-back node (§8.3). Production wires a
 * disk-backed implementation (deferred to a follow-up thread alongside the
 * per-node key store); tests use the in-memory implementation here.
 */

import type { CounterName, CounterStore } from "./types.js";

/**
 * Runtime allowlist of the valid counter names. Mirrors the `CounterName`
 * union in types.ts (kept in lockstep — a compile-time exhaustiveness check
 * below fails the build if the union gains a member this set omits). A
 * persisted store loaded off disk may carry an unknown/tampered key; only
 * names in this set are admitted, so a bogus key cannot silently park a value
 * while the real counters reset to 0 (§8.3).
 */
export const COUNTER_NAMES: ReadonlySet<CounterName> = new Set<CounterName>([
  "envelope_monotonic_seq",
  "heartbeat_seq",
  "audit_batch_seq",
  "locator_update_seq",
]);

// Compile-time guard: if a CounterName is added to the union but not above,
// this assignment fails to typecheck (the missing member is not assignable).
const _counterNamesExhaustive: Record<CounterName, true> = {
  envelope_monotonic_seq: true,
  heartbeat_seq: true,
  audit_batch_seq: true,
  locator_update_seq: true,
};
void _counterNamesExhaustive;

/**
 * True when advancing `current` by one would leave the safe-integer range.
 * `next()` must refuse to cross 2^53: past it, integer spacing exceeds 1 and
 * `current + 1` rounds back onto an already-issued value, collapsing two
 * distinct sequence numbers onto one — a silent rollback-canary defeat.
 */
export function wouldOverflowOnNext(current: number): boolean {
  return current >= Number.MAX_SAFE_INTEGER;
}

export class InMemoryCounterStore implements CounterStore {
  private values = new Map<CounterName, number>();

  next(name: CounterName): number {
    const current = this.values.get(name) ?? 0;
    if (wouldOverflowOnNext(current)) {
      throw new Error(
        `CounterStore.next: ${name} is at the safe-integer ceiling ` +
          `(${current}); refusing to advance — incrementing past 2^53 would ` +
          `collide two sequence values and defeat the rollback canary (§8.3).`
      );
    }
    this.values.set(name, current + 1);
    return current;
  }

  peek(name: CounterName): number {
    return this.values.get(name) ?? 0;
  }

  set(name: CounterName, value: number): void {
    // Number.isSafeInteger (not Number.isInteger): integers above 2^53 pass
    // Number.isInteger but lose precision under next()'s `current + 1`, which
    // collides two distinct sequence values onto one representable double —
    // a silent rollback-canary defeat (§8.3). Fail closed on unsafe integers.
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(
        `CounterStore.set: value must be non-negative safe integer; got ${value}`
      );
    }
    const prior = this.values.get(name) ?? 0;
    if (value < prior) {
      throw new Error(
        `CounterStore.set: refuses to lower ${name} from ${prior} to ${value} — would appear as rollback to the mesh`
      );
    }
    this.values.set(name, value);
  }
}
