/**
 * Monotonic counter store (lifecycle orchestrator).
 *
 * Counters MUST strictly advance across process restarts. A counter that resets
 * is indistinguishable from a rolled-back node (§8.3). Production wires a
 * disk-backed implementation (deferred to a follow-up thread alongside the
 * per-node key store); tests use the in-memory implementation here.
 */

import type { CounterName, CounterStore } from "./types.js";

export class InMemoryCounterStore implements CounterStore {
  private values = new Map<CounterName, number>();

  next(name: CounterName): number {
    const current = this.values.get(name) ?? 0;
    this.values.set(name, current + 1);
    return current;
  }

  peek(name: CounterName): number {
    return this.values.get(name) ?? 0;
  }

  set(name: CounterName, value: number): void {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(
        `CounterStore.set: value must be non-negative integer; got ${value}`
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
