import { describe, expect, it } from "vitest";

import type { MasterWriteBarrierLease } from "../../src/storage/cross-process-lock.js";
import { releaseCustodyLeases } from "./custody-lease.js";

function fakeLease(outcome: "release" | "reject"): MasterWriteBarrierLease & { calls: number } {
  const lease = {
    calls: 0,
    async release(): Promise<void> {
      lease.calls += 1;
      if (outcome === "reject") throw new Error("release refused");
    },
  };
  return lease as unknown as MasterWriteBarrierLease & { calls: number };
}

describe("releaseCustodyLeases", () => {
  it("releases every tracked lease and empties the list", async () => {
    const leases = [fakeLease("release"), fakeLease("release")];
    const tracked = [...leases];
    await releaseCustodyLeases(tracked);
    expect(tracked).toEqual([]);
    expect(leases.map((lease) => lease.calls)).toEqual([1, 1]);
  });

  it("keeps a lease whose release rejected and still releases the rest", async () => {
    const failing = fakeLease("reject");
    const after = fakeLease("release");
    const tracked = [failing, after];
    await expect(releaseCustodyLeases(tracked)).rejects.toBeInstanceOf(AggregateError);
    expect(after.calls).toBe(1);
    // The rejected lease is still owned, so a later teardown retries it
    // instead of treating its namespace as free to delete.
    expect(tracked).toEqual([failing]);
    await expect(releaseCustodyLeases(tracked)).rejects.toBeInstanceOf(AggregateError);
    expect(failing.calls).toBe(2);
  });
});
