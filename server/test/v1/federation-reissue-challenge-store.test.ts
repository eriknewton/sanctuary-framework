/** Durable anti-replay store for federation node-cert reissue challenges. */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { MemoryStorage } from "../../src/storage/memory.js";
import { FederationReissueChallengeStore } from "../../src/v1/federation-reissue-challenge-store.js";

describe("FederationReissueChallengeStore", () => {
  it("consumes a challenge once and rehydrates the spent marker after restart", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const store = FederationReissueChallengeStore.durableFromBoot(storage, masterKey);
    const issued = store.issue({ fortressId: "fortress-1", nodeId: "node-1", nowMs: 1_000 });

    await expect(
      store.consume({
        fortressId: "fortress-1",
        nodeId: "node-1",
        challengeId: issued.challenge_id,
        challenge: issued.challenge,
        nowMs: 1_001,
      }),
    ).resolves.toBe(true);
    await expect(
      store.consume({
        fortressId: "fortress-1",
        nodeId: "node-1",
        challengeId: issued.challenge_id,
        challenge: issued.challenge,
        nowMs: 1_002,
      }),
    ).resolves.toBe(false);

    const restarted = FederationReissueChallengeStore.durableFromBoot(
      storage,
      masterKey,
    );
    await restarted.init(1_003);
    expect(
      restarted.isSpent("fortress-1", "node-1", issued.challenge_id, 1_003),
    ).toBe(true);
  });

  // LD3 FED-REISSUE-DOS-01 corroboration: the pending map's only cap used to
  // be the global 1024 ceiling, so a flood of distinct (attacker-chosen,
  // cost-free) node_ids from ONE origin could grow it unbounded up to that
  // ceiling, and — combined across origins — exhaust it entirely and refuse
  // legitimate joiners. A per-origin cap bounds any single origin's own
  // contribution well under the global ceiling.
  it("bounds pending challenges PER ORIGIN, independent of the global cap", () => {
    const store = new FederationReissueChallengeStore();
    // Same origin, distinct node_ids (the cost-free attacker knob): the 65th
    // issue from this ONE origin must fail well before the 1024 global cap.
    for (let i = 0; i < 64; i++) {
      store.issue({ fortressId: "f", nodeId: `attacker-node-${i}`, originKey: "10.0.0.1", nowMs: 1_000 });
    }
    expect(() =>
      store.issue({ fortressId: "f", nodeId: "attacker-node-64", originKey: "10.0.0.1", nowMs: 1_000 }),
    ).toThrow(/too many pending federation reissue challenges/);

    // A DIFFERENT origin is unaffected: the cap is per-origin, not global-only.
    expect(() =>
      store.issue({ fortressId: "f", nodeId: "legit-node", originKey: "10.0.0.2", nowMs: 1_000 }),
    ).not.toThrow();
  });

  it("frees the per-origin slot when a pending challenge is consumed or expires", async () => {
    const store = new FederationReissueChallengeStore();
    const first = store.issue({
      fortressId: "f",
      nodeId: "node-1",
      originKey: "10.0.0.1",
      nowMs: 1_000,
    });
    // Consuming the ONLY pending entry for this origin frees its slot: a
    // fresh issue for the same origin must not be refused as "still pending".
    await store.consume({
      fortressId: "f",
      nodeId: "node-1",
      challengeId: first.challenge_id,
      challenge: first.challenge,
      nowMs: 1_001,
    });
    expect(() =>
      store.issue({ fortressId: "f", nodeId: "node-2", originKey: "10.0.0.1", nowMs: 1_002 }),
    ).not.toThrow();

    // Expiry (prune) frees the slot too, without an explicit consume.
    const ttlMs = 60_000; // FEDERATION_REISSUE_CHALLENGE_TTL_MS
    for (let i = 0; i < 64; i++) {
      store.issue({
        fortressId: "f",
        nodeId: `node-expiring-${i}`,
        originKey: "10.0.0.3",
        nowMs: 2_000,
      });
    }
    expect(() =>
      store.issue({ fortressId: "f", nodeId: "node-over-cap", originKey: "10.0.0.3", nowMs: 2_001 }),
    ).toThrow(/too many pending federation reissue challenges/);
    // Past the TTL, the next issue's prune() clears the expired entries first.
    expect(() =>
      store.issue({
        fortressId: "f",
        nodeId: "node-after-expiry",
        originKey: "10.0.0.3",
        nowMs: 2_000 + ttlMs + 1,
      }),
    ).not.toThrow();
  });
});
