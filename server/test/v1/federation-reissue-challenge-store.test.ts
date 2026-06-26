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
});
