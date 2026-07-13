/**
 * Castle Wall Observe / Learn Allow-List v1 -- StateStore round-trip tests.
 *
 * CI DoD test 5 (part 1): the suggestion store is readable, exportable, and
 * deletable through the standard state path; a delete removes the
 * candidates and leaves the live ruleset untouched (the live ruleset is not
 * modeled by the StateStore at all -- it is a signed on-disk manifest -- so
 * "leaves it untouched" is proven structurally here by this store never
 * importing or touching anything manifest-related; see
 * red-line-invariant.test.ts for the evaluator-side proof).
 */

import { describe, it, expect } from "vitest";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { ObserveStore } from "../../../src/castle-wall/observe/store.js";
import { OBSERVE_NAMESPACE, candidateKey, type CandidateObservation } from "../../../src/castle-wall/observe/types.js";

function candidate(overrides: Partial<CandidateObservation> = {}): CandidateObservation {
  return {
    agent_id: "agent-1",
    agent_template: "claude-code",
    host: "api.example.com",
    ip: "203.0.113.5",
    port: 443,
    protocol: "tcp",
    hostname_source: "sni",
    times_seen: 1,
    first_seen: "2026-07-07T10:00:00.000Z",
    last_seen: "2026-07-07T10:00:00.000Z",
    would_be_disposition: "denied",
    exfil_risk: false,
    ...overrides,
  };
}

function makeStore(): { store: ObserveStore; stateStore: StateStore } {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("operator", identityEncKey, "passphrase");
  const store = new ObserveStore(stateStore, {
    identityId: storedIdentity.identity_id,
    encryptedPrivateKey: storedIdentity.encrypted_private_key,
    identityEncryptionKey: identityEncKey,
  });
  return { store, stateStore };
}

describe("ObserveStore: readable / exportable / deletable (DoD test 5)", () => {
  it("round-trips the observe-mode state", async () => {
    const { store } = makeStore();
    const initial = await store.getState();
    expect(initial.enabled).toBe(false);

    await store.setState({ enabled: true, started_at: "2026-07-07T09:00:00.000Z", updated_at: "2026-07-07T09:00:00.000Z" });
    const after = await store.getState();
    expect(after).toEqual({ enabled: true, started_at: "2026-07-07T09:00:00.000Z", updated_at: "2026-07-07T09:00:00.000Z" });
  });

  it("round-trips a candidate through put/list", async () => {
    const { store } = makeStore();
    const c = candidate();
    await store.putCandidate(c);

    const listed = await store.listCandidates();
    expect(listed.size).toBe(1);
    expect(listed.get(candidateKey(c))).toEqual(c);
  });

  it("is readable through the standard StateStore read/list/export path (Invariant #2)", async () => {
    const { store, stateStore } = makeStore();
    await store.putCandidate(candidate());

    const listing = await stateStore.list(OBSERVE_NAMESPACE);
    expect(listing.keys.length).toBeGreaterThan(0);

    const exported = await stateStore.export(OBSERVE_NAMESPACE);
    expect(exported.bundle).toBeTruthy();
  });

  it("is deletable: removing a candidate leaves it absent from listCandidates", async () => {
    const { store } = makeStore();
    const c = candidate();
    await store.putCandidate(c);
    expect((await store.listCandidates()).size).toBe(1);

    await store.removeCandidate(candidateKey(c));
    expect((await store.listCandidates()).size).toBe(0);
  });

  it("deleting one candidate leaves an unrelated candidate untouched", async () => {
    const { store } = makeStore();
    const a = candidate({ host: "a.example.com" });
    const b = candidate({ host: "b.example.com" });
    await store.putCandidate(a);
    await store.putCandidate(b);

    await store.removeCandidate(candidateKey(a));

    const remaining = await store.listCandidates();
    expect(remaining.size).toBe(1);
    expect(remaining.get(candidateKey(b))).toEqual(b);
  });

  it("mergeObservations bumps an existing candidate rather than duplicating it", async () => {
    const { store } = makeStore();
    await store.putCandidate(candidate({ times_seen: 1 }));
    await store.mergeObservations([candidate({ times_seen: 2 })]);

    const listed = await store.listCandidates();
    expect(listed.size).toBe(1);
    expect([...listed.values()][0]!.times_seen).toBe(3);
  });

  it("lists candidates across more than one StateStore page (paging correctness)", async () => {
    const { store } = makeStore();
    for (let i = 0; i < 150; i++) {
      await store.putCandidate(candidate({ host: `host-${i}.example.com`, port: 443 + i }));
    }
    const listed = await store.listCandidates();
    expect(listed.size).toBe(150);
  });
});
