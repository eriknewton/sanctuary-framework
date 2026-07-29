/**
 * Wrap dashboard fleet-roster provider - REAL disk-backed presenter.
 *
 * These exercise `buildWrapFleetRosterProvider` against a REAL at-rest fortress
 * (a `MemoryStorage` with a real custody master), NOT a fabricated in-test
 * roster. They pin the guarantee that closed finding #1: the wrap ("Protect")
 * dashboard's fleet panel reads the REAL federation projection, so a provisioned
 * fleet is visible and an unprovisioned fortress is honestly absent.
 *
 *   1. NO federation provisioned -> honest `absentFleetRoster()` (the one absent
 *      shape; never a fabricated roster, never a greyed-green "all admitted"
 *      shell).
 *   2. Federation PROVISIONED (a real minted issuer trust root) -> `available:
 *      true` with THIS fortress's real fortress_id / node_id, read straight off
 *      the at-rest trust root. The live node roster is not durable and the wrap
 *      process runs no sync loop, so `nodes` is honestly empty (the panel shows
 *      "no other machines yet"), never a fabricated node.
 *   3. The provider is a REAL closure over disk: a fortress that gets provisioned
 *      AFTER the provider is built flips from absent to available on the next
 *      call (lazy per-request resolution, no restart), and carries no key
 *      material on the wire.
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { MemoryStorage } from "../../src/storage/memory.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  provisionOrLoadFederationTrustRoot,
  FEDERATION_TRUST_ROOT_NAMESPACE,
} from "../../src/mesh/federation-trust-root-store.js";
import { FEDERATION_ROTATE_ROOT_JOURNAL_KEY } from "../../src/mesh/federation-rotate-root.js";
import {
  FEDERATION_SYNC_STATE_STORE_NAMESPACE,
  FEDERATION_SYNC_STATE_STORE_KEY,
} from "../../src/v1/federation-sync-state-store.js";
import {
  OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
  OPERATOR_CLOUD_JOINED_NODE_KEY,
} from "../../src/mesh/operator-cloud-joined-node-store.js";
import {
  buildWrapFleetRosterProvider,
  readOnlyFederationDeps,
  type WrapFederationReadState,
} from "../../src/wrap/fleet-roster-provider.js";
import { absentFleetRoster } from "../../src/principal-policy/fleet-roster.js";

async function testMasterKey(storage: MemoryStorage): Promise<Uint8Array> {
  const { masterKey } = await establishMaster({
    storage,
    passphrase: `wrap-fleet-${randomBytes(6).toString("hex")}`,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  return masterKey;
}

/**
 * A deterministic, order-independent snapshot of EVERY byte in a MemoryStorage,
 * so a test can assert a read mutated nothing. Keyed by `${namespace} ${key}`
 * -> lowercase hex of the stored bytes. Order-independent because we compare the
 * whole map, not a serialized sequence.
 */
async function snapshotStorageBytes(
  storage: MemoryStorage,
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const namespace of await storage.listNamespaces()) {
    for (const entry of await storage.list(namespace)) {
      const raw = await storage.read(namespace, entry.key);
      out.set(
        `${namespace} ${entry.key}`,
        raw === null ? " absent" : Buffer.from(raw).toString("hex"),
      );
    }
  }
  return out;
}

describe("buildWrapFleetRosterProvider - real disk-backed fleet roster", () => {
  it("serves the honest absent roster when federation is NOT provisioned", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    const provider = buildWrapFleetRosterProvider({ storage, masterKey });
    const roster = await provider();

    // Byte-identical to the single honest-absence source of truth: a fortress
    // with no federation root has no fleet. Never fabricated, never green.
    expect(roster).toEqual(absentFleetRoster());
    expect(roster.available).toBe(false);
    expect(roster.enabled).toBe(false);
    expect(roster.nodes).toEqual([]);
  });

  it("serves the REAL provisioned roster when a federation trust root exists", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    // Mint a REAL issuer trust root on disk (the actual production primitive),
    // then read it back through the provider - no fabricated in-test roster.
    const minted = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "home-mac",
    });
    expect(minted?.source).toBe("minted");
    const fortressId = minted!.record.pinned_master_pubkey.fortress_id;

    const provider = buildWrapFleetRosterProvider({ storage, masterKey });
    const roster = await provider();

    // Provisioned: available, with THIS fortress's real ids read off the at-rest
    // trust root (not invented by the test).
    expect(roster.available).toBe(true);
    expect(roster.fortress_id).toBe(fortressId);
    expect(roster.node_id).toBe("home-mac");
    // Honest empty node list: the live roster is not durable and this process
    // runs no sync loop. Never a fabricated node, never a fake-green summary.
    expect(roster.nodes).toEqual([]);
    expect(roster.summary).toEqual({
      total: 0,
      admitted: 0,
      revoked: 0,
      untrusted: 0,
    });
    // Enabled is the LIVE operator switch, which a read-only wrap process cannot
    // observe: honestly OFF, never claimed on from absence.
    expect(roster.enabled).toBe(false);
    // The distribution rail is available for a provisioned fleet, with an
    // all-zero rollup over zero nodes (unknown is never silently in-sync).
    expect(roster.policy_distribution.available).toBe(true);
    expect(roster.policy_distribution.summary).toEqual({
      in_sync: 0,
      drifted: 0,
      unknown: 0,
    });
  });

  it("is a REAL closure over disk: flips absent -> available after provisioning, carries no key material", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    const provider = buildWrapFleetRosterProvider({ storage, masterKey });

    // Before provisioning: absent.
    expect((await provider()).available).toBe(false);

    // Provision after the provider was built.
    await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "home-mac",
    });

    // Same provider, next call: now available (lazy per-request read, no restart).
    const after = await provider();
    expect(after.available).toBe(true);

    // No key material ever crosses the roster shape.
    const serialized = JSON.stringify(after).toLowerCase();
    for (const forbidden of [
      "private",
      "secret",
      "privatekey",
      "private_key",
      "master_secret",
      "seed",
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });
});

/**
 * Finding #1 (HIGH) re-gate: a durable sync-state that is PRESENT-BUT-CORRUPT, or
 * a rotate-root journal mid-rotation, must fail CLOSED to the honest
 * `available: false` roster. The round-1 code returned `available: true` over a
 * corrupt sync-state (the panel read as "Fleet off / no machines" as if
 * fine-but-empty, while the trust standing was actually unreadable). The fix
 * makes ANY sync-state load failure - and the mid-rotation hold - render UNAVAILABLE.
 */
describe("buildWrapFleetRosterProvider - fail-closed on corrupt/held sync-state", () => {
  it("FAILS CLOSED to available:false when the durable sync-state is present-but-corrupt", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    // Federation IS provisioned (a real minted issuer trust root on disk), so the
    // provider WOULD build a provisioned roster - except the sync-state is corrupt.
    await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "home-mac",
    });

    // Corrupt the durable sync-state record: a non-JSON blob at the real key.
    // `FederationSyncStateStore.load()` throws `FederationSyncStateStoreError`
    // here (present-but-undecodable), which the provider must fail-close on.
    await storage.write(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
      Buffer.from("this-is-not-a-valid-encrypted-sync-state-blob", "utf8"),
    );

    const provider = buildWrapFleetRosterProvider({ storage, masterKey });
    const roster = await provider();

    // FAIL-BEFORE (round-1): this returned `available: true` (a green-looking
    // empty roster over an unreadable record). PASS-AFTER: honest UNAVAILABLE.
    expect(roster.available).toBe(false);
    // It is byte-identical to the single honest-absence source of truth: an
    // unreadable fleet is never shown green, never carries a fabricated node.
    expect(roster).toEqual(absentFleetRoster());
    expect(roster.nodes).toEqual([]);
    expect(roster.enabled).toBe(false);
  });

  it("FAILS CLOSED to available:false when a rotate-root journal is in progress", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    // Federation IS provisioned, AND a clean sync-state exists...
    await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "home-mac",
    });
    // Confirm that WITHOUT the journal this provisioned fortress serves available.
    expect(
      (await buildWrapFleetRosterProvider({ storage, masterKey })()).available,
    ).toBe(true);

    // ...but the signing master is mid-rotation: a rotate-root journal is present.
    // A half-rotated root must NEVER present as a live fleet.
    await storage.write(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_ROTATE_ROOT_JOURNAL_KEY,
      Buffer.from("rotate-root-journal-in-progress", "utf8"),
    );

    const roster = await buildWrapFleetRosterProvider({ storage, masterKey })();
    // Held off -> honest absent (fail closed), never a live-looking fleet.
    expect(roster.available).toBe(false);
    expect(roster).toEqual(absentFleetRoster());
  });

  it("FAILS CLOSED to available:false when the operator-cloud joined-node blob is present-but-corrupt", async () => {
    // Operator-cloud tier is the LAST trust-root fallback (no issuer, no joiner).
    // A present-but-undecodable operator-cloud blob means federation is
    // provisioned-shaped but its trust anchor is UNREADABLE: the provider must
    // fail closed to the honest absent shape, never propagate an uncaught throw
    // and never silently mint a replacement anchor.
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    // No issuer and no joiner trust root; only a corrupt operator-cloud blob.
    await storage.write(
      OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
      OPERATOR_CLOUD_JOINED_NODE_KEY,
      Buffer.from("this-is-not-a-valid-operator-cloud-joined-node", "utf8"),
    );

    const roster = await buildWrapFleetRosterProvider({ storage, masterKey })();
    expect(roster.available).toBe(false);
    expect(roster).toEqual(absentFleetRoster());
  });

  it("serves normally over a genuinely fresh (absent) sync-state record", async () => {
    // Guards the fix from over-firing: an ABSENT sync-state (a fresh fortress
    // that never persisted one) is NOT corrupt - it loads an empty projection
    // and serves the provisioned roster. Only a present-but-corrupt record fails.
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "home-mac",
    });
    // No sync-state record written at all -> load() returns empty, not a throw.
    const roster = await buildWrapFleetRosterProvider({ storage, masterKey })();
    expect(roster.available).toBe(true);
    expect(roster.eviction_serial).toBe(0);
  });
});

/**
 * Finding #2 (HIGH) re-gate: the read-only provider must NOT create or modify any
 * operator-cloud (or any other) at-rest record. A GET is read-only; a read
 * against an EMPTY or PARTIAL store must leave every byte on disk unchanged. The
 * provider now loads the operator-cloud tier via the store's `load()` primitive
 * directly (no `provisionOrLoad*` wrapper that could grow a mint path).
 */
describe("buildWrapFleetRosterProvider - read is strictly non-mutating", () => {
  it("does NOT create any operator-cloud record when reading an EMPTY store", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    // Empty of federation state: no trust root, no operator-cloud, no sync-state.
    const before = await snapshotStorageBytes(storage);
    expect(before.has(
      `${OPERATOR_CLOUD_JOINED_NODE_NAMESPACE} ${OPERATOR_CLOUD_JOINED_NODE_KEY}`,
    )).toBe(false);

    const roster = await buildWrapFleetRosterProvider({ storage, masterKey })();
    // Honest absent (no federation), AND nothing was written.
    expect(roster.available).toBe(false);

    const after = await snapshotStorageBytes(storage);
    // No operator-cloud record was minted by the read...
    expect(after.has(
      `${OPERATOR_CLOUD_JOINED_NODE_NAMESPACE} ${OPERATOR_CLOUD_JOINED_NODE_KEY}`,
    )).toBe(false);
    // ...and the store is byte-for-byte identical before and after the read.
    expect(after).toEqual(before);
  });

  it("does NOT mint/modify operator-cloud state when reading a PARTIAL store", async () => {
    // Partial: an issuer trust root exists (federation provisioned) but there is
    // NO operator-cloud joined-node and NO sync-state record. A read must not
    // fabricate the missing operator-cloud tier, nor touch anything on disk.
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "home-mac",
    });

    const before = await snapshotStorageBytes(storage);
    expect(before.has(
      `${OPERATOR_CLOUD_JOINED_NODE_NAMESPACE} ${OPERATOR_CLOUD_JOINED_NODE_KEY}`,
    )).toBe(false);

    // Read TWICE (lazy per-request resolution) to prove even repeated GETs are
    // pure: no lazy first-read provisioning, no write on the second either.
    await buildWrapFleetRosterProvider({ storage, masterKey })();
    await buildWrapFleetRosterProvider({ storage, masterKey })();

    const after = await snapshotStorageBytes(storage);
    expect(after.has(
      `${OPERATOR_CLOUD_JOINED_NODE_NAMESPACE} ${OPERATOR_CLOUD_JOINED_NODE_KEY}`,
    )).toBe(false);
    // Byte-unchanged: the read created nothing and modified nothing on disk.
    expect(after).toEqual(before);
  });
});

/**
 * Finding #3 (MED) re-gate: the read-only `V1FederationDeps` must be FAIL-LOUD.
 * EXACTLY the four methods the presenter calls (getContext, isEnabled, listNodes,
 * isNodeRevoked) may do real work; EVERY other method must THROW the shared
 * mustNotCall error - no silent no-op (audit, renewLocalNodeCertificate) and no
 * fabricated empty/null (rosterNodeIds, listFederationEvents, acceptedHighWaterFor,
 * resolveOperatorPublicKey, isRootRevoked) that could quietly launder a wrong roster.
 */
describe("readOnlyFederationDeps - fail-loud on every non-presenter method", () => {
  const state: WrapFederationReadState = {
    context: { fortressId: "fortress-abc", nodeId: "home-mac" },
    revokedNodeIds: new Set<string>(["revoked-node-1"]),
    evictionSerial: 3,
    operatorPolicy: null,
  };

  it("allows ONLY the four presenter reads to answer without throwing", () => {
    const deps = readOnlyFederationDeps(state);

    // The four intentionally-allowed presenter reads answer honestly.
    expect(deps.getContext()).not.toBeNull();
    expect(deps.isEnabled()).toBe(false);
    expect(deps.listNodes()).toEqual([]);
    // isNodeRevoked reads the real durable projection (never a placeholder now).
    expect(deps.isNodeRevoked("revoked-node-1")).toBe(true);
    expect(deps.isNodeRevoked("some-other-node")).toBe(false);
  });

  it("THROWS on EVERY method that is not one of the four presenter reads", () => {
    const deps = readOnlyFederationDeps(state);

    // Read-shaped-but-not-on-the-presenter-path methods: must THROW, never a
    // silent empty/null that could look like a legitimate answer.
    expect(() => deps.isRootRevoked("some-master-pubkey")).toThrow();
    expect(() => deps.resolveOperatorPublicKey()).toThrow();
    expect(() => deps.rosterNodeIds()).toThrow();
    expect(() => deps.listFederationEvents()).toThrow();
    expect(() => deps.acceptedHighWaterFor("sender")).toThrow();
    expect(() => deps.federationPosture()).toThrow();

    // Silent-no-op methods in round-1 (audit, renewLocalNodeCertificate): must
    // THROW now so a mis-wire is loud rather than swallowed.
    expect(() => deps.renewLocalNodeCertificate()).toThrow();
    expect(() => deps.audit({} as never)).toThrow();

    // Mutation / signing / sync methods: must THROW.
    expect(() => deps.setEnabled(true)).toThrow();
    expect(() => deps.recordJoin({} as never)).toThrow();
    expect(() => deps.appendFederationEvents([])).toThrow();
    expect(() => deps.recordAcceptedHighWater("sender", 1)).toThrow();
    expect(() => deps.nextOutboundHighWater()).toThrow();
    expect(() => deps.issueReissueChallenge({} as never)).toThrow();
    expect(() => deps.consumeReissueChallenge({} as never)).toThrow();
  });
});
