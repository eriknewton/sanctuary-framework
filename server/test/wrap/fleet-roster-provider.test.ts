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
import { provisionOrLoadFederationTrustRoot } from "../../src/mesh/federation-trust-root-store.js";
import { buildWrapFleetRosterProvider } from "../../src/wrap/fleet-roster-provider.js";
import { absentFleetRoster } from "../../src/principal-policy/fleet-roster.js";

async function testMasterKey(storage: MemoryStorage): Promise<Uint8Array> {
  const { masterKey } = await establishMaster({
    storage,
    passphrase: `wrap-fleet-${randomBytes(6).toString("hex")}`,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  return masterKey;
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
