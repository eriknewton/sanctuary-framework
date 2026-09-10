/**
 * A legacy fortress -- one built before `castle_wall_provision` existed, the
 * exact shape a 1.8.4 or 1.8.6-rc.1 install left on disk -- opens normally
 * under this code, and no consumer reads its silence as `walled`.
 *
 * Capability bound this pins (server/docs/fortress-lifecycle.md, the Castle
 * Wall pin provisioning section): a fortress with no `castle-wall-provision-v1`
 * record reads `absent`, never `walled` and never the current `not_yet_walled`
 * claim. `absent` and `not_yet_walled` are BOTH not-proven (AGENTS.md rule 1);
 * the one place they render differently is `doctor`'s machine-level line,
 * because `doctor` is the one surface that also observes the host's own
 * extension state and has to say which of the two silences it is looking at.
 *
 * The fixture is a REAL fortress from a real `sanctuary init` run, with its
 * `castle-wall-provision-v1` record deleted afterward. A hand-built directory
 * holding only a policy file is not evidence that an upgraded 1.8.4 vault
 * still opens; a fortress `init` itself created, and can itself still read
 * back, is.
 *
 * Isolation: a per-test temp directory; nothing here reads or writes a real
 * `~/.sanctuary`, the operator's login keychain, or the real machine-wide
 * anchor.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { runInit } from "../../src/wrap/init.js";
import {
  castleWallProvisionRecordPath,
  readPersistedCastleWallProvision,
} from "../../src/castle-wall/provision-state.js";
import { runDoctorChecks } from "../../src/cli/doctor.js";
import { runStatus } from "../../src/cli/castle-wall.js";
import {
  getProtectionSnapshot,
  type AggregatorSources,
} from "../../src/dashboard/aggregator.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

/** A sink for CLI output a test does not assert on. */
const silent = (): Writable =>
  new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });

/** Collect a CLI writable's output. */
function capture(chunks: string[]): Writable {
  return new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk.toString());
      callback();
    },
  });
}

describe("a legacy fortress with no castle-wall-provision record", () => {
  let tmp: string;
  let fortressPath: string;
  const passphrase = "legacy-fortress-fixture-passphrase";

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-legacy-fortress-"));
    fortressPath = join(tmp, "vault");
    const priorPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.SANCTUARY_PASSPHRASE = passphrase;
    try {
      // A real init run: identity, principal policy, audit chain, this
      // fortress's own Castle key pair, and (as of this fix round) the
      // `not_yet_walled` claim -- exactly as a real install leaves them.
      await runInit({ fortress: fortressPath, noConfirm: true });
    } finally {
      if (priorPassphrase === undefined) delete process.env.SANCTUARY_PASSPHRASE;
      else process.env.SANCTUARY_PASSPHRASE = priorPassphrase;
    }
    // Remove exactly the one record a 1.8.4 / 1.8.6-rc.1 fortress never
    // wrote. Everything else this run created stays, so the fixture is a
    // real, openable fortress that merely predates the field -- not an empty
    // directory standing in for one.
    await rm(castleWallProvisionRecordPath(fortressPath), { force: true });
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("reads as absent, never as walled and never as the current not_yet_walled claim", async () => {
    expect(await readPersistedCastleWallProvision(fortressPath)).toEqual({ state: "absent" });
  });

  it("opens: doctor reports the fortress itself healthy, only the wall claim is silent", async () => {
    const checks = await runDoctorChecks({
      storagePath: fortressPath,
      env: { SANCTUARY_PASSPHRASE: passphrase },
      platform: "darwin",
      execSyncFn: () =>
        "ai.sanctuaryprotocol.macos.castle-wall (1.0/42)\tCastle Wall\t[activated enabled]",
    });
    // The fortress itself opens and is healthy: deleting one additive _meta
    // record does not touch identity, policy, audit, or state -- that is the
    // "opens" property a hand-built fixture with no identity or audit chain
    // could not have demonstrated.
    for (const name of ["state dir", "identity", "principal policy"]) {
      const check = checks.find((c) => c.name === name);
      expect(check, name).toBeDefined();
      expect(check!.status, name).toBe("OK");
    }
    // Audit chain is non-FAIL, not strictly OK: a fresh fortress with no
    // production checkpoint signer configured legitimately WARNs
    // ("no checkpoint signature was verified"), independent of anything this
    // fixture does to the wall claim.
    const audit = checks.find((c) => c.name === "audit chain");
    expect(audit).toBeDefined();
    expect(audit!.status).not.toBe("FAIL");
    // The wall claim is honestly silent: doctor can report ONLY the
    // machine's extension state, and it says so rather than reading a
    // leftover activated extension as this vault's own protection -- the
    // machine-level line this fix round added to the OK case.
    const wall = checks.find((c) => c.name === "castle wall sysext")!;
    expect(wall.status).toBe("OK");
    expect(wall.message).toContain("[activated enabled]");
    expect(wall.message).toContain("machine-level");
    expect(wall.message).toContain("no vault-level protection is asserted");
    // Never the words that describe the CURRENT claim states: this fortress
    // predates the field, it does not carry either of them.
    expect(wall.message).not.toContain("not_yet_walled");
    expect(wall.message).not.toContain("walled)");
  });

  it("castle-wall status prints nothing that reads as a wall claim", async () => {
    const chunks: string[] = [];
    await runStatus([], {
      out: capture(chunks),
      err: silent(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "linux",
    });
    const text = chunks.join("");
    expect(text).not.toContain("Vault wall provisioning: walled");
    expect(text).not.toContain("Vault wall provisioning: not_yet_walled");
    expect(text).not.toContain("Vault wall provisioning:");
  });

  // NOTE (release/1.8.6 branch): "the health snapshot and evidence surface
  // carry no vault claim" is intentionally dropped from this cherry-pick. It
  // exercises castleWallSnapshotForHealthReport in
  // server/src/health/castle-wall-detector.ts, a module introduced by the
  // Linux Castle Wall reconstruction (#1398), which this release branch does
  // not carry (base 913fa8b9 predates it).

  it("the dashboard protection snapshot never marks it walled", async () => {
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const sources = {
      mode: "co-located",
      server_version: "test",
      auditLog,
      platform: "darwin",
      // The exact resolver `principal-policy/dashboard.ts` wires in
      // production (`resolveVaultProvisionClaimed`): collapse to `false` on
      // anything but the current, persisted `not_yet_walled` claim.
      resolveVaultProvisionClaimed: async () =>
        (await readPersistedCastleWallProvision(fortressPath)).state === "not-yet-walled",
    } as AggregatorSources;
    const snapshot = await getProtectionSnapshot(sources);
    expect(snapshot).not.toHaveProperty("castle_wall_provision");
  });
});
