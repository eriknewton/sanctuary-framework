/**
 * Castle Wall wrap-banner enforcement probes (fix-round MED-4c for PR #843,
 * protection-claim chokepoint 2026-07-19).
 *
 * The wrap success banner's affirmative "protected / Castle Wall Full" hero
 * is reserved for OBSERVED enforcement, judged by the SAME
 * adjudicated-flow-evidence standard the dashboard's feature-health panel
 * uses. These tests pin the probe's gating directly against a real audit
 * log (no mocked panel):
 *
 *   - fresh adjudicated evidence (egress_allowed with the Castle Wall
 *     provenance marker) reads true;
 *   - policy loads and heartbeats never do (the honesty seam);
 *   - stale adjudicated evidence (outside the 10-minute freshness window)
 *     never does;
 *   - any probe error reads false (fail-closed), never true.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  probeCastleWallProtectionClaim,
  probeCoarseCastleWallEnforcementObserved,
} from "../../src/wrap/cli.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import type { ExclusiveEgressStatus } from "../../src/principal-policy/posture.js";

function exclusiveStatus(): ExclusiveEgressStatus {
  return {
    fine_grained_declared: true,
    exclusive_egress_live: true,
    mode: "exclusive",
    agents: [],
    reasons: [],
  };
}

function coarseOnlyStatus(): ExclusiveEgressStatus {
  return {
    fine_grained_declared: true,
    exclusive_egress_live: false,
    mode: "coarse-only",
    agents: [],
    reasons: ["uid 503: coarse-only"],
  };
}

describe("Castle Wall wrap-banner evidence probes", () => {
  let storagePath: string;
  let fortressId: string;
  let log: AuditLog;

  beforeEach(async () => {
    // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
    // No producer key file exists under it, matching a macOS fortress where
    // the panel accepts marker-gated entries without a pinned key.
    storagePath = await mkdtemp(join(tmpdir(), "sanctuary-banner-probe-"));
    fortressId = fortressIdFromStoragePath(storagePath);
    log = new AuditLog(new MemoryStorage(), generateRandomKey());
  });

  afterEach(async () => {
    try {
      await rm(storagePath, { recursive: true, force: true });
    } catch {}
  });

  /** A Castle-Wall-originated entry carrying the provenance marker. */
  async function appendCW(operation: string, ageMs: number): Promise<void> {
    await log.appendCritical({
      layer: "l1",
      operation,
      identity_id: fortressId,
      result: "success",
      details: { cw_source: "castle_wall_audit_consumer" },
      timestamp: new Date(Date.now() - ageMs).toISOString(),
    });
  }

  it("fresh adjudicated evidence (egress_allowed, inside the freshness window) reads true", async () => {
    await appendCW("egress_allowed", 60_000);
    expect(await probeCoarseCastleWallEnforcementObserved(log, storagePath)).toBe(true);
  });

  it("policy loads and heartbeats NEVER arm the banner (the honesty seam)", async () => {
    await appendCW("policy_loaded", 60_000);
    await appendCW("castle_wall_heartbeat", 60_000);
    expect(await probeCoarseCastleWallEnforcementObserved(log, storagePath)).toBe(false);
  });

  it("stale adjudicated evidence (outside the 10-minute window) reads false", async () => {
    await appendCW("egress_allowed", 30 * 60_000);
    expect(await probeCoarseCastleWallEnforcementObserved(log, storagePath)).toBe(false);
  });

  it("a probe error reads false (fail-closed), never true", async () => {
    const throwing = {
      runEagerReads: async () => {
        throw new Error("audit log unreadable");
      },
    } as unknown as AuditLog;
    expect(
      await probeCoarseCastleWallEnforcementObserved(throwing, storagePath),
    ).toBe(false);
  });

  it("protection claim renders exclusive only when the capped resolver proves exclusive-egress live", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => exclusiveStatus(),
    );
    expect(claim.state).toBe("exclusive");
  });

  it("fresh coarse evidence without exclusive live maps to coarse-only, not green", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => coarseOnlyStatus(),
    );
    expect(claim.state).toBe("coarse-only");
  });

  it("an unresolvable exclusive-egress provider maps to unknown, never green", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => {
        throw new Error("registry unreadable");
      },
    );
    expect(claim.state).toBe("unknown");
  });
});
