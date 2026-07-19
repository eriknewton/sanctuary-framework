/**
 * Observability Slice 2 — false-RED fix: a clean stop / arm-lease revoke is
 * distinguished from a silent death.
 *
 * The merged Slice 2 silent-death alarm (#656) fired `dead_no_heartbeat`/red
 * whenever a wall that was once provably alive went quiet with no fresh
 * heartbeat. But a CLEAN operator stop and an arm-lease revoke produce exactly
 * that heartbeat-then-silent pattern, so a DELIBERATELY-stopped wall read a
 * false red "silently died" alarm for the whole 24h digest window.
 *
 * This file pins the fix:
 *   - the producer now records an INTENTIONAL stand-down marker (`filter_stopped`
 *     with the `cw_source` marker, or `arm_lease_revoked`);
 *   - the reader, BEFORE firing `dead_no_heartbeat`, checks whether the
 *     most-recent lifecycle signal is a stand-down. If so it relabels to an
 *     honest non-fault `intentionally_stopped` (`unknown`, off on purpose) —
 *     never red, never green.
 *
 * Honesty invariants pinned hard (this is a GREEN-WHILE-DEAD / false-RED
 * security-posture surface):
 *   1. A genuine silent death (heartbeat stopped, NO subsequent stand-down) MUST
 *      still fire `dead_no_heartbeat`/fault — the alarm is not over-suppressed.
 *   2. The suppression NEVER renders green; it can only relabel red -> `unknown`.
 *   3. The stand-down rests on the SAME trust basis as the heartbeat
 *      (channel-basis, `livenessEntryCounts`-gated). A FORGED `producer_signed`-
 *      claiming stand-down with a bad signature must NOT suppress a real alarm on
 *      a key-bearing host (mirrors the forged-heartbeat test).
 *   4. A stand-down OLDER than the most-recent heartbeat does NOT suppress (the
 *      daemon came back, beat, then died for real).
 *
 * Entries are written through a REAL AuditLog over MemoryStorage — exactly what
 * an in-process forger can do — and the reader's verdict is asserted. There are
 * NO temp paths (the storage is in-memory).
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  buildFeatureHealthPanel,
  type FeatureHealthRow,
} from "../../src/principal-policy/feature-health.js";
import {
  CASTLE_WALL_ENFORCEMENT_OPERATIONS,
  CASTLE_WALL_LIVENESS_OPERATIONS,
  CASTLE_WALL_NOT_ENFORCING_OPERATIONS,
  CASTLE_WALL_STAND_DOWN_OPERATIONS,
} from "../../src/principal-policy/posture.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_HEARTBEAT_OPERATION,
  CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../src/castle-wall/constants.js";

const FORTRESS = "fortress:test";
const NOW = 1_750_000_000_000;
// Safely OUTSIDE the 10-minute freshness window but inside the 24h digest.
const STALE_TS = NOW - 30 * 60_000;
// A second, even older stale timestamp (still inside the 24h digest).
const OLDER_TS = NOW - 60 * 60_000;

function toB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const daemonPriv = ed25519.utils.randomPrivateKey();
const daemonPubB64 = toB64url(ed25519.getPublicKey(daemonPriv));

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

function cwRow(panel: { rows: FeatureHealthRow[] }): FeatureHealthRow {
  const r = panel.rows.find((x) => x.feature_id === "castle_wall_egress");
  if (!r) throw new Error("no castle_wall_egress row");
  return r;
}

/** The signed WAL body for a heartbeat (operation === castle_wall_heartbeat). */
function heartbeatWalBody(tsMs: number): string {
  return JSON.stringify({
    timestamp: new Date(tsMs).toISOString(),
    layer: "l1",
    operation: CASTLE_WALL_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    details: { socket_path: "/tmp/x" },
  });
}

/** A GENUINE daemon-signed heartbeat, persisted the way the consumer would. */
async function appendGenuineHeartbeat(
  log: AuditLog,
  tsMs: number,
  seq: number,
): Promise<void> {
  const canonical = heartbeatWalBody(tsMs);
  const sig = ed25519.sign(producerSigningBytes(canonical, tsMs, seq), daemonPriv);
  await log.appendCritical({
    layer: "l1",
    operation: CASTLE_WALL_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: {
      seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toB64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: tsMs,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

/**
 * A channel-basis (no producer signature) heartbeat — the SHAPE THE REAL
 * PRODUCER EMITS on every host (`macos-daemon.ts:emitAuditHeartbeat`).
 */
async function appendChannelHeartbeat(log: AuditLog, tsMs: number): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation: CASTLE_WALL_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: {
      socket_path: "/tmp/x",
      daemon_mode: "local-sign",
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

async function appendCW(
  log: AuditLog,
  operation: string,
  tsMs: number,
): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: {
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

/**
 * A GENUINE intentional stand-down, the SHAPE THE REAL PRODUCER EMITS: a direct
 * channel-basis append carrying the `cw_source` marker and NO producer
 * signature. `op` is either `filter_stopped` (clean operator stop) or
 * `arm_lease_revoked` (lease revoke).
 */
async function appendChannelStandDown(
  log: AuditLog,
  op: string,
  tsMs: number,
): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation: op,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: {
      socket_path: "/tmp/x",
      source: "sanctuary-wrap",
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

/**
 * A FORGED stand-down: the right op + `cw_source` marker + a CLAIMED
 * `producer_signed` basis, but the signature is missing/garbage. Exactly what a
 * co-located in-process module could write to try to MUTE a real silent-death
 * alarm on a key-bearing host.
 */
async function appendForgedSignedStandDown(
  log: AuditLog,
  op: string,
  tsMs: number,
  variant: "missing_sig" | "garbage_sig",
): Promise<void> {
  const canonical = JSON.stringify({
    timestamp: new Date(tsMs).toISOString(),
    layer: "l1",
    operation: op,
    identity_id: FORTRESS,
    result: "success",
    details: { socket_path: "/tmp/x" },
  });
  const details: Record<string, unknown> = {
    seq: 0,
    [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
    [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: tsMs,
    [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  };
  if (variant === "garbage_sig") {
    details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] = "AAAA" + "A".repeat(82);
  }
  await log.appendCritical({
    layer: "l1",
    operation: op,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details,
  });
}

describe("Slice 2 false-RED fix — stand-down op set is honest and disjoint", () => {
  it("the stand-down set is filter_stopped + arm_lease_revoked + wall_disarmed", () => {
    expect([...CASTLE_WALL_STAND_DOWN_OPERATIONS].sort()).toEqual(
      ["arm_lease_revoked", "filter_stopped", "wall_disarmed"].sort(),
    );
    expect(CASTLE_WALL_STAND_DOWN_OPERATIONS.has(CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION)).toBe(
      true,
    );
  });

  it("the stand-down set is STRICTLY DISJOINT from enforcement, liveness, and fault sets", () => {
    for (const op of CASTLE_WALL_STAND_DOWN_OPERATIONS) {
      expect(CASTLE_WALL_ENFORCEMENT_OPERATIONS.has(op)).toBe(false);
      expect(CASTLE_WALL_LIVENESS_OPERATIONS.has(op)).toBe(false);
      expect(CASTLE_WALL_NOT_ENFORCING_OPERATIONS.has(op)).toBe(false);
    }
  });
});

describe("B2 false-green fix — newer stand-down beats older fresh enforcement", () => {
  for (const op of [
    "filter_stopped",
    "wall_disarmed",
    CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
  ] as const) {
    it(`${op} after egress_allowed demotes active to intentionally_stopped`, async () => {
      const log = newLog();
      await appendChannelHeartbeat(log, NOW - 5 * 60_000);
      await appendCW(log, "egress_allowed", NOW - 4 * 60_000);
      await appendChannelStandDown(log, op, NOW - 60_000);
      const panel = await buildFeatureHealthPanel({
        auditLog: log,
        originMachine: FORTRESS,
        now: NOW,
      });
      const cw = cwRow(panel);
      expect(cw.status).toBe("unknown");
      expect(cw.basis).toBe("intentionally_stopped");
      expect(cw.status).not.toBe("active");
    });
  }

  it("a previously-seen heartbeat producer with no fresh heartbeat demotes stale-instance green", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, NOW - 20 * 60_000);
    await appendCW(log, "egress_allowed", NOW - 9 * 60_000);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("daemon_liveness_unconfirmed");
  });
});

describe("Slice 2 false-RED fix — a clean stop is intentionally_stopped, NOT dead_no_heartbeat", () => {
  it("channel-basis (macOS / no key): stale heartbeat THEN filter_stopped → intentionally_stopped / unknown, not red", async () => {
    const log = newLog();
    // The producer was provably running (a stale beat), then the operator
    // stopped it cleanly. Without the fix this read dead_no_heartbeat/red.
    await appendChannelHeartbeat(log, OLDER_TS);
    await appendChannelStandDown(log, "filter_stopped", STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("intentionally_stopped");
    expect(cw.status).not.toBe("fault");
    expect(cw.status).not.toBe("active");
  });

  it("key-bearing (Linux): stale heartbeat THEN filter_stopped → intentionally_stopped, the alarm is suppressed honestly", async () => {
    const log = newLog();
    await appendGenuineHeartbeat(log, OLDER_TS, 1);
    await appendChannelStandDown(log, "filter_stopped", STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("intentionally_stopped");
  });
});

describe("Slice 2 false-RED fix — an arm-lease revoke is intentionally_stopped, NOT dead_no_heartbeat", () => {
  it("stale heartbeat THEN arm_lease_revoked → intentionally_stopped / unknown, not red", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, OLDER_TS);
    await appendChannelStandDown(log, CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION, STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("intentionally_stopped");
  });

  it("key-bearing: stale signed heartbeat THEN arm_lease_revoked → intentionally_stopped", async () => {
    const log = newLog();
    await appendGenuineHeartbeat(log, OLDER_TS, 1);
    await appendChannelStandDown(log, CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION, STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("intentionally_stopped");
  });
});

describe("Slice 2 false-RED fix — a GENUINE silent death STILL fires the alarm (no over-suppression)", () => {
  it("stale heartbeat with NO stand-down signal → STILL dead_no_heartbeat / fault", async () => {
    const log = newLog();
    // The daemon beat, then was KILLED (no stand-down marker recorded).
    await appendChannelHeartbeat(log, STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("dead_no_heartbeat");
  });

  it("a stand-down THEN a LATER heartbeat (daemon came back and beat, then died) → STILL dead_no_heartbeat", async () => {
    const log = newLog();
    // Stood down at OLDER_TS, then the daemon restarted and beat at STALE_TS, then
    // died for real (no further stand-down). The last lifecycle signal is the
    // heartbeat, so the alarm MUST fire — the stale stand-down must NOT mute it.
    await appendChannelStandDown(log, "filter_stopped", OLDER_TS);
    await appendChannelHeartbeat(log, STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("dead_no_heartbeat");
    expect(cw.basis).not.toBe("intentionally_stopped");
  });
});

describe("Slice 2 false-RED fix — a FORGED stand-down cannot mute a real alarm on a key-bearing host (invariant 3)", () => {
  for (const op of ["filter_stopped", CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION] as const) {
    for (const variant of ["missing_sig", "garbage_sig"] as const) {
      it(`forged producer_signed ${op} (${variant}) does NOT suppress the silent-death alarm on a key-bearing host`, async () => {
        const log = newLog();
        // The producer was provably running (genuine stale beat), then died for
        // real. A forger drops a FORGED producer_signed-claiming stand-down to
        // try to relabel the red alarm. The forged stand-down fails re-verify, so
        // it does NOT count, and the alarm still fires.
        await appendGenuineHeartbeat(log, STALE_TS, 1);
        await appendForgedSignedStandDown(log, op, NOW - 1000, variant);
        const panel = await buildFeatureHealthPanel({
          auditLog: log,
          originMachine: FORTRESS,
          now: NOW,
          pinnedProducerKeyB64url: daemonPubB64,
        });
        const cw = cwRow(panel);
        expect(cw.status).toBe("fault");
        expect(cw.basis).toBe("dead_no_heartbeat");
        expect(cw.basis).not.toBe("intentionally_stopped");
        expect(cw.status).not.toBe("active");
      });
    }
  }
});

describe("Slice 2 false-RED fix — a signed heartbeat RELABELED as a stand-down cannot mute the alarm (operation binding)", () => {
  for (const op of ["filter_stopped", CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION] as const) {
    it(`a genuine signed heartbeat re-appended as ${op} does NOT suppress the silent-death alarm on a key-bearing host`, async () => {
      const log = newLog();
      // The producer was provably running (genuine stale beat), then died for
      // real. A forger takes a GENUINE daemon-signed heartbeat and relabels its
      // TOP-LEVEL op to a stand-down to try to mute the red alarm. The signature
      // re-verifies, but the signed body attests to `castle_wall_heartbeat`, not
      // the stand-down op, so the operation-binding check drops it.
      await appendGenuineHeartbeat(log, STALE_TS, 1);
      // A genuine heartbeat body, signed, but re-appended under a stand-down op.
      const canonical = heartbeatWalBody(NOW - 1000);
      const sig = ed25519.sign(
        producerSigningBytes(canonical, NOW - 1000, 2),
        daemonPriv,
      );
      await log.appendCritical({
        layer: "l1",
        operation: op, // FORGED top-level op: claims a stand-down.
        identity_id: FORTRESS,
        result: "success",
        timestamp: new Date(NOW - 1000).toISOString(),
        details: {
          seq: 2,
          [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toB64url(sig),
          [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
          [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
          [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: NOW - 1000,
          [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
          [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
        },
      });
      const panel = await buildFeatureHealthPanel({
        auditLog: log,
        originMachine: FORTRESS,
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });
      const cw = cwRow(panel);
      expect(cw.status).toBe("fault");
      expect(cw.basis).toBe("dead_no_heartbeat");
      expect(cw.basis).not.toBe("intentionally_stopped");
    });
  }
});

describe("Slice 2 false-RED fix — suppression NEVER manufactures green (invariant 2)", () => {
  it("a stand-down alongside a fresh fault still reads fault (fault precedence unchanged)", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, OLDER_TS);
    await appendChannelStandDown(log, "filter_stopped", STALE_TS);
    // A fresh not-enforcing fault (channel basis; faults are never producer-gated).
    await log.appendCritical({
      layer: "l1",
      operation: "provider_unbound",
      identity_id: FORTRESS,
      result: "failure",
      timestamp: new Date(NOW - 60_000).toISOString(),
      details: {},
    });
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    // Fault precedence: a fresh fault still wins over an intentional stand-down.
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("fault_evidence");
  });

  it("the stand-down disclosure flag is set and the silent-death flag stays false", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, OLDER_TS);
    await appendChannelStandDown(log, "filter_stopped", STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    expect(panel.disclosure.silent_death_distinguished_from_intentional_stop).toBe(true);
    expect(panel.disclosure.castle_wall_silent_death_is_unknown_not_green).toBe(false);
  });
});

describe("Slice 2 false-RED fix — a tainted read still fails closed to unknown (invariant 4)", () => {
  it("integrity-tainted read forces unknown even with a stand-down present", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, OLDER_TS);
    await appendChannelStandDown(log, "filter_stopped", STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: null,
      producerKeyExpectedButUnavailable: true,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("integrity_tainted");
  });
});

describe("Slice 2 false-RED fix — a stand-down WITHOUT prior liveness does not fabricate a reading", () => {
  it("a stand-down but NO heartbeat ever (and no enforcement) → honest no_evidence, not intentionally_stopped", async () => {
    const log = newLog();
    // A stand-down marker exists, but the heartbeat producer was never observed
    // running, so we cannot prove the daemon was alive. We never fabricate a
    // silent-death alarm here, and equally we do not claim an intentional stop of
    // a wall we never saw run.
    await appendChannelStandDown(log, "filter_stopped", STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.status).not.toBe("fault");
    expect(cw.basis).toBe("no_evidence_self_reporting");
  });
});
