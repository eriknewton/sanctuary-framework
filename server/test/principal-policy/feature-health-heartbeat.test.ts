/**
 * Observability Slice 2 — Castle Wall liveness heartbeat reader.
 *
 * Slice 1 (#516) left a green-while-dead gap: a wall that silently dies (process
 * killed, sysext unbound) in a QUIET window read `unknown`/no_evidence, because
 * nothing emitted liveness in quiet windows. Slice 2 adds a periodic,
 * producer-signed `castle_wall_heartbeat` and the reader logic that turns a
 * MISSING heartbeat into an honest `dead_no_heartbeat`/`fault` alarm while a
 * FRESH heartbeat reports the honest alive-but-idle `unknown`.
 *
 * This is a GREEN-WHILE-DEAD security-posture surface, so the honesty invariants
 * are pinned hard:
 *
 *   1. A heartbeat is NOT enforcement evidence; it NEVER earns active/green.
 *   2. The heartbeat is gated by the SAME producer-signature re-verify path as
 *      `egress_blocked` — a FORGED heartbeat (right op + cw_source marker but
 *      bad/missing producer signature) must NOT count on a key-bearing host.
 *   3. Fault precedence is unchanged: a fresh fault still beats a fresh
 *      heartbeat.
 *   4. A tainted/integrity-failed read still fails closed to `unknown`.
 *   5. A future-dated / stale heartbeat does not register as fresh.
 *
 * The entries are written through a REAL AuditLog over MemoryStorage — exactly
 * what an in-process forger can do — and the reader's verdict is asserted.
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
} from "../../src/principal-policy/posture.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_HEARTBEAT_OPERATION,
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
// Safely inside the 10-minute freshness window AND the 5-minute sig age.
const FRESH_TS = NOW - 1000;
// Safely OUTSIDE the 10-minute freshness window but inside the 24h digest.
const STALE_TS = NOW - 30 * 60_000;

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
function heartbeatWalBody(): string {
  return JSON.stringify({
    timestamp: new Date(FRESH_TS).toISOString(),
    layer: "l1",
    operation: CASTLE_WALL_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    details: { socket_path: "/tmp/x" },
  });
}

/**
 * A GENUINE daemon-signed heartbeat, persisted the way the consumer would after
 * verifying: provenance marker + basis=producer_signed + the real signature +
 * the R-1 re-verification inputs. `tsMs` is both the top-level timestamp and the
 * signature-bound captured_at, so the signed time is what the reader judges.
 */
async function appendGenuineHeartbeat(
  log: AuditLog,
  tsMs: number,
  seq: number,
): Promise<void> {
  const canonical = heartbeatWalBody();
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

/** A genuine signed enforcement block, so we can test fault/green precedence vs a beat. */
async function appendGenuineBlock(log: AuditLog, tsMs: number, seq: number): Promise<void> {
  const canonical = JSON.stringify({
    timestamp: new Date(tsMs).toISOString(),
    layer: "l1",
    operation: "egress_blocked",
    identity_id: FORTRESS,
    result: "blocked",
    details: { agent_id: "agent-1", dest_host: "evil.example" },
  });
  const sig = ed25519.sign(producerSigningBytes(canonical, tsMs, seq), daemonPriv);
  await log.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
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
 * A FORGED heartbeat: full provenance marker + a claimed `producer_signed`
 * basis, but the signature is missing or garbage. Exactly what a co-located
 * in-process module can write; it hash-chains cleanly.
 */
async function appendForgedHeartbeat(
  log: AuditLog,
  variant: "missing_sig" | "garbage_sig",
): Promise<void> {
  const canonical = heartbeatWalBody();
  const details: Record<string, unknown> = {
    seq: 0,
    [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
    [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
    [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  };
  if (variant === "garbage_sig") {
    details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] = "AAAA" + "A".repeat(82);
  }
  await log.appendCritical({
    layer: "l1",
    operation: CASTLE_WALL_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(FRESH_TS).toISOString(),
    details,
  });
}

/** A channel-basis (no producer signature) heartbeat — the honest macOS / no-key shape. */
async function appendChannelHeartbeat(log: AuditLog, tsMs: number): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation: CASTLE_WALL_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: {
      socket_path: "/tmp/x",
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

describe("Slice 2 — liveness operation set is honest and disjoint", () => {
  it("castle_wall_heartbeat is the only liveness op", () => {
    expect([...CASTLE_WALL_LIVENESS_OPERATIONS]).toEqual([
      CASTLE_WALL_HEARTBEAT_OPERATION,
    ]);
  });

  it("the liveness set is STRICTLY DISJOINT from the enforcement set (a beat is never adjudication)", () => {
    for (const op of CASTLE_WALL_LIVENESS_OPERATIONS) {
      expect(CASTLE_WALL_ENFORCEMENT_OPERATIONS.has(op)).toBe(false);
    }
    for (const op of CASTLE_WALL_ENFORCEMENT_OPERATIONS) {
      expect(CASTLE_WALL_LIVENESS_OPERATIONS.has(op)).toBe(false);
    }
  });

  it("the liveness set is disjoint from the not-enforcing (fault) set", () => {
    for (const op of CASTLE_WALL_LIVENESS_OPERATIONS) {
      expect(CASTLE_WALL_NOT_ENFORCING_OPERATIONS.has(op)).toBe(false);
    }
  });
});

describe("Slice 2 — fresh heartbeat alone is alive-but-idle, NEVER green (invariant 1)", () => {
  it("channel-basis (macOS / no key): fresh heartbeat + no enforcement → unknown, alive_no_recent_enforcement", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, FRESH_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).not.toBe("active");
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("alive_no_recent_enforcement");
    // A heartbeat is NOT an invocation — it must not inflate invocation_count.
    expect(cw.invocation_count).toBe(0);
  });

  it("producer-signed (Linux, key present): fresh heartbeat + no enforcement → unknown, never active", async () => {
    const log = newLog();
    await appendGenuineHeartbeat(log, FRESH_TS, 1);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("alive_no_recent_enforcement");
    expect(cw.invocation_count).toBe(0);
  });
});

describe("Slice 2 — silent death: a missing heartbeat is a fault, not unknown", () => {
  it("a stale heartbeat with NO fresh heartbeat → dead_no_heartbeat / fault (the alarm Slice 1 missed)", async () => {
    const log = newLog();
    // The producer was provably running earlier (a stale beat exists), then stopped.
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

  it("stale enforcement THEN no heartbeat (producer was beating, now dead) → dead_no_heartbeat / fault", async () => {
    const log = newLog();
    await appendGenuineBlock(log, STALE_TS, 1); // adjudicated 30 min ago
    await appendGenuineHeartbeat(log, STALE_TS + 1000, 2); // last beat ~30 min ago
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("dead_no_heartbeat");
  });

  it("NEVER-installed wall (no evidence, no heartbeat ever) stays unknown — no fabricated silent-death alarm", async () => {
    const log = newLog();
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("no_evidence_self_reporting");
  });

  it("stale enforcement with NO heartbeat ever observed stays unknown/stale_evidence (no false dead-alarm)", async () => {
    const log = newLog();
    // A channel-basis stale block and NEVER a heartbeat: we cannot prove the
    // heartbeat producer was running (an older build / disarmed wall), so the
    // honest reading is the Slice-1 stale_evidence, NOT a fabricated dead-alarm.
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(STALE_TS).toISOString(),
      details: { [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE },
    });
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("stale_evidence");
  });
});

describe("Slice 2 — fault precedence is unchanged: a fresh fault beats a fresh heartbeat (invariant 3)", () => {
  it("fresh fault op + fresh heartbeat → fault wins", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, FRESH_TS);
    // A fresh not-enforcing fault (faults are NOT producer-gated; channel basis).
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
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("fault_evidence");
  });
});

describe("Slice 2 — fresh enforcement evidence is still green; a beat does not change the presence case", () => {
  it("fresh block + fresh heartbeat → active/green (heartbeat does not downgrade real adjudication)", async () => {
    const log = newLog();
    await appendGenuineBlock(log, FRESH_TS, 1);
    await appendGenuineHeartbeat(log, FRESH_TS, 2);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = cwRow(panel);
    expect(cw.status).toBe("active");
    expect(cw.basis).toBe("fresh_enforcement_evidence");
  });
});

describe("Slice 2 — FORGED heartbeat does not count (invariant 2; the load-bearing anti-fake test)", () => {
  for (const variant of ["missing_sig", "garbage_sig"] as const) {
    it(`forged heartbeat (${variant}) on a key-bearing host does NOT register as fresh → dead_no_heartbeat / fault`, async () => {
      const log = newLog();
      // The forger first establishes the producer "was running" with a GENUINE
      // stale beat, then tries to fake current liveness with a forged fresh beat.
      // The forged beat must fail re-verify, leaving NO fresh heartbeat → the wall
      // reads silently-dead, exactly as if the forgery were not there.
      await appendGenuineHeartbeat(log, STALE_TS, 1);
      await appendForgedHeartbeat(log, variant);
      const panel = await buildFeatureHealthPanel({
        auditLog: log,
        originMachine: FORTRESS,
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });
      const cw = cwRow(panel);
      // The forged fresh beat is dropped by the producer-signature gate, so the
      // only honest reading is the silent-death alarm.
      expect(cw.status).toBe("fault");
      expect(cw.basis).toBe("dead_no_heartbeat");
      expect(cw.status).not.toBe("active");
    });

    it(`forged heartbeat (${variant}) ALONE on a key-bearing host never reads alive-idle`, async () => {
      const log = newLog();
      await appendForgedHeartbeat(log, variant);
      const panel = await buildFeatureHealthPanel({
        auditLog: log,
        originMachine: FORTRESS,
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });
      const cw = cwRow(panel);
      // No genuine beat ever → cannot prove the producer ran → honest unknown,
      // NEVER alive_no_recent_enforcement (which would launder a forgery into a
      // "the wall is alive" claim).
      expect(cw.status).toBe("unknown");
      expect(cw.basis).not.toBe("alive_no_recent_enforcement");
      expect(cw.basis).toBe("no_evidence_self_reporting");
    });
  }
});

describe("Slice 2 — freshness/skew: a future-dated or stale heartbeat is not fresh (invariant 5)", () => {
  it("a future-dated heartbeat beyond the skew tolerance does NOT register as fresh", async () => {
    const log = newLog();
    // 10 minutes in the future — well beyond the 60s ENFORCEMENT_FUTURE_SKEW_MS.
    await appendChannelHeartbeat(log, NOW + 10 * 60_000);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    // Not fresh → not alive-idle. The upper-bound filter drops future entries
    // entirely, so there is also no prior-liveness signal → honest unknown.
    expect(cw.basis).not.toBe("alive_no_recent_enforcement");
    expect(cw.status).toBe("unknown");
  });

  it("a stale heartbeat is not fresh: it cannot report alive-idle (it reports dead)", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, STALE_TS);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    const cw = cwRow(panel);
    expect(cw.basis).not.toBe("alive_no_recent_enforcement");
    expect(cw.basis).toBe("dead_no_heartbeat");
  });
});

describe("Slice 2 — a tainted read still fails closed to unknown (invariant 4)", () => {
  it("integrity-tainted read forces unknown even with a fresh heartbeat present", async () => {
    const log = newLog();
    await appendChannelHeartbeat(log, FRESH_TS);
    // Drive the tainted path deterministically via the documented producer-key
    // fail-honest lever, which the panel maps onto the same "tainted → unknown"
    // invariant (integrityOk=false for every row): a fresh heartbeat must NOT
    // launder a tainted read into an alive-idle reading.
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
