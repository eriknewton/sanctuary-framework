/**
 * Slice R — read-side producer-signature RE-verification (the proof the hole is
 * closed).
 *
 * The hole: the posture readers gated the Castle Wall green light on the
 * forgeable `cw_source` provenance marker. Any in-process module holding the
 * `AuditLog` reference can `appendCritical` a marked `egress_blocked` entry; it
 * hash-chains cleanly (a NEW valid entry, not tampering) and rendered the wall
 * green. Upgrading the gate to trust the `cw_evidence_basis === producer_signed`
 * STRING (or a forged `cw_producer_sig`) closes nothing — every detail key is
 * forgeable at the append boundary.
 *
 * The close: with a pinned producer key configured, the reader cryptographically
 * RE-verifies the persisted producer signature against the pinned key. A forger
 * cannot mint a signature that verifies against the daemon's key, so a forged
 * `producer_signed` entry fails re-verification and renders NON-green.
 *
 * These tests write entries through a REAL AuditLog over MemoryStorage — i.e.
 * exactly what an in-process forger can do — and assert the reader's verdict.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  buildCastleWallPosture,
  buildAuditDigest,
} from "../../src/principal-policy/posture.js";
import { buildFeatureHealthPanel } from "../../src/principal-policy/feature-health.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../src/castle-wall/constants.js";

const FORTRESS = "fortress:test";
const NOW = 1_750_000_000_000;
// A timestamp safely inside the freshness window AND inside the 5-min sig age.
const FRESH_TS = NOW - 1000;

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const daemonPriv = ed25519.utils.randomPrivateKey();
const daemonPubB64 = toBase64url(ed25519.getPublicKey(daemonPriv));

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

/**
 * The WAL canonical body the daemon signs (the same shape the consumer's
 * `walBodyFor` produces and verifies over). Minimal but valid: layer + operation
 * are the only fields the reader binds against; the rest is opaque signed bytes.
 */
function walBody(seq: number): string {
  return JSON.stringify({
    timestamp: new Date(FRESH_TS).toISOString(),
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "agent-1",
    result: "blocked",
    details: { agent_id: "agent-1", dest_host: "evil.example" },
  });
}

/**
 * Append a GENUINE daemon-signed enforcement entry, the way the consumer
 * persists it after verifying: provenance marker + basis=producer_signed + the
 * real signature + the R-1 re-verification inputs (canonical + captured_at).
 */
async function appendGenuineSigned(log: AuditLog, seq: number): Promise<void> {
  const canonical = walBody(seq);
  const sig = ed25519.sign(producerSigningBytes(canonical, FRESH_TS, seq), daemonPriv);
  await log.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(FRESH_TS).toISOString(),
    details: {
      seq,
      agent_id: "agent-1",
      dest_host: "evil.example",
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

/**
 * Append a FORGED in-process entry: full provenance marker + a claimed
 * `producer_signed` basis, but the signature is missing/garbage/lifted. This is
 * exactly what a co-located module can write — it hash-chains cleanly. The
 * variant decides which forgery shape.
 */
async function appendForged(
  log: AuditLog,
  variant: "missing_sig" | "garbage_sig" | "wrong_canonical" | "stale",
): Promise<void> {
  const seq = 0;
  const canonical = walBody(seq);
  const realSig = toBase64url(
    ed25519.sign(producerSigningBytes(canonical, FRESH_TS, seq), daemonPriv),
  );
  const details: Record<string, unknown> = {
    seq,
    [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
    [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
    [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  };
  let ts = FRESH_TS;
  if (variant === "missing_sig") {
    // No cw_producer_sig at all — the forger just claims the basis.
  } else if (variant === "garbage_sig") {
    details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] = "AAAA" + "A".repeat(82);
  } else if (variant === "wrong_canonical") {
    // A REAL signature, but stapled over a DIFFERENT canonical body than the one
    // persisted — the signature does not verify against the persisted bytes.
    details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] = realSig;
    details[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY] = walBody(seq) + " ";
  } else if (variant === "stale") {
    // A real signature over a body, but persisted with a different captured_at
    // so the signed message no longer matches (the producer_signing_bytes bind
    // the timestamp).
    details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] = realSig;
    details[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY] = FRESH_TS - 50_000;
    ts = FRESH_TS;
  }
  await log.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(ts).toISOString(),
    details,
  });
}

/** Append a channel-authenticated (unsigned) entry, the macOS / no-key shape. */
async function appendChannelUnsigned(log: AuditLog): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(FRESH_TS).toISOString(),
    details: {
      seq: 0,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

describe("Slice R — HEADLINE NEGATIVE: a forged in-process entry never renders green", () => {
  const forgeryVariants = [
    "missing_sig",
    "garbage_sig",
    "wrong_canonical",
    "stale",
  ] as const;

  for (const variant of forgeryVariants) {
    it(`posture: forged producer_signed entry (${variant}) does NOT arm with a key configured`, async () => {
      const log = newLog();
      await appendForged(log, variant);

      const posture = await buildCastleWallPosture({
        auditLog: log,
        originMachine: FORTRESS,
        platform: "linux",
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });

      // The forgery fails re-verification → NON-green, and it does not count.
      expect(posture.arm_state).not.toBe("armed");
      expect(posture.producer_authenticity).toBe("not_applicable");
      // Forged entry also does not inflate the display verdict counts.
      expect(posture.verdict_counts.blocked).toBe(0);
    });

    it(`digest: forged producer_signed entry (${variant}) does NOT count as a kernel_block`, async () => {
      const log = newLog();
      await appendForged(log, variant);

      const digest = await buildAuditDigest({
        auditLog: log,
        originMachine: FORTRESS,
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });
      expect(digest.kernel_blocks).toBe(0);
    });

    it(`feature-health: forged producer_signed entry (${variant}) does NOT render Castle Wall active`, async () => {
      const log = newLog();
      await appendForged(log, variant);

      const panel = await buildFeatureHealthPanel({
        auditLog: log,
        originMachine: FORTRESS,
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });
      const cw = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
      expect(cw).toBeDefined();
      expect(cw!.status).not.toBe("active");
    });
  }
});

describe("Slice R — codex HIGH #1: key-bearing reader rejects channel/legacy-basis enforcement evidence", () => {
  it("posture: a channel_authenticated_unsigned egress_blocked does NOT arm when a key IS configured", async () => {
    const log = newLog();
    await appendChannelUnsigned(log);
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    // When a key is set the consumer never persists genuine enforcement evidence
    // on the channel basis, so a channel-basis enforcement entry is a forgery.
    expect(posture.arm_state).not.toBe("armed");
    expect(posture.verdict_counts.blocked).toBe(0);
  });

  it("posture: a marker-only egress_blocked (no basis) does NOT arm when a key IS configured", async () => {
    const log = newLog();
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(),
      details: { seq: 0, [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE },
    });
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(posture.arm_state).not.toBe("armed");
  });

  it("digest: a channel-basis egress_blocked does NOT count as a kernel_block with a key configured", async () => {
    const log = newLog();
    await appendChannelUnsigned(log);
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(0);
  });

  it("feature-health: a channel-basis invocation does NOT render active with a key configured", async () => {
    const log = newLog();
    await appendChannelUnsigned(log);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
    expect(cw!.status).not.toBe("active");
  });
});

describe("Slice R — codex HIGH #2: policy_loaded cannot arm without re-verification when a key is set", () => {
  it("a marker-only policy_loaded does NOT arm posture when a key IS configured", async () => {
    const log = newLog();
    await log.appendCritical({
      layer: "l1",
      operation: "policy_loaded",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(),
      details: { seq: 0, [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE },
    });
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    // policy_loaded is not signed enforcement evidence; with a key configured it
    // is treated as channel/forged basis and cannot arm.
    expect(posture.arm_state).not.toBe("armed");
  });

  it("a marker-only policy_loaded STILL arms when NO key is configured (legacy / macOS floor preserved)", async () => {
    const log = newLog();
    await log.appendCritical({
      layer: "l1",
      operation: "policy_loaded",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(),
      details: { seq: 0, [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE },
    });
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "macos",
      now: NOW,
      pinnedProducerKeyB64url: null,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("channel_authenticated");
  });
});

describe("Slice R — codex HIGH #3: same-seq replay with a forged-fresh top-level timestamp does NOT arm", () => {
  it("an old signed tuple copied into a fresh-timestamped audit entry is rejected by freshness-of-signed-time", async () => {
    const log = newLog();
    // Build a GENUINELY signed tuple over an OLD captured time (well outside the
    // freshness window), then persist it into an audit entry whose TOP-LEVEL
    // timestamp is forged fresh. The signature still verifies (same seq, same
    // canonical, same captured_at), but freshness is judged from the signed time.
    const OLD_TS = NOW - 60 * 60 * 1000; // 1h ago
    const canonical = JSON.stringify({
      timestamp: new Date(OLD_TS).toISOString(),
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "agent-1",
      result: "blocked",
      details: { agent_id: "agent-1" },
    });
    const sig = ed25519.sign(producerSigningBytes(canonical, OLD_TS, 0), daemonPriv);
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: FORTRESS,
      result: "success",
      // Forged-fresh top-level timestamp (an in-process replayer's lever).
      timestamp: new Date(FRESH_TS).toISOString(),
      details: {
        seq: 0,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        // The signed captured-at is the OLD time (bound into the signature).
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: OLD_TS,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    // The signature verifies, but the signed time is stale → not armed.
    expect(posture.arm_state).toBe("unknown");
    expect(posture.evidence_basis).toBe("stale_evidence");
  });
});

describe("Slice R — codex re-review HIGH: digest kernel counts bind to the signature, not the entry", () => {
  it("a same-seq replay of an OLD signed tuple into a fresh entry does NOT inflate kernel_blocks", async () => {
    const log = newLog();
    const OLD_TS = NOW - 48 * 60 * 60 * 1000; // 2 days ago, outside the 24h digest window
    const canonical = JSON.stringify({
      timestamp: new Date(OLD_TS).toISOString(),
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "agent-1",
      result: "blocked",
      details: { agent_id: "agent-1" },
    });
    const sig = ed25519.sign(producerSigningBytes(canonical, OLD_TS, 0), daemonPriv);
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(), // forged-fresh top-level ts
      details: {
        seq: 0,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: OLD_TS,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    // The signature verifies, but the signed capture time is outside the digest
    // window → the replay does not inflate the kernel-block count.
    expect(digest.kernel_blocks).toBe(0);
  });

  it("a signed 'allow' tuple stapled onto an 'egress_blocked' entry does NOT inflate posture verdict_counts.blocked", async () => {
    const log = newLog();
    const allowCanonical = JSON.stringify({
      timestamp: new Date(FRESH_TS).toISOString(),
      layer: "l1",
      operation: "egress_approved",
      identity_id: "agent-1",
      result: "success",
      details: { agent_id: "agent-1" },
    });
    const sig = ed25519.sign(producerSigningBytes(allowCanonical, FRESH_TS, 0), daemonPriv);
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked", // stapled onto the wrong slot
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(),
      details: {
        seq: 0,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: allowCanonical,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    // The display count is bound to the SIGNED operation (an allow), so the
    // stapled "block" entry does not inflate verdict_counts.blocked. It counts
    // as the allow it actually was.
    expect(posture.verdict_counts.blocked).toBe(0);
    expect(posture.verdict_counts.allowed).toBe(1);
  });

  it("a stale producer-signed replay does NOT inflate posture verdict_counts", async () => {
    const log = newLog();
    const OLD_TS = NOW - 48 * 60 * 60 * 1000; // outside the 24h digest window
    const canonical = JSON.stringify({
      timestamp: new Date(OLD_TS).toISOString(),
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "agent-1",
      result: "blocked",
      details: { agent_id: "agent-1" },
    });
    const sig = ed25519.sign(producerSigningBytes(canonical, OLD_TS, 0), daemonPriv);
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(),
      details: {
        seq: 0,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: OLD_TS,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(posture.verdict_counts.blocked).toBe(0);
    expect(posture.arm_state).not.toBe("armed");
  });

  it("a signed 'allow' tuple stapled onto an 'egress_blocked' entry does NOT count as a kernel_block", async () => {
    const log = newLog();
    // Genuinely sign an egress_APPROVED (allow) WAL body, then file it under an
    // egress_blocked audit entry. The signature verifies, but the signed
    // operation (egress_approved → egress_allowed) does not map to the entry's
    // egress_blocked, so it must not count as a block.
    const allowCanonical = JSON.stringify({
      timestamp: new Date(FRESH_TS).toISOString(),
      layer: "l1",
      operation: "egress_approved",
      identity_id: "agent-1",
      result: "success",
      details: { agent_id: "agent-1" },
    });
    const sig = ed25519.sign(producerSigningBytes(allowCanonical, FRESH_TS, 0), daemonPriv);
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked", // stapled onto the WRONG operation slot
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(),
      details: {
        seq: 0,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: allowCanonical,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(0);
    // It also must not be mis-counted as an allow (it was filed as a block).
    expect(digest.kernel_allows).toBe(0);
  });
});

describe("Slice R — codex round-4 HIGH: a duplicated fresh signed tuple counts at most once", () => {
  // Append the SAME genuine signed tuple (same seq + signature) N times — what a
  // copy-replay attacker does. Each copy re-verifies, but must be deduped.
  async function appendDuplicateSigned(log: AuditLog, copies: number): Promise<void> {
    const canonical = walBody(0);
    const sig = toBase64url(
      ed25519.sign(producerSigningBytes(canonical, FRESH_TS, 0), daemonPriv),
    );
    for (let i = 0; i < copies; i++) {
      await log.appendCritical({
        layer: "l1",
        operation: "egress_blocked",
        identity_id: FORTRESS,
        result: "success",
        // distinct top-level timestamps, but identical signed tuple
        timestamp: new Date(FRESH_TS + i).toISOString(),
        details: {
          seq: 0,
          [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: sig,
          [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
          [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
          [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
          [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
          [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
        },
      });
    }
  }

  it("posture verdict_counts.blocked counts the duplicated tuple once", async () => {
    const log = newLog();
    await appendDuplicateSigned(log, 5);
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(posture.verdict_counts.blocked).toBe(1);
    expect(posture.arm_state).toBe("armed"); // the genuine event still arms
  });

  it("digest kernel_blocks counts the duplicated tuple once", async () => {
    const log = newLog();
    await appendDuplicateSigned(log, 5);
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(1);
  });

  it("feature-health invocation_count counts the duplicated tuple once", async () => {
    const log = newLog();
    await appendDuplicateSigned(log, 5);
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
    expect(cw!.status).toBe("active");
    expect(cw!.invocation_count).toBe(1);
  });

  it("TWO DISTINCT signed events (different seq) both count — dedup does not over-collapse", async () => {
    const log = newLog();
    await appendGenuineSigned(log, 0);
    await appendGenuineSigned(log, 1);
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(2);
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(posture.verdict_counts.blocked).toBe(2);
  });
});

describe("Slice R — POSITIVE: a genuine daemon-signed entry re-verifies and renders green", () => {
  it("posture: genuine signed entry arms with producer_signed authenticity", async () => {
    const log = newLog();
    await appendGenuineSigned(log, 0);

    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("producer_signed");
    expect(posture.verdict_counts.blocked).toBe(1);
  });

  it("digest: genuine signed entry counts as a kernel_block", async () => {
    const log = newLog();
    await appendGenuineSigned(log, 0);

    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(1);
  });

  it("feature-health: genuine signed entry renders Castle Wall active", async () => {
    const log = newLog();
    await appendGenuineSigned(log, 0);

    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
    expect(cw!.status).toBe("active");
  });

  it("a genuine signed-but-STALE entry re-verifies but is NOT armed (freshness gate intact)", async () => {
    const log = newLog();
    // Sign over an OLD timestamp (consistent canonical/captured_at, so the sig
    // re-verifies), but the entry is well past the 10-min freshness window.
    const OLD_TS = NOW - 60 * 60 * 1000; // 1h ago
    const canonical = JSON.stringify({
      timestamp: new Date(OLD_TS).toISOString(),
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "agent-1",
      result: "blocked",
      details: { agent_id: "agent-1" },
    });
    const sig = ed25519.sign(producerSigningBytes(canonical, OLD_TS, 0), daemonPriv);
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(OLD_TS).toISOString(),
      details: {
        seq: 0,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: OLD_TS,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });

    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    // A validly-signed but stale entry past the freshness floor does not arm.
    expect(posture.arm_state).toBe("unknown");
    expect(posture.evidence_basis).toBe("stale_evidence");
    expect(posture.producer_authenticity).toBe("not_applicable");
  });

  it("a genuine signed entry is REJECTED when the WRONG pinned key is configured", async () => {
    const log = newLog();
    await appendGenuineSigned(log, 0);
    const wrongKey = toBase64url(
      ed25519.getPublicKey(ed25519.utils.randomPrivateKey()),
    );
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: wrongKey,
    });
    // The signature does not verify against the wrong key → non-green.
    expect(posture.arm_state).not.toBe("armed");
  });
});

describe("Slice R — FALLBACK (macOS parity): no pinned key → honest channel basis", () => {
  it("posture: channel-unsigned entry arms but is labeled channel_authenticated, never producer_signed", async () => {
    const log = newLog();
    await appendChannelUnsigned(log);

    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "macos",
      now: NOW,
      pinnedProducerKeyB64url: null,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("channel_authenticated");
  });

  it("posture: a producer_signed-claiming entry with NO key falls to channel basis (cannot verify, must not crash or default-green-as-authenticated)", async () => {
    const log = newLog();
    // Even a GENUINELY signed entry: with no key the reader cannot check it, so
    // it must label the green as channel-authenticated, never producer_signed.
    await appendGenuineSigned(log, 0);

    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "macos",
      now: NOW,
      pinnedProducerKeyB64url: null,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("channel_authenticated");
  });

  it("unknown-never-green still holds: no evidence at all → unknown, not_applicable", async () => {
    const log = newLog();
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "macos",
      now: NOW,
      pinnedProducerKeyB64url: null,
    });
    expect(posture.arm_state).toBe("unknown");
    expect(posture.producer_authenticity).toBe("not_applicable");
  });

  it("a forged producer_signed entry, with NO key, falls to channel basis (cannot be checked) — the honest no-key floor", async () => {
    const log = newLog();
    await appendForged(log, "missing_sig");
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "macos",
      now: NOW,
      pinnedProducerKeyB64url: null,
    });
    // No key → cannot verify → channel basis. This is the documented macOS cap:
    // the no-key reader is no stronger than the channel today. The KEY-BEARING
    // reader (HEADLINE NEGATIVE above) is what closes the hole.
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("channel_authenticated");
  });
});
