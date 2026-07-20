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

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  buildCastleWallPosture,
  buildAuditDigest,
} from "../../src/principal-policy/posture.js";
import { buildFeatureHealthPanel } from "../../src/principal-policy/feature-health.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
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
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
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
const signedIdentitySubjectBindingDetails = {
  [CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]:
    CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
} as const;

function auditTokenForRuid(uid: number): string {
  const vals = [
    0xffffffff,
    uid,
    uid,
    uid,
    uid,
    0x00000269,
    0x000186ae,
    0x00000566,
  ];
  return vals
    .map((value) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
      return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    })
    .join("");
}

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

type SignedWalOperation =
  | "egress_blocked"
  | "egress_approved"
  | "egress_pending";
type PersistedEnforcementOperation =
  | "egress_blocked"
  | "egress_allowed"
  | "operator_decision";

function signedWalResult(operation: SignedWalOperation): string {
  if (operation === "egress_blocked") return "blocked";
  if (operation === "egress_pending") return "pending";
  return "success";
}

/**
 * The WAL canonical body the daemon signs (the same shape the consumer's
 * `walBodyFor` produces and verifies over). Minimal but valid: layer + operation
 * are the only fields the reader binds against; the rest is opaque signed bytes.
 */
function walBody(
  seq: number,
  identityId: string = FORTRESS,
  operation: SignedWalOperation = "egress_blocked",
): string {
  return JSON.stringify({
    timestamp: new Date(FRESH_TS).toISOString(),
    layer: "l1",
    operation,
    identity_id: identityId,
    result: signedWalResult(operation),
    details: { agent_id: identityId, dest_host: "evil.example" },
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
      agent_id: FORTRESS,
      dest_host: "evil.example",
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      ...signedIdentitySubjectBindingDetails,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

async function appendRelabeledSigned(
  log: AuditLog,
  input: {
    seq: number;
    signedIdentityId: string;
    persistedIdentityId: string;
    signedOperation?: SignedWalOperation;
    persistedOperation?: PersistedEnforcementOperation;
  },
): Promise<void> {
  const signedOperation = input.signedOperation ?? "egress_blocked";
  const persistedOperation = input.persistedOperation ?? "egress_blocked";
  const canonical = walBody(
    input.seq,
    input.signedIdentityId,
    signedOperation,
  );
  const sig = ed25519.sign(
    producerSigningBytes(canonical, FRESH_TS, input.seq),
    daemonPriv,
  );
  await log.appendCritical({
    layer: "l1",
    operation: persistedOperation,
    identity_id: input.persistedIdentityId,
    result: "success",
    timestamp: new Date(FRESH_TS).toISOString(),
    details: {
      seq: input.seq,
      agent_id: input.signedIdentityId,
      dest_host: "evil.example",
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      ...signedIdentitySubjectBindingDetails,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

async function appendMacOSSignedAuditToken(
  log: AuditLog,
  input: {
    seq: number;
    signedAuditToken: string;
    persistedIdentityId: string;
  },
): Promise<void> {
  const canonical = JSON.stringify({
    timestamp: new Date(FRESH_TS).toISOString(),
    layer: "l1",
    operation: "egress_blocked",
    result: "blocked",
    details: { agent_id: input.signedAuditToken, dest_host: "evil.example" },
  });
  const sig = ed25519.sign(
    producerSigningBytes(canonical, FRESH_TS, input.seq),
    daemonPriv,
  );
  await log.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: input.persistedIdentityId,
    result: "success",
    timestamp: new Date(FRESH_TS).toISOString(),
    details: {
      seq: input.seq,
      agent_id: input.signedAuditToken,
      dest_host: "evil.example",
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

async function appendSignedWithoutSubject(
  log: AuditLog,
  input: {
    seq: number;
    persistedIdentityId: string;
    signedOperation?: SignedWalOperation;
    persistedOperation?: PersistedEnforcementOperation;
  },
): Promise<void> {
  const signedOperation = input.signedOperation ?? "egress_blocked";
  const persistedOperation = input.persistedOperation ?? "egress_blocked";
  const canonical = JSON.stringify({
    timestamp: new Date(FRESH_TS).toISOString(),
    layer: "l1",
    operation: signedOperation,
    result: signedWalResult(signedOperation),
    details: { dest_host: "evil.example" },
  });
  const sig = ed25519.sign(
    producerSigningBytes(canonical, FRESH_TS, input.seq),
    daemonPriv,
  );
  await log.appendCritical({
    layer: "l1",
    operation: persistedOperation,
    identity_id: input.persistedIdentityId,
    result: "success",
    timestamp: new Date(FRESH_TS).toISOString(),
    details: {
      seq: input.seq,
      dest_host: "evil.example",
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      ...signedIdentitySubjectBindingDetails,
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
    ...signedIdentitySubjectBindingDetails,
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
        protectionClaimSubject: FORTRESS,
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
        protectionClaimSubject: FORTRESS,
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });
      expect(digest.kernel_blocks).toBe(0);
    });

    it(`feature-health: forged producer_signed entry (${variant}) does NOT render Castle Wall active`, async () => {
      const log = newLog();
      await appendForged(log, variant);

      const panel = await buildFeatureHealthPanel({
        protectionClaimSubject: FORTRESS,
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

describe("Slice R — read-side subject binding rejects producer-signed relabels", () => {
  it("posture refuses a uid-504 signed tuple persisted under uid-503", async () => {
    const log = newLog();
    const victim = `${FORTRESS}/uid-503`;
    const signedSubject = `${FORTRESS}/uid-504`;
    await appendRelabeledSigned(log, {
      seq: 0,
      signedIdentityId: signedSubject,
      persistedIdentityId: victim,
    });

    const posture = await buildCastleWallPosture({
      protectionClaimSubject: victim,
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });

    expect(posture.arm_state).toBe("unknown");
    expect(posture.evidence_basis).toBe("subject_unbound_evidence");
    expect(posture.producer_authenticity).toBe("not_applicable");
  });

  it("feature-health refuses a uid-504 signed tuple persisted under uid-503", async () => {
    const log = newLog();
    const victim = `${FORTRESS}/uid-503`;
    const signedSubject = `${FORTRESS}/uid-504`;
    await appendRelabeledSigned(log, {
      seq: 0,
      signedIdentityId: signedSubject,
      persistedIdentityId: victim,
    });

    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: victim,
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const cw = panel.rows.find((r) => r.feature_id === "castle_wall_egress");

    expect(cw).toBeDefined();
    expect(cw!.status).toBe("unknown");
    expect(cw!.basis).toBe("subject_unbound_evidence");
  });

  const relabeledDigestCases = [
    {
      name: "egress_blocked",
      signedOperation: "egress_blocked",
      persistedOperation: "egress_blocked",
      kernelBlocks: 1,
      kernelAllows: 0,
    },
    {
      name: "egress_allowed",
      signedOperation: "egress_approved",
      persistedOperation: "egress_allowed",
      kernelBlocks: 0,
      kernelAllows: 1,
    },
    {
      name: "operator_decision from signed egress_pending",
      signedOperation: "egress_pending",
      persistedOperation: "operator_decision",
      kernelBlocks: 0,
      kernelAllows: 0,
    },
  ] as const;

  for (const relabelCase of relabeledDigestCases) {
    it(`digest attributes a relabeled producer-signed ${relabelCase.name} tuple to the signed subject, not the row label`, async () => {
      const log = newLog();
      const rowLabel = `${FORTRESS}/uid-503`;
      const signedSubject = `${FORTRESS}/uid-504`;
      await appendRelabeledSigned(log, {
        seq: 0,
        signedIdentityId: signedSubject,
        persistedIdentityId: rowLabel,
        signedOperation: relabelCase.signedOperation,
        persistedOperation: relabelCase.persistedOperation,
      });

      const digest = await buildAuditDigest({
        auditLog: log,
        originMachine: FORTRESS,
        protectionClaimSubject: FORTRESS,
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });

      expect(digest.total_operations).toBe(1);
      expect(digest.kernel_blocks).toBe(relabelCase.kernelBlocks);
      expect(digest.kernel_allows).toBe(relabelCase.kernelAllows);
      expect(digest.by_agent).toEqual([
        { identity_id: signedSubject, operations: 1 },
      ]);
      expect(digest.by_agent).not.toContainEqual({
        identity_id: rowLabel,
        operations: 1,
      });
    });
  }

  it("digest and posture join on the storage-path fortress subject for macOS signed audit-token evidence", async () => {
    const log = newLog();
    const storagePath = "/var/sanctuary/fortress-alpha";
    const subjectFortressId = fortressIdFromStoragePath(storagePath);
    const signedAuditToken = auditTokenForRuid(503);
    const postureSubject = `${subjectFortressId}/uid-503`;
    const originMachine = `fortress:${storagePath}`;
    await appendMacOSSignedAuditToken(log, {
      seq: 0,
      signedAuditToken,
      persistedIdentityId: postureSubject,
    });

    const posture = await buildCastleWallPosture({
      protectionClaimSubject: postureSubject,
      auditLog: log,
      originMachine,
      platform: "macos",
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine,
      protectionClaimSubject: postureSubject,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });

    expect(posture.arm_state).toBe("armed");
    expect(digest.by_agent).toEqual([
      { identity_id: postureSubject, operations: 1 },
    ]);
  });

  it("digest omits producer-signed attribution when the signed operation does not bind to the enforcement row", async () => {
    const log = newLog();
    await appendRelabeledSigned(log, {
      seq: 0,
      signedIdentityId: `${FORTRESS}/uid-504`,
      persistedIdentityId: `${FORTRESS}/uid-503`,
      signedOperation: "egress_blocked",
      persistedOperation: "operator_decision",
    });

    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      protectionClaimSubject: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });

    expect(digest.total_operations).toBe(1);
    expect(digest.by_agent).toEqual([]);
  });

  const missingSubjectDigestCases = [
    {
      name: "egress_blocked",
      signedOperation: "egress_blocked",
      persistedOperation: "egress_blocked",
    },
    {
      name: "egress_allowed",
      signedOperation: "egress_approved",
      persistedOperation: "egress_allowed",
    },
    {
      name: "operator_decision from signed egress_pending",
      signedOperation: "egress_pending",
      persistedOperation: "operator_decision",
    },
  ] as const;

  for (const missingSubjectCase of missingSubjectDigestCases) {
    it(`digest omits key-bearing producer-signed ${missingSubjectCase.name} attribution when no signed subject can be derived`, async () => {
      const log = newLog();
      await appendSignedWithoutSubject(log, {
        seq: 0,
        persistedIdentityId: `${FORTRESS}/uid-503`,
        signedOperation: missingSubjectCase.signedOperation,
        persistedOperation: missingSubjectCase.persistedOperation,
      });

      const digest = await buildAuditDigest({
        auditLog: log,
        originMachine: FORTRESS,
        protectionClaimSubject: FORTRESS,
        now: NOW,
        pinnedProducerKeyB64url: daemonPubB64,
      });

      expect(digest.total_operations).toBe(1);
      expect(digest.by_agent).toEqual([]);
    });
  }
});

describe("Slice R — codex HIGH #1: key-bearing reader rejects channel/legacy-basis enforcement evidence", () => {
  it("posture: a channel_authenticated_unsigned egress_blocked does NOT arm when a key IS configured", async () => {
    const log = newLog();
    await appendChannelUnsigned(log);
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(0);
  });

  it("feature-health: a channel-basis invocation does NOT render active with a key configured", async () => {
    const log = newLog();
    await appendChannelUnsigned(log);
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
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

  it("a marker-only policy_loaded does NOT arm even when NO key is configured (no-key floor raised by the arm-set honesty narrowing)", async () => {
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
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      platform: "macos",
      now: NOW,
      pinnedProducerKeyB64url: null,
    });
    // UPDATED by the arm-set honesty narrowing: policy_loaded attests
    // manifest-acceptance, not live adjudication, so it is no longer arm-eligible
    // on ANY basis. A wall that only loaded a policy now reads unknown (amber),
    // never armed. This intentionally raises the prior no-key / macOS channel
    // floor (which armed on a manifest-load alone); posture and feature-health
    // now share one live-adjudication set so the banner cannot over-claim green.
    expect(posture.arm_state).not.toBe("armed");
    expect(posture.producer_authenticity).toBe("not_applicable");
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
      identity_id: FORTRESS,
      result: "blocked",
      details: { agent_id: FORTRESS },
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
        ...signedIdentitySubjectBindingDetails,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
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
      identity_id: FORTRESS,
      result: "blocked",
      details: { agent_id: FORTRESS },
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
        ...signedIdentitySubjectBindingDetails,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      protectionClaimSubject: FORTRESS,
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
      identity_id: FORTRESS,
      result: "success",
      details: { agent_id: FORTRESS },
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
        ...signedIdentitySubjectBindingDetails,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
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
      identity_id: FORTRESS,
      result: "blocked",
      details: { agent_id: FORTRESS },
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
        ...signedIdentitySubjectBindingDetails,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
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
      identity_id: FORTRESS,
      result: "success",
      details: { agent_id: FORTRESS },
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
        ...signedIdentitySubjectBindingDetails,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      protectionClaimSubject: FORTRESS,
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
          ...signedIdentitySubjectBindingDetails,
          [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
        },
      });
    }
  }

  it("posture verdict_counts.blocked counts the duplicated tuple once", async () => {
    const log = newLog();
    await appendDuplicateSigned(log, 5);
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(1);
  });

  it("feature-health invocation_count counts the duplicated tuple once", async () => {
    const log = newLog();
    await appendDuplicateSigned(log, 5);
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(2);
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
      now: NOW,
      pinnedProducerKeyB64url: daemonPubB64,
    });
    expect(digest.kernel_blocks).toBe(1);
  });

  it("feature-health: genuine signed entry renders Castle Wall active", async () => {
    const log = newLog();
    await appendGenuineSigned(log, 0);

    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
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
      identity_id: FORTRESS,
      result: "blocked",
      details: { agent_id: FORTRESS },
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
        ...signedIdentitySubjectBindingDetails,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });

    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
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
      protectionClaimSubject: FORTRESS,
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
