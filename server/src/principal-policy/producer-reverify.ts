/**
 * Read-side producer-signature re-verification (Slice R — the core).
 *
 * # The hole this closes
 *
 * The Castle Wall posture readers (`posture.ts`, `feature-health.ts`) decide
 * whether the wall renders GREEN ("armed"/"active") from audit-log entries.
 * Before this slice, the gate was the `cw_source` provenance MARKER — a plain
 * `details` string. Any in-process module already holding the `AuditLog`
 * reference can `append("l1", "egress_blocked", ..., { cw_source: ... })`; the
 * entry hash-chains cleanly (it is a NEW valid entry, not tampering) and the
 * reader renders green. The chain does not defend against this.
 *
 * Upgrading the gate to trust `cw_evidence_basis === "producer_signed"` would
 * close NOTHING: the basis string is just as forgeable as the marker at the
 * `AuditLog.append` boundary, as are `cw_producer_sig` / `cw_producer_kid`.
 *
 * # The sound close
 *
 * The reader CRYPTOGRAPHICALLY RE-VERIFIES the persisted producer signature
 * against the daemon's pinned producer public key. A forger cannot mint a
 * signature that verifies against that key (the signing key lives only in the
 * daemon process — the in-process server holds only the public key). So a
 * forged `producer_signed` entry fails re-verification here and never counts.
 * The marker and basis string become a cheap pre-filter; the SIGNATURE is the
 * authority.
 *
 * # Honest macOS / no-key fallback (never-overclaim)
 *
 * When the reader has NO pinned key (macOS today, or Linux pre-provision), it
 * cannot re-verify. It then accepts entries on the legacy CHANNEL basis only
 * (mutually-pinned IPC + tamper-evident chain) so current behavior is
 * preserved — but the posture surface honestly reports the basis as
 * channel-authenticated, NEVER as per-producer-authenticated. macOS green must
 * never be claimed as per-event-authenticated until the extension signs.
 */

import {
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
} from "../castle-wall/constants.js";
import {
  parseCastleWallSignedCanonicalBody,
  signedCanonicalIdentityId,
} from "../castle-wall/audit-attribution.js";
import {
  BROKER_EVIDENCE_BASIS_DETAIL_KEY,
  BROKER_EVIDENCE_BASIS_PRODUCER_SIGNED,
  BROKER_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  BROKER_PRODUCER_KID_DETAIL_KEY,
  BROKER_PRODUCER_SIG_DETAIL_KEY,
  BROKER_PRODUCER_SIGNATURE_SCHEME_DETAIL_KEY,
  BROKER_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  brokerSignedCanonicalOperation,
  verifyBrokerProducerSignature,
  type BrokerProducerSignatureInput,
} from "../broker-mcp/producer-signature.js";

/**
 * The RAW `operation` string the persisted SIGNED canonical body attests to,
 * read straight from the signed bytes (NOT mapped to any read-side vocabulary).
 * Returns null on any parse failure / shape mismatch (fail closed).
 *
 * This is the authoritative operation for a `producer_signed_verified` entry:
 * the signature is over the canonical body, so the body's `operation` is what
 * the daemon actually attested to, whereas the top-level `entry.operation` is a
 * forgeable label an in-process writer chooses when it re-appends the entry. A
 * reader that counts a verified entry by `entry.operation` WITHOUT confirming it
 * matches the signed body lets a genuine signed tuple be relabeled into a
 * different slot (e.g. a signed liveness heartbeat stapled onto an `egress_blocked`
 * entry to manufacture green). Each reader maps this raw op into its own
 * vocabulary and compares to the entry op to close that staple attack.
 */
export function signedCanonicalOperation(
  details: Record<string, unknown>,
): string | null {
  const parsed = parseCastleWallSignedCanonicalBody(details);
  if (parsed === null) return null;
  const op = parsed.operation;
  return typeof op === "string" ? op : null;
}
import {
  verifyProducerSignature,
  type ProducerSignatureInput,
  type ProducerSignatureVerdict,
} from "../castle-wall/runtime/producer-signature.js";

/**
 * The injectable verify function shape — defaults to `verifyProducerSignature`
 * but is swappable in tests so the re-verification logic can be exercised
 * without standing up a real Ed25519 vector.
 */
export type VerifyProducerSignatureFn = (
  input: ProducerSignatureInput,
  pinnedProducerKeyB64url: string,
) => ProducerSignatureVerdict;

/**
 * The authenticity basis the READER established for an enforcement-evidence
 * entry. This is the entry-level verdict the surfaces aggregate up into the
 * posture-level `evidence_basis`.
 *
 *  - `producer_signed_verified`  — a producer signature RE-verified against the
 *    pinned key. Per-producer authenticated; the forgery hole is closed for
 *    this entry. The ONLY basis that may contribute to a producer-authenticated
 *    green light.
 *  - `producer_signed_rejected`  — the entry CLAIMS `producer_signed` and a
 *    pinned key IS available, but re-verification FAILED (missing/garbage sig,
 *    wrong canonical bytes, stale, kid mismatch). A forgery. Fails closed: must
 *    NOT count and must render non-green.
 *  - `channel_authenticated`     — accepted on the legacy channel basis: either
 *    the entry's basis is `channel_authenticated_unsigned`/absent, OR no pinned
 *    key is available so the reader cannot re-verify. Honest about NOT being
 *    per-producer authenticated.
 */
export type EntryReverifyBasis =
  | "producer_signed_verified"
  | "producer_signed_rejected"
  | "channel_authenticated";

/**
 * The full re-verification result. For a `producer_signed_verified` entry it
 * also carries the SIGNED capture timestamp, so the reader judges freshness from
 * the signature-bound time — NOT the forgeable top-level audit-entry timestamp.
 * A replay of a real signed tuple (same seq, same canonical, same captured_at)
 * into a fresh audit entry keeps its OLD signed timestamp, so freshness-by-
 * signed-time rejects it even though the top-level timestamp was forged fresh.
 */
export interface EntryReverifyResult {
  basis: EntryReverifyBasis;
  /** The signature-bound capture time (ms), present only when verified. */
  signedCapturedAtMs: number | null;
  /**
   * The signature-bound subject from the signed canonical body. Present only
   * when the producer signature verifies and the signed body names a subject.
   */
  signedIdentityId: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Re-verify one Castle Wall enforcement-evidence audit entry's producer
 * signature at READ time.
 *
 * `seq` is read from the entry's own `details.seq` (the consumer preserves the
 * chain-authenticated seq there); it binds the signature to a WAL position so a
 * signature lifted from a different-seq event cannot be stapled on.
 *
 * Fail-closed contract:
 *   - basis `producer_signed` + pinned key present → MUST re-verify or be
 *     rejected. No silent acceptance.
 *   - basis `producer_signed` + NO pinned key → the reader cannot check it;
 *     it does NOT crash and does NOT default-green — it falls to the channel
 *     basis with the honest label (R-3 asymmetry).
 *   - basis `channel_authenticated_unsigned` / absent → channel basis.
 *
 * @param details the persisted entry `details` record.
 * @param pinnedProducerKeyB64url the reader's pinned producer key, or null when
 *   none is configured (macOS today / Linux pre-provision).
 * @param verify injectable verify fn (defaults to `verifyProducerSignature`).
 */
export function reverifyEntryProducerSignature(
  details: unknown,
  pinnedProducerKeyB64url: string | null,
  verify: VerifyProducerSignatureFn = verifyProducerSignature,
  subjectFortressId?: string | null,
): EntryReverifyResult {
  const channel: EntryReverifyResult = {
    basis: "channel_authenticated",
    signedCapturedAtMs: null,
    signedIdentityId: null,
  };
  if (!isRecord(details)) return channel;

  const basis = details[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY];

  // Not a producer-signed-claiming entry (channel-unsigned, or legacy/absent):
  // channel basis. Never elevate a channel-basis entry to producer-authenticated.
  if (basis !== CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED) {
    return channel;
  }

  // The entry CLAIMS producer_signed. Without a pinned key the reader cannot
  // check the claim — it must NOT trust the claim (the claim is forgeable) and
  // must NOT crash. Fall to the channel basis with the honest label: this green
  // rests on channel-authentication, not on a verified producer signature.
  if (pinnedProducerKeyB64url === null) {
    return channel;
  }

  // A pinned key IS available: the producer_signed claim is now CHECKABLE, so
  // it must actually verify. Reconstruct the signed inputs from the persisted
  // details and re-verify. Any missing field / failed check → rejected (forgery
  // fails closed; it does not fall back to channel basis, because a key-bearing
  // reader that accepted an unverifiable producer_signed entry would re-open the
  // hole).
  const signatureB64url = details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY];
  const keyId = details[CASTLE_WALL_PRODUCER_KID_DETAIL_KEY];
  const eventCanonicalJson =
    details[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY];
  const capturedAtUnixMs =
    details[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY];
  const seq = details.seq;

  if (
    typeof signatureB64url !== "string" ||
    typeof keyId !== "string" ||
    typeof eventCanonicalJson !== "string" ||
    typeof capturedAtUnixMs !== "number" ||
    typeof seq !== "number"
  ) {
    return {
      basis: "producer_signed_rejected",
      signedCapturedAtMs: null,
      signedIdentityId: null,
    };
  }

  const input: ProducerSignatureInput = {
    eventCanonicalJson,
    capturedAtUnixMs,
    seq,
    signatureB64url,
    keyId,
  };
  const verdict = verify(input, pinnedProducerKeyB64url);
  if (!verdict.ok) {
    return {
      basis: "producer_signed_rejected",
      signedCapturedAtMs: null,
      signedIdentityId: null,
    };
  }
  // Verified: carry the SIGNATURE-BOUND capture time so the reader judges
  // freshness from it, not the forgeable top-level audit timestamp. This closes
  // the same-seq replay: copying an old signed tuple into a fresh audit entry
  // keeps its old signed `capturedAtUnixMs`, so freshness-by-signed-time rejects
  // it regardless of the forged top-level timestamp.
  return {
    basis: "producer_signed_verified",
    signedCapturedAtMs: capturedAtUnixMs,
    signedIdentityId: signedCanonicalIdentityId(details, subjectFortressId),
  };
}

/**
 * Re-verify a broker daemon liveness / stand-down producer signature.
 *
 * Broker differs from Castle Wall's macOS floor: this producer is Node-side and
 * is expected to have a dedicated key. Without the pinned broker producer
 * public key, a broker heartbeat cannot count on the channel basis.
 */
export function reverifyBrokerEntryProducerSignature(
  details: unknown,
  pinnedProducerKeyB64url: string | null,
): EntryReverifyResult {
  if (!isRecord(details)) {
    return {
      basis: "producer_signed_rejected",
      signedCapturedAtMs: null,
      signedIdentityId: null,
    };
  }
  if (details[BROKER_EVIDENCE_BASIS_DETAIL_KEY] !== BROKER_EVIDENCE_BASIS_PRODUCER_SIGNED) {
    return {
      basis: "producer_signed_rejected",
      signedCapturedAtMs: null,
      signedIdentityId: null,
    };
  }
  if (pinnedProducerKeyB64url === null) {
    return {
      basis: "producer_signed_rejected",
      signedCapturedAtMs: null,
      signedIdentityId: null,
    };
  }

  const signatureB64url = details[BROKER_PRODUCER_SIG_DETAIL_KEY];
  const keyId = details[BROKER_PRODUCER_KID_DETAIL_KEY];
  const signatureScheme = details[BROKER_PRODUCER_SIGNATURE_SCHEME_DETAIL_KEY];
  const eventCanonicalJson = details[BROKER_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY];
  const capturedAtUnixMs = details[BROKER_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY];
  const seq = details.seq;

  if (
    typeof signatureB64url !== "string" ||
    typeof keyId !== "string" ||
    typeof signatureScheme !== "string" ||
    typeof eventCanonicalJson !== "string" ||
    typeof capturedAtUnixMs !== "number" ||
    typeof seq !== "number"
  ) {
    return {
      basis: "producer_signed_rejected",
      signedCapturedAtMs: null,
      signedIdentityId: null,
    };
  }

  const input: BrokerProducerSignatureInput = {
    eventCanonicalJson,
    capturedAtUnixMs,
    seq,
    signatureB64url,
    keyId,
    signatureScheme,
  };
  const verdict = verifyBrokerProducerSignature(input, pinnedProducerKeyB64url);
  if (!verdict.ok) {
    return {
      basis: "producer_signed_rejected",
      signedCapturedAtMs: null,
      signedIdentityId: null,
    };
  }
  return {
    basis: "producer_signed_verified",
    signedCapturedAtMs: capturedAtUnixMs,
    signedIdentityId: null,
  };
}

/**
 * Does this re-verification basis permit a Castle Wall ENFORCEMENT-EVIDENCE
 * entry to count toward a GREEN arm-state / kernel-block / active tally?
 *
 * The rule is asymmetric on whether the reader holds a pinned key, mirroring the
 * design's "never read with a weaker basis than the consumer wrote with" (R-4):
 *
 *  - **Key present** (`keyPresent === true`): ONLY `producer_signed_verified`
 *    counts. This is the load-bearing close. When a key is configured the audit
 *    CONSUMER rejects any enforcement evidence lacking a valid producer
 *    signature (it never persists a genuine enforcement entry on the channel
 *    basis), so a key-bearing reader seeing a `channel_authenticated` /
 *    absent-basis enforcement entry is looking at a FORGERY — an in-process
 *    writer that stamped the marker but could not sign. It must not count.
 *    `producer_signed_rejected` (forged/failed signature) also never counts.
 *  - **No key** (`keyPresent === false`): `channel_authenticated` counts (the
 *    honest legacy / macOS floor); `producer_signed_rejected` cannot occur (a
 *    no-key reader never attempts verification — see
 *    `reverifyEntryProducerSignature`).
 */
export function enforcementEntryCounts(
  basis: EntryReverifyBasis,
  keyPresent: boolean,
): boolean {
  if (keyPresent) return basis === "producer_signed_verified";
  return basis !== "producer_signed_rejected";
}

/**
 * Does this re-verification basis permit a Castle Wall LIVENESS HEARTBEAT
 * (observability Slice 2) to count as a fresh "the daemon is alive" signal?
 *
 * A heartbeat is NOT enforcement evidence and NEVER earns green; its only job is
 * to split the absence-of-enforcement case into alive-but-idle vs silently-dead.
 * So the trust asymmetry is the INVERSE of `enforcementEntryCounts`:
 *
 *  - The real heartbeat producer (`macos-daemon.ts:emitAuditHeartbeat`) writes
 *    the beat as a DIRECT `auditLog.append`, NOT through the signing audit
 *    consumer, so a genuine production beat carries the `cw_source` marker on the
 *    CHANNEL basis with NO producer signature — on EVERY host, Linux included
 *    (the daemon has no read-side signing path for this entry). Gating the beat
 *    with `enforcementEntryCounts` would therefore drop every genuine beat on a
 *    key-bearing host and render the marquee silent-death alarm INERT on Linux
 *    (the platform the thesis-gate designates as the one that matters). That is
 *    the capability gap this rule closes.
 *  - A forged beat that CLAIMS `producer_signed` but whose signature fails
 *    re-verify (`producer_signed_rejected`) must still NOT count: that is the one
 *    way an in-process forger could fake "I am alive" to SUPPRESS the
 *    silent-death alarm. (The channel-basis marker is forgeable by an in-process
 *    writer too, exactly as in `posture.ts` — but a forged channel beat only ever
 *    suppresses a RED alarm into `unknown`, never manufactures green, so it is no
 *    more permissive than the shipped marker trust boundary.)
 *
 * Net: a heartbeat counts on BOTH no-key and key-bearing hosts unless it is a
 * rejected producer-signed forgery. The rule is independent of `keyPresent`
 * because a genuine beat is channel-basis on every host.
 */
export function livenessEntryCounts(basis: EntryReverifyBasis): boolean {
  return basis !== "producer_signed_rejected";
}

/** Broker liveness counts only on a verified producer signature. */
export function brokerLivenessEntryCounts(basis: EntryReverifyBasis): boolean {
  return basis === "producer_signed_verified";
}

/**
 * Subject evidence after read-side re-verification.
 *
 * For a verified producer-signed Castle Wall entry, the signed canonical body is
 * the only subject authority. The top-level audit row label is forgeable by the
 * in-process appender and must not participate in subject-bound green decisions.
 * Channel-basis entries have no signed body, so they retain the legacy row
 * label floor.
 */
export function subjectEvidenceForReverifiedEntry(
  entry: { identity_id?: unknown },
  reverify: EntryReverifyResult,
): { identity_id?: unknown } {
  if (reverify.basis !== "producer_signed_verified") return entry;
  return reverify.signedIdentityId === null
    ? {}
    : { identity_id: reverify.signedIdentityId };
}

/**
 * A stable dedup key for a re-verified producer-signed entry, used to count each
 * genuine signed enforcement event AT MOST ONCE.
 *
 * Why this is needed (codex round-4 HIGH): re-verification proves a signed tuple
 * is genuine and binds it to a seq/time/operation, but an in-process writer can
 * COPY a still-fresh genuine signed entry N times — each copy re-verifies
 * identically. Without dedup, the copies inflate verdict/kernel/invocation
 * counts (and could manufacture fresh evidence from a single real event).
 *
 * The daemon's WAL `seq` is monotonic, so two genuine enforcement events never
 * share a seq; the signature is unique per signed message. Keying on
 * `seq | signature` therefore collapses exact replays without rejecting any
 * legitimate distinct evidence. Returns null when the inputs aren't both present
 * (the caller should not have reached here for a verified entry, but fail safe).
 */
export function producerSignedDedupKey(
  details: Record<string, unknown>,
): string | null {
  const seq = details.seq;
  const sig = details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY];
  if (typeof seq !== "number" || typeof sig !== "string") return null;
  return `${seq}|${sig}`;
}

export function brokerSignedOperationMatchesEntry(
  details: Record<string, unknown>,
  entryOperation: string,
): boolean {
  return brokerSignedCanonicalOperation(details) === entryOperation;
}

export function brokerProducerSignedDedupKey(
  details: Record<string, unknown>,
): string | null {
  const seq = details.seq;
  const sig = details[BROKER_PRODUCER_SIG_DETAIL_KEY];
  if (typeof seq !== "number" || typeof sig !== "string") return null;
  return `${seq}|${sig}`;
}
