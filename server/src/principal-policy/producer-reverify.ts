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
): EntryReverifyBasis {
  if (!isRecord(details)) return "channel_authenticated";

  const basis = details[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY];

  // Not a producer-signed-claiming entry (channel-unsigned, or legacy/absent):
  // channel basis. Never elevate a channel-basis entry to producer-authenticated.
  if (basis !== CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED) {
    return "channel_authenticated";
  }

  // The entry CLAIMS producer_signed. Without a pinned key the reader cannot
  // check the claim — it must NOT trust the claim (the claim is forgeable) and
  // must NOT crash. Fall to the channel basis with the honest label: this green
  // rests on channel-authentication, not on a verified producer signature.
  if (pinnedProducerKeyB64url === null) {
    return "channel_authenticated";
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
    return "producer_signed_rejected";
  }

  const input: ProducerSignatureInput = {
    eventCanonicalJson,
    capturedAtUnixMs,
    seq,
    signatureB64url,
    keyId,
  };
  const verdict = verify(input, pinnedProducerKeyB64url);
  return verdict.ok ? "producer_signed_verified" : "producer_signed_rejected";
}

/**
 * Does this re-verification basis permit an enforcement-evidence entry to count
 * toward a GREEN arm-state / kernel-block tally?
 *
 *  - `producer_signed_verified` → yes (per-producer authenticated).
 *  - `channel_authenticated`    → yes (legacy channel basis; the only honest
 *    floor on a no-key reader, and the shipped behavior on macOS).
 *  - `producer_signed_rejected` → NO. A forged/failed producer_signed entry,
 *    on a key-bearing reader, must never render green.
 */
export function reverifyBasisCounts(basis: EntryReverifyBasis): boolean {
  return basis !== "producer_signed_rejected";
}
