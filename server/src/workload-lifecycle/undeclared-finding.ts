/**
 * Sanctuary — Undeclared-workload detection finding builder (thin prototype,
 * rung c).
 *
 * Builds a SIGNED statement over the result of cross-checking the host's LIVE
 * supervised workloads (the supervisor `status()` snapshot) against the
 * DECLARED, audit-chain-recorded set ({@link detectUndeclaredWorkloads}). The
 * signed bundle is offline-verifiable by a second reader holding only the public
 * key, and is sealed chain-bound by `undeclared-finding-seal.ts`.
 *
 * COMPOSES with #513 (host-attestation), additive — REUSES its crypto pattern,
 * changes none of its semantics:
 *   - Signing is Ed25519 over domain-separated canonical JSON, the SAME signing
 *     discipline as `host-attestation.ts` (`hostAttestationSigningBytes`) and the
 *     audit/transparency checkpoints. NO new crypto is introduced.
 *   - `signer_kid` + `signature_algorithm` + `payload_encoding` are bound INSIDE
 *     the signed body (mirroring #513's FIX-3 signer binding); the envelope
 *     carries verbatim copies and the verifier cross-checks them, so an offline
 *     tamperer cannot swap the envelope's signer identity without breaking the
 *     signature.
 *   - It reuses the SAME `WorkloadAttestationSigner` opaque-bytes handle the
 *     host attestation consumes (no second signer abstraction), and the same
 *     `core/identity.ts` `verify` for offline verification.
 *
 * HONESTY BOUNDARY (the rung-c discipline — codex checks this):
 *   The `scope` field, embedded verbatim in the signed body, states that this:
 *     - compares the supervisor's LIVE supervised set against the audit-chain
 *       DECLARED set, flagging live workloads with no matching declared record
 *       (matched by `workload_id` OR `instance_id`);
 *     - does NOT enumerate all host processes — a workload running entirely
 *       OUTSIDE the supervisor's view is a further frontier (host-wide process
 *       enumeration, rung d) and is OUT OF SCOPE;
 *     - cannot resolve a workload whose adapter overrode BOTH `workload_id` AND
 *       `instance_id` away from its `agent_id` (a documented limitation — such a
 *       workload could appear undeclared even though it was declared under
 *       different ids), so the undeclared list is not definitive beyond that
 *       boundary;
 *     - clears a live workload ONLY against an ACTIVE declared record; a match to
 *       a `deleted`/`slept` record is flagged as running without a current
 *       declaration, and — because ids are not guaranteed unique/non-reused — a
 *       live workload could in principle be cleared by an UNRELATED active record
 *       sharing its id (the false-CLEAR residual; full precision needs
 *       per-instance identity disambiguation, a later refinement).
 *   No consciousness / sentience / welfare claim appears anywhere. Neutral
 *   "workload" language only (CISO-safe).
 */

import { canonicalJson, sha256Hex } from "../audit/chain.js";
import { fromBase64url, stringToBytes, toBase64url } from "../core/encoding.js";
import { verify as verifyEd25519 } from "../core/identity.js";
import type { WorkloadAttestationSigner } from "./host-attestation.js";
import type {
  UndeclaredDetection,
  UndeclaredWorkload,
} from "./undeclared-detection.js";

/** Domain-string version for the undeclared-finding payload. */
export const WORKLOAD_UNDECLARED_FINDING_SCHEMA =
  "sanctuary.workload-undeclared-finding.v1" as const;

/** Domain-separation prefix for the bytes actually signed (mirrors the
 * host-attestation signing discipline: a versioned prefix + canonical JSON, so a
 * signature over one domain can never be replayed in another). Note the domain
 * differs from the host attestation's, so a host-attestation signature can never
 * be replayed as an undeclared finding and vice versa. */
export const WORKLOAD_UNDECLARED_FINDING_DOMAIN =
  "sanctuary.workload-undeclared-finding.v1" as const;
const WORKLOAD_UNDECLARED_FINDING_DOMAIN_PREFIX = `${WORKLOAD_UNDECLARED_FINDING_DOMAIN}\n`;

/**
 * The EXACT honesty-scoping text embedded in every undeclared finding payload.
 * Quoted verbatim into the `scope` field so it travels with the signed bundle
 * and a downstream reader cannot interpret the undeclared list as host-wide or
 * definitive beyond the documented boundary. A test asserts this exact string is
 * present (regression guard against a future edit that over-claims).
 */
export const WORKLOAD_UNDECLARED_FINDING_SCOPE_TEXT =
  "This finding compares the supervisor's LIVE supervised workload set against " +
  "the DECLARED, audit-chain-recorded set. It flags each live supervised " +
  "workload that has NO matching declared lifecycle record, where a live " +
  "agent_id matches a declared workload by workload_id OR by instance_id. It " +
  "does NOT enumerate all host processes: a workload running entirely OUTSIDE " +
  "the supervisor's view is a separate later capability (host-wide process " +
  "enumeration) and is out of scope here. It also CANNOT resolve a workload " +
  "whose adapter overrode BOTH its workload_id AND its instance_id away from " +
  "its agent_id; such a workload may appear in the undeclared list even though " +
  "it was declared under different identifiers, so the undeclared list is not " +
  "definitive beyond the workload_id-or-instance_id match. Only ACTIVE declared " +
  "records clear a live workload: a live workload matching only a terminated " +
  "(deleted) or dormant (slept) declared record is flagged as running without a " +
  "current declaration. Conversely, because the schema does not guarantee " +
  "identifiers are globally unique or non-reused, a live workload could in " +
  "principle be cleared by an UNRELATED active declared record that happens to " +
  "share its workload_id or instance_id; fully precise detection requires " +
  "per-instance identity disambiguation, a later refinement. This is a detection " +
  "of declaration gaps in the supervised set, NOT a consciousness, sentience, " +
  "or welfare verdict of any kind.";

/** The only accepted signature algorithm for a v1 finding. */
export const WORKLOAD_UNDECLARED_FINDING_SIGNATURE_ALGORITHM =
  "Ed25519" as const;
/**
 * The only accepted payload encoding for a v1 finding.
 *
 * The string is SHARED VOCABULARY across several independently-versioned
 * signed surfaces, not a mirror of one canonical constant; the surfaces are
 * enumerated on `AuditCheckpointRecord.payload_encoding` in
 * `audit/checkpoint-shape.ts`. Read that note before changing the spelling
 * here.
 */
export const WORKLOAD_UNDECLARED_FINDING_PAYLOAD_ENCODING =
  "domain-separated-canonical-json-v1" as const;

/** The signable finding body (the bytes under signature). */
export interface UndeclaredFindingBody {
  schema: typeof WORKLOAD_UNDECLARED_FINDING_SCHEMA;
  fortress_id: string;
  attested_at: string;
  /** Verbatim honesty-scoping text (supervisor-view + match-rule disclaimer). */
  scope: string;
  /** Live supervised workloads with no matching declared record (sorted). */
  undeclared: UndeclaredWorkload[];
  undeclared_count: number;
  live_count: number;
  declared_count: number;
  /**
   * Signer identity + crypto descriptors bound INTO the signed bytes (mirrors
   * #513 FIX-3). The envelope carries verbatim copies for transport, but binding
   * them here means an offline reader (holding only the public key, NOT the
   * chain seal) cannot swap the envelope's `signer_kid` / `signature_algorithm`
   * / `payload_encoding` without invalidating the signature. The verifier
   * cross-checks the envelope copies against these and rejects any mismatch.
   */
  signer_kid: string;
  signature_algorithm: typeof WORKLOAD_UNDECLARED_FINDING_SIGNATURE_ALGORITHM;
  payload_encoding: typeof WORKLOAD_UNDECLARED_FINDING_PAYLOAD_ENCODING;
}

/** Signed envelope: the body plus an offline-verifiable Ed25519 signature.
 * `signer_kid` / `signature_algorithm` / `payload_encoding` are transport copies
 * of the same fields now bound inside `body`; the verifier cross-checks them. */
export interface SignedUndeclaredFinding {
  body: UndeclaredFindingBody;
  signer_kid: string;
  signature: string;
  signature_algorithm: typeof WORKLOAD_UNDECLARED_FINDING_SIGNATURE_ALGORITHM;
  payload_encoding: typeof WORKLOAD_UNDECLARED_FINDING_PAYLOAD_ENCODING;
  /** Base64url raw 32-byte Ed25519 public key the body verifies under. */
  public_key: string;
}

export class UndeclaredFindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UndeclaredFindingError";
  }
}

/** Domain-separated bytes that are actually signed (mirrors
 * `hostAttestationSigningBytes`). */
export function undeclaredFindingSigningBytes(
  body: UndeclaredFindingBody,
): Uint8Array {
  return stringToBytes(
    `${WORKLOAD_UNDECLARED_FINDING_DOMAIN_PREFIX}${canonicalJson(body)}`,
  );
}

/**
 * Canonical bundle hash for chain binding — sha256 over the domain-separated
 * canonical bytes of the WHOLE signed envelope (body + signature). The seal
 * binds the audit entry to this hash, mirroring `hostAttestationBundleHash`.
 */
export function undeclaredFindingBundleHash(
  finding: SignedUndeclaredFinding,
): string {
  return sha256Hex(
    `${WORKLOAD_UNDECLARED_FINDING_DOMAIN_PREFIX}${canonicalJson(finding)}`,
  );
}

export interface BuildUndeclaredFindingParams {
  detection: UndeclaredDetection;
  signer: WorkloadAttestationSigner;
  fortressId: string;
  /** Finding timestamp (ISO-8601). Injected for determinism in tests. */
  now: string;
}

/**
 * Build + sign an undeclared-workload finding from a detection result.
 *
 * Embeds the verbatim `scope` disclaimer, binds the signer descriptors into the
 * body (mirroring #513 FIX-3), and signs the canonical body. Independently
 * verifies the signer's returned signature before returning (a signer that
 * returns garbage must not produce a bundle — constraint #5, never silently
 * degrade).
 */
export async function buildUndeclaredFinding(
  params: BuildUndeclaredFindingParams,
): Promise<SignedUndeclaredFinding> {
  // Signer public key must be well-formed before we bind its kid into the body.
  if (params.signer.publicKey.length !== 32) {
    throw new UndeclaredFindingError(
      `finding signer public key must be 32 bytes, got ${params.signer.publicKey.length}`,
    );
  }

  const body: UndeclaredFindingBody = {
    schema: WORKLOAD_UNDECLARED_FINDING_SCHEMA,
    fortress_id: params.fortressId,
    attested_at: params.now,
    scope: WORKLOAD_UNDECLARED_FINDING_SCOPE_TEXT,
    // The detection already sorts `undeclared` by agent_id deterministically.
    undeclared: params.detection.undeclared,
    undeclared_count: params.detection.undeclared.length,
    live_count: params.detection.live_count,
    declared_count: params.detection.declared_count,
    // Bind signer identity + crypto descriptors INTO the signed bytes so an
    // offline reader cannot swap the envelope's copies without breaking the
    // signature (mirrors #513 FIX-3).
    signer_kid: params.signer.signer_kid,
    signature_algorithm: WORKLOAD_UNDECLARED_FINDING_SIGNATURE_ALGORITHM,
    payload_encoding: WORKLOAD_UNDECLARED_FINDING_PAYLOAD_ENCODING,
  };

  let signature: Uint8Array;
  try {
    signature = await params.signer.sign(undeclaredFindingSigningBytes(body));
  } catch (err) {
    throw new UndeclaredFindingError(
      `finding signer failed; nothing was produced: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (signature.length !== 64) {
    throw new UndeclaredFindingError(
      `finding signer returned a ${signature.length}-byte signature ` +
        `(expected 64); nothing was produced`,
    );
  }
  const finding: SignedUndeclaredFinding = {
    body,
    signer_kid: params.signer.signer_kid,
    signature: toBase64url(signature),
    signature_algorithm: WORKLOAD_UNDECLARED_FINDING_SIGNATURE_ALGORITHM,
    payload_encoding: WORKLOAD_UNDECLARED_FINDING_PAYLOAD_ENCODING,
    public_key: toBase64url(params.signer.publicKey),
  };

  // Independently verify before handing the bundle back. A signer that returns
  // a non-verifying signature must not yield a usable finding.
  if (!verifyUndeclaredFinding(finding, params.signer.publicKey)) {
    throw new UndeclaredFindingError(
      "finding signature does not verify against the signer's own public key; nothing was produced",
    );
  }
  return finding;
}

/**
 * Optional trust constraints for {@link verifyUndeclaredFinding}. Absent keeps
 * the legacy 2-arg behavior (self-consistency only). Present ALSO pins the
 * accepted signer, closing the self-signed-forgery fail-open (mirrors #513 FIX-4).
 */
export interface UndeclaredFindingTrust {
  /**
   * The out-of-band trusted public key the signature MUST verify under. When set,
   * verification uses THIS key and IGNORES the envelope's self-declared
   * `public_key`, so a finding forged under an attacker's OWN keypair (and
   * self-declared) is rejected. Base64url string or raw 32 bytes.
   */
  trustedPublicKey?: string | Uint8Array;
  /**
   * The expected signer kid. This is an ADJUNCT to `trustedPublicKey`, never a
   * standalone trust input: `signer_kid` is attacker-controlled (it is copied
   * into the signed body, so a forger self-signs it to any value they like).
   * Pinning a kid WITHOUT also pinning `trustedPublicKey` is therefore rejected
   * outright (fail-closed) rather than performing a kid-only check against the
   * self-declared key, which would give false forgery-assurance. When both are
   * set, the finding's bound `signer_kid` MUST match it, so a bundle from an
   * unexpected signer identity is rejected even when it verifies under the
   * pinned key.
   */
  expectedSignerKid?: string;
}

/**
 * Offline-verify a signed undeclared finding.
 *
 * The 2-arg form verifies SELF-CONSISTENCY only: passing `finding.public_key`
 * proves the envelope is internally consistent, NOT that the signer is trusted
 * (a forger can self-sign under their own key and self-declare it). To
 * authenticate the ORIGIN a caller MUST pin the fortress's out-of-band key via
 * `trust.trustedPublicKey` (and/or `trust.expectedSignerKid`), see
 * {@link UndeclaredFindingTrust} (mirrors #513 FIX-4).
 *
 * Returns false (never throws) on any malformed input or signature mismatch.
 *
 * Mirrors #513's FIX-3 verifier: it (a) rejects an unexpected
 * `signature_algorithm` / `payload_encoding` on either the envelope or the
 * signed body, and (b) cross-checks the envelope's `signer_kid` /
 * `signature_algorithm` / `payload_encoding` against the copies bound INSIDE the
 * signed body, rejecting any mismatch, so an offline tamperer who swaps the
 * envelope `signer_kid` (without re-signing, which they cannot do without the
 * private key) fails this cross-check AND the signature recomputation.
 *
 * FIX 4 expected-signer pinning. When `trust.trustedPublicKey` is set the
 * signature is checked against THAT key (not the envelope's self-declared one);
 * when `trust.expectedSignerKid` is set the bound `signer_kid` must equal it.
 * This closes the self-signed-forgery fail-open (a forged suppression finding
 * minted under an attacker key is rejected because it does not verify under the
 * pinned key). `expectedSignerKid` is only ever an ADJUNCT to `trustedPublicKey`,
 * never the sole trust input: because `signer_kid` is attacker-controlled,
 * pinning a kid WITHOUT a trusted key would only compare the forger's
 * self-declared kid and still verify against the forger's own key, giving false
 * forgery-assurance. That combination is therefore rejected outright.
 */
export function verifyUndeclaredFinding(
  finding: SignedUndeclaredFinding,
  publicKey: string | Uint8Array,
  trust?: UndeclaredFindingTrust,
): boolean {
  try {
    const body = finding.body;
    // (a) Reject an unexpected algorithm / encoding on the body or envelope.
    if (
      body.signature_algorithm !==
        WORKLOAD_UNDECLARED_FINDING_SIGNATURE_ALGORITHM ||
      finding.signature_algorithm !==
        WORKLOAD_UNDECLARED_FINDING_SIGNATURE_ALGORITHM
    ) {
      return false;
    }
    if (
      body.payload_encoding !== WORKLOAD_UNDECLARED_FINDING_PAYLOAD_ENCODING ||
      finding.payload_encoding !== WORKLOAD_UNDECLARED_FINDING_PAYLOAD_ENCODING
    ) {
      return false;
    }
    // (b) Envelope copies MUST match the signed-body copies (offline-swap guard).
    if (finding.signer_kid !== body.signer_kid) return false;
    if (finding.signature_algorithm !== body.signature_algorithm) return false;
    if (finding.payload_encoding !== body.payload_encoding) return false;

    // (c) FIX 4 expected-signer pinning. An expected kid must match the bound
    // signer_kid; a pinned trusted key REPLACES the caller's key for the check,
    // so the envelope's self-declared public_key cannot authenticate a forgery.
    //
    // `expectedSignerKid` is an ADJUNCT to `trustedPublicKey`, never standalone:
    // `signer_kid` is attacker-controlled (a forger self-signs it to the victim
    // kid), so a kid-only check against the self-declared key gives false
    // forgery-assurance. Fail closed if a kid is pinned without a trusted key.
    if (
      trust?.expectedSignerKid !== undefined &&
      trust.trustedPublicKey === undefined
    ) {
      return false;
    }
    if (
      trust?.expectedSignerKid !== undefined &&
      body.signer_kid !== trust.expectedSignerKid
    ) {
      return false;
    }
    const effectiveKey =
      trust?.trustedPublicKey !== undefined ? trust.trustedPublicKey : publicKey;

    const keyBytes =
      typeof effectiveKey === "string"
        ? fromBase64url(effectiveKey)
        : effectiveKey;
    if (keyBytes.length !== 32) return false;
    return verifyEd25519(
      undeclaredFindingSigningBytes(body),
      fromBase64url(finding.signature),
      keyBytes,
    );
  } catch {
    return false;
  }
}
