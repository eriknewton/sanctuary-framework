/**
 * Fleet control plane - signed compliance-ATTESTATION export.
 *
 * Composes already-computed, already-verified posture facts (roster counts,
 * the resolved node-count cap, the policy-distribution rollup, and the
 * license/entitlement status) into ONE canonical, operator-signed, OFFLINE
 * VERIFIABLE document. No new cryptography: signing reuses the exact
 * `core/identity.sign()` path over the exact `audit/chain.canonicalJson`
 * convention that `entitlement/ledger.ts` already signs licenses with (the
 * SAME software Ed25519 default operator identity `sanctuary license issue`
 * uses via `cli/license.ts`'s `openIssuer`). This is NOT a Dev-ID / notary /
 * Secure-Enclave / signing-console key.
 *
 * ── THE SINGLE MOST IMPORTANT INVARIANT (honesty / thesis-gate) ─────────────
 * The attestation is an OPERATOR SELF-ATTESTATION of this fortress's OWN
 * LOCALLY-VERIFIABLE control-plane posture at a point in time (`generated_at`).
 * It is NOT a third-party audit and NOT a per-flow rule-attributed audit
 * trail (the unbuilt C4 build). The `claims_scope` field on every produced
 * document, and every CLI/README string describing this feature, MUST say so
 * plainly and MUST NEVER imply "Sanctuary-audited", "compliance-certified",
 * or "audited per-rule per-flow". A review that finds overclaiming copy here
 * is a BLOCKER (see the `claims_scope`-content test in
 * `test/entitlement/compliance-attestation.test.ts`).
 *
 * ── WHAT IS SIGNED, AND HOW ──────────────────────────────────────────────────
 * `buildAttestationBody` is PURE (no I/O, no crypto): it takes already-resolved
 * posture facts and maps them to the versioned attestation body. It NEVER
 * refuses on an unlicensed/community fleet - attesting "I am on the free tier"
 * is an honest compliance statement and must not be blocked (see
 * `entitlement/fleet-cap.ts`'s fail-closed-to-community contract).
 *
 * `serializeSignedAttestation` takes an INJECTED signer (the same
 * `IssuerSigner` shape `entitlement/ledger.ts` uses) and produces the signed,
 * offline-verifiable document: `signature = Ed25519(canonicalJson(attestation))`
 * plus the embedded PUBLIC key (never private material, AGENTS.md #6).
 *
 * `verifySignedAttestation` is PURE (no I/O, no custody): it recomputes the
 * canonical bytes and checks the signature. Given an independently-pinned
 * operator public key (`opts.pinnedOperatorKey`), it ALSO requires the
 * embedded `doc.public_key` to equal the pinned key before verifying the
 * signature against it, reporting `provenance: "verified"` - this is the ONLY
 * result the CLI may call "VALID" (AGENTS.md honesty invariant, A1 fix
 * 2026-07-07). Without a pinned key it falls back to checking the signature
 * against the document's OWN embedded key, proving SELF-CONSISTENCY only (the
 * document was not altered after signing) - it does NOT prove WHO the
 * operator is, and `provenance: "self_consistent"` says so explicitly so no
 * caller can print "VALID" for a doc signed by an unpinned, unknown key.
 */

import { canonicalJson } from "../audit/chain.js";
import { toBase64url, fromBase64urlStrict } from "../core/encoding.js";
import { verify as verifyEd25519 } from "../core/identity.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../core/crypto-suite-registry.js";

/**
 * FROZEN domain / schema label for the attestation document. This is a
 * signing-crypto-adjacent identifier (it is embedded in the signed body and
 * is how a downstream consumer recognizes the document shape): once shipped,
 * this string must never change. A superset-schema addition is fine; a
 * *change* to this label would make every already-signed attestation
 * unrecognizable to a future verifier expecting the same domain.
 */
export const COMPLIANCE_ATTESTATION_SCHEMA =
  "sanctuary.fleet.compliance-attestation.v1" as const;

/**
 * The mandatory self-attestation disclaimer. This EXACT sentence (or one
 * materially equivalent to it) is what every produced `claims_scope` must
 * contain; the overclaim-guard test asserts this string's presence verbatim
 * and asserts the absence of overclaiming phrasing. Centralizing it here means
 * the CLI banner and the document body can never drift from each other.
 */
export const CLAIMS_SCOPE_DISCLAIMER =
  "This attestation states this fortress's OWN locally-verifiable fleet " +
  "posture at generated_at, signed by the operator's own key. It is a " +
  "self-attestation of the operator's control-plane state, NOT a " +
  "third-party audit and NOT a per-flow rule-attributed audit trail.";

/** License/entitlement status as the attestation honestly reports it. */
export type AttestationLicenseStatus = "active" | "grace" | "community";

/** The license facts the attestation reports (already resolved by the caller). */
export interface AttestationLicenseView {
  /** Signed license id, or null when unlicensed (community). */
  licenseId: string | null;
  /** Subject the license names, or null when unlicensed. */
  subject: string | null;
  /** Resolved tier label ("community" | the granted tier). */
  tier: string;
  /** Entitled node count; null = unlimited or not applicable (community). */
  entitledNodes: number | null;
  /** ISO-8601 grant expiry, or null when unlicensed. */
  notAfter: string | null;
  /** The canonicalized feature-flag set granted, or empty for community. */
  features: string[];
  /** active = in the normal validity window; grace = honored past notAfter
   * within the grace window; community = no valid paid grant. */
  status: AttestationLicenseStatus;
}

/**
 * The roster/posture facts the attestation reports (already computed).
 *
 * ── MEASURED VS UNAVAILABLE (the A3 honesty fix, 2026-07-07) ────────────────
 * `revoked`, `untrusted`, `evictionSerial`, and `policyDistribution` are
 * `null` when the posture SOURCE does not measure them (today's
 * `/api/fleet/status` daemon route is a banner endpoint that only reports
 * `admitted_node_count` + a banner string - it does NOT measure these).
 * `null` here means "not measured by this source," and is DISTINCT from a
 * measured value of `0` ("measured, and the true count is zero"). A caller
 * must never zero-fill an unmeasured field: doing so signs FALSE PRECISION
 * into a document that reads as "no drift, none revoked" when the truth is
 * "we never checked." `centralNodesTotal` and `admitted` are always numbers
 * because the shipped source DOES measure them (or the caller has no roster
 * at all, in which case the whole view honestly reports `bannerState:
 * "roster_unavailable"` with admitted/centralNodesTotal at 0, which IS a
 * measured fact: no roster was found).
 */
export interface AttestationPostureView {
  /** Total nodes in the CENTRAL roster after any cap has been applied. */
  centralNodesTotal: number;
  admitted: number;
  /** null = not measured by the posture source (see the type doc above). */
  revoked: number | null;
  /** null = not measured by the posture source (see the type doc above). */
  untrusted: number | null;
  /** Resolved node-count cap; null = unlimited. */
  maxNodes: number | null;
  /** True when the (capped) roster total exceeds maxNodes (should not happen
   * post-cap, but reported honestly if the caller observes it pre-cap). */
  overCap: boolean;
  /** The fleet-wide eviction serial (see `fleet-roster.ts`); null = not
   * measured by the posture source (see the type doc above). */
  evictionSerial: number | null;
  /** Signed-policy-distribution rollup (see `fleet-roster.ts`); null = not
   * measured by the posture source (see the type doc above) - never a
   * zero-filled `{0,0,0}` standing in for "we never checked." */
  policyDistribution: {
    inSync: number;
    drifted: number;
    unknown: number;
  } | null;
  /** Operator-facing banner state, when the roster/roster-fetch is unavailable
   * this is "roster_unavailable" and the numeric counts are honest zeros. */
  bannerState: string;
}

/** The full set of pure inputs {@link buildAttestationBody} composes. */
export interface AttestationInputs {
  /** This fortress's own federation id, or null when unprovisioned. */
  fortressId: string | null;
  /** The signing operator identity's fingerprint (public-key-derived id). */
  issuerFingerprint: string;
  license: AttestationLicenseView;
  posture: AttestationPostureView;
  /** Injected clock (ISO-8601), so tests are deterministic. */
  now: string;
}

/** The signed content of an attestation document (everything under `signature`). */
export interface AttestationBody {
  schema: typeof COMPLIANCE_ATTESTATION_SCHEMA;
  generated_at: string;
  fortress_id: string | null;
  issuer_fingerprint: string;
  license: {
    license_id: string | null;
    subject: string | null;
    tier: string;
    entitled_nodes: number | null;
    not_after: string | null;
    features: string[];
    status: AttestationLicenseStatus;
  };
  posture: {
    central_nodes_total: number;
    admitted: number;
    /** null = not measured by the posture source; NEVER a stand-in zero. */
    revoked: number | null;
    /** null = not measured by the posture source; NEVER a stand-in zero. */
    untrusted: number | null;
    max_nodes: number | null;
    over_cap: boolean;
    /** null = not measured by the posture source; NEVER a stand-in zero. */
    eviction_serial: number | null;
    /** null = not measured by the posture source; NEVER a zero-filled
     * `{in_sync:0,drifted:0,unknown:0}` standing in for "we never checked." */
    policy_distribution: {
      in_sync: number;
      drifted: number;
      unknown: number;
    } | null;
    banner_state: string;
  };
  claims_scope: string;
}

/** The signed, offline-verifiable attestation document. */
export interface SignedAttestation {
  attestation: AttestationBody;
  /** base64url Ed25519 signature over `canonicalJson(attestation)`. */
  signature: string;
  /** base64url 32-byte operator identity PUBLIC key (never private material). */
  public_key: string;
}

/** Signs a message with the operator identity key. Injected (mirrors
 * `entitlement/ledger.ts`'s `IssuerSigner`) so this pure core never holds key
 * material: the CLI supplies a closure over the encrypted-key `sign()` path
 * (which decrypts transiently and zeroes in a `finally`, AGENTS.md #6).
 * Returns the raw 64-byte Ed25519 signature. */
export type AttestationSigner = (message: Uint8Array) => Uint8Array;

/**
 * Build the attestation body from already-resolved posture facts. PURE: no
 * I/O, no crypto, no custody. Every branch (paid/active, grace, community,
 * over-cap, roster-unavailable) maps honestly - a caller who cannot resolve
 * the roster passes honest zeros with `bannerState: "roster_unavailable"`
 * rather than this function guessing or fabricating a count. `null` posture
 * fields (`revoked`, `untrusted`, `eviction_serial`, `policy_distribution`)
 * pass straight through as `null`, never coerced to a zero (the A3 fix): a
 * source that does not measure a field must sign "not measured," not
 * "measured, and it is zero."
 *
 * `claims_scope` is ALWAYS the same disclaimer text: it does not vary by
 * branch, because the honesty invariant applies uniformly regardless of tier
 * or posture.
 */
export function buildAttestationBody(inputs: AttestationInputs): AttestationBody {
  const { fortressId, issuerFingerprint, license, posture, now } = inputs;
  return {
    schema: COMPLIANCE_ATTESTATION_SCHEMA,
    generated_at: now,
    fortress_id: fortressId,
    issuer_fingerprint: issuerFingerprint,
    license: {
      license_id: license.licenseId,
      subject: license.subject,
      tier: license.tier,
      entitled_nodes: license.entitledNodes,
      not_after: license.notAfter,
      features: [...license.features],
      status: license.status,
    },
    posture: {
      central_nodes_total: posture.centralNodesTotal,
      admitted: posture.admitted,
      revoked: posture.revoked,
      untrusted: posture.untrusted,
      max_nodes: posture.maxNodes,
      over_cap: posture.overCap,
      eviction_serial: posture.evictionSerial,
      // null (not measured by the source) passes straight through - NEVER
      // coerced to a zero-filled object (the A3 fix).
      policy_distribution:
        posture.policyDistribution === null
          ? null
          : {
              in_sync: posture.policyDistribution.inSync,
              drifted: posture.policyDistribution.drifted,
              unknown: posture.policyDistribution.unknown,
            },
      banner_state: posture.bannerState,
    },
    claims_scope: CLAIMS_SCOPE_DISCLAIMER,
  };
}

/**
 * Sign an attestation body into the full offline-verifiable document. PURE
 * apart from invoking the injected `sign` closure (no I/O of its own): the
 * signature covers `canonicalJson(body)` exactly the way the license ledger
 * signs its rows, so a one-byte mutation of any field changes the signed
 * bytes and fails {@link verifySignedAttestation}.
 *
 * `publicKey` is embedded so a downstream verifier can check the signature
 * OFFLINE. Embedding the public key proves the document is INTERNALLY
 * CONSISTENT (self-signed, unaltered); it does NOT by itself prove the
 * document came from a SPECIFIC trusted operator - a verifier who cares about
 * identity provenance must independently pin `publicKey` against the
 * operator's known identity (exactly as `license list --verified` pins the
 * fortress key rather than trusting a claim inside the file).
 */
export function serializeSignedAttestation(
  body: AttestationBody,
  sign: AttestationSigner,
  publicKey: Uint8Array,
): SignedAttestation {
  const message = new TextEncoder().encode(canonicalJson(body));
  const signature = sign(message);
  return {
    attestation: body,
    signature: toBase64url(signature),
    public_key: toBase64url(publicKey),
  };
}

/** Why {@link verifySignedAttestation} rejected a document. Never a throw. */
export type AttestationVerifyReason =
  | "malformed"
  | "bad_public_key"
  | "bad_signature_encoding"
  | "signature_invalid"
  | "operator_key_mismatch";

/**
 * How strongly a passing verification establishes WHO signed the document:
 *
 *  - `"verified"`: an independently-pinned operator public key was supplied
 *    AND matched `doc.public_key` AND the signature checked out against that
 *    SAME pinned key. This is the only level that may be reported as "VALID"
 *    identity-provenance-wise - the caller trusted a key from OUTSIDE the
 *    document, not a claim the document makes about itself.
 *  - `"self_consistent"`: no pinned key was supplied (or none is available),
 *    so the document was checked ONLY against its OWN embedded
 *    `doc.public_key`. This proves the document is internally consistent
 *    (unaltered since signing) and NOTHING about who signed it - an attacker
 *    can sign a fake posture with THEIR OWN key, embed that key, and this
 *    branch will still report success. Never render this as "VALID" without
 *    the accompanying provenance caveat (see the CLI `verify` verb).
 */
export type AttestationVerifyProvenance = "verified" | "self_consistent";

/** The outcome of an offline attestation verification. */
export type AttestationVerification =
  | {
      ok: true;
      attestation: AttestationBody;
      provenance: AttestationVerifyProvenance;
    }
  | { ok: false; reason: AttestationVerifyReason };

/**
 * Verify a signed attestation document OFFLINE. PURE (no I/O, no custody, no
 * network): recomputes `canonicalJson(doc.attestation)` and checks
 * `doc.signature`. FAIL-CLOSED: any malformed shape, non-canonical signature
 * encoding, wrong-length key, a signature that does not verify, or (when a
 * pinned key is supplied) a public-key mismatch returns `{ ok: false, reason
 * }` - it NEVER throws and NEVER reports `ok: true` on a mismatch.
 *
 * ── IDENTITY PROVENANCE (the A1 fix) ─────────────────────────────────────
 * `opts.pinnedOperatorKey`, when supplied, is an INDEPENDENTLY-KNOWN operator
 * public key (e.g. from `--operator-key`/`--pin`, or the fortress's own
 * identity) that the caller trusts from OUTSIDE this document. When present:
 *   - the embedded `doc.public_key` MUST equal the pinned key byte-for-byte
 *     (mismatch -> `{ ok: false, reason: "operator_key_mismatch" }`, checked
 *     BEFORE the signature so a wrong-key document never even reaches the
 *     crypto check);
 *   - the signature is verified against the PINNED key (not merely the
 *     embedded one - though they are equal at this point, verifying against
 *     the pinned key keeps the trust root explicit);
 *   - success reports `provenance: "verified"`.
 * Without a pinned key, verification falls back to checking the signature
 * against the document's OWN embedded key and reports `provenance:
 * "self_consistent"` - this proves the document was not altered since
 * signing and NOTHING about who signed it (an attacker can self-sign a fake
 * posture with their own key). Callers (the CLI `verify` verb) MUST NOT print
 * "VALID" for a `self_consistent` result; only a `verified` result may be
 * called "VALID".
 */
export function verifySignedAttestation(
  doc: unknown,
  opts?: { pinnedOperatorKey?: Uint8Array },
): AttestationVerification {
  if (typeof doc !== "object" || doc === null) {
    return { ok: false, reason: "malformed" };
  }
  const d = doc as Record<string, unknown>;
  const attestation = d.attestation;
  const signature = d.signature;
  const publicKeyB64 = d.public_key;

  if (
    typeof attestation !== "object" ||
    attestation === null ||
    typeof signature !== "string" ||
    typeof publicKeyB64 !== "string"
  ) {
    return { ok: false, reason: "malformed" };
  }
  if (!isPlausibleAttestationBody(attestation)) {
    return { ok: false, reason: "malformed" };
  }

  let publicKey: Uint8Array;
  try {
    publicKey = fromBase64urlStrict(publicKeyB64);
  } catch {
    return { ok: false, reason: "bad_public_key" };
  }
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: "bad_public_key" };
  }

  const pinned = opts?.pinnedOperatorKey;
  if (pinned !== undefined) {
    if (pinned.length !== ED25519_PUBLIC_KEY_BYTES || !timingSafeEqualBytes(pinned, publicKey)) {
      return { ok: false, reason: "operator_key_mismatch" };
    }
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64urlStrict(signature);
  } catch {
    return { ok: false, reason: "bad_signature_encoding" };
  }
  if (sigBytes.length !== ED25519_SIGNATURE_BYTES) {
    return { ok: false, reason: "bad_signature_encoding" };
  }

  const message = new TextEncoder().encode(canonicalJson(attestation));
  const verifyKey = pinned ?? publicKey;
  if (!verifyEd25519(message, sigBytes, verifyKey)) {
    return { ok: false, reason: "signature_invalid" };
  }
  return {
    ok: true,
    attestation: attestation as AttestationBody,
    provenance: pinned !== undefined ? "verified" : "self_consistent",
  };
}

/** Constant-time byte comparison (avoids leaking key-match timing). Both
 * inputs are PUBLIC keys (never secret material), so this is a defense-in-
 * depth hygiene choice rather than a security-critical requirement. */
function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Cheap structural plausibility of an attestation body BEFORE signature
 * verification (mirrors `activation.ts`'s `isPlausibleToken` chokepoint
 * pattern): a shape that cannot be an attestation body fails to `malformed`
 * here rather than reaching the crypto check. This does not validate every
 * nested field exhaustively - the signature check is the real trust
 * boundary - it only guards against `canonicalJson` being asked to hash a
 * shape that could never have been legitimately signed (e.g. a missing
 * `claims_scope`, which is the load-bearing honesty field).
 */
function isPlausibleAttestationBody(value: unknown): value is AttestationBody {
  if (typeof value !== "object" || value === null) return false;
  const b = value as Record<string, unknown>;
  return (
    b.schema === COMPLIANCE_ATTESTATION_SCHEMA &&
    typeof b.generated_at === "string" &&
    (b.fortress_id === null || typeof b.fortress_id === "string") &&
    typeof b.issuer_fingerprint === "string" &&
    typeof b.license === "object" &&
    b.license !== null &&
    typeof b.posture === "object" &&
    b.posture !== null &&
    typeof b.claims_scope === "string" &&
    b.claims_scope.length > 0
  );
}
