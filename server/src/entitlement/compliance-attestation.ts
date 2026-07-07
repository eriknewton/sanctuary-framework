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
 * canonical bytes and checks the embedded public key against the embedded
 * signature. This proves SELF-CONSISTENCY (the document was not altered after
 * signing) - it does NOT prove WHO the operator is. A verifier that cares about
 * identity provenance must independently pin the operator's public key and
 * compare it to the embedded one; `verifySignedAttestation`'s reason strings
 * and the CLI `verify` output say this explicitly.
 */

import { canonicalJson } from "../audit/chain.js";
import { toBase64url, fromBase64urlStrict } from "../core/encoding.js";
import { verify as verifyEd25519 } from "../core/identity.js";

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

/** The roster/posture facts the attestation reports (already computed). */
export interface AttestationPostureView {
  /** Total nodes in the CENTRAL roster after any cap has been applied. */
  centralNodesTotal: number;
  admitted: number;
  revoked: number;
  untrusted: number;
  /** Resolved node-count cap; null = unlimited. */
  maxNodes: number | null;
  /** True when the (capped) roster total exceeds maxNodes (should not happen
   * post-cap, but reported honestly if the caller observes it pre-cap). */
  overCap: boolean;
  /** The fleet-wide eviction serial (see `fleet-roster.ts`). */
  evictionSerial: number;
  /** Signed-policy-distribution rollup (see `fleet-roster.ts`). */
  policyDistribution: {
    inSync: number;
    drifted: number;
    unknown: number;
  };
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
    revoked: number;
    untrusted: number;
    max_nodes: number | null;
    over_cap: boolean;
    eviction_serial: number;
    policy_distribution: {
      in_sync: number;
      drifted: number;
      unknown: number;
    };
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
 * rather than this function guessing or fabricating a count.
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
      policy_distribution: {
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
  | "signature_invalid";

/** The outcome of an offline attestation verification. */
export type AttestationVerification =
  | { ok: true; attestation: AttestationBody }
  | { ok: false; reason: AttestationVerifyReason };

/**
 * Verify a signed attestation document OFFLINE. PURE (no I/O, no custody, no
 * network): recomputes `canonicalJson(doc.attestation)` and checks
 * `doc.signature` against the EMBEDDED `doc.public_key`. FAIL-CLOSED: any
 * malformed shape, non-canonical signature encoding, wrong-length key, or a
 * signature that does not verify returns `{ ok: false, reason }` - it NEVER
 * throws and NEVER reports `ok: true` on a mismatch.
 *
 * IMPORTANT (identity provenance, not just self-consistency): a passing
 * verify proves the document was signed by the holder of the EMBEDDED key and
 * has not been altered since - it does NOT prove that key belongs to any
 * particular operator. A caller who needs identity provenance must
 * additionally compare `doc.public_key` against the operator's independently
 * pinned identity (the CLI `verify` verb prints this caveat).
 */
export function verifySignedAttestation(
  doc: unknown,
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
  if (publicKey.length !== 32) {
    return { ok: false, reason: "bad_public_key" };
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64urlStrict(signature);
  } catch {
    return { ok: false, reason: "bad_signature_encoding" };
  }
  if (sigBytes.length !== 64) {
    return { ok: false, reason: "bad_signature_encoding" };
  }

  const message = new TextEncoder().encode(canonicalJson(attestation));
  if (!verifyEd25519(message, sigBytes, publicKey)) {
    return { ok: false, reason: "signature_invalid" };
  }
  return { ok: true, attestation: attestation as AttestationBody };
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
