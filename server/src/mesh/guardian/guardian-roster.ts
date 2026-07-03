/**
 * GuardianRoster — fortress-master-signed certificate set defining the M-of-N
 * guardians and their public keys.
 *
 * Spec §9.1 — distributed to every node at federation-bootstrap and on every
 * change. Nodes verify guardian signatures (per §3.6.1 + §9.3) against the
 * pinned roster.
 *
 * Two primitives ship here:
 *   - `verifyGuardianRoster(roster, pinnedMaster)` — verifies the master
 *     signature on the roster body. Throws GuardianRosterSignatureError on
 *     failure, GuardianRosterError on shape violation.
 *   - `verifyGuardianQuorum(input, proof, pinnedRoster)` — verifies an
 *     `M`-or-more guardian signatures over a rotation input against the
 *     pinned roster. Throws GuardianQuorumError on failure.
 *
 * Both primitives use real Ed25519 verification through @noble/curves and the
 * shared canonical-JSON serializer — no mocking, no shortcut.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url, toBase64url } from "../../core/encoding.js";
import { canonicalizeToBytes } from "../canonical-json.js";
import { SIGNATURE_SCHEME_V1 } from "../constants.js";
import type { FortressMasterPublicKey } from "../types.js";
import {
  isV10GuardianKind,
} from "./constants.js";
import {
  GuardianQuorumError,
  GuardianRosterError,
  GuardianRosterSignatureError,
} from "./errors.js";
import type {
  GuardianIdentity,
  GuardianQuorumProof,
  GuardianRoster,
  MasterRotationQuorumInput,
} from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Canonical guardian-key identity
// ═══════════════════════════════════════════════════════════════════════

/**
 * Reduce a guardian public_key to a canonical identity string for uniqueness
 * checks. Ed25519 verification decodes base64url permissively (fromBase64url
 * pads and tolerates whitespace), so the SAME 32-byte key can appear under
 * many distinct strings ("KEY", "KEY=", "KEY ", "-"/"+" swaps). Comparing the
 * raw strings for uniqueness therefore lets one key holder occupy several
 * guardian slots under non-canonical spellings and satisfy M-of-N alone, even
 * though every slot verifies against one key. Fail closed: decode, require a
 * 32-byte Ed25519 key, and require the input to already be the canonical
 * base64url spelling of those bytes. Anything else is rejected, not silently
 * accepted, so a non-canonical spelling can never masquerade as a new key.
 */
export function canonicalGuardianKey(public_key: string): string {
  let decoded: Uint8Array;
  try {
    decoded = fromBase64url(public_key);
  } catch {
    throw new GuardianRosterError(
      `guardian public_key is not valid base64url`
    );
  }
  if (decoded.length !== 32) {
    throw new GuardianRosterError(
      `guardian public_key must decode to 32 bytes (Ed25519); got ${decoded.length}`
    );
  }
  const canonical = toBase64url(decoded);
  if (canonical !== public_key) {
    throw new GuardianRosterError(
      `guardian public_key must be canonical base64url (unpadded, no whitespace); got a non-canonical spelling`
    );
  }
  return canonical;
}

// ═══════════════════════════════════════════════════════════════════════
// Issuance (master-side)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Issue a fortress-master-signed GuardianRoster.
 *
 * Caller supplies the master private key transiently for the signature
 * operation and MUST zero the buffer after. Body is canonicalized so that two
 * issuers producing the same logical roster produce byte-identical signatures.
 *
 * Validation:
 *   - 1 ≤ m ≤ n
 *   - guardians.length === n
 *   - guardian_ids unique within the roster
 *   - each kind in `GUARDIAN_KINDS_V1_0` (v1.0 issuance discipline)
 *   - version ≥ 1 and integer
 */
export function issueGuardianRoster(params: {
  m: number;
  n: number;
  guardians: GuardianIdentity[];
  fortress_id: string;
  version: number;
  master_private_key: Uint8Array;
  created_at?: string;
}): GuardianRoster {
  validateRosterShape({
    m: params.m,
    n: params.n,
    guardians: params.guardians,
  });
  if (!Number.isInteger(params.version) || params.version < 1) {
    throw new GuardianRosterError(
      `roster version must be a positive integer; got ${params.version}`
    );
  }
  for (const g of params.guardians) {
    if (!isV10GuardianKind(g.kind)) {
      throw new GuardianRosterError(
        `v1.0 issuance MUST use a v1.0 guardian kind; got "${g.kind}" for ${g.guardian_id}`
      );
    }
  }
  const body = {
    m: params.m,
    n: params.n,
    guardians: params.guardians,
    signature_scheme: SIGNATURE_SCHEME_V1,
    version: params.version,
    created_at: params.created_at ?? new Date().toISOString(),
    fortress_id: params.fortress_id,
  };
  const sig = ed25519.sign(
    canonicalizeToBytes(body),
    params.master_private_key
  );
  return { ...body, master_signature: toBase64url(sig) };
}

/**
 * Assert a roster body is structurally sound before it is trusted for any
 * quorum decision. This is the SAME shape contract issuance enforces, exported
 * so receiver-side quorum evaluators (recovery threshold, master-rotation
 * quorum) can fail closed on a malformed roster rather than assuming issuance
 * already screened it. Enforced invariants: integer m and n, 1 <= m <= n,
 * guardians.length === n, unique guardian_ids, and canonical distinct public
 * keys. Throws GuardianRosterError on any violation.
 */
export function assertValidRosterShape(params: {
  m: number;
  n: number;
  guardians: GuardianIdentity[];
}): void {
  validateRosterShape(params);
}

/**
 * Non-throwing predicate form of assertValidRosterShape. Returns true only when
 * the roster body satisfies every shape invariant. Callers that must not throw
 * (for example a pure evaluator that returns a fail-closed result object) use
 * this to reject a malformed roster before comparing an approval count against
 * m, so a degenerate roster such as m=0 can never report threshold_met.
 */
export function isValidRosterShape(params: {
  m: number;
  n: number;
  guardians: GuardianIdentity[];
}): boolean {
  try {
    validateRosterShape(params);
    return true;
  } catch {
    return false;
  }
}

function validateRosterShape(params: {
  m: number;
  n: number;
  guardians: GuardianIdentity[];
}): void {
  if (
    !Number.isInteger(params.m) ||
    !Number.isInteger(params.n) ||
    params.m < 1 ||
    params.n < 1 ||
    params.m > params.n
  ) {
    throw new GuardianRosterError(
      `invalid M-of-N: m=${params.m} n=${params.n}; require 1 ≤ m ≤ n`
    );
  }
  if (params.guardians.length !== params.n) {
    throw new GuardianRosterError(
      `guardian list length=${params.guardians.length} does not match n=${params.n}`
    );
  }
  const seen = new Set<string>();
  const seenKeys = new Set<string>();
  for (const g of params.guardians) {
    if (seen.has(g.guardian_id)) {
      throw new GuardianRosterError(
        `duplicate guardian_id in roster: ${g.guardian_id}`
      );
    }
    seen.add(g.guardian_id);
    // Fail closed on a shared public key across distinct guardian_ids. Without
    // this, one key holder can occupy multiple guardian slots under different
    // ids and satisfy M-of-N alone (approval signatures bind the signing input
    // and the guardian's key, not the guardian_id), collapsing the quorum's
    // independence assumption. Each guardian must hold a distinct key. The
    // uniqueness key is the CANONICAL decoded form, not the raw string, so a
    // non-canonical re-spelling of one key cannot pass as a distinct guardian.
    const canonicalKey = canonicalGuardianKey(g.public_key);
    if (seenKeys.has(canonicalKey)) {
      throw new GuardianRosterError(
        `duplicate guardian public_key in roster: guardian_id ${g.guardian_id} reuses a key already assigned to another guardian`
      );
    }
    seenKeys.add(canonicalKey);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Verification (receiver-side)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Verify a GuardianRoster against the pinned fortress-master public key.
 *
 * Throws on shape violation, fortress-id mismatch, unknown signature_scheme,
 * or master-signature failure.
 *
 * v1.0 receivers tolerate guardians whose `kind` is unknown (forward-compat
 * for v1.x institutional-custody integration). The check is at issuance time
 * only.
 */
export function verifyGuardianRoster(
  roster: GuardianRoster,
  pinnedMaster: FortressMasterPublicKey
): void {
  validateRosterShape({
    m: roster.m,
    n: roster.n,
    guardians: roster.guardians,
  });
  if (roster.fortress_id !== pinnedMaster.fortress_id) {
    throw new GuardianRosterError(
      `roster fortress_id=${roster.fortress_id} does not match pinned master fortress_id=${pinnedMaster.fortress_id} — cross-operator isolation invariant`
    );
  }
  if (roster.signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new GuardianRosterError(
      `unknown signature_scheme=${roster.signature_scheme}; v1.0 verifier accepts only ${SIGNATURE_SCHEME_V1}`
    );
  }
  if (!Number.isInteger(roster.version) || roster.version < 1) {
    throw new GuardianRosterError(
      `roster version must be a positive integer; got ${roster.version}`
    );
  }
  const body = {
    m: roster.m,
    n: roster.n,
    guardians: roster.guardians,
    signature_scheme: roster.signature_scheme,
    version: roster.version,
    created_at: roster.created_at,
    fortress_id: roster.fortress_id,
  };
  const ok = ed25519.verify(
    fromBase64url(roster.master_signature),
    canonicalizeToBytes(body),
    fromBase64url(pinnedMaster.public_key)
  );
  if (!ok) {
    throw new GuardianRosterSignatureError(
      `guardian-roster master_signature does not verify against pinned fortress-master`
    );
  }
}

/**
 * Verify an M-or-more guardian quorum signed over a master-rotation input.
 *
 * Verification rules:
 *   1. `proof.roster_version === pinnedRoster.version` (no stale-roster).
 *   2. Each `signatures[i].guardian_id` resolves to exactly one entry in the
 *      pinned roster (no unknown guardians).
 *   3. Distinct `guardian_id`s across signatures (no double-counting).
 *   4. At least `M` signatures present.
 *   5. Each Ed25519 signature verifies against the matching guardian pubkey
 *      over `canonicalize(input)`.
 *
 * Throws GuardianQuorumError on any failure.
 */
export function verifyGuardianQuorum(params: {
  input: MasterRotationQuorumInput;
  proof: GuardianQuorumProof;
  pinned_roster: GuardianRoster;
}): void {
  const { input, proof, pinned_roster: roster } = params;
  // Fail-closed shape gate: this evaluator compares proof.signatures.length and
  // validCount against roster.m/roster.n, so a structurally invalid pinned
  // roster must be rejected BEFORE any threshold comparison, not assumed to have
  // been screened at issuance. A degenerate roster (m=0, or m>n, or
  // guardians.length !== n, or duplicate ids/keys) would otherwise let the
  // empty-signature path pass: with m=0 and an empty proof, `0 < 0` is false and
  // `validCount(0) < m(0)` is false, returning success with zero guardian
  // signatures. validateRosterShape is the SAME shape contract issuance enforces;
  // running it first closes this class at the boundary for the master-rotation
  // quorum path (the recovery threshold path guards with the same contract via
  // isValidRosterShape). Throws GuardianRosterError on any violation.
  validateRosterShape({ m: roster.m, n: roster.n, guardians: roster.guardians });
  if (proof.roster_version !== roster.version) {
    throw new GuardianQuorumError(
      `quorum proof roster_version=${proof.roster_version} != pinned roster version=${roster.version}`
    );
  }
  if (proof.signatures.length < roster.m) {
    throw new GuardianQuorumError(
      `quorum requires ≥${roster.m} signatures; got ${proof.signatures.length}`
    );
  }
  const seen = new Set<string>();
  const seenKeys = new Set<string>();
  const byId = new Map<string, GuardianIdentity>();
  for (const g of roster.guardians) byId.set(g.guardian_id, g);

  let validCount = 0;
  const signedBytes = canonicalizeToBytes(input);
  for (const sig of proof.signatures) {
    if (seen.has(sig.guardian_id)) {
      throw new GuardianQuorumError(
        `duplicate guardian_id in quorum proof: ${sig.guardian_id}`
      );
    }
    seen.add(sig.guardian_id);
    const guardian = byId.get(sig.guardian_id);
    if (!guardian) {
      throw new GuardianQuorumError(
        `quorum signature from unknown guardian ${sig.guardian_id}; not in pinned roster v${roster.version}`
      );
    }
    // Fail closed on a shared public key across distinct guardian_ids within a
    // single proof. verifyGuardianRoster already rejects such rosters, but this
    // is defense in depth for a proof evaluated against a roster that skipped
    // that path: one key must not be counted toward the quorum more than once.
    // Compare on the CANONICAL decoded key so a non-canonical re-spelling of one
    // key cannot slip a second slot past this counter.
    let quorumKey: string;
    try {
      quorumKey = canonicalGuardianKey(guardian.public_key);
    } catch {
      throw new GuardianQuorumError(
        `guardian ${sig.guardian_id} has a non-canonical or malformed public key in the pinned roster`
      );
    }
    if (seenKeys.has(quorumKey)) {
      throw new GuardianQuorumError(
        `guardian ${sig.guardian_id} reuses a public key already counted in this quorum proof`
      );
    }
    seenKeys.add(quorumKey);
    const ok = ed25519.verify(
      fromBase64url(sig.signature),
      signedBytes,
      fromBase64url(guardian.public_key)
    );
    if (!ok) {
      throw new GuardianQuorumError(
        `guardian ${sig.guardian_id} signature does not verify`
      );
    }
    validCount += 1;
  }
  if (validCount < roster.m) {
    throw new GuardianQuorumError(
      `valid signature count ${validCount} below threshold m=${roster.m}`
    );
  }
}

/**
 * Sign a master-rotation input as one guardian. Helper for the reconstitution
 * ceremony; production callers running the ceremony on a separate signing
 * device produce these signatures out-of-band and assemble the proof.
 */
export function signMasterRotationAsGuardian(params: {
  input: MasterRotationQuorumInput;
  guardian_id: string;
  guardian_private_key: Uint8Array;
}): { guardian_id: string; signature: string } {
  const sig = ed25519.sign(
    canonicalizeToBytes(params.input),
    params.guardian_private_key
  );
  return {
    guardian_id: params.guardian_id,
    signature: toBase64url(sig),
  };
}
