/**
 * Sanctuary Federation Protocol v0.1 — Guardian + Recovery Cascade Types
 *
 * Spec §9 (recovery cascade), Architecture Walk Key 13 (M-of-N guardian quorum
 * + DMswitch + master rotation).
 *
 * Wire-shape note: every field below is JSON-serializable and signature-stable
 * under the canonical-JSON rules of mesh/canonical-json.ts. Adding fields
 * requires a spec amendment. v1.x extension fields (e.g., crypto-custody
 * adapter slots) MUST land via the same `extension` pattern as the mesh
 * envelope's `extension_envelope`, not as new top-level fields.
 */

import type { SignatureScheme } from "../constants.js";
import type { FortressMasterPublicKey } from "../types.js";

/**
 * Single guardian's identity within an M-of-N roster.
 *
 * `kind` is a string (not a strict enum on the type) to admit forward-compat
 * for v1.x institutional-custody integration. v1.0 ISSUERS MUST set kind to
 * one of the two values in `GUARDIAN_KINDS_V1_0`; v1.0 verifiers tolerate
 * unknown kinds (forward-compat).
 *
 * `public_key` is a base64url-encoded Ed25519 public key (32 bytes raw).
 */
export interface GuardianIdentity {
  guardian_id: string;
  public_key: string;
  kind: string;
  invited_at: string;
}

/**
 * The fortress-master-signed guardian-roster certificate set.
 *
 * Distributed to every node at federation-bootstrap and on every change.
 * Versioned per-fortress; receivers pin highest-seen version.
 *
 * Signature is computed by the fortress-master private key over the canonical-
 * JSON serialization of `{m, n, guardians, signature_scheme, version,
 * created_at, fortress_id}` — i.e., the body excluding the signature itself.
 */
export interface GuardianRoster {
  m: number;
  n: number;
  guardians: GuardianIdentity[];
  signature_scheme: SignatureScheme;
  version: number;
  created_at: string;
  fortress_id: string;
  master_signature: string;
}

/**
 * One guardian's signature over a master-rotation event.
 *
 * The signature is Ed25519 over the canonical-JSON encoding of
 * `{rotation_payload_hash, rotated_at, fortress_id, new_master_pubkey,
 * old_master_pubkey}`. Aggregating M of these signatures forms a quorum.
 */
export interface GuardianQuorumSignature {
  guardian_id: string;
  signature: string;
}

/**
 * The guardian-quorum proof attached to a master-rotation event.
 *
 * Receivers verify each `signatures[i]` against the corresponding
 * `GuardianIdentity.public_key` from the pinned `GuardianRoster`. At least M
 * distinct guardians must sign for the rotation to be accepted.
 *
 * `roster_version` MUST equal the pinned guardian-roster version on the
 * receiving node. If the roster has been rotated since rotation-prep
 * (rare), the receiver rejects and surfaces the stale-roster condition for
 * operator decision.
 */
export interface GuardianQuorumProof {
  roster_version: number;
  signatures: GuardianQuorumSignature[];
}

/**
 * DISTINCT FROM the master-rotation quorum input, despite the name.
 *
 * QI-SIBLING-02 moved master rotation onto `GuardianMasterRotationQuorumInput`
 * in `guardian/revoke-quorum-input.ts`, which carries a domain separator and a
 * collection window. This v1 shape has neither and now serves exactly ONE
 * remaining consumer: `canonicalAuditPromoteQuorumInput` in
 * `recovery-flows/canonical-audit-promotion.ts`, which reuses the field slots to
 * carry `canonical_audit:<id>` strings rather than timestamps and keys. The name
 * is kept because that consumer's own v2 shape is a separate change; do NOT
 * reach for this type for a new ceremony.
 *
 * Its field set is disjoint from the v2 shape's (no `schema`, no window), and
 * `canonicalizeToBytes` is field-name-bearing, so bytes signed under one can
 * never verify as the other.
 */
export interface MasterRotationQuorumInput {
  old_master_pubkey: string;
  new_master_pubkey: FortressMasterPublicKey;
  rotated_at: string;
  fortress_id: string;
}
