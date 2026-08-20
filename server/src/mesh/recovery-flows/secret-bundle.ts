/**
 * Master-rotation secret bundle.
 *
 * During a master-rotation ceremony the initiator (the node running the
 * orchestrator) must deliver three pieces of state to every peer:
 *   - the NEW fortress-master secret (so each peer can re-derive its HKDF
 *     subkeys: audit-chain, transport, and wrap keys);
 *   - the peer's re-issued NodeIdentityCertificate (signed under the new
 *     master + new root principal);
 *   - the new root-principal certificate (so the peer can verify its cert's
 *     chain end-to-end).
 *
 * The bundle is AES-256-GCM-wrapped under the peer's OLD per-node transport
 * key (HKDF of the OLD fortress-master against the peer's node_id + mode).
 * Only a peer that already holds the old master material can unwrap. This
 * prevents a passive network observer from harvesting the new master secret
 * and guarantees the bundle cannot be redirected to a node that was not in
 * the pre-rotation roster.
 *
 * Spec note: this is an orchestration-layer mechanism, not a federation
 * protocol wire shape. The federation protocol's `master_rotation` SignedEvent
 * broadcast still carries only the public proof (old master pubkey + new
 * master pubkey + guardian quorum). The secret bundle flows over the shipped
 * MeshTransport.unicast path with an orchestration-layer message kind. The
 * WP-MVP-8 handoff flags this as a candidate for v0.1.1 spec surface.
 */

import { toBase64url, fromBase64url, stringToBytes } from "../../core/encoding.js";
import { encrypt, decrypt, type EncryptedPayload } from "../../core/encryption.js";
import type { NodeMode } from "../constants.js";
import { deriveNodeTransportKey } from "../trust-root.js";
import type {
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../types.js";
import { SecretBundleError } from "./errors.js";
// the bundle plaintext is `JSON.parse`d after decryption, so its fields are
// peer-supplied; diagnostics go through the untrusted-diagnostic chokepoint
// (STATE-STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../../errors/index.js";

/** Plaintext bundle payload, pre-wrap. */
export interface MasterRotationBundlePlaintext {
  /** Base64url-encoded NEW fortress-master secret (32 bytes raw Ed25519 seed). */
  new_master_secret: string;
  /** Re-issued NodeIdentityCertificate for the target peer. */
  re_issued_self_cert: NodeIdentityCertificate;
  /** New root-principal certificate the re-issued cert chains through. */
  new_root_principal_cert: PrincipalCertificate;
  /** ISO8601 rotated_at from the master-rotation ceremony (binds the bundle to the rotation). */
  rotated_at: string;
  /** Base64url-encoded NEW master pubkey (binds the bundle to a specific rotation). */
  new_master_pubkey: string;
}

/** Wire form — what travels on the unicast path. */
export interface MasterRotationBundleEnvelope {
  kind: "master_rotation_bundle";
  /** Target peer's node_id. Receiver checks this matches its own id before unwrapping. */
  target_node_id: string;
  /** Fortress id for cross-operator isolation. */
  fortress_id: string;
  /** Wrapped ciphertext of `MasterRotationBundlePlaintext`. */
  ciphertext: EncryptedPayload;
  /** ISO8601 rotated_at from the rotation payload. */
  rotated_at: string;
  /** Base64url-encoded NEW master pubkey (unencrypted for receiver routing). */
  new_master_pubkey: string;
}

/** Why a wire envelope was refused. Closed set; each names one field. */
export type MasterRotationBundleEnvelopeParseFailure =
  | "envelope_not_object"
  | "kind_invalid"
  | "target_node_id_not_string"
  | "fortress_id_not_string"
  | "rotated_at_not_string"
  | "new_master_pubkey_not_string"
  | "ciphertext_not_object"
  | "ciphertext_field_invalid"
  // Reading a field threw: an exotic object (a Proxy, a throwing accessor).
  // Not reachable from `JSON.parse` output, but this function is exported and
  // a parse that can throw fails open at the very boundary it defines.
  | "envelope_unreadable";

export type MasterRotationBundleEnvelopeParseResult =
  | { ok: true; envelope: MasterRotationBundleEnvelope }
  | { ok: false; reason: MasterRotationBundleEnvelopeParseFailure };

/**
 * THE element-level parse for a wire master-rotation bundle envelope, and the
 * only agreement between the unicast receiver and this unwrapper (AGENTS.md
 * rule 11: one shared schema whose typed result IS the contract, never two
 * hand-mirrored validators that can drift).
 *
 * WHY THIS IS A PARSE AND NOT A CAST: the envelope arrives as arbitrary JSON
 * off the unicast path, so `MasterRotationBundleEnvelope` is an assertion about
 * bytes an attacker chose. Its fields are consumed in COMPARISONS and in AAD
 * CONSTRUCTION before anything is authenticated, and both coerce with String().
 * A deeply nested value there overflows the stack inside the comparison itself,
 * so the receiver fails with an unrelated RangeError instead of the typed
 * cross-operator-isolation refusal it correctly reached (defect
 * STATE-STORE-ERRMSG-INTERP-01, wire variant). Bounding the MESSAGE is not
 * enough when the value is consumed before the message is built; the shape has
 * to be established first.
 *
 * SCOPE, stated so a later reader does not over-trust this: the result is a
 * validated view of the ORIGINAL object, not a copied snapshot, and callers
 * still re-read fields off it. A stateful accessor can therefore satisfy this
 * parse and return something else on a later read. Closing that, and the
 * matching gaps on the decrypted plaintext and on the bootstrap-token path, is
 * separate tracked work; this function does not claim to have closed it.
 */
export function parseMasterRotationBundleEnvelope(
  value: unknown
): MasterRotationBundleEnvelopeParseResult {
  try {
    return parseEnvelopeFields(value);
  } catch {
    return { ok: false, reason: "envelope_unreadable" };
  }
}

function parseEnvelopeFields(
  value: unknown
): MasterRotationBundleEnvelopeParseResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, reason: "envelope_not_object" };
  }
  const raw = value as Record<string, unknown>;
  if (raw.kind !== "master_rotation_bundle") {
    return { ok: false, reason: "kind_invalid" };
  }
  if (typeof raw.target_node_id !== "string") {
    return { ok: false, reason: "target_node_id_not_string" };
  }
  if (typeof raw.fortress_id !== "string") {
    return { ok: false, reason: "fortress_id_not_string" };
  }
  if (typeof raw.rotated_at !== "string") {
    return { ok: false, reason: "rotated_at_not_string" };
  }
  if (typeof raw.new_master_pubkey !== "string") {
    return { ok: false, reason: "new_master_pubkey_not_string" };
  }
  const ciphertext = raw.ciphertext;
  if (ciphertext === null || typeof ciphertext !== "object" || Array.isArray(ciphertext)) {
    return { ok: false, reason: "ciphertext_not_object" };
  }
  const payload = ciphertext as Record<string, unknown>;
  // Exactly the fields `decrypt` consumes: it compares `v`/`alg` and
  // base64url-decodes `iv`/`ct`, and a non-string there is a raw TypeError one
  // frame later. `ts` is documented envelope metadata that no security decision
  // reads, so requiring it here would reject valid bundles for no gain - the
  // check must match what the consumer actually touches (must stay in step with
  // `EncryptedPayload` and `decrypt` in `core/encryption.ts`).
  if (
    typeof payload.v !== "number" ||
    typeof payload.alg !== "string" ||
    typeof payload.iv !== "string" ||
    typeof payload.ct !== "string"
  ) {
    return { ok: false, reason: "ciphertext_field_invalid" };
  }
  return { ok: true, envelope: raw as unknown as MasterRotationBundleEnvelope };
}

/**
 * AAD string bound into the AES-GCM tag so a bundle cannot be replayed at a
 * different rotated_at or re-targeted at a different peer.
 */
function bundleAad(params: {
  target_node_id: string;
  fortress_id: string;
  rotated_at: string;
  new_master_pubkey: string;
}): Uint8Array {
  return stringToBytes(
    "sanctuary-recovery-flows-v0.1-master-rotation-bundle|" +
      params.fortress_id +
      "|" +
      params.target_node_id +
      "|" +
      params.rotated_at +
      "|" +
      params.new_master_pubkey
  );
}

/**
 * Wrap a `MasterRotationBundlePlaintext` for delivery to `target_node_id`.
 *
 * The wrapping key is the OLD fortress-master-derived transport key for the
 * target peer. Caller supplies the OLD master secret transiently; it is not
 * retained by this function.
 */
export function wrapMasterRotationBundle(params: {
  plaintext: MasterRotationBundlePlaintext;
  old_fortress_master_secret: Uint8Array;
  target_node_id: string;
  target_node_mode: NodeMode;
  fortress_id: string;
}): MasterRotationBundleEnvelope {
  if (params.plaintext.rotated_at.length === 0) {
    throw new SecretBundleError("rotated_at must be non-empty");
  }
  if (params.plaintext.new_master_pubkey.length === 0) {
    throw new SecretBundleError("new_master_pubkey must be non-empty");
  }
  const wrappingKey = deriveNodeTransportKey({
    fortress_master_secret: params.old_fortress_master_secret,
    node_id: params.target_node_id,
    node_mode: params.target_node_mode,
  });
  const aad = bundleAad({
    target_node_id: params.target_node_id,
    fortress_id: params.fortress_id,
    rotated_at: params.plaintext.rotated_at,
    new_master_pubkey: params.plaintext.new_master_pubkey,
  });
  const bytes = stringToBytes(JSON.stringify(params.plaintext));
  const ciphertext = encrypt(bytes, wrappingKey, aad);
  return {
    kind: "master_rotation_bundle",
    target_node_id: params.target_node_id,
    fortress_id: params.fortress_id,
    ciphertext,
    rotated_at: params.plaintext.rotated_at,
    new_master_pubkey: params.plaintext.new_master_pubkey,
  };
}

/**
 * Unwrap a `MasterRotationBundleEnvelope` on the receiver side.
 *
 * Throws `SecretBundleError` on any mismatch (target_node_id, fortress_id,
 * AAD failure). The receiver MUST verify:
 *   - `envelope.target_node_id === this_node_id`
 *   - `envelope.fortress_id === this_fortress_id`
 *   - The unwrapped plaintext's `new_master_pubkey` matches the envelope's.
 *   - The unwrapped re-issued cert's `node_id === this_node_id`.
 *
 * AAD authentication defends against cross-peer replay and cross-rotation
 * replay; the additional in-body checks defend against a compromised relay
 * that swaps the envelope target before delivery.
 */
export function unwrapMasterRotationBundle(params: {
  envelope: MasterRotationBundleEnvelope;
  old_fortress_master_secret: Uint8Array;
  this_node_id: string;
  this_node_mode: NodeMode;
  this_fortress_id: string;
}): MasterRotationBundlePlaintext {
  // Establish the SHAPE before any field is compared or folded into the AAD.
  // This function is exported and reachable directly, so it re-parses rather
  // than trusting that its caller did: the parse is O(1) field checks, and a
  // caller that casts instead is the shape this exists to prevent.
  const parsed = parseMasterRotationBundleEnvelope(params.envelope);
  if (!parsed.ok) {
    throw new SecretBundleError(
      `master_rotation_bundle envelope is malformed (${parsed.reason})`
    );
  }
  const envelope = parsed.envelope;

  if (envelope.target_node_id !== params.this_node_id) {
    throw new SecretBundleError(
      `master_rotation_bundle target_node_id=${describeUntrusted(envelope.target_node_id)} does not match this node ${params.this_node_id}`
    );
  }
  if (envelope.fortress_id !== params.this_fortress_id) {
    throw new SecretBundleError(
      `master_rotation_bundle fortress_id=${describeUntrusted(envelope.fortress_id)} does not match this fortress ${params.this_fortress_id} (cross-operator isolation)`
    );
  }
  const wrappingKey = deriveNodeTransportKey({
    fortress_master_secret: params.old_fortress_master_secret,
    node_id: params.this_node_id,
    node_mode: params.this_node_mode,
  });
  const aad = bundleAad({
    target_node_id: params.this_node_id,
    fortress_id: params.this_fortress_id,
    rotated_at: envelope.rotated_at,
    new_master_pubkey: envelope.new_master_pubkey,
  });
  let plaintextBytes: Uint8Array;
  try {
    plaintextBytes = decrypt(envelope.ciphertext, wrappingKey, aad);
  } catch (e) {
    throw new SecretBundleError(
      `master_rotation_bundle AES-GCM authentication failed: ${e instanceof Error ? e.message : String(e)}`
    );
  }
  let plaintext: MasterRotationBundlePlaintext;
  try {
    const decoder = new TextDecoder();
    plaintext = JSON.parse(decoder.decode(plaintextBytes));
  } catch (e) {
    throw new SecretBundleError(
      `master_rotation_bundle plaintext is not valid JSON: ${e instanceof Error ? e.message : String(e)}`
    );
  }
  if (plaintext.new_master_pubkey !== envelope.new_master_pubkey) {
    throw new SecretBundleError(
      `master_rotation_bundle plaintext new_master_pubkey does not match envelope`
    );
  }
  if (plaintext.rotated_at !== envelope.rotated_at) {
    throw new SecretBundleError(
      `master_rotation_bundle plaintext rotated_at does not match envelope`
    );
  }
  // The plaintext is AES-GCM authenticated, so its author held the key - but
  // authenticity is not shape. Dereferencing an absent or non-object
  // `re_issued_self_cert` here is a raw TypeError where a typed refusal
  // belongs (AGENTS.md rule 11).
  const selfCert = plaintext.re_issued_self_cert;
  if (selfCert === null || typeof selfCert !== "object") {
    throw new SecretBundleError(
      `master_rotation_bundle plaintext re_issued_self_cert is malformed`
    );
  }
  if (selfCert.node_id !== params.this_node_id) {
    throw new SecretBundleError(
      `master_rotation_bundle re_issued_self_cert.node_id=${describeUntrusted(selfCert.node_id)} does not match this node ${params.this_node_id}`
    );
  }
  return plaintext;
}

/**
 * Convert base64url-encoded secret to raw bytes + back. These are thin
 * wrappers over `core/encoding` so callers building/unwrapping bundles do not
 * have to import from two places.
 */
export const toBundleSecret = (bytes: Uint8Array): string => toBase64url(bytes);
export const fromBundleSecret = (s: string): Uint8Array => fromBase64url(s);
