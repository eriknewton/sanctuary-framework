/**
 * Bootstrap token issuance + verification (§3.1).
 *
 * Short-lived (15-minute default) signed token from the operator's principal
 * key, carrying the right to submit a JoinRequest. The token alone does not
 * grant membership — operator approval at the gate is mandatory.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { fromBase64url, toBase64url } from "../../core/encoding.js";
import { randomBytes } from "../../core/random.js";
import { canonicalizeToBytes } from "../canonical-json.js";
import type { NodeMode } from "../constants.js";
import { MeshError } from "../errors.js";
import type { PrincipalCertificate } from "../types.js";
import { BOOTSTRAP_TOKEN_TTL_MS } from "./constants.js";
import type { BootstrapToken } from "./types.js";

export class MeshBootstrapTokenError extends MeshError {
  constructor(message: string) {
    super(message);
    this.name = "MeshBootstrapTokenError";
  }
}

export function issueBootstrapToken(params: {
  intended_node_id: string;
  intended_node_mode: NodeMode;
  fortress_id: string;
  issuing_principal: string;
  principal_private_key: Uint8Array;
  ttl_ms?: number;
}): BootstrapToken {
  const ttl = params.ttl_ms ?? BOOTSTRAP_TOKEN_TTL_MS;
  const now = Date.now();
  const body: Omit<BootstrapToken, "signature"> = {
    intended_node_id: params.intended_node_id,
    intended_node_mode: params.intended_node_mode,
    fortress_id: params.fortress_id,
    issuing_principal: params.issuing_principal,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttl).toISOString(),
    nonce: toBase64url(randomBytes(16)),
  };
  const sig = ed25519.sign(
    canonicalizeToBytes(body),
    params.principal_private_key
  );
  return { ...body, signature: toBase64url(sig) };
}

export function verifyBootstrapToken(params: {
  token: BootstrapToken;
  expected_fortress_id: string;
  issuing_principal_cert: PrincipalCertificate;
  now_ms?: number;
}): void {
  const now = params.now_ms ?? Date.now();
  if (params.token.fortress_id !== params.expected_fortress_id) {
    throw new MeshBootstrapTokenError(
      `bootstrap token fortress_id=${params.token.fortress_id} does not match expected ${params.expected_fortress_id}`
    );
  }
  if (
    params.token.issuing_principal !==
    params.issuing_principal_cert.principal_id
  ) {
    throw new MeshBootstrapTokenError(
      `bootstrap token issuing_principal=${params.token.issuing_principal} does not match principal cert ${params.issuing_principal_cert.principal_id}`
    );
  }
  if (Date.parse(params.token.expires_at) < now) {
    throw new MeshBootstrapTokenError(
      `bootstrap token expired at ${params.token.expires_at}`
    );
  }
  const body: Omit<BootstrapToken, "signature"> = {
    intended_node_id: params.token.intended_node_id,
    intended_node_mode: params.token.intended_node_mode,
    fortress_id: params.token.fortress_id,
    issuing_principal: params.token.issuing_principal,
    issued_at: params.token.issued_at,
    expires_at: params.token.expires_at,
    nonce: params.token.nonce,
  };
  const ok = ed25519.verify(
    fromBase64url(params.token.signature),
    canonicalizeToBytes(body),
    fromBase64url(params.issuing_principal_cert.principal_pubkey)
  );
  if (!ok) {
    throw new MeshBootstrapTokenError(
      "bootstrap token signature does not verify against issuing principal"
    );
  }
}

/**
 * Compute the hkdf_salt_proof for a JoinRequest.
 *
 * HMAC over canonicalize({intended_node_id, node_mode}) using the per-node
 * transport key (HKDF-derived from the master). Defeats an attacker who steals
 * a bootstrap token but does not hold the master secret — the HKDF-derived
 * transport key is required to forge this proof.
 */
export function computeJoinHkdfSaltProof(params: {
  intended_node_id: string;
  node_mode: NodeMode;
  node_transport_key: Uint8Array;
}): string {
  const input = canonicalizeToBytes({
    intended_node_id: params.intended_node_id,
    node_mode: params.node_mode,
  });
  return toBase64url(hmac(sha256, params.node_transport_key, input));
}

/** Verifier-side check of the hkdf_salt_proof. */
export function verifyJoinHkdfSaltProof(params: {
  intended_node_id: string;
  node_mode: NodeMode;
  node_transport_key: Uint8Array;
  proof: string;
}): boolean {
  const expected = computeJoinHkdfSaltProof({
    intended_node_id: params.intended_node_id,
    node_mode: params.node_mode,
    node_transport_key: params.node_transport_key,
  });
  return expected === params.proof;
}
