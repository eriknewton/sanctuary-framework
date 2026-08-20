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
import { parseIsoInstantWithOffset } from "../../core/time.js";
import { canonicalizeToBytes } from "../canonical-json.js";
import { SIGNATURE_SCHEME_V1, type NodeMode } from "../constants.js";
import { MeshError } from "../errors.js";
import type { PrincipalCertificate } from "../types.js";
import { BOOTSTRAP_TOKEN_TTL_MS } from "./constants.js";
import type { BootstrapToken } from "./types.js";
import { describeUntrusted } from "../../errors/index.js";

export class MeshBootstrapTokenError extends MeshError {
  constructor(message: string) {
    super(message);
    this.name = "MeshBootstrapTokenError";
  }
}

type BootstrapTokenSnapshot = Readonly<BootstrapToken>;

// Must match NodeMode in ../constants.ts: the verifier rejects values outside
// the protocol's closed node-mode wire contract before canonical verification.
const BOOTSTRAP_TOKEN_NODE_MODES: readonly NodeMode[] = [
  "local",
  "operator_cloud",
  "sovereign_tee",
];

function isBootstrapTokenNodeMode(value: string): value is NodeMode {
  return BOOTSTRAP_TOKEN_NODE_MODES.includes(value as NodeMode);
}

/**
 * Read a wire token exactly once into plain strings before verification.
 *
 * The caller's TypeScript annotation is not evidence: this boundary receives
 * decoded network data, whose properties can be stateful accessors or a Proxy.
 * Every later trust decision reads this new object only, so a single signed
 * snapshot is what expiry, principal binding, and canonical bytes all mean.
 */
function snapshotBootstrapToken(value: unknown): BootstrapTokenSnapshot {
  let intended_node_id: unknown;
  let intended_node_mode: unknown;
  let fortress_id: unknown;
  let issuing_principal: unknown;
  let issued_at: unknown;
  let expires_at: unknown;
  let nonce: unknown;
  let signature_scheme: unknown;
  let signature: unknown;

  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error("bootstrap token is not an object");
    }
    const wire = value as Record<string, unknown>;
    // Read each field once: later validation and verification must not revisit
    // an attacker-owned accessor after this stable copy exists.
    ({
      intended_node_id,
      intended_node_mode,
      fortress_id,
      issuing_principal,
      issued_at,
      expires_at,
      nonce,
      signature_scheme,
      signature,
    } = wire);
  } catch {
    throw new MeshBootstrapTokenError("bootstrap token has an unreadable wire shape");
  }

  if (
    typeof intended_node_id !== "string" ||
    typeof intended_node_mode !== "string" ||
    typeof fortress_id !== "string" ||
    typeof issuing_principal !== "string" ||
    typeof issued_at !== "string" ||
    typeof expires_at !== "string" ||
    typeof nonce !== "string" ||
    typeof signature_scheme !== "string" ||
    typeof signature !== "string"
  ) {
    throw new MeshBootstrapTokenError(
      "bootstrap token has a missing or wrong-type required field"
    );
  }
  if (!isBootstrapTokenNodeMode(intended_node_mode)) {
    throw new MeshBootstrapTokenError("bootstrap token has an unknown intended_node_mode");
  }
  if (signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new MeshBootstrapTokenError(
      `bootstrap token signature_scheme must be ${SIGNATURE_SCHEME_V1}`
    );
  }

  return Object.freeze({
    intended_node_id,
    intended_node_mode,
    fortress_id,
    issuing_principal,
    issued_at,
    expires_at,
    nonce,
    signature_scheme,
    signature,
  });
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
    signature_scheme: SIGNATURE_SCHEME_V1,
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
  const token = snapshotBootstrapToken(params.token);
  // Trust arithmetic accepts only the shared strict offset-bearing instant;
  // a wrong-type or ambiguous wire timestamp must fail before signature work.
  const expiresAtMs = parseIsoInstantWithOffset(token.expires_at);
  if (
    parseIsoInstantWithOffset(token.issued_at) === undefined ||
    expiresAtMs === undefined
  ) {
    throw new MeshBootstrapTokenError(
      "bootstrap token issued_at and expires_at must be strict ISO instants with an offset"
    );
  }

  const now = params.now_ms ?? Date.now();
  if (token.fortress_id !== params.expected_fortress_id) {
    throw new MeshBootstrapTokenError(
      `bootstrap token fortress_id=${describeUntrusted(token.fortress_id)} does not match expected ${params.expected_fortress_id}`
    );
  }
  if (
    token.issuing_principal !==
    params.issuing_principal_cert.principal_id
  ) {
    throw new MeshBootstrapTokenError(
      `bootstrap token issuing_principal=${describeUntrusted(token.issuing_principal)} does not match principal cert ${params.issuing_principal_cert.principal_id}`
    );
  }
  if (expiresAtMs < now) {
    throw new MeshBootstrapTokenError(
      `bootstrap token expired at ${describeUntrusted(token.expires_at)}`
    );
  }
  const body: Omit<BootstrapToken, "signature"> = {
    intended_node_id: token.intended_node_id,
    intended_node_mode: token.intended_node_mode,
    fortress_id: token.fortress_id,
    issuing_principal: token.issuing_principal,
    issued_at: token.issued_at,
    expires_at: token.expires_at,
    nonce: token.nonce,
    signature_scheme: token.signature_scheme,
  };
  let ok: boolean;
  try {
    ok = ed25519.verify(
      fromBase64url(token.signature),
      canonicalizeToBytes(body),
      fromBase64url(params.issuing_principal_cert.principal_pubkey)
    );
  } catch {
    throw new MeshBootstrapTokenError("bootstrap token signature encoding is invalid");
  }
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
