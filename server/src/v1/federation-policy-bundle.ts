/**
 * Signed operator policy-bundle event for the v1 federation rail.
 *
 * The event carries only the Principal Policy version and SHA-256 hash. It never
 * carries raw policy rules, approval-channel secrets, or private key material.
 * Accepting the event updates a derived version projection only after the
 * operator-principal signature verifies through the pinned federation master.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import { verifyPrincipalCertificate } from "../mesh/trust-root.js";
import type {
  FortressMasterPublicKey,
  PrincipalCertificate,
} from "../mesh/types.js";
import { canonicalJson } from "./operator-signed.js";
import { ED25519_SIGNATURE_BYTES } from "../core/crypto-suite-registry.js";

export const FEDERATION_POLICY_BUNDLE_EVENT_KIND =
  "operator_policy_bundle" as const;
export const FEDERATION_POLICY_BUNDLE_EVENT_VERSION =
  "sanctuary.v1.operator-policy-bundle" as const;
export const FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM =
  "sha256-base64url" as const;
export const V1_FEDERATION_POLICY_BUNDLE_DOMAIN =
  "sanctuary.v1.federation-policy-bundle" as const;

const SHA256_BASE64URL_RE = /^[A-Za-z0-9_-]{43}$/;
const POLICY_BUNDLE_PAYLOAD_KEYS = new Set([
  "event_version",
  "fortress_id",
  "policy_version",
  "policy_hash",
  "policy_hash_algorithm",
  "signed_at",
  "operator_principal_id",
  "operator_signature",
]);

export interface FederationPolicyBundlePayload {
  event_version: typeof FEDERATION_POLICY_BUNDLE_EVENT_VERSION;
  fortress_id: string;
  policy_version: number;
  policy_hash: string;
  policy_hash_algorithm: typeof FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM;
  signed_at: string;
  operator_principal_id: string;
  operator_signature: string;
}

export interface FederationPolicyBundleLogEvent {
  event_id: string;
  origin_node_id: string;
  sequence: number;
  occurred_at: string;
  kind: string;
  payload: Record<string, unknown>;
  previous_hash: string | null;
  event_hash: string;
}

export interface FederationAppliedPolicyVersion {
  version: number;
  hash: string;
  hash_algorithm: typeof FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM;
  applied_at: string;
  source_event_id: string;
}

export interface FederationPolicyProjection {
  current: FederationAppliedPolicyVersion | null;
  appliedByNode: Map<string, FederationAppliedPolicyVersion>;
}

export type FederationPolicyBundleVerification =
  | {
      ok: true;
      policyVersion: number;
      policyHash: string;
      payload: FederationPolicyBundlePayload;
    }
  | { ok: false; reason: FederationPolicyBundleRejectionReason };

export type FederationPolicyBundleRejectionReason =
  | "wrong_event_kind"
  | "wrong_authority_origin"
  | "malformed_payload"
  | "fortress_mismatch"
  | "principal_mismatch"
  | "principal_chain_invalid"
  | "operator_signature_invalid"
  | "policy_version_replay"
  | "unsupported_event_version";

export function federationOperatorAuthorityOriginForPolicy(
  fortressId: string,
): string {
  return `operator:${fortressId}`;
}

export function isFederationPolicyBundleAuthorityEvent(
  event: FederationPolicyBundleLogEvent,
  fortressId: string,
): boolean {
  return (
    event.origin_node_id === federationOperatorAuthorityOriginForPolicy(fortressId) &&
    event.kind === FEDERATION_POLICY_BUNDLE_EVENT_KIND
  );
}

function lengthPrefixed(field: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + field.length);
  new DataView(out.buffer).setUint32(0, field.length, false);
  out.set(field, 4);
  return out;
}

export function buildFederationPolicyBundleMessage(
  payload: Omit<FederationPolicyBundlePayload, "operator_signature">,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(V1_FEDERATION_POLICY_BUNDLE_DOMAIN),
    lengthPrefixed(encoder.encode(canonicalJson(payload))),
  ];
  const total = parts.reduce((n, part) => n + part.length, 0);
  const message = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }
  return message;
}

export function signFederationPolicyBundlePayload(params: {
  fortressId: string;
  policyVersion: number;
  policyHash: string;
  signedAt: string;
  operatorPrincipalId: string;
  operatorPrincipalPrivateKey: Uint8Array;
}): FederationPolicyBundlePayload {
  const body = {
    event_version: FEDERATION_POLICY_BUNDLE_EVENT_VERSION,
    fortress_id: params.fortressId,
    policy_version: params.policyVersion,
    policy_hash: params.policyHash,
    policy_hash_algorithm: FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM,
    signed_at: params.signedAt,
    operator_principal_id: params.operatorPrincipalId,
  };
  const signature = ed25519.sign(
    buildFederationPolicyBundleMessage(body),
    params.operatorPrincipalPrivateKey,
  );
  return {
    ...body,
    operator_signature: toBase64url(signature),
  };
}

export function verifyFederationPolicyBundleEvent(input: {
  event: FederationPolicyBundleLogEvent;
  fortressId: string;
  pinnedMaster: FortressMasterPublicKey;
  operatorPrincipalCert: PrincipalCertificate;
  currentPolicyVersion: number | null;
}): FederationPolicyBundleVerification {
  const { event } = input;
  if (event.kind !== FEDERATION_POLICY_BUNDLE_EVENT_KIND) {
    return { ok: false, reason: "wrong_event_kind" };
  }
  if (
    event.origin_node_id !==
    federationOperatorAuthorityOriginForPolicy(input.fortressId)
  ) {
    return { ok: false, reason: "wrong_authority_origin" };
  }
  if (event.payload.event_version !== FEDERATION_POLICY_BUNDLE_EVENT_VERSION) {
    return { ok: false, reason: "unsupported_event_version" };
  }
  const payload = parseFederationPolicyBundlePayload(event.payload);
  if (payload === null) return { ok: false, reason: "malformed_payload" };
  if (payload.fortress_id !== input.fortressId) {
    return { ok: false, reason: "fortress_mismatch" };
  }
  if (
    payload.operator_principal_id !==
    input.operatorPrincipalCert.principal_id
  ) {
    return { ok: false, reason: "principal_mismatch" };
  }
  if (
    input.currentPolicyVersion !== null &&
    payload.policy_version <= input.currentPolicyVersion
  ) {
    return { ok: false, reason: "policy_version_replay" };
  }

  try {
    verifyPrincipalCertificate(input.operatorPrincipalCert, input.pinnedMaster);
  } catch {
    return { ok: false, reason: "principal_chain_invalid" };
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64url(payload.operator_signature);
  } catch {
    return { ok: false, reason: "operator_signature_invalid" };
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    return { ok: false, reason: "operator_signature_invalid" };
  }
  const signedBody = {
    event_version: payload.event_version,
    fortress_id: payload.fortress_id,
    policy_version: payload.policy_version,
    policy_hash: payload.policy_hash,
    policy_hash_algorithm: payload.policy_hash_algorithm,
    signed_at: payload.signed_at,
    operator_principal_id: payload.operator_principal_id,
  };
  const ok = verify(
    buildFederationPolicyBundleMessage(signedBody),
    signature,
    fromBase64url(input.operatorPrincipalCert.principal_pubkey),
  );
  if (!ok) return { ok: false, reason: "operator_signature_invalid" };

  return {
    ok: true,
    policyVersion: payload.policy_version,
    policyHash: payload.policy_hash,
    payload,
  };
}

export function foldFederationPolicyBundleEvent(input: {
  event: FederationPolicyBundleLogEvent;
  projection: FederationPolicyProjection;
  fortressId: string;
  pinnedMaster: FortressMasterPublicKey;
  operatorPrincipalCert: PrincipalCertificate;
  applyingNodeId: string;
}): FederationPolicyBundleVerification {
  const verification = verifyFederationPolicyBundleEvent({
    event: input.event,
    fortressId: input.fortressId,
    pinnedMaster: input.pinnedMaster,
    operatorPrincipalCert: input.operatorPrincipalCert,
    currentPolicyVersion: input.projection.current?.version ?? null,
  });
  if (!verification.ok) return verification;

  const marker: FederationAppliedPolicyVersion = {
    version: verification.payload.policy_version,
    hash: verification.payload.policy_hash,
    hash_algorithm: verification.payload.policy_hash_algorithm,
    applied_at: input.event.occurred_at,
    source_event_id: input.event.event_id,
  };
  input.projection.current = marker;
  input.projection.appliedByNode.set(input.applyingNodeId, marker);
  return verification;
}

export function parseFederationPolicyBundlePayload(
  value: Record<string, unknown>,
): FederationPolicyBundlePayload | null {
  const keys = Object.keys(value);
  if (
    keys.length !== POLICY_BUNDLE_PAYLOAD_KEYS.size ||
    keys.some((key) => !POLICY_BUNDLE_PAYLOAD_KEYS.has(key))
  ) {
    return null;
  }
  const eventVersion = value.event_version;
  const fortressId = value.fortress_id;
  const policyVersion = value.policy_version;
  const policyHash = value.policy_hash;
  const hashAlgorithm = value.policy_hash_algorithm;
  const signedAt = value.signed_at;
  const operatorPrincipalId = value.operator_principal_id;
  const operatorSignature = value.operator_signature;

  if (eventVersion !== FEDERATION_POLICY_BUNDLE_EVENT_VERSION) return null;
  if (typeof fortressId !== "string" || fortressId.length === 0) return null;
  if (
    typeof policyVersion !== "number" ||
    !Number.isSafeInteger(policyVersion) ||
    policyVersion < 1
  ) {
    return null;
  }
  if (
    typeof policyHash !== "string" ||
    !SHA256_BASE64URL_RE.test(policyHash)
  ) {
    return null;
  }
  if (hashAlgorithm !== FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM) return null;
  if (typeof signedAt !== "string" || Number.isNaN(Date.parse(signedAt))) {
    return null;
  }
  if (
    typeof operatorPrincipalId !== "string" ||
    operatorPrincipalId.length === 0
  ) {
    return null;
  }
  if (
    typeof operatorSignature !== "string" ||
    operatorSignature.length === 0
  ) {
    return null;
  }
  return {
    event_version: eventVersion,
    fortress_id: fortressId,
    policy_version: policyVersion,
    policy_hash: policyHash,
    policy_hash_algorithm: hashAlgorithm,
    signed_at: signedAt,
    operator_principal_id: operatorPrincipalId,
    operator_signature: operatorSignature,
  };
}
