/**
 * Sanctuary MCP Server — Sovereignty Health Report (SHR) Types
 *
 * Machine-readable, signed, versioned sovereignty capability advertisement.
 * An agent presents its SHR to counterparties to prove its sovereignty posture.
 * The SHR is signed by one of the instance's Ed25519 identities and can be
 * independently verified by any party without trusting the presenter.
 *
 * SHR version: 1.0
 */

import type { SignatureScheme } from "../mesh/constants.js";

// ── Layer Status ─────────────────────────────────────────────────────

export type LayerStatus = "active" | "degraded" | "inactive";
export type DegradationSeverity = "info" | "warning" | "critical";
export type DegradationCode =
  | "NO_TEE"
  | "PROCESS_ISOLATION_ONLY"
  | "COMMITMENT_ONLY"
  | "NO_ZK_PROOFS"
  | "SELF_REPORTED_ATTESTATION"
  | "NO_SELECTIVE_DISCLOSURE"
  | "BASIC_SYBIL_ONLY"
  // L4 reputation degradations (v0.9.1 — additive)
  | "NO_REPUTATION_HISTORY"
  | "LOW_TIER_DOMINANCE"
  | "STALE_REPUTATION"
  | "DISPUTE_ON_RECORD"
  | "NO_VERASCORE_LINK";

// ── SHR Body (signed content) ────────────────────────────────────────

export interface SHRLayerL1 {
  status: LayerStatus;
  encryption: string;
  key_custody: "self" | "delegated" | "platform";
  integrity: string;
  identity_type: string;
  state_portable: boolean;
}

export interface SHRLayerL2 {
  status: LayerStatus;
  isolation_type: string;
  attestation_available: boolean;
  /** Model provenance: what inference model(s) power this agent */
  model_provenance?: {
    model_id: string;
    model_name: string;
    provider: string;
    open_weights: boolean;
    open_source: boolean;
    local_inference: boolean;
    weights_hash?: string;
  };
}

export interface SHRLayerL3 {
  status: LayerStatus;
  proof_system: string;
  selective_disclosure: boolean;
}

export interface SHRLayerL4 {
  status: LayerStatus;
  reputation_mode: string;
  attestation_format: string;
  reputation_portable: boolean;
}

export interface SHRDegradation {
  layer: "l1" | "l2" | "l3" | "l4";
  code: DegradationCode;
  severity: DegradationSeverity;
  description: string;
  mitigation?: string;
}

export interface SHRCapabilities {
  handshake: boolean;
  shr_exchange: boolean;
  reputation_verify: boolean;
  encrypted_channel: boolean;
}

/**
 * A single key-rotation event, carried in the SHR so a verifier can bind a
 * rotated signing key back to a stable `instance_id`.
 *
 * Each event is signed by `old_public_key` over the canonical event data
 * (the five fields below, in declaration order — matching `rotateKeys` in
 * core/identity.ts). The chain is self-authenticating: forging a link
 * requires the prior key's private key, so an attacker cannot fabricate a
 * chain that terminates at a key they control while originating from a
 * victim's `instance_id`.
 */
export interface SHRRotationEvent {
  old_public_key: string; // base64url
  new_public_key: string; // base64url
  identity_id: string; // stable instance_id (constant across rotations)
  reason: string;
  rotated_at: string; // ISO 8601
  signature: string; // base64url, by old_public_key over the event data
}

/**
 * The SHR body — the content that gets signed.
 * Canonical form: JSON with sorted keys, no whitespace.
 */
export interface SHRBody {
  shr_version: "1.0";
  implementation: {
    sanctuary_version: string;
    node_version: string;
    generated_by: string;  // "sanctuary-mcp-server"
  };
  instance_id: string;
  generated_at: string;
  expires_at: string;
  layers: {
    l1: SHRLayerL1;
    l2: SHRLayerL2;
    l3: SHRLayerL3;
    l4: SHRLayerL4;
  };
  capabilities: SHRCapabilities;
  degradations: SHRDegradation[];
  /**
   * Optional key-rotation chain. Present only when the signing identity has
   * rotated its keys at least once. Lets a verifier accept an SHR whose
   * `signed_by` no longer derives `instance_id` directly, provided the chain
   * links the origin key (which does derive `instance_id`) to `signed_by`.
   * Absent for never-rotated identities, keeping their canonical form
   * byte-identical to pre-rotation SHRs.
   */
  key_rotation_proof?: SHRRotationEvent[];
}

/**
 * The complete signed SHR — body + signature envelope.
 */
export interface SignedSHR {
  body: SHRBody;
  signed_by: string;       // Public key (base64url)
  signature_scheme: SignatureScheme; // Layer 1 crypto-agility tag
  signature: string;       // Ed25519 signature over canonical body (base64url)
}

// ── Verification result ──────────────────────────────────────────────

export interface SHRVerificationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  sovereignty_level: "full" | "degraded" | "minimal";
  counterparty_id: string;
  expires_at: string;
}

// ── Canonical serialization ──────────────────────────────────────────

/**
 * Produce a canonical JSON representation of an SHR body.
 * Sorted keys, no whitespace — deterministic for signing.
 */
export function canonicalize(body: SHRBody): string {
  return JSON.stringify(body, Object.keys(body).sort(), 0)
    .replace(/\n/g, "");
}

/**
 * Deep-sort an object's keys for canonical JSON.
 * Handles nested objects and arrays.
 */
export function deepSortKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(deepSortKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = deepSortKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * Canonical serialization suitable for signing.
 *
 * Accepts SHRBody or any structurally compatible body (e.g.
 * DecommissionCertificateBody) — the underlying deepSortKeys
 * operates on arbitrary objects.
 */
export function canonicalizeForSigning(body: object): string {
  return JSON.stringify(deepSortKeys(body)).normalize("NFC");
}
