/**
 * Sanctuary — Host workload attestation builder (thin prototype, rung b).
 *
 * Builds a SIGNED statement over the DECLARED/recorded workload set and each
 * workload's consent disposition, derived from the {@link WorkloadRegistry}
 * projection of the audit chain. The signed bundle is offline-verifiable by a
 * second reader holding only the public key.
 *
 * COMPOSES with #504 (additive, no schema/consent/seal semantics changed):
 *   - Inputs come from the registry projection, which carries #504's validated
 *     `consent_status` / `consent_ref` / `override` / `manufactured_preference_
 *     caveat` verbatim. This module classifies (consented vs not) and signs; it
 *     never re-defines the consent enum or relaxes the schema.
 *   - It reuses the EXISTING fortress Ed25519 signing primitive (the same
 *     opaque-bytes signer abstraction the transparency checkpoint emitter and
 *     audit checkpoint signer use). NO new crypto is introduced: signing is
 *     Ed25519 over domain-separated canonical JSON, the codebase's signing
 *     discipline (`checkpointSigningBytes` pattern).
 *
 * HONESTY BOUNDARY (the #504 discipline — codex checks this):
 *   The attestation covers DECLARED/RECORDED workloads ONLY. The `scope` field
 *   states this in the payload itself: it does NOT assert that every process
 *   actually running on the host is declared. Detecting undeclared workloads is
 *   the separate registry-attestation / undeclared-workload frontier, an
 *   explicitly LATER item. No field, name, or comment implies host-wide process
 *   completeness.
 *
 *   `manufactured_preference_caveat` is propagated, never laundered: v1 consent
 *   is operator AUTHORIZATION as a proxy, NOT agent-side preference. Operator
 *   authorization is not relabeled as "the agent consented."
 *
 *   No consciousness / sentience / welfare verdict appears anywhere. Neutral
 *   "workload" language only (CISO-safe).
 *
 * FAIL-CLOSED BUT HONEST: if any declared workload is unconsented, `compliant`
 * is false AND that workload is still listed truthfully. The builder never
 * refuses to attest and never hides a non-compliant workload — suppressing the
 * worst case is exactly the omission pattern the schema exists to kill.
 */

import { canonicalJson, sha256Hex } from "../audit/chain.js";
import { fromBase64url, stringToBytes, toBase64url } from "../core/encoding.js";
import { verify as verifyEd25519 } from "../core/identity.js";
import type { ConsentStatus } from "./payload.js";
import type { WorkloadLifecycleState, WorkloadRegistry } from "./registry.js";

/** Domain-string version for the host-attestation payload. */
export const WORKLOAD_HOST_ATTESTATION_SCHEMA =
  "sanctuary.workload-host-attestation.v1" as const;

/** Domain-separation prefix for the bytes actually signed (mirrors the audit/
 * transparency checkpoint signing discipline: a versioned prefix + canonical
 * JSON, so a signature over one domain can never be replayed in another). */
export const WORKLOAD_HOST_ATTESTATION_DOMAIN =
  "sanctuary.workload-host-attestation.v1" as const;
const WORKLOAD_HOST_ATTESTATION_DOMAIN_PREFIX = `${WORKLOAD_HOST_ATTESTATION_DOMAIN}\n`;

/**
 * The EXACT honesty-scoping text embedded in every attestation payload. Quoted
 * verbatim into the `scope` field so it travels with the signed bundle and a
 * downstream reader cannot interpret the attestation as host-wide-complete. A
 * test asserts this exact string is present (regression guard against a future
 * edit that over-claims).
 */
export const WORKLOAD_HOST_ATTESTATION_SCOPE_TEXT =
  "This attestation covers DECLARED, audit-chain-recorded workloads ONLY. " +
  "It asserts that every workload this host has a lifecycle record for is " +
  "listed with its consent disposition. It does NOT assert that every process " +
  "running on the host is declared or recorded; detecting undeclared, " +
  "never-recorded workloads is a separate later capability (registry " +
  "attestation / undeclared-workload frontier) and is out of scope here. " +
  "Consent reflects operator authorization recorded against the workload, a " +
  "proxy and NOT agent-side preference (see manufactured_preference_caveat).";

/** Per-workload line in the attestation, derived from the registry projection. */
export interface AttestedWorkload {
  workload_id: string;
  state: WorkloadLifecycleState;
  consent_status: ConsentStatus;
  /** Consent reference (never the body), or null. */
  consent_ref: string | null;
  /** Classification result for THIS workload (see {@link classifyConsent}). */
  consented: boolean;
  /** Honest-insufficiency flag carried verbatim from the recorded payload. */
  manufactured_preference_caveat: boolean;
}

/** The signable attestation body (the bytes under signature). */
export interface HostWorkloadAttestationBody {
  schema: typeof WORKLOAD_HOST_ATTESTATION_SCHEMA;
  fortress_id: string;
  attested_at: string;
  /** Verbatim honesty-scoping text (declared-workloads-only disclaimer). */
  scope: string;
  workloads: AttestedWorkload[];
  /** True iff EVERY declared workload is consented. Fail-closed but honest. */
  compliant: boolean;
  /** Always true in v1: the whole consent channel is operator-authorization,
   * not agent preference. Propagated, never laundered. */
  manufactured_preference_caveat: boolean;
}

/** Signed envelope: the body plus an offline-verifiable Ed25519 signature. */
export interface SignedHostWorkloadAttestation {
  body: HostWorkloadAttestationBody;
  signer_kid: string;
  signature: string;
  signature_algorithm: "Ed25519";
  payload_encoding: "domain-separated-canonical-json-v1";
  /** Base64url raw 32-byte Ed25519 public key the body verifies under. */
  public_key: string;
}

/**
 * Opaque-bytes signing handle. Carries NO private key material in the type — the
 * same abstraction the transparency checkpoint emitter uses (production custody
 * is the Castle Wall root signer; dev/test decrypts the pinned key transiently
 * inside `sign`). Reusing this shape means this module introduces no new crypto.
 */
export interface WorkloadAttestationSigner {
  signer_kid: string;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** Sign opaque domain-separated bytes → raw 64-byte Ed25519 signature. */
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}

export class HostWorkloadAttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HostWorkloadAttestationError";
  }
}

/**
 * Consent classification rule (composes with #504's recorded fields, relaxes
 * nothing):
 *
 *   consented  iff  consent_status ∈ {present, inherited}
 *               OR  (state === "deleted" AND a valid override block carrying a
 *                    non-empty approval_record_id is present)
 *   unconsented otherwise (notably `consent_status: "absent"` with no override).
 *
 * The delete-with-override carve-out exists because #504 records an exceptional
 * gated destruction with `consent_status: "absent"` + an `override` (the
 * operator's on-chain account, hash-pinned at the act). That is an AUTHORIZED
 * act with a Tier-1 approval record backing it, so it classifies as consented —
 * but only when the override is well-formed (has an `approval_record_id`); an
 * `absent` status with no override is unconsented and stays listed truthfully.
 */
export function classifyConsent(input: {
  consent_status: ConsentStatus;
  state: WorkloadLifecycleState;
  override?: { approval_record_id: string };
}): boolean {
  if (input.consent_status === "present" || input.consent_status === "inherited") {
    return true;
  }
  // consent_status === "absent": consented ONLY via a valid delete override.
  if (
    input.state === "deleted" &&
    input.override !== undefined &&
    typeof input.override.approval_record_id === "string" &&
    input.override.approval_record_id.length > 0
  ) {
    return true;
  }
  return false;
}

/** Domain-separated bytes that are actually signed (mirrors checkpointSigningBytes). */
export function hostAttestationSigningBytes(
  body: HostWorkloadAttestationBody
): Uint8Array {
  return stringToBytes(
    `${WORKLOAD_HOST_ATTESTATION_DOMAIN_PREFIX}${canonicalJson(body)}`
  );
}

/**
 * Canonical bundle hash for chain binding — sha256 over the domain-separated
 * canonical bytes of the WHOLE signed envelope (body + signature). The seal
 * binds the audit entry to this hash, mirroring how `sealLifecycleEmission`
 * binds a lifecycle entry to its mesh event's `signedEventHash`.
 */
export function hostAttestationBundleHash(
  attestation: SignedHostWorkloadAttestation
): string {
  return sha256Hex(
    `${WORKLOAD_HOST_ATTESTATION_DOMAIN_PREFIX}${canonicalJson(attestation)}`
  );
}

export interface BuildHostWorkloadAttestationParams {
  registry: WorkloadRegistry;
  signer: WorkloadAttestationSigner;
  fortressId: string;
  /** Attestation timestamp (ISO-8601). Injected for determinism in tests. */
  now: string;
}

/**
 * Build + sign a host workload attestation from the registry projection.
 *
 * Enumerates `registry.listDeclared()`, classifies each workload's consent,
 * computes `compliant` (every declared workload consented), embeds the verbatim
 * `scope` disclaimer, and signs the canonical body. Independently verifies the
 * signer's returned signature before returning (a signer that returns garbage
 * must not produce a bundle — constraint #5, never silently degrade).
 */
export async function buildHostWorkloadAttestation(
  params: BuildHostWorkloadAttestationParams
): Promise<SignedHostWorkloadAttestation> {
  const declared = params.registry.listDeclared();
  const workloads: AttestedWorkload[] = declared.map((r) => {
    const consented = classifyConsent({
      consent_status: r.consent_status,
      state: r.state,
      ...(r.override ? { override: r.override } : {}),
    });
    return {
      workload_id: r.workload_id,
      state: r.state,
      consent_status: r.consent_status,
      consent_ref: r.consent_ref,
      consented,
      manufactured_preference_caveat: r.manufactured_preference_caveat,
    };
  });

  // Fail-closed but HONEST: compliant is the AND over every declared workload.
  // A single unconsented workload flips compliant to false; it is NOT dropped
  // from `workloads` — the non-compliant entry is listed truthfully above.
  const compliant =
    workloads.length === 0 ? true : workloads.every((w) => w.consented);

  const body: HostWorkloadAttestationBody = {
    schema: WORKLOAD_HOST_ATTESTATION_SCHEMA,
    fortress_id: params.fortressId,
    attested_at: params.now,
    scope: WORKLOAD_HOST_ATTESTATION_SCOPE_TEXT,
    workloads,
    compliant,
    // v1: the whole consent channel is operator-authorization, never agent
    // preference. Propagated at the bundle level so a reader cannot mistake any
    // `consented: true` line for an agent's own preference.
    manufactured_preference_caveat: true,
  };

  let signature: Uint8Array;
  try {
    signature = await params.signer.sign(hostAttestationSigningBytes(body));
  } catch (err) {
    throw new HostWorkloadAttestationError(
      `attestation signer failed; nothing was produced: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }
  if (signature.length !== 64) {
    throw new HostWorkloadAttestationError(
      `attestation signer returned a ${signature.length}-byte signature ` +
        `(expected 64); nothing was produced`
    );
  }
  if (params.signer.publicKey.length !== 32) {
    throw new HostWorkloadAttestationError(
      `attestation signer public key must be 32 bytes, got ${params.signer.publicKey.length}`
    );
  }

  const attestation: SignedHostWorkloadAttestation = {
    body,
    signer_kid: params.signer.signer_kid,
    signature: toBase64url(signature),
    signature_algorithm: "Ed25519",
    payload_encoding: "domain-separated-canonical-json-v1",
    public_key: toBase64url(params.signer.publicKey),
  };

  // Independently verify before handing the bundle back. A signer that returns
  // a non-verifying signature must not yield a usable attestation.
  if (!verifyHostWorkloadAttestation(attestation, params.signer.publicKey)) {
    throw new HostWorkloadAttestationError(
      "attestation signature does not verify against the signer's own public key; nothing was produced"
    );
  }
  return attestation;
}

/**
 * Offline-verify a signed host attestation against an explicit public key.
 * Returns false (never throws) on any malformed input or signature mismatch.
 */
export function verifyHostWorkloadAttestation(
  attestation: SignedHostWorkloadAttestation,
  publicKey: string | Uint8Array
): boolean {
  try {
    const keyBytes =
      typeof publicKey === "string" ? fromBase64url(publicKey) : publicKey;
    if (keyBytes.length !== 32) return false;
    return verifyEd25519(
      hostAttestationSigningBytes(attestation.body),
      fromBase64url(attestation.signature),
      keyBytes
    );
  } catch {
    return false;
  }
}
