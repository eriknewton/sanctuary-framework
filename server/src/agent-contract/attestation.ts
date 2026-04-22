/**
 * Sanctuary Agent Contract v0.1 — Per-Action Attestation (§2.9).
 *
 * Every contract-bearing action has a matching attestation binding
 * `usage_event_id → attested_hash`. The broker exposes an
 * `attestation_endpoint` URL (declared on the Agent Card); external
 * verifiers fetch `GET {endpoint}/{usage_event_id}` and receive the signed
 * Attestation blob.
 *
 * Two sources:
 *   - `harness_self_report`: the agent's own claim about what it did.
 *   - `proxy_canonical`: the broker's observation through the egress proxy
 *      or tool-call router. Cross-check Walkthrough Key 16.
 *
 * Degrade-not-destroy: if attestation emission fails (disk full, signing
 * error, network partition), the action MUST NOT be blocked. Callers
 * record `attestation_state: "degraded"` on the usage event; verifiers
 * see the missing attestation and apply policy per operator configuration
 * (e.g. halve Verascore weight, display a warning in the dashboard).
 *
 * The endpoint itself is a simple map lookup at v0.1; production swaps in a
 * disk-backed store. Retention policy is owned by Walkthrough Key 15 (not
 * implemented here).
 */

import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import {
  packSignedEvent,
  verifySignedEvent,
  type VerifyContext,
} from "../mesh/envelope.js";
import type { SignedEvent } from "../mesh/types.js";
import {
  AGENT_CONTRACT_VERSION,
  SIGNATURE_SCHEME_V1,
  type AgentContractEventType,
} from "./constants.js";
import { AttestationUnavailableError } from "./errors.js";
import { validateAttestation } from "./schema.js";
import type { Attestation } from "./types.js";

export const AGENT_ATTESTATION_EVENT_TYPE: AgentContractEventType =
  "agent_attestation";

export interface EmitAttestationParams {
  agent_id: string;
  fortress_id: string;
  usage_event_id: string;
  source: "harness_self_report" | "proxy_canonical";
  /** The body the attestation attests to — canonicalized + hashed here. */
  attested_payload?: Record<string, unknown>;
  emitter_node: string;
  emitter_principal: string;
  node_private_key: Uint8Array;
  principal_private_key?: Uint8Array;
  monotonic_seq: number;
  emitted_at?: string;
}

/** Emit a signed attestation + register it in the endpoint store. */
export function buildAttestation(
  params: EmitAttestationParams
): { signed_event: SignedEvent<Attestation>; attestation: Attestation } {
  const emitted_at = params.emitted_at ?? new Date().toISOString();
  const attested_hash =
    params.attested_payload !== undefined
      ? toBase64url(sha256(canonicalizeToBytes(params.attested_payload)))
      : toBase64url(sha256(canonicalizeToBytes({ degraded: true })));
  const attestation: Attestation = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    attestation_id: generateAttestationId(),
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
    usage_event_id: params.usage_event_id,
    source: params.source,
    attested_hash,
    emitted_at,
    ...(params.attested_payload
      ? { attested_payload: params.attested_payload }
      : {}),
  };
  validateAttestation(attestation);
  const signed_event = packSignedEvent<Attestation>({
    event_type: AGENT_ATTESTATION_EVENT_TYPE,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    payload: attestation,
    monotonic_seq: params.monotonic_seq,
    node_private_key: params.node_private_key,
    principal_private_key: params.principal_private_key,
  });
  return { signed_event, attestation };
}

/**
 * Registered attestation — stores both the parsed body (cheap lookup) and
 * the signed event (for auditor verification). Endpoint store exposes
 * both fields.
 */
export interface RegisteredAttestation {
  attestation: Attestation;
  signed_event: SignedEvent<Attestation>;
}

/**
 * AttestationStore — the broker's attestation_endpoint backing map.
 * Keyed by usage_event_id. Production wires a disk-backed implementation.
 */
export interface AttestationStore {
  register(reg: RegisteredAttestation): Promise<void>;
  lookup(usage_event_id: string): Promise<RegisteredAttestation | null>;
  /** Record a degrade so verifiers can distinguish "never attested" from "attested failed". */
  recordDegradation(
    usage_event_id: string,
    reason: string,
    emitted_at?: string
  ): Promise<void>;
  /** Fetch degradation reason if one was recorded. */
  degradationReason(usage_event_id: string): Promise<string | null>;
}

export class InMemoryAttestationStore implements AttestationStore {
  private reg = new Map<string, RegisteredAttestation>();
  private degraded = new Map<string, { reason: string; at: string }>();

  async register(reg: RegisteredAttestation): Promise<void> {
    this.reg.set(reg.attestation.usage_event_id, reg);
  }

  async lookup(
    usage_event_id: string
  ): Promise<RegisteredAttestation | null> {
    return this.reg.get(usage_event_id) ?? null;
  }

  async recordDegradation(
    usage_event_id: string,
    reason: string,
    emitted_at?: string
  ): Promise<void> {
    this.degraded.set(usage_event_id, {
      reason,
      at: emitted_at ?? new Date().toISOString(),
    });
  }

  async degradationReason(usage_event_id: string): Promise<string | null> {
    return this.degraded.get(usage_event_id)?.reason ?? null;
  }
}

/**
 * Emit an attestation and persist it to the store. Returns the signed event
 * so the caller can hand it to the audit log.
 *
 * Degrade-not-destroy: if emission throws (signing error, store error), the
 * caller is expected to call `markAttestationDegraded` and continue.
 */
export async function emitAttestation(
  store: AttestationStore,
  params: EmitAttestationParams
): Promise<RegisteredAttestation> {
  const built = buildAttestation(params);
  const reg: RegisteredAttestation = {
    attestation: built.attestation,
    signed_event: built.signed_event,
  };
  await store.register(reg);
  return reg;
}

/**
 * Record that attestation for a usage event was not produced. The endpoint
 * reports this to verifiers so they can apply degrade-not-destroy policy.
 */
export async function markAttestationDegraded(
  store: AttestationStore,
  usage_event_id: string,
  reason: string
): Promise<void> {
  await store.recordDegradation(usage_event_id, reason);
}

/**
 * Verifier-side: fetch the attestation by usage_event_id and verify the mesh
 * envelope. Throws AttestationUnavailableError if not present and no
 * degradation recorded; callers apply degrade-not-destroy on that error.
 */
export async function fetchAttestation(
  store: AttestationStore,
  usage_event_id: string,
  verifyCtx: VerifyContext
): Promise<Attestation> {
  const reg = await store.lookup(usage_event_id);
  if (!reg) {
    const degradation = await store.degradationReason(usage_event_id);
    throw new AttestationUnavailableError(
      "<unknown>",
      degradation ??
        `no attestation registered for usage_event_id=${usage_event_id}`
    );
  }
  verifySignedEvent(reg.signed_event as SignedEvent, verifyCtx);
  const body = validateAttestation(reg.signed_event.payload);
  return body;
}

function generateAttestationId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}
