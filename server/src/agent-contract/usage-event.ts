/**
 * Sanctuary Agent Contract v0.1 — Usage Event Emission (§6).
 *
 * Every contract-bearing action emits exactly one signed usage event. The
 * event rides the mesh envelope under event_type `agent_usage_event`.
 *
 * `input_hash` and `output_hash` are SHA-256 over the canonical-JSON
 * encoding of the action input/output. Callers pass the raw values; this
 * module canonicalizes and hashes consistently so different emitters produce
 * identical hashes for identical inputs.
 *
 * Append-only invariant: this module does not expose a mutation path. Each
 * call yields a new signed envelope. The audit log consumes the envelope as
 * an immutable record.
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
  type CapabilityKind,
  type EventClass,
} from "./constants.js";
import { UsageEventSchemaError } from "./errors.js";
import { validateUsageEvent } from "./schema.js";
import type { UsageEvent } from "./types.js";

export const AGENT_USAGE_EVENT_TYPE: AgentContractEventType =
  "agent_usage_event";

export interface EmitUsageEventParams {
  agent_id: string;
  fortress_id: string;
  /** Spec §6 classification — discriminator for downstream consumers. */
  event_class: EventClass;
  /**
   * Capability kind invoked. REQUIRED when `event_class === "tool_call"`;
   * MUST be absent for every other class. The validator enforces both sides.
   */
  capability_kind?: CapabilityKind;
  capability_target: string;
  /** Raw input value — canonicalized + hashed here. */
  input: unknown;
  /** Raw output value — canonicalized + hashed here. */
  output: unknown;
  policy_version: number;
  policy_version_hash: string;
  attestation_state: "present" | "degraded" | "unavailable";
  emitter_node: string;
  emitter_principal: string;
  node_private_key: Uint8Array;
  principal_private_key?: Uint8Array;
  monotonic_seq: number;
  emitted_at?: string;
  /**
   * Causal references back to prior usage events per spec §6. Each entry
   * points at a predecessor by `event_class` + `usage_event_id`. Validator
   * enforces allow-listed `event_type` values.
   */
  references?: Array<{ event_type: EventClass; event_id: string }>;
  extension?: Record<string, unknown>;
}

/**
 * Emit a signed usage event. Returns both the envelope and the event body so
 * callers can persist either.
 */
export function emitUsageEvent(
  params: EmitUsageEventParams
): { signed_event: SignedEvent<UsageEvent>; event: UsageEvent } {
  const emitted_at = params.emitted_at ?? new Date().toISOString();
  const input_hash = toBase64url(sha256(canonicalizeToBytes(params.input)));
  const output_hash = toBase64url(sha256(canonicalizeToBytes(params.output)));
  const usage_event_id = generateUsageEventId();
  const event: UsageEvent = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    usage_event_id,
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
    event_class: params.event_class,
    ...(params.capability_kind !== undefined
      ? { capability_kind: params.capability_kind }
      : {}),
    capability_target: params.capability_target,
    input_hash,
    output_hash,
    policy_version: params.policy_version,
    policy_version_hash: params.policy_version_hash,
    attestation_state: params.attestation_state,
    emitted_at,
    ...(params.references !== undefined && params.references.length > 0
      ? { references: params.references.map((r) => ({ ...r })) }
      : {}),
    ...(params.extension ? { extension: params.extension } : {}),
  };
  validateUsageEvent(event);
  const signed_event = packSignedEvent<UsageEvent>({
    event_type: AGENT_USAGE_EVENT_TYPE,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    payload: event,
    monotonic_seq: params.monotonic_seq,
    node_private_key: params.node_private_key,
    principal_private_key: params.principal_private_key,
  });
  return { signed_event, event };
}

/** Verify a usage-event envelope + body. Mirror of verifyAgentCard. */
export function verifyUsageEvent(
  evt: SignedEvent<unknown>,
  ctx: VerifyContext
): { event: UsageEvent; signed_event: SignedEvent<UsageEvent> } {
  if (evt.event_type !== AGENT_USAGE_EVENT_TYPE) {
    throw new UsageEventSchemaError(
      `expected event_type "${AGENT_USAGE_EVENT_TYPE}"; got "${evt.event_type}"`
    );
  }
  const verifyResult = verifySignedEvent(evt as SignedEvent, ctx);
  const event = validateUsageEvent(verifyResult.event.payload);
  if (event.fortress_id !== verifyResult.event.fortress_id) {
    throw new UsageEventSchemaError(
      `usage event fortress_id does not match envelope fortress_id`
    );
  }
  return {
    event,
    signed_event: verifyResult.event as SignedEvent<UsageEvent>,
  };
}

function generateUsageEventId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}
