/**
 * Sanctuary Attestation UX v1.0 -- Attestation Event Emitter
 *
 * Creates attestation events and binds them to the federation v0.1
 * signed-event envelope shape. Every badge state-change is derived
 * from or tied to a signed event per acceptance criterion 6.
 *
 * No LLM calls. No network fetches. Pure-logic event construction.
 */

import { randomBytes } from "../core/random.js";
import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";
import type { SignedEvent } from "../mesh/types.js";
import {
  ATTESTATION_EVENT_TYPE_PREFIX,
  type AttestationEventType,
  type BadgeStateColor,
  type FailureModeCode,
  type LayerType,
} from "./constants.js";
import { getFailureMode } from "./failure-catalog.js";
import type { AttestationEvent } from "./types.js";

// -----------------------------------------------------------------------
// Event ID generation
// -----------------------------------------------------------------------

function generateAttestationEventId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return `attest-${hex}`;
}

// -----------------------------------------------------------------------
// Event creation
// -----------------------------------------------------------------------

/**
 * Create an attestation event for a state change.
 *
 * The event is a logical record; binding to a mesh SignedEvent envelope
 * is done by the caller (service layer or federation transport).
 */
export function createAttestationEvent(params: {
  event_type: AttestationEventType;
  target_layer: LayerType;
  scope_id: string;
  resulting_state: BadgeStateColor;
  failure_mode?: FailureModeCode;
  explanation: string;
  metadata?: Record<string, unknown>;
}): AttestationEvent {
  return {
    event_id: generateAttestationEventId(),
    event_type: params.event_type,
    signature_scheme: SIGNATURE_SCHEME_V1,
    target_layer: params.target_layer,
    scope_id: params.scope_id,
    resulting_state: params.resulting_state,
    failure_mode: params.failure_mode,
    emitted_at: new Date().toISOString(),
    explanation: params.explanation,
    metadata: params.metadata,
  };
}

/**
 * Create a state-change event from a failure-mode code.
 * Looks up the failure mode in the catalog and derives the badge result.
 */
export function createFailureModeEvent(params: {
  failure_code: FailureModeCode;
  target_layer: LayerType;
  scope_id: string;
  detail?: string;
}): AttestationEvent {
  const entry = getFailureMode(params.failure_code);
  const explanation = entry
    ? `${entry.name}${params.detail ? `. ${params.detail}` : ""}`
    : `Unknown failure: ${params.failure_code}`;
  const resulting_state: BadgeStateColor = entry
    ? entry.badge_result
    : "yellow";

  return createAttestationEvent({
    event_type: "attestation_failure_detected",
    target_layer: params.target_layer,
    scope_id: params.scope_id,
    resulting_state,
    failure_mode: params.failure_code,
    explanation,
    metadata: entry
      ? { severity: entry.severity, remediation: entry.remediation_actions }
      : undefined,
  });
}

/**
 * Create a recovery event (state returning to green).
 */
export function createRecoveryEvent(params: {
  target_layer: LayerType;
  scope_id: string;
  recovered_from?: FailureModeCode;
}): AttestationEvent {
  return createAttestationEvent({
    event_type: "attestation_recovered",
    target_layer: params.target_layer,
    scope_id: params.scope_id,
    resulting_state: "green",
    explanation: params.recovered_from
      ? `Recovered from ${params.recovered_from}`
      : "Attestation recovered, all checks passing",
  });
}

// -----------------------------------------------------------------------
// Signed-event envelope binding
// -----------------------------------------------------------------------

/**
 * Shape the attestation event as a federation signed-event payload.
 *
 * The caller is responsible for wrapping this in a mesh `packSignedEvent`
 * call with the appropriate node/principal keys. This function produces
 * the payload and metadata needed by packSignedEvent.
 *
 * Per spawn prompt acceptance criterion 6: every badge state-change is
 * tied to a signed event via federation v0.1 envelope shape.
 */
export function toSignedEventPayload(event: AttestationEvent): {
  event_type: string;
  payload: AttestationEvent;
} {
  // Verify the event_type has the attestation_ prefix
  if (!event.event_type.startsWith(ATTESTATION_EVENT_TYPE_PREFIX)) {
    throw new Error(
      `Attestation event type must start with "${ATTESTATION_EVENT_TYPE_PREFIX}", got "${event.event_type}"`
    );
  }

  return {
    event_type: event.event_type,
    payload: event,
  };
}

/**
 * Extract an attestation event from a verified signed-event envelope.
 * Returns null if the event is not an attestation event.
 */
export function fromSignedEvent(
  evt: SignedEvent
): AttestationEvent | null {
  if (
    typeof evt.event_type !== "string" ||
    !evt.event_type.startsWith(ATTESTATION_EVENT_TYPE_PREFIX)
  ) {
    return null;
  }
  // The payload is the AttestationEvent
  return evt.payload as AttestationEvent;
}
