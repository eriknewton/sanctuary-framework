/**
 * Sanctuary Operator Console v1.0 — AttestationBadge three-layer surface.
 *
 * Implements the three persistent badge classes from the Attestation UX Brief
 * (global / per-agent / per-action). The fourth per-transaction
 * custody-provenance class stubs to v1.x (per Key 17 Agentic.Market / x402
 * reservation; not shipped).
 *
 * Principles per the Attestation UX Brief:
 *   - Persistent, never a popup.
 *   - Degrade-not-destroy on attestation-verification failure.
 *   - Every one of the nine failure-row patterns produces a deterministic
 *     rendered state (AC5).
 */

import type {
  AttestationBadgeView,
  AttestationState,
} from "./types.js";

const VERIFIED_MESSAGE = "Attestation verified. Chain walks to the fortress-master.";
const PENDING_MESSAGE = "Attestation pending. First action for this agent.";
const DEGRADED_MESSAGE = "Attestation degraded. Still usable; recovery cascade suggested.";
const FAILED_MESSAGE = "Attestation failed. Operator review required.";
const UNKNOWN_MESSAGE = "Attestation unknown. No recent action from this agent.";

const LAYER_LABELS = {
  global: "Fortress",
  "per-agent": "Agent",
  "per-action": "Action",
  "custody-provenance-stub": "Custody (v1.x)",
} as const;

function labelFor(layer: AttestationBadgeView["layer"], state: AttestationState): string {
  const prefix = LAYER_LABELS[layer];
  switch (state) {
    case "verified":
      return `${prefix}: verified`;
    case "pending":
      return `${prefix}: pending`;
    case "degraded":
      return `${prefix}: degraded`;
    case "failed":
      return `${prefix}: failed`;
    case "unknown":
      return `${prefix}: unknown`;
  }
}

function tooltipFor(state: AttestationState): string {
  switch (state) {
    case "verified":
      return VERIFIED_MESSAGE;
    case "pending":
      return PENDING_MESSAGE;
    case "degraded":
      return DEGRADED_MESSAGE;
    case "failed":
      return FAILED_MESSAGE;
    case "unknown":
      return UNKNOWN_MESSAGE;
  }
}

/**
 * Deterministic class name used by CSS + tests (AC5 requires a deterministic
 * rendered state for every failure row). Format: `att-badge att-<layer>-<state>`.
 */
export function badgeClassName(
  layer: AttestationBadgeView["layer"],
  state: AttestationState
): string {
  return `att-badge att-${layer}-${state}`;
}

export function renderBadge(
  layer: AttestationBadgeView["layer"],
  state: AttestationState
): AttestationBadgeView {
  return {
    layer,
    state,
    label: labelFor(layer, state),
    class_name: badgeClassName(layer, state),
    tooltip: tooltipFor(state),
  };
}

/** Global (fortress-wide) badge — aggregates across the mesh. */
export function globalBadge(state: AttestationState): AttestationBadgeView {
  return renderBadge("global", state);
}

/** Per-agent badge — one per wrapped agent row. */
export function perAgentBadge(state: AttestationState): AttestationBadgeView {
  return renderBadge("per-agent", state);
}

/** Per-action badge — one per agent's most-recent action. */
export function perActionBadge(state: AttestationState): AttestationBadgeView {
  return renderBadge("per-action", state);
}

/**
 * The v1.x custody-provenance stub. Returns a deterministic "v1.x" label
 * so the UI can render a disabled affordance — the class is reserved in
 * navigation + testable without shipping the live rendering.
 */
export function custodyProvenanceStub(): AttestationBadgeView {
  return {
    layer: "custody-provenance-stub",
    state: "unknown",
    label: "Custody (v1.x)",
    class_name: "att-badge att-custody-provenance-stub att-v1x-reserved",
    tooltip:
      "Custody-provenance attestation (Agentic.Market / x402 signing flow) lands in v1.x. Not rendered at v1.0.",
  };
}

/**
 * Roll up a list of per-agent attestation states into a global state.
 * Failure propagates: any failed → global failed; any degraded → global
 * degraded; any pending → global pending; all verified → verified; empty →
 * unknown.
 */
export function rollupGlobal(
  perAgentStates: AttestationState[]
): AttestationState {
  if (perAgentStates.length === 0) return "unknown";
  if (perAgentStates.some((s) => s === "failed")) return "failed";
  if (perAgentStates.some((s) => s === "degraded")) return "degraded";
  if (perAgentStates.some((s) => s === "pending")) return "pending";
  if (perAgentStates.every((s) => s === "verified")) return "verified";
  return "unknown";
}
