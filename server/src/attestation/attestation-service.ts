/**
 * Sanctuary Attestation UX v1.0 -- Attestation Service
 *
 * Public API: getGlobalBadge, getAgentBadge, getActionBadge,
 * getCustodyProvenance, listFailureModes, processAttestationEvent.
 *
 * This is the entry point for the operator console and reference HTML surface.
 * All derivation is pure-logic; no LLM calls, no external network fetches.
 */

import {
  applyAttestationEvent,
  clearAllBadgeStores,
  getActionBadgeState,
  getAgentBadgeState,
  getBadgeStoreCounts,
  getGlobalBadgeState,
  updateActionFromContext,
  updateAgentFromContext,
  updateGlobalFromContext,
} from "./badge-state.js";
import {
  createFailureModeEvent,
  createRecoveryEvent,
} from "./attestation-event.js";
import type { FailureModeCode, LayerType } from "./constants.js";
import {
  clearCustodyProvenanceStore,
  getCustodyProvenance as getCustodyProvenanceStub,
} from "./custody-provenance-stub.js";
import { clearAllRetryStates, safeVerify } from "./degrade-not-destroy.js";
import {
  FAILURE_MODE_CATALOG,
  getFailureMode,
  getFailureModesByLayer,
  getFailureModesBySeverity,
  verifyDegradeNotDestroy,
} from "./failure-catalog.js";
import type {
  ActionLayerContext,
  AgentLayerContext,
  AttestationEvent,
  BadgeState,
  CustodyProvenanceStub,
  FailureModeEntry,
  GlobalLayerContext,
} from "./types.js";

// -----------------------------------------------------------------------
// Badge read API (acceptance criteria 1-2)
// -----------------------------------------------------------------------

/**
 * Get the global (fortress-level) badge state.
 * Acceptance criterion 1: returns a BadgeState object.
 */
export function getGlobalBadge(fortress_id: string): BadgeState {
  return getGlobalBadgeState(fortress_id);
}

/**
 * Get per-agent badge state.
 * Acceptance criterion 1: returns a BadgeState object.
 *
 * Wraps with degrade-not-destroy: if the agent isn't found,
 * returns a degraded badge instead of throwing.
 */
export function getAgentBadge(agent_id: string): BadgeState {
  const result = safeVerify(
    `agent-badge-${agent_id}`,
    () => getAgentBadgeState(agent_id)
  );
  if (result.ok) {
    return result.result;
  }
  // Degrade: return an offline badge (scope not found)
  return {
    state: "offline",
    label: "No signal",
    last_updated_at: new Date().toISOString(),
    source_event_ids: [],
    explanation_key: "per_agent.not_found",
    layer: "per_agent",
    scope_id: agent_id,
  };
}

/**
 * Get per-action badge state.
 * Acceptance criterion 1: returns a BadgeState object.
 */
export function getActionBadge(action_id: string): BadgeState {
  const result = safeVerify(
    `action-badge-${action_id}`,
    () => getActionBadgeState(action_id)
  );
  if (result.ok) {
    return result.result;
  }
  return {
    state: "offline",
    label: "No signal",
    last_updated_at: new Date().toISOString(),
    source_event_ids: [],
    explanation_key: "per_action.not_found",
    layer: "per_action",
    scope_id: action_id,
  };
}

/**
 * Get custody provenance for a transaction (Layer 4 stub).
 * Acceptance criterion 2: returns a stub shape with `v1_0_stub: true`.
 */
export function getCustodyProvenance(tx_id: string): CustodyProvenanceStub {
  return getCustodyProvenanceStub(tx_id);
}

// -----------------------------------------------------------------------
// Failure-mode catalog API (acceptance criterion 3)
// -----------------------------------------------------------------------

/**
 * List all 9 failure modes. Acceptance criterion 3.
 */
export function listFailureModes(): readonly FailureModeEntry[] {
  return FAILURE_MODE_CATALOG;
}

/**
 * Get a specific failure mode by code.
 */
export function getFailureModeByCode(
  code: FailureModeCode
): FailureModeEntry | undefined {
  return getFailureMode(code);
}

/**
 * Get failure modes filtered by severity.
 */
export function listFailureModesBySeverity(
  minSeverity: "critical" | "warning" | "informational"
): FailureModeEntry[] {
  return getFailureModesBySeverity(minSeverity);
}

/**
 * Get failure modes filtered by affected layer.
 */
export function listFailureModesByLayer(
  layer: "global" | "per_agent" | "per_action"
): FailureModeEntry[] {
  return getFailureModesByLayer(layer);
}

/**
 * Verify the degrade-not-destroy invariant on the catalog.
 */
export function verifyDegradeInvariant(): {
  valid: boolean;
  violations: string[];
} {
  return verifyDegradeNotDestroy();
}

// -----------------------------------------------------------------------
// Event processing API (acceptance criterion 4, 6)
// -----------------------------------------------------------------------

/**
 * Process an attestation event and update badge state.
 * Returns the updated badge.
 *
 * Degrade-not-destroy: errors in processing are caught and the event
 * is applied as-is; no path throws or halts.
 */
export function processAttestationEvent(event: AttestationEvent): BadgeState {
  const result = safeVerify(
    `process-event-${event.event_id}`,
    () => applyAttestationEvent(event)
  );
  if (result.ok) {
    return result.result;
  }
  // Fallback: create a degraded badge
  return {
    state: result.state,
    label: result.state === "red" ? "Walls breached" : "Walls watch",
    last_updated_at: new Date().toISOString(),
    source_event_ids: [event.event_id],
    explanation_key: `processing_error.${event.event_type}`,
    layer: event.target_layer,
    scope_id: event.scope_id,
  };
}

/**
 * Report a failure mode. Creates an event and applies it.
 */
export function reportFailureMode(params: {
  failure_code: FailureModeCode;
  target_layer: LayerType;
  scope_id: string;
  detail?: string;
}): BadgeState {
  const event = createFailureModeEvent(params);
  return processAttestationEvent(event);
}

/**
 * Report recovery (return to green). Creates an event and applies it.
 */
export function reportRecovery(params: {
  target_layer: LayerType;
  scope_id: string;
  recovered_from?: FailureModeCode;
}): BadgeState {
  const event = createRecoveryEvent(params);
  return processAttestationEvent(event);
}

// -----------------------------------------------------------------------
// Context-based update API
// -----------------------------------------------------------------------

/**
 * Update global badge from full fortress context.
 */
export function updateGlobalBadge(
  ctx: GlobalLayerContext,
  source_event_ids?: string[]
): BadgeState {
  return updateGlobalFromContext(ctx, source_event_ids ?? []);
}

/**
 * Update per-agent badge from agent context.
 */
export function updateAgentBadge(
  ctx: AgentLayerContext,
  source_event_ids?: string[]
): BadgeState {
  return updateAgentFromContext(ctx, source_event_ids ?? []);
}

/**
 * Update per-action badge from action context.
 */
export function updateActionBadge(
  ctx: ActionLayerContext,
  source_event_ids?: string[]
): BadgeState {
  return updateActionFromContext(ctx, source_event_ids ?? []);
}

// -----------------------------------------------------------------------
// Diagnostics
// -----------------------------------------------------------------------

/**
 * Get badge store counts for health monitoring.
 */
export function getStoreCounts(): Record<string, number> {
  return getBadgeStoreCounts();
}

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

/**
 * Reset all attestation state. Test-only.
 */
export function resetAttestationState(): void {
  clearAllBadgeStores();
  clearAllRetryStates();
  clearCustodyProvenanceStore();
}
