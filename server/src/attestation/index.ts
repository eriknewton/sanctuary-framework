/**
 * Sanctuary Attestation UX v1.0 -- Public Surface
 *
 * Three-layer persistent badge surface (global / per-agent / per-action)
 * plus a fourth custody-provenance stub. 9-row failure-mode catalog.
 * Degrade-not-destroy. Never a popup. Real crypto, non-dependency clean.
 *
 * Design brief: Review/Sanctuary/Attestation_UX_Design_Brief_2026-04-21.md
 * Scope lock: Review/Sanctuary/Sanctuary_MVP_Scope_Lock_2026-04-21.md WP-MVP-9
 */

export * from "./constants.js";
export * from "./types.js";
export * from "./errors.js";
export * from "./badge-state.js";
export * from "./attestation-event.js";
export * from "./failure-catalog.js";
export {
  hasCustodyProvenance,
  clearCustodyProvenanceStore,
} from "./custody-provenance-stub.js";
export * from "./degrade-not-destroy.js";
export * from "./attestation-service.js";
