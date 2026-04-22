/**
 * Sanctuary Agent Contract v0.1 — Public surface.
 *
 * WP-MVP-4. Implements the ten-point Agent Contract (spec §2) as runtime
 * enforcement code over the mesh + policy-engine + broker + egress + audit
 * log surfaces shipped in PR #29 / #30 / #31 and v0.10.x.
 *
 * Non-dependency invariant: this module does not import Concordia or
 * Verascore. Commitment proposals emit a primitive event shape; a separate
 * Concordia Python sidecar (WP-MVP-10) handles the negotiation cycle.
 *
 * Spec: Review/Sanctuary/Agent_Contract_V0.1_Spec_2026-04-21.md
 * Scope lock: Review/Sanctuary/Sanctuary_MVP_Scope_Lock_2026-04-21.md §WP-MVP-4
 */

export * from "./constants.js";
export * from "./errors.js";
export * from "./types.js";
export * from "./schema.js";
export * from "./identity-bind.js";
export * from "./card-issuer.js";
export * from "./usage-event.js";
export * from "./capability-enforcer.js";
export * from "./envelope.js";
export * from "./lifecycle.js";
export * from "./attestation.js";
export * from "./commitment-boundary.js";
