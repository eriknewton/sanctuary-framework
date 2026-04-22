/**
 * Sanctuary Agent Contract v0.1 — Constants.
 *
 * Canonical enumerations for the ten-point Agent Contract. Every signed
 * Agent Contract emission (Agent Card, usage event, lifecycle event,
 * attestation, commitment-boundary proposal) MUST embed `signature_scheme`
 * from this module as its crypto-agility hinge.
 *
 * Spec: Review/Sanctuary/Agent_Contract_V0.1_Spec_2026-04-21.md
 * Scope lock: Review/Sanctuary/Sanctuary_MVP_Scope_Lock_2026-04-21.md §WP-MVP-4
 */

import { SIGNATURE_SCHEME_V1, type SignatureScheme } from "../mesh/constants.js";

/** Agent Contract protocol version. Stable at v0.1 through v1.0. */
export const AGENT_CONTRACT_VERSION = "0.1" as const;

/**
 * Re-export the mesh signature-scheme identifier. Every signed Agent Contract
 * emission carries this in its payload so a v1.x PQ-hybrid upgrade can land
 * without breaking v1.0 readers.
 */
export { SIGNATURE_SCHEME_V1 };
export type { SignatureScheme };

/**
 * Harness tier taxonomy per spec §5 + Walkthrough Key 5 LOCKED.
 *
 * - A (native): harness speaks Agent Contract directly. OpenClaw / ClawChief.
 * - B (adapter-wrapped): harness is wrapped by a `sanctuary wrap` adapter that
 *   presents the Agent Contract surface. Cline / Claude Code / Mastra at v0.1.
 * - C (escape hatch): fully unmanaged; operator acknowledges limited coverage.
 */
export const HARNESS_TIERS = ["A", "B", "C"] as const;
export type HarnessTier = (typeof HARNESS_TIERS)[number];

/**
 * Agent Card capability kinds per spec §3.
 *
 * Gate-ability: runtime enforcement checks that every harness-initiated action
 * maps to a capability with a matching `kind`. Undeclared capabilities fail
 * closed at the broker.
 */
export const CAPABILITY_KINDS = [
  "read-slot",
  "write-slot",
  "subscribe-slot",
  "tool-call",
  "egress",
  "concordia-commitment",
  "attestation",
  "lifecycle",
] as const;
export type CapabilityKind = (typeof CAPABILITY_KINDS)[number];

/**
 * Model-provider enum per spec §3. Per coordinator decision §11.3, ship the
 * enum as-is and route additions through `other` until a policy template
 * emerges. Adding a vendor requires a spec amendment.
 */
export const MODEL_PROVIDERS = [
  "anthropic",
  "openai",
  "google",
  "meta",
  "mistral",
  "cohere",
  "xai",
  "venice",
  "self-hosted",
  "other",
] as const;
export type ModelProvider = (typeof MODEL_PROVIDERS)[number];

/**
 * Lifecycle states per spec §2.8. A retire seals the audit log segment; a
 * revoke is guardian-initiated and force-closes outstanding work.
 */
export const LIFECYCLE_STATES = [
  "launched",
  "paused",
  "checkpointed",
  "resumed",
  "retired",
  "revoked",
] as const;
export type LifecycleState = (typeof LIFECYCLE_STATES)[number];

/**
 * Agent Contract event types ridden on the mesh SignedEvent envelope.
 *
 * None of these collide with the v0.1 mesh event types (heartbeat,
 * policy_update, etc.) and none are in the reserved-prefix namespaces
 * (EXTENSION_*, cross_fortress_*, multi_master_*). The mesh envelope accepts
 * them as opaque event_type strings.
 */
export const AGENT_CONTRACT_EVENT_TYPES = [
  "agent_card_issued",
  "agent_usage_event",
  "agent_lifecycle_event",
  "agent_attestation",
  "agent_commitment_proposed",
] as const;
export type AgentContractEventType =
  (typeof AGENT_CONTRACT_EVENT_TYPES)[number];

/**
 * Usage-event classification per spec §6. Every signed usage event carries
 * exactly one `event_class` from this set; the value is the primary
 * discriminator for downstream consumers (audit viewers, Verascore ingest,
 * attestation-UX rendering) and cannot be inferred from `capability_kind`
 * (which only meaningfully applies when the class is `tool_call`).
 *
 * Ordering and spelling match the spec JSON Schema exactly (lines 473–488 of
 * `Review/Sanctuary/Agent_Contract_V0.1_Spec_2026-04-21.md`). Do not reorder
 * without bumping `AGENT_CONTRACT_VERSION`.
 *
 * Some classes (`mandate_*`, `budget_*`, `honeypot_triggered`) are listed for
 * v1.x emitter coverage and are not emitted by v0.1 enforcement code. They
 * remain in the enum so a spec-conforming external emitter's events validate
 * cleanly against the Sanctuary validator.
 */
export const EVENT_CLASSES = [
  "launched",
  "paused",
  "checkpointed",
  "resumed",
  "retired",
  "revoked",
  "tool_call",
  "egress_request",
  "egress_blocked",
  "gate_request",
  "gate_approved",
  "gate_denied",
  "gate_timeout",
  "policy_pinned",
  "policy_update_requested",
  "capability_declared",
  "capability_extension_requested",
  "envelope_sent",
  "envelope_received",
  "attestation_emitted",
  "attestation_failed",
  "commitment_proposed",
  "commitment_accepted",
  "commitment_fulfilled",
  "commitment_unwound",
  "mandate_referenced",
  "mandate_revoked",
  "budget_consumed",
  "budget_exceeded",
  "sentinel_alert",
  "honeypot_triggered",
] as const;
export type EventClass = (typeof EVENT_CLASSES)[number];

/**
 * HKDF info-string prefix for per-agent signing-key derivation.
 *
 * Per-agent Ed25519 private keys are generated fresh at launch (not HKDF-
 * derived — keys must have full 256 bits of independent entropy). HKDF is
 * used ONLY for symmetric per-agent subkeys (envelope wrap keys, audit chain
 * keys) that guardian recovery needs to re-derive.
 *
 * Info format: `${PREFIX}|${agent_id}|${purpose}` where purpose is a short
 * string enumerated in the caller (e.g. "envelope-wrap", "audit-chain").
 */
export const HKDF_AGENT_SUBKEY_INFO_PREFIX = "sanctuary-agent-contract-v0.1";

/**
 * Standard per-agent subkey purposes. Enumerated so misspellings are caught at
 * compile time and so auditors can enumerate what subkeys exist for an agent.
 */
export const AGENT_SUBKEY_PURPOSES = [
  "envelope-wrap",
  "audit-chain",
  "attestation-nonce",
] as const;
export type AgentSubkeyPurpose = (typeof AGENT_SUBKEY_PURPOSES)[number];

/**
 * Egress response codes honored per spec §2.5. `402` (payment required),
 * `403` (forbidden), `429` (too many requests), `451` (unavailable for legal
 * reasons). The egress proxy emits these verbatim; the adapter layer maps
 * them into broker lifecycle transitions.
 */
export const EGRESS_HONORED_STATUS_CODES = [402, 403, 429, 451] as const;

/**
 * Commitment classes the Agent Contract layer understands how to propose. The
 * actual gate evaluation is delegated to the policy engine's
 * `evaluateCommitmentBoundary` (WP-MVP-5). This enum is purely for type-safe
 * proposal construction.
 */
export const COMMITMENT_CLASSES = [
  "task-accept",
  "task-delegate",
  "escrow-hold",
  "plan-publish",
  "output-publish",
  "credential-share",
] as const;
export type CommitmentClass = (typeof COMMITMENT_CLASSES)[number];
