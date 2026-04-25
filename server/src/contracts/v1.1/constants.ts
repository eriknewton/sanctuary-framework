/**
 * Sanctuary v1.1 Local Sovereignty Harness — Shared Constants
 *
 * Cross-workstream constants for the v1.1 contract surface. Every workstream
 * (privacy, enforcement, hub, coordination, exit) imports from here so that
 * crypto-agility hinges and reserved-namespace boundaries stay coherent.
 *
 * v1.1 is local-single-operator. Public federation, fleet, mobile-native, and
 * payment surfaces are out of scope and live in v1.2 / v1.3 / v1.4+.
 */

/**
 * v1.1 contract version. v1.1 is the only valid value while v1.1 is current.
 * Future v1.2 contracts MAY accept v1.1 records unchanged where shape is preserved.
 */
export const V11_CONTRACT_VERSION = "1.1" as const;

/**
 * Signature scheme identifier embedded on every signed v1.1 record.
 *
 * v1.1 only accepts "ed25519-v1". Mirrors the mesh module: this field is the
 * forward-compat hinge for v1.4+ post-quantum migration. Verifiers MUST reject
 * unknown schemes. Do not optimize this field away.
 *
 * Mirror of: server/src/mesh/constants.ts SignatureScheme.
 */
export type SignatureScheme = "ed25519-v1";
export const SIGNATURE_SCHEME_V1: SignatureScheme = "ed25519-v1";

/**
 * Detector classes for the privacy filter. Workstreams MUST use this enum so
 * the dashboard privacy panel and audit consumers can group consistently.
 *
 * "custom" is reserved for operator-defined detectors via policy.
 */
export const PRIVACY_DETECTOR_CLASSES = [
  "person",
  "client",
  "project",
  "secret",
  "credential",
  "account",
  "file_path",
  "domain_term",
  "custom",
] as const;
export type PrivacyDetectorClass =
  (typeof PRIVACY_DETECTOR_CLASSES)[number];

/**
 * Outbound destination categories. The privacy filter and the remote-bound
 * enforcement workstream agree on this enum so events compose end-to-end.
 *
 * Categories deliberately mirror the L2 ProviderCategory taxonomy without
 * importing across module boundaries. If the L2 category set grows, keep this
 * v1.1 list in lockstep through coordinator review.
 */
export const PRIVACY_DESTINATION_CATEGORIES = [
  "inference",
  "tool_api",
  "logging",
  "analytics",
  "peer_agent",
  "custom",
] as const;
export type PrivacyDestinationCategory =
  (typeof PRIVACY_DESTINATION_CATEGORIES)[number];

/**
 * Privacy actions taken on a single field. Uses the L2 vocabulary.
 *
 * "rehydrate" is v1.1-new and applies to inbound responses, not outbound calls.
 */
export const PRIVACY_ACTIONS = [
  "allow",
  "redact",
  "hash",
  "summarize",
  "deny",
  "rehydrate",
] as const;
export type PrivacyAction = (typeof PRIVACY_ACTIONS)[number];

/**
 * Hub inbox item kinds. Hub API and dashboard consume the same enum so the
 * unified inbox renders without inventing new categories per surface.
 */
export const HUB_INBOX_KINDS = [
  "approval_pending",
  "blocked_egress",
  "privacy_event",
  "budget_warning",
  "recovery_prompt",
  "agent_error",
] as const;
export type HubInboxKind = (typeof HUB_INBOX_KINDS)[number];

/**
 * Agent lifecycle states surfaced to the operator hub.
 *
 * Underlying harness capability dictates which transitions are reachable; the
 * hub API surfaces unsupported transitions as "not_supported" rather than
 * faking them.
 */
export const HUB_AGENT_STATUSES = [
  "active",
  "paused",
  "restarting",
  "locked_down",
  "unwrapping",
  "error",
  "unknown",
] as const;
export type HubAgentStatus = (typeof HUB_AGENT_STATUSES)[number];

/**
 * Local handoff lifecycle. Mirrors the audit-event coverage required by the
 * acceptance checklist: created / accepted / denied / completed / failed.
 */
export const HANDOFF_STATUSES = [
  "created",
  "accepted",
  "denied",
  "completed",
  "failed",
] as const;
export type HandoffStatus = (typeof HANDOFF_STATUSES)[number];

/**
 * Exit-bundle manifest version. v1 is the only valid value at v1.1 ship.
 * v1.x bumps require coordinator-approved manifest amendment.
 */
export const EXIT_BUNDLE_MANIFEST_VERSION = "SANCTUARY_EXIT_BUNDLE_V1" as const;
export type ExitBundleManifestVersion = typeof EXIT_BUNDLE_MANIFEST_VERSION;

/**
 * Artifact kinds enumerated by the exit-bundle manifest. The export command
 * MUST list every included artifact under one of these kinds. The verifier
 * CLI rejects unknown kinds.
 */
export const EXIT_BUNDLE_ARTIFACT_KINDS = [
  "public_identity",
  "encrypted_state",
  "policy_set",
  "audit_receipts",
  "reputation_bundle",
  "commitments",
  "placeholder_vault_metadata",
] as const;
export type ExitBundleArtifactKind =
  (typeof EXIT_BUNDLE_ARTIFACT_KINDS)[number];
