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
 * Categories deliberately mirror the L2 `ProviderCategory` taxonomy in
 * `server/src/operational/context-gate.ts` (hyphen form) so JSON-stable
 * strings flow through both layers without translation. If the L2 category
 * set grows, keep this v1.1 list in lockstep through coordinator review.
 */
export const PRIVACY_DESTINATION_CATEGORIES = [
  "inference",
  "tool-api",
  "logging",
  "analytics",
  "peer-agent",
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
 * Hash algorithm identifier embedded in every privacy event content_hash.
 *
 * v1.1 ships ONLY `hmac-sha256-fortress-keyed-v1`: HMAC-SHA-256 over the
 * raw field value, using a per-fortress secret derived from the master key
 * via HKDF info string `sanctuary-v1.1-privacy-content-hmac`. Plain SHA-256
 * is NOT permitted because privacy field values (PII, project names, client
 * names, file paths) are low-entropy and dictionary-attackable. The keyed
 * hash makes content hashes meaningful for equality checks across events
 * within a fortress while remaining opaque to anyone without the per-
 * fortress key.
 *
 * Forward-compat: a future v1.x privacy hardening pass may add ML-DSA-keyed
 * variants. Verifiers MUST reject unknown algorithms.
 */
export const PRIVACY_HASH_ALGS = [
  "hmac-sha256-fortress-keyed-v1",
] as const;
export type PrivacyHashAlg = (typeof PRIVACY_HASH_ALGS)[number];

/**
 * Sanitized field-path schema for privacy events.
 *
 * Raw object keys CAN themselves leak sensitive information ("client_acme",
 * "project_secret_launch"). v1.1 privacy events MUST emit field paths in
 * sanitized form: a stable, fortress-local identifier mapped from the real
 * path through the placeholder vault. Two formats are accepted on the wire:
 *
 *   - "$<n>" — opaque positional reference (e.g., "$0", "$1.$2"); the
 *     fortress-local mapping resolves the index back to a path. Indices are
 *     stable per-event but NOT stable across events (rotated per emission).
 *
 *   - "<schema>:<n>" — typed positional reference where <schema> is one of
 *     a small enumerated set: "obj", "arr", "key", "val". Used when the
 *     dashboard needs to render structural distinctions ("a key was
 *     redacted" vs "a value was redacted") without revealing the real key.
 *
 * Real object keys MUST NOT appear in `field_path` on the wire. The
 * privacy core is responsible for the sanitization step before emission.
 */
export const PRIVACY_FIELD_PATH_PATTERN = /^(\$[0-9]+|(?:obj|arr|key|val):[0-9]+)(?:\.(?:\$[0-9]+|(?:obj|arr|key|val):[0-9]+))*$/;

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
 * Exit-bundle manifest version. `EXIT_BUNDLE_MANIFEST_VERSION` ("V1") is the
 * ORIGINAL, FROZEN, seven-artifact contract - byte-stable, untouched by the
 * Exit V2 known_signers addition below. v1.x bumps require
 * coordinator-approved manifest amendment.
 *
 * `EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS` (independent Codex gate
 * finding, 2026-08-23, item 5 on the #1303 fix round: HIGH - "the frozen V1
 * artifact-kind set was changed in place; an older verifier would reject a
 * new export as carrying an unknown artifact kind"): a bundle that carries
 * the `known_signers` artifact (Exit V2 drill F2) declares a DIFFERENT
 * `manifest_version` literal, so a pre-this-change verifier - which only
 * recognizes the exact string "SANCTUARY_EXIT_BUNDLE_V1" - refuses it
 * through the EXISTING, already-handled `manifest_unknown_version` path
 * instead of silently attempting to parse an artifact set it does not
 * understand. A V1 bundle (declaring the original literal) is refused by
 * this build's verifier unless it carries EXACTLY
 * `EXIT_BUNDLE_ARTIFACT_KINDS` (below) and nothing else; a
 * known-signers bundle is refused unless it carries EXACTLY
 * `EXIT_BUNDLE_ARTIFACT_KINDS_V1_KNOWN_SIGNERS` and nothing else (checked in
 * server/src/exit/verifier.ts).
 */
export const EXIT_BUNDLE_MANIFEST_VERSION = "SANCTUARY_EXIT_BUNDLE_V1" as const;
export const EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS =
  "SANCTUARY_EXIT_BUNDLE_V1_KNOWN_SIGNERS" as const;
export type ExitBundleManifestVersion =
  | typeof EXIT_BUNDLE_MANIFEST_VERSION
  | typeof EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS;

/**
 * Artifact kinds enumerated by the ORIGINAL v1.1 exit-bundle manifest
 * (`manifest_version === EXIT_BUNDLE_MANIFEST_VERSION`). FROZEN: this exact
 * seven-element array, in this exact order, is the byte-stable V1 contract
 * (test/exit/exit-v2-sdw-memory-archive.test.ts pins it verbatim). The
 * export command MUST list every V1-bundle artifact under one of these
 * kinds and no other; the verifier CLI rejects unknown kinds AND rejects a
 * V1 bundle whose artifact set is not EXACTLY this one (independent gate,
 * item 5).
 *
 * Do NOT add "known_signers" here - see
 * `EXIT_BUNDLE_ARTIFACT_KINDS_V1_KNOWN_SIGNERS` below, which is the exact
 * contract for the SEPARATE `EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS`
 * manifest version instead.
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

/**
 * Exit V2 drill F2 (2026-08-22/23, Erik-ratified option a): the signed
 * DID -> public key table for every attestation signer the exporting
 * fortress verified at an earlier import, so a re-exported (second-hop)
 * reputation bundle stays verifiable. NOT part of the V1 contract above -
 * see `EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS`'s doc comment for why a
 * separate manifest version exists instead of widening V1 in place.
 */
export const KNOWN_SIGNERS_ARTIFACT_KIND = "known_signers" as const;

/**
 * The exact, complete artifact-kind set for
 * `manifest_version === EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS`: the
 * frozen V1 seven plus `known_signers`. A bundle declaring this manifest
 * version is refused unless its artifact set is EXACTLY this one (checked
 * in server/src/exit/verifier.ts, "must match" this literal).
 */
export const EXIT_BUNDLE_ARTIFACT_KINDS_V1_KNOWN_SIGNERS = [
  ...EXIT_BUNDLE_ARTIFACT_KINDS,
  KNOWN_SIGNERS_ARTIFACT_KIND,
] as const;

/**
 * Every artifact-kind literal this codebase recognizes SYNTACTICALLY,
 * across every manifest version - used by the verifier's `isKnownKind`
 * membership check. Recognizing a kind string here is necessary but not
 * sufficient: whether a PARTICULAR kind is required, permitted, or
 * forbidden for a given bundle is the separate, exact per-version set
 * check (`EXIT_BUNDLE_ARTIFACT_KINDS` for V1, above,
 * `EXIT_BUNDLE_ARTIFACT_KINDS_V1_KNOWN_SIGNERS` for the known-signers
 * version) - never this union alone.
 */
export type ExitBundleArtifactKind =
  (typeof EXIT_BUNDLE_ARTIFACT_KINDS_V1_KNOWN_SIGNERS)[number];
