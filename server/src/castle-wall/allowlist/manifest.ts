/**
 * Castle Wall allowlist manifest types.
 *
 * The manifest is the signed root document that lists every rule file in the
 * allowlist directory along with its SHA-256 digest. The filter daemon verifies
 * the manifest signature against a pinned fortress public key (TOFU per scope-lock
 * section 4 OQ #1) and then verifies each rule file's bytes match the manifest's
 * recorded digest. Either check failing means: keep prior ruleset, emit audit,
 * surface to menubar.
 */

import { CASTLE_WALL_SCHEMA_VERSION_V1, CASTLE_WALL_SIGNATURE_SCHEME_V1 } from "../constants.js";

/** A single entry in the manifest's rules array. */
export interface ManifestRuleEntry {
  /** Stable rule id matching the rule file's `id` field. */
  rule_id: string;
  /** Path of the rule file relative to the manifest's directory. */
  file: string;
  /** SHA-256 hex digest of the rule file's UTF-8 bytes. */
  sha256: string;
}

/**
 * Install mode of the agent-origin descriptor (2026-05-29 origin-classifier
 * foundation). Mirrors the Swift `AgentOriginModeWire` enum.
 *
 * - `nat`: agent runs inside a Sanctuary-owned NAT runtime; its egress helper
 *   has a distinct code-signing identity. Recommended (default).
 * - `uid`: agent runs under its own dedicated macOS user account. Fallback.
 */
export type AgentOriginMode = "nat" | "uid";

/**
 * Additive, optional descriptor telling the macOS sysext how to recognise
 * agent-originated flows. Carried INSIDE the signed manifest body so it rides
 * under the existing pinned-key Ed25519 signature; an unsigned or replayed
 * envelope can never inject it.
 *
 * FAIL-CLOSED: when this field is absent, the sysext classifies every flow as
 * `.agent` (machine-wide default-deny preserved); it NEVER infers operator.
 * The daemon must emit a fully-formed descriptor or omit the field entirely:
 * a half-built descriptor is never written (see `validateAgentOrigin`).
 *
 * Field shapes are mode-specific but the type is a single object so the signed
 * body stays a flat document:
 * - `nat`: at least one of `egress_helper_signing_id` / `egress_helper_team_id`
 *   must be present; `agent_runtime_port_range` is an optional [lo, hi] pair.
 * - `uid`: `agent_uid` (the dedicated account uid) must be present.
 * - both: `system_uid_allow_ceiling` is required (uids strictly below it are
 *   treated as system daemons on the conceded operator low-UID path).
 *
 * `gate_uid` (S5-0, 2026-07-14 two-confined-uid extension): a SECOND optional
 * confined-principal uid, valid only alongside `mode: "uid"`. When present,
 * the sysext classifies flows from EITHER `agent_uid` OR `gate_uid` as
 * `.agent` (default-deny + allowlist), never `.operator` -- see
 * `OriginClassifier.classifyUid` in castle-wall-macos. It rides in the same
 * signed body as `agent_uid` so it is covered by the exact same Ed25519
 * signature; canonical-JSON bytes are byte-identical to today when absent
 * (additive, no `schema_version` bump). `validateAgentOrigin` enforces the
 * same floor invariants as `agent_uid` (>=1, >= `system_uid_allow_ceiling`)
 * PLUS distinctness from `agent_uid` (a colliding gate uid would let a
 * gate-scoped `RuleScope.uids` rule apply to the agent's own flows too,
 * defeating the entire two-principal separation) -- any violation rejects the
 * WHOLE descriptor (never a partially-trusted one), the same fail-closed
 * treatment `agent_uid` already gets.
 */
export interface AgentOrigin {
  mode: AgentOriginMode;
  egress_helper_signing_id?: string;
  egress_helper_team_id?: string;
  agent_runtime_port_range?: [number, number];
  agent_uid?: number;
  gate_uid?: number;
  system_uid_allow_ceiling: number;
}

/**
 * One operator-approved system-essential baseline entry. The daemon sources
 * this from `policy/egress/operator-baseline.json` and signs it into the same
 * manifest body as the allowlist. The extension consumes only the signed copy.
 */
export interface OperatorBaselineEssential {
  name: string;
  signing_id?: string;
  team_id?: string;
  source_app_identifier?: string;
}

export interface OperatorBaseline {
  essentials: OperatorBaselineEssential[];
}

/**
 * The unsigned manifest. Canonical-JSON of this structure is the signing input.
 */
export interface AllowlistManifest {
  schema_version: typeof CASTLE_WALL_SCHEMA_VERSION_V1;
  fortress_id: string;
  issued_at: string;
  rules: ManifestRuleEntry[];
  /**
   * Optional agent-origin descriptor. Omitted (NOT null) when absent so the
   * canonical-JSON bytes stay identical to a manifest built without it; both
   * the TS canonicalizer and the Swift `JSONEncoder` drop the field, keeping
   * the signature byte-compatible across versions.
   */
  agent_origin?: AgentOrigin;
  /**
   * Optional operator/system-essential baseline allowlist. Omitted when absent;
   * when present, it is covered by the manifest signature.
   */
  operator_baseline?: OperatorBaseline;
}

/**
 * The Ed25519 signature wrapper produced by Sanctuary main and verified by
 * the filter daemon. The `signing_key_id` is a fingerprint of the public key
 * used so the daemon can detect mismatch against its pinned key without
 * loading the manifest body. `signature_scheme` is the post-quantum migration
 * hinge field already shipped on federation v0.1.
 */
export interface ManifestSignature {
  signature_scheme: typeof CASTLE_WALL_SIGNATURE_SCHEME_V1;
  signing_key_id: string;
  signature_b64url: string;
}

/** A manifest plus its signature. This is the structure persisted on disk. */
export interface SignedManifest {
  manifest: AllowlistManifest;
  signature: ManifestSignature;
}
