/**
 * Sanctuary v1.2 — Intelligence Substrate Audit Payload Contracts
 *
 * Shared payload shapes emitted by the substrate selector and consumed by
 * audit-query callers, the dashboard transparency UI, and the
 * `/api/hub/intelligence/status` route.
 *
 * Local-only invariant:
 * Payloads describe substrate-selection and substrate-invocation activity
 * inside a single fortress on a single operator's machine. v1.2 ships
 * local-only, single-operator scope.
 *
 * Enclosure-and-signing model:
 * Intelligence events are NOT signed objects on their own. They are
 * payloads carried inside an enclosing audit-chain entry
 * (`l2-operational/audit-log` AuditEntry encrypted-at-rest under L1, plus
 * `mesh/audit-batch` SignedAuditBatch where federation propagation
 * applies). The enclosing audit entry carries the signature scheme; this
 * file deliberately does not declare a signature field on any payload type.
 *
 * Operation-name registry:
 * The string operation names emitted into AuditEntry.operation are the
 * `INTEL_OPS` constants in `server/src/intelligence/audit-events.ts`. The
 * `kind` discriminator on each payload mirrors its operation name (with
 * the `intelligence_` prefix dropped) so consumers can pattern-match on
 * payload shape without re-parsing the operation field.
 *
 * When a selector path emits an intelligence event:
 *   1. Build an `IntelligenceAuditPayload` from this file.
 *   2. Append it as the `details` of an `AuditEntry` in the L2 audit log
 *      with operation name from `INTEL_OPS`.
 *   3. The mesh-layer batch envelope signs the batch that carries this
 *      entry where federation propagation applies.
 *
 * Safe-metadata invariant:
 * Raw query bodies, response bodies, and operator credentials MUST NEVER
 * appear in any field of any payload defined in this file. Only safe
 * metadata is permitted: surface enum, substrate enum, failure-class
 * enum, hashes of request/response bodies, latency, identity id, fallback
 * action enum, match counts.
 *
 * Hashing discipline:
 * Substrate-invocation payloads carry hashes of the request and response
 * bodies, never the bodies themselves. v1.2 uses the existing
 * `core/hashing.hashToString(sha256(stringToBytes(...)))` SHA-256 hash
 * encoded as base64url (43 chars, no padding) because intelligence-event
 * payloads are scoped to per-fortress audit chains and the
 * dictionary-attack threat model that drove the v1.1 privacy-events
 * keyed-HMAC requirement does not apply (intelligence payloads are not
 * exchanged across fortress boundaries at v1.2).
 */

import type {
  Surface,
  SubstrateChoice,
  SubstrateFailureClass,
} from "../../intelligence/types.js";

/**
 * Common metadata header on every v1.2 intelligence audit payload.
 *
 * `event_id` is the audit-chain id assigned by the enclosing AuditEntry.
 * `identity_id` is the operator identity that owns the substrate config.
 */
export interface IntelligenceAuditPayloadHeader {
  /** v1.2 payload-shape version. */
  version: "1.2";
  /** Unique event id; SHOULD match the enclosing audit-chain id. */
  event_id: string;
  /** ISO8601 timestamp of the decision. */
  emitted_at: string;
  /** Identity the substrate config is bound to. */
  identity_id: string;
}

/**
 * Operator picked (or re-picked) a substrate for a given surface. Emitted
 * once per operator change in the picker modal; not per invocation.
 */
export interface IntelligenceSubstrateChosenPayload extends IntelligenceAuditPayloadHeader {
  kind: "substrate_chosen";
  surface: Surface;
  substrate: SubstrateChoice;
  /**
   * SHA-256 base64url of the operator-readable tradeoff text the operator
   * saw at choice time. Lets an auditor prove WHICH tradeoff text the
   * operator agreed to without storing the prose itself (which would
   * bloat the audit log and introduce localization drift).
   */
  tradeoff_text_hash: string;
  /** Whether the operator overrode a default vs. accepted the default. */
  was_default: boolean;
  /** Substrate the surface was previously bound to; null on first config. */
  prior_substrate: SubstrateChoice | null;
}

/**
 * A surface invoked the substrate selector. Emitted once per
 * `selector.invoke()` call regardless of success or fallback.
 *
 * The `substrate` field is what the operator chose; the `served_by` field
 * is what actually served the request. They can differ when fallback
 * behavior is `degrade-silent` and the chosen substrate failed.
 */
export interface IntelligenceSubstrateInvokedPayload extends IntelligenceAuditPayloadHeader {
  kind: "substrate_invoked";
  surface: Surface;
  substrate: SubstrateChoice;
  served_by: SubstrateChoice;
  /** SHA-256 base64url of the request body, never the body itself. */
  request_hash: string;
  /** SHA-256 base64url of the response body, or null on failure. */
  response_hash: string | null;
  /** Wall-clock latency in ms. */
  latency_ms: number;
  /** Stable failure-class enum, or null on success. */
  failure_class: SubstrateFailureClass | null;
}

/**
 * The chosen substrate failed. Emitted in addition to the invoked event
 * when fallback behavior fired or the surface was disabled. Lets an
 * auditor reconstruct exactly which failure paths fired in which order.
 */
export interface IntelligenceSubstrateFailurePayload extends IntelligenceAuditPayloadHeader {
  kind: "substrate_failure";
  surface: Surface;
  substrate: SubstrateChoice;
  failure_class: SubstrateFailureClass;
  /** Operator-action taken: which fallback fired, or which surface was disabled. */
  fallback_taken: "next-substrate" | "deny" | "disable-surface";
}

/**
 * A pre-egress PII redaction event. Always emitted before any frontier or
 * Venice call when the surface routes through the substrate selector. The
 * Tier 1 regex filter and the Tier 2 NER+LLM classifier both emit this
 * shape; the `filter_tier` field distinguishes.
 *
 * `match_count` is the number of PII spans the filter found. The actual
 * spans, replacement placeholders, and source text MUST NOT appear here;
 * they live in the encrypted placeholder vault under L1.
 */
export interface IntelligencePiiRedactionEventPayload extends IntelligenceAuditPayloadHeader {
  kind: "pii_redaction_event";
  surface: Surface;
  /** Substrate the redaction was performed for (always pre-egress). */
  substrate: SubstrateChoice;
  /** Number of PII matches the filter produced. */
  match_count: number;
  /** Filter tier that produced the result. 1 = regex; 2 = NER + small-LLM classifier. */
  filter_tier: 1 | 2;
}

/**
 * Operator loaded the substrate config from disk (boot path or
 * post-rotation reload). Emitted to confirm the encrypted config was
 * readable and parsed cleanly; the dashboard transparency UI surfaces a
 * red banner if this event is missing for too long after boot.
 */
export interface IntelligenceConfigLoadedPayload extends IntelligenceAuditPayloadHeader {
  kind: "config_loaded";
  /** Whether the loaded config was the default (no on-disk record found). */
  was_default: boolean;
  /** Number of surfaces with non-default substrate bindings. */
  overridden_surface_count: number;
}

/**
 * Operator reset substrate config to defaults. Emitted on
 * `selector.resetToDefaults()` so post-reset audit trails make the
 * configuration discontinuity visible.
 */
export interface IntelligenceConfigResetPayload extends IntelligenceAuditPayloadHeader {
  kind: "config_reset";
  /** Number of surfaces that had non-default bindings before reset. */
  overridden_surface_count: number;
}

/**
 * Operator picked a substrate and applied it to every surface in one
 * action via the "Apply to all surfaces" affordance. Emitted once per
 * bulk apply. The fan-out is captured in `surface_count` (always 6 in
 * v1.2, equals SURFACES.length) and each per-surface prior substrate
 * is captured in `prior_substrates` for forensic reconstruction.
 *
 * Per-surface `intelligence_substrate_chosen` events are NOT emitted
 * alongside this event; the bulk event is the single source of truth.
 * This avoids audit-log churn when an operator with six default
 * surfaces flips them all to Venice in one click.
 */
export interface IntelligenceBulkSubstrateChosenPayload extends IntelligenceAuditPayloadHeader {
  kind: "bulk_substrate_chosen";
  substrate: SubstrateChoice;
  /** Number of surfaces the substrate was applied to. */
  surface_count: number;
  /** SHA-256 base64url of the operator-readable tradeoff text. */
  tradeoff_text_hash: string;
  /** Per-surface substrate the operator overrode; null if the surface had no prior binding. */
  prior_substrates: Partial<Record<Surface, SubstrateChoice | null>>;
}

/** Discriminated union of every v1.2 intelligence audit payload. */
export type IntelligenceAuditPayload =
  | IntelligenceSubstrateChosenPayload
  | IntelligenceSubstrateInvokedPayload
  | IntelligenceSubstrateFailurePayload
  | IntelligencePiiRedactionEventPayload
  | IntelligenceConfigLoadedPayload
  | IntelligenceConfigResetPayload
  | IntelligenceBulkSubstrateChosenPayload;
