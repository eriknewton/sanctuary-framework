/**
 * Sanctuary Agent Contract v0.1 — Schema Validation.
 *
 * Hand-rolled structural validators matching the spec §3 (Agent Card) and
 * §6 (usage event) JSON Schemas exactly. No runtime dependency on Zod.
 * The policy engine follows the same pattern — deterministic checks on
 * known fields, explicit rejection of unknown fields where forward-compat
 * is not intended.
 *
 * Every validator throws the matching `AgentContractError` subclass on
 * failure. No validator returns partial data or coerces values.
 */

import {
  AGENT_CONTRACT_VERSION,
  CAPABILITY_KINDS,
  EVENT_CLASSES,
  HARNESS_TIERS,
  LIFECYCLE_STATES,
  MODEL_PROVIDERS,
  SIGNATURE_SCHEME_V1,
  type CapabilityKind,
  type EventClass,
  type HarnessTier,
  type LifecycleState,
  type ModelProvider,
} from "./constants.js";
import {
  AgentCardSchemaError,
  UsageEventSchemaError,
  AgentContractError,
} from "./errors.js";
import type {
  AgentCard,
  AgentCardCapability,
  Attestation,
  CommitmentProposal,
  HarnessEnvelope,
  LifecycleEvent,
  UsageEvent,
} from "./types.js";
import { isBase64urlToken } from "../core/token-grammar.js";

// ═══════════════════════════════════════════════════════════════════════
// Primitives
// ═══════════════════════════════════════════════════════════════════════

/**
 * ISO 8601 UTC with required `Z` terminator and second precision or finer.
 * Rejects offsets other than `Z` so receivers don't need timezone math.
 */
const ISO8601_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isBase64url(v: unknown): v is string {
  return isBase64urlToken(v);
}

function isISOUtc(v: unknown): v is string {
  return typeof v === "string" && ISO8601_UTC.test(v);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Enum membership check. */
function isIn<T extends readonly string[]>(
  v: unknown,
  set: T
): v is T[number] {
  return typeof v === "string" && (set as readonly string[]).includes(v);
}

// ═══════════════════════════════════════════════════════════════════════
// Agent Card (§3)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Allowed top-level keys on an Agent Card. Unknown keys are rejected so the
 * schema is closed — spec §3 versions the schema via `schema_version`, not
 * via silent extension. If a future version adds fields, bump schema_version
 * and fan out the allowed key set.
 */
const AGENT_CARD_ALLOWED_KEYS = new Set([
  "schema_version",
  "signature_scheme",
  "agent_id",
  "fortress_id",
  "tier",
  "harness_id",
  "model_provider",
  "model_id",
  "agent_pubkey",
  "policy_version_hash",
  "policy_version",
  "attestation_endpoint",
  "capabilities",
  "issued_at",
  "expires_at",
]);

const CAPABILITY_ALLOWED_KEYS = new Set(["kind", "target", "constraints"]);

/**
 * Validate a single capability entry on an Agent Card. Throws
 * AgentCardSchemaError on any deviation.
 */
export function validateCapability(c: unknown): AgentCardCapability {
  if (!isPlainObject(c)) {
    throw new AgentCardSchemaError(
      `capability must be an object; got ${typeof c}`
    );
  }
  for (const key of Object.keys(c)) {
    if (!CAPABILITY_ALLOWED_KEYS.has(key)) {
      throw new AgentCardSchemaError(
        `capability has unknown key "${key}" — allowed: ${[...CAPABILITY_ALLOWED_KEYS].join(", ")}`
      );
    }
  }
  if (!isIn(c.kind, CAPABILITY_KINDS)) {
    throw new AgentCardSchemaError(
      `capability.kind must be one of ${CAPABILITY_KINDS.join("|")}; got ${JSON.stringify(c.kind)}`
    );
  }
  if (!isNonEmptyString(c.target)) {
    throw new AgentCardSchemaError(
      `capability.target must be a non-empty string; got ${JSON.stringify(c.target)}`
    );
  }
  if ("constraints" in c && c.constraints !== undefined) {
    if (!isPlainObject(c.constraints)) {
      throw new AgentCardSchemaError(
        `capability.constraints must be a plain object if present; got ${typeof c.constraints}`
      );
    }
    if (
      "per_day_max" in c.constraints &&
      c.constraints.per_day_max !== undefined
    ) {
      const pdm = c.constraints.per_day_max;
      if (typeof pdm !== "number" || !Number.isInteger(pdm) || pdm <= 0) {
        throw new AgentCardSchemaError(
          `capability.constraints.per_day_max must be a positive integer (> 0); ` +
            `use omission of the capability to ban it instead of zero-cap. ` +
            `Got ${JSON.stringify(pdm)}`
        );
      }
    }
  }
  const out: AgentCardCapability = {
    kind: c.kind,
    target: c.target,
  };
  if (c.constraints !== undefined) {
    out.constraints = c.constraints as Record<string, unknown>;
  }
  return out;
}

/**
 * Validate an Agent Card against spec §3. Returns the card typed on success;
 * throws AgentCardSchemaError on any deviation.
 *
 * Closed-schema: unknown top-level keys are rejected.
 */
export function validateAgentCard(v: unknown): AgentCard {
  if (!isPlainObject(v)) {
    throw new AgentCardSchemaError(
      `Agent Card must be an object; got ${typeof v}`
    );
  }
  for (const key of Object.keys(v)) {
    if (!AGENT_CARD_ALLOWED_KEYS.has(key)) {
      throw new AgentCardSchemaError(
        `Agent Card has unknown key "${key}" — bump schema_version instead of silently extending`
      );
    }
  }
  if (v.schema_version !== AGENT_CONTRACT_VERSION) {
    throw new AgentCardSchemaError(
      `Agent Card schema_version must be "${AGENT_CONTRACT_VERSION}"; got ${JSON.stringify(v.schema_version)}`
    );
  }
  if (v.signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new AgentCardSchemaError(
      `Agent Card signature_scheme must be "${SIGNATURE_SCHEME_V1}"; got ${JSON.stringify(v.signature_scheme)} — crypto-agility hinge, do not drop`
    );
  }
  if (!isNonEmptyString(v.agent_id)) {
    throw new AgentCardSchemaError(
      `Agent Card agent_id must be a non-empty string`
    );
  }
  if (!isNonEmptyString(v.fortress_id)) {
    throw new AgentCardSchemaError(
      `Agent Card fortress_id must be a non-empty string`
    );
  }
  if (!isIn(v.tier, HARNESS_TIERS)) {
    throw new AgentCardSchemaError(
      `Agent Card tier must be one of ${HARNESS_TIERS.join("|")}; got ${JSON.stringify(v.tier)}`
    );
  }
  if (!isNonEmptyString(v.harness_id)) {
    throw new AgentCardSchemaError(
      `Agent Card harness_id must be a non-empty string`
    );
  }
  if (!isIn(v.model_provider, MODEL_PROVIDERS)) {
    throw new AgentCardSchemaError(
      `Agent Card model_provider must be one of ${MODEL_PROVIDERS.join("|")}; got ${JSON.stringify(v.model_provider)}`
    );
  }
  if (!isNonEmptyString(v.model_id)) {
    throw new AgentCardSchemaError(
      `Agent Card model_id must be a non-empty string`
    );
  }
  if (!isBase64url(v.agent_pubkey)) {
    throw new AgentCardSchemaError(
      `Agent Card agent_pubkey must be a base64url string`
    );
  }
  if (!isBase64url(v.policy_version_hash)) {
    throw new AgentCardSchemaError(
      `Agent Card policy_version_hash must be a base64url string`
    );
  }
  if (typeof v.policy_version !== "number" || !Number.isInteger(v.policy_version)) {
    throw new AgentCardSchemaError(
      `Agent Card policy_version must be an integer; got ${JSON.stringify(v.policy_version)}`
    );
  }
  if (!isNonEmptyString(v.attestation_endpoint)) {
    throw new AgentCardSchemaError(
      `Agent Card attestation_endpoint must be a non-empty string`
    );
  }
  if (!Array.isArray(v.capabilities)) {
    throw new AgentCardSchemaError(
      `Agent Card capabilities must be an array; got ${typeof v.capabilities}`
    );
  }
  for (const c of v.capabilities) validateCapability(c);
  if (!isISOUtc(v.issued_at)) {
    throw new AgentCardSchemaError(
      `Agent Card issued_at must be ISO8601 UTC (with Z terminator); got ${JSON.stringify(v.issued_at)}`
    );
  }
  if (v.expires_at !== undefined && !isISOUtc(v.expires_at)) {
    throw new AgentCardSchemaError(
      `Agent Card expires_at must be ISO8601 UTC or omitted; got ${JSON.stringify(v.expires_at)}`
    );
  }
  const out: AgentCard = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    agent_id: v.agent_id as string,
    fortress_id: v.fortress_id as string,
    tier: v.tier as HarnessTier,
    harness_id: v.harness_id as string,
    model_provider: v.model_provider as ModelProvider,
    model_id: v.model_id as string,
    agent_pubkey: v.agent_pubkey as string,
    policy_version_hash: v.policy_version_hash as string,
    policy_version: v.policy_version,
    attestation_endpoint: v.attestation_endpoint as string,
    capabilities: v.capabilities.map(validateCapability),
    issued_at: v.issued_at as string,
  };
  if (v.expires_at !== undefined) {
    out.expires_at = v.expires_at as string;
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
// Usage event (§6)
// ═══════════════════════════════════════════════════════════════════════

const USAGE_EVENT_ALLOWED_KEYS = new Set([
  "schema_version",
  "signature_scheme",
  "usage_event_id",
  "agent_id",
  "fortress_id",
  "event_class",
  "capability_kind",
  "capability_target",
  "input_hash",
  "output_hash",
  "policy_version",
  "policy_version_hash",
  "attestation_state",
  "emitted_at",
  "references",
  "extension",
]);

const USAGE_EVENT_REFERENCE_ALLOWED_KEYS = new Set(["event_type", "event_id"]);

const ATTESTATION_STATES = ["present", "degraded", "unavailable"] as const;

export function validateUsageEvent(v: unknown): UsageEvent {
  if (!isPlainObject(v)) {
    throw new UsageEventSchemaError(
      `usage event must be an object; got ${typeof v}`
    );
  }
  for (const key of Object.keys(v)) {
    if (!USAGE_EVENT_ALLOWED_KEYS.has(key)) {
      throw new UsageEventSchemaError(
        `usage event has unknown key "${key}"`
      );
    }
  }
  if (v.schema_version !== AGENT_CONTRACT_VERSION) {
    throw new UsageEventSchemaError(
      `usage event schema_version must be "${AGENT_CONTRACT_VERSION}"; got ${JSON.stringify(v.schema_version)}`
    );
  }
  if (v.signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new UsageEventSchemaError(
      `usage event signature_scheme must be "${SIGNATURE_SCHEME_V1}"; got ${JSON.stringify(v.signature_scheme)}`
    );
  }
  if (!isNonEmptyString(v.usage_event_id)) {
    throw new UsageEventSchemaError(
      `usage event usage_event_id must be a non-empty string`
    );
  }
  if (!isNonEmptyString(v.agent_id)) {
    throw new UsageEventSchemaError(
      `usage event agent_id must be a non-empty string`
    );
  }
  if (!isNonEmptyString(v.fortress_id)) {
    throw new UsageEventSchemaError(
      `usage event fortress_id must be a non-empty string`
    );
  }
  if (!isIn(v.event_class, EVENT_CLASSES)) {
    throw new UsageEventSchemaError(
      `usage event event_class must be one of ${EVENT_CLASSES.join("|")}; got ${JSON.stringify(v.event_class)}`
    );
  }
  if (v.capability_kind !== undefined) {
    if (!isIn(v.capability_kind, CAPABILITY_KINDS)) {
      throw new UsageEventSchemaError(
        `usage event capability_kind must be one of ${CAPABILITY_KINDS.join("|")}; got ${JSON.stringify(v.capability_kind)}`
      );
    }
    if (v.event_class !== "tool_call") {
      throw new UsageEventSchemaError(
        `usage event capability_kind may only be set when event_class === "tool_call"; got event_class=${JSON.stringify(v.event_class)}`
      );
    }
  }
  if (!isNonEmptyString(v.capability_target)) {
    throw new UsageEventSchemaError(
      `usage event capability_target must be a non-empty string`
    );
  }
  if (!isBase64url(v.input_hash)) {
    throw new UsageEventSchemaError(
      `usage event input_hash must be a base64url string`
    );
  }
  if (!isBase64url(v.output_hash)) {
    throw new UsageEventSchemaError(
      `usage event output_hash must be a base64url string`
    );
  }
  if (
    typeof v.policy_version !== "number" ||
    !Number.isInteger(v.policy_version)
  ) {
    throw new UsageEventSchemaError(
      `usage event policy_version must be an integer`
    );
  }
  if (!isBase64url(v.policy_version_hash)) {
    throw new UsageEventSchemaError(
      `usage event policy_version_hash must be a base64url string`
    );
  }
  if (!isIn(v.attestation_state, ATTESTATION_STATES)) {
    throw new UsageEventSchemaError(
      `usage event attestation_state must be one of ${ATTESTATION_STATES.join("|")}; got ${JSON.stringify(v.attestation_state)}`
    );
  }
  if (!isISOUtc(v.emitted_at)) {
    throw new UsageEventSchemaError(
      `usage event emitted_at must be ISO8601 UTC with Z terminator`
    );
  }
  if (v.extension !== undefined && !isPlainObject(v.extension)) {
    throw new UsageEventSchemaError(
      `usage event extension must be a plain object if present`
    );
  }
  const validatedReferences =
    v.references !== undefined ? validateUsageEventReferences(v.references) : undefined;
  const out: UsageEvent = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    usage_event_id: v.usage_event_id as string,
    agent_id: v.agent_id as string,
    fortress_id: v.fortress_id as string,
    event_class: v.event_class as EventClass,
    capability_target: v.capability_target as string,
    input_hash: v.input_hash as string,
    output_hash: v.output_hash as string,
    policy_version: v.policy_version,
    policy_version_hash: v.policy_version_hash as string,
    attestation_state: v.attestation_state as UsageEvent["attestation_state"],
    emitted_at: v.emitted_at as string,
  };
  if (v.capability_kind !== undefined) {
    out.capability_kind = v.capability_kind as CapabilityKind;
  }
  if (validatedReferences !== undefined) {
    out.references = validatedReferences;
  }
  if (v.extension !== undefined) {
    out.extension = v.extension as Record<string, unknown>;
  }
  return out;
}

/**
 * Validate the `references[]` array on a usage event per spec §6.
 *
 * Each entry is `{ event_type, event_id }` where `event_type` MUST be a member
 * of `EVENT_CLASSES` (allow-listed) and `event_id` MUST be a non-empty string
 * pointing at a prior usage event's `usage_event_id`.
 *
 * Empty array is allowed; absence vs empty array carry the same semantics
 * (no causal link). Unknown keys on entries are rejected: the closed-schema
 * convention applies here too.
 */
export function validateUsageEventReferences(
  v: unknown
): Array<{ event_type: EventClass; event_id: string }> {
  if (!Array.isArray(v)) {
    throw new UsageEventSchemaError(
      `usage event references must be an array if present; got ${typeof v}`
    );
  }
  const out: Array<{ event_type: EventClass; event_id: string }> = [];
  for (const entry of v) {
    if (!isPlainObject(entry)) {
      throw new UsageEventSchemaError(
        `usage event references entry must be an object; got ${typeof entry}`
      );
    }
    for (const key of Object.keys(entry)) {
      if (!USAGE_EVENT_REFERENCE_ALLOWED_KEYS.has(key)) {
        throw new UsageEventSchemaError(
          `usage event references entry has unknown key "${key}"`
        );
      }
    }
    if (!isIn(entry.event_type, EVENT_CLASSES)) {
      throw new UsageEventSchemaError(
        `usage event references entry event_type must be one of ${EVENT_CLASSES.join("|")}; got ${JSON.stringify(entry.event_type)}`
      );
    }
    if (!isNonEmptyString(entry.event_id)) {
      throw new UsageEventSchemaError(
        `usage event references entry event_id must be a non-empty string`
      );
    }
    out.push({
      event_type: entry.event_type as EventClass,
      event_id: entry.event_id as string,
    });
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
// Lifecycle event (§2.8)
// ═══════════════════════════════════════════════════════════════════════

const LIFECYCLE_FROM_STATES = [...LIFECYCLE_STATES, "uninstantiated"] as const;

export function validateLifecycleEvent(v: unknown): LifecycleEvent {
  if (!isPlainObject(v)) {
    throw new AgentContractError(
      `lifecycle event must be an object; got ${typeof v}`
    );
  }
  if (v.schema_version !== AGENT_CONTRACT_VERSION) {
    throw new AgentContractError(
      `lifecycle event schema_version must be "${AGENT_CONTRACT_VERSION}"`
    );
  }
  if (v.signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new AgentContractError(
      `lifecycle event signature_scheme must be "${SIGNATURE_SCHEME_V1}"`
    );
  }
  if (!isNonEmptyString(v.agent_id)) {
    throw new AgentContractError(`lifecycle event agent_id required`);
  }
  if (!isNonEmptyString(v.fortress_id)) {
    throw new AgentContractError(`lifecycle event fortress_id required`);
  }
  if (!isIn(v.from_state, LIFECYCLE_FROM_STATES)) {
    throw new AgentContractError(
      `lifecycle event from_state must be one of ${LIFECYCLE_FROM_STATES.join("|")}`
    );
  }
  if (!isIn(v.to_state, LIFECYCLE_STATES)) {
    throw new AgentContractError(
      `lifecycle event to_state must be one of ${LIFECYCLE_STATES.join("|")}`
    );
  }
  if (!isNonEmptyString(v.reason)) {
    throw new AgentContractError(`lifecycle event reason required`);
  }
  if (!isISOUtc(v.emitted_at)) {
    throw new AgentContractError(`lifecycle event emitted_at must be ISO8601 UTC`);
  }
  if (v.checkpoint_hash !== undefined && !isBase64url(v.checkpoint_hash)) {
    throw new AgentContractError(
      `lifecycle event checkpoint_hash must be base64url if present`
    );
  }
  if (v.guardian_quorum !== undefined) {
    if (!Array.isArray(v.guardian_quorum)) {
      throw new AgentContractError(
        `lifecycle event guardian_quorum must be an array if present`
      );
    }
    for (const g of v.guardian_quorum) {
      if (!isPlainObject(g)) {
        throw new AgentContractError(
          `guardian_quorum entry must be an object`
        );
      }
      if (!isBase64url(g.guardian_pubkey) || !isBase64url(g.signature)) {
        throw new AgentContractError(
          `guardian_quorum entry must have base64url guardian_pubkey + signature`
        );
      }
    }
  }
  const out: LifecycleEvent = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    agent_id: v.agent_id as string,
    fortress_id: v.fortress_id as string,
    from_state: v.from_state as LifecycleEvent["from_state"],
    to_state: v.to_state as LifecycleState,
    reason: v.reason as string,
    emitted_at: v.emitted_at as string,
  };
  if (v.checkpoint_hash !== undefined) {
    out.checkpoint_hash = v.checkpoint_hash as string;
  }
  if (v.guardian_quorum !== undefined) {
    out.guardian_quorum = (v.guardian_quorum as Array<Record<string, unknown>>).map((g) => ({
      guardian_pubkey: g.guardian_pubkey as string,
      signature: g.signature as string,
    }));
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
// Attestation (§2.9)
// ═══════════════════════════════════════════════════════════════════════

const ATTESTATION_SOURCES = ["harness_self_report", "proxy_canonical"] as const;

export function validateAttestation(v: unknown): Attestation {
  if (!isPlainObject(v)) {
    throw new AgentContractError(
      `attestation must be an object; got ${typeof v}`
    );
  }
  if (v.schema_version !== AGENT_CONTRACT_VERSION) {
    throw new AgentContractError(`attestation schema_version mismatch`);
  }
  if (v.signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new AgentContractError(`attestation signature_scheme mismatch`);
  }
  if (!isNonEmptyString(v.attestation_id)) {
    throw new AgentContractError(`attestation_id required`);
  }
  if (!isNonEmptyString(v.agent_id)) {
    throw new AgentContractError(`attestation agent_id required`);
  }
  if (!isNonEmptyString(v.fortress_id)) {
    throw new AgentContractError(`attestation fortress_id required`);
  }
  if (!isNonEmptyString(v.usage_event_id)) {
    throw new AgentContractError(`attestation usage_event_id required`);
  }
  if (!isIn(v.source, ATTESTATION_SOURCES)) {
    throw new AgentContractError(
      `attestation source must be one of ${ATTESTATION_SOURCES.join("|")}`
    );
  }
  if (!isBase64url(v.attested_hash)) {
    throw new AgentContractError(`attestation attested_hash must be base64url`);
  }
  if (!isISOUtc(v.emitted_at)) {
    throw new AgentContractError(`attestation emitted_at must be ISO8601 UTC`);
  }
  if (v.attested_payload !== undefined && !isPlainObject(v.attested_payload)) {
    throw new AgentContractError(
      `attestation attested_payload must be a plain object if present`
    );
  }
  const out: Attestation = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    attestation_id: v.attestation_id as string,
    agent_id: v.agent_id as string,
    fortress_id: v.fortress_id as string,
    usage_event_id: v.usage_event_id as string,
    source: v.source as Attestation["source"],
    attested_hash: v.attested_hash as string,
    emitted_at: v.emitted_at as string,
  };
  if (v.attested_payload !== undefined) {
    out.attested_payload = v.attested_payload as Record<string, unknown>;
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
// Commitment proposal (§7.1 output shape)
// ═══════════════════════════════════════════════════════════════════════

export function validateCommitmentProposal(v: unknown): CommitmentProposal {
  if (!isPlainObject(v)) {
    throw new AgentContractError(
      `commitment proposal must be an object; got ${typeof v}`
    );
  }
  if (v.schema_version !== AGENT_CONTRACT_VERSION) {
    throw new AgentContractError(`commitment proposal schema_version mismatch`);
  }
  if (v.signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new AgentContractError(`commitment proposal signature_scheme mismatch`);
  }
  if (!isNonEmptyString(v.proposal_id)) {
    throw new AgentContractError(`commitment proposal proposal_id required`);
  }
  if (!isNonEmptyString(v.agent_id)) {
    throw new AgentContractError(`commitment proposal agent_id required`);
  }
  if (!isNonEmptyString(v.fortress_id)) {
    throw new AgentContractError(`commitment proposal fortress_id required`);
  }
  if (!isNonEmptyString(v.commitment_class)) {
    throw new AgentContractError(`commitment proposal commitment_class required`);
  }
  if (!isNonEmptyString(v.counterparty)) {
    throw new AgentContractError(`commitment proposal counterparty required`);
  }
  if (!isPlainObject(v.bounded_scope)) {
    throw new AgentContractError(`commitment proposal bounded_scope required`);
  }
  for (const field of [
    "deliverable",
    "deadline_or_terminal",
    "budget_ref",
  ] as const) {
    const bs = v.bounded_scope as Record<string, unknown>;
    if (!isNonEmptyString(bs[field])) {
      throw new AgentContractError(
        `commitment proposal bounded_scope.${field} required (non-empty)`
      );
    }
  }
  if (
    typeof v.policy_version !== "number" ||
    !Number.isInteger(v.policy_version)
  ) {
    throw new AgentContractError(`commitment proposal policy_version must be integer`);
  }
  if (!isBase64url(v.policy_version_hash)) {
    throw new AgentContractError(`commitment proposal policy_version_hash base64url required`);
  }
  if (!isISOUtc(v.emitted_at)) {
    throw new AgentContractError(`commitment proposal emitted_at must be ISO8601 UTC`);
  }
  if (!isNonEmptyString(v.gate_receipt_id)) {
    throw new AgentContractError(`commitment proposal gate_receipt_id required`);
  }
  const bs = v.bounded_scope as Record<string, unknown>;
  return {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    proposal_id: v.proposal_id as string,
    agent_id: v.agent_id as string,
    fortress_id: v.fortress_id as string,
    commitment_class: v.commitment_class as CommitmentProposal["commitment_class"],
    counterparty: v.counterparty as string,
    bounded_scope: {
      deliverable: bs.deliverable as string,
      deadline_or_terminal: bs.deadline_or_terminal as string,
      budget_ref: bs.budget_ref as string,
    },
    policy_version: v.policy_version,
    policy_version_hash: v.policy_version_hash as string,
    emitted_at: v.emitted_at as string,
    gate_receipt_id: v.gate_receipt_id as string,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Harness envelope (§2.3)
// ═══════════════════════════════════════════════════════════════════════

const ENVELOPE_DIRECTIONS = ["harness_in", "harness_out"] as const;

export function validateHarnessEnvelope(v: unknown): HarnessEnvelope {
  if (!isPlainObject(v)) {
    throw new AgentContractError(
      `harness envelope must be an object; got ${typeof v}`
    );
  }
  if (v.schema_version !== AGENT_CONTRACT_VERSION) {
    throw new AgentContractError(`harness envelope schema_version mismatch`);
  }
  if (v.signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new AgentContractError(`harness envelope signature_scheme mismatch`);
  }
  if (!isNonEmptyString(v.envelope_id)) {
    throw new AgentContractError(`harness envelope envelope_id required`);
  }
  if (!isIn(v.direction, ENVELOPE_DIRECTIONS)) {
    throw new AgentContractError(
      `harness envelope direction must be one of ${ENVELOPE_DIRECTIONS.join("|")}`
    );
  }
  if (!isNonEmptyString(v.agent_id)) {
    throw new AgentContractError(`harness envelope agent_id required`);
  }
  if (!isNonEmptyString(v.fortress_id)) {
    throw new AgentContractError(`harness envelope fortress_id required`);
  }
  if (!isIn(v.capability_kind, CAPABILITY_KINDS)) {
    throw new AgentContractError(
      `harness envelope capability_kind must be a valid CapabilityKind`
    );
  }
  if (!isNonEmptyString(v.capability_target)) {
    throw new AgentContractError(`harness envelope capability_target required`);
  }
  if (v.body === undefined) {
    throw new AgentContractError(`harness envelope body required`);
  }
  if (!isBase64url(v.body_hash)) {
    throw new AgentContractError(`harness envelope body_hash must be base64url`);
  }
  if (
    typeof v.policy_version !== "number" ||
    !Number.isInteger(v.policy_version)
  ) {
    throw new AgentContractError(`harness envelope policy_version must be integer`);
  }
  if (!isPlainObject(v.sender_claim)) {
    throw new AgentContractError(`harness envelope sender_claim required`);
  }
  const claim = v.sender_claim as Record<string, unknown>;
  if (!isNonEmptyString(claim.claimant) || !isISOUtc(claim.asserted_at)) {
    throw new AgentContractError(
      `harness envelope sender_claim.{claimant,asserted_at} malformed`
    );
  }
  if (!isISOUtc(v.wrapped_at)) {
    throw new AgentContractError(`harness envelope wrapped_at must be ISO8601 UTC`);
  }
  if (v.receiver_check !== undefined) {
    if (!isPlainObject(v.receiver_check)) {
      throw new AgentContractError(
        `harness envelope receiver_check must be an object if present`
      );
    }
    const rc = v.receiver_check as Record<string, unknown>;
    if (rc.decision !== "allow" && rc.decision !== "deny") {
      throw new AgentContractError(
        `harness envelope receiver_check.decision must be allow|deny`
      );
    }
    if (!isNonEmptyString(rc.reason_code)) {
      throw new AgentContractError(
        `harness envelope receiver_check.reason_code required`
      );
    }
  }
  const senderClaim = v.sender_claim as Record<string, unknown>;
  const out: HarnessEnvelope = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    envelope_id: v.envelope_id as string,
    direction: v.direction as HarnessEnvelope["direction"],
    agent_id: v.agent_id as string,
    fortress_id: v.fortress_id as string,
    capability_kind: v.capability_kind as CapabilityKind,
    capability_target: v.capability_target as string,
    body: v.body,
    body_hash: v.body_hash as string,
    policy_version: v.policy_version,
    sender_claim: {
      claimant: senderClaim.claimant as string,
      asserted_at: senderClaim.asserted_at as string,
    },
    wrapped_at: v.wrapped_at as string,
  };
  if (v.receiver_check !== undefined) {
    const rc = v.receiver_check as Record<string, unknown>;
    const recv: HarnessEnvelope["receiver_check"] = {
      decision: rc.decision as "allow" | "deny",
      reason_code: rc.reason_code as string,
    };
    if (rc.gate_receipt_id !== undefined) {
      if (typeof rc.gate_receipt_id !== "string") {
        throw new AgentContractError(
          `harness envelope receiver_check.gate_receipt_id must be a string when present`
        );
      }
      recv!.gate_receipt_id = rc.gate_receipt_id;
    }
    out.receiver_check = recv;
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
// Type-level reassurance — exhaustiveness aids
// ═══════════════════════════════════════════════════════════════════════

/** Compile-time check: every CapabilityKind is enumerated. */
const _exhaustiveCapabilityKind: Record<CapabilityKind, true> = {
  "read-slot": true,
  "write-slot": true,
  "subscribe-slot": true,
  "tool-call": true,
  egress: true,
  "concordia-commitment": true,
  attestation: true,
  lifecycle: true,
};
void _exhaustiveCapabilityKind;

/** Compile-time check: every HarnessTier is enumerated. */
const _exhaustiveHarnessTier: Record<HarnessTier, true> = {
  A: true,
  B: true,
  C: true,
};
void _exhaustiveHarnessTier;

/** Compile-time check: every LifecycleState is enumerated. */
const _exhaustiveLifecycleState: Record<LifecycleState, true> = {
  launched: true,
  paused: true,
  checkpointed: true,
  resumed: true,
  retired: true,
  revoked: true,
};
void _exhaustiveLifecycleState;

/** Compile-time check: every ModelProvider is enumerated. */
const _exhaustiveModelProvider: Record<ModelProvider, true> = {
  anthropic: true,
  openai: true,
  google: true,
  meta: true,
  mistral: true,
  cohere: true,
  xai: true,
  venice: true,
  "self-hosted": true,
  other: true,
};
void _exhaustiveModelProvider;

/** Compile-time check: every EventClass is enumerated. */
const _exhaustiveEventClass: Record<EventClass, true> = {
  launched: true,
  paused: true,
  checkpointed: true,
  resumed: true,
  retired: true,
  revoked: true,
  tool_call: true,
  egress_request: true,
  egress_blocked: true,
  gate_request: true,
  gate_approved: true,
  gate_denied: true,
  gate_timeout: true,
  policy_pinned: true,
  policy_update_requested: true,
  capability_declared: true,
  capability_extension_requested: true,
  envelope_sent: true,
  envelope_received: true,
  attestation_emitted: true,
  attestation_failed: true,
  commitment_proposed: true,
  commitment_accepted: true,
  commitment_fulfilled: true,
  commitment_unwound: true,
  mandate_referenced: true,
  mandate_revoked: true,
  budget_consumed: true,
  budget_exceeded: true,
  retention_sweep: true,
  sentinel_alert: true,
};
void _exhaustiveEventClass;
