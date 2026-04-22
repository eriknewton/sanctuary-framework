/**
 * Sanctuary Policy Engine — Canonical compiled-policy blob.
 *
 * The mesh's PolicyUpdatePayload carries `policy_blob: string` as opaque
 * bytes. This engine is authoritative on the blob shape. The wire shape is:
 *
 *   policy_blob = base64url(canonicalizeToBytes(compiled_policy))
 *
 * Deterministic across senders (canonical-JSON sorted keys, no Unicode
 * variance, no timestamp drift once compiled). Receivers decode and run the
 * same shape check the sender ran.
 *
 * Schema is schema_version-tagged. Unknown schema_version values are
 * rejected — a v0.2 blob landing on a v0.1 verifier is a hard error, never
 * a silent degrade.
 */

import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import {
  COMPILED_POLICY_SCHEMA_VERSION,
  POLICY_SLOTS,
  isPolicySlot,
} from "./constants.js";
import { CompiledPolicyShapeError, PolicyBlobDecodeError } from "./errors.js";
import type { CompiledPolicy, SlotGrant, SlotRule } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Shape check — runtime structural validation
// ═══════════════════════════════════════════════════════════════════════

function checkSlotGrant(value: unknown, path: string): asserts value is SlotGrant {
  if (typeof value !== "object" || value === null) {
    throw new CompiledPolicyShapeError(`${path}: grant must be an object`);
  }
  const g = value as Record<string, unknown>;
  if (typeof g.counterparty !== "string" || g.counterparty.length === 0) {
    throw new CompiledPolicyShapeError(
      `${path}.counterparty must be a non-empty string`
    );
  }
  if (typeof g.action !== "string" || g.action.length === 0) {
    throw new CompiledPolicyShapeError(
      `${path}.action must be a non-empty string`
    );
  }
  if (g.scope !== undefined) {
    if (typeof g.scope !== "object" || g.scope === null || Array.isArray(g.scope)) {
      throw new CompiledPolicyShapeError(
        `${path}.scope must be an object when present`
      );
    }
  }
  if (g.max_uses_per_day !== undefined) {
    if (
      typeof g.max_uses_per_day !== "number" ||
      !Number.isInteger(g.max_uses_per_day) ||
      g.max_uses_per_day < 0
    ) {
      throw new CompiledPolicyShapeError(
        `${path}.max_uses_per_day must be a non-negative integer when present`
      );
    }
  }
}

function checkSlotRule(
  slot: string,
  value: unknown,
  path: string
): asserts value is SlotRule {
  if (typeof value !== "object" || value === null) {
    throw new CompiledPolicyShapeError(`${path}: slot rule must be an object`);
  }
  const r = value as Record<string, unknown>;
  if (r.slot !== slot) {
    throw new CompiledPolicyShapeError(
      `${path}.slot expected ${slot}, got ${String(r.slot)}`
    );
  }
  if (r.mode !== "deny" && r.mode !== "grant") {
    throw new CompiledPolicyShapeError(
      `${path}.mode must be "deny" or "grant"`
    );
  }
  if (!Array.isArray(r.grants)) {
    throw new CompiledPolicyShapeError(
      `${path}.grants must be an array (possibly empty)`
    );
  }
  if (r.mode === "deny" && r.grants.length > 0) {
    throw new CompiledPolicyShapeError(
      `${path}: deny-mode slot rule must carry zero grants`
    );
  }
  r.grants.forEach((g, i) => checkSlotGrant(g, `${path}.grants[${i}]`));
}

/**
 * Exhaustive runtime shape check on a CompiledPolicy candidate. Throws
 * CompiledPolicyShapeError on any deviation; on success narrows the type.
 *
 * This check is load-bearing — every receiver runs it against the blob the
 * sender signed. A sender that tries to introduce a fifth slot, or a grant
 * list under "deny" mode, or a non-monotonic version fails here before any
 * gate evaluates anything.
 */
export function validateCompiledPolicyShape(
  candidate: unknown
): asserts candidate is CompiledPolicy {
  if (typeof candidate !== "object" || candidate === null) {
    throw new CompiledPolicyShapeError("compiled policy must be an object");
  }
  const p = candidate as Record<string, unknown>;

  if (p.schema_version !== COMPILED_POLICY_SCHEMA_VERSION) {
    throw new CompiledPolicyShapeError(
      `schema_version ${String(p.schema_version)} not supported at v0.1 (expected "${COMPILED_POLICY_SCHEMA_VERSION}")`
    );
  }
  if (typeof p.agent_id !== "string" || p.agent_id.length === 0) {
    throw new CompiledPolicyShapeError("agent_id must be a non-empty string");
  }
  if (typeof p.fortress_id !== "string" || p.fortress_id.length === 0) {
    throw new CompiledPolicyShapeError(
      "fortress_id must be a non-empty string"
    );
  }
  if (
    typeof p.policy_version !== "number" ||
    !Number.isInteger(p.policy_version) ||
    p.policy_version < 0
  ) {
    throw new CompiledPolicyShapeError(
      "policy_version must be a non-negative integer"
    );
  }
  if (
    p.parent_version !== undefined &&
    (typeof p.parent_version !== "number" ||
      !Number.isInteger(p.parent_version) ||
      p.parent_version < 0)
  ) {
    throw new CompiledPolicyShapeError(
      "parent_version must be a non-negative integer when present"
    );
  }

  if (typeof p.slots !== "object" || p.slots === null) {
    throw new CompiledPolicyShapeError("slots must be an object");
  }
  const slots = p.slots as Record<string, unknown>;
  const slotKeys = Object.keys(slots).sort();
  const expectedSlotKeys = [...POLICY_SLOTS].sort();
  if (
    slotKeys.length !== expectedSlotKeys.length ||
    !slotKeys.every((k, i) => k === expectedSlotKeys[i])
  ) {
    throw new CompiledPolicyShapeError(
      `slots must contain exactly ${expectedSlotKeys.join(", ")}; got ${slotKeys.join(", ") || "(none)"}`
    );
  }
  for (const slot of POLICY_SLOTS) {
    checkSlotRule(slot, slots[slot], `slots.${slot}`);
  }

  if (typeof p.capabilities !== "object" || p.capabilities === null) {
    throw new CompiledPolicyShapeError("capabilities must be an object");
  }
  const caps = p.capabilities as Record<string, unknown>;
  if (
    !Array.isArray(caps.concordia_commitment_classes) ||
    !caps.concordia_commitment_classes.every((c) => typeof c === "string")
  ) {
    throw new CompiledPolicyShapeError(
      "capabilities.concordia_commitment_classes must be a string[]"
    );
  }
  if (
    !Array.isArray(caps.honeypot_skill_ids) ||
    !caps.honeypot_skill_ids.every((c) => typeof c === "string")
  ) {
    throw new CompiledPolicyShapeError(
      "capabilities.honeypot_skill_ids must be a string[]"
    );
  }
  if (typeof caps.is_sentinel !== "boolean") {
    throw new CompiledPolicyShapeError(
      "capabilities.is_sentinel must be boolean"
    );
  }

  if (
    typeof p.auto_trigger_ladder !== "object" ||
    p.auto_trigger_ladder === null
  ) {
    throw new CompiledPolicyShapeError(
      "auto_trigger_ladder must be an object"
    );
  }
  const lad = p.auto_trigger_ladder as Record<string, unknown>;
  if (typeof lad.honeypot_auto_freeze !== "boolean") {
    throw new CompiledPolicyShapeError(
      "auto_trigger_ladder.honeypot_auto_freeze must be boolean"
    );
  }
  if (
    lad.threshold_rule_action !== "operator_approved" &&
    lad.threshold_rule_action !== "auto"
  ) {
    throw new CompiledPolicyShapeError(
      'auto_trigger_ladder.threshold_rule_action must be "operator_approved" or "auto"'
    );
  }
  if (
    lad.ml_anomaly_action !== "operator_approved" &&
    lad.ml_anomaly_action !== "auto"
  ) {
    throw new CompiledPolicyShapeError(
      'auto_trigger_ladder.ml_anomaly_action must be "operator_approved" or "auto"'
    );
  }

  if (typeof p.source_english !== "string") {
    throw new CompiledPolicyShapeError("source_english must be a string");
  }
  if (typeof p.compiled_at !== "string" || Number.isNaN(Date.parse(p.compiled_at))) {
    throw new CompiledPolicyShapeError(
      "compiled_at must be an ISO8601 timestamp string"
    );
  }

  // All POLICY_SLOTS are valid — checkSlotRule asserted each slot key too.
  // This is a defense-in-depth check in case someone expands POLICY_SLOTS
  // without updating the schema check logic.
  for (const key of slotKeys) {
    if (!isPolicySlot(key)) {
      throw new CompiledPolicyShapeError(
        `slots.${key} is not a recognized policy slot`
      );
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Encode / decode
// ═══════════════════════════════════════════════════════════════════════

/**
 * Encode a CompiledPolicy to the wire blob carried by PolicyUpdatePayload.
 * Canonical JSON then base64url — byte-identical across platforms.
 */
export function encodePolicyBlob(policy: CompiledPolicy): string {
  validateCompiledPolicyShape(policy);
  return toBase64url(canonicalizeToBytes(policy));
}

/**
 * Decode a wire blob back to a CompiledPolicy. Runs full shape validation.
 *
 * Throws PolicyBlobDecodeError for base64 / JSON decoding failures,
 * CompiledPolicyShapeError for schema failures. Receivers MUST handle both
 * and translate to the appropriate mesh error — NEVER silently fall back to
 * a permissive default.
 */
export function decodePolicyBlob(blob: string): CompiledPolicy {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64url(blob);
  } catch (err) {
    throw new PolicyBlobDecodeError(
      `policy_blob is not valid base64url: ${(err as Error).message}`
    );
  }
  let parsed: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(text);
  } catch (err) {
    throw new PolicyBlobDecodeError(
      `policy_blob is not valid canonical JSON: ${(err as Error).message}`
    );
  }
  validateCompiledPolicyShape(parsed);
  return parsed;
}
