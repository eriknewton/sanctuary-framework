/**
 * Plugin substrate — host-owned closed field allowlist (design §3.2/§3.2a; RFC §4.1a).
 *
 * The field set a plugin may request is a HOST decision, not a plugin assertion. Each
 * field is tagged Low / Sensitive / (Never = simply absent from any table). A manifest
 * field outside the table REJECTS the install — it is never silently ignored. Sensitive
 * fields require a Tier-1 per-field grant at install (enforced in S4); S1 fixes the
 * tables + the rejection rule.
 *
 * This is the closed allowlist applied to NESTED selectors too, not only top-level
 * manifest keys (codex HIGH): a Sensitive `arguments_fields` request is a list of
 * JSON-pointers, each of which must be a member of the per-hook Sensitive selector set.
 */

import { reject } from "./errors.js";

export type HookClass =
  | "egress_decision"
  | "ingress_content"
  | "policy_decision"
  | "substrate_identity";

export type Sensitivity = "low" | "sensitive";

export interface FieldSpec {
  readonly field: string;
  readonly sensitivity: Sensitivity;
}

/**
 * The closed allowlist, per hook class. "Never"-tier data (keys, raw state, raw audit,
 * policy internals, another plugin's data) is intentionally ABSENT — not requestable.
 *
 * S1 ships the egress_decision table fully (the slice-1 hook) and the skeleton for the
 * other three so the types slot in without contract churn (design §8: "the contract
 * surface (S1) already covers their types").
 */
export const FIELD_ALLOWLIST: Record<HookClass, readonly FieldSpec[]> = {
  egress_decision: [
    { field: "egress.host", sensitivity: "low" },
    { field: "egress.port", sensitivity: "low" },
    { field: "egress.protocol", sensitivity: "low" },
    { field: "origin.channel", sensitivity: "low" },
    { field: "origin.trust_label", sensitivity: "low" },
  ],
  ingress_content: [
    { field: "ingress.content_length", sensitivity: "low" },
    { field: "ingress.content_hash", sensitivity: "low" },
    { field: "ingress.trust_label", sensitivity: "low" },
    // raw ingress content is Sensitive-tier, gated at install:
    { field: "ingress.content", sensitivity: "sensitive" },
  ],
  policy_decision: [
    { field: "tool_name", sensitivity: "low" },
    { field: "tool_fingerprint", sensitivity: "low" },
    { field: "arguments_hash", sensitivity: "low" },
    { field: "origin.channel", sensitivity: "low" },
    { field: "origin.trust_label", sensitivity: "low" },
    // per-field tool arguments are Sensitive; declared as JSON-pointer selectors:
    { field: "arguments_fields", sensitivity: "sensitive" },
  ],
  substrate_identity: [
    { field: "attestation.subject_id", sensitivity: "low" },
    { field: "attestation.claim_type", sensitivity: "low" },
    { field: "origin.trust_label", sensitivity: "low" },
  ],
};

function tableFor(hook: HookClass): readonly FieldSpec[] {
  const t = FIELD_ALLOWLIST[hook];
  if (!t) reject("invalid_field_value", `unknown hook class "${hook}"`);
  return t;
}

/** Look up a field's sensitivity, or reject if it is not in the closed allowlist. */
export function sensitivityOf(hook: HookClass, field: string): Sensitivity {
  const spec = tableFor(hook).find((f) => f.field === field);
  if (!spec) {
    reject("unknown_nested_key", `field "${field}" is not in the ${hook} allowlist (Never-tier or unknown)`);
  }
  return spec.sensitivity;
}

/**
 * Validate a plugin's declared field set for a hook. Every requested field must be in the
 * closed allowlist; an unknown/Never-tier field rejects. Returns the set of Sensitive
 * fields requested (which S4 will route through a Tier-1 per-field grant).
 */
export function validateDeclaredFields(hook: HookClass, fields: readonly string[]): {
  low: string[];
  sensitive: string[];
} {
  const low: string[] = [];
  const sensitive: string[] = [];
  const seen = new Set<string>();
  for (const f of fields) {
    if (seen.has(f)) {
      reject("invalid_field_value", `field "${f}" declared more than once`);
    }
    seen.add(f);
    const s = sensitivityOf(hook, f);
    if (s === "sensitive") sensitive.push(f);
    else low.push(f);
  }
  return { low, sensitive };
}

/**
 * Validate a JSON-pointer argument selector requested under the Sensitive
 * `arguments_fields` grant (policy_decision only). Each pointer must be a well-formed
 * RFC-6901 relative pointer; the per-tool allowlist of pointers is supplied by the host
 * at install (S4). S1 fixes the well-formedness + the closed-set rule.
 */
export function validateArgumentSelectors(
  pointers: readonly string[],
  hostAllowed: readonly string[],
): void {
  const allowed = new Set(hostAllowed);
  for (const ptr of pointers) {
    if (typeof ptr !== "string" || !ptr.startsWith("/")) {
      reject("undeclared_field_selector", `argument selector "${ptr}" must be a JSON pointer ("/..")`);
    }
    // RFC-6901: only ~0 and ~1 escapes are valid
    if (/~(?![01])/.test(ptr)) {
      reject("undeclared_field_selector", `argument selector "${ptr}" has an invalid ~ escape`);
    }
    if (!allowed.has(ptr)) {
      reject(
        "undeclared_field_selector",
        `argument selector "${ptr}" is not in the host-allowlisted Sensitive selector set`,
      );
    }
  }
}
