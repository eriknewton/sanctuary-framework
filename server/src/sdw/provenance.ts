import type { SdwRecord } from "./records.js";
import { SdwValidationError } from "./errors.js";
import type { Taint } from "./write-gate.js";

const TAINTED_BRAND: unique symbol = Symbol("sanctuary.sdw.tainted");
const taintedValues = new WeakSet<object>();

export type PersistableTaint = "user_content" | "agent_derived_clean" | "system_generated";

export interface Tainted<V> {
  readonly [TAINTED_BRAND]: true;
  readonly value: V;
  readonly taint: Taint;
}

const TAINT_RANK: ReadonlyMap<Taint, number> = Object.freeze(
  new Map<Taint, number>([
    ["user_content", 0],
    ["agent_derived_clean", 1],
    ["system_generated", 2],
    ["unknown", 3],
    ["policy", 4],
    ["secret", 5],
    ["identity_key", 6],
  ]),
);

function mintTainted<V>(value: V, taint: Taint): Tainted<V> {
  const carrier = Object.create(null) as Tainted<V> & {
    toString: () => never;
    toJSON: () => never;
    [Symbol.toPrimitive]: () => never;
  };
  Object.defineProperties(carrier, {
    [TAINTED_BRAND]: { value: true },
    value: { value, enumerable: true },
    taint: { value: taint, enumerable: true },
    toString: { value: rejectCoercion },
    toJSON: { value: rejectCoercion },
    [Symbol.toPrimitive]: { value: rejectCoercion },
  });
  Object.freeze(carrier);
  taintedValues.add(carrier);
  return carrier;
}

function rejectCoercion(): never {
  throw new SdwValidationError(
    "tainted_value_coercion",
    "SDW tainted values must be joined by provenance before persistence",
  );
}

function joinTaint(a: Taint, b: Taint): Taint {
  return rankOf(a) >= rankOf(b) ? a : b;
}

function rankOf(taint: Taint): number {
  const rank = TAINT_RANK.get(taint);
  if (rank === undefined) {
    throw new SdwValidationError("unknown_taint", "Unknown SDW taint");
  }
  return rank;
}

export function assertTainted<V>(value: Tainted<V>): asserts value is Tainted<V> {
  if (value === null || typeof value !== "object" || !taintedValues.has(value)) {
    throw new SdwValidationError("untrusted_tainted_value", "Untrusted SDW taint carrier");
  }
}

export function taintFromPolicy<V>(value: V): Tainted<V> {
  return mintTainted(value, "policy");
}

export function taintFromIdentityKey<V>(value: V): Tainted<V> {
  return mintTainted(value, "identity_key");
}

export function taintFromSecret<V>(value: V): Tainted<V> {
  return mintTainted(value, "secret");
}

export function taintClean<V>(value: V, taint: PersistableTaint): Tainted<V> {
  return mintTainted(value, taint);
}

export function taintRecordFromFields<T extends SdwRecord>(
  value: T,
  fields: readonly Tainted<unknown>[],
): Tainted<T> {
  if (fields.length === 0) return mintTainted(value, "unknown");
  let effectiveTaint: Taint | undefined;
  for (const field of fields) {
    assertTainted(field);
    effectiveTaint = effectiveTaint === undefined ? field.taint : joinTaint(effectiveTaint, field.taint);
  }
  return mintTainted(value, effectiveTaint ?? "unknown");
}

export const sdwProvenanceMinters = Object.freeze({
  taintFromPolicy,
  taintFromIdentityKey,
  taintFromSecret,
  taintClean,
  taintRecordFromFields,
});

Object.freeze(taintFromPolicy);
Object.freeze(taintFromIdentityKey);
Object.freeze(taintFromSecret);
Object.freeze(taintClean);
Object.freeze(taintRecordFromFields);
