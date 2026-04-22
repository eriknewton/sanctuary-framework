/**
 * Gate dispatcher. Four slot entries plus a unified `evaluateGate(slot, ...)`
 * helper for callers that have the slot in a variable.
 *
 * This module's import graph MUST NOT include any network, LLM, or mesh-
 * transport module. Gates run at request time; they are not compile-time or
 * authoring-time surfaces. See test/policy-engine/no-network-at-gate.test.ts
 * for the structural assertion.
 */

import type { PolicySlot } from "../constants.js";
import type { GateRequest, GateResult } from "../types.js";
import { evaluateMemoryGate } from "./memory.js";
import { evaluateCredentialsGate } from "./credentials.js";
import { evaluatePlansGate } from "./plans.js";
import { evaluateOutputsGate } from "./outputs.js";
import type { SlotGateExtendedContext } from "./evaluator.js";

export { evaluateMemoryGate } from "./memory.js";
export { evaluateCredentialsGate } from "./credentials.js";
export { evaluatePlansGate } from "./plans.js";
export { evaluateOutputsGate } from "./outputs.js";
export type { SlotGateExtendedContext } from "./evaluator.js";

/** Route a gate call by slot. Throws on an unknown slot (schema-impossible at v0.1). */
export function evaluateGate(
  slot: PolicySlot,
  ctx: SlotGateExtendedContext,
  req: GateRequest
): GateResult {
  switch (slot) {
    case "memory":
      return evaluateMemoryGate(ctx, req);
    case "credentials":
      return evaluateCredentialsGate(ctx, req);
    case "plans":
      return evaluatePlansGate(ctx, req);
    case "outputs":
      return evaluateOutputsGate(ctx, req);
  }
}
