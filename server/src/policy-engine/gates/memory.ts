/**
 * Memory-slot gate entry. One of four canonical slot gates (Walkthrough
 * Key 10 LOCKED). Agent A reads / writes / subscribes / shares Agent B's
 * cocoon memory only if this gate returns allow.
 */

import { evaluateSlotGate } from "./evaluator.js";
import type { SlotGateExtendedContext } from "./evaluator.js";
import type { GateRequest, GateResult } from "../types.js";

export function evaluateMemoryGate(
  ctx: SlotGateExtendedContext,
  req: GateRequest
): GateResult {
  return evaluateSlotGate("memory", ctx, req);
}
