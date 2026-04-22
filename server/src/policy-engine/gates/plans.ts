/**
 * Plans-slot gate entry. Walkthrough Key 10 LOCKED slot. Gates introspection
 * and export of an agent's in-flight tool-call sequences. "Plan inspect
 * read-only" and "plan export" are common shapes; default-deny until
 * operator opens a channel.
 */

import { evaluateSlotGate } from "./evaluator.js";
import type { SlotGateExtendedContext } from "./evaluator.js";
import type { GateRequest, GateResult } from "../types.js";

export function evaluatePlansGate(
  ctx: SlotGateExtendedContext,
  req: GateRequest
): GateResult {
  return evaluateSlotGate("plans", ctx, req);
}
