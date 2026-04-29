/**
 * Outputs-slot gate entry. Walkthrough Key 10 LOCKED slot. Gates cross-
 * agent consumption of results (tool-call results, artifacts). Default-deny;
 * the "request-approve-act" channel template grants the minimum useful shape
 * for supervision workflows.
 */

import { evaluateSlotGate } from "./evaluator.js";
import type { SlotGateExtendedContext } from "./evaluator.js";
import type { GateRequest, GateResult } from "../types.js";

export function evaluateOutputsGate(
  ctx: SlotGateExtendedContext,
  req: GateRequest
): GateResult {
  return evaluateSlotGate("outputs", ctx, req);
}
