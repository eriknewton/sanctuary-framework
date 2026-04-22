/**
 * Credentials-slot gate entry. Walkthrough Key 10 LOCKED slot. Gates access
 * to broker-issued scoped tokens (Walkthrough Key 3). Share / delegate /
 * subscribe on this slot are high-blast-radius — see Key 3 for the
 * defense-in-depth layers the broker runs on top of this gate.
 */

import { evaluateSlotGate } from "./evaluator.js";
import type { SlotGateExtendedContext } from "./evaluator.js";
import type { GateRequest, GateResult } from "../types.js";

export function evaluateCredentialsGate(
  ctx: SlotGateExtendedContext,
  req: GateRequest
): GateResult {
  return evaluateSlotGate("credentials", ctx, req);
}
