/**
 * Generic operator advice for binding Castle Wall evidence to an agent uid.
 * This must stay agent-agnostic: Hermes-specific provisioning belongs only in
 * Hermes-scoped protect/recovery flows.
 */
export const GENERIC_UID_CONFINEMENT_REMEDY =
  "Ensure this wrapped agent is uid-confined, then bind Castle Wall to that uid with " +
  "'sanctuary castle-wall configure-origin uid --agent-uid=<uid> --ceiling=500'; " +
  "reload or re-arm Castle Wall so per-agent enforcement evidence can bind to this wrapped agent.";

export const EGRESS_GATE_STAND_DOWN_EFFECT = "stops and disables the agent harness";

export const EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND =
  "sudo sanctuary protect --repair-egress-gate --stand-down-agent";

export const EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND =
  "sudo sanctuary protect --unprotect-egress-gate --stand-down-agent";

export const EGRESS_GATE_REPAIR_WITH_STAND_DOWN_ADVICE =
  `${EGRESS_GATE_REPAIR_WITH_STAND_DOWN_COMMAND} (${EGRESS_GATE_STAND_DOWN_EFFECT})`;

export const EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_ADVICE =
  `${EGRESS_GATE_UNPROTECT_WITH_STAND_DOWN_COMMAND} (${EGRESS_GATE_STAND_DOWN_EFFECT})`;
