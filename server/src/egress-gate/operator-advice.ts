/**
 * Generic operator advice for binding Castle Wall evidence to an agent uid.
 * This must stay agent-agnostic: Hermes-specific provisioning belongs only in
 * Hermes-scoped protect/recovery flows.
 */
export const GENERIC_UID_CONFINEMENT_REMEDY =
  "Ensure this wrapped agent is uid-confined, then bind Castle Wall to that uid with " +
  "'sanctuary castle-wall configure-origin uid --agent-uid=<uid> --ceiling=500'; " +
  "reload or re-arm Castle Wall so per-agent enforcement evidence can bind to this wrapped agent.";
