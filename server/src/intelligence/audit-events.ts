/**
 * Sanctuary MCP Server — Intelligence Substrate Audit Operation Names
 *
 * Stable string operation names for AuditLog.append() emissions in the
 * intelligence layer. Single source of truth so the selector, substrate
 * clients, and audit-query callers agree.
 *
 * Layer is always L2 — the substrate selector controls execution behavior
 * (which provider sees what context, whether a surface is permitted to
 * invoke an LLM at all). Mirrors the BROKER_OPS pattern in audit-log.ts.
 */
export const INTEL_OPS = {
  SUBSTRATE_CHOSEN: "intelligence_substrate_chosen",
  SUBSTRATE_INVOKED: "intelligence_substrate_invoked",
  SUBSTRATE_FAILURE: "intelligence_substrate_failure",
  PII_REDACTION_EVENT: "intelligence_pii_redaction_event",
  CONFIG_LOADED: "intelligence_config_loaded",
  CONFIG_RESET: "intelligence_config_reset",
} as const;

export type IntelOp = (typeof INTEL_OPS)[keyof typeof INTEL_OPS];
