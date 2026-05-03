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
  /**
   * Operator picked a substrate and applied it to every surface at once
   * via the "Apply to all surfaces" affordance (Finding SS,
   * v1.2.0-rc.1). One audit entry per bulk apply, even though the
   * underlying SubstrateConfig.perSurface map is mutated for all six
   * surfaces in a single persist.
   */
  BULK_SUBSTRATE_CHOSEN: "intelligence_bulk_substrate_chosen",
} as const;

export type IntelOp = (typeof INTEL_OPS)[keyof typeof INTEL_OPS];
