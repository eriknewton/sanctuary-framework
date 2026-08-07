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
   * Reserved for the local-intelligence provisioning executor's successful
   * model download. Defining the op string here before wiring emission keeps
   * future audit producers from inventing ad hoc names.
   */
  MODEL_PULL: "intelligence_model_pull",
  /**
   * Reserved for fail-closed provisioning paths: absent runtime, operator
   * decline, below-baseline hardware, bad manifest, pull failure, or digest
   * mismatch. Emission wiring is deliberately outside this source-only slice.
   */
  MODEL_PROVISION_REFUSED: "intelligence_model_provision_refused",
  /**
   * Operator picked a substrate and applied it to every surface at once
   * via the "Apply to all surfaces" affordance (Finding SS,
   * v1.2.0-rc.1). One audit entry per bulk apply, even though the
   * underlying SubstrateConfig.perSurface map is mutated for all six
   * surfaces in a single persist.
   */
  BULK_SUBSTRATE_CHOSEN: "intelligence_bulk_substrate_chosen",
  /**
   * The invoke-time chokepoint found a persisted non-local binding for
   * the pinned `privacy-filter-tier-2` surface (pre-existing or
   * tampered config) and overrode it to `local` per the ratified
   * 2026-07-23 posture. Emitted ONCE per process on the first override
   * so a tampered binding leaves a trace without flooding the log on
   * every call. Never silently honored.
   */
  TIER2_BINDING_PINNED: "query_anonymity_tier2_binding_pinned",
} as const;

export type IntelOp = (typeof INTEL_OPS)[keyof typeof INTEL_OPS];
