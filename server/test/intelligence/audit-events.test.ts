import { describe, expect, it } from "vitest";

import { OPERATOR_CHAT_OPS } from "../../src/chat/operator-chat-audit-events.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";

describe("audit operation name constants", () => {
  it("maps intelligence operation keys to stable audit operation names", () => {
    expect(INTEL_OPS).toEqual({
      SUBSTRATE_CHOSEN: "intelligence_substrate_chosen",
      SUBSTRATE_INVOKED: "intelligence_substrate_invoked",
      SUBSTRATE_FAILURE: "intelligence_substrate_failure",
      PII_REDACTION_EVENT: "intelligence_pii_redaction_event",
      CONFIG_LOADED: "intelligence_config_loaded",
      CONFIG_RESET: "intelligence_config_reset",
      CONFIG_QUARANTINED: "intelligence_config_quarantined",
      MODEL_PULL: "intelligence_model_pull",
      MODEL_PROVISION_REFUSED: "intelligence_model_provision_refused",
      LOAD_INTEGRITY: "intelligence_load_integrity",
      BULK_SUBSTRATE_CHOSEN: "intelligence_bulk_substrate_chosen",
      TIER2_BINDING_PINNED: "query_anonymity_tier2_binding_pinned",
    });
  });

  it("maps operator chat operation keys to stable audit operation names", () => {
    expect(OPERATOR_CHAT_OPS).toEqual({
      CONCIERGE_CHAT: "operator_concierge_chat",
      AGENT_INSPECT_PANEL_OPENED: "agent_inspect_panel_opened",
      CONCIERGE_HISTORY_READ: "operator_concierge_history_read",
      CONCIERGE_THREAD_DELETED: "operator_concierge_thread_deleted",
      CONCIERGE_MEMORY_READ_FAILED: "operator_concierge_memory_read_failed",
      CONCIERGE_CONTEXT_FETCHER_FAILED:
        "operator_concierge_context_fetcher_failed",
      CONCIERGE_PROACTIVE_SUGGESTION_OFFERED:
        "operator_concierge_proactive_suggestion_offered",
    });
  });

  it("keeps operation names unique across both audit surfaces", () => {
    const operationNames = [
      ...Object.values(INTEL_OPS),
      ...Object.values(OPERATOR_CHAT_OPS),
    ];

    expect(new Set(operationNames).size).toBe(operationNames.length);
  });
});
