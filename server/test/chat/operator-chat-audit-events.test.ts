import { describe, expect, it } from "vitest";

import {
  OPERATOR_CHAT_OPS,
  type OperatorChatOp,
} from "../../src/chat/operator-chat-audit-events.js";

describe("operator chat audit operation names", () => {
  it("maps each exported key to the stable audit operation string", () => {
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

  it("keeps operation names unique for audit query grouping", () => {
    const operationNames: OperatorChatOp[] = Object.values(OPERATOR_CHAT_OPS);

    expect(new Set(operationNames).size).toBe(operationNames.length);
  });
});
