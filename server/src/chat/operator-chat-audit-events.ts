/**
 * Sanctuary MCP Server — Operator Chat Audit Operation Names
 *
 * Stable string operation names for AuditLog.append() emissions in the
 * operator-chat surface (concierge in v1.2; direct-agent removed in the
 * v1.2 reshape). Single source of truth so the chat service, hub routes,
 * and audit-query callers agree.
 *
 * Layer is always L2 — operator chat is an operational-isolation surface
 * (operator types into a chat input, the gate evaluates whether the
 * resulting fortress activity is permitted, and the audit log records
 * the decision). Mirrors the BROKER_OPS / INTEL_OPS pattern.
 */
export const OPERATOR_CHAT_OPS = {
  CONCIERGE_CHAT: "operator_concierge_chat",
  /**
   * Click-to-inspect panel opened on an agent row. Repurposed from the
   * direct-agent session-open audit event in the v1.2 reshape; the click
   * affordance now opens an inspect/approve panel (recent activity +
   * pending approvals + policy summary) instead of a chat session.
   */
  AGENT_INSPECT_PANEL_OPENED: "agent_inspect_panel_opened",
} as const;

export type OperatorChatOp =
  (typeof OPERATOR_CHAT_OPS)[keyof typeof OPERATOR_CHAT_OPS];
