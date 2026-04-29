/**
 * Sanctuary MCP Server — Operator Chat Audit Operation Names
 *
 * Stable string operation names for AuditLog.append() emissions in the
 * operator-chat surface (concierge + direct-agent). Single source of
 * truth so the chat service, hub routes, and audit-query callers agree.
 *
 * Layer is always L2 — operator chat is an operational-isolation surface
 * (operator types into a chat input, the gate evaluates whether the
 * resulting fortress activity is permitted, and the audit log records
 * the decision). Mirrors the BROKER_OPS / INTEL_OPS pattern.
 */
export const OPERATOR_CHAT_OPS = {
  CONCIERGE_CHAT: "operator_concierge_chat",
  DIRECT_AGENT_CHAT: "operator_direct_agent_chat",
  DIRECT_AGENT_REPLY: "agent_direct_agent_reply",
  DIRECT_AGENT_SESSION_OPEN: "direct_agent_session_open",
  DIRECT_AGENT_SESSION_CLOSE: "direct_agent_session_close",
} as const;

export type OperatorChatOp =
  (typeof OPERATOR_CHAT_OPS)[keyof typeof OPERATOR_CHAT_OPS];
