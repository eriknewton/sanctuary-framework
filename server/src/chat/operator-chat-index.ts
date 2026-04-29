/**
 * Sanctuary MCP Server — Operator Chat Public Barrel
 *
 * Stable import surface for the operator chat service + types. Distinct
 * from `chat/index.ts` (which exports the agent-to-agent mesh chat
 * surface). Hub-service wiring + dashboard wiring import from this
 * barrel; tests import directly from the source files.
 */

export {
  OperatorChatService,
  operatorChatRoleLabel,
  type ConciergeContextProviders,
  type ConciergePiiFilter,
  type OperatorChatServiceDeps,
} from "./operator-chat-service.js";

export {
  OperatorChatStore,
  OPERATOR_CHAT_NAMESPACE,
  chatStorageKey,
} from "./operator-chat-store.js";

export {
  OPERATOR_CHAT_OPS,
  type OperatorChatOp,
} from "./operator-chat-audit-events.js";

export {
  CONCIERGE_THREAD_KEY,
  DEFAULT_SESSION_TIMEOUT_MS,
  OPERATOR_CHAT_MAX_THREAD_LENGTH,
  type ConciergeResponse,
  type DirectAgentSendResponse,
  type OperatorChatMessage,
  type OperatorChatRole,
  type OperatorChatSession,
  type OperatorChatSessionState,
  type OperatorChatSurface,
  type OperatorChatThread,
} from "./operator-chat-types.js";
