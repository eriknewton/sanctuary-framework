/**
 * Sanctuary Operator Console v1.0 -- Barrel exports.
 *
 * WP-MVP-2: Key 4 Console + Q5 Option A (single console artifact).
 * Six primary views + persistent attestation header. Browser-primary
 * HTML reference surface.
 */

export * from "./constants.js";
export * from "./types.js";
export * from "./errors.js";
export { enforceAuth, isLoopback, authMiddleware, type AuthConfig } from "./auth-middleware.js";
export {
  aggregateHeader,
  aggregateFortressView,
  aggregateAgentRosterView,
  aggregatePolicyEditorView,
  aggregateChatView,
  aggregateRecoveryView,
  aggregateAuditLogView,
  type ViewAggregatorDeps,
} from "./view-aggregator.js";
export { SignedEventStream } from "./signed-event-stream.js";
export { serveStaticFile, resolvePublicDir, auditNoExternalFetches } from "./serve-static.js";
export { handleConsoleRoute, type ConsoleRouterDeps } from "./api-router.js";
export { ConsoleService, type ConsoleServiceDeps } from "./console-service.js";
