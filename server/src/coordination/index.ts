/**
 * Sanctuary v1.1 Coordination — Public surface.
 *
 * Local-only agent-to-agent handoff orchestration inside a single operator
 * fortress. Cross-operator coordination, public discovery, fleet workflows,
 * and external relays are explicit non-goals (see v1.3 / v1.4+).
 *
 * Re-exports keep the consumer-side import path stable across internal
 * refactors:
 *
 *     import {
 *       LocalCoordinator,
 *       HandoffStore,
 *       transferContextSlot,
 *     } from "@sanctuary/server/src/coordination/index.js";
 */

export * from "./errors.js";
export * from "./signing.js";
export * from "./handoff-store.js";
export * from "./coordinator.js";
export * from "./context-transfer.js";
