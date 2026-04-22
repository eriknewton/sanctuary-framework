/**
 * Sanctuary Chat v1.0 — Public Surface
 *
 * Single-fortress + cross-fortress MLS-encrypted chat with four-state
 * presence, coordination-peers enforcement, encrypted log persistence,
 * and pgvector semantic indexing.
 *
 * WP-MVP-7: libp2p + OpenMLS chat surface per Q2 of the architecture walkthrough.
 */

export * from "./constants.js";
export * from "./errors.js";
export * from "./types.js";
export * from "./ephemeral-event.js";
export * from "./presence.js";
export * from "./mls-group.js";
export * from "./coordination-gate.js";
export * from "./chat-log.js";
export * from "./pgvector-index.js";
export * from "./retention-bridge.js";
export * from "./chat-service.js";
