/**
 * Sanctuary Handshake - Public surface.
 *
 * Two-party sovereignty handshake: a mutual verification protocol between
 * two Sanctuary instances. Each side presents its SHR and proves liveness
 * via a nonce challenge-response. The MCP tools are handshake_* and the
 * 120s server-anchored session TTL (HANDSHAKE_SESSION_TTL_MS) is the core
 * HS-2 replay invariant.
 *
 * Re-exports the four protocol steps and their wire types, the portable
 * attestation artifacts, the subscriber pre-handshake gate, the session-
 * lifecycle audit hooks, and the createHandshakeTools factory consumed by
 * the server entry point.
 *
 * tools.js is re-exported by name rather than with `export *`: it re-exports
 * HANDSHAKE_LIFECYCLE_OPS for audit-query callers, which would collide with
 * the same constant declared in audit.js under a star re-export (TS2308).
 * Exposing only its own declarations keeps the barrel free of that ambiguity
 * while audit.js remains the single star source for the lifecycle ops.
 */

export * from "./types.js";
export * from "./protocol.js";
export * from "./attestation.js";
export * from "./subscriber-gate.js";
export * from "./audit.js";
export { createHandshakeTools, type HandshakeToolsOptions } from "./tools.js";
