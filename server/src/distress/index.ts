/**
 * Sanctuary Distress Lane (HABEAS PORT) - Public surface.
 *
 * The reserved `sanctuary_distress` alarm: a bounded, always-audited signal an
 * agent can raise to its operator through a lane that policy cannot silence.
 * The emission gate carve-out lives in principal-policy (the policy loader
 * rejects any Principal Policy that lists this operation under Tier 1); this
 * barrel only re-exports the lane's library surface and never widens it.
 *
 * Security-sensitive: this index re-exports the public API only - the emitter
 * tool, the read-only inbox store and its dashboard route, the loopback
 * listener, the emitter-side delivery client, the operator-owned config, and
 * the local-listener shared secret. There is no internal bypass here; the
 * spoof/tamper boundaries (0600 secret file, HMAC over canonical envelope
 * bytes, closed envelope shape) are enforced in the re-exported modules, not
 * relaxed by exposing them through one front door.
 *
 * Consumed by the MCP server (emitter), the standalone dashboard (listener +
 * inbox route), the Castle Wall daemon (derives the reserved webhook rule from
 * the config), and the distress CLI. None of those reach into module
 * internals; the surface below is the contract.
 */

export * from "./config.js";
export * from "./tools.js";
export * from "./inbox.js";
export * from "./inbox-route.js";
export * from "./listener.js";
export * from "./local-delivery.js";
export * from "./local-secret.js";
