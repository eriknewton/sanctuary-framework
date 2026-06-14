/**
 * Sanctuary Concordia Bridge - Public surface.
 *
 * Three MCP tools (bridge_commit / bridge_verify / bridge_attest) that bind a
 * Concordia negotiation outcome to Sanctuary's selective-disclosure and
 * verifiable-reputation layers. Composes the existing commitment / ZK and
 * reputation primitives; introduces no new cryptography of its own.
 *
 * Trust-boundary invariant: the bridge accepts any ConcordiaOutcome-shaped
 * object and never assumes it came from a legitimate Concordia session.
 * Verification is purely cryptographic (SHA-256 commitment, Ed25519 signature,
 * terms-hash and session-id match). Non-dependency principle holds: this module
 * functions with or without Concordia running.
 */

export * from "./types.js";
export * from "./bridge.js";
export * from "./tools.js";
