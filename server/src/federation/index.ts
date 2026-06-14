/**
 * Sanctuary Federation - Public surface.
 *
 * MCP-to-MCP peer federation: a registry of known peers (entered ONLY
 * through verified, liveness-proven sovereignty handshakes), the trust
 * evaluation surface over those peers, and the federation_* MCP tools.
 *
 * Builds atop the handshake layer's public types via the public API only;
 * the handshake establishes trust and federation uses that trust for
 * ongoing cross-instance operations. Peers degrade to self-attested when
 * their handshake expires.
 */

export * from "./types.js";
export * from "./registry.js";
export * from "./tools.js";
