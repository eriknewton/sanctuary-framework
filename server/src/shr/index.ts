/**
 * Sanctuary Sovereignty Health Report (SHR) - Public surface.
 *
 * SHR version 1.0, frozen schema. A signed, versioned, machine-readable
 * advertisement of an instance's sovereignty posture: an agent presents its
 * SHR to a counterparty, which verifies it independently (Ed25519 signature,
 * temporal window, identity binding) without trusting the presenter. Surfaced
 * as the shr_generate / shr_verify / shr_gateway_export MCP tools.
 *
 * Re-exports the SHR body and signed-envelope types, the generator and
 * verifier, the MCP tool factory, the Ping Identity / generic gateway
 * adapter, and the decommissioning-certificate variant (a zero-credentials
 * proof signed as an agent's final act). All canonical serialization flows
 * through canonicalizeForSigning here; downstream layers treat the signed
 * blob as opaque bytes.
 */

export * from "./types.js";
export * from "./generator.js";
export * from "./verifier.js";
export * from "./tools.js";
export * from "./gateway-adapter.js";
export * from "./decommission-types.js";
export * from "./decommission-generator.js";
export * from "./decommission-verifier.js";
