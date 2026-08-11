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
// Explicit (not `export *`) so the test-only clock seam `transformSHRForGatewayAt`
// is NOT re-exported onto the public SHR surface: it lets its caller choose the
// verification clock, which on a trust-minting path is a footgun (a backdated
// clock would accept an expired SHR). Tests import it directly from the file.
// Public consumers get only the real-clock entry points. (SHR-GW-01.)
export {
  transformSHRForGateway,
  transformSHRGeneric,
} from "./gateway-adapter.js";
export type {
  PingAuthorizationContext,
  GatewayDegradation,
  AuthorizationConstraint,
  GenericAuthorizationContext,
} from "./gateway-adapter.js";
export * from "./decommission-types.js";
export * from "./decommission-generator.js";
export * from "./decommission-verifier.js";
