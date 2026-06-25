/**
 * Sanctuary Query-Layer Anonymity - Public surface.
 *
 * WP-V1.x outbound de-identification. Closes Principle 4 (opacity at
 * the query layer) by reducing what crosses the operator-substrate
 * boundary. Two enforced tiers plus a smart-mode extension:
 *   - Tier A header strip (Rho-1): removes fingerprintable HTTP
 *     headers from every outbound substrate-selector call. Default-on,
 *     structurally unconditional.
 *   - Tier B PII rewrite (Rho-2): operator-toggleable, consent-gated
 *     rewrite of personal data in the query body before invocation.
 *   - Smart mode (Rho-3): intent-aware rewrite plus an encrypted
 *     at-rest reverse map for render-time restoration.
 *   - Tier 3a transport (Slice 1): two-hop CONNECT/MASQUE egress-proxy
 *     encapsulation composed BENEATH the wrapped fetch, removing the
 *     operator's IP and path linkage (Property 1). Opt-in, disarmed by
 *     default, fail-closed. Does NOT touch the API key (credential
 *     decoupling is a later slice) and does NOT claim anonymity-set /
 *     unlinkability.
 *
 * Tiers A/B/Smart add NO new outbound surface; they are reductions on the
 * existing substrate-selector channel. Tier 3a adds a *transport* but it
 * is composed inside the same wrapped fetch, so the substrate selector's
 * wrapped fetch remains the single outbound channel the Castle Wall egress
 * filter binds (the tunnel never opens a socket outside it — AC-1). The
 * HTTP route handlers (pii-rewrite-routes, query-anonymity-routes) are
 * deliberately NOT part of this front door - they are wired by the
 * dashboard dispatcher, not library API.
 */

export * from "./header-strip.js";
export * from "./pii-rewrite.js";
export * from "./intent-classifier.js";
export * from "./pii-config-store.js";
export * from "./reverse-mapping-store.js";
export * from "./smart-rewriter.js";
export * from "./performance-budget.js";
export * from "./tier3-transport.js";
