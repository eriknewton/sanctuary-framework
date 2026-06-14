/**
 * Sanctuary Recognition Layer - Public surface.
 *
 * WP-V1.x-RECOGNITION-LAYER. did:web operator identity: issue, publish,
 * resolve, and rotate the keys behind an operator's DID Document, plus the
 * Path C hosted alternative for operators without their own domain.
 *
 * The external route GET /<handle>/.well-known/did.json and the
 * HKDF-derived hosted store are FROZEN; this barrel is additive and only
 * re-exports the issue / resolve / registry / route surface that other
 * modules already consume. It changes no route and binds no new behavior.
 *
 * Castle-walking: read-only resolution serves only operator-signed content;
 * operator signing keys never leave the castle.
 */

export * from "./did-web.js";
export * from "./did-web-hosted-registry.js";
export * from "./did-web-hosted-route.js";
