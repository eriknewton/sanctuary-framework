/**
 * Operator-side enforcement-event exporter: public module surface.
 *
 * The exporter maps live Castle Wall audit events to a FROZEN, versioned public
 * event schema (`sanctuary.enforcement-event.v1`) via a CLOSED, allowlist-only
 * mapping, and delivers them through a safe-by-default local sink or, behind a
 * Tier-1 gate + a pinned destination, an outbound HTTP push to a security
 * console collector (for example Palo Alto Cortex XSIAM).
 *
 * What leaves the host and what NEVER does is documented in ./README.md.
 */

export * from "./schema.js";
export * from "./map.js";
export * from "./config.js";
export * from "./sink.js";
export * from "./audit-ops.js";
export * from "./exporter.js";
