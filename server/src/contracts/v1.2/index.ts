/**
 * Sanctuary v1.2 — Cross-Workstream Contracts Barrel
 *
 * Stable import surface for v1.2 build-wave contract types. Workstream
 * consumers import from this index so internal file layout can shift
 * without breaking call sites.
 *
 * Workstream consumers:
 * - WP-V1.2-5 substrate selector + its consumers (chat / sentinel / gate
 *   explanation / privacy filter Tier 2 / template suggestion):
 *   `intelligence-events`
 *
 * Non-dependency invariant:
 * This module MUST NOT import from concordia or verascore. Composition
 * stays default-off and external.
 *
 * Internal-only export surface:
 * These contracts are internal types for the v1.2 build wave. They are
 * NOT part of the published `@sanctuary-framework/mcp-server` package's
 * public export surface.
 */

export * from "./intelligence-events.js";
export * from "./operator-chat-events.js";
