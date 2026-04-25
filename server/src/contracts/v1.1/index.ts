/**
 * Sanctuary v1.1 — Local Sovereignty Harness Contracts
 *
 * Barrel file for the v1.1 cross-workstream contract surface. Other modules
 * import from this index so the contract location is stable even if internal
 * file layout shifts during the v1.1 build wave.
 *
 * Workstream consumers:
 * - Privacy core (Prompt 3): privacy-events, constants
 * - Remote-bound enforcement (Prompt 4): privacy-events
 * - Operator hub API (Prompt 5): hub-events, local-agent-records, constants
 * - Internal coordination (Prompt 6): handoff-records, constants
 * - Exit bundle (Prompt 7): exit-bundle-manifest, constants
 * - Dashboard UI (Prompt 8): all of the above
 * - Acceptance drills (Prompt 10): all of the above
 *
 * Non-dependency invariant:
 * This module MUST NOT import from concordia or verascore. Composition stays
 * default-off and external.
 *
 * Scope invariant:
 * v1.1 ships local-only, single-operator scope. Cross-fortress, fleet,
 * public-federation, mobile-native runtime, payments, and compliance-pack
 * shapes are out of scope and live in v1.2 / v1.3 / v1.4+ contract surfaces.
 *
 * Internal-only export surface:
 * These contracts are internal types for the v1.1 build wave. They are NOT
 * part of the published `@sanctuary-framework/mcp-server` package's public
 * export surface and carry no external SemVer stability guarantees. The
 * outward-facing public-API surface is the Agent Contract on the W3C AIVS
 * track, plus a future `@sanctuary-framework/agent-bundle` (v1.4+). External
 * consumers MUST NOT import from this path.
 */

export * from "./constants.js";
export * from "./privacy-events.js";
export * from "./hub-events.js";
export * from "./local-agent-records.js";
export * from "./handoff-records.js";
export * from "./exit-bundle-manifest.js";
