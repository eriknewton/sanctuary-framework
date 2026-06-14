/**
 * Sanctuary Sentinels framework - Public surface.
 *
 * Sanctuary v1.3 WP-V1.3-1. The Sentinels observe server-local data only
 * (Castle Layer 2): NO outbound network, NO blocking. Findings flow into
 * the operator surface and the encrypted finding store.
 *
 * This barrel re-exports the framework public surface only: the base
 * class subclassed by every watcher, the per-fortress dispatcher,
 * registry, encrypted finding store, subscription persistence, and the
 * shared types. The concrete watchers live under ./sentinels/ and are
 * their own catalog surface - import them from "./sentinels/index.js".
 *
 * Deliberately NOT re-exported: ./sentinel-routes.js. That module is the
 * /api/sentinels HTTP route handler (mounted by the principal-policy
 * dashboard), not library API, so it stays off the front door.
 */

export * from "./sentinel.js";
export * from "./sentinel-dispatcher.js";
export * from "./sentinel-registry.js";
export * from "./sentinel-finding-store.js";
export * from "./subscription-store.js";
export * from "./types.js";
