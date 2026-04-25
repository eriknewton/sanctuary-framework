/**
 * Sanctuary v1.1. Operator Hub API barrel
 *
 * Stable import surface for the hub workstream. Other modules import from
 * here so internal layout shifts during v1.x do not ripple through callers.
 *
 * Local-only invariant:
 * Every export here describes activity inside a single fortress on a
 * single operator's machine. Cross-fortress, fleet, and public-federation
 * surfaces are out of scope; they ship in v1.3+.
 */

export * from "./constants.js";
export * from "./errors.js";
export * from "./types.js";
export { InMemoryLocalAgentRegistry } from "./agent-registry.js";
export {
  HubInboxStore,
  type Tier1HandlerResult,
  type Tier1ResolutionHandler,
} from "./inbox-store.js";
export { aggregateInbox } from "./inbox-aggregator.js";
export { aggregateActivity, type HubActivityCategory } from "./activity-feed.js";
export { HubService } from "./hub-service.js";
export { handleHubRoute, type HubRouterDeps } from "./api-router.js";
