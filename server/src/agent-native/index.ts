/**
 * Sanctuary Agent-Native surface - Public surface.
 *
 * The agent-facing MCP tool facade. cooperative-surface.ts builds the
 * sanctuary_* tool definitions (remember / recall / hide / forget / help /
 * who_am_i / events / audit_search / compound_execute) that an agent calls
 * instead of the raw state primitives. safety-base.ts is the shared crypto
 * and approval-proof base (canonical JSON, sha256, approval envelopes,
 * session-identity resolution, opaque namespace handles) re-used across
 * distress, cognitive, principal-policy, router, and sdw.
 *
 * Re-exported here for external consumers; the facade calls primitive
 * tools through their public handlers only and holds no module state of
 * its own at import time.
 */

export * from "./safety-base.js";
export * from "./cooperative-surface.js";
