/**
 * Sanctuary Health Evidence - Public surface.
 *
 * Assembles the runtime health-evidence report (layer status, Castle Wall
 * runtime snapshot, degradations) consumed by the server's status surface.
 * Pure library module - no side effects, no binary entrypoint.
 */

export * from "./evidence.js";
// The detector and the snapshot mapper are part of this module's surface, not
// internals: `server/src/index.ts` reaches them from the MCP tool handlers, and
// the activation gate reaches the snapshot mapper. Re-exported here so consumers
// import the module surface rather than a file path, per the barrel convention
// in AGENTS.md. Must stay in step with the `health` row in `server/src/README.md`.
export * from "./castle-wall-detector.js";
export * from "./castle-wall-snapshot.js";
