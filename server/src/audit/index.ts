/**
 * Sanctuary Audit - Public surface.
 *
 * Two cooperating subsystems live here:
 *
 *   1. The Sovereignty Audit Tool - a read-only posture scan that
 *      fingerprints the local environment (detector), scores it against the
 *      four-layer sovereignty model (analyzer), and surfaces the result as an
 *      MCP tool (tools). Strictly read-only and Tier 3 (auto-allow); never
 *      writes, deletes, or makes network calls.
 *
 *   2. The audit-chain crypto (chain) - canonical-JSON hashing, entry/root
 *      hashing, and checkpoint signing/verification used by the encrypted
 *      audit log, transparency anchors, anti-rollback, and workload
 *      attestation. This is the most externally-consumed surface in the
 *      module.
 *
 * Plus the SIEM export path (siem-formatter / siem-tools) that renders audit
 * entries as CEF/OCSF for Splunk, Datadog, and QRadar, and the reset-history
 * continuity helper that re-commits post-nuke reset markers into the
 * freshly-rebuilt audit log on boot.
 */

export * from "./types.js";
export * from "./chain.js";
export * from "./detector.js";
export * from "./analyzer.js";
export * from "./siem-formatter.js";
export * from "./siem-tools.js";
export * from "./tools.js";
export * from "./reset-history.js";
