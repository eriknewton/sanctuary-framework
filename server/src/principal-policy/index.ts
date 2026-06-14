/**
 * Sanctuary Principal Policy - Public surface.
 *
 * The Principal Policy is the human-controlled, agent-immutable approval
 * gate. Operations are classified into tiers (Tier 1 always-approve,
 * Tier 2 anomaly, Tier 3 always-allow); the gate blocks Tier 1/2 work
 * until an operator decision arrives through an approval channel.
 *
 * This barrel re-exports the consumer-facing API only:
 *   - types: PrincipalPolicy / ApprovalRequest / GateResult / SessionProfile.
 *   - loader: policy parse/load, DEFAULT_POLICY, MalformedPrincipalPolicyError.
 *   - baseline: BaselineTracker (Tier 2 behavioral baseline).
 *   - gate: ApprovalGate, the runtime classify-and-block entry point.
 *   - approval channels: stderr / callback / auto / webhook / dashboard /
 *     aggregator-backed, plus the ApprovalChannel contract.
 *   - approval aggregator + payload store: cross-harness redirect inbox.
 *   - tools: createPrincipalPolicyTools (MCP tool surface).
 *   - unified inbox: bridge, stores, prefs, retention, scheduler, producers.
 *
 * Internal-only modules are intentionally NOT re-exported: the HTML
 * renderers (dashboard-html, posture-home-html), the route handlers
 * (approval-aggregator-routes, posture-routes, unified-inbox-routes), the
 * posture / feature-health computation surfaces, the push-trigger registry,
 * deny-vocabulary, and producer-reverify are wired internally by the
 * dashboard and route layer and are not part of the front-door API. Deep
 * imports of those files remain valid; this barrel is the convention for
 * external consumers and does not change any existing import.
 */

export * from "./types.js";
export * from "./loader.js";
export * from "./baseline.js";
export * from "./gate.js";
export * from "./approval-channel.js";
export * from "./webhook.js";
export * from "./dashboard.js";
export * from "./approval-aggregator.js";
export * from "./aggregator-store.js";
export * from "./channels/aggregator-backed-channel.js";
export * from "./tools.js";
export * from "./unified-inbox-bridge.js";
export * from "./unified-inbox-store.js";
export * from "./unified-inbox-prefs-store.js";
export * from "./unified-inbox-retention-policy.js";
export * from "./unified-inbox-scheduler.js";
export * from "./unified-inbox-producers.js";
