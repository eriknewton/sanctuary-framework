/**
 * Sanctuary Auto-Trigger (Sentinels escalation ladder) - Public surface.
 *
 * v1.3 WP-V1.3-7. Operator-configurable 3-rung action ladder for
 * sentinel, anomaly, and future honeypot findings: Rung 1 inbox-only
 * (operator-approved), Rung 2 auto-action with a cancel-window, Rung 3
 * fully-automatic with retroactive revoke. The rule-id wire format
 * (sentinel__/anomaly__/honeypot__ prefixes) and the per-rule HKDF
 * label "l2-auto-trigger-rules-v1" are frozen; do not change either
 * without a migration.
 *
 * Per-rule config persists encrypted at rest, AAD-bound to
 * (rule_id, fortress_id), and never leaves the fortress; there is no
 * outbound surface. The HTTP route handler is mounted directly by the
 * dashboard and is intentionally not part of this library surface.
 */

export * from "./types.js";
export * from "./threshold-config-store.js";
export * from "./action-dispatcher.js";
export * from "./promotion-criteria.js";
export * from "./calibration-suggester.js";
