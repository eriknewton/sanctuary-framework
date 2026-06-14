/**
 * Sanctuary Anomaly Detection - Public surface.
 *
 * Sentinels statistical-drift complement (WP-V1.3-2, Castle Layer 2).
 * Where the rule-based Sentinel pack surfaces known-shape anomalies,
 * this pipeline learns each agent's normal pattern locally and
 * surfaces statistical drift. Findings reuse the SentinelFinding
 * shape so they flow through the existing finding-store + audit +
 * dashboard pipeline without parallel infrastructure.
 *
 * Re-exports the library surface other modules consume: the
 * foundation types + detector base class, the root-cause hint
 * helpers, the encrypted classifier-state store, the operator
 * detector catalog, the subscription-persistence helpers, and the
 * per-fortress dispatcher. The HTTP route handlers, feature
 * extractors, concrete classifiers, and concrete detectors are
 * internal wiring reached through the catalog factory rather than
 * direct imports, so they stay out of this front door.
 *
 * Classifier state never leaves the fortress; importing through this
 * barrel adds no outbound surface.
 */

export * from "./types.js";
export * from "./root-cause-hints.js";
export * from "./classifier-state-store.js";
export * from "./anomaly-catalog.js";
export * from "./anomaly-subscription-store.js";
export * from "./anomaly-pipeline.js";
