/**
 * Sanctuary transparency log - public surface.
 *
 * Tamper-evident enforcement checkpoints: a hash-chained,
 * signature-verified record of what Castle Wall enforced, optionally
 * anchored to a public Rekor transparency log, with an anti-rollback
 * counter-floor so a truncated chain cannot pass verification.
 *
 * Public surface, in dependency order: the checkpoint schema + hashing
 * (checkpoint), the on-disk emitter + counter-floor (emitter), signer
 * resolution against the pinned key (signer), the anchor commitment +
 * Rekor proposal primitives (anchor), the anchoring lifecycle
 * enable/disable/anchorCheckpoint (anchoring), the Rekor HTTP client
 * (rekor-client), exported-anchor evidence verification (anchor-verify),
 * the offline chain verifier + fork detection (verify), host-side
 * against-log reconciliation (against-log), and the periodic anchoring
 * scheduler (scheduler).
 *
 * The standalone `verify-transparency` binary entrypoint (offline-cli) is
 * intentionally NOT re-exported here: it is a CLI artifact, not part of the
 * library API. Its helpers stay reachable by deep import for the binary
 * build and tests.
 */

export * from "./checkpoint.js";
export * from "./emitter.js";
export * from "./signer.js";
export * from "./anchor.js";
export * from "./anchoring.js";
export * from "./rekor-client.js";
export * from "./anchor-verify.js";
export * from "./verify.js";
export * from "./against-log.js";
export * from "./scheduler.js";
