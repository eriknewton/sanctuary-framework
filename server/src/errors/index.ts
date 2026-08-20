/**
 * Sanctuary error types - Public surface.
 *
 * Typed Error subclasses for load-time failures: ConfigLoadError for
 * Sanctuary config loads, ProfileLoadError for sovereignty-profile loads.
 * Each carries a classification, a recovery hint, and an optional
 * quarantined-copy path so callers can branch on failure mode without
 * string-matching the message.
 *
 * Plus `describeUntrusted`, the chokepoint for rendering a STORED or
 * WIRE-SUPPLIED value into any diagnostic string. Interpolating such a field
 * directly can make building the message fail or mislead; see the invariant at
 * the top of `untrusted-diagnostic.ts`.
 *
 * All three files are pure declarations (no top-level side effects, no binary
 * entrypoint); they are safe to re-export wholesale.
 */

export * from "./config-error.js";
export * from "./profile-error.js";
export * from "./untrusted-diagnostic.js";
