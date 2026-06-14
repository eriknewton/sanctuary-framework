/**
 * Sanctuary error types - Public surface.
 *
 * Typed Error subclasses for load-time failures: ConfigLoadError for
 * Sanctuary config loads, ProfileLoadError for sovereignty-profile loads.
 * Each carries a classification, a recovery hint, and an optional
 * quarantined-copy path so callers can branch on failure mode without
 * string-matching the message.
 *
 * Both files are pure declarations (no top-level side effects, no binary
 * entrypoint); they are safe to re-export wholesale.
 */

export * from "./config-error.js";
export * from "./profile-error.js";
