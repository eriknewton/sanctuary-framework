/**
 * Castle Wall Phase 1 wire constants.
 *
 * Every value here is a wire-protocol or schema constant that crosses the
 * Sanctuary main / filter daemon boundary. Bumping a value means a wire
 * incompatibility; PR 6 adds the cross-language vector tests that gate any
 * change.
 */

/** Schema version for v1 allowlist rules + manifest + signed envelopes. */
export const CASTLE_WALL_SCHEMA_VERSION_V1 = 1 as const;

/** Audit-log layer for every Castle Wall event. Layer 1 per the Castle Architecture ADR. */
export const CASTLE_WALL_AUDIT_LAYER = "l1" as const;

/** Ed25519 signature scheme tag used in manifest envelopes (matches federation v0.1). */
export const CASTLE_WALL_SIGNATURE_SCHEME_V1 = "ed25519-v1" as const;

/** IPC framing header per scope-lock section 5 (LSP-style). */
export const CASTLE_WALL_IPC_CONTENT_LENGTH_HEADER = "Content-Length" as const;

/** Prompt coalescing default: at most this many prompts per window per agent. */
export const CASTLE_WALL_DEFAULT_PROMPT_FLOOD_CAP = 5 as const;

/** Prompt coalescing window in seconds for the default cap. */
export const CASTLE_WALL_DEFAULT_PROMPT_FLOOD_WINDOW_SECONDS = 30 as const;

/** Default operator-decision timeout for an open prompt, in seconds. */
export const CASTLE_WALL_DEFAULT_PROMPT_TIMEOUT_SECONDS = 30 as const;

/** Default duration for the emergency `--no-wall` recovery mode, in seconds (1 hour). */
export const CASTLE_WALL_DEFAULT_NO_WALL_DURATION_SECONDS = 3600 as const;

/** Default WAL retention TTL on the filter-daemon side, in seconds (24 hours). */
export const CASTLE_WALL_DEFAULT_WAL_TTL_SECONDS = 86400 as const;

/** Default WAL size cap on the filter-daemon side, in bytes (100 MB). */
export const CASTLE_WALL_DEFAULT_WAL_SIZE_CAP_BYTES = 104857600 as const;

/** Fixed length of an IPC request_id nonce in bytes (16 bytes hex-encoded = 32 chars). */
export const CASTLE_WALL_REQUEST_ID_NONCE_BYTES = 16 as const;

/** JSON-RPC method namespace for IPC messages. Subsequent PRs add concrete methods. */
export const CASTLE_WALL_IPC_NAMESPACE = "castle-wall" as const;
