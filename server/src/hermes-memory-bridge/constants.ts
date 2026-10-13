export const HERMES_MEMORY_DENIAL = "Memory request denied.";

export const HERMES_MEMORY_PROTOCOL_VERSION = "2026-10-12"; // Node-local protocol date for the relay contract this slice consumes.

// Must match MAX_PUBLIC_FRAME_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_PUBLIC_FRAME_BYTES = 65_536;
// Must match MAX_RESULT_FRAME_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_RESULT_FRAME_BYTES = 65_536;
// Must match MAX_REQUEST_ID_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_REQUEST_ID_BYTES = 128;
// Must match PROBE_NONCE_BYTES in hermes-memory-relay/SEAM.md.
export const PROBE_NONCE_BYTES = 32;
// Must match MAX_CONNECTION_ID_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_CONNECTION_ID_BYTES = 21;
// Must match PRIVATE_RESPONSE_ENVELOPE_SYNTAX_BYTES in hermes-memory-relay/SEAM.md.
export const PRIVATE_RESPONSE_ENVELOPE_SYNTAX_BYTES = 70;
// Must match PRIVATE_RESPONSE_FRAME_HEADROOM_BYTES in hermes-memory-relay/SEAM.md.
export const PRIVATE_RESPONSE_FRAME_HEADROOM_BYTES = 256;
// Must match MAX_FRAME_OVERHEAD_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_FRAME_OVERHEAD_BYTES =
  PRIVATE_RESPONSE_ENVELOPE_SYNTAX_BYTES +
  MAX_CONNECTION_ID_BYTES +
  MAX_REQUEST_ID_BYTES +
  PRIVATE_RESPONSE_FRAME_HEADROOM_BYTES;
// Must match MAX_PRIVATE_FRAME_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_PRIVATE_FRAME_BYTES = 4 * Math.ceil(MAX_PUBLIC_FRAME_BYTES / 3) +
  MAX_FRAME_OVERHEAD_BYTES;
export const LENGTH_PREFIX_BYTES = 4; // 4 bytes is the u32 big-endian payload prefix in hermes-memory-relay/SEAM.md.
// Must match MAX_PARTIAL_FRAME_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_PARTIAL_FRAME_BYTES = MAX_PUBLIC_FRAME_BYTES + LENGTH_PREFIX_BYTES;
// Must match CONTROL_QUEUE_DEPTH_PER_CONNECTION in hermes-memory-relay/SEAM.md.
export const CONTROL_QUEUE_DEPTH_PER_CONNECTION = 8;
// Must match CONTROL_RESPONSE_ALLOWANCE_PER_CONNECTION in hermes-memory-relay/SEAM.md.
export const CONTROL_RESPONSE_ALLOWANCE_PER_CONNECTION = 2;
// Must match MAX_CLIENT_OUTBOUND_FRAMES_PER_CONNECTION in hermes-memory-relay/SEAM.md.
export const MAX_CLIENT_OUTBOUND_FRAMES_PER_CONNECTION =
  1 + 1 + CONTROL_RESPONSE_ALLOWANCE_PER_CONNECTION;
// Must match MAX_JSON_NESTING_DEPTH in hermes-memory-relay/SEAM.md.
export const MAX_JSON_NESTING_DEPTH = 64;
// Must match MAX_PUBLIC_READ_CHUNK_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_PUBLIC_READ_CHUNK_BYTES = 65_536;
// Must match PROBE_REPLY_BOUND_MS in hermes-memory-relay/SEAM.md.
export const PROBE_REPLY_BOUND_MS = 2_000;
// Must match CHILD_READY_TIMEOUT_MS in hermes-memory-relay/SEAM.md.
export const CHILD_READY_TIMEOUT_MS = 5_000;
// Must match RELAY_CHILD_EXIT_BOUND_MS in hermes-memory-relay/SEAM.md.
export const RELAY_CHILD_EXIT_BOUND_MS = 5_000;
// Must match MAX_PUBLIC_CONNECTIONS in hermes-memory-relay/SEAM.md.
export const MAX_PUBLIC_CONNECTIONS = 4;
// Must match ABANDONED_PROBE_NONCE_CAP in hermes-memory-relay/SEAM.md.
export const ABANDONED_PROBE_NONCE_CAP = 16;

export const MIN_SEARCH_LIMIT = 1; // Node-local; the memory search tool represents no hits with an empty result set.
export const MAX_SEARCH_LIMIT = 20; // Node-local; this keeps a typed search request comfortably below one result frame.

export const REQUEST_ID_PATTERN = new RegExp(`^[A-Za-z0-9._:-]{1,${MAX_REQUEST_ID_BYTES}}$`, "u");
export const CONNECTION_ID_PATTERN = new RegExp(`^c[0-9]{1,${MAX_CONNECTION_ID_BYTES - 1}}$`, "u");
export const NONCE_PATTERN = new RegExp(`^[0-9a-f]{${PROBE_NONCE_BYTES}}$`, "u");
export const STANDARD_BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
