import { MEMORY_BATCH_LOCK_TIMEOUT_MS } from "../sdw/adapters/sdw-memory-backend.js";

// Must match the fixed denial text in hermes-memory-relay/SEAM.md.
export const HERMES_MEMORY_DENIAL = "Memory request denied.";
export const HERMES_MEMORY_UNAVAILABLE = "Memory service unavailable.";

// Must match MAX_PUBLIC_CONNECTIONS in hermes-memory-relay/SEAM.md.
export const HERMES_MAX_PUBLIC_CONNECTIONS = 4;
// 4 = the settling reserve paired with the four relay-admitted public slots; no separate settling ceiling is enforced.
export const HERMES_SETTLING_RESERVE = HERMES_MAX_PUBLIC_CONNECTIONS;
// 8 = the single total cap enforced at call admission: four live slots plus the settling reserve of four.
export const HERMES_MAX_CALL_RECORDS = HERMES_MAX_PUBLIC_CONNECTIONS + HERMES_SETTLING_RESERVE;

// Must match MAX_PUBLIC_FRAME_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_PUBLIC_FRAME_BYTES = 65_536;
// Must match MAX_RESULT_FRAME_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_RESULT_FRAME_BYTES = 65_536;
// Must match PROBE_REPLY_BOUND_MS in hermes-memory-relay/SEAM.md.
export const PROBE_REPLY_BOUND_MS = 2_000;
// Must match MAX_REQUEST_ID_BYTES in hermes-memory-relay/SEAM.md.
export const MAX_REQUEST_ID_BYTES = 128;
// Must match PROBE_NONCE_BYTES in hermes-memory-relay/SEAM.md: a hex-character length for 16 random bytes, never a byte length.
export const PROBE_NONCE_BYTES = 32;
// Must match ABANDONED_PROBE_NONCE_CAP in hermes-memory-relay/SEAM.md (value only; no eviction, pair-only state).
export const ABANDONED_PROBE_NONCE_CAP = 16;
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
// Must match MAX_JSON_NESTING_DEPTH in hermes-memory-relay/SEAM.md.
export const MAX_JSON_NESTING_DEPTH = 64;

export const MIN_SEARCH_LIMIT = 1; // Node-local; the memory search tool represents no hits with an empty result set.
export const MAX_SEARCH_LIMIT = 20; // Node-local policy bound; oversized results are handled by the response denial path.

export const HERMES_TOOL_TIMEOUT_MS = 120_000; // Node-local: Hermes client tool timeout budget.
export const HERMES_RESPONSE_MARGIN_MS = 5_000; // Node-local: room for shim cancel and response delivery.
export const HERMES_APPROVAL_DEADLINE_MS =
  HERMES_TOOL_TIMEOUT_MS -
  MEMORY_BATCH_LOCK_TIMEOUT_MS -
  PROBE_REPLY_BOUND_MS -
  HERMES_RESPONSE_MARGIN_MS;
export const HERMES_RATE_WINDOW_MS = 60_000; // Node-local: one-minute rolling admission window.
export const HERMES_MAX_CALLS_PER_MINUTE = 60; // 60 = one call per second in HERMES_RATE_WINDOW_MS.
export const HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE = 6; // 6 = one owner prompt per ten seconds in HERMES_RATE_WINDOW_MS.
export const HERMES_MAX_PENDING_APPROVALS = 1; // Node-local: the approval ledger owns one global slot.

// Must match the decoded request_id and cancel.mcp_request_id pattern in hermes-memory-relay/SEAM.md.
export const REQUEST_ID_PATTERN = new RegExp(`^[A-Za-z0-9._:-]{1,${MAX_REQUEST_ID_BYTES}}$`, "u");
// Must match the relay-minted connection_id shape in hermes-memory-relay/SEAM.md.
export const CONNECTION_ID_PATTERN = new RegExp(`^c[0-9]{1,${MAX_CONNECTION_ID_BYTES - 1}}$`, "u");
// Must match probe.nonce and probe_reply.nonce in hermes-memory-relay/SEAM.md.
export const NONCE_PATTERN = new RegExp(`^[0-9a-f]{${PROBE_NONCE_BYTES}}$`, "u");
// Must match standard base64 with required padding in hermes-memory-relay/SEAM.md.
export const STANDARD_BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
