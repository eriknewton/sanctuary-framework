/**
 * Credential surrogacy: the named bounds of design v2.1 section 3.5.
 *
 * Every constant here is DERIVED from something already shipped in this tree,
 * and the derivation is written at the constant, not in a design document that
 * the code can drift from. A bare number in this file would be a defect: the
 * whole point of the table is that a reviewer can check the bound against the
 * thing it was sized from.
 *
 * Each constant also names its ENFORCEMENT SITE, because several of these are
 * relied on by a different process than the one that declares them (the helper
 * daemon, the gate, root arming, the policy parser). A bound nobody enforces is
 * documentation, not a bound.
 *
 * WHY THIS FILE IMPORTS NOTHING. The helper daemon, root arming, the policy
 * parser and (slice 1b) the gate all load it, and two of those run as root. A
 * literal plus a pinning TEST is a smaller surface than an import chain that
 * would pull the audit log and a socket client into every one of them. Each
 * constant derived from a shipped constant is pinned equal to its source in
 * `server/test/credential-surrogate/constants.test.ts`, which imports both
 * sides; a drift on either side fails that test rather than going unnoticed.
 */

/**
 * Bindings one agent may carry in a single generation.
 *
 * Derivation: `MAX_LIVE_TOKENS_PER_CALLER` (100) in `token-issuer.ts`, for the
 * same reason stated there: a legitimate principal holds a handful of distinct
 * credentials, so 100 is far above real use while still turning a runaway or
 * hostile policy file into a small fixed footprint in the helper's table
 * instead of unbounded growth.
 *
 * Enforced at: policy parse (`parseSurrogatePolicyDocument`), root arming
 * (refuse to arm), and helper load (refuse to start).
 */
// Must match `MAX_LIVE_TOKENS_PER_CALLER` in `disclosure/broker/token-issuer.ts`.
export const MAX_SURROGATE_BINDINGS_PER_AGENT = 100;

/**
 * Bindings summed over every armed agent on one host.
 *
 * Derivation: `MAX_LIVE_TOKENS_GLOBAL` (2000) in `token-issuer.ts`, the same
 * fleet-scale headroom, applied here across agents rather than across callers.
 *
 * Enforced at: root arming only, under the existing provision lock, because
 * that is the only place where the per-host total is knowable.
 */
// Must match `MAX_LIVE_TOKENS_GLOBAL` in `disclosure/broker/token-issuer.ts`.
export const MAX_SURROGATE_BINDINGS_PER_HOST = 2000;

/**
 * Destinations one binding may name.
 *
 * Derivation: one API host plus a regional or versioned alternate is the common
 * shape; 4 doubles that and keeps the destination membership check a
 * constant-size scan in the helper's hot path.
 *
 * Enforced at: policy parse.
 */
export const MAX_SURROGATE_DESTINATIONS_PER_BINDING = 4;

/**
 * Placeholders the gate will act on in one forward-mode request.
 *
 * Derivation: one credential header per in-scope API; 4 leaves room for
 * key-plus-secret schemes and bounds the helper queries one request can cause.
 *
 * Enforced at: the gate forward handler (slice 1b), which refuses an over-cap
 * request rather than querying the helper more times.
 */
export const MAX_PLACEHOLDERS_PER_REQUEST = 4;

/**
 * Longest surrogate value the helper will accept on an unlock.
 *
 * Derivation: the gate server calls `createServer` with no options
 * (`egress-gate/gate-server.ts`), so it runs Node's default
 * `http.maxHeaderSize` of 16384 bytes. One credential at a quarter of that
 * leaves room for the rest of the request head after the swap.
 *
 * Enforced at: helper unlock validation.
 */
export const MAX_SURROGATE_VALUE_BYTES = 4096;

/**
 * Bytes reserved for everything in a wire frame that is not a value.
 *
 * Derivation: `PEER_RESOLVER_MAX_FRAME_BYTES` (512) in
 * `egress-gate/peer-resolver-protocol.ts`. That same budget already covers a
 * strictly larger envelope than ours needs: `v`, a 32-character `id`, `kind`,
 * `reason`, a 52-byte placeholder, a DNS host of at most 253 bytes, a port, and
 * `location` (`header:` plus a token of at most 64 bytes), with room to spare.
 *
 * Enforced at: both codecs.
 */
// Must match `PEER_RESOLVER_MAX_FRAME_BYTES` in `egress-gate/peer-resolver-protocol.ts`.
export const SURROGATE_WIRE_ENVELOPE_BYTES = 512;

/**
 * Hard cap on one encoded frame, either direction, on either socket.
 *
 * Derivation: a surrogate value is visible ASCII, space or tab (the unlock
 * validation below), and JSON escaping expands only `"`, `\` and tab, each to
 * two bytes, so an escaped value is at most twice its length. One value per
 * frame (design 3.4.3), so `2 * MAX_SURROGATE_VALUE_BYTES` plus the envelope is
 * the largest legal frame.
 *
 * Enforced at: both codecs, checked BEFORE `JSON.parse` in both directions, so
 * an oversized or endless stream can never pin memory or block the event loop.
 */
export const SURROGATE_WIRE_MAX_FRAME_BYTES =
  2 * MAX_SURROGATE_VALUE_BYTES + SURROGATE_WIRE_ENVELOPE_BYTES;

/**
 * Queries the helper will have in flight at once.
 *
 * Derivation: `PEER_RESOLVER_MAX_CONCURRENT_LOOKUPS` (8) in
 * `peer-resolver-daemon.ts`, the same root-process amplification bound: this is
 * the other root daemon an unprivileged uid can address, and it should not be a
 * larger lever than that one.
 *
 * Enforced at: the helper, which answers `rate_limited` over cap rather than
 * queueing, so the queue itself is never a memory lever.
 */
// Must match `PEER_RESOLVER_MAX_CONCURRENT_LOOKUPS` in `egress-gate/peer-resolver-daemon.ts`.
export const SURROGATE_HELPER_MAX_CONCURRENT_QUERIES = 8;

/**
 * Deadline the gate applies to one helper query.
 *
 * Derivation: `PRIVILEGED_PEER_RUNNER_TIMEOUT_MS` (2000) in
 * `peer-resolver-client.ts`, the same local Unix-socket round trip to a root
 * daemon on the same host.
 *
 * Enforced at: the gate-side helper client (slice 1b), which destroys the
 * socket on the deadline so a later reply has no reader.
 */
// Must match `PRIVILEGED_PEER_RUNNER_TIMEOUT_MS` in `egress-gate/peer-resolver-client.ts`.
export const SURROGATE_QUERY_TIMEOUT_MS = 2000;

/**
 * Ceiling the helper clamps an unlock TTL to.
 *
 * Derivation: 86400 seconds is one day, so a forgotten unlock does not outlive
 * a working day. The RELYING side clamps (AGENTS.md rule 10): the helper never
 * trusts the caller's number.
 *
 * Enforced at: the helper's unlock validation.
 */
export const MAX_SURROGATE_UNLOCK_SECONDS = 86400;

/**
 * Response-body bytes the echo guard scans before giving up.
 *
 * Derivation: 256 times `MAX_SURROGATE_VALUE_BYTES` (1 MiB). An echoed
 * credential appears in an error, introspection or header-reflection body,
 * which for the in-scope JSON APIs is far below 1 MiB; 256 times the longest
 * value leaves two orders of magnitude of headroom, and it bounds scan work per
 * response to 2^20 bytes times at most `MAX_PLACEHOLDERS_PER_REQUEST` linear
 * substring searches.
 *
 * Enforced at: the gate echo scanner (slice 1b), which passes a longer body
 * unscanned and emits an event saying so rather than scanning without a bound.
 */
export const MAX_SURROGATE_ECHO_SCAN_BYTES = 256 * MAX_SURROGATE_VALUE_BYTES;
