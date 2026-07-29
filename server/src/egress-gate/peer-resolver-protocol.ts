/**
 * Wire protocol for the privileged peer-uid resolver (Unified Protect Slice 5
 * S5-3 fix: Mini1 2026-07-24 drill finding, `Gate_Peer_Resolution_Fix_Build_
 * Spec_2026-07-24.md`, Option 1).
 *
 * THE PROBLEM THIS CLOSES. `peer-identity.ts` resolves the loopback CONNECT
 * peer's uid by shelling `lsof`, run by the UNPRIVILEGED gate uid. A non-root
 * process cannot `lsof` a socket owned by a different uid, so resolution
 * returned `null` on EVERY real agent connect (drill-confirmed 100%,
 * `drill-evidence-2026-07-24/RESULTS.md`), and the S5-3 fail-closed rule
 * denies on any unresolved peer -- the gate strangled its own agent.
 *
 * THE FIX. A root-owned peer-resolver DAEMON (`peer-resolver-daemon.ts`) runs
 * the privileged lookup and answers over a narrow, per-agent-uid-scoped Unix
 * domain socket. This module is the WIRE SHAPE between the two: intentionally
 * the SMALLEST possible request/response pair, never a general "run this
 * command" oracle.
 *
 * SCOPE DISCIPLINE (the security-sensitive core, per the build spec):
 *   - the request carries EXACTLY one field, the loopback client port to
 *     resolve -- there is no `command`/`argv`/free-form field a caller could
 *     ever widen into arbitrary root command execution;
 *   - the response is `resolved {uid,pid}` | `unresolved` | a bounded error
 *     reason string, never a raw process/uid enumeration;
 *   - both directions are LENGTH-BOUNDED before any JSON.parse runs, so an
 *     oversized or endless stream cannot pin memory or block the event loop
 *     (mirrors the bounded-frame discipline in `supervisor/protocol.ts`).
 *
 * TRANSPORT. Newline-delimited JSON, ONE request then ONE response per
 * connection (the caller then closes) -- the same "one request per
 * connection" model `supervisor/socket-server.ts` uses, chosen for the same
 * reason: it removes an entire class of pipelining/ordering bugs for a
 * channel that only ever needs a single round trip.
 *
 * THE UID BOUNDARY IS FILESYSTEM PERMISSION, NOT THIS PROTOCOL. Node exposes
 * no `SO_PEERCRED`/`getpeereid` binding (the same observation
 * `supervisor/socket-server.ts` makes); "invocable ONLY by the gate uid" is
 * enforced by the socket FILE being root-owned-then-chowned to the one gate
 * uid inside a root 0711 directory (`peer-resolver-daemon.ts`), the SAME
 * mechanism `liveness-oracle.ts` already uses for the per-uid `.token` file.
 * This module never authenticates a caller; it only shapes bytes.
 */

/**
 * On-wire protocol version. Bumping this is a breaking change on both ends.
 *
 * v2 (fix-round-2, 2026-07-24 re-gate BLOCKER): the ok response now carries
 * `gatePort` -- the port the DAEMON actually matched the 4-tuple against, its
 * OWN argv-derived value. The client compares it to the gate's current policy
 * port and REJECTS on mismatch, so a stale resolver whose loaded argv drifted
 * (matched an old port) can never be relabeled as if it matched the current
 * gate port. Adding a required field is the breaking change this header warns
 * about; both ends ship together, and a stale v1 daemon then fails this v2
 * parser -> fail-closed (a deny), never a silent accept.
 */
export const PEER_RESOLVER_PROTOCOL_VERSION = 2 as const;

/** Hard cap on one frame's encoded bytes (request OR response), before any parse. */
export const PEER_RESOLVER_MAX_FRAME_BYTES = 512;

/** The ONLY request shape: resolve the uid/pid owning this loopback client port. */
export interface PeerResolveRequest {
  v: typeof PEER_RESOLVER_PROTOCOL_VERSION;
  clientPort: number;
}

/** A successful resolution: the peer, or `null` for a genuine (rare) unresolved case. */
export interface PeerResolveOkResponse {
  v: typeof PEER_RESOLVER_PROTOCOL_VERSION;
  ok: true;
  peer: { uid: number; pid: number } | null;
  /**
   * The gate port the DAEMON matched the 4-tuple against (its OWN
   * argv-derived `deps.gatePort`, NEVER anything from the wire request). The
   * client rejects any answer whose `gatePort` differs from the gate's
   * current policy port (fix-round-2 BLOCKER): that closes the stale-resolver
   * wrong-ALLOW where a daemon still matching an old port `A` gets its answer
   * relabeled as if it matched the current port `B`.
   */
  gatePort: number;
}

/** A bounded, non-throwing failure (malformed request, rate-limited, lookup faulted). */
export interface PeerResolveErrResponse {
  v: typeof PEER_RESOLVER_PROTOCOL_VERSION;
  ok: false;
  reason: string;
}

export type PeerResolveResponse = PeerResolveOkResponse | PeerResolveErrResponse;

function isValidPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535;
}

/**
 * Encode a frame as newline-terminated JSON. Throws if the caller ever tries
 * to encode something that would exceed the bound (a programmer error, not a
 * runtime/network condition) -- callers control both message shapes, so this
 * can only fire on a future field addition that forgot the size budget.
 */
function encodeFrame(value: unknown): Buffer {
  const json = JSON.stringify(value);
  const buf = Buffer.from(`${json}\n`, "utf8");
  if (buf.length > PEER_RESOLVER_MAX_FRAME_BYTES) {
    throw new Error(
      `peer-resolver protocol: encoded frame (${buf.length} bytes) exceeds the ${PEER_RESOLVER_MAX_FRAME_BYTES}-byte bound`,
    );
  }
  return buf;
}

export function encodePeerResolveRequest(req: PeerResolveRequest): Buffer {
  return encodeFrame(req);
}

export function encodePeerResolveResponse(resp: PeerResolveResponse): Buffer {
  return encodeFrame(resp);
}

/**
 * Strictly parse one request line. Rejects anything that is not EXACTLY
 * `{ v: 2, clientPort: <valid TCP port> }` -- no extra fields, no coercion.
 * Returns `null` on any deviation (the server treats that as a bounded
 * protocol-error response, never a throw).
 */
export function parsePeerResolveRequest(raw: string): PeerResolveRequest | null {
  if (Buffer.byteLength(raw, "utf8") > PEER_RESOLVER_MAX_FRAME_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const r = parsed as Record<string, unknown>;
  const keys = Object.keys(r);
  if (keys.length !== 2 || !keys.includes("v") || !keys.includes("clientPort")) return null;
  if (r.v !== PEER_RESOLVER_PROTOCOL_VERSION) return null;
  if (!isValidPort(r.clientPort)) return null;
  return { v: PEER_RESOLVER_PROTOCOL_VERSION, clientPort: r.clientPort };
}

/**
 * Strictly parse one response line. Rejects malformed/unexpected shapes as
 * `null` (the CLIENT then treats it exactly like a transport failure: a
 * bounded, fail-closed non-resolution -- never a throw, never a silent
 * allow).
 */
export function parsePeerResolveResponse(raw: string): PeerResolveResponse | null {
  if (Buffer.byteLength(raw, "utf8") > PEER_RESOLVER_MAX_FRAME_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const r = parsed as Record<string, unknown>;
  if (r.v !== PEER_RESOLVER_PROTOCOL_VERSION) return null;
  if (r.ok === true) {
    // v2 (fix-round-2): the ok response is EXACTLY `{v, ok, peer, gatePort}`
    // (4 keys). `gatePort` is REQUIRED and range-validated on EVERY ok answer
    // (resolved AND unresolved) so the client always has the daemon's matched
    // port to compare against; a missing/garbage port is rejected here, which
    // the client treats as a fail-closed non-resolution.
    const keys = Object.keys(r);
    if (keys.length !== 4 || !keys.includes("peer") || !keys.includes("gatePort")) return null;
    if (!isValidPort(r.gatePort)) return null;
    const gatePort = r.gatePort;
    const peer = r.peer;
    if (peer === null) return { v: PEER_RESOLVER_PROTOCOL_VERSION, ok: true, peer: null, gatePort };
    if (typeof peer !== "object" || Array.isArray(peer)) return null;
    const peerKeys = Object.keys(peer as Record<string, unknown>);
    if (
      peerKeys.length !== 2 ||
      !peerKeys.includes("uid") ||
      !peerKeys.includes("pid") ||
      !Number.isInteger((peer as Record<string, unknown>).uid) ||
      !Number.isInteger((peer as Record<string, unknown>).pid) ||
      ((peer as Record<string, unknown>).uid as number) < 0 ||
      ((peer as Record<string, unknown>).pid as number) < 0
    ) {
      return null;
    }
    return {
      v: PEER_RESOLVER_PROTOCOL_VERSION,
      ok: true,
      peer: { uid: (peer as { uid: number }).uid, pid: (peer as { pid: number }).pid },
      gatePort,
    };
  }
  if (r.ok === false) {
    const keys = Object.keys(r);
    if (keys.length !== 3 || !keys.includes("reason") || typeof r.reason !== "string") return null;
    return { v: PEER_RESOLVER_PROTOCOL_VERSION, ok: false, reason: r.reason };
  }
  return null;
}
