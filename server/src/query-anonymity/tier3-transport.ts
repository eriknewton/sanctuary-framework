/**
 * Sanctuary WP-V1.x-QUERY-LAYER-ANONYMITY Tier 3a — network-path anonymity
 * transport (egress-proxy encapsulation, Slice 1).
 *
 * Design source of truth: `Review/Sanctuary/Query_Anon_Tier3_Design_Revised_2026-06-13.md`.
 *
 * ── What this slice delivers ────────────────────────────────────────────
 *
 * Slice 1 delivers **Property 1 only**: IP-decoupling and path-linkage
 * removal. After the transport is armed, the request to the provider
 * originates from the egress hop, not the operator host, so:
 *   - Adversary B (a path / network observer) sees the operator talking
 *     only to the relay, never to the provider — closed unconditionally
 *     at any relay size N.
 *   - Adversary A (the provider) no longer sees the operator's source IP.
 *     (Subject to the credential-layer caveat: the API key still identifies
 *     the operator. Credential-decoupling is a LATER slice — see the note
 *     at the bottom of this header. This module does NOT touch the key.)
 *
 * Slice 1 does NOT claim Property 2 (unlinkability / anonymity-set). A
 * relay with a handful of users is "a crowd of N", not anonymity. This
 * module surfaces no anonymity-set claim; live-set instrumentation (AC-3)
 * is deferred to a later slice and any future claim must be gated on it.
 *
 * ── The single most important architectural fact (AC-1) ─────────────────
 *
 * This transport is a **fetch decorator that composes BENEATH
 * `createAnonymizedFetch`**. The composition order installed at the
 * substrate selector is:
 *
 *     baseFetch (real network)
 *       └─ createTunneledFetch(baseFetch, tier3Config)   ← THIS module
 *            └─ createAnonymizedFetch(tunneledFetch, audit)   ← Tier 1
 *                 └─ selector.fetchImpl  (what substrate clients hold)
 *
 * Because the tunnel is reachable ONLY by calling the wrapped fetch the
 * substrate clients already hold, there is **no second outbound socket**:
 * the Tier 3 transport never opens its own egress outside the wrapped
 * channel. Castle Wall's egress filter still binds the sole outbound
 * channel, and the existing `query_anonymity_headers_stripped` audit
 * emission still fires on every call. AC-1 (no unwrapped outbound socket)
 * is a structural property of this composition, asserted by a regression
 * test (`tier3-transport.test.ts`).
 *
 * The `TunnelDialer` abstraction is the seam where a real two-hop
 * CONNECT/MASQUE chain is dialed. The dialer returns a `fetch`-shaped
 * function bound to the relay→egress tunnel; this module never holds a
 * raw socket itself, so a dialer that respects the wrapped-fetch contract
 * cannot create an unwrapped egress path.
 *
 * ── Connection-reuse hygiene (Slice 1.5, F-6) ───────────────────────────
 *
 * A reused tunnel connection is a within-crowd linkage channel: if two
 * queries ride the same relay→egress tunnel (a kept-alive socket, a TLS
 * session ticket, or a pooled/cached `TunnelFetch` handed back twice), a
 * downstream observer can correlate those queries to one origin and the
 * *effective* anonymity set collapses below the raw crowd size k (F-6 /
 * HIGH-2 in the Property-2 design review). The reference dialer below
 * already opens a fresh tunnel per `dial()` and forbids a second request
 * on its single bound socket, but that is the dialer's own discipline.
 * This slice makes no-reuse a **transport-enforced invariant that binds
 * EVERY `TunnelDialer`**, reference or production, so a dialer that pools
 * or keep-alives connections cannot leak through the seam:
 *
 *   1. Single-use per tunnel: a `TunnelFetch` returned by `dial()` is
 *      allowed to serve at most ONE request; the transport closes it
 *      immediately after that request (or its streamed body) completes,
 *      so a kept-alive socket cannot carry a second query.
 *   2. No handle aliasing: if a dialer ever returns the SAME `TunnelFetch`
 *      instance for two queries (a pooled/cached tunnel), the transport
 *      refuses to reuse it and fails closed (a reused handle is exactly
 *      the correlatable connection F-6 describes).
 *
 * This does NOT measure or claim an anonymity-set size (that is Slice 2/3
 * and gated on Erik's D-1..D-7 decisions); it only removes the cheap,
 * in-scope connection-reuse contributor to F-6 so that any future honest
 * Property-2 claim is not built over an open linkage channel. Fail-closed
 * and disarmed-by-default are unchanged: a reuse violation is treated as a
 * tunnel failure and routed through the existing `onTunnelFailure` policy
 * (DENY by default), never a silent direct connection.
 *
 * ── Fail-closed (WA-5) ──────────────────────────────────────────────────
 *
 * When the transport is armed but the tunnel cannot be established, the
 * request is **DENIED** (a `Tier3FailClosedError` is thrown). It is NEVER
 * silently fulfilled over a direct deanonymizing connection. This honors
 * the "never silently degrade to a less-secure behavior" hard constraint.
 * Fallback to a direct connection is only ever possible via an explicit,
 * documented operator opt-in (`onTunnelFailure: "fallback-direct"`), which
 * is NOT the default and is itself audited as a deanonymizing event.
 *
 * ── Trust model / non-collusion (WA-1) ──────────────────────────────────
 *
 * Security rests on the relay and the egress being operated by
 * non-colluding parties (relay ≠ egress). The relay sees the operator's
 * IP but only an opaque tunnel (not the destination); the egress sees the
 * destination but connects from its own IP, not the operator's. No single
 * hop sees both. If relay and egress collude, the operator IP and the
 * destination reunite and the protection collapses. The default posture is
 * operator-run / federated (the hops sit inside, or are chosen by, the
 * operator); third-party / Tor are labeled opt-ins, NEVER a
 * Sanctuary-embedded default.
 *
 * ── Out of scope for Slice 1 (noted, not built) ─────────────────────────
 *
 *   - Credential-identity / API-key decoupling (key rotation / pooled
 *     keys). The API key is in the Tier 1 REQUIRED_HEADERS allowlist and is
 *     never stripped; against the provider, IP-hiding is necessary but not
 *     sufficient. This is a LATER slice with a billing/quota tradeoff.
 *   - Property 2 (unlinkability) + live-set instrumentation (AC-3).
 *   - Mixnet / GPA-resistant mode (Tier-3b) + source-side traffic shaping.
 *   - Anonymous-credential (Privacy-Pass / ZK) relay gating. The dialer
 *     interface reserves a `credential` field so it can be added without a
 *     rewrite, but Slice 1 ships no credential scheme.
 */

import { Buffer } from "node:buffer";
import http from "node:http";
import net from "node:net";
import tls from "node:tls";

// ── Public configuration surface ─────────────────────────────────────────

/**
 * The wire mode for the two-hop tunnel. `connect` is HTTP CONNECT over
 * TLS (the classical form, RFC 9110 §9.3.6); `masque` is QUIC/HTTP-3
 * proxying (CONNECT-UDP / CONNECT-IP). Slice 1 implements the `connect`
 * reference dialer; `masque` is accepted in config for forward
 * compatibility but a `masque` dialer is a later slice.
 */
export type Tier3TunnelMode = "connect" | "masque";

/**
 * Which parties operate the two hops. This is a *labeling* of the same
 * primitive (Section 6.2 of the design); it does not change the mechanism.
 * `operator-run` / `federated` are the first-class defaults; the hosted /
 * third-party postures are labeled opt-ins that must never be selected by
 * default.
 */
export type Tier3Posture =
  | "operator-run"
  | "federated"
  | "sanctuary-hosted"
  | "third-party";

/**
 * Behavior when the anonymous tunnel cannot be established or fails
 * mid-request.
 *
 *   - `deny` (DEFAULT): fail closed. The request is denied; no direct
 *     connection is attempted. This is the only posture consistent with
 *     the "never silently degrade" hard constraint and is the default.
 *   - `fallback-direct`: explicit operator opt-in to fall back to a direct
 *     (deanonymizing) connection. NOT the default. Audited as a
 *     deanonymizing event by the caller.
 */
export type Tier3FailureMode = "deny" | "fallback-direct";

export interface Tier3TransportConfig {
  /**
   * Master arm switch. When `false` (the default for an operator who has
   * not opted into Tier 3), `createTunneledFetch` returns the base fetch
   * unchanged — Tier 3 is a no-op and adds no latency.
   */
  armed: boolean;
  mode: Tier3TunnelMode;
  posture: Tier3Posture;
  /**
   * What to do when the tunnel cannot be established. Defaults to `deny`
   * (fail closed). Only an explicit operator choice sets `fallback-direct`.
   */
  onTunnelFailure: Tier3FailureMode;
  /**
   * The dialer that establishes the two-hop tunnel and returns a
   * `fetch`-shaped function bound to it. Injected so the transport is
   * decoupled from any concrete relay/egress implementation; the
   * reference loopback CONNECT dialer (`createLoopbackConnectDialer`) is
   * one implementation, an operator-run or federated relay is another.
   *
   * When `armed` is true and `dialer` is absent, the transport fails
   * closed: there is no tunnel to route through, so the request is denied
   * (never sent direct). This makes "armed but unconfigured" safe by
   * construction.
   */
  dialer?: TunnelDialer;
}

/**
 * A two-hop tunnel dialer. Given the operator's intended destination
 * (derived from the outbound request), it establishes the relay→egress
 * chain and returns a `fetch`-shaped function whose connections are made
 * through the egress hop. The returned fetch MUST NOT open any socket
 * outside the tunnel it was handed; that contract is what preserves AC-1.
 *
 * The dialer returns `null` to signal it cannot serve this destination
 * (e.g. policy, relay unreachable), which the transport treats as a tunnel
 * failure and handles per `onTunnelFailure`.
 */
export interface TunnelDialer {
  /**
   * Human-readable label for audit / operator surfacing, e.g.
   * "operator-run loopback CONNECT". Never includes secrets.
   */
  readonly label: string;
  /**
   * Establish the tunnel to `destination` and return a fetch bound to it,
   * or `null` if the tunnel cannot be established. Implementations should
   * keep the relay and egress operated by non-colluding parties (WA-1).
   *
   * `credential` is reserved for the anonymous-credential relay-gating
   * slice; Slice 1 always passes `undefined`.
   */
  dial(
    destination: TunnelDestination,
    credential?: unknown,
  ): Promise<TunnelFetch | null>;
}

export interface TunnelDestination {
  /** Destination host (the provider), e.g. `api.anthropic.com`. */
  host: string;
  /** Destination port, defaulted to 443 for https. */
  port: number;
}

/**
 * A `fetch`-shaped function bound to an established tunnel, plus the egress
 * IP observed for that tunnel (used by AC-2 instrumentation: the provider
 * sees this IP, never the operator's). The fetch returns a standard
 * `Response` whose `body` ReadableStream is forwarded byte-for-byte, so
 * token-by-token streaming survives the tunnel (AC-4).
 */
export interface TunnelFetch {
  fetch: typeof fetch;
  /** The egress hop's source IP as seen by the destination. */
  egressIp: string;
  /** Close the tunnel and release sockets. */
  close(): void;
}

/**
 * Thrown when the Tier 3 transport is armed but the anonymous path cannot
 * be established and the failure mode is `deny`. Carries no operator IP or
 * secret. The substrate selector surfaces this as a denied query, never as
 * a silent direct connection.
 */
export class Tier3FailClosedError extends Error {
  public readonly destinationHost: string;
  public readonly dialerLabel: string | null;

  constructor(destinationHost: string, dialerLabel: string | null, cause?: unknown) {
    super(
      `Tier 3 anonymous path unavailable for ${destinationHost}; query denied (fail-closed). ` +
        `No direct connection was attempted.`,
    );
    this.name = "Tier3FailClosedError";
    this.destinationHost = destinationHost;
    this.dialerLabel = dialerLabel;
    if (cause !== undefined) {
      // Preserve the cause without leaking it into the user-facing message.
      (this as { cause?: unknown }).cause = cause;
    }
  }
}

/** Audit-op constants for the Tier 3 transport. */
export const TIER3_AUDIT_OPS = {
  /** A query was routed through the two-hop anonymous tunnel. */
  TUNNEL_USED: "query_anonymity_tier3_tunnel_used",
  /** The anonymous path failed and the query was denied (fail-closed). */
  FAIL_CLOSED: "query_anonymity_tier3_fail_closed",
  /**
   * An explicit operator opt-in caused a deanonymizing direct fallback.
   * Surfaced loudly because it defeats Tier 3 for that request.
   */
  DEANON_FALLBACK: "query_anonymity_tier3_deanon_fallback",
  /**
   * A dialer handed back a tunnel handle that had already served a request
   * (a pooled / aliased / kept-alive reuse). The transport refused to reuse
   * it (a reused connection is an F-6 within-crowd linkage channel) and
   * routed the query through the fail-closed policy instead (Slice 1.5).
   */
  REUSE_REJECTED: "query_anonymity_tier3_connection_reuse_rejected",
} as const;

export type Tier3AuditOp = (typeof TIER3_AUDIT_OPS)[keyof typeof TIER3_AUDIT_OPS];

export interface Tier3AuditEvent {
  op: Tier3AuditOp;
  destinationHost: string;
  mode: Tier3TunnelMode;
  posture: Tier3Posture;
  dialerLabel: string | null;
  /** Egress IP for a successful tunnel; null on failure. */
  egressIp: string | null;
}

export type Tier3AuditCallback = (event: Tier3AuditEvent) => void;

/**
 * The default, safe configuration: disarmed. An operator who has not opted
 * into Tier 3 gets exactly the Tier 1 behavior with zero added latency.
 */
export const DISARMED_TIER3_CONFIG: Tier3TransportConfig = {
  armed: false,
  mode: "connect",
  posture: "operator-run",
  onTunnelFailure: "deny",
};

// ── The transport: a fetch decorator that sits BENEATH createAnonymizedFetch ─

/**
 * Wrap a `fetch`-compatible function so that, when armed, every call is
 * routed through the two-hop anonymous tunnel instead of connecting
 * directly. Disarmed, it returns `baseFetch` unchanged.
 *
 * Compose this BENEATH `createAnonymizedFetch` (see the module header):
 * the substrate selector builds
 *   createAnonymizedFetch(createTunneledFetch(baseFetch, cfg), onAudit)
 * so the tunnel is reachable only through the wrapped fetch boundary and
 * Castle Wall still governs the sole outbound channel (AC-1).
 *
 * Streaming (AC-4): the tunnel fetch returns a standard `Response`; its
 * `body` ReadableStream is returned untouched, so token-by-token streaming
 * is preserved.
 *
 * Fail-closed (WA-5): when armed and the tunnel cannot be established, the
 * request is denied via `Tier3FailClosedError` unless the operator has
 * explicitly chosen `fallback-direct`.
 */
export function createTunneledFetch(
  baseFetch: typeof fetch,
  config: Tier3TransportConfig,
  onAudit?: Tier3AuditCallback,
): typeof fetch {
  if (!config.armed) {
    // No-op: Tier 3 is off. Return the base fetch unchanged so there is
    // zero added latency and zero behavioral change for operators who have
    // not opted in.
    return baseFetch;
  }

  // Slice 1.5 (F-6) connection-reuse hygiene: remember every tunnel handle
  // this transport has already routed a query through. If a dialer ever
  // hands the SAME handle back (a pooled / cached tunnel), reusing it would
  // link the two queries on one connection and collapse the effective
  // anonymity set. We refuse to reuse it and fail closed. A `WeakSet` keys
  // on object identity and never retains the handle past its own lifetime.
  const seenTunnels = new WeakSet<TunnelFetch>();

  const wrapped: typeof fetch = async (input, init) => {
    const destination = resolveDestination(input);

    // A non-https destination, or one we cannot parse, must not be sent
    // over a direct connection while armed: that would deanonymize. Treat
    // it as a tunnel failure and apply the fail-closed policy.
    if (!destination) {
      return handleTunnelFailure(
        baseFetch,
        config,
        onAudit,
        "<unresolved-destination>",
        null,
        input,
        init,
        new Error("could not resolve a tunnelable https destination"),
      );
    }

    if (!config.dialer) {
      // Armed but no dialer configured → fail closed. Never send direct.
      return handleTunnelFailure(
        baseFetch,
        config,
        onAudit,
        destination.host,
        null,
        input,
        init,
        new Error("Tier 3 armed but no tunnel dialer configured"),
      );
    }

    let tunnel: TunnelFetch | null;
    try {
      tunnel = await config.dialer.dial(destination);
    } catch (err) {
      return handleTunnelFailure(
        baseFetch,
        config,
        onAudit,
        destination.host,
        config.dialer.label,
        input,
        init,
        err,
      );
    }

    if (!tunnel) {
      return handleTunnelFailure(
        baseFetch,
        config,
        onAudit,
        destination.host,
        config.dialer.label,
        input,
        init,
        new Error("dialer declined to serve destination"),
      );
    }

    // Slice 1.5 (F-6): a tunnel handle may serve at most one query. If the
    // dialer returned a handle we have already routed through, it is a
    // pooled / aliased connection, and reusing it correlates the two queries.
    // Refuse and fail closed (the handle is torn down so the pooled socket
    // does not linger). This binds on EVERY dialer, not just the reference
    // one, so a production keep-alive/pooling dialer cannot leak here.
    if (seenTunnels.has(tunnel)) {
      try {
        tunnel.close();
      } catch {
        /* best-effort teardown of the reused handle */
      }
      onAudit?.({
        op: TIER3_AUDIT_OPS.REUSE_REJECTED,
        destinationHost: destination.host,
        mode: config.mode,
        posture: config.posture,
        dialerLabel: config.dialer.label,
        egressIp: null,
      });
      return handleTunnelFailure(
        baseFetch,
        config,
        onAudit,
        destination.host,
        config.dialer.label,
        input,
        init,
        new Error("dialer returned a reused tunnel handle (F-6 connection reuse)"),
      );
    }
    seenTunnels.add(tunnel);

    // Single-use enforcement: wrap the handle so it is hard-closed after one
    // request (or one streamed body). A dialer that keeps its socket alive
    // for reuse cannot carry a second query through this transport.
    const singleUse = makeSingleUseTunnel(tunnel);

    try {
      const response = await singleUse.fetch(input, init);
      onAudit?.({
        op: TIER3_AUDIT_OPS.TUNNEL_USED,
        destinationHost: destination.host,
        mode: config.mode,
        posture: config.posture,
        dialerLabel: config.dialer.label,
        egressIp: singleUse.egressIp,
      });
      // Return the Response with its streaming body intact (AC-4). The
      // tunnel handle is closed once the body has been fully consumed.
      return wrapResponseForTunnelClose(response, singleUse);
    } catch (err) {
      // The tunnel was established but the request failed mid-flight. Do
      // NOT retry direct (that would deanonymize). Apply the fail-closed
      // policy; the tunnel is torn down.
      singleUse.close();
      return handleTunnelFailure(
        baseFetch,
        config,
        onAudit,
        destination.host,
        config.dialer.label,
        input,
        init,
        err,
      );
    }
  };

  return wrapped;
}

/**
 * Slice 1.5 (F-6) single-use wrapper. Wraps a `TunnelFetch` so that:
 *   - its `fetch` may be invoked at most once; a second call throws rather
 *     than carrying a second query over the same (possibly kept-alive)
 *     connection, and
 *   - `close()` is idempotent and is guaranteed to fire after that one
 *     request (or its streamed body) completes, tearing down any socket the
 *     dialer might otherwise have kept alive for reuse.
 *
 * This makes "one tunnel, one query" a transport-enforced invariant that
 * binds every dialer, so a pooling / keep-alive dialer cannot create a
 * cross-query connection-reuse linkage at this seam. `egressIp` is passed
 * through unchanged.
 */
function makeSingleUseTunnel(tunnel: TunnelFetch): TunnelFetch {
  let fetched = false;
  let closed = false;
  const closeOnce = () => {
    if (closed) return;
    closed = true;
    tunnel.close();
  };
  return {
    egressIp: tunnel.egressIp,
    fetch: ((input, init) => {
      if (fetched) {
        // Reuse of this handle would link a second query to the first over
        // the same connection (F-6). Refuse rather than serve it.
        throw new Error(
          "tunnel handle already used (Slice 1.5: one tunnel serves one query)",
        );
      }
      fetched = true;
      return tunnel.fetch(input, init);
    }) as typeof fetch,
    close: closeOnce,
  };
}

/**
 * Apply the configured failure policy. Default `deny` throws a
 * `Tier3FailClosedError` (the query is denied, never sent direct). The
 * explicit `fallback-direct` opt-in audits a deanonymizing event and then
 * connects directly via `baseFetch`.
 */
async function handleTunnelFailure(
  baseFetch: typeof fetch,
  config: Tier3TransportConfig,
  onAudit: Tier3AuditCallback | undefined,
  destinationHost: string,
  dialerLabel: string | null,
  input: Parameters<typeof fetch>[0],
  init: Parameters<typeof fetch>[1],
  cause: unknown,
): Promise<Response> {
  if (config.onTunnelFailure === "fallback-direct") {
    onAudit?.({
      op: TIER3_AUDIT_OPS.DEANON_FALLBACK,
      destinationHost,
      mode: config.mode,
      posture: config.posture,
      dialerLabel,
      egressIp: null,
    });
    return baseFetch(input, init);
  }
  onAudit?.({
    op: TIER3_AUDIT_OPS.FAIL_CLOSED,
    destinationHost,
    mode: config.mode,
    posture: config.posture,
    dialerLabel,
    egressIp: null,
  });
  throw new Tier3FailClosedError(destinationHost, dialerLabel, cause);
}

/**
 * Resolve the destination host/port from a fetch input. Returns `null` for
 * anything that is not a parseable https URL (Slice 1 only tunnels https
 * provider traffic; a non-https or unparseable target is handled by the
 * fail-closed path rather than silently connecting direct).
 */
function resolveDestination(input: Parameters<typeof fetch>[0]): TunnelDestination | null {
  let urlStr: string;
  if (typeof input === "string") urlStr = input;
  else if (input instanceof URL) urlStr = input.toString();
  else if (typeof Request !== "undefined" && input instanceof Request) urlStr = input.url;
  else return null;

  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  const port = url.port ? Number(url.port) : 443;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { host: url.hostname, port };
}

/**
 * Return a Response that closes the tunnel handle once its body has been
 * fully read. If the body is already consumed/empty, close immediately.
 * The Response itself (status, headers, streaming body) is preserved.
 */
function wrapResponseForTunnelClose(response: Response, tunnel: TunnelFetch): Response {
  if (!response.body) {
    tunnel.close();
    return response;
  }
  const closing = new TransformStream<Uint8Array, Uint8Array>({
    flush() {
      tunnel.close();
    },
  });
  const streamed = response.body.pipeThrough(closing);
  return new Response(streamed, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

// ── Reference operator-run dialer: in-process two-hop CONNECT chain ──────

/**
 * Endpoint coordinates for a hop (relay or egress).
 */
export interface ConnectHopEndpoint {
  host: string;
  port: number;
  /** Whether the hop terminates TLS (a real relay does; loopback test hops may not). */
  tls: boolean;
}

export interface LoopbackConnectDialerConfig {
  relay: ConnectHopEndpoint;
  egress: ConnectHopEndpoint;
  /** Optional dialer label override for audit. */
  label?: string;
  /** Connection/handshake timeout in ms. Default 10000. */
  timeoutMs?: number;
  /**
   * TLS options applied to the final end-to-end handshake to the
   * destination (e.g. a test CA in `ca`). Production omits this and uses
   * the system trust store.
   */
  destinationTlsOptions?: tls.ConnectionOptions;
}

/**
 * Build a reference two-hop CONNECT dialer.
 *
 * The chain is: client → relay (CONNECT egress) → egress (CONNECT
 * destination) → provider. Hop 1 (relay) sees the operator IP but only an
 * opaque CONNECT to the egress, never the provider. Hop 2 (egress) sees
 * the provider and connects from its own IP. No single hop sees both
 * (WA-1, assuming relay ≠ egress operator).
 *
 * This dialer never exposes a raw socket to the caller; it returns a
 * `fetch` bound to the tunnel via a Node http Agent whose
 * `createConnection` yields the already-tunneled socket. That keeps the
 * transport's only egress inside the wrapped channel (AC-1).
 *
 * Intended for operator-run mode (the operator runs both hops, or a
 * federation peer runs the egress) and for the AC-1/AC-2/AC-4 regression
 * harness. Production federated/hosted dialers implement the same
 * `TunnelDialer` interface against real remote hops.
 */
export function createLoopbackConnectDialer(
  config: LoopbackConnectDialerConfig,
): TunnelDialer {
  const timeoutMs = config.timeoutMs ?? 10000;
  const label = config.label ?? `operator-run two-hop CONNECT (${config.relay.host}→${config.egress.host})`;

  return {
    label,
    async dial(destination: TunnelDestination): Promise<TunnelFetch | null> {
      // Establish the two-hop tunnel to the destination. The resulting
      // socket is a TLS connection to the destination, carried inside the
      // relay→egress CONNECT chain.
      const tunnelSocket = await dialTwoHopConnect(
        config.relay,
        config.egress,
        destination,
        timeoutMs,
        config.destinationTlsOptions,
      );

      // The egress IP as the destination would observe it. For the
      // loopback reference chain this is the egress hop's local address;
      // a production dialer reports the egress hop's public IP.
      const egressIp = tunnelSocket.egressIp;

      // Bind a Node http Agent to the tunneled socket so the request
      // reuses it as the connection. We use the http.request path with an
      // agent that hands back the tunneled TLS socket, avoiding any second
      // outbound connection.
      const tunnelFetch = makeTunnelBoundFetch(tunnelSocket.socket, destination, timeoutMs);

      return {
        fetch: tunnelFetch,
        egressIp,
        close() {
          tunnelSocket.socket.destroy();
        },
      };
    },
  };
}

interface TwoHopResult {
  socket: tls.TLSSocket;
  egressIp: string;
}

/**
 * Open relay → egress → destination as a chained CONNECT tunnel and return
 * the TLS socket to the destination plus the egress IP.
 *
 * Step 1: TCP/TLS connect to the relay; send `CONNECT egress:port`.
 * Step 2: over that tunnel, send `CONNECT destination:port` to the egress.
 * Step 3: TLS-handshake to the destination over the doubly-tunneled byte
 *         stream (so the provider sees a normal TLS client, terminating at
 *         the operator end-to-end, so the egress cannot read content).
 */
async function dialTwoHopConnect(
  relay: ConnectHopEndpoint,
  egress: ConnectHopEndpoint,
  destination: TunnelDestination,
  timeoutMs: number,
  destinationTlsOptions?: tls.ConnectionOptions,
): Promise<TwoHopResult> {
  // ── Hop 1: connect to the relay ──
  const relaySocket = await connectHop(relay, timeoutMs);

  // Ask the relay to CONNECT onward to the egress. The relay sees only
  // "this client wants to reach the egress", never the destination.
  await sendConnect(relaySocket, egress.host, egress.port, timeoutMs);

  // ── Hop 2: over the relay tunnel, reach the egress ──
  // If the egress terminates TLS, wrap the relay tunnel in TLS to the
  // egress first; otherwise speak CONNECT in the clear over the tunnel
  // (loopback test hops).
  let egressStream: net.Socket | tls.TLSSocket = relaySocket;
  if (egress.tls) {
    egressStream = await tlsUpgrade(relaySocket, egress.host, timeoutMs);
  }

  // Capture the egress IP the destination will observe. For loopback this
  // is the egress hop's bound address; a production egress reports its
  // public IP via the CONNECT response or an out-of-band attribute. We use
  // the egress endpoint host as the reported egress identity.
  const egressIp = egress.host;

  // Ask the egress to CONNECT to the actual destination.
  await sendConnect(egressStream, destination.host, destination.port, timeoutMs);

  // ── Step 3: end-to-end TLS to the destination over the double tunnel ──
  const destTls = await tlsUpgrade(
    egressStream,
    destination.host,
    timeoutMs,
    destinationTlsOptions,
  );

  return { socket: destTls, egressIp };
}

function connectHop(hop: ConnectHopEndpoint, timeoutMs: number): Promise<net.Socket | tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    let socket: net.Socket | tls.TLSSocket;
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      socket?.removeListener("error", onError);
      clearTimeout(timer);
    };
    const timer = setTimeout(() => {
      cleanup();
      socket?.destroy();
      reject(new Error(`timeout connecting to hop ${hop.host}:${hop.port}`));
    }, timeoutMs);

    if (hop.tls) {
      socket = tls.connect({ host: hop.host, port: hop.port, servername: hop.host }, () => {
        cleanup();
        resolve(socket);
      });
    } else {
      socket = net.connect({ host: hop.host, port: hop.port }, () => {
        cleanup();
        resolve(socket);
      });
    }
    socket.once("error", onError);
  });
}

/**
 * Send an HTTP CONNECT request over an already-open stream and resolve
 * once the proxy returns a 2xx. The stream is left in tunnel mode (raw
 * bytes flow to the connected target after the blank line).
 */
function sendConnect(
  stream: net.Socket | tls.TLSSocket,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const authority = formatAuthority(host, port);
    const req = `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`;
    let buf = Buffer.alloc(0);

    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const headerEnd = buf.indexOf("\r\n\r\n");
      if (headerEnd === -1) return; // wait for full status line + headers
      cleanup();
      const lineEnd = buf.indexOf("\r\n");
      const statusLine = buf.subarray(0, lineEnd === -1 ? headerEnd : lineEnd).toString("ascii");
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
      if (!m || m[1]?.[0] !== "2") {
        reject(new Error(`CONNECT to ${authority} failed: ${statusLine}`));
        return;
      }
      // Any bytes after the header terminator belong to the tunnel; push
      // them back so the next consumer (TLS handshake) sees them.
      const leftover = buf.subarray(headerEnd + 4);
      if (leftover.length > 0) stream.unshift(leftover);
      resolve();
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      stream.removeListener("data", onData);
      stream.removeListener("error", onError);
      clearTimeout(timer);
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timeout on CONNECT to ${authority}`));
    }, timeoutMs);

    stream.on("data", onData);
    stream.once("error", onError);
    stream.write(req);
  });
}

/**
 * Upgrade an existing duplex stream to TLS with the given servername.
 * Used both for the egress hop (if it terminates TLS) and for the final
 * end-to-end handshake to the destination.
 */
function tlsUpgrade(
  stream: net.Socket | tls.TLSSocket,
  servername: string,
  timeoutMs: number,
  extraOptions?: tls.ConnectionOptions,
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const secured = tls.connect({ socket: stream, servername, ...extraOptions }, () => {
      cleanup();
      resolve(secured);
    });
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      secured.removeListener("error", onError);
      clearTimeout(timer);
    };
    const timer = setTimeout(() => {
      cleanup();
      secured.destroy();
      reject(new Error(`timeout on TLS upgrade to ${servername}`));
    }, timeoutMs);
    secured.once("error", onError);
  });
}

/**
 * Build a `fetch`-shaped function whose HTTP requests reuse the supplied
 * already-tunneled TLS socket as their connection. No new outbound socket
 * is created; the Agent's `createConnection` hands back the tunnel socket
 * exactly once (Slice 1 serves a single request per tunnel, matching the
 * non-streaming-friendly v1.2 substrate clients; connection reuse across
 * requests is a later optimization).
 */
function makeTunnelBoundFetch(
  tunnelSocket: tls.TLSSocket,
  destination: TunnelDestination,
  timeoutMs: number,
): typeof fetch {
  let used = false;
  const agent = new http.Agent({ keepAlive: false, maxSockets: 1 });
  // Override createConnection to return the pre-established tunnel socket.
  (agent as unknown as { createConnection: () => net.Socket }).createConnection = () => {
    if (used) {
      throw new Error("tunnel socket already consumed (Slice 1 is single-request per tunnel)");
    }
    used = true;
    return tunnelSocket;
  };

  const boundFetch: typeof fetch = (input, init) =>
    fetchOverAgent(input, init, agent, destination, timeoutMs);
  return boundFetch;
}

/**
 * Minimal fetch implementation over a Node http.Agent that reuses the
 * tunnel socket. Returns a standard `Response` whose body is a
 * ReadableStream fed from the response stream, preserving token-by-token
 * streaming (AC-4).
 */
function fetchOverAgent(
  input: Parameters<typeof fetch>[0],
  init: Parameters<typeof fetch>[1],
  agent: http.Agent,
  destination: TunnelDestination,
  timeoutMs: number,
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const method =
      init?.method ??
      (typeof input !== "string" && !(input instanceof URL) ? (input as Request).method : "GET");
    const urlStr =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const url = new URL(urlStr);

    const headers = normalizeOutgoingHeaders(init?.headers as HeadersInitLike);
    // Ensure Host is present and points at the destination authority.
    if (!Object.keys(headers).some((h) => h.toLowerCase() === "host")) {
      headers["Host"] = formatAuthority(destination.host, destination.port);
    }

    const req = http.request({
      method,
      host: destination.host,
      port: destination.port,
      path: `${url.pathname}${url.search}`,
      headers,
      agent,
      // The socket is already TLS-terminated to the destination; treat the
      // request as plain HTTP over that secured tunnel.
      protocol: "http:",
      timeout: timeoutMs,
    });

    req.once("response", (res) => {
      const status = res.statusCode ?? 502;
      const responseHeaders = new Headers();
      for (const [k, v] of Object.entries(res.headers)) {
        if (v === undefined) continue;
        responseHeaders.set(k, Array.isArray(v) ? v.join(", ") : String(v));
      }
      // Stream the response body through a ReadableStream so streaming
      // survives the tunnel (AC-4).
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          res.on("data", (chunk: Buffer) => controller.enqueue(new Uint8Array(chunk)));
          res.on("end", () => {
            try {
              controller.close();
            } catch {
              /* already closed */
            }
          });
          res.on("error", (err) => controller.error(err));
        },
        cancel() {
          res.destroy();
        },
      });
      // 204/304 and HEAD have no body per the fetch spec.
      const nullBody = status === 204 || status === 304 || method === "HEAD";
      resolve(
        new Response(nullBody ? null : body, {
          status,
          statusText: res.statusMessage ?? "",
          headers: responseHeaders,
        }),
      );
    });

    req.once("error", (err) => reject(err));
    req.once("timeout", () => {
      req.destroy(new Error("tunnel request timeout"));
    });

    const bodyInit = init?.body;
    if (bodyInit !== undefined && bodyInit !== null) {
      if (typeof bodyInit === "string") req.write(bodyInit);
      else if (bodyInit instanceof Uint8Array) req.write(Buffer.from(bodyInit));
      else req.write(String(bodyInit));
    }
    req.end();
  });
}

type HeadersInitLike =
  | Record<string, string>
  | Array<[string, string]>
  | Headers
  | undefined;

function normalizeOutgoingHeaders(raw: HeadersInitLike): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  if (typeof Headers !== "undefined" && raw instanceof Headers) {
    raw.forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }
  if (Array.isArray(raw)) {
    for (const [k, v] of raw) {
      if (k !== undefined && v !== undefined) out[k] = v;
    }
    return out;
  }
  return { ...(raw as Record<string, string>) };
}

function formatAuthority(host: string, port: number): string {
  // Bracket IPv6 literals.
  if (host.includes(":") && !host.startsWith("[")) return `[${host}]:${port}`;
  return `${host}:${port}`;
}
