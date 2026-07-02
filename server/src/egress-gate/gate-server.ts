/**
 * The exclusive-egress policy gate: a pinned loopback-TCP CONNECT gate
 * (Unified Protect Slice 1).
 *
 * GREENFIELD (design HIGH-2): this is NOT `server/src/proxy/` (the MCP-tool
 * proxy), NOT `castle-wall/egress-proxy.ts` (the VM/vsock-coupled
 * CONNECT evaluator), and NOT `policy-engine/egress-gate.ts` (the
 * compiled-policy per-agent egress allowlist gate, `evaluateEgressGate`,
 * which shares this module's name but runs inside the policy engine's gate
 * hierarchy). It is the local policy gate the confined agent talks
 * to: the agent's off-box egress is denied at the kernel (proven per-uid
 * floor), its loopback reach is confined to this gate's port by the pf
 * anchor (Slice 3), and this gate applies per-action destination policy and
 * then makes the real off-box request as the gate process's own
 * (non-agent) uid.
 *
 * The DECISION LOGIC is reused, not re-invented: destination policy is
 * `decideEgressProxyConnect` from `castle-wall/egress-proxy.ts`, the TS
 * evaluator that must agree with the Swift `AllowlistEvaluator` (parity
 * invariant asserted in that module's tests).
 *
 * FAIL-CLOSED LIVENESS (MANDATORY, Slice 3 requirement): before ANY
 * tunneling, the gate consults the injected liveness probe (production:
 * `checkPfAnchorLiveness`). If the pf anchor is absent, unloaded, or the
 * probe errors, the gate REFUSES to proxy (503) and emits a
 * `liveness_refused` event so posture surfaces report not-protected. A
 * positive result is NEVER cached across requests: a stale positive would
 * allow the gate to proxy after the anchor was silently flushed. Concurrent
 * requests still share one in-flight probe, so the confined agent cannot
 * amplify one traffic burst into one pfctl subprocess tree per socket.
 *
 * SUBPROCESS AMPLIFICATION IS BOUNDED (the confined agent is the adversary
 * on this socket and can open CONNECTs in a tight loop; each probe/lookup
 * spawns a child as the gate's NON-agent uid, so unbounded concurrency
 * would let the agent degrade the enforcement host past its own uid's
 * process limits -- a confused-deputy resource amplification):
 *   - the liveness probe is SINGLE-FLIGHT: concurrent requests share one
 *     in-flight probe instead of each spawning pfctl (this also bounds the
 *     not-live case, where the no-negative-caching rule would otherwise
 *     make every request pay its own probe);
 *   - advisory peer lookups are capped at PEER_LOOKUP_MAX_CONCURRENT;
 *     at the cap the lookup is SKIPPED (peer_unresolved) rather than
 *     queued, because queuing would just move the amplification into
 *     memory. Skipping is safe precisely because peer identity is
 *     advisory-only and never gates the decision.
 *
 * PEER IDENTITY (Slice 2) is advisory-only: a resolved peer uid that is not
 * the agent uid emits a loud `peer_uid_mismatch` event; it never grants and
 * never (alone) denies. The TOCTOU window is documented in
 * `peer-identity.ts`.
 *
 * HONESTY BOUNDS: routing is kernel-enforced; destination policy here is
 * userspace-enforced (this process); loopback confinement is pf-enforced,
 * drill-proven on Tahoe only. Drill acceptance for the composed gate is
 * PENDING. Multiplexed egress over an already-authorized channel is seen
 * and audited upstream, not selectively blocked here.
 */

import http from "node:http";
import net from "node:net";
import type { Duplex } from "node:stream";

import {
  decideEgressProxyConnect,
  type EgressProxyDecision,
  type EgressProxyOptions,
  type EgressProxyResolver,
} from "../castle-wall/egress-proxy.js";
import type { AllowlistRule } from "../castle-wall/allowlist/schema.js";
import {
  validateExclusiveEgressGatePolicy,
  type ExclusiveEgressGatePolicy,
} from "../castle-wall/allowlist/gate-derivation.js";
import type { PfLivenessResult } from "./pf-anchor.js";
import { resolveLoopbackPeer, type PeerCommandRunner } from "./peer-identity.js";

/** The loopback address the gate binds. Never configurable wider. */
export const GATE_BIND_HOST = "127.0.0.1";

/**
 * Hard cap on concurrent advisory peer lookups (each spawns one lsof as the
 * gate's non-agent uid). At the cap a lookup is skipped, not queued: peer
 * identity is advisory-only, so skipping loses a second-lens audit signal
 * for that request while denying the agent a subprocess-amplification lever.
 */
export const PEER_LOOKUP_MAX_CONCURRENT = 4;

/** A liveness probe the gate consults before proxying (fail-closed). */
export interface GateLivenessProbe {
  check(): Promise<PfLivenessResult>;
}

/** Events the gate emits for audit/posture wiring. */
export type EgressGateEvent =
  | { kind: "liveness_refused"; authority: string; reasons: string[] }
  | { kind: "peer_uid_mismatch"; authority: string; peerUid: number; peerPid: number; agentUid: number }
  | { kind: "peer_unresolved"; authority: string }
  | { kind: "decision"; authority: string; decision: EgressProxyDecision }
  | { kind: "gate_error"; authority: string; message: string };

/** Options for {@link createExclusiveEgressGate}. */
export interface ExclusiveEgressGateOptions {
  /** The single-source gate policy (agent uid + gate port). */
  policy: ExclusiveEgressGatePolicy;
  /** Destination rules the gate enforces per CONNECT. */
  rules: AllowlistRule[];
  /**
   * MANDATORY fail-closed liveness probe. Production callers wire
   * `checkPfAnchorLiveness` via a `PfCommandRunner`; there is deliberately
   * no default that answers "live".
   */
  livenessProbe: GateLivenessProbe;
  /** Advisory peer-identity runner; omit to skip peer resolution. */
  peerRunner?: PeerCommandRunner;
  /** Event sink for audit/posture wiring. */
  onEvent?: (event: EgressGateEvent) => void;
  /** Pass-through to the destination evaluator (tests). */
  resolver?: EgressProxyResolver;
  isRoutable?: (address: string) => boolean;
}

/** A running gate handle. */
export interface ExclusiveEgressGateHandle {
  server: http.Server;
  /** The bound port (=== policy.gate_port). */
  port: number;
  close(): Promise<void>;
}

/**
 * Create the gate's HTTP server (CONNECT handler installed, not yet
 * listening). Exposed separately from {@link startExclusiveEgressGate} so
 * tests can drive it on an ephemeral port.
 */
export function createExclusiveEgressGate(options: ExclusiveEgressGateOptions): http.Server {
  if (validateExclusiveEgressGatePolicy(options.policy) === null) {
    throw new Error("createExclusiveEgressGate: malformed exclusive-egress gate policy");
  }
  let inflightProbe: Promise<PfLivenessResult> | null = null;
  let activePeerLookups = 0;

  /**
   * Single-flight, never-rejecting liveness probe: concurrent requests in
   * the same decision window share ONE probe (one pfctl spawn set) instead
   * of each spawning their own. The shared variable is cleared when the
   * probe settles so the no-negative-caching contract holds: the next
   * request AFTER a failure starts a fresh probe.
   */
  function probeLiveness(): Promise<PfLivenessResult> {
    if (inflightProbe === null) {
      const probe = (async (): Promise<PfLivenessResult> => {
        try {
          return await options.livenessProbe.check();
        } catch (err) {
          return {
            live: false,
            reasons: [`liveness probe threw: ${err instanceof Error ? err.message : String(err)}`],
          };
        }
      })();
      inflightProbe = probe;
      void probe.finally(() => {
        if (inflightProbe === probe) {
          inflightProbe = null;
        }
      });
    }
    return inflightProbe;
  }

  const server = http.createServer((_request, response) => {
    // The gate speaks CONNECT only; plain requests get a terse 405 that
    // names the sanctioned path (enforcement-as-teacher, design Section 5).
    response.statusCode = 405;
    response.setHeader("Allow", "CONNECT");
    response.end("Sanctuary egress gate: use HTTP CONNECT via your configured proxy.");
  });

  server.on("error", (err) => {
    // Accept-time server errors (canonically EMFILE under FD exhaustion,
    // which the confined agent can drive by opening unbounded concurrent
    // tunnels) must not crash the gate: an 'error' event with no listener
    // throws -> uncaughtException -> the agent kills its own enforcement
    // gate. Deny-direction: the affected accept is lost; the gate keeps
    // serving. Listen-time bind failures are still surfaced to callers by
    // the one-shot reject listener in startExclusiveEgressGate.
    options.onEvent?.({ kind: "gate_error", authority: "", message: err.message });
  });

  server.on("connect", (request, clientSocket, head) => {
    handleGateConnect(request, clientSocket, head).catch((err: unknown) => {
      // Defense-in-depth backstop (deny-direction): no rejection out of the
      // decision path may escape as an unhandledRejection, because Node's
      // default handler would kill the whole gate process -- letting the
      // agent kill its own enforcement gate. `decideEgressProxyConnect` is
      // contract-bound never to reject; this catches any future edit that
      // breaks that contract.
      try {
        options.onEvent?.({
          kind: "gate_error",
          authority: request.url ?? "",
          message: err instanceof Error ? err.message : String(err),
        });
        if (!clientSocket.destroyed) {
          clientSocket.end("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n");
        }
      } catch {
        // The backstop itself must never throw.
      }
    });
  });

  async function handleGateConnect(
    request: http.IncomingMessage,
    clientSocket: Duplex,
    head: Buffer,
  ): Promise<void> {
    const authority = request.url ?? "";

    // 0. Swallow client-socket errors BEFORE the first await. The confined
    // agent is the party on this socket and can reset the connection at any
    // point during the async decision window below (liveness probe, peer
    // resolution, destination policy); a listener-less 'error' event would
    // crash the whole gate process (uncaughtException), letting the agent
    // kill its own enforcement gate at will. The handler also tears down
    // the upstream leg once one exists.
    let upstream: net.Socket | null = null;
    clientSocket.on("error", () => {
      upstream?.destroy();
    });

    // 1. MANDATORY fail-closed liveness gate. Every request requires fresh
    // positive evidence; concurrent requests share one in-flight probe (see
    // probeLiveness), but no positive verdict survives into a later request.
    const liveness = await probeLiveness();
    if (!liveness.live) {
      options.onEvent?.({ kind: "liveness_refused", authority, reasons: liveness.reasons });
      clientSocket.end(
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n",
      );
      return;
    }

    // 2. Advisory peer identity (never grants, never solely denies).
    // Lookups are capped: at the cap this request's lookup is skipped
    // (surfaced as peer_unresolved) instead of spawning another lsof.
    if (options.peerRunner) {
      const socket = clientSocket as net.Socket;
      const clientPort = socket.remotePort;
      if (typeof clientPort === "number") {
        if (activePeerLookups >= PEER_LOOKUP_MAX_CONCURRENT) {
          options.onEvent?.({ kind: "peer_unresolved", authority });
        } else {
          activePeerLookups += 1;
          let peer: Awaited<ReturnType<typeof resolveLoopbackPeer>>;
          try {
            peer = await resolveLoopbackPeer({
              clientPort,
              runner: options.peerRunner,
            });
          } finally {
            activePeerLookups -= 1;
          }
          if (peer === null) {
            options.onEvent?.({ kind: "peer_unresolved", authority });
          } else if (peer.uid !== options.policy.agent_uid) {
            options.onEvent?.({
              kind: "peer_uid_mismatch",
              authority,
              peerUid: peer.uid,
              peerPid: peer.pid,
              agentUid: options.policy.agent_uid,
            });
          }
        }
      }
    }

    // 3. Destination policy: the shared TS evaluator (Swift-parity logic).
    const evaluatorOptions: EgressProxyOptions = {
      rules: options.rules,
      ...(options.resolver ? { resolver: options.resolver } : {}),
      ...(options.isRoutable ? { isRoutable: options.isRoutable } : {}),
    };
    const decision = await decideEgressProxyConnect(authority, evaluatorOptions);
    options.onEvent?.({ kind: "decision", authority, decision });
    if (decision.disposition === "deny") {
      // Enforcement-as-teacher: the denial names the sanctioned route.
      clientSocket.end(
        "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nX-Sanctuary-Gate: denied-by-policy\r\n\r\n",
      );
      return;
    }

    // The client may have reset during the async window above; don't dial
    // the upstream for a dead client leg.
    if (clientSocket.destroyed) {
      return;
    }
    const upstreamSocket = net.connect({ host: decision.address, port: decision.target.port });
    upstream = upstreamSocket;
    let established = false;
    upstreamSocket.once("connect", () => {
      established = true;
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) {
        upstreamSocket.write(head);
      }
      upstreamSocket.pipe(clientSocket);
      clientSocket.pipe(upstreamSocket);
    });
    upstreamSocket.once("error", () => {
      // Pre-establishment: report a clean 502. Post-establishment the
      // client treats the stream as raw tunneled bytes (e.g. mid-TLS);
      // injecting an HTTP status line would be in-band garbage, so just
      // drop the client leg.
      if (established) {
        clientSocket.destroy();
      } else {
        clientSocket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
      }
    });
  }

  return server;
}

/**
 * Start the gate listening on `127.0.0.1:<policy.gate_port>` (loopback
 * pinned; the gate is never reachable off-box by construction).
 */
export async function startExclusiveEgressGate(
  options: ExclusiveEgressGateOptions,
): Promise<ExclusiveEgressGateHandle> {
  const server = createExclusiveEgressGate(options);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.policy.gate_port, GATE_BIND_HOST, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : options.policy.gate_port;
  return {
    server,
    port,
    close(): Promise<void> {
      return new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
