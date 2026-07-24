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
 * allow the gate to proxy after the anchor was silently flushed. Whether
 * concurrent requests share one in-flight probe is decided AT CONSTRUCTION
 * from the probe's self-declared `coalescing` discriminator (see
 * `singleFlightLiveness` on the options): a coalescing-safe (pfctl-backed)
 * probe is single-flight so the confined agent cannot amplify one traffic
 * burst into one pfctl subprocess tree per socket; a coalescing-forbidden
 * (oracle) probe runs per-CONNECT so no CONNECT can join a pre-flush
 * in-flight green. This is a construction guard, never a caller obligation.
 *
 * SUBPROCESS AMPLIFICATION IS BOUNDED (the confined agent is the adversary
 * on this socket and can open CONNECTs in a tight loop; each probe/lookup
 * spawns a child as the gate's NON-agent uid -- or, since the 2026-07-24 S5-3
 * TCB fix, dials the privileged peer-resolver daemon instead of spawning
 * locally, moving the actual subprocess cost to that root process, which
 * enforces its OWN independent concurrency cap
 * (`PEER_RESOLVER_MAX_CONCURRENT_LOOKUPS`, `peer-resolver-daemon.ts`) -- so
 * unbounded concurrency would let the agent degrade the enforcement host past
 * its own uid's process limits -- a confused-deputy resource amplification):
 *   - a coalescing-safe liveness probe is SINGLE-FLIGHT: concurrent
 *     requests share one in-flight probe instead of each spawning pfctl
 *     (this also bounds the not-live case, where the no-negative-caching
 *     rule would otherwise make every request pay its own probe);
 *   - peer lookups (both the legacy advisory path and the TCB path) are
 *     capped at PEER_LOOKUP_MAX_CONCURRENT in-flight calls to the injected
 *     `peerRunner`; at the cap the lookup is SKIPPED (peer_unresolved /
 *     skipped_cap) rather than queued, because queuing would just move the
 *     amplification into memory. Skipping is always safe in the legacy path
 *     (peer identity is advisory there); in TCB mode a skip is a genuine DENY
 *     (see `gate-client-auth.ts`), which the 2026-07-24 fix left UNCHANGED --
 *     it is now the rare case, not the common one (see that module's
 *     reconciled availability-bound comment).
 *
 * PEER IDENTITY (Slice 2) is advisory-only IN THE LEGACY PATH: a resolved peer
 * uid that is not the agent uid emits a loud `peer_uid_mismatch` event; it never
 * grants and never (alone) denies. The TOCTOU window is documented in
 * `peer-identity.ts`. In FAIL-CLOSED TCB MODE (Slice 5 S5-3, below), the same
 * lookup is a REQUIRED second lens instead: see `gate-client-auth.ts`.
 *
 * FAIL-CLOSED CLIENT AUTH (Slice 5 S5-3): when a `clientAuth` authenticator is
 * supplied the gate runs in TCB mode -- every CONNECT must present a current,
 * generation-bound bearer credential (`gate-credential.ts`) AND resolve to the
 * agent uid, or it is DENIED (403 + a `client_denied` audit event). Bearer never
 * overrides peer, and an unresolved/capped peer denies (fail-closed availability
 * bound, see `gate-client-auth.ts`). In TCB mode the gate's mandatory
 * `livenessProbe` MUST be the root-owned signed-freshness-token oracle probe
 * (`liveness-oracle.ts`) -- the constructor REFUSES any probe that does not
 * self-declare `coalescing: "forbidden"` AND a `binding` (fail-closed; a
 * subprocess-backed or unbound probe cannot give a TCB gate per-CONNECT,
 * principal-bound liveness): the non-root gate verifies liveness by checking a
 * signature, never by holding pf privilege.
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
import type {
  GateClientAuthenticator,
  GateClientDenyReason,
  GatePeerResolution,
} from "./gate-client-auth.js";

/** The loopback address the gate binds. Never configurable wider. */
export const GATE_BIND_HOST = "127.0.0.1";

/**
 * Recursively freeze a value in place (Codex/Family-A round-6). Used on a CLONE
 * of the caller's destination rules so the gate's captured rule set is a true
 * immutable snapshot: a caller cannot `push` a permissive rule into the array,
 * reorder it, or flip an existing rule's `disposition`/`match` AFTER
 * construction and thereby change what the gate enforces per CONNECT. Freezing a
 * clone (never the caller's own array) keeps the defensive-copy discipline the
 * frozen `policy` copy already established, without mutating caller state.
 */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value as Record<string, unknown>)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
    Object.freeze(value);
  }
  return value;
}

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
  /**
   * EXPLICIT coalescing discriminator (second-family fix-round on the
   * single-flight construction guard). The probe SELF-DECLARES whether its
   * `check()` may be coalesced under single-flight, instead of the gate
   * INFERRING oracle-ness from the presence of `binding` (the inference
   * conflated "principal-bound verdict" with "subprocess-free oracle": a
   * pfctl-backed probe that grows a binding for cross-principal safety must
   * NOT silently lose its single-flight amplification bound, and a hand-rolled
   * oracle-style probe that forgot its binding must NOT silently keep a
   * shared-green window):
   *   - `"forbidden"` -- the probe is subprocess-free and its verdict must be
   *     read PER-CONNECT (the signed-token oracle probe,
   *     `createOracleLivenessProbe`, always declares this). The constructor
   *     auto-disables single-flight and REFUSES `singleFlightLiveness: true`.
   *   - `"safe"` or omitted -- coalescing concurrent CONNECTs onto one
   *     in-flight `check()` is sound (the pfctl-backed legacy probe; omitted
   *     covers every pre-existing probe object). The single-flight default
   *     stays `true` regardless of whether the probe also declares `binding`.
   */
  readonly coalescing?: "safe" | "forbidden";
  /**
   * OPTIONAL self-declared binding (Slice 5 S5-3; Codex F3 fix-round). When a
   * probe advertises the `{ agentUid, gatePort }` its verdict is computed for
   * (the oracle probe does), the gate cross-checks it against `policy` at
   * construction and REFUSES to start if they disagree -- so a probe bound to a
   * DIFFERENT agent/port (a live token for gate A) can never be wired into gate
   * B and read as live here. Generation binding is out of the gate policy's
   * knowledge and stays the wiring layer's job (`evaluateGenerationMatch`,
   * S5-2). A probe that omits this (the legacy pf probe) is used as-is on a
   * non-TCB gate; a TCB gate (`clientAuth` present) REQUIRES it (see
   * {@link ExclusiveEgressGateOptions.clientAuth}).
   */
  readonly binding?: { agentUid: number; gatePort: number };
}

/** Events the gate emits for audit/posture wiring. */
export type EgressGateEvent =
  | { kind: "liveness_refused"; authority: string; reasons: string[] }
  | { kind: "peer_uid_mismatch"; authority: string; peerUid: number; peerPid: number; agentUid: number }
  | { kind: "peer_unresolved"; authority: string }
  | { kind: "client_denied"; authority: string; reason: GateClientDenyReason; peerUid?: number }
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
  /**
   * FAIL-CLOSED client authorization (Slice 5 S5-3). When present the gate is in
   * TCB mode: every CONNECT must present a current generation-bound bearer
   * credential AND resolve to the agent uid, or it is DENIED (`client_denied`,
   * 403) -- the advisory peer path below is NOT used. The gate resolves the peer
   * itself (capped, as in advisory mode) and feeds it to the authenticator, so
   * this REQUIRES a `peerRunner`; with none, every peer is unresolved and every
   * CONNECT denies (fail-closed). Omit for the legacy advisory behavior.
   *
   * TCB mode also CONSTRAINS the `livenessProbe`: the constructor REFUSES any
   * probe that does not self-declare `coalescing: "forbidden"` AND a `binding`
   * (i.e. anything but the oracle-probe shape, `createOracleLivenessProbe`).
   * A TCB gate wired to a subprocess-backed or unbound probe would either keep
   * a coalesced shared-green window or accept a cross-principal verdict, so it
   * fails loudly at construction instead.
   */
  clientAuth?: GateClientAuthenticator;
  /**
   * Whether concurrent CONNECTs share ONE in-flight liveness probe (Slice 5
   * S5-3; Codex F4 fix-round). Keyed off the probe's EXPLICIT
   * {@link GateLivenessProbe.coalescing} discriminator, never inferred. For a
   * coalescing-safe (or undeclared, i.e. legacy pfctl-backed) probe the
   * default is `true`, bounding pfctl subprocess amplification -- including a
   * future pfctl-backed probe that also declares a `binding`. For a
   * `coalescing: "forbidden"` probe (the subprocess-free oracle probe) the
   * CONSTRUCTOR enforces per-CONNECT liveness: omitting this option
   * auto-disables single-flight, and `true` is REFUSED at construction (a
   * shared in-flight green would let a CONNECT arriving after a flush read
   * stale liveness -- the post-flush shared-green window; there is no
   * amplification cost to lose). This is a construction guard, not a caller
   * obligation: the S5-6 wiring constructs with `createOracleLivenessProbe`
   * and simply omits this option.
   */
  singleFlightLiveness?: boolean;
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
  // CHOKEPOINT: CAPTURE EVERY CONSUMED DEPENDENCY AT CONSTRUCTION (Codex round-5).
  // The gate must never re-dereference the caller-owned `options` object at
  // runtime -- otherwise a caller mutating its own `options` after construction
  // (swapping `clientAuth`/`livenessProbe`/`rules`, or mutating `policy`) would
  // change what the gate ENFORCES while the construction guards already passed
  // against the original -- the advertised-vs-enforced divergence class, one
  // level up from the individual objects. Everything below (guards AND the
  // per-CONNECT handlers) reads these frozen/captured locals ONLY; `options` is
  // never touched again. `policy` is a FROZEN COPY (so even field mutation on the
  // caller's policy cannot change the gate); the authenticator and oracle probe
  // are themselves frozen at their factories, so capturing the reference is
  // sufficient for those.
  const policy = Object.freeze({
    agent_uid: options.policy.agent_uid,
    gate_port: options.policy.gate_port,
  });
  const clientAuth = options.clientAuth;
  const livenessProbe = options.livenessProbe;
  // BIND injected-op METHODS once at construction (Codex round-7). Runtime must
  // never re-read `obj.method` off a caller-held object, or a caller could
  // reassign `.check`/`.run`/`.resolve` after construction and flip enforcement
  // (503->200, fake a peer uid, redirect resolution). Binding captures the
  // method as it was at construction; a later property swap on the caller's
  // object cannot reach the gate. (What an injected method closes over is the
  // injector's own behavior -- the injector is trusted TCB by construction; this
  // closes the REASSIGNMENT vector, which is the accidental/aliasing one.)
  const probeCheck = livenessProbe.check.bind(livenessProbe);
  // Bind the authenticator's method too (uniform with the other injected ops),
  // so the discipline "runtime never re-reads obj.method" holds independently of
  // the factory freeze -- even a hand-rolled unfrozen authenticator cannot have
  // its `.authorize` swapped after construction.
  const clientAuthorize = clientAuth ? clientAuth.authorize.bind(clientAuth) : undefined;
  const boundPeerRunner: PeerCommandRunner | undefined = options.peerRunner
    ? Object.freeze({ run: options.peerRunner.run.bind(options.peerRunner) })
    : undefined;
  const boundResolver: EgressProxyResolver | undefined = options.resolver
    ? Object.freeze({ resolve: options.resolver.resolve.bind(options.resolver) })
    : undefined;
  // Destination rules are a DEEP-FROZEN CLONE (not the caller's array): a
  // post-construction in-place mutation (push a permissive rule, flip a
  // disposition, widen a match) cannot change what the gate enforces.
  const rules = deepFreeze(structuredClone(options.rules)) as AllowlistRule[];
  const isRoutable = options.isRoutable;
  const onEvent = options.onEvent;

  if (validateExclusiveEgressGatePolicy(policy) === null) {
    throw new Error("createExclusiveEgressGate: malformed exclusive-egress gate policy");
  }
  // FAIL-CLOSED SELF-CONSISTENCY GUARDS (Slice 5 S5-3; Codex F1 + F3 fix-round).
  // The gate is TCB; a mis-wired authenticator or liveness probe bound to a
  // DIFFERENT principal would let a valid-for-someone-else credential/liveness
  // read as green here. Refuse to construct rather than trust the injected
  // config blindly. These check the SAME captured locals the runtime enforces.
  //   F1: the client authenticator must be bound to THIS gate's agent uid, so a
  //       uid-501 authenticator can never be paired with a uid-502 policy and
  //       admit a uid-501 client.
  if (clientAuth && clientAuth.agentUid !== policy.agent_uid) {
    throw new Error(
      `createExclusiveEgressGate: clientAuth.agentUid (${clientAuth.agentUid}) must equal ` +
        `policy.agent_uid (${policy.agent_uid}); refusing to authorize one uid's clients against another's credential`,
    );
  }
  //   F3: a liveness probe that declares its binding must be bound to THIS
  //       gate's { agent_uid, gate_port }, so a live token for gate A cannot be
  //       wired into gate B and read as live. (Generation binding is not in the
  //       gate policy; it stays the wiring layer's job via evaluateGenerationMatch.)
  const probeBinding = livenessProbe.binding;
  if (
    probeBinding !== undefined &&
    (probeBinding.agentUid !== policy.agent_uid || probeBinding.gatePort !== policy.gate_port)
  ) {
    throw new Error(
      `createExclusiveEgressGate: livenessProbe.binding {agentUid:${probeBinding.agentUid}, gatePort:${probeBinding.gatePort}} ` +
        `must match policy {agent_uid:${policy.agent_uid}, gate_port:${policy.gate_port}}; refusing a cross-principal liveness verdict`,
    );
  }
  // TCB PROBE REQUIREMENT (second-family fix-round HIGH). A TCB gate
  // (`clientAuth` present) must run on the oracle-probe shape: a probe that
  // SELF-DECLARES `coalescing: "forbidden"` (per-CONNECT verdict, no coalesced
  // shared-green window) AND a `binding` (principal-bound verdict, cross-checked
  // above). Anything else -- a legacy pfctl probe, or an oracle-style probe that
  // forgot its marker or binding -- would give the TCB gate either a stale
  // shared-green window or an unbound liveness verdict; refuse to construct
  // rather than default into either.
  const probeCoalescing = livenessProbe.coalescing;
  if (clientAuth && (probeCoalescing !== "forbidden" || probeBinding === undefined)) {
    throw new Error(
      "createExclusiveEgressGate: TCB mode (clientAuth present) requires an oracle-shape liveness probe " +
        `that self-declares coalescing:"forbidden" AND a binding (use createOracleLivenessProbe); got ` +
        `coalescing:${probeCoalescing === undefined ? "undeclared" : JSON.stringify(probeCoalescing)}, ` +
        `binding:${probeBinding === undefined ? "undeclared" : "declared"}. A subprocess-backed or ` +
        "unbound probe cannot give a TCB gate per-CONNECT, principal-bound liveness; refusing to construct.",
    );
  }
  // Per-CONNECT liveness (Codex F4 fix-round; hardened to a CONSTRUCTION GUARD
  // pre-S5-6, then keyed off the EXPLICIT `coalescing` marker in the
  // second-family fix-round). Single-flight shares ONE in-flight probe across
  // concurrent CONNECTs to bound pfctl SUBPROCESS amplification -- correct for
  // the legacy pfctl probe. The oracle probe (S5-3) spawns no subprocess (a
  // file read + signature verify), so single-flight buys no amplification
  // protection there and can let a CONNECT that arrived strictly AFTER a flush
  // join an already-in-flight green read (the post-flush shared-green window).
  // That must not be a caller obligation: for a `coalescing: "forbidden"` probe
  // (the oracle probe always self-declares it; see createOracleLivenessProbe)
  // the constructor auto-disables single-flight when the option is omitted, and
  // REFUSES to construct when the caller explicitly asked for `true` --
  // honoring it silently would re-open the window. A coalescing-safe or
  // undeclared probe keeps the unchanged default `true` (the pfctl path and all
  // existing callers) EVEN IF it also declares a `binding`: binding means
  // "principal-bound verdict", not "subprocess-free", and a future pfctl-backed
  // probe that grows a binding must not silently lose its amplification bound.
  if (probeCoalescing === "forbidden" && options.singleFlightLiveness === true) {
    throw new Error(
      'createExclusiveEgressGate: singleFlightLiveness:true is incompatible with a coalescing:"forbidden" ' +
        "(oracle) liveness probe: a shared in-flight probe can hand a post-flush CONNECT a stale green " +
        "verdict, and the subprocess-free oracle probe gains no amplification protection from coalescing. " +
        "Omit singleFlightLiveness (auto-disabled) or pass false.",
    );
  }
  const singleFlight = probeCoalescing === "forbidden" ? false : (options.singleFlightLiveness ?? true);
  let inflightProbe: Promise<PfLivenessResult> | null = null;
  let activePeerLookups = 0;

  /**
   * Liveness probe wrapper. With single-flight (the default for
   * coalescing-safe/undeclared probes), concurrent requests in the same
   * decision window share ONE probe (one pfctl spawn set) instead of each
   * spawning their own; the shared variable is cleared when the probe settles
   * so no positive survives into a later request. Without single-flight
   * (forced at construction for `coalescing: "forbidden"` oracle probes;
   * opt-in via `singleFlightLiveness: false` otherwise) every CONNECT runs its
   * own probe (no shared in-flight verdict), which closes the post-flush
   * shared-green window for the subprocess-free oracle probe. Either way the
   * probe never rejects.
   */
  function probeLiveness(): Promise<PfLivenessResult> {
    if (!singleFlight) {
      return (async (): Promise<PfLivenessResult> => {
        try {
          return await probeCheck();
        } catch (err) {
          return {
            live: false,
            reasons: [`liveness probe threw: ${err instanceof Error ? err.message : String(err)}`],
          };
        }
      })();
    }
    if (inflightProbe === null) {
      const probe = (async (): Promise<PfLivenessResult> => {
        try {
          return await probeCheck();
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

  /**
   * Resolve the connecting loopback peer into a {@link GatePeerResolution} for
   * the fail-closed authenticator, applying the SAME subprocess-amplification
   * cap as the advisory path: at the cap the lookup is skipped
   * (`skipped_cap`), which the authenticator treats as a DENY (fail-closed),
   * never queued. A missing client port or a null lsof result is `unresolved`
   * (also a deny). With no `peerRunner` every peer is `unresolved`, so a TCB
   * gate with no peer runner denies every CONNECT (documented on the option).
   */
  async function resolvePeerForAuth(
    clientSocket: Duplex,
    peerRunner: PeerCommandRunner | undefined,
  ): Promise<GatePeerResolution> {
    if (peerRunner === undefined) {
      return { kind: "unresolved" };
    }
    const clientPort = (clientSocket as net.Socket).remotePort;
    if (typeof clientPort !== "number") {
      return { kind: "unresolved" };
    }
    if (activePeerLookups >= PEER_LOOKUP_MAX_CONCURRENT) {
      return { kind: "skipped_cap" };
    }
    activePeerLookups += 1;
    let peer: Awaited<ReturnType<typeof resolveLoopbackPeer>>;
    try {
      peer = await resolveLoopbackPeer({ clientPort, runner: peerRunner });
    } finally {
      activePeerLookups -= 1;
    }
    if (peer === null) {
      return { kind: "unresolved" };
    }
    return { kind: "resolved", uid: peer.uid, pid: peer.pid };
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
    onEvent?.({ kind: "gate_error", authority: "", message: err.message });
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
        onEvent?.({
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
      onEvent?.({ kind: "liveness_refused", authority, reasons: liveness.reasons });
      clientSocket.end(
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n",
      );
      return;
    }

    // 2. Client authorization. TWO modes:
    //   - TCB / FAIL-CLOSED (Slice 5 S5-3), when `clientAuth` is set: resolve
    //     the peer (capped) and require BOTH a current bearer credential AND a
    //     matching peer uid, or DENY (403 `client_denied`). Bearer never
    //     overrides peer; unresolved/skipped-at-cap peers deny.
    //   - ADVISORY (Slice 2, unchanged), when only `peerRunner` is set: a
    //     mismatch/unresolved is logged loudly but the request still proceeds.
    if (clientAuthorize) {
      const peer = await resolvePeerForAuth(clientSocket, boundPeerRunner);
      const decision = await clientAuthorize({
        credentialHeader: request.headers["proxy-authorization"],
        peer,
      });
      if (!decision.allow) {
        onEvent?.({
          kind: "client_denied",
          authority,
          reason: decision.reason,
          ...(decision.peerUid !== undefined ? { peerUid: decision.peerUid } : {}),
        });
        // Enforcement-as-teacher: a distinct header names the auth failure so a
        // misconfigured client is told the channel exists but rejected it.
        clientSocket.end(
          "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nX-Sanctuary-Gate: client-denied\r\n\r\n",
        );
        return;
      }
    } else if (boundPeerRunner) {
      // Advisory peer identity (never grants, never solely denies). Lookups are
      // capped: at the cap this request's lookup is skipped (surfaced as
      // peer_unresolved) instead of spawning another lsof.
      const socket = clientSocket as net.Socket;
      const clientPort = socket.remotePort;
      if (typeof clientPort === "number") {
        if (activePeerLookups >= PEER_LOOKUP_MAX_CONCURRENT) {
          onEvent?.({ kind: "peer_unresolved", authority });
        } else {
          activePeerLookups += 1;
          let peer: Awaited<ReturnType<typeof resolveLoopbackPeer>>;
          try {
            peer = await resolveLoopbackPeer({
              clientPort,
              runner: boundPeerRunner,
            });
          } finally {
            activePeerLookups -= 1;
          }
          if (peer === null) {
            onEvent?.({ kind: "peer_unresolved", authority });
          } else if (peer.uid !== policy.agent_uid) {
            onEvent?.({
              kind: "peer_uid_mismatch",
              authority,
              peerUid: peer.uid,
              peerPid: peer.pid,
              agentUid: policy.agent_uid,
            });
          }
        }
      }
    }

    // 3. Destination policy: the shared TS evaluator (Swift-parity logic).
    const evaluatorOptions: EgressProxyOptions = {
      rules: rules,
      ...(boundResolver ? { resolver: boundResolver } : {}),
      ...(isRoutable ? { isRoutable } : {}),
    };
    const decision = await decideEgressProxyConnect(authority, evaluatorOptions);
    onEvent?.({ kind: "decision", authority, decision });
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
  // Snapshot the bind port once (consistent with the per-CONNECT chokepoint) so
  // a caller mutating options.policy after construction cannot change where the
  // gate binds vs what it was validated/constructed for.
  const gatePort = options.policy.gate_port;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(gatePort, GATE_BIND_HOST, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : gatePort;
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
