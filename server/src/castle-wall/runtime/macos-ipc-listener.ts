/**
 * Castle Wall macOS IPC listener (Sanctuary main side).
 *
 * The macOS topology is INVERTED relative to Linux: on macOS the system
 * extension is the IPC client and Sanctuary main hosts the listener
 * (per the comments in CastleWallIPC.IPCClient - "main hosts the UDS
 * listener at a path the extension resolves via SocketPath.resolve").
 * This module is the listener that binds the UDS path, accepts extension
 * connections, sends the handshake challenge, and routes inbound
 * post-handshake messages into `MacOSFlowEventConsumer`.
 *
 * Scope (Phase 2 / Alpha-3):
 *
 *  - bind() + accept() - `net.createServer` on a Unix domain socket at
 *    the resolved Castle Wall path.
 *  - Outbound `handshake_challenge` on every new connection. Phase 2
 *    sends the raw nonce envelope and, when configured with a handshake
 *    signer, immediately follows with a signed `handshake_response`.
 *    The Swift client does not trust post-handshake frames until that
 *    response verifies against the pinned public key.
 *  - Inbound frame routing - manifest_subscribe / flow_decision_recorded
 *    / flow_pending_approval dispatch to the existing
 *    `MacOSFlowEventConsumer` handlers.
 *  - Subscriber registration - extension-origin connections register as
 *    `MacOSSubscriber`s once they send extension traffic. Local admin query
 *    clients never enter the extension availability pool.
 *
 * Out of scope (deferred to follow-up):
 *
 *  - decision_response operator-resume envelope on the server-to-extension
 *    direction (gates on uncertain-flow `resumeFlow(_:with:)` wiring in
 *    Alpha-4 install scope).
 *  - SO_PEERCRED-style peer authorization. macOS UDS sockets do support
 *    `getpeereid`, but the pinned-public-key handshake is the canonical
 *    authn surface on macOS; peer-uid checks come with the install flow.
 *
 * Castle-walking: the listener is observation-side + manifest-publish
 * surface. A misbehaving listener cannot bypass kernel-level enforcement
 * because the kernel-level decision is owned by the NEFilterDataProvider
 * inside the extension; the listener is the application-layer
 * coordinator that feeds it manifests and consumes its telemetry.
 */

import { createServer, type Server, type Socket } from "node:net";
import { unlink, chmod, lchown, lstat } from "node:fs/promises";
import { randomBytes } from "node:crypto";

import { CASTLE_WALL_IPC_NAMESPACE } from "../constants.js";
import { frame, parseFrame } from "../ipc/framing.js";
import { canonicalize } from "../../mesh/canonical-json.js";
import type {
  AuditEmitNotification,
  CastleWallMessage,
  EnforcementAvailabilityReportNotification,
  EnforcementAvailabilityRequest,
  FlowDecisionRecordedNotification,
  HandshakeResponse,
  FlowPendingApprovalNotification,
  ManifestSubscribeRequest,
  ManifestUpdatedNotification,
  PolicyReloadRequest,
  PolicyReloadResponse,
  DecisionResponse,
  ArmLeaseNotification,
} from "../ipc/messages.js";
import type { MacOSFlowEventConsumer } from "./macos-flow-events.js";

function sanitizeLogValue(value: string): string {
  let sanitized = "";
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    if (!((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f))) {
      sanitized += ch;
      continue;
    }
    switch (ch) {
      case "\n":
        sanitized += "\\n";
        break;
      case "\r":
        sanitized += "\\r";
        break;
      case "\t":
        sanitized += "\\t";
        break;
      default:
        sanitized += `\\x${code.toString(16).padStart(2, "0")}`;
    }
  }
  return sanitized;
}

/** Wire envelope shape. Mirrors `wrapEnvelope` in `ipc-client.ts`. */
interface JsonRpcEnvelope {
  jsonrpc: "2.0";
  method: string;
  params: CastleWallMessage;
}

/** Configuration knobs for the listener. */
export interface MacOSFlowIpcListenerOptions {
  /**
   * Filesystem path of the UDS socket. Resolved via
   * `resolveCastleWallSocketPath` by the caller.
   */
  socketPath: string;
  /** Consumer that handles dispatched inbound messages. */
  consumer: MacOSFlowEventConsumer;
  /**
   * File mode for the bound socket. Default 0o600 (owner-only) so a
   * fortress's UDS socket is not readable by other local users. The
   * macOS extension runs as the operator user so 0o600 is correct;
   * multi-user fortresses are out of scope for v1.x.
   */
  socketMode?: number;
  /**
   * Re-own the bound socket to this uid after binding (F1 #450 item 3). The
   * safe-mode BOOT daemon runs as ROOT, so it creates a root-owned socket the
   * operator CLI (notably the dead-man `disable` lever) cannot connect to:
   * EPERM on a 0600 root socket as a non-root uid. Set this to the operator
   * (fortress owner) uid so the operator owns the socket while mode stays 0600:
   * root (the daemon + a root-running extension) still reaches it via superuser
   * bypass, and no other local user can. Undefined (the full operator daemon,
   * already operator-owned) leaves ownership untouched. Best-effort: a failed
   * chown warns but does not abort startup (the socket stays secure root:0600
   * and the GUI dead-man toggle remains the backstop; aborting would drop to a
   * worse daemon-less brick).
   */
  socketOwnerUid?: number;
  /**
   * Maximum number of concurrent extension connections. Default 8.
   * Production deployments expect exactly one (the single loaded
   * system-extension); the higher cap lets local dev runs co-host a
   * test harness alongside a real extension.
   */
  maxConnections?: number;
  /**
   * Override for `randomBytes`; tests inject deterministic nonces for
   * golden-vector assertions.
   */
  generateNonce?: () => Uint8Array;
  /** Signs the connection nonce so the extension can authenticate main. */
  handshakeSigner?: MacOSHandshakeSigner;
  /**
   * Signs every emitted `arm_lease` frame (O-02). When configured, an emitted
   * lease ALWAYS carries a fortress-key signature and a fresh `updated_at`
   * stamp; a signing failure DROPS the emission (never an unsigned fallback —
   * MUST-NEVER #5). When absent (legacy/dev harnesses), frames go out unsigned
   * and a current extension rejects them fail-closed on its side.
   */
  leaseSigner?: MacOSLeaseSigner;
  /** Optional local-admin command handler used by the CLI verbs. */
  adminHandler?: MacOSFlowIpcAdminHandler;
  /** Called before an inbound operator revoke is broadcast to subscribers. */
  onArmLeaseRevoke?: (lease: ArmLeaseNotification) => void | Promise<void>;
  /**
   * Called before an inbound NON-revoke operator arm-lease is broadcast to
   * subscribers, so the daemon can ADOPT the operator's dead-man TTL. Without
   * this, the daemon's periodic no-TTL heartbeat re-broadcast erases the
   * operator's `--ttl` deadline in the extension every heartbeat interval, so
   * the dead-man `ttl_expired` fail-open never fires (the 2026-07-05 Mini1
   * TTL-expiry drill gap: armed `--ttl 90s`, still enforcing at t+160s).
   */
  onArmLease?: (lease: ArmLeaseNotification) => void | Promise<void>;
}

export interface MacOSHandshakeSigner {
  fortressId: string;
  signingKeyId: string;
  /**
   * Sign the handshake nonce. May be async: under B2 the daemon delegates this
   * to the root helper over the XPC shim, so the signature arrives a tick later.
   * A synchronous (local dev) signer is still supported and emits the response
   * inline (preserving prior timing for existing tests).
   */
  signNonce(nonce: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface MacOSLeaseSigner {
  /** Recorded in the frame's `signing_key_id`; audit-facing, not authority. */
  signingKeyId: string;
  /**
   * Sign the canonical arm-lease body bytes with the fortress Ed25519 key
   * (the same key the extension pins for the handshake and the manifest).
   * May be async (root-helper XPC path) or sync (local dev path).
   *
   * LIVENESS CONTRACT: the lease-emission chain (`leaseEmitChain`) applies no
   * deadline of its own — every implementation MUST settle (resolve or reject)
   * every call, or the chain wedges and the extension's dead-man fires. The
   * production implementation satisfies this via the shim's per-invocation
   * SIGKILL timeout (must match `DEFAULT_TIMEOUT_MS` in `helper-signer.ts`,
   * 10s today); that timeout is the ONLY deadline bounding a chain link.
   */
  signLeaseBody(canonicalBytes: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/**
 * Bounds applied to the numeric lease fields at the signing chokepoint
 * (`signArmLease`). The extension decodes both fields as Swift `UInt32` and
 * computes the dead-man deadline as `heartbeatIntervalSeconds * 2` IN UInt32
 * (`ArmLease.swift`), so an out-of-range value either fails the whole-frame
 * decode (lease starved, dead-man fires for a config error) or traps the
 * extension process on overflow. Clamping here keeps the wall live under a
 * bogus producer value while the stderr warning surfaces the defect; the
 * signature is computed over the CLAMPED body, so wire and signature agree.
 */
/**
 * 1: an interval of 0 would put the extension's heartbeat deadline at "now",
 * i.e. an instant `heartbeat_stopped` degrade on every accepted lease.
 */
const HEARTBEAT_INTERVAL_MIN_SECONDS = 1;
/**
 * 3600: dead-man detection latency is 2x the interval (the extension's
 * `interval * 2` deadline), so one hour already means a two-hour dead-man;
 * anything longer defeats the dead-man's purpose. Also keeps the Swift UInt32
 * multiply far from its trap point (3600 * 2 = 7200 << 2^32 - 1; the trap
 * begins at interval >= 2^31).
 */
const HEARTBEAT_INTERVAL_MAX_SECONDS = 3600;
/**
 * 31_536_000 = 365 * 86_400 (one year). Must fit Swift's UInt32 decode
 * (2^32 - 1 seconds is ~136 years; a larger wire value rejects the whole
 * frame), and a year bounds an accidental or hostile decades-long arm window.
 */
const TTL_MAX_SECONDS = 31_536_000;

/**
 * Clamp to an integer in [min, max]. `Math.floor` because the Swift side
 * decodes UInt32: a fractional wire value fails the frame decode (fail closed
 * but lease-starving) and would also break canonical-body parity. The
 * non-finite guard is defensive against a programmatic caller only — parsed
 * JSON cannot carry NaN/Infinity.
 */
function clampLeaseInt(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

/**
 * Canonical SIGNED BODY of an arm lease: exactly these six fields, always all
 * present (`revoked` explicit even when false, `ttl_seconds` explicit null when
 * absent), serialized via `canonicalize` (sorted keys, no whitespace). The
 * normalization exists because the wire frame legitimately omits
 * `revoked`/`ttl_seconds` and may carry extra diagnostic fields (the CLI's
 * `source`); the signature must bind every field the extension CONSUMES and
 * nothing whose presence varies by producer.
 *
 * Must match `canonicalSignedBody` in
 * `castle-wall-macos/Sources/CastleWallFilter/SignedArmLeaseVerification.swift`
 * byte-for-byte: a divergence surfaces as the extension rejecting every lease
 * (fail closed, wall degrades to missing-lease posture), never as a silent
 * acceptance.
 */
export function armLeaseSignedBody(lease: ArmLeaseNotification): Record<string, unknown> {
  return {
    // `type` doubles as a domain-separation tag: the fortress key also signs
    // manifest bodies and handshake nonces, and no other signed payload can
    // contain `"type":"arm_lease"` as a top-level canonical field.
    type: "arm_lease",
    armed: lease.armed,
    revoked: lease.revoked === true,
    ttl_seconds: lease.ttl_seconds ?? null,
    heartbeat_interval_seconds: lease.heartbeat_interval_seconds,
    updated_at: lease.updated_at,
  };
}

export interface MacOSFlowIpcAdminHandler {
  reloadPolicy(request: PolicyReloadRequest): Promise<PolicyReloadResponse>;
  handleDecision(response: DecisionResponse): Promise<{ ok: boolean; error?: string }>;
}

/** Per-connection bookkeeping. */
interface ConnectionState {
  /** Stable per-connection id used by the consumer's subscriber map. */
  subscriberId: string;
  /** The underlying socket. */
  socket: Socket;
  /** Inbound byte accumulator for LSP framing. */
  inbound: Uint8Array;
  /**
   * True once the connection has been registered with the consumer
   * as an extension subscriber. Admin-only connections stay unregistered.
   */
  registered: boolean;
}

/**
 * Snapshot of listener counters, surfaced for observability + tests.
 */
export interface MacOSFlowIpcListenerStats {
  /** Connections currently held open. */
  activeConnections: number;
  /** Inbound frames decoded successfully across the lifetime. */
  framesDecoded: number;
  /** Frames the listener rejected as malformed envelopes. */
  framesRejected: number;
  /** Handshake challenges sent across the lifetime. */
  handshakesSent: number;
  /** Subscriber connections recycled by daemon-side recovery watchdogs. */
  connectionsRecycled: number;
  /** Listening state (true once bind has completed). */
  isListening: boolean;
}

/**
 * UDS listener serving macOS NEFilterDataProvider clients. Public methods:
 *
 *  - `start()` - bind the UDS socket; resolves once the socket is ready
 *    to accept connections.
 *  - `stop()` - close every active connection and unlink the socket path.
 *  - `broadcastManifestUpdate()` - fans the current manifest snapshot to
 *    every registered subscriber via the consumer's broadcast path.
 *  - `recycleConnection()` - drops one registered IPC connection so the
 *    extension re-enters the known-good reconnect + resubscribe path.
 *  - `getStats()` - observability counters.
 *
 * Lifecycle invariants:
 *
 *  - Sockets that disconnect before handshake-complete are dropped
 *    without ever registering as subscribers (so a transport blip cannot
 *    leak subscribers into the consumer map).
 *  - Re-binding cleans up any stale socket file at the configured path
 *    (mirrors the Linux daemon's bind behavior). The cleanup is
 *    fail-soft: a missing-path error on unlink is ignored; any other
 *    error rejects `start()`.
 *  - Per-connection sends are best-effort and do NOT throw to the
 *    caller. A broken downstream pipe surfaces as a connection
 *    `error` event; the listener tears down the connection and
 *    continues serving the rest.
 */
export class MacOSFlowIpcListener {
  private readonly socketPath: string;
  private readonly consumer: MacOSFlowEventConsumer;
  private readonly socketMode: number;
  private readonly socketOwnerUid: number | undefined;
  private readonly maxConnections: number;
  private readonly generateNonce: () => Uint8Array;
  private readonly handshakeSigner: MacOSHandshakeSigner | null;
  private readonly leaseSigner: MacOSLeaseSigner | null;
  private readonly adminHandler: MacOSFlowIpcAdminHandler | null;
  private readonly onArmLeaseRevoke: ((lease: ArmLeaseNotification) => void | Promise<void>) | null;
  private readonly onArmLease: ((lease: ArmLeaseNotification) => void | Promise<void>) | null;
  private currentArmLease: ArmLeaseNotification | null = null;
  /**
   * Last `updated_at` epoch-ms this listener stamped into a signed lease. The
   * extension enforces STRICT monotonicity per connection, and
   * `Date.now()` has only millisecond resolution, so two emissions inside the
   * same millisecond (e.g. an operator arm relay immediately followed by a
   * heartbeat) would otherwise produce an equal stamp the extension rejects
   * as a replay. Bumping to last+1ms keeps every emitted stamp unique and
   * ordered without waiting.
   */
  private lastLeaseStampMs = 0;
  /**
   * Tail of the serialized lease-emission chain (see `broadcastArmLease`).
   * Always settles; rejections are absorbed so one failed emission cannot
   * wedge every later one.
   *
   * BOUND (rule 12): the chain must not grow with heartbeat enqueue rate. A
   * slow signer (worst case one shim SIGKILL timeout per link, see the
   * `MacOSLeaseSigner` liveness contract) drains slower than the 5s heartbeat
   * cadence enqueues, so without coalescing the chain grows without limit and
   * every emission falls further behind the live arm state. Coalescing caps
   * the heartbeat contribution at TWO links — one in-flight signing plus one
   * pending slot that later heartbeats overwrite in place — so total depth is
   * bounded by 2 + (discrete operator emissions) + (subscribe resends, one
   * per connection, `maxConnections`-capped), each a bounded external event.
   */
  private leaseEmitChain: Promise<void> = Promise.resolve();
  /**
   * The single pending coalescible-heartbeat slot. A queued-but-not-started
   * heartbeat link reads `slot.lease` when it runs, so a newer heartbeat
   * REPLACES the payload in place instead of appending a link (only the
   * latest arm state matters; a superseded heartbeat is dead weight the
   * extension would accept and immediately have overwritten). Cleared when
   * the link starts running, and SEALED (nulled) by every non-coalescible
   * emission so a heartbeat enqueued after an operator arm/revoke can never
   * emit at a chain position before it (call order = emit order holds).
   */
  private pendingHeartbeatSlot: {
    lease: ArmLeaseNotification;
    run: Promise<number>;
  } | null = null;
  private server: Server | null = null;
  private connections = new Map<string, ConnectionState>();
  private stats: MacOSFlowIpcListenerStats = {
    activeConnections: 0,
    framesDecoded: 0,
    framesRejected: 0,
    handshakesSent: 0,
    connectionsRecycled: 0,
    isListening: false,
  };

  constructor(opts: MacOSFlowIpcListenerOptions) {
    this.socketPath = opts.socketPath;
    this.consumer = opts.consumer;
    this.socketMode = opts.socketMode ?? 0o600;
    this.socketOwnerUid = opts.socketOwnerUid;
    this.maxConnections = opts.maxConnections ?? 8;
    this.generateNonce = opts.generateNonce ?? defaultNonceBytes;
    this.handshakeSigner = opts.handshakeSigner ?? null;
    this.leaseSigner = opts.leaseSigner ?? null;
    this.adminHandler = opts.adminHandler ?? null;
    this.onArmLeaseRevoke = opts.onArmLeaseRevoke ?? null;
    this.onArmLease = opts.onArmLease ?? null;
  }

  /** Bind the UDS socket and start accepting connections. */
  async start(): Promise<void> {
    if (this.server) {
      throw new Error("MacOSFlowIpcListener already started");
    }
    await this.unlinkStaleSocket();
    return await new Promise((resolve, reject) => {
      const server = createServer((socket) => this.handleConnection(socket));
      server.maxConnections = this.maxConnections;
      const onError = (err: Error): void => {
        server.off("listening", onListening);
        reject(err);
      };
      const onListening = async (): Promise<void> => {
        server.off("error", onError);
        try {
          await chmod(this.socketPath, this.socketMode);
        } catch (err) {
          server.close();
          reject(
            new Error(
              `chmod on socket failed: ${err instanceof Error ? err.message : String(err)}`,
            ),
          );
          return;
        }
        // F1 #450 item 3: re-own the socket to the operator when a root daemon
        // bound it (safe-mode boot daemon), so the operator CLI dead-man lever
        // can reach it. Keep the existing gid; chmod ran first so 0600 holds
        // (chown preserves regular perms). Best-effort + loud: a failed chown
        // leaves the socket secure (root:0600) and the GUI toggle as backstop —
        // we warn rather than abort, since aborting would drop to a daemon-less brick.
        //
        // SECURITY (codex 2026-06-14): the socket path lives under the
        // operator-writable fortress dir, so a local operator/agent could unlink
        // our just-bound socket and swap something in before we re-own it.
        //   - `lstat` + `isSocket()` rejects a non-socket swap (we only re-own a
        //     real socket), and `lchown` does NOT follow symlinks, so the
        //     symlink-redirect-to-arbitrary-target escalation is closed.
        //   - RESIDUAL (documented, not fully closed here): this is still a
        //     by-NAME chown, so a hard-link/regular-file swap winning the tiny
        //     window between `lstat` and `lchown` could re-own the swapped inode
        //     to the operator uid. Fully eliminating it needs either binding the
        //     safe-mode socket in a root-owned (non-operator-writable) directory
        //     — a coordinated SocketPath.swift mirror change — or an fd-based
        //     bind+fchown (not exposed by Node's net.Server). The safe-mode
        //     socket's operator-reachability assumes the confined agent runs
        //     under a separate uid from the operator; the operator-owned 0o700
        //     fortress dir excludes the agent from the socket dir. A same-uid
        //     agent is an unsupported config (it also breaks per-uid enforcement).
        if (this.socketOwnerUid !== undefined) {
          try {
            const linkStat = await lstat(this.socketPath);
            if (linkStat.isSocket()) {
              await lchown(this.socketPath, this.socketOwnerUid, linkStat.gid);
            } else {
              // SAFETY: daemon startup diagnostics are operator-facing stderr output.
              console.error(
                `[castle-wall] warning: refusing to re-own the IPC socket — ${this.socketPath} is not a socket ` +
                  "(possible swap). The operator CLI dead-man lever may be unreachable in the safe-mode window; " +
                  "disarm via the System Settings VPN & Filters toggle if needed.",
              );
            }
          } catch (err) {
            // SAFETY: daemon startup diagnostics are operator-facing stderr output.
            console.error(
              `[castle-wall] warning: could not re-own the IPC socket to operator uid ${this.socketOwnerUid} ` +
                `(${err instanceof Error ? err.message : String(err)}); the operator CLI dead-man lever may be ` +
                `unreachable in the pre-login safe-mode window — disarm via the System Settings VPN & Filters toggle if needed.`,
            );
          }
        }
        this.server = server;
        this.stats.isListening = true;
        resolve();
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(this.socketPath);
    });
  }

  /** Close every active connection and unlink the socket path. */
  async stop(): Promise<void> {
    if (!this.server) return;
    const server = this.server;
    this.server = null;
    this.stats.isListening = false;
    for (const conn of this.connections.values()) {
      conn.socket.destroy();
    }
    this.connections.clear();
    this.stats.activeConnections = 0;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await this.unlinkStaleSocket();
  }

  /**
   * Fan the current manifest snapshot to every registered subscriber
   * via the consumer's broadcast path. Returns the number of subscribers
   * that received the snapshot.
   */
  async broadcastManifestUpdate(): Promise<number> {
    return await this.consumer.broadcastManifestUpdate();
  }

  /** Fan an operator decision response to active extension subscribers. */
  async broadcastDecisionResponse(response: DecisionResponse): Promise<number> {
    let emitted = 0;
    for (const conn of this.connections.values()) {
      if (!conn.registered) continue;
      this.writeMessage(conn, response);
      emitted += 1;
    }
    return emitted;
  }

  /**
   * Fan the current arm lease heartbeat to active extension subscribers.
   *
   * O-02: every emission funnels through `signArmLease` — the daemon heartbeat,
   * the CLI-relayed operator arm/revoke, and the subscribe-time resend all use
   * this one chokepoint, so no path can emit a lease the extension would have
   * to trust unauthenticated. If signing fails while a signer is configured,
   * NOTHING is emitted and `currentArmLease` keeps the last signed frame
   * (never an unsigned fallback; the extension's dead-man handles the gap).
   */
  async broadcastArmLease(
    lease: ArmLeaseNotification,
    opts: { coalesce?: boolean } = {},
  ): Promise<number> {
    // Serialize emissions: signing is async (root-helper round trip), and two
    // concurrent broadcasts completing out of call order would let an OLDER
    // arm state overwrite `currentArmLease` and reach subscribers after a
    // newer one (e.g. a heartbeat racing an operator revoke). The chain keeps
    // call order = emit order; a failed emission never breaks the chain.
    //
    // `coalesce: true` marks a periodic-heartbeat emission: only the LATEST
    // heartbeat state matters, so a heartbeat still queued behind a slow
    // signer is replaced in place by a newer one (chain-depth bound, see
    // `leaseEmitChain`). Operator arm/revoke and lifecycle emissions use the
    // default and are NEVER coalesced away: each is a discrete state change
    // the extension must observe in order.
    if (opts.coalesce === true) {
      const existing = this.pendingHeartbeatSlot;
      if (existing) {
        // Supersede in place: the queued link will sign + emit THIS payload
        // instead. The superseded caller resolves with the coalesced
        // emission's result.
        existing.lease = lease;
        return await existing.run;
      }
      const slot = {
        lease,
        run: Promise.resolve(0),
      };
      slot.run = this.leaseEmitChain.then(() => {
        // The slot closes when its link starts running: a heartbeat arriving
        // while THIS payload is being signed reflects newer state and must
        // queue a fresh link, not mutate an in-flight body.
        if (this.pendingHeartbeatSlot === slot) {
          this.pendingHeartbeatSlot = null;
        }
        return this.emitSignedArmLease(slot.lease);
      });
      this.pendingHeartbeatSlot = slot;
      this.leaseEmitChain = slot.run.then(
        () => undefined,
        () => undefined,
      );
      return await slot.run;
    }
    // Non-coalescible emission: seal any pending heartbeat slot so a LATER
    // heartbeat cannot overwrite a payload queued at a chain position BEFORE
    // this emission (that would emit post-revoke heartbeat state ahead of the
    // revoke, reordering what the extension observes). The sealed link still
    // emits its already-captured payload at its original position.
    this.pendingHeartbeatSlot = null;
    const run = this.leaseEmitChain.then(() => this.emitSignedArmLease(lease));
    this.leaseEmitChain = run.then(
      () => undefined,
      () => undefined,
    );
    return await run;
  }

  private async emitSignedArmLease(lease: ArmLeaseNotification): Promise<number> {
    const signed = await this.signArmLease(lease);
    if (signed === null) {
      return 0;
    }
    this.currentArmLease = signed;
    let emitted = 0;
    for (const conn of this.connections.values()) {
      if (!conn.registered) continue;
      this.writeMessage(conn, signed);
      emitted += 1;
    }
    return emitted;
  }

  /**
   * Stamp and sign one arm-lease frame. Returns the frame to emit, or `null`
   * when a configured signer failed (the caller must then emit nothing).
   *
   * The `updated_at` re-stamp is deliberate: the stamp is the daemon's LIVE
   * attestation ("this arm state holds as of now"), which is what lets the
   * extension bound lease age and reject a captured old frame. Signing an
   * inbound producer's original stamp would re-attest stale state. Unsigned
   * legacy path (no signer configured) is left byte-identical to the previous
   * behavior so existing dev harnesses see no change.
   */
  private async signArmLease(
    lease: ArmLeaseNotification,
  ): Promise<ArmLeaseNotification | null> {
    if (!this.leaseSigner) {
      return lease;
    }
    // Strip any inbound signature fields before re-signing: the daemon signs
    // what IT attests, never relays another producer's signature envelope.
    const {
      signing_key_id: _inboundKeyId,
      lease_signature_b64url: _inboundSig,
      ...body
    } = lease;
    const stampMs = Math.max(Date.now(), this.lastLeaseStampMs + 1);
    this.lastLeaseStampMs = stampMs;
    // Range-clamp the numeric fields BEFORE signing so the signature covers
    // exactly the bytes on the wire (constants + derivations above). An
    // out-of-range value would either fail the extension's UInt32 frame
    // decode (lease starved) or trap its `interval * 2` dead-man math.
    const clampedInterval = clampLeaseInt(
      body.heartbeat_interval_seconds,
      HEARTBEAT_INTERVAL_MIN_SECONDS,
      HEARTBEAT_INTERVAL_MAX_SECONDS,
    );
    const clampedTtl =
      body.ttl_seconds === null || body.ttl_seconds === undefined
        ? body.ttl_seconds
        : clampLeaseInt(body.ttl_seconds, 0, TTL_MAX_SECONDS);
    if (
      clampedInterval !== body.heartbeat_interval_seconds ||
      clampedTtl !== body.ttl_seconds
    ) {
      // SAFETY: a clamped value is a producer defect; surface it on daemon
      // stderr rather than silently normalizing (the emission still proceeds
      // with the safe value so a config error cannot starve the lease).
      console.error(
        `[castle-wall] arm_lease numeric field out of range; clamped before signing ` +
          `(heartbeat_interval_seconds ${body.heartbeat_interval_seconds} -> ${clampedInterval}, ` +
          `ttl_seconds ${body.ttl_seconds ?? "null"} -> ${clampedTtl ?? "null"})`,
      );
    }
    const stamped: ArmLeaseNotification = {
      ...body,
      type: "arm_lease",
      heartbeat_interval_seconds: clampedInterval,
      ...(body.ttl_seconds === undefined ? {} : { ttl_seconds: clampedTtl }),
      updated_at: new Date(stampMs).toISOString(),
    };
    try {
      const canonicalBytes = new TextEncoder().encode(
        canonicalize(armLeaseSignedBody(stamped)),
      );
      const signature = await this.leaseSigner.signLeaseBody(canonicalBytes);
      return {
        ...stamped,
        signing_key_id: this.leaseSigner.signingKeyId,
        lease_signature_b64url: toBase64url(signature),
      };
    } catch (err) {
      this.stats.framesRejected += 1;
      const reason = sanitizeLogValue(
        err instanceof Error ? err.message : String(err),
      );
      // SAFETY: a dropped lease emission must surface on daemon stderr — the
      // visible symptom downstream is the extension's dead-man firing.
      console.error(
        `[castle-wall] arm_lease signing failed; emission dropped (fail closed, no unsigned fallback): ${reason}`,
      );
      return null;
    }
  }

  /**
   * Recycle one subscriber connection through the transport-close recovery
   * edge. The existing socket `close` handler unregisters the subscriber and
   * clears the connection map; this method deliberately does no duplicate
   * cleanup. `reason` is part of the caller contract and reserved for a future
   * hook; logging stays with the daemon, which owns reason-coded recovery.
   */
  recycleConnection(subscriberId: string, _reason: string): boolean {
    const state = this.connections.get(subscriberId);
    if (!state) {
      return false;
    }
    this.stats.connectionsRecycled += 1;
    state.socket.destroy();
    return true;
  }

  /** Snapshot listener counters. */
  getStats(): MacOSFlowIpcListenerStats {
    return { ...this.stats, activeConnections: this.connections.size };
  }

  // ---------- internals ----------

  private async unlinkStaleSocket(): Promise<void> {
    try {
      await unlink(this.socketPath);
    } catch (err) {
      if (
        err instanceof Error &&
        (err as NodeJS.ErrnoException).code !== "ENOENT"
      ) {
        throw err;
      }
    }
  }

  private handleConnection(socket: Socket): void {
    const subscriberId = randomSubscriberId();
    const state: ConnectionState = {
      subscriberId,
      socket,
      inbound: new Uint8Array(0),
      registered: false,
    };
    this.connections.set(subscriberId, state);
    this.stats.activeConnections = this.connections.size;

    socket.on("data", (chunk: Buffer) => this.handleData(state, chunk));
    socket.on("close", () => this.handleClose(state));
    socket.on("error", (err) => this.handleSocketError(state, err));

    // Send the handshake challenge, then prove possession of the pinned
    // fortress key when the runtime supplied signing material.
    const nonceBytes = this.generateNonce();
    const challenge: CastleWallMessage = {
      type: "handshake_challenge",
      nonce_b64url: toBase64url(nonceBytes),
    };
    this.writeMessage(state, challenge);
    this.stats.handshakesSent += 1;
    if (this.handshakeSigner) {
      const signed = this.handshakeSigner.signNonce(nonceBytes);
      if (signed instanceof Promise) {
        // Helper path: emit the response once the helper returns the signature.
        // Fail closed — if signing is unavailable, tear the connection down
        // rather than completing an unsigned handshake (hard constraint #5).
        void signed.then(
          (sig) => this.writeHandshakeResponse(state, sig),
          () => {
            this.stats.framesRejected += 1;
            state.socket.destroy();
          },
        );
      } else {
        // Local path: preserve inline (synchronous) emission timing.
        this.writeHandshakeResponse(state, signed);
      }
    }
  }

  private writeHandshakeResponse(state: ConnectionState, signature: Uint8Array): void {
    if (!this.handshakeSigner) return;
    const response: HandshakeResponse = {
      type: "handshake_response",
      fortress_id: this.handshakeSigner.fortressId,
      signing_key_id: this.handshakeSigner.signingKeyId,
      nonce_signature_b64url: toBase64url(signature),
    };
    this.writeMessage(state, response);
  }

  private handleData(state: ConnectionState, chunk: Buffer): void {
    const combined = new Uint8Array(state.inbound.length + chunk.length);
    combined.set(state.inbound, 0);
    combined.set(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length), state.inbound.length);
    state.inbound = combined;

    let bufferRef = state.inbound;
    while (bufferRef.length > 0) {
      const step = parseFrame(bufferRef);
      if (step.kind === "need_more") {
        break;
      }
      if (step.kind === "error") {
        this.stats.framesRejected += 1;
        state.socket.destroy();
        return;
      }
      bufferRef = bufferRef.slice(step.consumedBytes);
      this.dispatchFrame(state, step.body);
    }
    state.inbound = bufferRef;
  }

  private dispatchFrame(state: ConnectionState, jsonBody: string): void {
    let envelope: JsonRpcEnvelope;
    try {
      envelope = JSON.parse(jsonBody) as JsonRpcEnvelope;
    } catch {
      this.stats.framesRejected += 1;
      return;
    }
    if (
      envelope.jsonrpc !== "2.0" ||
      typeof envelope.method !== "string" ||
      !envelope.method.startsWith(`${CASTLE_WALL_IPC_NAMESPACE}.`) ||
      typeof envelope.params !== "object" ||
      envelope.params === null
    ) {
      this.stats.framesRejected += 1;
      return;
    }
    const message = envelope.params as CastleWallMessage;
    this.stats.framesDecoded += 1;
    void this.routeMessage(state, message).catch((error) => {
      const type = sanitizeLogValue(String(message.type));
      const reason = sanitizeLogValue(
        error instanceof Error ? error.message : String(error),
      );
      // SAFETY: listener route failures must surface in daemon stderr.
      console.error(
        `[castle-wall] listener routeMessage failed for type=${type}: ${reason}`,
      );
    });
  }

  private async routeMessage(
    state: ConnectionState,
    message: CastleWallMessage,
  ): Promise<void> {
    switch (message.type) {
      case "manifest_subscribe":
        await this.handleSubscribe(state, message);
        return;
      case "policy_reload_request":
        await this.handlePolicyReload(state, message as PolicyReloadRequest);
        return;
      case "decision_response":
        await this.handleDecisionResponse(state, message as DecisionResponse);
        return;
      case "arm_lease":
        await this.handleArmLease(message as ArmLeaseNotification);
        return;
      case "audit_emit":
        this.ensureSubscriberRegistered(state);
        await this.consumer.handleAuditEmit(message as AuditEmitNotification);
        return;
      case "enforcement_availability_report":
        this.ensureSubscriberRegistered(state);
        this.consumer.handleEnforcementAvailabilityReport(
          message as EnforcementAvailabilityReportNotification,
          state.subscriberId,
        );
        return;
      case "enforcement_availability_request":
        this.handleEnforcementAvailabilityRequest(
          state,
          message as EnforcementAvailabilityRequest,
        );
        return;
      case "flow_decision_recorded":
        this.ensureSubscriberRegistered(state);
        await this.consumer.handleFlowDecisionRecorded(
          message as FlowDecisionRecordedNotification,
          state.subscriberId,
        );
        return;
      case "flow_pending_approval":
        this.ensureSubscriberRegistered(state);
        await this.consumer.handleFlowPendingApproval(
          message as FlowPendingApprovalNotification,
        );
        return;
      default:
        // Other inbound types are not consumed today. Drop quietly so
        // an unexpected envelope from a future extension build does
        // not desync the connection.
        return;
    }
  }

  private async handleArmLease(message: ArmLeaseNotification): Promise<void> {
    if (message.revoked === true) {
      await this.onArmLeaseRevoke?.(message);
    } else {
      // A non-revoke operator arm lets the daemon ADOPT the operator's TTL so
      // its periodic heartbeat re-broadcasts the SAME dead-man deadline instead
      // of erasing it with a no-TTL renewal.
      await this.onArmLease?.(message);
    }
    await this.broadcastArmLease(message);
  }

  private async handleSubscribe(
    state: ConnectionState,
    request: ManifestSubscribeRequest,
  ): Promise<void> {
    this.ensureSubscriberRegistered(state);
    await this.consumer.handleManifestSubscribe(request, state.subscriberId);
    if (this.currentArmLease) {
      // Re-stamp + re-sign rather than replaying the stored frame: the
      // extension bounds lease age, so a late subscriber served the ORIGINAL
      // stamp would reject it as stale. A fresh signature is the daemon's live
      // re-attestation of the current arm state. On signing failure nothing is
      // sent (the heartbeat delivers the next signed lease). Rides the same
      // serialization chain as `broadcastArmLease` so the resend cannot
      // interleave with a concurrent broadcast and emit out-of-order stamps.
      const run = this.leaseEmitChain.then(async () => {
        if (!this.currentArmLease) return;
        const resigned = await this.signArmLease(this.currentArmLease);
        if (resigned !== null) {
          this.currentArmLease = resigned;
          this.writeMessage(state, resigned);
        }
      });
      this.leaseEmitChain = run.then(
        () => undefined,
        () => undefined,
      );
      await run;
    }
  }

  private handleEnforcementAvailabilityRequest(
    state: ConnectionState,
    request: EnforcementAvailabilityRequest,
  ): void {
    this.writeMessage(state, {
      type: "enforcement_availability_response",
      request_id: request.request_id,
      availability: this.consumer.resolveEnforcementAvailability(),
    });
  }

  private ensureSubscriberRegistered(state: ConnectionState): void {
    if (state.registered) return;
    this.consumer.registerSubscriber({
      subscriberId: state.subscriberId,
      emitManifestUpdate: async (notification) => {
        this.writeMessage(state, notification);
      },
    });
    state.registered = true;
  }

  private async handlePolicyReload(
    state: ConnectionState,
    request: PolicyReloadRequest,
  ): Promise<void> {
    if (!this.adminHandler) {
      this.writeMessage(state, {
        type: "policy_reload_response",
        request_id: request.request_id,
        ok: false,
        loaded_manifest_signature_b64url: null,
        loaded_rule_count: 0,
        error: "policy reload handler unavailable",
      });
      return;
    }
    this.writeMessage(state, await this.adminHandler.reloadPolicy(request));
  }

  private async handleDecisionResponse(
    state: ConnectionState,
    response: DecisionResponse,
  ): Promise<void> {
    const result = this.adminHandler
      ? await this.adminHandler.handleDecision(response)
      : { ok: false, error: "decision handler unavailable" };
    this.writeMessage(state, {
      type: "decision_response_ack",
      request_id: response.request_id,
      ok: result.ok,
      ...(result.error ? { error: result.error } : {}),
    });
  }

  private writeMessage(state: ConnectionState, message: CastleWallMessage): void {
    const envelope: JsonRpcEnvelope = {
      jsonrpc: "2.0",
      method: `${CASTLE_WALL_IPC_NAMESPACE}.${message.type}`,
      params: message,
    };
    const body = JSON.stringify(envelope);
    const bytes = frame(body);
    try {
      state.socket.write(bytes);
    } catch {
      // Pipe broken; the socket's `error`/`close` handlers tear down.
    }
  }

  private handleSocketError(state: ConnectionState, _err: Error): void {
    state.socket.destroy();
    this.removeConnection(state);
  }

  private handleClose(state: ConnectionState): void {
    this.removeConnection(state);
  }

  private removeConnection(state: ConnectionState): void {
    if (state.registered) {
      this.consumer.unregisterSubscriber(state.subscriberId);
    }
    this.connections.delete(state.subscriberId);
    this.stats.activeConnections = this.connections.size;
  }
}

/**
 * Used for ManifestUpdated typing only - not a runtime guard. Surfaced
 * so callers can reason about the type without importing from a deep
 * module path.
 */
export type { ManifestUpdatedNotification };

// ---------- helpers ----------

function randomSubscriberId(): string {
  return randomBytes(8).toString("hex");
}

function defaultNonceBytes(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
