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
 *  - Subscriber registration - each connection registers as a
 *    `MacOSSubscriber` so manifest broadcasts fan out to it.
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
import type {
  AuditEmitNotification,
  CastleWallMessage,
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
  /** Optional local-admin command handler used by the CLI verbs. */
  adminHandler?: MacOSFlowIpcAdminHandler;
  /** Called before an inbound operator revoke is broadcast to subscribers. */
  onArmLeaseRevoke?: (lease: ArmLeaseNotification) => void | Promise<void>;
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
   * (post-handshake). Subsequent inbound frames are dispatched.
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
  private readonly adminHandler: MacOSFlowIpcAdminHandler | null;
  private readonly onArmLeaseRevoke: ((lease: ArmLeaseNotification) => void | Promise<void>) | null;
  private currentArmLease: ArmLeaseNotification | null = null;
  private server: Server | null = null;
  private connections = new Map<string, ConnectionState>();
  private stats: MacOSFlowIpcListenerStats = {
    activeConnections: 0,
    framesDecoded: 0,
    framesRejected: 0,
    handshakesSent: 0,
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
    this.adminHandler = opts.adminHandler ?? null;
    this.onArmLeaseRevoke = opts.onArmLeaseRevoke ?? null;
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

  /** Fan the current arm lease heartbeat to active extension subscribers. */
  async broadcastArmLease(lease: ArmLeaseNotification): Promise<number> {
    this.currentArmLease = lease;
    let emitted = 0;
    for (const conn of this.connections.values()) {
      if (!conn.registered) continue;
      this.writeMessage(conn, lease);
      emitted += 1;
    }
    return emitted;
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

    // Register the subscriber wrapper BEFORE sending the handshake. The
    // consumer needs the subscriber present so a synchronous
    // `manifest_subscribe` arriving immediately after the handshake can
    // resolve via `subscribers.get(subscriberId)`.
    this.consumer.registerSubscriber({
      subscriberId,
      emitManifestUpdate: async (notification) => {
        this.writeMessage(state, notification);
      },
    });
    state.registered = true;

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
        await this.consumer.handleAuditEmit(message as AuditEmitNotification);
        return;
      case "flow_decision_recorded":
        await this.consumer.handleFlowDecisionRecorded(
          message as FlowDecisionRecordedNotification,
        );
        return;
      case "flow_pending_approval":
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
    }
    await this.broadcastArmLease(message);
  }

  private async handleSubscribe(
    state: ConnectionState,
    request: ManifestSubscribeRequest,
  ): Promise<void> {
    await this.consumer.handleManifestSubscribe(request, state.subscriberId);
    if (this.currentArmLease) {
      this.writeMessage(state, this.currentArmLease);
    }
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
