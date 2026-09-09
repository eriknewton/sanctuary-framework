/**
 * Castle Wall IPC client (Sanctuary main side).
 *
 * Mirrors the Linux daemon's IPC server: LSP-style framing, JSON-RPC
 * envelope, Ed25519 challenge-response handshake. The transport is
 * abstracted via a Duplex interface so PR 2a can run integration tests
 * against an in-process mock daemon on macOS without Linux-only `net`
 * primitives.
 *
 * Source: Castle_Wall_Phase1_Scope_Lock_2026-05-03.md section 5.
 */

import {
  CASTLE_WALL_IPC_NAMESPACE,
  CASTLE_WALL_REQUEST_ID_NONCE_BYTES,
} from "../constants.js";
import { frame, parseFrame } from "../ipc/framing.js";
import type {
  AuditDrainAckResponse,
  AuditDrainResponse,
  CastleWallMessage,
  EnforcementAvailabilityResponse,
  HandshakeChallenge,
  HandshakeResponse,
  IpcRequestId,
  PolicyReloadResponse,
  PolicyBundlePublishResponse,
  StatusResponse,
} from "../ipc/messages.js";
import {
  CAP_AUDIT_DRAIN_ACK_RESPONSE,
  CAP_POLICY_BUNDLE_PUBLISH,
  CASTLE_WALL_IPC_CAPABILITIES,
  CASTLE_WALL_IPC_PROTOCOL_VERSION,
  classifyDrainFailure,
} from "../ipc/messages.js";
import { fromBase64url, stringToBytes, toBase64url } from "../../core/encoding.js";
import { sign as identitySign } from "../../core/identity.js";
import type { EncryptedPayload } from "../../core/encryption.js";
import { RuntimeDrainError, RuntimeHandshakeError, RuntimeIpcError } from "./errors.js";

const HANDSHAKE_CONTEXT_DOMAIN = "sanctuary-castle-wall-ipc-handshake-v1\0";
const DAEMON_MAX_INBOUND_BODY_BYTES = 512 * 1024;

/** Exact cross-language bytes authenticated by the Linux IPC handshake. */
export function handshakeSigningBytes(input: {
  nonce: Uint8Array;
  fortressId: string;
  signingKeyId: string;
  protocolVersion: number;
  capabilities: readonly string[];
}): Uint8Array {
  const chunks: Uint8Array[] = [stringToBytes(HANDSHAKE_CONTEXT_DOMAIN), input.nonce];
  const u32 = (value: number): Uint8Array => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
      throw new RuntimeHandshakeError("handshake context length/version is out of range", "signature_failed");
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    return bytes;
  };
  const field = (value: string): void => {
    const bytes = stringToBytes(value);
    chunks.push(u32(bytes.length), bytes);
  };
  field(input.fortressId);
  field(input.signingKeyId);
  chunks.push(u32(input.protocolVersion), u32(input.capabilities.length));
  for (const capability of input.capabilities) field(capability);
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Two-way byte transport. The mock daemon and the real UDS socket both implement it. */
export interface IpcTransport {
  send(bytes: Uint8Array): Promise<void>;
  /** Subscribe to inbound bytes. Returns an unsubscribe handle. */
  onData(listener: (bytes: Uint8Array) => void): () => void;
  /**
   * Subscribe to an unexpected peer/socket close. Optional for legacy test
   * transports; the production UDS transport implements it so daemon loss
   * rejects in-flight requests immediately instead of waiting for every
   * request deadline.
   */
  onClose?(listener: (reason: Error) => void): () => void;
  /** Close the transport. Pending in-flight requests reject with `transport_dropped`. */
  close(): Promise<void>;
}

/** Identity key material the client signs handshake challenges with. */
export interface ClientKeyMaterial {
  fortressId: string;
  signingKeyId: string;
  encryptedPrivateKey: EncryptedPayload;
  encryptionKey: Uint8Array;
}

/** Configuration knobs for the client. */
export interface IpcClientOptions {
  /** Handshake decision deadline. Defaults to 5s. */
  handshakeTimeoutMs?: number;
  /** Per-request decision deadline. Defaults to 10s. */
  requestTimeoutMs?: number;
  /** Override for randomBytes; tests inject deterministic nonces. */
  generateNonceHex?: () => string;
}

/** Public client surface. */
export class IpcClient {
  private inbound: Uint8Array = new Uint8Array(0);
  private pending = new Map<IpcRequestId, PendingRequest>();
  private handshakeComplete = false;
  private closed = false;
  private listenerCleanup: (() => void) | null = null;
  private closeListenerCleanup: (() => void) | null = null;
  /**
   * What the DAEMON advertised in its handshake challenge. Empty until the
   * handshake completes, and empty forever against a pre-v2 daemon that sent no
   * capability list. Never inferred: a capability the daemon did not name is
   * treated as absent, because the failure of guessing is a hung request loop
   * (see `sendDrainAck`).
   */
  private daemonCapabilities: ReadonlySet<string> = new Set();
  private daemonProtocolVersion: number | null = null;

  constructor(
    private readonly transport: IpcTransport,
    private readonly key: ClientKeyMaterial,
    private readonly options: Required<IpcClientOptions>
  ) {}

  static create(
    transport: IpcTransport,
    key: ClientKeyMaterial,
    options: IpcClientOptions = {}
  ): IpcClient {
    return new IpcClient(transport, key, {
      handshakeTimeoutMs: options.handshakeTimeoutMs ?? 5_000,
      requestTimeoutMs: options.requestTimeoutMs ?? 10_000,
      generateNonceHex: options.generateNonceHex ?? defaultNonceHex,
    });
  }

  /** Begin reading frames from the transport and complete the handshake. */
  async start(): Promise<void> {
    if (this.listenerCleanup) {
      throw new RuntimeIpcError("ipc client already started");
    }
    this.listenerCleanup = this.transport.onData((bytes) => this.ingest(bytes));
    this.closeListenerCleanup =
      this.transport.onClose?.((reason) => {
        this.handleFatal(
          new RuntimeIpcError(`Castle Wall daemon transport dropped: ${reason.message}`)
        );
      }) ?? null;
    await this.completeHandshake();
  }

  /** Send a status query; resolves with the daemon's response. */
  async statusRequest(): Promise<StatusResponse> {
    const requestId = this.options.generateNonceHex();
    const params: CastleWallMessage = {
      type: "status_request",
      request_id: requestId,
    };
    const envelope = wrapEnvelope("status_request", params);
    const reply = await this.send<StatusResponse>(requestId, envelope);
    return reply;
  }

  /** Send a policy_reload request; resolves with the daemon's response. */
  async policyReload(manifestPath: string): Promise<PolicyReloadResponse> {
    const requestId = this.options.generateNonceHex();
    const params: CastleWallMessage = {
      type: "policy_reload_request",
      request_id: requestId,
      manifest_path: manifestPath,
    };
    const envelope = wrapEnvelope("policy_reload_request", params);
    return await this.send<PolicyReloadResponse>(requestId, envelope);
  }

  /** Publish one complete signed bundle; caller supplies bytes, never paths. */
  async publishPolicyBundle(
    manifestBytes: Uint8Array,
    rules: ReadonlyArray<{ file: string; bytes: Uint8Array }>
  ): Promise<PolicyBundlePublishResponse> {
    if (!this.daemonSupports(CAP_POLICY_BUNDLE_PUBLISH)) {
      throw new RuntimeIpcError("daemon does not advertise authenticated policy bundle publication");
    }
    const requestId = this.options.generateNonceHex();
    const params: CastleWallMessage = {
      type: "policy_bundle_publish_request",
      request_id: requestId,
      manifest_b64url: toBase64url(manifestBytes),
      rules: rules.map((rule) => ({
        file: rule.file,
        body_b64url: toBase64url(rule.bytes),
      })),
    };
    const envelope = wrapEnvelope("policy_bundle_publish_request", params);
    const encodedBytes = new TextEncoder().encode(JSON.stringify(envelope)).length;
    if (encodedBytes > DAEMON_MAX_INBOUND_BODY_BYTES) {
      throw new RuntimeIpcError(
        `policy bundle request exceeds daemon framing bound (${encodedBytes} > ${DAEMON_MAX_INBOUND_BODY_BYTES})`
      );
    }
    return await this.send<PolicyBundlePublishResponse>(
      requestId,
      envelope
    );
  }

  /**
   * Pull a batch of WAL entries strictly above `afterSeq` (capped at
   * `maxEvents`). Per scope-lock §8 hybrid PULL model: main drives the pace.
   * Resolves with the daemon's `audit_drain_response` (which carries the
   * per-event producer-signature material the consumer re-verifies).
   */
  async drainRequest(
    afterSeq: number | null,
    maxEvents: number
  ): Promise<AuditDrainResponse> {
    const requestId = this.options.generateNonceHex();
    const params: CastleWallMessage = {
      type: "audit_drain_request",
      request_id: requestId,
      after_seq: afterSeq,
      max_events: maxEvents,
    };
    const envelope = wrapEnvelope("audit_drain_request", params);
    const response = await this.send<AuditDrainResponse>(requestId, envelope);
    if (response.error) {
      // The DRAIN path delivers evidence, so an unclassified failure is not
      // assumed harmless: it stays `unclassified` and the caller's bounded retry
      // budget decides. See `classifyDrainFailure`.
      throw new RuntimeDrainError(
        `audit drain failed: ${response.error}`,
        "drain",
        classifyDrainFailure({
          errorClass: response.error_class,
          consumerDataAlreadyDurable: false,
        })
      );
    }
    return response;
  }

  /** Query daemon-cached extension-origin enforcement availability. */
  async enforcementAvailabilityRequest(): Promise<EnforcementAvailabilityResponse> {
    const requestId = this.options.generateNonceHex();
    const params: CastleWallMessage = {
      type: "enforcement_availability_request",
      request_id: requestId,
    };
    const envelope = wrapEnvelope("enforcement_availability_request", params);
    return await this.send<EnforcementAvailabilityResponse>(requestId, envelope);
  }

  /**
   * Acknowledge durable receipt of every drained event through `lastAckedSeq`
   * so the daemon truncates its WAL through that point. The cursor must advance
   * only after the daemon confirms `ok=true`; a timeout or negative response is
   * retryable and is surfaced to the audit consumer.
   */
  async sendDrainAck(lastAckedSeq: number): Promise<void> {
    const requestId = this.options.generateNonceHex();
    const params: CastleWallMessage = {
      type: "audit_drain_ack",
      request_id: requestId,
      last_acked_seq: lastAckedSeq,
    };
    const envelope = wrapEnvelope("audit_drain_ack", params);
    if (!this.drainAcksAreConfirmed()) {
      // PRE-V2 DAEMON: the ACK is a one-way notification and no reply is coming.
      // Awaiting one would time out on EVERY ack, so the drain cursor would never
      // advance, the daemon's WAL would grow to its cap, and `evaluate_attempt`
      // would fail closed and deny all wrapped-agent egress. A partial upgrade
      // must not become an outage, so send and return, exactly as this client
      // behaved before the confirmation existed. The weaker guarantee is
      // reported through `drainAcksAreConfirmed()`, never hidden.
      await this.transport.send(frame(JSON.stringify(envelope)));
      return;
    }
    const response = await this.send<AuditDrainAckResponse>(requestId, envelope);
    // The ACK path never risks evidence: the consumer advances its own chain
    // state and flushes BEFORE calling ack, so a refused truncation costs daemon
    // WAL space and nothing else. An unclassified refusal is therefore safely
    // retryable here, unlike on the drain path.
    const failureClass = (): "retryable" | "terminal" | "unclassified" =>
      classifyDrainFailure({
        errorClass: response.error_class,
        consumerDataAlreadyDurable: true,
      });
    if (!response.ok) {
      throw new RuntimeDrainError(
        `audit drain ACK ${lastAckedSeq} failed: ${response.error ?? "daemon refused ACK"}`,
        "ack",
        failureClass()
      );
    }
    // `ok` ALONE IS NOT CONFIRMATION. A reply is only evidence about the
    // sequence it names: `ok: true` with a different `last_acked_seq` confirms a
    // truncation through some OTHER point, and treating it as confirmation of
    // this one would let a skewed, buggy, or hostile daemon advance the
    // consumer's reclamation claim past evidence it never truncated (AGENTS
    // rule 7: a signed/typed field must mean what its consumer treats it as
    // meaning; `request_id` correlation proves which REQUEST this answers, not
    // which SEQUENCE it applied).
    //
    // Classified `terminal` rather than retryable: a daemon that answers a
    // different sequence is not busy, it is wrong, and retrying cannot fix a
    // peer whose replies do not describe the request.
    if (response.last_acked_seq !== lastAckedSeq) {
      throw new RuntimeDrainError(
        `audit drain ACK ${lastAckedSeq} was answered for sequence ` +
          `${String(response.last_acked_seq)}; a confirmation is evidence only ` +
          `about the sequence it names, so this ACK is NOT confirmed`,
        "ack",
        "terminal"
      );
    }
  }

  /**
   * Notify the daemon that the fortress is unlocked (mutations now permitted).
   * One-way; no ACK.
   */
  async sendUnlockNotification(unlockedAt: string): Promise<void> {
    const params: CastleWallMessage = {
      type: "unlock_notification",
      fortress_id: this.key.fortressId,
      unlocked_at: unlockedAt,
    };
    const envelope = wrapEnvelope("unlock_notification", params);
    await this.transport.send(frame(JSON.stringify(envelope)));
  }

  /**
   * Notify the daemon that the fortress is locked (last validated snapshot
   * remains in force; novel-destination prompts are denied automatically).
   */
  async sendLockNotification(lockedAt: string): Promise<void> {
    const params: CastleWallMessage = {
      type: "lock_notification",
      fortress_id: this.key.fortressId,
      locked_at: lockedAt,
    };
    const envelope = wrapEnvelope("lock_notification", params);
    await this.transport.send(frame(JSON.stringify(envelope)));
  }

  /** Close the transport and reject all in-flight requests. */
  async close(): Promise<void> {
    this.closed = true;
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(new RuntimeIpcError(`transport closed; request ${id} dropped`));
    }
    this.pending.clear();
    if (this.listenerCleanup) {
      this.listenerCleanup();
      this.listenerCleanup = null;
    }
    if (this.closeListenerCleanup) {
      this.closeListenerCleanup();
      this.closeListenerCleanup = null;
    }
    await this.transport.close();
  }

  /** Whether the daemon-issued handshake has been signed and accepted. */
  isHandshakeComplete(): boolean {
    return this.handshakeComplete;
  }

  /**
   * Did the connected daemon advertise `capability`?
   *
   * Always false before the handshake completes and against a pre-v2 daemon.
   * Callers use this to choose the older wire behavior, never to decide
   * authorization.
   */
  daemonSupports(capability: string): boolean {
    return this.daemonCapabilities.has(capability);
  }

  /**
   * Protocol version the daemon declared, or `null` for a pre-v2 daemon that
   * declared none. Reported so an operator-facing surface can say WHY a
   * confirmation-backed guarantee is unavailable instead of silently degrading.
   */
  daemonProtocol(): number | null {
    return this.daemonProtocolVersion;
  }

  /**
   * Does this link confirm audit ACKs?
   *
   * When false, `sendDrainAck` resolves as soon as the notification is written
   * and the caller has NO proof the daemon truncated its WAL. That is the exact
   * pre-v2 guarantee, and it is weaker: a refused truncation is indistinguishable
   * from an applied one. Surface it rather than letting a caller assume the
   * stronger property (never overclaim).
   */
  drainAcksAreConfirmed(): boolean {
    return this.daemonSupports(CAP_AUDIT_DRAIN_ACK_RESPONSE);
  }

  // ---------- internals ----------

  private async completeHandshake(): Promise<void> {
    const challenge = await this.awaitMessage<HandshakeChallenge>(
      "handshake_challenge",
      this.options.handshakeTimeoutMs
    ).catch((err) => {
      if (err instanceof RuntimeIpcError) {
        throw new RuntimeHandshakeError(err.message, "timeout");
      }
      throw err;
    });

    const nonceBytes = fromBase64url(challenge.nonce_b64url);
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = identitySign(
        handshakeSigningBytes({
          nonce: nonceBytes,
          fortressId: this.key.fortressId,
          signingKeyId: this.key.signingKeyId,
          protocolVersion: CASTLE_WALL_IPC_PROTOCOL_VERSION,
          capabilities: CASTLE_WALL_IPC_CAPABILITIES,
        }),
        this.key.encryptedPrivateKey,
        this.key.encryptionKey
      );
    } catch (err) {
      throw new RuntimeHandshakeError(
        `handshake signing failed: ${(err as Error).message}`,
        "signature_failed"
      );
    }

    // Record what the daemon offered BEFORE declaring the handshake complete, so
    // no request can be built against an unnegotiated assumption. A challenge
    // with no `capabilities` (a pre-v2 daemon) leaves the set empty; absence is
    // never read as support.
    this.daemonProtocolVersion =
      typeof challenge.protocol_version === "number" ? challenge.protocol_version : null;
    this.daemonCapabilities = new Set(
      Array.isArray(challenge.capabilities)
        ? challenge.capabilities.filter((c): c is string => typeof c === "string")
        : []
    );

    const response: HandshakeResponse = {
      type: "handshake_response",
      fortress_id: this.key.fortressId,
      signing_key_id: this.key.signingKeyId,
      nonce_signature_b64url: toBase64url(signatureBytes),
      // Declare what THIS consumer can parse. A pre-v2 daemon ignores the extra
      // fields (both sides tolerate unknown JSON members), and a v2 daemon uses
      // them to decide whether it may reply to an `audit_drain_ack`.
      protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
    };
    const envelope = wrapEnvelope("handshake_response", response);
    await this.transport.send(frame(JSON.stringify(envelope)));
    this.handshakeComplete = true;
  }

  private ingest(bytes: Uint8Array): void {
    if (this.closed) return;
    const merged = new Uint8Array(this.inbound.length + bytes.length);
    merged.set(this.inbound, 0);
    merged.set(bytes, this.inbound.length);
    this.inbound = merged;

    let progressed = true;
    while (progressed) {
      const step = parseFrame(this.inbound);
      if (step.kind === "complete") {
        const remaining = this.inbound.subarray(step.consumedBytes);
        this.inbound = new Uint8Array(remaining);
        this.handleFrame(step.body);
      } else if (step.kind === "need_more") {
        progressed = false;
      } else {
        progressed = false;
        // Hard framing error closes the channel per scope-lock §5.
        this.handleFatal(new RuntimeIpcError(`framing error: ${step.reason}`));
      }
    }
  }

  private handleFrame(body: string): void {
    let envelope: { method?: string; params?: { type?: string } & Record<string, unknown> };
    try {
      envelope = JSON.parse(body) as typeof envelope;
    } catch (err) {
      this.handleFatal(
        new RuntimeIpcError(`malformed JSON envelope: ${(err as Error).message}`)
      );
      return;
    }
    const params = envelope.params;
    if (!params || typeof params !== "object" || typeof params.type !== "string") {
      // Spurious or notification-without-type; ignore in PR 2a.
      return;
    }
    const message = params as unknown as CastleWallMessage;
    if ("request_id" in message) {
      const pending = this.pending.get(message.request_id);
      if (pending && pending.expectedType === message.type) {
        clearTimeout(pending.timer);
        this.pending.delete(message.request_id);
        pending.resolve(message);
        return;
      }
    }
    if (this.handshakeWaiter && message.type === this.handshakeWaiter.expectedType) {
      const waiter = this.handshakeWaiter;
      this.handshakeWaiter = null;
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    }
  }

  private handleFatal(err: Error): void {
    if (this.closed) return;
    this.closed = true;
    this.handshakeComplete = false;
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.pending.clear();
    if (this.handshakeWaiter) {
      clearTimeout(this.handshakeWaiter.timer);
      this.handshakeWaiter.reject(err);
      this.handshakeWaiter = null;
    }
    this.listenerCleanup?.();
    this.listenerCleanup = null;
    this.closeListenerCleanup?.();
    this.closeListenerCleanup = null;
    // A framing error is as terminal as a kernel socket close. Best-effort
    // closure releases the fd; callers observe the already-rejected request.
    void this.transport.close().catch(() => {});
  }

  private handshakeWaiter:
    | {
        expectedType: string;
        resolve: (msg: CastleWallMessage) => void;
        reject: (err: Error) => void;
        timer: ReturnType<typeof setTimeout>;
      }
    | null = null;

  private awaitMessage<T extends CastleWallMessage>(
    expectedType: T["type"],
    timeoutMs: number
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.handshakeWaiter = null;
        reject(new RuntimeIpcError(`timed out waiting for ${expectedType}`));
      }, timeoutMs);
      this.handshakeWaiter = {
        expectedType,
        resolve: (msg) => resolve(msg as T),
        reject,
        timer,
      };
    });
  }

  private async send<T extends CastleWallMessage>(
    requestId: IpcRequestId,
    envelope: { method: string; params: CastleWallMessage }
  ): Promise<T> {
    if (this.closed) {
      throw new RuntimeIpcError("Castle Wall daemon transport is closed");
    }
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new RuntimeIpcError(`request ${requestId} timed out`));
      }, this.options.requestTimeoutMs);
      this.pending.set(requestId, {
        expectedType: expectedReplyType(envelope.params.type),
        resolve: (msg) => resolve(msg as T),
        reject,
        timer,
      });
      this.transport
        .send(frame(JSON.stringify(envelope)))
        .catch((err) => {
          clearTimeout(timer);
          this.pending.delete(requestId);
          reject(err);
        });
    });
  }
}

interface PendingRequest {
  expectedType: string;
  resolve: (message: CastleWallMessage) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

function expectedReplyType(requestType: string): string {
  switch (requestType) {
    case "status_request":
      return "status_response";
    case "policy_reload_request":
      return "policy_reload_response";
    case "policy_bundle_publish_request":
      return "policy_bundle_publish_response";
    case "audit_drain_request":
      return "audit_drain_response";
    case "audit_drain_ack":
      return "audit_drain_ack_response";
    case "enforcement_availability_request":
      return "enforcement_availability_response";
    default:
      return requestType;
  }
}

function wrapEnvelope(
  methodSuffix: string,
  params: CastleWallMessage
): { jsonrpc: string; method: string; params: CastleWallMessage } {
  return {
    jsonrpc: "2.0",
    method: `${CASTLE_WALL_IPC_NAMESPACE}.${methodSuffix}`,
    params,
  };
}

function defaultNonceHex(): string {
  const bytes = new Uint8Array(CASTLE_WALL_REQUEST_ID_NONCE_BYTES);
  // Node 19+ + browsers expose globalThis.crypto.
  const cryptoObj: { getRandomValues?: (b: Uint8Array) => Uint8Array } | undefined =
    (globalThis as { crypto?: { getRandomValues?: (b: Uint8Array) => Uint8Array } }).crypto;
  if (cryptoObj && typeof cryptoObj.getRandomValues === "function") {
    cryptoObj.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

/** Re-exported for tests. */
export { defaultNonceHex as __defaultNonceHexForTests, wrapEnvelope as __wrapEnvelopeForTests };

/** Stable signature for fixture data; intentionally lazy to keep stringToBytes referenced. */
export const __utf8 = (s: string): Uint8Array => stringToBytes(s);
