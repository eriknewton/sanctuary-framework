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
  CastleWallMessage,
  HandshakeChallenge,
  HandshakeResponse,
  IpcRequestId,
  PolicyReloadResponse,
  StatusResponse,
} from "../ipc/messages.js";
import { fromBase64url, stringToBytes, toBase64url } from "../../core/encoding.js";
import { sign as identitySign } from "../../core/identity.js";
import type { EncryptedPayload } from "../../core/encryption.js";
import { RuntimeHandshakeError, RuntimeIpcError } from "./errors.js";

/** Two-way byte transport. The mock daemon and the real UDS socket both implement it. */
export interface IpcTransport {
  send(bytes: Uint8Array): Promise<void>;
  /** Subscribe to inbound bytes. Returns an unsubscribe handle. */
  onData(listener: (bytes: Uint8Array) => void): () => void;
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
      pending.reject(new RuntimeIpcError(`transport closed; request ${id} dropped`));
    }
    this.pending.clear();
    if (this.listenerCleanup) {
      this.listenerCleanup();
      this.listenerCleanup = null;
    }
    await this.transport.close();
  }

  /** Whether the daemon-issued handshake has been signed and accepted. */
  isHandshakeComplete(): boolean {
    return this.handshakeComplete;
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
        nonceBytes,
        this.key.encryptedPrivateKey,
        this.key.encryptionKey
      );
    } catch (err) {
      throw new RuntimeHandshakeError(
        `handshake signing failed: ${(err as Error).message}`,
        "signature_failed"
      );
    }

    const response: HandshakeResponse = {
      type: "handshake_response",
      fortress_id: this.key.fortressId,
      signing_key_id: this.key.signingKeyId,
      nonce_signature_b64url: toBase64url(signatureBytes),
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
    for (const [, pending] of this.pending) {
      pending.reject(err);
    }
    this.pending.clear();
    if (this.handshakeWaiter) {
      this.handshakeWaiter.reject(err);
      this.handshakeWaiter = null;
    }
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
