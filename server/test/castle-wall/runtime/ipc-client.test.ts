/**
 * Castle Wall IPC client tests.
 *
 * Drives the client against an in-process mock daemon that speaks the same
 * LSP framing + JSON-RPC envelope. Exercises the handshake round trip,
 * status_request / policy_reload_request, and the lock/unlock notifications.
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  handshakeSigningBytes,
  IpcClient,
  type IpcTransport,
} from "../../../src/castle-wall/runtime/ipc-client.js";
import { frame, parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import type {
  AuditDrainAck,
  AuditDrainRequest,
  CastleWallMessage,
  HandshakeResponse,
  PolicyBundlePublishRequest,
  PolicyReloadRequest,
  StatusRequest,
} from "../../../src/castle-wall/ipc/messages.js";
import {
  CASTLE_WALL_IPC_CAPABILITIES,
  CASTLE_WALL_IPC_PROTOCOL_VERSION,
} from "../../../src/castle-wall/ipc/messages.js";
import {
  createIdentity,
  verify,
} from "../../../src/core/identity.js";
import { RuntimeDrainError } from "../../../src/castle-wall/runtime/errors.js";
import { fromBase64url } from "../../../src/core/encoding.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { generateRandomKey } from "../../../src/core/random.js";

interface PairedTransports {
  clientTransport: IpcTransport;
  daemonSend: (msg: CastleWallMessage) => Promise<void>;
  daemonDrop: (reason?: Error) => void;
  daemonInbound: Array<CastleWallMessage>;
  closeAll: () => Promise<void>;
}

function pairTransports(): PairedTransports {
  let clientListener: ((bytes: Uint8Array) => void) | null = null;
  let clientCloseListener: ((reason: Error) => void) | null = null;
  const daemonInbound: CastleWallMessage[] = [];
  let clientBuffer = new Uint8Array(0);

  const clientTransport: IpcTransport = {
    send: async (bytes: Uint8Array) => {
      // Daemon-side ingest: parse frames and push to daemonInbound.
      const merged = new Uint8Array(clientBuffer.length + bytes.length);
      merged.set(clientBuffer, 0);
      merged.set(bytes, clientBuffer.length);
      clientBuffer = merged;
      while (true) {
        const step = parseFrame(clientBuffer);
        if (step.kind === "complete") {
          clientBuffer = new Uint8Array(clientBuffer.subarray(step.consumedBytes));
          const envelope = JSON.parse(step.body) as { params?: CastleWallMessage };
          if (envelope.params) daemonInbound.push(envelope.params);
        } else if (step.kind === "need_more") {
          break;
        } else {
          throw new Error(`framing error: ${step.reason}`);
        }
      }
    },
    onData: (listener) => {
      clientListener = listener;
      return () => {
        clientListener = null;
      };
    },
    onClose: (listener) => {
      clientCloseListener = listener;
      return () => {
        clientCloseListener = null;
      };
    },
    close: async () => {
      clientListener = null;
      clientCloseListener = null;
    },
  };

  const daemonSend = async (msg: CastleWallMessage) => {
    if (!clientListener) return;
    const envelope = {
      jsonrpc: "2.0",
      method: `castle-wall.${msg.type}`,
      params: msg,
    };
    const framed = frame(JSON.stringify(envelope));
    clientListener(framed);
  };

  return {
    clientTransport,
    daemonSend,
    daemonDrop: (reason = new Error("daemon socket reset")) => {
      clientCloseListener?.(reason);
    },
    daemonInbound,
    closeAll: async () => {
      clientListener = null;
      clientCloseListener = null;
    },
  };
}

let masterKey: Uint8Array;
let identityEncKey: Uint8Array;
let signingKeyId: string;
let publicKeyBytes: Uint8Array;

beforeEach(() => {
  masterKey = generateRandomKey();
  identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { publicIdentity, storedIdentity } = createIdentity(
    "ipc-client-test",
    identityEncKey,
    "passphrase"
  );
  signingKeyId = storedIdentity.identity_id;
  publicKeyBytes = fromBase64url(publicIdentity.public_key);
});

function makeClient(transport: IpcTransport, override?: Partial<{ encryptedPrivateKey: Parameters<typeof IpcClient.create>[1]["encryptedPrivateKey"] }>) {
  // Re-derive a fresh stored identity per call so we always get a usable
  // encrypted-private-key pair without leaking state across tests.
  const { storedIdentity } = createIdentity(
    "ipc-client-test-x",
    identityEncKey,
    "passphrase"
  );
  void override;
  return IpcClient.create(
    transport,
    {
      fortressId: "deadbeef",
      signingKeyId: signingKeyId,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: identityEncKey,
    },
    { handshakeTimeoutMs: 1_000, requestTimeoutMs: 1_000 }
  );
}

describe("castle-wall/runtime/ipc-client : handshake", () => {
  it("rejects in-flight work immediately when the daemon transport drops", async () => {
    const { clientTransport, daemonSend, daemonDrop } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({
      type: "handshake_challenge",
      nonce_b64url: "AAEC",
      protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
    });
    await startP;

    const pending = client.statusRequest();
    daemonDrop();
    await expect(pending).rejects.toThrow(/transport dropped.*socket reset/i);
    expect(client.isHandshakeComplete()).toBe(false);
    await expect(client.statusRequest()).rejects.toThrow(/transport is closed/i);
  });

  it("signs the full handshake context and binds every negotiated field", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    // Use the same stored identity so we can verify the signature here.
    const { publicIdentity, storedIdentity } = createIdentity(
      "ipc-client-test-handshake",
      identityEncKey,
      "passphrase"
    );
    const pkBytes = fromBase64url(publicIdentity.public_key);
    const client = IpcClient.create(
      clientTransport,
      {
        fortressId: "deadbeef",
        signingKeyId: storedIdentity.identity_id,
        encryptedPrivateKey: storedIdentity.encrypted_private_key,
        encryptionKey: identityEncKey,
      },
      { handshakeTimeoutMs: 1_000, requestTimeoutMs: 1_000 }
    );

    const startPromise = client.start();
    // Mock daemon issues the challenge.
    const nonceB64url = "AAECAwQFBgcICQoLDA0ODw";
    await daemonSend({
      type: "handshake_challenge",
      nonce_b64url: nonceB64url,
    });
    await startPromise;

    expect(client.isHandshakeComplete()).toBe(true);
    const response = daemonInbound.find(
      (m) => m.type === "handshake_response"
    ) as HandshakeResponse | undefined;
    expect(response).toBeTruthy();
    const sigBytes = fromBase64url(response!.nonce_signature_b64url);
    const context = (overrides: Partial<Parameters<typeof handshakeSigningBytes>[0]> = {}) =>
      handshakeSigningBytes({
        nonce: fromBase64url(nonceB64url),
        fortressId: "deadbeef",
        signingKeyId: storedIdentity.identity_id,
        protocolVersion: CASTLE_WALL_IPC_PROTOCOL_VERSION,
        capabilities: CASTLE_WALL_IPC_CAPABILITIES,
        ...overrides,
      });
    expect(verify(context(), sigBytes, pkBytes)).toBe(true);
    expect(verify(fromBase64url(nonceB64url), sigBytes, pkBytes)).toBe(false);
    expect(verify(context({ fortressId: "feedface" }), sigBytes, pkBytes)).toBe(false);
    expect(
      verify(context({ signingKeyId: `${storedIdentity.identity_id}-other` }), sigBytes, pkBytes)
    ).toBe(false);
    expect(
      verify(context({ protocolVersion: CASTLE_WALL_IPC_PROTOCOL_VERSION + 1 }), sigBytes, pkBytes)
    ).toBe(false);
    expect(verify(context({ capabilities: [] }), sigBytes, pkBytes)).toBe(false);

    await client.close();
  });

  it("times out cleanly if the daemon never sends a challenge", async () => {
    const { clientTransport } = pairTransports();
    const client = makeClient(clientTransport);
    await expect(client.start()).rejects.toThrow();
  });
});

describe("castle-wall/runtime/ipc-client : status_request", () => {
  it("round-trips a status_request to the mock daemon", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const { storedIdentity } = createIdentity(
      "status-req-test",
      identityEncKey,
      "passphrase"
    );
    const client = IpcClient.create(
      clientTransport,
      {
        fortressId: "deadbeef",
        signingKeyId: storedIdentity.identity_id,
        encryptedPrivateKey: storedIdentity.encrypted_private_key,
        encryptionKey: identityEncKey,
      },
      { handshakeTimeoutMs: 1_000, requestTimeoutMs: 1_000 }
    );

    void publicKeyBytes;

    const startP = client.start();
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    await startP;

    const statusP = client.statusRequest();
    // Wait a tick for the request to be marshaled into daemonInbound.
    await new Promise((r) => setImmediate(r));
    const req = daemonInbound.find(
      (m) => m.type === "status_request"
    ) as StatusRequest | undefined;
    expect(req).toBeTruthy();
    await daemonSend({
      type: "status_response",
      request_id: req!.request_id,
      uptime_seconds: 42,
      loaded_manifest_signature_b64url: null,
      loaded_rule_count: 7,
      manifest_state: "ready" as const,
      lifecycle_state: "running",
      runtime_state: "enforcing",
      kernel_runtime_ready: true,
      enforcing: true,
      no_wall_engaged: false,
    });
    const status = await statusP;
    expect(status.uptime_seconds).toBe(42);
    expect(status.loaded_rule_count).toBe(7);

    await client.close();
  });
});

describe("castle-wall/runtime/ipc-client : policy_reload_request", () => {
  it("round-trips policy_reload to the mock daemon", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const { storedIdentity } = createIdentity(
      "policy-reload-test",
      identityEncKey,
      "passphrase"
    );
    const client = IpcClient.create(
      clientTransport,
      {
        fortressId: "deadbeef",
        signingKeyId: storedIdentity.identity_id,
        encryptedPrivateKey: storedIdentity.encrypted_private_key,
        encryptionKey: identityEncKey,
      },
      { handshakeTimeoutMs: 1_000, requestTimeoutMs: 1_000 }
    );
    const startP = client.start();
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    await startP;

    const reloadP = client.policyReload("/var/lib/sanctuary/x/policy/egress/manifest.json");
    await new Promise((r) => setImmediate(r));
    const req = daemonInbound.find(
      (m) => m.type === "policy_reload_request"
    ) as PolicyReloadRequest | undefined;
    expect(req).toBeTruthy();
    expect(req!.manifest_path).toContain("manifest.json");
    await daemonSend({
      type: "policy_reload_response",
      request_id: req!.request_id,
      ok: true,
      loaded_manifest_signature_b64url: "sig",
      loaded_rule_count: 2,
    });
    const reload = await reloadP;
    expect(reload.ok).toBe(true);
    expect(reload.loaded_rule_count).toBe(2);
    await client.close();
  });
});

describe("castle-wall/runtime/ipc-client : authenticated policy publication", () => {
  it("sends only bounded bundle bytes after the capability was handshake-bound", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({
      type: "handshake_challenge",
      nonce_b64url: "AAEC",
      protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
    });
    await startP;

    const publishP = client.publishPolicyBundle(
      new TextEncoder().encode("manifest"),
      [{ file: "rid1_example.json", bytes: new Uint8Array([0, 1, 2]) }]
    );
    await new Promise((resolve) => setImmediate(resolve));
    const request = daemonInbound.find(
      (message) => message.type === "policy_bundle_publish_request"
    ) as PolicyBundlePublishRequest | undefined;
    expect(request).toEqual(
      expect.objectContaining({
        manifest_b64url: "bWFuaWZlc3Q",
        rules: [{ file: "rid1_example.json", body_b64url: "AAEC" }],
      })
    );
    expect(JSON.stringify(request)).not.toContain("/var/");
    await daemonSend({
      type: "policy_bundle_publish_response",
      request_id: request!.request_id,
      ok: true,
      loaded_manifest_signature_b64url: "sig",
      loaded_rule_count: 1,
    });
    await expect(publishP).resolves.toEqual(
      expect.objectContaining({ ok: true, loaded_rule_count: 1 })
    );
    await client.close();
  });

  it("refuses locally when the daemon did not bind the publication capability", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    await startP;

    await expect(
      client.publishPolicyBundle(new Uint8Array(), [])
    ).rejects.toThrow(/does not advertise/);
    expect(daemonInbound.some((message) => message.type === "policy_bundle_publish_request"))
      .toBe(false);
    await client.close();
  });
});

describe("castle-wall/runtime/ipc-client : audit WAL failures", () => {
  it("rejects a drain response that could not prove a WAL snapshot", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    await startP;

    const drainP = client.drainRequest(null, 100);
    await new Promise((r) => setImmediate(r));
    const req = daemonInbound.find(
      (message) => message.type === "audit_drain_request"
    ) as AuditDrainRequest | undefined;
    expect(req).toBeTruthy();
    await daemonSend({
      type: "audit_drain_response",
      request_id: req!.request_id,
      events: [],
      next_after_seq: null,
      more_pending: false,
      wal_overflow_count: 0,
      error: "WAL lock is poisoned",
    });
    await expect(drainP).rejects.toThrow(/WAL lock is poisoned/);
    await client.close();
  });

  it("waits for explicit ACK confirmation and rejects a negative ACK", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    // A v2 daemon: it ADVERTISES the ack-response capability, so the client
    // awaits confirmation. Without the advertisement the client must fall back
    // to the pre-v2 one-way behavior (covered separately below).
    await daemonSend({
      type: "handshake_challenge",
      nonce_b64url: "AAEC",
      protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
    });
    await startP;
    expect(client.drainAcksAreConfirmed()).toBe(true);

    const ackP = client.sendDrainAck(42);
    await new Promise((r) => setImmediate(r));
    const ack = daemonInbound.find(
      (message) => message.type === "audit_drain_ack"
    ) as AuditDrainAck | undefined;
    expect(ack).toBeTruthy();
    let settled = false;
    void ackP.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      }
    );
    await new Promise((r) => setImmediate(r));
    expect(settled).toBe(false);

    await daemonSend({
      type: "audit_drain_ack_response",
      request_id: ack!.request_id,
      ok: false,
      last_acked_seq: 42,
      truncated_entries: 0,
      error: "WAL truncate failed: injected fsync error",
    });
    await expect(ackP).rejects.toThrow(/injected fsync error/);
    await client.close();
  });

  it("resolves ACK only after the daemon confirms truncation", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({
      type: "handshake_challenge",
      nonce_b64url: "AAEC",
      protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
    });
    await startP;

    const ackP = client.sendDrainAck(7);
    await new Promise((r) => setImmediate(r));
    const ack = daemonInbound.find(
      (message) => message.type === "audit_drain_ack"
    ) as AuditDrainAck | undefined;
    await daemonSend({
      type: "audit_drain_ack_response",
      request_id: ack!.request_id,
      ok: true,
      last_acked_seq: 7,
      truncated_entries: 3,
    });
    await expect(ackP).resolves.toBeUndefined();
    await client.close();
  });

  /**
   * FAIL-BEFORE for the ACK-sequence-mismatch defect (P1).
   *
   * `ok: true` alone was treated as confirmation, so a reply naming a DIFFERENT
   * sequence confirmed a truncation the daemon never applied to the sequence the
   * consumer asked about. `request_id` correlation proves which REQUEST is being
   * answered; it says nothing about which SEQUENCE was truncated (AGENTS rule 7:
   * a field must mean what its consumer treats it as meaning).
   */
  it("REFUSES an ok ACK whose last_acked_seq is not the sequence that was requested", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({
      type: "handshake_challenge",
      nonce_b64url: "AAEC",
      protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
    });
    await startP;

    const ackP = client.sendDrainAck(100);
    await new Promise((r) => setImmediate(r));
    const ack = daemonInbound.find(
      (message) => message.type === "audit_drain_ack"
    ) as AuditDrainAck | undefined;
    expect(ack).toBeTruthy();
    // Correct request_id, `ok: true`, WRONG sequence. Under the old check this
    // resolved and the consumer treated seq 100 as reclaimed.
    await daemonSend({
      type: "audit_drain_ack_response",
      request_id: ack!.request_id,
      ok: true,
      last_acked_seq: 99,
      truncated_entries: 3,
    });
    const thrown = await ackP.then(
      () => null,
      (err: unknown) => err
    );
    expect(thrown).toBeInstanceOf(RuntimeDrainError);
    expect((thrown as Error).message).toMatch(/answered for sequence 99/);
    expect((thrown as RuntimeDrainError).errorClass).toBe("terminal");
    await client.close();
  });

  /**
   * The same rule under a MALFORMED reply. A missing or non-numeric
   * `last_acked_seq` is not "close enough": the equality check is what makes the
   * confirmation mean anything, so a reply that cannot satisfy it is refused
   * rather than accepted on the strength of `ok`.
   */
  it("REFUSES an ok ACK whose last_acked_seq is missing or malformed", async () => {
    for (const malformed of [undefined, null, "100", Number.NaN]) {
      const { clientTransport, daemonSend, daemonInbound } = pairTransports();
      const client = makeClient(clientTransport);
      const startP = client.start();
      await daemonSend({
        type: "handshake_challenge",
        nonce_b64url: "AAEC",
        protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
        capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
      });
      await startP;
      const ackP = client.sendDrainAck(100);
      await new Promise((r) => setImmediate(r));
      const ack = daemonInbound.find(
        (message) => message.type === "audit_drain_ack"
      ) as AuditDrainAck | undefined;
      await daemonSend({
        type: "audit_drain_ack_response",
        request_id: ack!.request_id,
        ok: true,
        last_acked_seq: malformed,
        truncated_entries: 0,
      } as unknown as CastleWallMessage);
      await expect(ackP).rejects.toBeInstanceOf(RuntimeDrainError);
      await client.close();
    }
  });

  /**
   * CLOCK/VERSION SKEW: a pre-v2 daemon sends no `error_class`. On the ACK path
   * the consumer already holds the events durably, so an unclassified refusal is
   * safely RETRYABLE - and classifying it terminal is what turned a `systemctl
   * stop` into a permanently not-armed wall.
   */
  it("classifies ACK refusals: daemon-stated class wins, and an unclassified one is retryable", async () => {
    const cases: Array<{
      errorClass: string | undefined;
      expected: "retryable" | "terminal";
    }> = [
      { errorClass: "retryable", expected: "retryable" },
      { errorClass: "terminal", expected: "terminal" },
      // Pre-v2 daemon: no class. Safe to retry HERE because the data is durable.
      { errorClass: undefined, expected: "retryable" },
    ];
    for (const testCase of cases) {
      const { clientTransport, daemonSend, daemonInbound } = pairTransports();
      const client = makeClient(clientTransport);
      const startP = client.start();
      await daemonSend({
        type: "handshake_challenge",
        nonce_b64url: "AAEC",
        protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
        capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
      });
      await startP;
      const ackP = client.sendDrainAck(5);
      await new Promise((r) => setImmediate(r));
      const ack = daemonInbound.find(
        (message) => message.type === "audit_drain_ack"
      ) as AuditDrainAck | undefined;
      await daemonSend({
        type: "audit_drain_ack_response",
        request_id: ack!.request_id,
        ok: false,
        last_acked_seq: 5,
        truncated_entries: 0,
        error: "daemon is stopping",
        ...(testCase.errorClass ? { error_class: testCase.errorClass } : {}),
      } as unknown as CastleWallMessage);
      const thrown = await ackP.then(
        () => null,
        (err: unknown) => err
      );
      expect(thrown).toBeInstanceOf(RuntimeDrainError);
      expect((thrown as RuntimeDrainError).errorClass).toBe(testCase.expected);
      expect((thrown as RuntimeDrainError).phase).toBe("ack");
      await client.close();
    }
  });

  /**
   * The DRAIN path is the asymmetric half: it DELIVERS evidence, so an
   * unclassified failure is not assumed harmless. It stays `unclassified` and
   * the caller's bounded retry budget decides, rather than either answer being
   * invented here.
   */
  it("classifies drain failures, leaving an unclassified one explicitly unclassified", async () => {
    const cases: Array<{
      errorClass: string | undefined;
      expected: "retryable" | "terminal" | "unclassified";
    }> = [
      { errorClass: "retryable", expected: "retryable" },
      { errorClass: "terminal", expected: "terminal" },
      { errorClass: undefined, expected: "unclassified" },
    ];
    for (const testCase of cases) {
      const { clientTransport, daemonSend, daemonInbound } = pairTransports();
      const client = makeClient(clientTransport);
      const startP = client.start();
      await daemonSend({
        type: "handshake_challenge",
        nonce_b64url: "AAEC",
        protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
        capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
      });
      await startP;
      const drainP = client.drainRequest(null, 10);
      await new Promise((r) => setImmediate(r));
      const req = daemonInbound.find(
        (message) => message.type === "audit_drain_request"
      ) as { request_id: string } | undefined;
      await daemonSend({
        type: "audit_drain_response",
        request_id: req!.request_id,
        events: [],
        next_after_seq: null,
        more_pending: false,
        wal_overflow_count: 0,
        error: "WAL lock failed: WAL lock acquisition exceeded the control-operation budget",
        ...(testCase.errorClass ? { error_class: testCase.errorClass } : {}),
      } as unknown as CastleWallMessage);
      const thrown = await drainP.then(
        () => null,
        (err: unknown) => err
      );
      expect(thrown).toBeInstanceOf(RuntimeDrainError);
      expect((thrown as RuntimeDrainError).errorClass).toBe(testCase.expected);
      expect((thrown as RuntimeDrainError).phase).toBe("drain");
      await client.close();
    }
  });
});

describe("castle-wall/runtime/ipc-client : lock/unlock notifications", () => {
  it("emits unlock_notification and lock_notification messages", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const { storedIdentity } = createIdentity(
      "lock-unlock-test",
      identityEncKey,
      "passphrase"
    );
    const client = IpcClient.create(
      clientTransport,
      {
        fortressId: "f",
        signingKeyId: storedIdentity.identity_id,
        encryptedPrivateKey: storedIdentity.encrypted_private_key,
        encryptionKey: identityEncKey,
      },
      { handshakeTimeoutMs: 1_000, requestTimeoutMs: 1_000 }
    );
    const startP = client.start();
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    await startP;

    await client.sendUnlockNotification("2026-05-04T00:00:00Z");
    await client.sendLockNotification("2026-05-04T00:01:00Z");
    await new Promise((r) => setImmediate(r));

    expect(daemonInbound.some((m) => m.type === "unlock_notification")).toBe(true);
    expect(daemonInbound.some((m) => m.type === "lock_notification")).toBe(true);

    await client.close();
  });
});

describe("castle-wall/runtime/ipc-client : close rejects in-flight", () => {
  it("rejects pending requests when the transport closes", async () => {
    const { clientTransport, daemonSend } = pairTransports();
    const { storedIdentity } = createIdentity(
      "close-test",
      identityEncKey,
      "passphrase"
    );
    const client = IpcClient.create(
      clientTransport,
      {
        fortressId: "f",
        signingKeyId: storedIdentity.identity_id,
        encryptedPrivateKey: storedIdentity.encrypted_private_key,
        encryptionKey: identityEncKey,
      },
      { handshakeTimeoutMs: 1_000, requestTimeoutMs: 30_000 }
    );
    const startP = client.start();
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    await startP;
    const pending = client.statusRequest();
    await client.close();
    await expect(pending).rejects.toThrow(/dropped/);
  });
});

describe("castle-wall/runtime/ipc-client : protocol skew (owner-gated compatibility)", () => {
  /**
   * NEW DAEMON + OLD CLIENT is proven on the daemon side
   * (`the_drain_ack_response_is_withheld_from_a_legacy_peer_and_sent_to_a_v2_peer`
   * in `castle-wall-daemon/src/ipc/server.rs`). This file proves the other
   * direction: OLD DAEMON + NEW CLIENT.
   */
  it("falls back to the one-way ACK against a pre-v2 daemon instead of hanging", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    // A pre-v2 daemon: no protocol_version, no capabilities.
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    await startP;

    expect(client.daemonProtocol()).toBeNull();
    expect(client.drainAcksAreConfirmed()).toBe(false);

    // FAIL-BEFORE for the outage: with the confirmation unconditionally awaited,
    // this would sit until `requestTimeoutMs` and then REJECT. The drain cursor
    // would never advance, the daemon's WAL would grow to its cap, and
    // `evaluate_attempt` would fail closed and deny every wrapped agent's
    // egress. Resolving here is what keeps a partial upgrade from becoming an
    // outage; the weaker guarantee is reported, not hidden.
    await expect(client.sendDrainAck(42)).resolves.toBeUndefined();
    const ack = daemonInbound.find((m) => m.type === "audit_drain_ack");
    expect(ack).toBeTruthy();
    await client.close();
  });

  it("ignores an unsolicited ack_response from a daemon that never advertised it", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    await startP;

    await expect(client.sendDrainAck(7)).resolves.toBeUndefined();
    const ack = daemonInbound.find((m) => m.type === "audit_drain_ack") as
      | { request_id: string }
      | undefined;
    // A daemon that replies anyway must not break the channel: the reply has no
    // pending request behind it and is dropped, not treated as a protocol fault.
    await daemonSend({
      type: "audit_drain_ack_response",
      request_id: ack!.request_id,
      ok: true,
      last_acked_seq: 7,
      truncated_entries: 1,
    });
    await expect(client.statusRequest()).rejects.toThrow(/timed out/);
    await client.close();
  });

  it("declares its own version and capabilities in the handshake response", async () => {
    const { clientTransport, daemonSend, daemonInbound } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({
      type: "handshake_challenge",
      nonce_b64url: "AAEC",
      protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
    });
    await startP;

    const response = daemonInbound.find((m) => m.type === "handshake_response") as
      | { protocol_version?: number; capabilities?: string[] }
      | undefined;
    expect(response?.protocol_version).toBe(CASTLE_WALL_IPC_PROTOCOL_VERSION);
    // Full-SET equality, not a first-entry check: a missing token is exactly the
    // drift a partial assertion cannot see (AGENTS rule 5).
    expect([...(response?.capabilities ?? [])].sort()).toEqual(
      [...CASTLE_WALL_IPC_CAPABILITIES].sort()
    );
    expect(client.daemonProtocol()).toBe(CASTLE_WALL_IPC_PROTOCOL_VERSION);
    await client.close();
  });

  it("treats an unknown capability token as absent rather than assuming support", async () => {
    const { clientTransport, daemonSend } = pairTransports();
    const client = makeClient(clientTransport);
    const startP = client.start();
    await daemonSend({
      type: "handshake_challenge",
      nonce_b64url: "AAEC",
      protocol_version: 99,
      capabilities: ["some_future_capability"],
    });
    await startP;

    // A future daemon version alone never implies a capability: only the token
    // does. Guessing from the version number is how a client ends up awaiting a
    // reply that never comes.
    expect(client.daemonProtocol()).toBe(99);
    expect(client.drainAcksAreConfirmed()).toBe(false);
    expect(client.daemonSupports("some_future_capability")).toBe(true);
    await client.close();
  });
});
