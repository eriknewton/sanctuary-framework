/**
 * Castle Wall lifecycle tests.
 *
 * Spins up startCastleWall against an in-process mock daemon transport,
 * runs the handshake, exercises the audit consumer + approval stub through
 * the lifecycle handle, and verifies the stop() drain.
 */

import { describe, it, expect, beforeEach } from "vitest";

import { healthCheck, startCastleWall } from "../../../src/castle-wall/runtime/lifecycle.js";
import {
  CASTLE_WALL_IPC_CAPABILITIES,
  CASTLE_WALL_IPC_PROTOCOL_VERSION,
} from "../../../src/castle-wall/ipc/messages.js";
import {
  type AuditSink,
} from "../../../src/castle-wall/runtime/audit-consumer.js";
import { frame, parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import type {
  CastleWallMessage,
} from "../../../src/castle-wall/ipc/messages.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { IpcClient, type IpcTransport } from "../../../src/castle-wall/runtime/ipc-client.js";

class CountingSink implements AuditSink {
  count = 0;
  flushes = 0;
  append(): void {
    this.count += 1;
  }
  async flush(): Promise<void> {
    this.flushes += 1;
  }
}

function buildMockTransport(): {
  transport: IpcTransport;
  daemonSend: (msg: CastleWallMessage) => Promise<void>;
} {
  let listener: ((bytes: Uint8Array) => void) | null = null;
  let buffer = new Uint8Array(0);
  return {
    transport: {
      send: async (bytes: Uint8Array) => {
        const merged = new Uint8Array(buffer.length + bytes.length);
        merged.set(buffer, 0);
        merged.set(bytes, buffer.length);
        buffer = merged;
        while (true) {
          const step = parseFrame(buffer);
          if (step.kind === "complete") {
            buffer = new Uint8Array(buffer.subarray(step.consumedBytes));
          } else if (step.kind === "need_more") {
            break;
          } else {
            throw new Error(`framing error: ${step.reason}`);
          }
        }
      },
      onData: (l) => {
        listener = l;
        return () => {
          listener = null;
        };
      },
      close: async () => {
        listener = null;
      },
    },
    daemonSend: async (msg) => {
      if (!listener) return;
      listener(
        frame(
          JSON.stringify({
            jsonrpc: "2.0",
            method: `castle-wall.${msg.type}`,
            params: msg,
          })
        )
      );
    },
  };
}

let identityEncKey: Uint8Array;

beforeEach(() => {
  const masterKey = generateRandomKey();
  identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
});

describe("castle-wall/runtime/lifecycle : startCastleWall", () => {
  it("transitions through handshaking -> running on a successful handshake", async () => {
    const { transport, daemonSend } = buildMockTransport();
    const sink = new CountingSink();
    const { storedIdentity } = createIdentity(
      "lifecycle-test",
      identityEncKey,
      "passphrase"
    );
    const startP = startCastleWall({
      transport,
      key: {
        fortressId: "f",
        signingKeyId: storedIdentity.identity_id,
        encryptedPrivateKey: storedIdentity.encrypted_private_key,
        encryptionKey: identityEncKey,
      },
      auditSink: sink,
      handshakeTimeoutMs: 1_000,
    });
    await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    const handle = await startP;
    expect(handle.state()).toBe("running");
    expect(handle.client().isHandshakeComplete()).toBe(true);
    expect(handle.audit().getStats().acceptedCriticalEvents).toBe(0);
    expect(handle.approval().pendingCount()).toBe(0);
    await handle.stop();
    expect(handle.state()).toBe("stopped");
  });

  it("error state propagates if handshake never completes", async () => {
    const { transport } = buildMockTransport();
    const sink = new CountingSink();
    const { storedIdentity } = createIdentity(
      "lifecycle-fail-test",
      identityEncKey,
      "passphrase"
    );
    await expect(
      startCastleWall({
        transport,
        key: {
          fortressId: "f",
          signingKeyId: storedIdentity.identity_id,
          encryptedPrivateKey: storedIdentity.encrypted_private_key,
          encryptionKey: identityEncKey,
        },
        auditSink: sink,
        handshakeTimeoutMs: 50,
      })
    ).rejects.toThrow();
  });

  it("stop() drains pending approval prompts to timeout_default_deny", async () => {
    const { transport, daemonSend } = buildMockTransport();
    const sink = new CountingSink();
    const { storedIdentity } = createIdentity(
      "lifecycle-drain-test",
      identityEncKey,
      "passphrase"
    );
    const handle = await (async () => {
      const startP = startCastleWall({
        transport,
        key: {
          fortressId: "f",
          signingKeyId: storedIdentity.identity_id,
          encryptedPrivateKey: storedIdentity.encrypted_private_key,
          encryptionKey: identityEncKey,
        },
        auditSink: sink,
        handshakeTimeoutMs: 1_000,
        promptTimeoutMs: 60_000,
      });
      await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
      return await startP;
    })();
    const promptP = handle.approval().process({
      type: "decision_request",
      request_id: "x",
      surface: "egress",
      destination: {
        host: "example.com",
        ip: "1.2.3.4",
        port: 443,
        protocol: "tcp",
        hostname_source: "dns",
        opaque: false,
      },
      agent: { id: "a", template: "t" },
      timeout_seconds: 30,
    });
    expect(handle.approval().pendingCount()).toBe(1);
    await handle.stop();
    const decision = await promptP;
    expect(decision.decision).toBe("timeout_default_deny");
  });
});

/**
 * A mock daemon that ANSWERS `status_request`, so `healthCheck` can be exercised
 * end to end. `buildMockTransport` above deliberately discards client frames,
 * which is right for the handshake tests but cannot serve a status round-trip.
 */
function buildRespondingDaemon(options: {
  capabilities?: string[];
  protocolVersion?: number | null;
  status?: Record<string, unknown>;
}): { transport: IpcTransport; sendChallenge: () => Promise<void> } {
  let listener: ((bytes: Uint8Array) => void) | null = null;
  let buffer = new Uint8Array(0);
  const emit = (msg: Record<string, unknown>): void => {
    if (!listener) throw new Error("mock daemon: no listener attached");
    listener(
      frame(
        JSON.stringify({
          jsonrpc: "2.0",
          method: `castle-wall.${String(msg.type)}`,
          params: msg,
        })
      )
    );
  };
  return {
    transport: {
      send: async (bytes: Uint8Array) => {
        const merged = new Uint8Array(buffer.length + bytes.length);
        merged.set(buffer, 0);
        merged.set(bytes, buffer.length);
        buffer = merged;
        while (true) {
          const step = parseFrame(buffer);
          if (step.kind !== "complete") break;
          const body = step.body;
          buffer = new Uint8Array(buffer.subarray(step.consumedBytes));
          const env = JSON.parse(body) as { params?: { type?: string; request_id?: string } };
          if (env.params?.type === "status_request") {
            emit({
              type: "status_response",
              request_id: env.params.request_id,
              uptime_seconds: 9,
              loaded_manifest_signature_b64url: "sig",
              loaded_rule_count: 2,
              no_wall_engaged: false,
              manifest_state: "ready" as const,
              lifecycle_state: "running",
              runtime_state: "kernel_runtime_ready",
              kernel_runtime_ready: true,
              enforcing: false,
              runtime_health: "ready",
              ...(options.status ?? {}),
            });
          }
        }
      },
      onData: (l) => {
        listener = l;
        return () => {
          listener = null;
        };
      },
      close: async () => {
        listener = null;
      },
    },
    sendChallenge: async () => {
      for (let i = 0; i < 500 && !listener; i++) {
        await new Promise((r) => setTimeout(r, 1));
      }
      const pv = options.protocolVersion;
      emit({
        type: "handshake_challenge",
        nonce_b64url: "AAEC",
        ...(pv === null || pv === undefined ? {} : { protocol_version: pv }),
        ...(options.capabilities && options.capabilities.length > 0
          ? { capabilities: options.capabilities }
          : {}),
      });
    },
  };
}

describe("castle-wall/runtime/lifecycle : healthCheck and the audit-ACK gate", () => {
  async function connect(options: Parameters<typeof buildRespondingDaemon>[0]) {
    const daemon = buildRespondingDaemon(options);
    const { storedIdentity } = createIdentity("health-test", identityEncKey, "passphrase");
    const startP = startCastleWall({
      transport: daemon.transport,
      key: {
        fortressId: "f",
        signingKeyId: storedIdentity.identity_id,
        encryptedPrivateKey: storedIdentity.encrypted_private_key,
        encryptionKey: identityEncKey,
      },
      auditSink: new CountingSink(),
      handshakeTimeoutMs: 1_000,
    });
    await daemon.sendChallenge();
    return await startP;
  }

  it("reports ok on a live runtime with CONFIRMED acks", async () => {
    const handle = await connect({
      protocolVersion: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
    });
    const health = await healthCheck(handle.client());
    expect(health.readiness).toBe("kernel_runtime_ready");
    expect(health.auditAckConfirmed).toBe(true);
    expect(health.ok).toBe(true);
    // Still NOT complete enforcement: no agent is wrapped in this slice.
    expect(health.enforcementComplete).toBe(false);
    await handle.stop();
  });

  /**
   * OWNER RULING: the two conditions are independent, and BOTH are required.
   * This is the input a runtime-only gate would wave through.
   */
  it("refuses ok on a live runtime with UNCONFIRMED acks", async () => {
    const handle = await connect({ protocolVersion: null, capabilities: [] });
    const health = await healthCheck(handle.client());
    expect(health.readiness).toBe("kernel_runtime_ready");
    expect(health.indeterminate).toBe(false);
    expect(health.auditAckConfirmed).toBe(false);
    expect(health.ok).toBe(false);
    expect(health.enforcementComplete).toBe(false);
    await handle.stop();
  });

  /**
   * The strongest claim needs BOTH a gated agent and a confirmed channel. An
   * unconfirmed peer reporting `enforcing` must not produce a
   * complete-enforcement claim.
   */
  it("refuses a complete-enforcement claim on an unconfirmed channel", async () => {
    const unconfirmed = await connect({
      protocolVersion: null,
      capabilities: [],
      status: { runtime_state: "enforcing", kernel_runtime_ready: true, enforcing: true },
    });
    const weak = await healthCheck(unconfirmed.client());
    expect(weak.readiness).toBe("enforcing");
    expect(weak.enforcementComplete).toBe(false);
    expect(weak.ok).toBe(false);
    await unconfirmed.stop();

    const confirmed = await connect({
      protocolVersion: CASTLE_WALL_IPC_PROTOCOL_VERSION,
      capabilities: [...CASTLE_WALL_IPC_CAPABILITIES],
      status: { runtime_state: "enforcing", kernel_runtime_ready: true, enforcing: true },
    });
    const strong = await healthCheck(confirmed.client());
    expect(strong.enforcementComplete).toBe(true);
    expect(strong.ok).toBe(true);
    await confirmed.stop();
  });

  it("refuses to health-check before the handshake completes", async () => {
    // The guard exists so a caller cannot query status on an unauthenticated
    // channel and treat the answer as evidence. Built directly (never started)
    // so the pre-handshake window is actually reachable.
    const daemon = buildRespondingDaemon({});
    const { storedIdentity } = createIdentity("health-test-2", identityEncKey, "passphrase");
    const client = IpcClient.create(daemon.transport, {
      fortressId: "f",
      signingKeyId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: identityEncKey,
    });
    expect(client.isHandshakeComplete()).toBe(false);
    await expect(healthCheck(client)).rejects.toThrow(/handshake not complete/);
    // And no capability may be assumed before negotiation either.
    expect(client.drainAcksAreConfirmed()).toBe(false);
  });
});
