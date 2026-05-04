/**
 * Castle Wall lifecycle tests.
 *
 * Spins up startCastleWall against an in-process mock daemon transport,
 * runs the handshake, exercises the audit consumer + approval stub through
 * the lifecycle handle, and verifies the stop() drain.
 */

import { describe, it, expect, beforeEach } from "vitest";

import { startCastleWall } from "../../../src/castle-wall/runtime/lifecycle.js";
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
import type { IpcTransport } from "../../../src/castle-wall/runtime/ipc-client.js";

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
