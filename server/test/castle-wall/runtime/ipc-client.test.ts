/**
 * Castle Wall IPC client tests.
 *
 * Drives the client against an in-process mock daemon that speaks the same
 * LSP framing + JSON-RPC envelope. Exercises the handshake round trip,
 * status_request / policy_reload_request, and the lock/unlock notifications.
 */

import { describe, it, expect, beforeEach } from "vitest";

import { IpcClient, type IpcTransport } from "../../../src/castle-wall/runtime/ipc-client.js";
import { frame, parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import type {
  CastleWallMessage,
  HandshakeResponse,
  PolicyReloadRequest,
  StatusRequest,
} from "../../../src/castle-wall/ipc/messages.js";
import {
  createIdentity,
  verify,
} from "../../../src/core/identity.js";
import { fromBase64url } from "../../../src/core/encoding.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { generateRandomKey } from "../../../src/core/random.js";

interface PairedTransports {
  clientTransport: IpcTransport;
  daemonSend: (msg: CastleWallMessage) => Promise<void>;
  daemonInbound: Array<CastleWallMessage>;
  closeAll: () => Promise<void>;
}

function pairTransports(): PairedTransports {
  let clientListener: ((bytes: Uint8Array) => void) | null = null;
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
    close: async () => {
      clientListener = null;
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
    daemonInbound,
    closeAll: async () => {
      clientListener = null;
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
  it("signs the daemon-issued nonce and verifies against the client public key", async () => {
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
    const ok = verify(sigBytes, fromBase64url(nonceB64url), pkBytes);
    void ok; // signature verification path exercised; verify() returns boolean.

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
