/**
 * B2 daemon helper-signing-path integration tests.
 *
 * Asserts the production default (helper-signed):
 *  - the manifest is signed via the shim and verifies against K_helper (so a
 *    successful start proves the helper signature is accepted);
 *  - a shim failure fails the daemon CLOSED (no unsigned manifest, no local-key
 *    fallback);
 *  - the handshake nonce is signed via the helper and verifies against K_helper.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519";
import { parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { fromBase64url, toBase64url } from "../../../src/core/encoding.js";
import {
  startMacOSCastleWallDaemon,
  type MacOSCastleWallListenerOptions,
} from "../../../src/castle-wall/runtime/index.js";
import type { ShimInvoker } from "../../../src/castle-wall/runtime/helper-signer.js";

function makeMockHelper() {
  const seed = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(seed);
  const invoke: ShimInvoker = async (args, stdin) => {
    const mode = args[0];
    if (mode === "get-pubkey" || mode === "re-pin") {
      return { stdout: toBase64url(pub), stderr: "", code: 0 };
    }
    const sig = ed25519.sign(stdin ?? new Uint8Array(0), seed);
    return { stdout: toBase64url(sig), stderr: "", code: 0 };
  };
  return { pub, invoke };
}

describe("Castle Wall macOS daemon — helper signing path (B2)", () => {
  const tempDirs: string[] = [];
  const liveSockets: Socket[] = [];

  afterEach(async () => {
    for (const socket of liveSockets.splice(0)) socket.destroy();
    for (const dir of tempDirs.splice(0)) await rm(dir, { recursive: true, force: true });
  });

  async function provisionFortress() {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-helper-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    return { fortressPath, masterKey, auditLog };
  }

  function fakeListenerFactory(options: MacOSCastleWallListenerOptions) {
    return {
      async start() {
        await writeFile(options.socketPath, "");
      },
      async stop() {
        await unlink(options.socketPath).catch(() => {});
      },
      async broadcastManifestUpdate() {
        return 0;
      },
      async broadcastDecisionResponse() {
        return 0;
      },
    };
  }

  it("signs the manifest via the shim and starts (verifies against K_helper)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const helper = makeMockHelper();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-helper",
      masterKey,
      auditLog,
      platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"),
      socketPath: join(fortressPath, "castle.sock"),
      listenerFactory: fakeListenerFactory,
      signerClientInvoke: helper.invoke,
    });
    // A successful start means loadManifestState's internal
    // verifyManifestSignature(signed, K_helper) passed — i.e. the shim signature
    // is accepted. Tear down.
    await handle.stop();
  });

  it("fails CLOSED when the shim errors (no unsigned manifest)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const brokenInvoke: ShimInvoker = async () => ({
      stdout: "",
      stderr: "helper down",
      code: 1,
    });
    await expect(
      startMacOSCastleWallDaemon({
        fortressPath,
        fortressId: "fortress-helper",
        masterKey,
        auditLog,
        platform: "darwin",
        activeConfigPath: join(fortressPath, "active.json"),
        socketPath: join(fortressPath, "castle.sock"),
        listenerFactory: fakeListenerFactory,
        signerClientInvoke: brokenInvoke,
      }),
    ).rejects.toThrow();
  });

  it("fails CLOSED when no signer is configured at all", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    await expect(
      startMacOSCastleWallDaemon({
        fortressPath,
        fortressId: "fortress-helper",
        masterKey,
        auditLog,
        platform: "darwin",
        activeConfigPath: join(fortressPath, "active.json"),
        socketPath: join(fortressPath, "castle.sock"),
        listenerFactory: fakeListenerFactory,
        // no localSign, no signerClientInvoke, no signerClientPath
      }),
    ).rejects.toThrow(/helper signing is unavailable/);
  });

  it("signs the handshake nonce via the helper (verifies against K_helper)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const helper = makeMockHelper();
    const socketPath = join(fortressPath, "castle.sock");
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-helper",
      masterKey,
      auditLog,
      platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"),
      socketPath,
      signerClientInvoke: helper.invoke,
    });

    try {
      const socket = createConnection(socketPath);
      liveSockets.push(socket);
      await new Promise<void>((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
      });

      let buffer = Buffer.alloc(0);
      const messages: Record<string, unknown>[] = [];
      const collected = new Promise<void>((resolve) => {
        socket.on("data", (chunk: Buffer) => {
          buffer = Buffer.concat([buffer, chunk]);
          while (buffer.length > 0) {
            const parsed = parseFrame(new Uint8Array(buffer));
            if (parsed.kind === "need_more") break;
            if (parsed.kind === "error") return;
            buffer = buffer.subarray(parsed.consumedBytes);
            const envelope = JSON.parse(parsed.body) as { params?: Record<string, unknown> };
            messages.push(envelope.params ?? envelope);
            if (messages.length >= 2) resolve();
          }
        });
      });
      await collected;

      const challenge = messages.find((m) => m.type === "handshake_challenge")!;
      const response = messages.find((m) => m.type === "handshake_response")!;
      expect(challenge).toBeTruthy();
      expect(response).toBeTruthy();
      const nonce = fromBase64url(challenge.nonce_b64url as string);
      const sig = fromBase64url(response.nonce_signature_b64url as string);
      expect(ed25519.verify(sig, nonce, helper.pub)).toBe(true);
    } finally {
      await handle.stop();
    }
  });
});
