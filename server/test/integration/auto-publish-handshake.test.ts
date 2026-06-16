/**
 * Integration: Handshake Auto-Publish to Verascore
 *
 * Spins up a real local HTTP server (node:http) as a Verascore stand-in,
 * points SANCTUARY_VERASCORE_URL at it, runs handshake_respond, and asserts
 * the mock received a POST /api/publish with a handshake-shaped envelope.
 *
 * Also asserts that autoPublishHandshakes=false suppresses the POST entirely.
 *
 * Unlike test/handshake/auto-publish.test.ts (which mocks global fetch), this
 * test exercises the actual network path.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createHandshakeTools } from "../../src/handshake/tools.js";
import { generateSHR } from "../../src/shr/generator.js";
import { initiateHandshake } from "../../src/handshake/protocol.js";
import { defaultConfig } from "../../src/config.js";
import type { SignedSHR } from "../../src/shr/types.js";

interface Received {
  url: string | undefined;
  method: string | undefined;
  body: any;
}

function startMockVerascore(): Promise<{
  server: http.Server;
  url: string;
  received: Received[];
}> {
  return new Promise((resolve) => {
    const received: Received[] = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c.toString()));
      req.on("end", () => {
        let parsed: any = null;
        try {
          parsed = JSON.parse(body);
        } catch {
          parsed = null;
        }
        received.push({ url: req.url, method: req.method, body: parsed });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      resolve({ server, url: `http://127.0.0.1:${addr.port}`, received });
    });
  });
}

function makeAgent() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const config = defaultConfig();
  const { identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  return { storage, masterKey, config, identityManager, auditLog };
}

async function createIdentityFor(agent: ReturnType<typeof makeAgent>) {
  const { createIdentity } = await import("../../src/core/identity.js");
  const { derivePurposeKey } = await import("../../src/core/key-derivation.js");
  const encKey = derivePurposeKey(agent.masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("test-agent", encKey, "recovery-key");
  await agent.identityManager.save(storedIdentity);
  return storedIdentity;
}

async function buildChallenge() {
  const initiator = makeAgent();
  await createIdentityFor(initiator);
  const shr = generateSHR(undefined, {
    config: initiator.config,
    identityManager: initiator.identityManager,
    masterKey: initiator.masterKey,
  });
  if (typeof shr === "string") throw new Error(shr);
  const { challenge } = initiateHandshake(shr as SignedSHR);
  return challenge;
}

describe("Integration: handshake auto-publish hits live HTTP endpoint", () => {
  let mock: Awaited<ReturnType<typeof startMockVerascore>>;

  beforeEach(async () => {
    mock = await startMockVerascore();
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => mock.server.close(() => resolve()));
  });

  it("POSTs handshake envelope to Verascore /api/publish when enabled", async () => {
    // The handshake tool's auto-publish only proceeds if the URL is HTTPS.
    // We pretend the configured URL is HTTPS, then redirect the actual fetch
    // to our local HTTP mock. This exercises the full auto-publish code path
    // (URL guard, body construction, response parsing, audit log) while still
    // hitting a real network socket.
    const agent = makeAgent();
    await createIdentityFor(agent);

    const httpsUrl = mock.url.replace("http://", "https://");
    const originalFetch = globalThis.fetch;
    globalThis.fetch = ((input: any, init?: any) => {
      const urlStr = typeof input === "string" ? input : input.url;
      const redirected = urlStr.replace("https://", "http://");
      return originalFetch(redirected, init);
    }) as typeof fetch;

    try {
      const { tools } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog,
        {
          autoPublishHandshakes: true,
          verascoreUrl: httpsUrl,
        }
      );

      const challenge = await buildChallenge();
      const respondTool = tools.find((t) => t.name === "handshake_respond")!;
      const result = await respondTool.handler({ challenge });
      const parsed = JSON.parse(result.content[0]!.text);

      expect(parsed.session_id).toBeDefined();
      expect(parsed.auto_publish).toBeDefined();
      expect(parsed.auto_publish.attempted).toBe(true);
      expect(parsed.auto_publish.ok).toBe(true);
      expect(parsed.auto_publish.status).toBe(200);

      // Assert the mock actually received the POST
      expect(mock.received).toHaveLength(1);
      const r = mock.received[0]!;
      expect(r.method).toBe("POST");
      expect(r.url).toBe("/api/publish");
      expect(r.body).toBeTruthy();
      expect(r.body.type).toBe("handshake");
      expect(r.body.agentId).toBeDefined();
      expect(r.body.publicKey).toBeDefined();
      expect(r.body.data).toBeDefined();
      expect(r.body.data.type).toBe("handshake");
      expect(r.body.data.session_id).toBe(parsed.session_id);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does NOT POST when autoPublishHandshakes=false", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);

    const { tools } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog,
      {
        autoPublishHandshakes: false,
        verascoreUrl: mock.url,
      }
    );

    const challenge = await buildChallenge();
    const respondTool = tools.find((t) => t.name === "handshake_respond")!;
    const result = await respondTool.handler({ challenge });
    const parsed = JSON.parse(result.content[0]!.text);

    expect(parsed.session_id).toBeDefined();
    expect(parsed.auto_publish).toBeUndefined();
    expect(mock.received).toHaveLength(0);
  });
});
