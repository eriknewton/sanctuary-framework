/**
 * Handshake Auto-Publish Hook Tests
 *
 * Verifies that handshake_respond auto-publishes a handshake attestation
 * to Verascore when the autoPublishHandshakes config flag is enabled,
 * and respects the flag when disabled.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { createHandshakeTools } from "../../src/handshake/tools.js";
import { generateSHR } from "../../src/shr/generator.js";
import { initiateHandshake } from "../../src/handshake/protocol.js";
import { defaultConfig } from "../../src/config.js";
import type { SignedSHR } from "../../src/shr/types.js";

function makeAgent() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const config = defaultConfig();
  const { identityManager } = createL1Tools(
    stateStore, storage, masterKey, "recovery-key", auditLog
  );
  return { storage, masterKey, config, identityManager, auditLog };
}

async function createIdentityFor(agent: ReturnType<typeof makeAgent>) {
  // Use the identity manager directly to create + save one identity.
  const { createIdentity } = await import("../../src/core/identity.js");
  const { derivePurposeKey } = await import("../../src/core/key-derivation.js");
  const encKey = derivePurposeKey(agent.masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("test-agent", encKey, "recovery-key");
  await agent.identityManager.save(storedIdentity);
  return storedIdentity;
}

describe("Handshake auto-publish hook", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ success: true }),
    } as unknown as Response));
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function buildResponder(autoPublish: boolean) {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const { tools } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog,
      {
        autoPublishHandshakes: autoPublish,
        verascoreUrl: "https://verascore.ai",
      }
    );
    return { agent, tools };
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

  it("auto-publishes when autoPublishHandshakes=true and signs the envelope", async () => {
    const { tools } = await buildResponder(true);
    const challenge = await buildChallenge();

    const respondTool = tools.find((t) => t.name === "handshake_respond")!;
    const result = await respondTool.handler({ challenge });
    const parsed = JSON.parse(result.content[0]!.text);

    expect(parsed.session_id).toBeDefined();
    expect(parsed.auto_publish).toBeDefined();
    expect(parsed.auto_publish.attempted).toBe(true);
    expect(parsed.auto_publish.ok).toBe(true);
    expect(parsed.auto_publish.status).toBe(200);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const call = fetchSpy.mock.calls[0]!;
    expect((call[0] as string)).toContain("/api/publish");
    const body = JSON.parse((call[1] as { body: string }).body);
    expect(body.type).toBe("handshake");
    expect(body.agentId).toBeDefined();
    // DELTA-05: envelope MUST be signed
    expect(typeof body.signature).toBe("string");
    expect(body.signature.length).toBeGreaterThan(0);
    expect(typeof body.publicKey).toBe("string");

    // DELTA-05: verify the signature against JSON.stringify(data) + publicKey
    const { ed25519 } = await import("@noble/curves/ed25519");
    const { fromBase64url } = await import("../../src/core/encoding.js");
    const sig = fromBase64url(body.signature);
    const pub = fromBase64url(body.publicKey);
    const msg = new TextEncoder().encode(JSON.stringify(body.data));
    expect(ed25519.verify(sig, msg, pub)).toBe(true);

    // DELTA-04: counterparty-identifying fields are redacted by default.
    expect(body.data.counterparty_signed_by).toBe("redacted");
  });

  it("does NOT publish when autoPublishHandshakes=false", async () => {
    const { tools } = await buildResponder(false);
    const challenge = await buildChallenge();

    const respondTool = tools.find((t) => t.name === "handshake_respond")!;
    const result = await respondTool.handler({ challenge });
    const parsed = JSON.parse(result.content[0]!.text);

    expect(parsed.session_id).toBeDefined();
    expect(parsed.auto_publish).toBeUndefined();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("does not block the handshake response if publish fails", async () => {
    fetchSpy.mockImplementationOnce(async () => {
      throw new Error("network down");
    });
    const { tools } = await buildResponder(true);
    const challenge = await buildChallenge();

    const respondTool = tools.find((t) => t.name === "handshake_respond")!;
    const result = await respondTool.handler({ challenge });
    const parsed = JSON.parse(result.content[0]!.text);

    expect(parsed.session_id).toBeDefined();
    expect(parsed.response).toBeDefined();
    expect(parsed.auto_publish.attempted).toBe(true);
    expect(parsed.auto_publish.error).toContain("network down");
  });
});
