import { describe, expect, it } from "vitest";
import {
  createIdentity,
  legacyPublicKeyToDid,
  publicKeyToDid,
} from "../src/core/identity.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";
import { generateRandomKey } from "../src/core/random.js";
import { createL1Tools } from "../src/cognitive/tools.js";
import { StateStore } from "../src/cognitive/state-store.js";
import { AuditLog } from "../src/operational/audit-log.js";
import { MemoryStorage } from "../src/storage/memory.js";

function bytesFromHex(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

async function callTool(
  tools: Array<{
    name: string;
    handler: (
      args: Record<string, unknown>
    ) => Promise<{ content: Array<{ type: string; text: string }> }>;
  }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

describe("did:key Ed25519 encoding", () => {
  it.each([
    {
      name: "W3C Ed25519 test vector",
      publicKey:
        "095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44",
      did: "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
      legacyDid: "did:key:z7QEJX5oaWV3edV2CeGhkrQPfpaT71ogyVmNk4rZeE8yeRA",
    },
    {
      name: "W3C Ed25519 with X25519 example signing key",
      publicKey:
        "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6",
      did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      legacyDid: "did:key:z7QEub8zjZwHceRSI4NCxdFzB4zpMHJ_MQcY700Pbvglw5g",
    },
  ])("matches $name", ({ publicKey, did, legacyDid }) => {
    const publicKeyBytes = bytesFromHex(publicKey);

    expect(publicKeyToDid(publicKeyBytes)).toBe(did);
    expect(legacyPublicKeyToDid(publicKeyBytes)).toBe(legacyDid);
  });

  it("creates standards-compliant DIDs for new identities", () => {
    const masterKey = generateRandomKey();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity } = createIdentity(
      "did-key-test",
      identityEncKey,
      "passphrase"
    );

    expect(publicIdentity.did).toMatch(/^did:key:z6Mk/);
    expect(publicIdentity.did).not.toMatch(/[-_]/);
  });

  it("keeps identity_verify round trips independent of DID encoding", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new StateStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog
    );
    await identityManager.load();

    const identity = await callTool(tools, "identity_create", {
      label: "did-key-round-trip",
    });
    expect(identity.did).toMatch(/^did:key:z6Mk/);

    const signed = await callTool(tools, "identity_sign", {
      identity_id: identity.identity_id,
      payload: "verify this payload",
    });
    const verified = await callTool(tools, "identity_verify", {
      identity_id: identity.identity_id,
      payload: "verify this payload",
      signature: signed.signature,
    });

    expect(verified.valid).toBe(true);
  });
});
