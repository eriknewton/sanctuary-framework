/**
 * Sanctuary MCP Server — EU AI Act Verascore Publish Hook Tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests for the publish_to_verascore optional side-effect:
 *
 *   - Happy path: mocked fetch returns 200; bundle is returned with
 *     publish_result.published === true
 *   - Failure path (fetch throws): bundle still lands with
 *     publish_result.published === false and a clear error
 *   - Failure path (non-2xx response): bundle still lands with
 *     publish_result.status and error set
 *   - URL validation (non-HTTPS rejected before fetch is attempted)
 *   - URL validation (non-allowlisted host rejected)
 *   - publish_to_verascore=false or omitted → no publish_result at
 *     all in the bundle output
 *
 * NON-DEPENDENCY PRINCIPLE: the bundle must land locally in every
 * failure mode — fetch throws, fetch rejects, fetch returns 500,
 * network is unreachable, URL is malformed, host is not allow-
 * listed. Sanctuary never requires Verascore to be online.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { gcm } from "@noble/ciphers/aes.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import {
  publicKeyToDid,
  generateIdentityId,
  type StoredIdentity,
} from "../../../src/core/identity.js";
import { toBase64url } from "../../../src/core/encoding.js";
import type { EncryptedPayload } from "../../../src/core/encryption.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { IdentityManager } from "../../../src/cognitive/tools.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { defaultConfig } from "../../../src/config.js";
import {
  generateEuAiActBundle,
  type GeneratorDeps,
} from "../../../src/compliance/eu_ai_act/generator.js";
import type { ComplianceBundleInput } from "../../../src/compliance/eu_ai_act/types.js";

// ── Fixture helpers ──────────────────────────────────────────────────

const FIXED_MASTER_KEY = new Uint8Array(32).fill(0x42);
const FIXED_PRIVATE_KEY = new Uint8Array(32);
for (let i = 0; i < 32; i++) FIXED_PRIVATE_KEY[i] = (i * 7 + 13) & 0xff;
const FIXED_IV = new Uint8Array(12).fill(0x11);
const FIXED_GENERATED_AT = "2026-04-10T12:00:00.000Z";

function buildDeterministicIdentity(): StoredIdentity {
  const publicKey = ed25519.getPublicKey(FIXED_PRIVATE_KEY);
  const identityId = generateIdentityId(publicKey);
  const did = publicKeyToDid(publicKey);
  const identityEncKey = derivePurposeKey(
    FIXED_MASTER_KEY,
    "identity-encryption"
  );
  const cipher = gcm(identityEncKey, FIXED_IV);
  const ciphertext = cipher.encrypt(FIXED_PRIVATE_KEY);
  const encryptedPrivateKey: EncryptedPayload = {
    v: 1,
    alg: "aes-256-gcm",
    iv: toBase64url(FIXED_IV),
    ct: toBase64url(ciphertext),
    ts: FIXED_GENERATED_AT,
  };
  return {
    identity_id: identityId,
    label: "verascore-publish-test-fixture",
    public_key: toBase64url(publicKey),
    did,
    created_at: FIXED_GENERATED_AT,
    key_type: "ed25519",
    key_protection: "passphrase",
    encrypted_private_key: encryptedPrivateKey,
    rotation_history: [],
  };
}

async function buildFixture(): Promise<GeneratorDeps> {
  const storage = new MemoryStorage();
  const identityManager = new IdentityManager(storage, FIXED_MASTER_KEY);
  const auditLog = new AuditLog(storage, FIXED_MASTER_KEY);
  await identityManager.save(buildDeterministicIdentity());
  return {
    config: defaultConfig(),
    identityManager,
    masterKey: FIXED_MASTER_KEY,
    auditLog,
    policy: DEFAULT_POLICY,
  };
}

function inputFor(
  overrides: Partial<ComplianceBundleInput> = {}
): ComplianceBundleInput {
  return {
    agent_did: "did:sanctuary:verascore-publish-test-agent",
    deployment_context: {
      intended_purpose: "Customer support chatbot for product FAQs",
      provider_legal_name: "Publish Test Co",
    },
    period_start: "2026-04-01T00:00:00.000Z",
    period_end: "2026-04-30T23:59:59.999Z",
    generated_at_override: FIXED_GENERATED_AT,
    ...overrides,
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("Verascore publish hook", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(FIXED_GENERATED_AT));
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    vi.useRealTimers();
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("publish_to_verascore omitted → no publish_result in bundle output", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(inputFor(), deps);
    expect(bundle.publish_result).toBeUndefined();
  });

  it("publish_to_verascore=false → no publish_result in bundle output", async () => {
    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({ publish_to_verascore: false }),
      deps
    );
    expect(bundle.publish_result).toBeUndefined();
  });

  it("happy path: mocked fetch returns 200 → published: true", async () => {
    const fetchCalls: Array<{ url: string; body: unknown }> = [];
    globalThis.fetch = vi.fn(async (url, init) => {
      fetchCalls.push({
        url: String(url),
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return new Response(JSON.stringify({ success: true, id: "test-123" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({ publish_to_verascore: true }),
      deps
    );

    // Bundle still lands locally (7 documents, manifest, etc.)
    expect(bundle.files.length).toBe(7);
    expect(bundle.manifest.agent_did).toBe(
      "did:sanctuary:verascore-publish-test-agent"
    );

    // Publish result reflects success
    expect(bundle.publish_result).toBeDefined();
    expect(bundle.publish_result!.attempted).toBe(true);
    expect(bundle.publish_result!.published).toBe(true);
    expect(bundle.publish_result!.status).toBe(200);
    expect(bundle.publish_result!.error).toBeUndefined();
    expect(bundle.publish_result!.verascore_url).toBe(
      "https://verascore.ai"
    );
    expect(bundle.publish_result!.published_manifest_sha256).toMatch(
      /^[0-9a-f]{64}$/
    );

    // Fetch was called exactly once with the expected shape
    expect(fetchCalls.length).toBe(1);
    expect(fetchCalls[0]!.url).toBe("https://verascore.ai/api/publish");
    const reqBody = fetchCalls[0]!.body as {
      agentId: string;
      signature: string;
      publicKey: string;
      type: string;
      data: { bundle_version: string };
    };
    expect(reqBody.type).toBe("eu-ai-act-bundle");
    expect(reqBody.agentId).toMatch(/^did-sanctuary-/);
    expect(reqBody.signature).toBeTruthy();
    expect(reqBody.publicKey).toBe(bundle.manifest.signer.public_key_base64url);
    expect(reqBody.data.bundle_version).toBe("1.0");
  });

  it("failure path: fetch throws → bundle still lands with publish_result.published=false", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("ECONNREFUSED: simulated network failure");
    }) as unknown as typeof globalThis.fetch;

    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({ publish_to_verascore: true }),
      deps
    );

    // Bundle still generated normally
    expect(bundle.files.length).toBe(7);
    expect(bundle.manifest.files.length).toBe(7);
    for (const f of bundle.files) {
      expect(f.signature).toBeTruthy();
      expect(f.sha256).toMatch(/^[0-9a-f]{64}$/);
    }

    // Publish result reports the failure honestly
    expect(bundle.publish_result).toBeDefined();
    expect(bundle.publish_result!.attempted).toBe(true);
    expect(bundle.publish_result!.published).toBe(false);
    expect(bundle.publish_result!.error).toContain("ECONNREFUSED");
  });

  it("failure path: fetch returns 503 → bundle still lands with error and status", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(JSON.stringify({ error: "service unavailable" }), {
          status: 503,
        })
    ) as unknown as typeof globalThis.fetch;

    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({ publish_to_verascore: true }),
      deps
    );
    expect(bundle.files.length).toBe(7);
    expect(bundle.publish_result!.published).toBe(false);
    expect(bundle.publish_result!.status).toBe(503);
    expect(bundle.publish_result!.error).toContain("503");
  });

  it("URL validation: non-HTTPS rejected before fetch", async () => {
    const fetchSpy = vi.fn() as unknown as typeof globalThis.fetch;
    globalThis.fetch = fetchSpy;

    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({
        publish_to_verascore: true,
        verascore_url: "http://verascore.ai",
      }),
      deps
    );
    expect(bundle.files.length).toBe(7);
    expect(bundle.publish_result!.published).toBe(false);
    expect(bundle.publish_result!.error).toContain("HTTPS");
    // Fetch must NOT have been called — validation short-circuits
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("URL validation: non-allowlisted host rejected before fetch", async () => {
    const fetchSpy = vi.fn() as unknown as typeof globalThis.fetch;
    globalThis.fetch = fetchSpy;

    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({
        publish_to_verascore: true,
        verascore_url: "https://attacker.example.com",
      }),
      deps
    );
    expect(bundle.files.length).toBe(7);
    expect(bundle.publish_result!.published).toBe(false);
    expect(bundle.publish_result!.error).toContain("Verascore host");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("URL validation: malformed URL rejected before fetch", async () => {
    const fetchSpy = vi.fn() as unknown as typeof globalThis.fetch;
    globalThis.fetch = fetchSpy;

    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({
        publish_to_verascore: true,
        verascore_url: "not a url",
      }),
      deps
    );
    expect(bundle.files.length).toBe(7);
    expect(bundle.publish_result!.published).toBe(false);
    expect(bundle.publish_result!.error).toContain("not a valid URL");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("happy path: custom verascore_url to an allow-listed host", async () => {
    const fetchCalls: string[] = [];
    globalThis.fetch = vi.fn(async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({
        publish_to_verascore: true,
        verascore_url: "https://api.verascore.ai",
      }),
      deps
    );
    expect(bundle.publish_result!.published).toBe(true);
    expect(fetchCalls[0]).toBe("https://api.verascore.ai/api/publish");
  });

  it("publish failure never affects the cryptographic signatures of bundle documents", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("simulated failure after bundle is built");
    }) as unknown as typeof globalThis.fetch;

    const deps = await buildFixture();
    const bundle = await generateEuAiActBundle(
      inputFor({ publish_to_verascore: true }),
      deps
    );
    // Every file has a valid signature even though publish failed
    for (const file of bundle.files) {
      expect(file.signature).toBeTruthy();
      expect(file.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(bundle.manifest.manifest_signature).toBeTruthy();
  });
});
