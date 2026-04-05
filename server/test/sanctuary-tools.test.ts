/**
 * Sanctuary Meta-Tools Tests
 *
 * Covers the Phase-D tools:
 *   sanctuary_bootstrap
 *   sanctuary_policy_status
 *   sanctuary_export_identity_bundle
 *   sanctuary_link_to_human
 *   sanctuary_sign_challenge
 *
 * Uses in-memory storage, a locally-generated identity, and a fetch stub
 * to avoid real network calls.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { MemoryStorage } from "../src/storage/memory.js";
import { generateRandomKey } from "../src/core/random.js";
import { StateStore } from "../src/l1-cognitive/state-store.js";
import { AuditLog } from "../src/l2-operational/audit-log.js";
import { createL1Tools } from "../src/l1-cognitive/tools.js";
import { createSanctuaryTools } from "../src/sanctuary-tools.js";
import { DEFAULT_POLICY } from "../src/principal-policy/loader.js";
import { defaultConfig } from "../src/config.js";
import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url } from "../src/core/encoding.js";

async function callTool(
  tools: Array<{
    name: string;
    handler: (args: Record<string, unknown>) => Promise<{
      content: Array<{ type: string; text: string }>;
    }>;
  }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

function setup() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const config = defaultConfig();

  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );

  const { tools: metaTools } = createSanctuaryTools({
    config,
    identityManager,
    masterKey,
    auditLog,
    policy: DEFAULT_POLICY,
    keyProtection: "recovery-key",
  });

  return {
    storage,
    masterKey,
    config,
    identityManager,
    auditLog,
    allTools: [...l1Tools, ...metaTools],
  };
}

describe("sanctuary meta-tools", () => {
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

  describe("sanctuary_bootstrap", () => {
    it("creates an identity, generates SHR, and attempts to publish", async () => {
      const { allTools } = setup();

      const result = await callTool(allTools, "sanctuary/sanctuary_bootstrap", {
        label: "test-bootstrap",
      });

      expect(result.did).toBeDefined();
      expect((result.did as string).startsWith("did:key:z")).toBe(true);
      expect(result.identity_id).toBeDefined();
      expect(result.profileUrl).toBeDefined();
      expect((result.profileUrl as string)).toContain("/agent/");
      expect(result.tier).toBe("self-attested");
      expect(fetchSpy).toHaveBeenCalled();
      const call = fetchSpy.mock.calls[0]!;
      expect(call[0]).toContain("/api/publish");
    });

    it("returns identity without publishing when publish=false", async () => {
      const { allTools } = setup();
      const result = await callTool(allTools, "sanctuary/sanctuary_bootstrap", {
        label: "no-publish",
        publish: false,
      });
      expect(result.published).toBe(false);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("rejects non-HTTPS verascore URLs", async () => {
      const { allTools } = setup();
      const result = await callTool(allTools, "sanctuary/sanctuary_bootstrap", {
        label: "bad-url",
        verascore_url: "http://evil.example.com",
      });
      expect(result.error).toBeDefined();
      expect((result.error as string)).toMatch(/HTTPS|verascore/i);
    });
  });

  describe("sanctuary_policy_status", () => {
    it("returns tier1 and tier3 lists from the active policy", async () => {
      const { allTools } = setup();
      const result = await callTool(allTools, "sanctuary/sanctuary_policy_status");

      expect(Array.isArray(result.tier1)).toBe(true);
      expect(Array.isArray(result.tier3)).toBe(true);
      expect((result.tier1 as string[])).toContain("state_export");
      expect((result.tier1 as string[])).toContain("sanctuary_bootstrap");
      expect((result.tier3 as string[])).toContain("state_read");
      expect((result.tier3 as string[])).toContain("reputation_publish");
      expect((result.tier3 as string[])).toContain("sanctuary_policy_status");
      const counts = result.counts as { tier1: number; tier3: number };
      expect(counts.tier1).toBe((result.tier1 as string[]).length);
      expect(counts.tier3).toBe((result.tier3 as string[]).length);
    });

    it("includes Tier 2 anomaly configuration", async () => {
      const { allTools } = setup();
      const result = await callTool(allTools, "sanctuary/sanctuary_policy_status");
      expect(result.tier2_anomaly_config).toBeDefined();
      const t2 = result.tier2_anomaly_config as Record<string, unknown>;
      expect(t2.new_counterparty).toBeDefined();
    });
  });

  describe("sanctuary_export_identity_bundle", () => {
    it("exports a signed identity bundle", async () => {
      const { allTools, identityManager } = setup();
      // Create an identity first
      await callTool(allTools, "sanctuary/identity_create", { label: "bundle-test" });
      const ids = identityManager.list();
      expect(ids.length).toBeGreaterThan(0);

      const result = await callTool(
        allTools,
        "sanctuary/sanctuary_export_identity_bundle",
        {}
      );
      expect(result.bundle).toBeDefined();
      expect(result.signature).toBeDefined();
      expect(result.signed_by).toBeDefined();
      const bundle = result.bundle as Record<string, unknown>;
      expect(bundle.format).toBe("SANCTUARY_IDENTITY_BUNDLE_V1");
      expect(bundle.publicKey).toBeDefined();
      expect(bundle.did).toBeDefined();
      expect(bundle.shr).toBeDefined();
    });

    it("bundle signature verifies against the included public key", async () => {
      const { allTools } = setup();
      await callTool(allTools, "sanctuary/identity_create", { label: "verify-test" });
      const result = await callTool(
        allTools,
        "sanctuary/sanctuary_export_identity_bundle",
        { attestations: [{ id: "att-1" }] }
      );

      const bundle = result.bundle as Record<string, unknown>;
      const sig = fromBase64url(result.signature as string);
      const pub = fromBase64url(bundle.publicKey as string);
      const payload = new TextEncoder().encode(JSON.stringify(bundle));
      const valid = ed25519.verify(sig, payload, pub);
      expect(valid).toBe(true);

      // Bundle should include attestations
      expect(Array.isArray(bundle.attestations)).toBe(true);
      expect((bundle.attestations as unknown[]).length).toBe(1);
    });

    it("errors when no identity exists", async () => {
      const { allTools } = setup();
      const result = await callTool(
        allTools,
        "sanctuary/sanctuary_export_identity_bundle",
        {}
      );
      expect(result.error).toBeDefined();
    });
  });

  describe("sanctuary_link_to_human", () => {
    it("POSTs to /api/auth/request and returns ok", async () => {
      const { allTools } = setup();
      const result = await callTool(allTools, "sanctuary/sanctuary_link_to_human", {
        email: "human@example.com",
      });
      expect(result.ok).toBe(true);
      expect((result.message as string)).toContain("email");
      expect(fetchSpy).toHaveBeenCalled();
      const call = fetchSpy.mock.calls[0]!;
      expect((call[0] as string)).toContain("/api/auth/request");
      const body = JSON.parse((call[1] as { body: string }).body);
      expect(body.email).toBe("human@example.com");
    });

    it("rejects invalid email formats", async () => {
      const { allTools } = setup();
      const result = await callTool(allTools, "sanctuary/sanctuary_link_to_human", {
        email: "not-an-email",
      });
      expect(result.ok).toBe(false);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("rejects non-HTTPS verascore URL", async () => {
      const { allTools } = setup();
      const result = await callTool(allTools, "sanctuary/sanctuary_link_to_human", {
        email: "human@example.com",
        verascore_url: "http://evil.example.com",
      });
      expect(result.ok).toBe(false);
    });
  });

  describe("sanctuary_sign_challenge", () => {
    function domainMessage(purpose: string, nonce: string): Uint8Array {
      const enc = new TextEncoder();
      const tag = enc.encode("sanctuary-sign-challenge-v1");
      const p = enc.encode(purpose);
      const n = enc.encode(nonce);
      const sep = new Uint8Array([0x00]);
      const out = new Uint8Array(tag.length + 1 + p.length + 1 + n.length);
      let o = 0;
      out.set(tag, o); o += tag.length;
      out.set(sep, o); o += 1;
      out.set(p, o); o += p.length;
      out.set(sep, o); o += 1;
      out.set(n, o);
      return out;
    }

    it("signs a domain-separated nonce and verifies against the reconstructed message", async () => {
      const { allTools, identityManager } = setup();
      await callTool(allTools, "sanctuary/identity_create", { label: "sign-test" });

      const nonce = "challenge-nonce-xyz-12345";
      const purpose = "verascore-claim";
      const result = await callTool(allTools, "sanctuary/sanctuary_sign_challenge", {
        nonce,
        purpose,
      });

      expect(result.signature).toBeDefined();
      expect(result.did).toBeDefined();
      expect(result.public_key).toBeDefined();
      expect(result.domain_tag).toBe("sanctuary-sign-challenge-v1");
      expect(result.purpose).toBe(purpose);

      const sig = fromBase64url(result.signature as string);
      const pub = fromBase64url(result.public_key as string);

      // Raw-nonce signature must NOT verify (regression guard for pre-DELTA-01 behavior).
      const rawPayload = new TextEncoder().encode(nonce);
      expect(ed25519.verify(sig, rawPayload, pub)).toBe(false);

      // Domain-separated message MUST verify.
      const dsPayload = domainMessage(purpose, nonce);
      expect(ed25519.verify(sig, dsPayload, pub)).toBe(true);

      // Matches the primary identity
      const ids = identityManager.list();
      expect(result.did).toBe(ids[0]!.did);
    });

    it("signatures for different purposes do not cross-verify", async () => {
      const { allTools } = setup();
      await callTool(allTools, "sanctuary/identity_create", { label: "sign-test-2" });
      const nonce = "same-nonce-diff-purpose";
      const a = await callTool(allTools, "sanctuary/sanctuary_sign_challenge", {
        nonce,
        purpose: "verascore-claim",
      });
      const pub = fromBase64url(a.public_key as string);
      const sigA = fromBase64url(a.signature as string);
      // A signature produced for purpose='verascore-claim' must NOT verify
      // against the reconstructed message for purpose='other-service'.
      const otherMessage = domainMessage("other-service", nonce);
      expect(ed25519.verify(sigA, otherMessage, pub)).toBe(false);
    });

    it("rejects missing purpose", async () => {
      const { allTools } = setup();
      await callTool(allTools, "sanctuary/identity_create", { label: "t" });
      const result = await callTool(
        allTools,
        "sanctuary/sanctuary_sign_challenge",
        { nonce: "abc" }
      );
      expect(result.error).toBeDefined();
    });

    it("rejects empty nonces", async () => {
      const { allTools } = setup();
      await callTool(allTools, "sanctuary/identity_create", { label: "t" });
      const result = await callTool(
        allTools,
        "sanctuary/sanctuary_sign_challenge",
        { nonce: "", purpose: "verascore-claim" }
      );
      expect(result.error).toBeDefined();
    });

    it("rejects over-long nonces", async () => {
      const { allTools } = setup();
      await callTool(allTools, "sanctuary/identity_create", { label: "t" });
      const result = await callTool(
        allTools,
        "sanctuary/sanctuary_sign_challenge",
        { nonce: "x".repeat(5000), purpose: "verascore-claim" }
      );
      expect(result.error).toBeDefined();
    });

    it("rejects purposes with non-ASCII characters", async () => {
      const { allTools } = setup();
      await callTool(allTools, "sanctuary/identity_create", { label: "t" });
      const result = await callTool(
        allTools,
        "sanctuary/sanctuary_sign_challenge",
        { nonce: "abc", purpose: "ver\u0000score" }
      );
      expect(result.error).toBeDefined();
    });
  });
});
