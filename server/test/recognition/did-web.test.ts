/**
 * WP-V1.x-RECOGNITION-LAYER Path C primary regression suite.
 *
 * Covers:
 *   - Issuance shape: fortress-level + agent-level identifiers,
 *     W3C DID Document structure, verificationMethod JWK.
 *   - Validation: rejects malformed authority_host / fortress_id /
 *     agent_label / wrong public-key length.
 *   - Publication: artifact bytes, SHA-256 stability, canonical
 *     publish path for both shapes, override path.
 *   - Resolution: allowed_hosts opt-in enforcement (default
 *     denied), success path, 404, generic non-2xx, JSON parse
 *     failure, document/id mismatch, signature mismatch, timeout.
 *   - did → URL mapping for both shapes.
 *   - Multi-fortress isolation: distinct fortresses produce
 *     distinct identifiers.
 *   - Castle-walking: empty allowed_hosts refuses without opening
 *     a socket (fetcher never invoked).
 */

import { describe, it, expect } from "vitest";

import {
  DID_WEB_AUDIT_OPS,
  deriveDidWebFromPrivateKey,
  didToUrl,
  issueDidWeb,
  parseDidWeb,
  publishDidWebDocument,
  resolveDidWeb,
} from "../../src/recognition/did-web.js";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";

const FROZEN_TIME = new Date("2026-05-09T12:00:00.000Z");

function publicKey(): Uint8Array {
  return generateKeypair().publicKey;
}

describe("WP-V1.x-RECOGNITION-LAYER did:web — issuance", () => {
  it("issues a fortress-level identifier with the bare did:web:<host> shape", async () => {
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: publicKey(),
      now: () => FROZEN_TIME,
    });
    expect(id.did).toBe("did:web:alice.example.com");
    expect(id.created_at).toBe(FROZEN_TIME.toISOString());
    expect(id.agent_label).toBeUndefined();
  });

  it("issues an agent-scoped identifier with the fortress + agent path", async () => {
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      agent_label: "agent_beta",
      public_key: publicKey(),
    });
    expect(id.did).toBe(
      "did:web:alice.example.com:fortress:fortress_alpha:agent:agent_beta",
    );
    expect(id.agent_label).toBe("agent_beta");
  });

  it("DID Document includes verificationMethod with the operator's Ed25519 public key as JWK", async () => {
    const key = publicKey();
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: key,
    });
    expect(id.did_document.id).toBe(id.did);
    expect(id.did_document["@context"]).toContain(
      "https://www.w3.org/ns/did/v1",
    );
    const vm = id.did_document.verificationMethod[0]!;
    expect(vm.type).toBe("JsonWebKey2020");
    expect(vm.controller).toBe(id.did);
    expect(vm.id).toBe(`${id.did}#key-1`);
    expect(vm.publicKeyJwk.kty).toBe("OKP");
    expect(vm.publicKeyJwk.crv).toBe("Ed25519");
    expect(vm.publicKeyJwk.x).toBe(toBase64url(key));
    expect(id.did_document.authentication).toEqual([vm.id]);
    expect(id.did_document.assertionMethod).toEqual([vm.id]);
  });

  it("rejects malformed authority_host", async () => {
    await expect(
      issueDidWeb({
        fortress_id: "fortress_alpha",
        authority_host: "not a host",
        public_key: publicKey(),
      }),
    ).rejects.toThrow(/not a valid DNS host/);
  });

  it("rejects malformed agent_label", async () => {
    await expect(
      issueDidWeb({
        fortress_id: "fortress_alpha",
        authority_host: "alice.example.com",
        agent_label: "has spaces",
        public_key: publicKey(),
      }),
    ).rejects.toThrow(/not a valid label/);
  });

  it("rejects a public key that is not 32 bytes", async () => {
    await expect(
      issueDidWeb({
        fortress_id: "fortress_alpha",
        authority_host: "alice.example.com",
        public_key: new Uint8Array(16),
      }),
    ).rejects.toThrow(/must be exactly 32 bytes/);
  });

  it("deriveDidWebFromPrivateKey produces an identifier whose verificationMethod matches the public-key derivation", async () => {
    const { publicKey, privateKey } = generateKeypair();
    const id = await deriveDidWebFromPrivateKey({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      private_key: privateKey,
    });
    expect(id.did_document.verificationMethod[0]!.publicKeyJwk.x).toBe(
      toBase64url(publicKey),
    );
  });
});

describe("WP-V1.x-RECOGNITION-LAYER did:web — publication", () => {
  it("canonical publish path for fortress-level is /.well-known/did.json", async () => {
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: publicKey(),
    });
    const out = publishDidWebDocument(id);
    expect(out.publish_path).toBe("/.well-known/did.json");
    expect(out.url).toBe("https://alice.example.com/.well-known/did.json");
  });

  it("canonical publish path for agent-scoped follows the spec colon-to-slash mapping", async () => {
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      agent_label: "agent_beta",
      public_key: publicKey(),
    });
    const out = publishDidWebDocument(id);
    expect(out.publish_path).toBe(
      "/fortress/fortress_alpha/agent/agent_beta/did.json",
    );
    expect(out.url).toBe(
      "https://alice.example.com/fortress/fortress_alpha/agent/agent_beta/did.json",
    );
  });

  it("artifact bytes are deterministic; same identifier produces same SHA-256", async () => {
    const key = publicKey();
    const a = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: key,
      now: () => FROZEN_TIME,
    });
    const b = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: key,
      now: () => FROZEN_TIME,
    });
    const outA = publishDidWebDocument(a);
    const outB = publishDidWebDocument(b);
    expect(outA.artifact).toBe(outB.artifact);
    expect(outA.sha256).toBe(outB.sha256);
  });

  it("publishDidWebDocument honors an explicit publish_path override", async () => {
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: publicKey(),
    });
    const out = publishDidWebDocument(id, { publish_path: "/custom/did.json" });
    expect(out.publish_path).toBe("/custom/did.json");
    expect(out.url).toBe("https://alice.example.com/custom/did.json");
  });
});

describe("WP-V1.x-RECOGNITION-LAYER did:web — resolution (Castle-walking opt-in)", () => {
  it("empty allowed_hosts refuses without invoking the fetcher (no-outbound-by-default)", async () => {
    let invoked = false;
    const result = await resolveDidWeb("did:web:alice.example.com", {
      allowed_hosts: [],
      fetcher: async () => {
        invoked = true;
        return { ok: true, status: 200, json: async () => ({}) };
      },
    });
    expect(invoked).toBe(false);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe("host_not_allowed");
    }
  });

  it("allowed authority host invokes the fetcher and returns the parsed DID Document on 200", async () => {
    const key = publicKey();
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: key,
    });
    const result = await resolveDidWeb(id.did, {
      allowed_hosts: ["alice.example.com"],
      fetcher: async (url) => ({
        ok: true,
        status: 200,
        json: async () => id.did_document,
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.did_document.id).toBe(id.did);
    }
  });

  it("404 from the authority host returns not_found", async () => {
    const result = await resolveDidWeb("did:web:alice.example.com", {
      allowed_hosts: ["alice.example.com"],
      fetcher: async () => ({
        ok: false,
        status: 404,
        json: async () => ({}),
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("not_found");
  });

  it("non-404 non-2xx returns fetch_failed", async () => {
    const result = await resolveDidWeb("did:web:alice.example.com", {
      allowed_hosts: ["alice.example.com"],
      fetcher: async () => ({
        ok: false,
        status: 503,
        json: async () => ({}),
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("fetch_failed");
  });

  it("invalid JSON returns invalid_json", async () => {
    const result = await resolveDidWeb("did:web:alice.example.com", {
      allowed_hosts: ["alice.example.com"],
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new Error("unexpected token");
        },
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("invalid_json");
  });

  it("body that does not look like a DID Document for the requested DID returns invalid_json", async () => {
    const result = await resolveDidWeb("did:web:alice.example.com", {
      allowed_hosts: ["alice.example.com"],
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ id: "did:web:bob.example.com" }),
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("invalid_json");
  });

  it("signature mismatch: expected_public_key not matching returns signature_mismatch", async () => {
    const idKey = publicKey();
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: idKey,
    });
    const otherKey = publicKey();
    const result = await resolveDidWeb(id.did, {
      allowed_hosts: ["alice.example.com"],
      expected_public_key: otherKey,
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => id.did_document,
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("signature_mismatch");
  });

  it("timeout: fetcher throwing an AbortError-shaped signal returns timeout", async () => {
    const result = await resolveDidWeb("did:web:alice.example.com", {
      allowed_hosts: ["alice.example.com"],
      timeout_ms: 5,
      fetcher: async (_url, init) => {
        await new Promise((resolve) => setTimeout(resolve, 50));
        if (init?.signal?.aborted) {
          const err = new Error("aborted");
          err.name = "AbortError";
          throw err;
        }
        return { ok: true, status: 200, json: async () => ({}) };
      },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("timeout");
  });
});

describe("WP-V1.x-RECOGNITION-LAYER did:web — did → URL mapping", () => {
  it("fortress-level did:web:<host> maps to /.well-known/did.json", () => {
    const parsed = parseDidWeb("did:web:alice.example.com");
    expect(didToUrl(parsed)).toBe(
      "https://alice.example.com/.well-known/did.json",
    );
  });

  it("agent-scoped did:web maps to /fortress/<fid>/agent/<alabel>/did.json", () => {
    const parsed = parseDidWeb(
      "did:web:alice.example.com:fortress:fortress_alpha:agent:agent_beta",
    );
    expect(didToUrl(parsed)).toBe(
      "https://alice.example.com/fortress/fortress_alpha/agent/agent_beta/did.json",
    );
  });

  it("parseDidWeb rejects non did:web identifiers", () => {
    expect(() => parseDidWeb("did:key:zABC")).toThrow(/is not a did:web/);
  });

  it("parseDidWeb rejects unsupported path shapes", () => {
    expect(() =>
      parseDidWeb("did:web:alice.example.com:something:else"),
    ).toThrow(/does not match the supported shapes/);
  });
});

describe("WP-V1.x-RECOGNITION-LAYER did:web — multi-fortress isolation + audit events", () => {
  it("two fortresses on the same authority host produce distinct agent-scoped DIDs", async () => {
    const a = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      agent_label: "default",
      public_key: publicKey(),
    });
    const b = await issueDidWeb({
      fortress_id: "fortress_beta",
      authority_host: "alice.example.com",
      agent_label: "default",
      public_key: publicKey(),
    });
    expect(a.did).not.toBe(b.did);
    expect(a.did_document.id).not.toBe(b.did_document.id);
  });

  it("exposes stable audit-op constants for downstream emitters", () => {
    expect(DID_WEB_AUDIT_OPS.ISSUED).toBe("did_web_issued");
    expect(DID_WEB_AUDIT_OPS.RESOLVED).toBe("did_web_resolved");
    expect(DID_WEB_AUDIT_OPS.PUBLISHED).toBe("did_web_published");
  });
});
