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
  applyDidWebRotationToRecord,
  buildDidWebHealthSnapshot,
  deriveDidWebFromPrivateKey,
  didToUrl,
  dropExpiredDidWebKeys,
  identifierFromFortressDidWebRecord,
  isPublicIpAddress,
  issueDidWeb,
  parseDidWeb,
  publishDidWebDocument,
  resolveDidWeb,
  rotateDidWebKey,
} from "../../src/recognition/did-web.js";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";

const FROZEN_TIME = new Date("2026-05-09T12:00:00.000Z");

function publicKey(): Uint8Array {
  return generateKeypair().publicKey;
}

describe("WP-V1.x-RECOGNITION-LAYER did:web - issuance", () => {
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

describe("WP-V1.x-RECOGNITION-LAYER did:web - publication", () => {
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

describe("WP-V1.x-RECOGNITION-LAYER did:web - resolution (Castle-walking opt-in)", () => {
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

  it("rejects IP-literal and metadata hosts before invoking the fetcher, even when allowlisted", async () => {
    const dangerousHosts = [
      "169.254.169.254",
      "127.0.0.1",
      "10.0.0.1",
      "0x7f.0.0.1",
      "metadata.google.internal",
    ];
    for (const host of dangerousHosts) {
      let invoked = false;
      const result = await resolveDidWeb(`did:web:${host}:fortress:abc123:agent:default`, {
        allowed_hosts: [host],
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

  it("oversize Content-Length is rejected before JSON buffering", async () => {
    const result = await resolveDidWeb("did:web:alice.example.com", {
      allowed_hosts: ["alice.example.com"],
      fetcher: async () =>
        new Response("{}", {
          status: 200,
          headers: { "content-length": String(256 * 1024 + 1) },
        }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe("invalid_json");
      expect(result.message).toMatch(/exceeds/);
    }
  });

  it("chunked oversize response bodies are rejected while streaming", async () => {
    const encoder = new TextEncoder();
    let pulls = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(encoder.encode("x".repeat(128 * 1024)));
      },
      cancel() {
        pulls = Math.max(pulls, 2);
      },
    });
    const result = await resolveDidWeb("did:web:alice.example.com", {
      allowed_hosts: ["alice.example.com"],
      fetcher: async () => new Response(body, { status: 200 }),
    });
    expect(result.ok).toBe(false);
    expect(pulls).toBeGreaterThanOrEqual(2);
    if (!result.ok) {
      expect(result.failure).toBe("invalid_json");
      expect(result.message).toMatch(/exceeds/);
    }
  });

  it("small Response-compatible bodies still resolve normally", async () => {
    const key = publicKey();
    const id = await issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: key,
    });
    const result = await resolveDidWeb(id.did, {
      allowed_hosts: ["alice.example.com"],
      fetcher: async () =>
        new Response(JSON.stringify(id.did_document), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.did_document.id).toBe(id.did);
    }
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

describe("WP-V1.x-RECOGNITION-LAYER did:web - did -> URL mapping", () => {
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

  it("parseDidWeb rejects unsafe fortress_id and agent_label path segments", () => {
    const unsafeDids = [
      "did:web:alice.example.com:fortress:abc?x:agent:default",
      "did:web:alice.example.com:fortress:abc#x:agent:default",
      "did:web:alice.example.com:fortress:abc/x:agent:default",
      "did:web:alice.example.com:fortress:%2e%2e:agent:default",
      "did:web:alice.example.com:fortress:abc123:agent:default?x",
      "did:web:alice.example.com:fortress:abc123:agent:default#x",
      "did:web:alice.example.com:fortress:abc123:agent:default/x",
    ];
    for (const did of unsafeDids) {
      expect(() => parseDidWeb(did)).toThrow(/is not a valid label/);
    }
  });
});

describe("WP-V1.x-RECOGNITION-LAYER did:web - multi-fortress isolation + audit events", () => {
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
    expect(DID_WEB_AUDIT_OPS.KEY_ROTATED).toBe("did_web_key_rotated");
    expect(DID_WEB_AUDIT_OPS.OLD_KEY_DROPPED).toBe("did_web_old_key_dropped");
    expect(DID_WEB_AUDIT_OPS.HISTORICAL_VERIFICATION_USED).toBe(
      "did_web_historical_verification_used",
    );
  });
});

describe("WP-V1.x-RECOGNITION-LAYER did:web - build 4 key rotation", () => {
  async function issued() {
    return issueDidWeb({
      fortress_id: "fortress_alpha",
      authority_host: "alice.example.com",
      public_key: publicKey(),
      now: () => FROZEN_TIME,
    });
  }

  it("periodic rotation preserves the did:web identifier and makes #key-2 active", async () => {
    const id = await issued();
    const rotated = await rotateDidWebKey(id, {
      reason: "periodic",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    expect(rotated.did).toBe(id.did);
    expect(rotated.old_verification_method_id).toBe(`${id.did}#key-1`);
    expect(rotated.new_verification_method_id).toBe(`${id.did}#key-2`);
    expect(rotated.new_did_document.authentication).toEqual([`${id.did}#key-2`]);
    expect(rotated.new_did_document.verificationMethod).toHaveLength(2);
    expect(rotated.new_did_document.verificationMethod[0]!.status).toBe("previous");
  });

  it("compromised rotation revokes the old key at the rotation timestamp", async () => {
    const id = await issued();
    const rotated = await rotateDidWebKey(id, {
      reason: "compromised",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const old = rotated.new_did_document.verificationMethod[0]!;
    expect(old.status).toBe("revoked");
    expect(old.valid_until).toBe("2026-06-01T00:00:00.000Z");
    expect(old.drop_after).toBe("2026-08-30T00:00:00.000Z");
  });

  it("manual rotation honors a custom preservation window", async () => {
    const id = await issued();
    const rotated = await rotateDidWebKey(id, {
      reason: "manual",
      preserve_old_key_for: 30,
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const old = rotated.new_did_document.verificationMethod[0]!;
    expect(old.status).toBe("previous");
    expect(old.valid_until).toBe("2026-07-01T00:00:00.000Z");
    expect(old.drop_after).toBe("2026-07-01T00:00:00.000Z");
  });

  it("uses caller-supplied public key so CLI identity rotation and DID rotation stay aligned", async () => {
    const id = await issued();
    const key = publicKey();
    const rotated = await rotateDidWebKey(id, {
      reason: "manual",
      new_public_key: key,
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    expect(rotated.new_public_key_b64u).toBe(toBase64url(key));
  });

  it("rejects invalid preservation windows", async () => {
    const id = await issued();
    await expect(
      rotateDidWebKey(id, {
        reason: "manual",
        preserve_old_key_for: -1,
      }),
    ).rejects.toThrow(/preserve_old_key_for/);
  });

  it("resolves a pre-rotation assertion against the historical key", async () => {
    const id = await issued();
    const oldKey = id.public_key;
    const rotated = await rotateDidWebKey(id, {
      reason: "manual",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const result = await resolveDidWeb(id.did, {
      allowed_hosts: ["alice.example.com"],
      expected_public_key: oldKey,
      assertion_time: "2026-05-15T00:00:00.000Z",
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => rotated.new_did_document,
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.selected_verification_method_id).toBe(`${id.did}#key-1`);
      expect(result.historical_verification_used).toBe(true);
    }
  });

  it("resolves a post-rotation assertion against the new active key", async () => {
    const id = await issued();
    const newKey = publicKey();
    const rotated = await rotateDidWebKey(id, {
      reason: "manual",
      new_public_key: newKey,
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const result = await resolveDidWeb(id.did, {
      allowed_hosts: ["alice.example.com"],
      expected_public_key: newKey,
      assertion_time: "2026-06-02T00:00:00.000Z",
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => rotated.new_did_document,
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.selected_verification_method_id).toBe(`${id.did}#key-2`);
      expect(result.historical_verification_used).toBe(false);
    }
  });

  it("compromised rotation rejects old-key assertions after the rotation timestamp", async () => {
    const id = await issued();
    const rotated = await rotateDidWebKey(id, {
      reason: "compromised",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const result = await resolveDidWeb(id.did, {
      allowed_hosts: ["alice.example.com"],
      expected_public_key: id.public_key,
      assertion_time: "2026-06-02T00:00:00.000Z",
      fetcher: async () => ({
        ok: true,
        status: 200,
        json: async () => rotated.new_did_document,
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("signature_mismatch");
  });

  it("drops expired old keys after the preservation window", async () => {
    const id = await issued();
    const rotated = await rotateDidWebKey(id, {
      reason: "manual",
      preserve_old_key_for: 1,
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const out = dropExpiredDidWebKeys(
      { ...id, did_document: rotated.new_did_document },
      { now: () => new Date("2026-06-03T00:00:00.000Z") },
    );
    expect(out.dropped).toHaveLength(1);
    expect(out.did_document.verificationMethod).toHaveLength(1);
    expect(out.did_document.verificationMethod[0]!.id).toBe(`${id.did}#key-2`);
  });

  it("keeps old keys before the preservation window expires", async () => {
    const id = await issued();
    const rotated = await rotateDidWebKey(id, {
      reason: "manual",
      preserve_old_key_for: 10,
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const out = dropExpiredDidWebKeys(
      { ...id, did_document: rotated.new_did_document },
      { now: () => new Date("2026-06-03T00:00:00.000Z") },
    );
    expect(out.dropped).toHaveLength(0);
    expect(out.did_document.verificationMethod).toHaveLength(2);
  });

  it("appends rotation history to the persisted fortress record", async () => {
    const id = await issued();
    const artifact = publishDidWebDocument(id);
    const record = {
      version: 1 as const,
      identifier: {
        did: id.did,
        created_at: id.created_at,
        authority_host: id.authority_host,
        fortress_id: id.fortress_id,
        did_document: id.did_document,
      },
      artifact: {
        url: artifact.url,
        publish_path: artifact.publish_path,
        sha256: artifact.sha256,
      },
    };
    const rotated = await rotateDidWebKey(id, {
      reason: "periodic",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const rotatedIdentifier = { ...id, did_document: rotated.new_did_document };
    const updated = applyDidWebRotationToRecord(
      record,
      rotated,
      publishDidWebDocument(rotatedIdentifier),
    );
    expect(updated.key_history).toHaveLength(1);
    expect(updated.key_history![0]!.reason).toBe("periodic");
    expect(identifierFromFortressDidWebRecord(updated).did).toBe(id.did);
  });

  it("builds dashboard health from last rotation history", async () => {
    const id = await issued();
    const artifact = publishDidWebDocument(id);
    const record = {
      version: 1 as const,
      identifier: {
        did: id.did,
        created_at: id.created_at,
        authority_host: id.authority_host,
        fortress_id: id.fortress_id,
        did_document: id.did_document,
      },
      artifact: {
        url: artifact.url,
        publish_path: artifact.publish_path,
        sha256: artifact.sha256,
      },
    };
    const rotated = await rotateDidWebKey(id, {
      reason: "manual",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const updated = applyDidWebRotationToRecord(
      record,
      rotated,
      publishDidWebDocument({ ...id, did_document: rotated.new_did_document }),
    );
    const health = buildDidWebHealthSnapshot(updated, {
      now: () => new Date("2026-06-11T00:00:00.000Z"),
    });
    expect(health.configured).toBe(true);
    expect(health.last_rotation?.reason).toBe("manual");
    expect(health.days_until_recommended_rotation).toBe(355);
  });

  it("increments verification method ids across repeated rotations", async () => {
    const id = await issued();
    const first = await rotateDidWebKey(id, {
      reason: "periodic",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const second = await rotateDidWebKey(
      { ...id, did_document: first.new_did_document },
      {
        reason: "manual",
        now: () => new Date("2026-07-01T00:00:00.000Z"),
      },
    );
    expect(second.new_verification_method_id).toBe(`${id.did}#key-3`);
    expect(second.new_did_document.authentication).toEqual([`${id.did}#key-3`]);
  });

  it("published rotated DID Document contains active and historical keys", async () => {
    const id = await issued();
    const rotated = await rotateDidWebKey(id, {
      reason: "periodic",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    const artifact = publishDidWebDocument({
      ...id,
      did_document: rotated.new_did_document,
    });
    const parsed = JSON.parse(artifact.artifact) as { verificationMethod: unknown[] };
    expect(parsed.verificationMethod).toHaveLength(2);
    expect(artifact.url).toBe("https://alice.example.com/.well-known/did.json");
  });

  it("Castle-walking invariant holds: rotation itself is local and resolution remains allowlist-gated", async () => {
    const id = await issued();
    const rotated = await rotateDidWebKey(id, {
      reason: "compromised",
      now: () => new Date("2026-06-01T00:00:00.000Z"),
    });
    let invoked = false;
    const result = await resolveDidWeb(id.did, {
      allowed_hosts: [],
      expected_public_key: id.public_key,
      assertion_time: "2026-05-15T00:00:00.000Z",
      fetcher: async () => {
        invoked = true;
        return {
          ok: true,
          status: 200,
          json: async () => rotated.new_did_document,
        };
      },
    });
    expect(invoked).toBe(false);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("host_not_allowed");
  });
});

describe("isPublicIpAddress SSRF classifier (incl. IPv4-mapped IPv6 + NAT64)", () => {
  it("rejects loopback / private / link-local / metadata, mapped-v6 and NAT64; allows real public", () => {
    const nonPublic = [
      "127.0.0.1",
      "10.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "192.168.1.1",
      "::1",
      "fe80::1",
      "fc00::1",
      // IPv4-mapped IPv6 of non-public addresses (the classifier hole this closes):
      "::ffff:127.0.0.1",
      "::ffff:169.254.169.254",
      "::ffff:10.0.0.1",
      "::ffff:192.168.1.1",
      "::ffff:7f00:1", // all-hex mapped form of 127.0.0.1
      "::ffff:a9fe:a9fe", // all-hex mapped form of 169.254.169.254
      "::127.0.0.1", // deprecated IPv4-compatible form
      // NAT64 prefix wrapping a private/loopback v4:
      "64:ff9b::7f00:1",
      "64:ff9b::8.8.8.8",
    ];
    const publicAddrs = [
      "8.8.8.8",
      "1.1.1.1",
      "::ffff:8.8.8.8", // mapped form of a genuinely public v4 stays public
      "2001:4860:4860::8888",
      "2606:4700:4700::1111",
    ];
    for (const addr of nonPublic) {
      expect(isPublicIpAddress(addr)).toBe(false);
    }
    for (const addr of publicAddrs) {
      expect(isPublicIpAddress(addr)).toBe(true);
    }
  });
});
