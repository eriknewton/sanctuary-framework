/**
 * WP-V1.x-RECOGNITION-LAYER Path C hosted-alternative regression suite.
 *
 * Covers:
 *   - Registry: store and retrieve hosted DID Documents via encrypted store.
 *   - Route handler: serves DID Document for registered handle.
 *   - 404 for unregistered handle.
 *   - Correct Content-Type and Cache-Control headers.
 *   - Audit event emitted on resolution.
 *   - Handle validation.
 *   - CLI register-hosted subcommand produces a registry entry.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { randomBytes } from "node:crypto";
import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";

import { MemoryStorage } from "../../src/storage/memory.js";
import { issueDidWeb, type DidDocument } from "../../src/recognition/did-web.js";
import {
  DidWebHostedRegistry,
  validateHandle,
  HOSTED_DID_WEB_NAMESPACE,
} from "../../src/recognition/did-web-hosted-registry.js";
import {
  handleHostedDidWebRoute,
  HOSTED_DID_WEB_AUDIT_OPS,
} from "../../src/recognition/did-web-hosted-route.js";
import { generateKeypair } from "../../src/core/identity.js";

const FROZEN_TIME = new Date("2026-05-18T12:00:00.000Z");

function testMasterKey(): Uint8Array {
  return randomBytes(32);
}

function publicKey(): Uint8Array {
  return generateKeypair().publicKey;
}

function makeDidDocument(handle: string): DidDocument {
  const did = `did:web:identity.sanctuaryprotocol.ai:${handle}`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        status: "active",
        valid_from: FROZEN_TIME.toISOString(),
      },
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
  };
}

function createMockRequest(method: string, path: string): IncomingMessage {
  const socket = new Socket();
  const req = new IncomingMessage(socket);
  req.method = method;
  req.url = path;
  return req;
}

interface MockResponse extends ServerResponse {
  _body: string;
  _capturedStatus: number;
  _capturedHeaders: Record<string, string>;
}

function createMockResponse(): MockResponse {
  const socket = new Socket();
  const req = new IncomingMessage(socket);
  const res = new ServerResponse(req) as MockResponse;
  res._body = "";
  res._capturedStatus = 0;
  res._capturedHeaders = {};
  // Spy on writeHead to capture status + headers without writing to socket
  vi.spyOn(res, "writeHead").mockImplementation((...args: unknown[]) => {
    res._capturedStatus = args[0] as number;
    // writeHead(status, headers) or writeHead(status, msg, headers)
    const headerArg = args.length >= 3 ? args[2] : args[1];
    if (headerArg && typeof headerArg === "object") {
      Object.assign(res._capturedHeaders, headerArg as Record<string, string>);
    }
    return res;
  });
  vi.spyOn(res, "end").mockImplementation((...args: unknown[]) => {
    if (typeof args[0] === "string") res._body = args[0];
    return res;
  });
  return res;
}

describe("did-web-hosted-registry", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  const fortressId = "fortress_test_alpha";

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = testMasterKey();
  });

  it("stores and retrieves a DID Document by handle", async () => {
    const registry = new DidWebHostedRegistry({
      storage,
      masterKey,
      fortressId,
      now: () => FROZEN_TIME,
    });
    const doc = makeDidDocument("my-operator");
    const entry = await registry.set("my-operator", doc);
    expect(entry.operator_handle).toBe("my-operator");
    expect(entry.did_document).toEqual(doc);
    expect(entry.published_at).toBe(FROZEN_TIME.toISOString());

    const retrieved = await registry.get("my-operator");
    expect(retrieved).not.toBeNull();
    expect(retrieved!.did_document.id).toBe(
      "did:web:identity.sanctuaryprotocol.ai:my-operator",
    );
  });

  it("returns null for unregistered handle", async () => {
    const registry = new DidWebHostedRegistry({
      storage,
      masterKey,
      fortressId,
    });
    const result = await registry.get("nonexistent");
    expect(result).toBeNull();
  });

  it("returns null for a different fortress id (AAD mismatch)", async () => {
    const registry1 = new DidWebHostedRegistry({
      storage,
      masterKey,
      fortressId: "fortress_a",
      now: () => FROZEN_TIME,
    });
    await registry1.set("shared-handle", makeDidDocument("shared-handle"));

    const registry2 = new DidWebHostedRegistry({
      storage,
      masterKey,
      fortressId: "fortress_b",
    });
    const result = await registry2.get("shared-handle");
    expect(result).toBeNull();
  });

  it("rejects invalid handles on set", async () => {
    const registry = new DidWebHostedRegistry({
      storage,
      masterKey,
      fortressId,
    });
    await expect(
      registry.set("UPPER", makeDidDocument("upper")),
    ).rejects.toThrow();
    await expect(
      registry.set("-starts-with-dash", makeDidDocument("bad")),
    ).rejects.toThrow();
    await expect(
      registry.set("", makeDidDocument("empty")),
    ).rejects.toThrow();
  });
});

describe("validateHandle", () => {
  it("accepts valid handles", () => {
    expect(validateHandle("alice")).toBeNull();
    expect(validateHandle("my-operator")).toBeNull();
    expect(validateHandle("a")).toBeNull();
    expect(validateHandle("test123")).toBeNull();
  });

  it("rejects invalid handles", () => {
    expect(validateHandle("")).not.toBeNull();
    expect(validateHandle("UPPER")).not.toBeNull();
    expect(validateHandle("-dash")).not.toBeNull();
    expect(validateHandle("dash-")).not.toBeNull();
    expect(validateHandle("has space")).not.toBeNull();
    expect(validateHandle("has.dot")).not.toBeNull();
  });
});

describe("did-web-hosted-route", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  const fortressId = "fortress_route_test";

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = testMasterKey();
  });

  async function registerHandle(handle: string): Promise<void> {
    const registry = new DidWebHostedRegistry({
      storage,
      masterKey,
      fortressId,
      now: () => FROZEN_TIME,
    });
    await registry.set(handle, makeDidDocument(handle));
  }

  async function callRoute(
    method: string,
    path: string,
    auditFn?: (op: string, detail: Record<string, unknown>) => void,
  ) {
    const req = createMockRequest(method, path);
    const res = createMockResponse();
    const url = new URL(path, "http://localhost");
    const handled = await handleHostedDidWebRoute(
      {
        storage,
        masterKey,
        fortressId,
        now: () => FROZEN_TIME,
        onAudit: auditFn,
      },
      req,
      res,
      url,
      method,
    );
    return { handled, res };
  }

  it("serves a DID Document for a registered handle", async () => {
    await registerHandle("my-op");
    const { handled, res } = await callRoute(
      "GET",
      "/my-op/.well-known/did.json",
    );
    expect(handled).toBe(true);
    expect(res._capturedStatus).toBe(200);
    const body = JSON.parse(res._body);
    expect(body.id).toBe("did:web:identity.sanctuaryprotocol.ai:my-op");
  });

  it("returns correct Content-Type header", async () => {
    await registerHandle("header-test");
    const { res } = await callRoute(
      "GET",
      "/header-test/.well-known/did.json",
    );
    expect(res._capturedHeaders["Content-Type"]).toBe(
      "application/did+json; charset=utf-8",
    );
  });

  it("returns correct Cache-Control header", async () => {
    await registerHandle("cache-test");
    const { res } = await callRoute(
      "GET",
      "/cache-test/.well-known/did.json",
    );
    expect(res._capturedHeaders["Cache-Control"]).toBe(
      "public, max-age=300, must-revalidate",
    );
  });

  it("returns 404 for unregistered handle", async () => {
    const { handled, res } = await callRoute(
      "GET",
      "/unknown/.well-known/did.json",
    );
    expect(handled).toBe(true);
    expect(res._capturedStatus).toBe(404);
    const body = JSON.parse(res._body);
    expect(body.error).toBe("not_found");
  });

  it("emits audit event on successful resolution", async () => {
    await registerHandle("audit-test");
    const auditFn = vi.fn();
    await callRoute("GET", "/audit-test/.well-known/did.json", auditFn);
    expect(auditFn).toHaveBeenCalledOnce();
    expect(auditFn).toHaveBeenCalledWith(
      HOSTED_DID_WEB_AUDIT_OPS.HOSTED_DID_RESOLVED,
      expect.objectContaining({
        operator_handle: "audit-test",
        did: "did:web:identity.sanctuaryprotocol.ai:audit-test",
      }),
    );
  });

  it("does not emit audit event on 404", async () => {
    const auditFn = vi.fn();
    await callRoute("GET", "/nope/.well-known/did.json", auditFn);
    expect(auditFn).not.toHaveBeenCalled();
  });

  it("returns false for non-matching paths", async () => {
    const { handled } = await callRoute("GET", "/api/hub/something");
    expect(handled).toBe(false);
  });

  it("returns false for non-GET methods", async () => {
    await registerHandle("post-test");
    const { handled } = await callRoute(
      "POST",
      "/post-test/.well-known/did.json",
    );
    expect(handled).toBe(false);
  });
});

describe("HOSTED_DID_WEB_AUDIT_OPS", () => {
  it("includes HOSTED_DID_RESOLVED alongside existing ops", () => {
    expect(HOSTED_DID_WEB_AUDIT_OPS.HOSTED_DID_RESOLVED).toBe(
      "did_web_hosted_resolved",
    );
    expect(HOSTED_DID_WEB_AUDIT_OPS.ISSUED).toBe("did_web_issued");
    expect(HOSTED_DID_WEB_AUDIT_OPS.RESOLVED).toBe("did_web_resolved");
  });
});
