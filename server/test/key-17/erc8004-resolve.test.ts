/**
 * Key 17 -- ERC-8004 Identity resolve (read side) tests.
 *
 * Covers: positive offline verify, tampered-record reject (fail closed),
 * malformed-record reject, no-endpoint offline-only path, the no-egress
 * guarantee when no endpoint is configured, the SSRF block for a private RPC
 * endpoint, and the on-chain confirm/mismatch paths through an injected fetch.
 * The resolver reuses the existing signer's verify path and the existing
 * `key-17:erc8004-identity:v1` scheme; it defines no new crypto label.
 */

import { describe, it, expect, vi } from "vitest";
import {
  resolveErc8004Identity,
  createErc8004ResolveTools,
  ERC8004_RESOLVE_AUDIT_OPS,
  type ResolveFetch,
} from "../../src/key-17/erc8004-resolve.js";
import {
  signErc8004Registration,
  type Erc8004Registration,
} from "../../src/key-17/erc8004-identity-signer.js";

// ── Helpers ──────────────────────────────────────────────────────────

function createMockAuditLog() {
  const entries: Array<{ op: string; data: Record<string, unknown> }> = [];
  return {
    entries,
    append(
      _layer: string,
      op: string,
      _identity: string,
      data?: Record<string, unknown>,
    ): Promise<void> {
      entries.push({ op, data: data ?? {} });
      return Promise.resolve();
    },
  };
}

const MASTER_KEY = new Uint8Array(32).fill(7);
const OPERATOR_ID = "did:sanctuary:resolve-test";

function makeSignedRecord() {
  const registration: Erc8004Registration = {
    identity: "did:agent:alice",
    registry: "0x1234567890abcdef1234567890abcdef12345678",
    chain_id: 11155111,
    nonce: 3,
    timestamp: "2026-06-27T00:00:00.000Z",
  };
  return signErc8004Registration(MASTER_KEY, OPERATOR_ID, registration);
}

function baseDeps(audit = createMockAuditLog()) {
  return {
    auditLog: audit as unknown as Parameters<
      typeof resolveErc8004Identity
    >[0]["auditLog"],
    identityId: OPERATOR_ID,
    fortressId: "fortress-test",
  };
}

// ── Offline verification ─────────────────────────────────────────────

describe("resolveErc8004Identity: offline verification", () => {
  it("resolves a well-formed signed record as valid (offline-only)", async () => {
    const audit = createMockAuditLog();
    const signed = makeSignedRecord();

    const result = await resolveErc8004Identity(baseDeps(audit), signed);

    expect(result.valid).toBe(true);
    expect(result.signer_address).toBe(signed.signer_address);
    expect(result.fields).toEqual({
      identity: signed.identity,
      registry: signed.registry,
      chain_id: signed.chain_id,
      nonce: signed.nonce,
      timestamp: signed.timestamp,
    });
    // Offline-only: no registry confirmation field at all.
    expect(result.registry_confirmed).toBeUndefined();
    expect(
      audit.entries.some(
        (e) => e.op === ERC8004_RESOLVE_AUDIT_OPS.RESOLVED_VALID,
      ),
    ).toBe(true);
  });

  it("never returns key material in the result", async () => {
    const signed = makeSignedRecord();
    const result = await resolveErc8004Identity(baseDeps(), signed);
    const serialized = JSON.stringify(result);
    // The compressed public_key from the record must not be echoed back.
    expect(serialized).not.toContain(signed.public_key);
    expect(serialized).not.toContain("private");
  });

  it("rejects a tampered record (changed identity) as invalid, fail closed", async () => {
    const audit = createMockAuditLog();
    const signed = makeSignedRecord();
    const tampered = { ...signed, identity: "did:agent:mallory" };

    const result = await resolveErc8004Identity(baseDeps(audit), tampered);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_verification_failed");
    expect(result.signer_address).toBeUndefined();
    expect(
      audit.entries.some(
        (e) => e.op === ERC8004_RESOLVE_AUDIT_OPS.RESOLVED_INVALID,
      ),
    ).toBe(true);
  });

  it("rejects a record with a tampered signature as invalid", async () => {
    const signed = makeSignedRecord();
    const badSig =
      "0x" + "0".repeat(128) + "1b"; // structurally 65 bytes but wrong
    const result = await resolveErc8004Identity(baseDeps(), {
      ...signed,
      signature: badSig,
    });
    expect(result.valid).toBe(false);
  });

  it("rejects a malformed record (missing required fields) fail closed", async () => {
    const result = await resolveErc8004Identity(baseDeps(), {
      identity: "did:agent:alice",
      // everything else missing
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("missing or malformed");
  });

  it("rejects a non-object record fail closed", async () => {
    const r1 = await resolveErc8004Identity(baseDeps(), null);
    const r2 = await resolveErc8004Identity(baseDeps(), "not-an-object");
    expect(r1.valid).toBe(false);
    expect(r2.valid).toBe(false);
  });

  it("rejects a record with a non-integer chain_id fail closed", async () => {
    const signed = makeSignedRecord();
    const result = await resolveErc8004Identity(baseDeps(), {
      ...signed,
      chain_id: 1.5,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("chain_id");
  });
});

// ── No-egress guarantee ──────────────────────────────────────────────

describe("resolveErc8004Identity: egress discipline", () => {
  it("makes NO outbound request when no endpoint is configured", async () => {
    const fetchSpy = vi.fn();
    const signed = makeSignedRecord();
    const result = await resolveErc8004Identity(
      { ...baseDeps(), resolveFetch: fetchSpy as unknown as ResolveFetch },
      signed,
    );
    expect(result.valid).toBe(true);
    // The injected fetch must never be called with no endpoint set.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("makes NO outbound request when the record is invalid even if an endpoint is set", async () => {
    const fetchSpy = vi.fn();
    const signed = makeSignedRecord();
    const result = await resolveErc8004Identity(
      {
        ...baseDeps(),
        rpcEndpoint: "http://10.0.0.5:8545",
        allowPrivateRpc: true,
        resolveFetch: fetchSpy as unknown as ResolveFetch,
      },
      { ...signed, identity: "did:agent:tampered" },
    );
    expect(result.valid).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("blocks a loopback RPC endpoint via the SSRF guard, no fetch", async () => {
    const fetchSpy = vi.fn();
    const audit = createMockAuditLog();
    const signed = makeSignedRecord();
    const result = await resolveErc8004Identity(
      {
        ...baseDeps(audit),
        rpcEndpoint: "http://127.0.0.1:8545",
        resolveFetch: fetchSpy as unknown as ResolveFetch,
      },
      signed,
    );
    // Offline check still passed; the registry claim is fail-closed (false).
    expect(result.valid).toBe(true);
    expect(result.registry_confirmed).toBe(false);
    expect(result.registry_note).toContain("rejected");
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(
      audit.entries.some(
        (e) => e.op === ERC8004_RESOLVE_AUDIT_OPS.RPC_BLOCKED,
      ),
    ).toBe(true);
  });
});

// ── On-chain confirmation through injected fetch ─────────────────────

describe("resolveErc8004Identity: on-chain confirmation", () => {
  it("confirms when the registry returns the matching owner address", async () => {
    const signed = makeSignedRecord();
    // ABI-encode the signer address as the last 32-byte word.
    const addrHex = signed.signer_address.replace(/^0x/, "").toLowerCase();
    const word = "0".repeat(24) + addrHex;
    const okFetch: ResolveFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: "2.0", id: "x", result: "0x" + word }),
    }));

    const result = await resolveErc8004Identity(
      {
        ...baseDeps(),
        rpcEndpoint: "http://10.0.0.5:8545",
        allowPrivateRpc: true,
        resolveFetch: okFetch,
      },
      signed,
    );

    expect(result.valid).toBe(true);
    expect(result.registry_confirmed).toBe(true);
    expect(okFetch).toHaveBeenCalledTimes(1);
  });

  it("does NOT confirm when the registry owner differs from the signer", async () => {
    const signed = makeSignedRecord();
    const otherWord = "0".repeat(24) + "a".repeat(40);
    const mismatchFetch: ResolveFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ result: "0x" + otherWord }),
    }));

    const result = await resolveErc8004Identity(
      {
        ...baseDeps(),
        rpcEndpoint: "http://10.0.0.5:8545",
        allowPrivateRpc: true,
        resolveFetch: mismatchFetch,
      },
      signed,
    );

    expect(result.valid).toBe(true);
    expect(result.registry_confirmed).toBe(false);
    expect(result.registry_note).toContain("does not match");
  });

  it("does NOT confirm (fail closed) when the registry read errors", async () => {
    const signed = makeSignedRecord();
    const errFetch: ResolveFetch = vi.fn(async () => {
      throw new Error("network down");
    });
    const result = await resolveErc8004Identity(
      {
        ...baseDeps(),
        rpcEndpoint: "http://10.0.0.5:8545",
        allowPrivateRpc: true,
        resolveFetch: errFetch,
      },
      signed,
    );
    expect(result.valid).toBe(true);
    expect(result.registry_confirmed).toBe(false);
    expect(result.registry_note).toContain("failed");
  });

  it("does NOT confirm when the registry returns a non-200 status", async () => {
    const signed = makeSignedRecord();
    const badStatus: ResolveFetch = vi.fn(async () => ({
      ok: false,
      status: 503,
      json: async () => ({}),
    }));
    const result = await resolveErc8004Identity(
      {
        ...baseDeps(),
        rpcEndpoint: "http://10.0.0.5:8545",
        allowPrivateRpc: true,
        resolveFetch: badStatus,
      },
      signed,
    );
    expect(result.valid).toBe(true);
    expect(result.registry_confirmed).toBe(false);
    expect(result.registry_note).toContain("503");
  });
});

// ── MCP tool wiring ──────────────────────────────────────────────────

describe("createErc8004ResolveTools", () => {
  it("registers a read-class resolve tool with an accurate description", () => {
    const { tools } = createErc8004ResolveTools({
      auditLog: createMockAuditLog() as unknown as Parameters<
        typeof createErc8004ResolveTools
      >[0]["auditLog"],
      identityId: OPERATOR_ID,
      fortressId: "fortress-test",
    });
    expect(tools).toHaveLength(1);
    const tool = tools[0]!;
    expect(tool.name).toBe("sanctuary/resolve_erc8004_identity");
    expect(tool.tool_class).toBe("read");
    expect(tool.description).toContain("OFFLINE");
    expect(tool.description.toLowerCase()).toContain("read-only");
  });

  it("the tool handler verifies a presented record end to end (offline)", async () => {
    const signed = makeSignedRecord();
    const { tools } = createErc8004ResolveTools({
      auditLog: createMockAuditLog() as unknown as Parameters<
        typeof createErc8004ResolveTools
      >[0]["auditLog"],
      identityId: OPERATOR_ID,
      fortressId: "fortress-test",
    });
    const res = await tools[0]!.handler({
      record: signed as unknown as Record<string, unknown>,
    });
    const text = res.content[0]!.text;
    const parsed = JSON.parse(text) as { valid: boolean };
    expect(parsed.valid).toBe(true);
  });

  it("the tool handler rejects a tampered record (fail closed)", async () => {
    const signed = makeSignedRecord();
    const { tools } = createErc8004ResolveTools({
      auditLog: createMockAuditLog() as unknown as Parameters<
        typeof createErc8004ResolveTools
      >[0]["auditLog"],
      identityId: OPERATOR_ID,
      fortressId: "fortress-test",
    });
    const res = await tools[0]!.handler({
      record: { ...signed, nonce: 999 } as unknown as Record<string, unknown>,
    });
    const parsed = JSON.parse(res.content[0]!.text) as { valid: boolean };
    expect(parsed.valid).toBe(false);
  });
});
