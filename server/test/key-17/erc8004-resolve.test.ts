/**
 * Key 17 -- ERC-8004 Identity OFFLINE verifier (read side) tests.
 *
 * Covers: positive offline verify, no-key-leak, tampered-record reject (fail
 * closed), tampered-signature reject, malformed/non-object/non-integer reject,
 * and the tool wiring. The verifier reuses the existing signer's verify path and
 * the existing `key-17:erc8004-identity:v1` scheme; it defines no new crypto
 * label and makes no outbound request (there is no RPC surface to test).
 */

import { describe, it, expect } from "vitest";
import {
  resolveErc8004Identity,
  createErc8004ResolveTools,
  ERC8004_RESOLVE_AUDIT_OPS,
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
  it("resolves a well-formed signed record as valid (offline)", async () => {
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

// ── MCP tool wiring ──────────────────────────────────────────────────

describe("createErc8004ResolveTools", () => {
  it("registers a read-class verify tool with an accurate description", () => {
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
    // The description must not overclaim an on-chain/registry-owner check.
    expect(tool.description).toContain("does NOT prove");
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
