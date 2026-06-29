/**
 * Key 17 -- ERC-8004 Identity verifier (read side) tests.
 *
 * Covers: positive offline verify, no-key-leak, tampered-record reject (fail
 * closed), tampered-signature reject, malformed/non-object/non-integer reject,
 * optional ownerOf registry confirmation, egress denial, and the tool wiring.
 * The verifier reuses the existing signer's verify path and the existing
 * `key-17:erc8004-identity:v1` scheme; it defines no new crypto label. The
 * optional RPC read is default-off and is mocked in-process.
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
import { evaluateEgressGate } from "../../src/policy-engine/egress-gate.js";
import { buildNullPolicy } from "../../src/policy-engine/null-policy.js";
import { buildFortress } from "../policy-engine/fixture.js";
import type {
  Erc8004RegistryConfirmationConfig,
  Erc8004RegistryEgressGate,
  Erc8004RegistryFetch,
} from "../../src/key-17/erc8004-registry-confirm.js";

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

function makeSignedRecord(overrides: Partial<Erc8004Registration> = {}) {
  const registration: Erc8004Registration = {
    identity: "did:agent:alice",
    registry: "0x1234567890abcdef1234567890abcdef12345678",
    chain_id: 11155111,
    nonce: 3,
    timestamp: "2026-06-27T00:00:00.000Z",
    ...overrides,
  };
  return signErc8004Registration(MASTER_KEY, OPERATOR_ID, registration);
}

function baseDeps(
  audit = createMockAuditLog(),
  overrides: Partial<Parameters<typeof resolveErc8004Identity>[0]> = {},
) {
  return {
    auditLog: audit as unknown as Parameters<
      typeof resolveErc8004Identity
    >[0]["auditLog"],
    identityId: OPERATOR_ID,
    fortressId: "fortress-test",
    ...overrides,
  };
}

const CONFIRMATION_CONFIG: Erc8004RegistryConfirmationConfig = {
  enabled: true,
  rpc_url: "https://rpc.example",
  chain_id: 1,
  timeout_ms: 1000,
};

function encodeEthCallAddress(address: string): string {
  return `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}`;
}

function fetchOwner(owner: string, calls: Array<Record<string, unknown>> = []): Erc8004RegistryFetch {
  return async (_input, init) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    calls.push(body);
    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: body.id ?? 1,
        result: encodeEthCallAddress(owner),
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  };
}

function unreachableRpc(): Erc8004RegistryFetch {
  return async () => {
    throw new Error("simulated network failure");
  };
}

function egressGateFromPolicy(destination: string): {
  gate: Erc8004RegistryEgressGate;
  calls: Array<{ destination: string; method: string; identity: string }>;
} {
  const fortress = buildFortress();
  const policy = buildNullPolicy({
    agent_id: OPERATOR_ID,
    fortress_id: fortress.master.public.fortress_id,
  });
  policy.policy_version = 1;
  policy.egress = { allowlist: [{ destination, methods: ["POST"] }] };

  const calls: Array<{ destination: string; method: string; identity: string }> = [];
  return {
    calls,
    gate: (req) => {
      calls.push({
        destination: req.destination,
        method: req.method,
        identity: req.identity,
      });
      const result = evaluateEgressGate(
        {
          policy,
          nodeSigningKey: fortress.nodeKeypair.privateKey,
          nodeId: fortress.nodeCert.node_id,
          fortressId: fortress.master.public.fortress_id,
        },
        {
          agent_id: OPERATOR_ID,
          destination: req.destination,
          method: req.method,
        },
      );
      return {
        decision: result.decision === "allow" ? "allow" : "deny",
        reason_code: result.reason_code,
        explanation: result.explanation,
      };
    },
  };
}

// ── Offline verification ─────────────────────────────────────────────

describe("resolveErc8004Identity: offline verification", () => {
  it("resolves a well-formed signed record as valid (offline)", async () => {
    const audit = createMockAuditLog();
    const signed = makeSignedRecord();

    const result = await resolveErc8004Identity(baseDeps(audit), signed);

    expect(result.valid).toBe(true);
    expect(result.assurance).toBe("offline_verified");
    expect(result.registry_confirmation).toEqual({ status: "disabled" });
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

// ── Optional registry confirmation ──────────────────────────────────

describe("resolveErc8004Identity: optional registry confirmation", () => {
  it("confirms when ownerOf(identity) matches the offline signer", async () => {
    const audit = createMockAuditLog();
    const signed = makeSignedRecord({ identity: "12345", chain_id: 1 });
    const fetchCalls: Array<Record<string, unknown>> = [];
    const egress = egressGateFromPolicy("rpc.example");

    const result = await resolveErc8004Identity(
      baseDeps(audit, {
        registryConfirmation: CONFIRMATION_CONFIG,
        egressGate: egress.gate,
        fetchFn: fetchOwner(signed.signer_address, fetchCalls),
      }),
      signed,
    );

    expect(result.valid).toBe(true);
    expect(result.assurance).toBe("registry_confirmed");
    expect(result.registry_confirmation?.status).toBe("confirmed");
    expect(result.registry_confirmation?.owner_address?.toLowerCase()).toBe(
      signed.signer_address.toLowerCase(),
    );
    expect(fetchCalls).toHaveLength(1);
    expect(egress.calls).toEqual([
      { destination: "rpc.example", method: "POST", identity: "12345" },
    ]);
    expect(
      audit.entries.some(
        (e) => e.op === ERC8004_RESOLVE_AUDIT_OPS.REGISTRY_CONFIRMED,
      ),
    ).toBe(true);
  });

  it("stays offline-verified/unconfirmed when ownerOf(identity) mismatches", async () => {
    const signed = makeSignedRecord({ identity: "12345", chain_id: 1 });
    const egress = egressGateFromPolicy("rpc.example");

    const result = await resolveErc8004Identity(
      baseDeps(createMockAuditLog(), {
        registryConfirmation: CONFIRMATION_CONFIG,
        egressGate: egress.gate,
        fetchFn: fetchOwner("0x9999999999999999999999999999999999999999"),
      }),
      signed,
    );

    expect(result.valid).toBe(true);
    expect(result.assurance).toBe("offline_verified");
    expect(result.registry_confirmation).toMatchObject({
      status: "unconfirmed",
      reason: "owner_mismatch",
    });
  });

  it("stays offline-verified/unconfirmed when RPC is unreachable", async () => {
    const signed = makeSignedRecord({ identity: "12345", chain_id: 1 });
    const egress = egressGateFromPolicy("rpc.example");

    const result = await resolveErc8004Identity(
      baseDeps(createMockAuditLog(), {
        registryConfirmation: CONFIRMATION_CONFIG,
        egressGate: egress.gate,
        fetchFn: unreachableRpc(),
      }),
      signed,
    );

    expect(result.valid).toBe(true);
    expect(result.assurance).toBe("offline_verified");
    expect(result.registry_confirmation).toMatchObject({
      status: "unconfirmed",
      reason: "rpc_error",
    });
  });

  it("routes RPC through the egress gate and does not fetch when denied", async () => {
    const signed = makeSignedRecord({ identity: "12345", chain_id: 1 });
    const fetchCalls: Array<Record<string, unknown>> = [];
    const egress = egressGateFromPolicy("different-rpc.example");

    const result = await resolveErc8004Identity(
      baseDeps(createMockAuditLog(), {
        registryConfirmation: CONFIRMATION_CONFIG,
        egressGate: egress.gate,
        fetchFn: fetchOwner(signed.signer_address, fetchCalls),
      }),
      signed,
    );

    expect(result.valid).toBe(true);
    expect(result.assurance).toBe("offline_verified");
    expect(result.registry_confirmation).toMatchObject({
      status: "unconfirmed",
      reason: "egress_destination_denied",
    });
    expect(egress.calls).toHaveLength(1);
    expect(fetchCalls).toHaveLength(0);
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
    expect(tool.description.toLowerCase()).toContain("offline");
    expect(tool.description.toLowerCase()).toContain("read-only");
    expect(tool.description).toContain("offline-verified");
    expect(tool.description).toContain("registry_confirmed");
    expect(tool.description).toContain("unconfirmed");
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
