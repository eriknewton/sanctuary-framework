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

import { describe, it, expect, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  resolveErc8004Identity,
  createErc8004ResolveTools,
  ERC8004_REASON_OUTSIDE_SET_ERROR,
  ERC8004_RESOLVE_AUDIT_OPS,
} from "../../src/key-17/erc8004-resolve.js";
import {
  confirmErc8004RegistryOwner,
  ERC8004_AGENT_REASONS,
  type Erc8004RegistryConfirmation,
} from "../../src/key-17/erc8004-registry-confirm.js";
import { createServer } from "../../src/router.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { DenialCause, DenialRecorder } from "../../src/agent-native/denial-ledger.js";
import { expectedRefusal } from "../helpers/expected-refusal.js";
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

// A test can make the registry confirmer return a fixed confirmation; otherwise the real one runs.
const forcedConfirmation = vi.hoisted(() => ({ value: undefined as Erc8004RegistryConfirmation | undefined }));
vi.mock("../../src/key-17/erc8004-registry-confirm.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/key-17/erc8004-registry-confirm.js")>();
  return {
    ...actual,
    confirmErc8004RegistryOwner: (...args: Parameters<typeof actual.confirmErc8004RegistryOwner>) =>
      forcedConfirmation.value !== undefined
        ? Promise.resolve(forcedConfirmation.value)
        : actual.confirmErc8004RegistryOwner(...args),
  };
});

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
      reason: "egress_unavailable",
    });
    expect(egress.calls).toHaveLength(1);
    expect(fetchCalls).toHaveLength(0);
  });
});

// ── Agent-facing registry reasons ────────────────────────────────────

function denyingGate(reasonCode: string): Erc8004RegistryEgressGate {
  return () => ({ decision: "deny", reason_code: reasonCode });
}

function unconfirmedRows(audit: ReturnType<typeof createMockAuditLog>) {
  return audit.entries.filter((entry) => entry.op === ERC8004_RESOLVE_AUDIT_OPS.REGISTRY_UNCONFIRMED);
}

const ALLOWED_CONFIRMATION_KEYS = ["status", "chain_id", "registry", "reason", "owner_address"];

describe("the registry reason an agent sees is one closed set", () => {
  it("two different egress-gate denials give the same agent-facing reason and different operator rows", async () => {
    const signed = makeSignedRecord({ identity: "12345", chain_id: 1 });
    const policyAudit = createMockAuditLog();
    const policyDenied = await resolveErc8004Identity(
      baseDeps(policyAudit, {
        registryConfirmation: CONFIRMATION_CONFIG,
        egressGate: egressGateFromPolicy("different-rpc.example").gate,
        fetchFn: fetchOwner(signed.signer_address),
      }),
      signed,
    );
    const customAudit = createMockAuditLog();
    const customDenied = await resolveErc8004Identity(
      baseDeps(customAudit, {
        registryConfirmation: CONFIRMATION_CONFIG,
        egressGate: denyingGate("egress_fixture_quota"),
        fetchFn: fetchOwner(signed.signer_address),
      }),
      signed,
    );
    expect(policyDenied.registry_confirmation).toEqual(customDenied.registry_confirmation);
    expect(policyDenied.registry_confirmation?.reason).toBe("egress_unavailable");
    expect(JSON.stringify(policyDenied)).not.toContain("egress_destination_denied");
    expect(JSON.stringify(customDenied)).not.toContain("egress_fixture_quota");
    expect(unconfirmedRows(policyAudit).map((row) => row.data.reason)).toEqual(["egress_destination_denied"]);
    expect(unconfirmedRows(customAudit).map((row) => row.data.reason)).toEqual(["egress_fixture_quota"]);
  });

  const SIGNER = "0x1111111111111111111111111111111111111111";
  const REGISTRY = "0x1234567890abcdef1234567890abcdef12345678";
  const allowAll: Erc8004RegistryEgressGate = () => ({ decision: "allow" });
  const missingRecordRpc: Erc8004RegistryFetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    return new Response(JSON.stringify({
      jsonrpc: "2.0",
      id: body.id ?? 1,
      error: { code: 3, message: "execution reverted: ERC721: owner query for nonexistent token" },
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const ARMS: Array<{ label: string; config?: Partial<Erc8004RegistryConfirmationConfig>; input?: Record<string, unknown>; gate?: Erc8004RegistryEgressGate | null; fetchFn?: Erc8004RegistryFetch }> = [
    { label: "no RPC configured", config: { rpc_url: "" } },
    { label: "an unusable RPC URL", config: { rpc_url: "ftp://rpc.example" } },
    { label: "a chain mismatch", input: { chain_id: 5 } },
    { label: "an invalid registry address", input: { registry: "not-an-address" } },
    { label: "an invalid signer address", input: { signer_address: "not-an-address" } },
    { label: "a non-numeric identity", input: { identity: "did:agent:alice" } },
    { label: "an unregistered identity", gate: allowAll, fetchFn: missingRecordRpc },
    { label: "an owner mismatch", gate: allowAll, fetchFn: fetchOwner("0x2222222222222222222222222222222222222222") },
    { label: "an RPC failure", gate: allowAll, fetchFn: unreachableRpc() },
    { label: "a denied egress read", gate: denyingGate("egress_fixture_denied") },
    { label: "a denied egress read with no code", gate: () => ({ decision: "deny" }) },
    { label: "no egress gate", gate: null },
  ];

  it.each(ARMS)("every agent-facing reason is in the closed set: $label", async (arm) => {
    const result = await confirmErc8004RegistryOwner(
      {
        config: { ...CONFIRMATION_CONFIG, ...arm.config },
        ...(arm.gate === null ? {} : { egressGate: arm.gate ?? allowAll }),
        fetchFn: arm.fetchFn ?? fetchOwner(SIGNER),
      },
      { identity: "12345", registry: REGISTRY, chain_id: 1, signer_address: SIGNER, ...arm.input } as Parameters<typeof confirmErc8004RegistryOwner>[1],
    );
    expect(result.status).toBe("unconfirmed");
    expect(ERC8004_AGENT_REASONS as readonly string[]).toContain(result.reason);
  });

  it("registry_confirmation carries only the allowlisted fields", async () => {
    const signed = makeSignedRecord({ identity: "12345", chain_id: 1 });
    const result = await resolveErc8004Identity(
      baseDeps(createMockAuditLog(), {
        registryConfirmation: CONFIRMATION_CONFIG,
        egressGate: denyingGate("egress_fixture_denied"),
        fetchFn: fetchOwner(signed.signer_address),
      }),
      signed,
    );
    const keys = Object.keys(result.registry_confirmation ?? {});
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) expect(ALLOWED_CONFIRMATION_KEYS).toContain(key);
  });

  it("a reason outside the set refuses with a message that contains no reason code", async () => {
    const forced = "egress_fixture_outside_the_set";
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const { tools } = createErc8004ResolveTools({
      auditLog,
      identityId: OPERATOR_ID,
      fortressId: "fortress-test",
      registryConfirmation: CONFIRMATION_CONFIG,
    });
    const causes: DenialCause[] = [];
    const denialLedger: DenialRecorder = { record: (cause) => { causes.push(cause); } };
    const server = createServer(tools, { auditLog, denialLedger });
    const client = new Client({ name: "erc8004-outside-set", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const signed = makeSignedRecord({ identity: "12345", chain_id: 1 });
      forcedConfirmation.value = { status: "unconfirmed", chain_id: 1, registry: signed.registry, reason: forced };
      const result = await client.callTool({
        name: "sanctuary/resolve_erc8004_identity",
        arguments: { record: signed as unknown as Record<string, unknown> },
      });
      expect(result).toEqual(expectedRefusal());
      for (const item of result.content as Array<{ text: string }>) expect(item.text).not.toContain(forced);
      expect(causes).toEqual(["handler_error"]);
      await auditLog.flush();
      const toolErrors = (await auditLog.query({ operation_type: "tool_error:sanctuary/resolve_erc8004_identity", limit: 10 })).entries;
      expect(toolErrors).toHaveLength(1);
      expect(toolErrors[0]!.details?.error).toBe(ERC8004_REASON_OUTSIDE_SET_ERROR);
      expect(ERC8004_REASON_OUTSIDE_SET_ERROR).not.toContain(forced);
      const rows = (await auditLog.query({ operation_type: ERC8004_RESOLVE_AUDIT_OPS.REGISTRY_UNCONFIRMED, limit: 10 })).entries;
      expect(rows.map((row) => row.details?.reason)).toEqual([forced]);
    } finally {
      forcedConfirmation.value = undefined;
      await client.close();
      await server.close();
    }
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
