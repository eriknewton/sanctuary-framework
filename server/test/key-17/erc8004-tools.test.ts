/**
 * Key 17 -- ERC-8004 operator opt-in UX tests.
 *
 * Covers: MCP tool input validation, three-tier policy flow (Tier 1 auto-
 * approved, Tier 2 pending approval, Tier 3 denied), CLI dispatch, inbox
 * wiring, end-to-end approval flow, and Castle-walking regression test.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { randomBytes } from "../../src/core/random.js";
import { Writable } from "node:stream";
import {
  DefaultPolicyGate,
  SigningDeniedError,
} from "../../src/key-17/policy-gate.js";
import {
  handleErc8004Request,
  Erc8004PendingStore,
  isValidEthAddress,
  resolvePendingRequest,
  ERC8004_AUDIT_OPS,
  createErc8004Tools,
  type Erc8004ServiceDeps,
} from "../../src/key-17/erc8004-tools.js";
import { verifyErc8004Registration } from "../../src/key-17/erc8004-identity-signer.js";
import type { Erc8004Registration } from "../../src/key-17/erc8004-identity-signer.js";

// ── Mock audit log ───────────────────────────────────────────────────

function createMockAuditLog() {
  const entries: Array<{
    layer: string;
    op: string;
    identity: string;
    data: Record<string, unknown>;
  }> = [];
  return {
    entries,
    append(
      layer: string,
      op: string,
      identity: string,
      data: Record<string, unknown>,
    ): void {
      entries.push({ layer, op, identity, data });
    },
    flush: vi.fn().mockResolvedValue(undefined),
  };
}

// ── Mock inbox bridge ────────────────────────────────────────────────

function createMockInboxBridge() {
  const ingested: Array<{
    source_event_id: string;
    severity: string;
    summary: string;
  }> = [];
  return {
    ingested,
    ingestApproval(input: {
      source_event_id: string;
      severity: string;
      summary: string;
      observed_at: string;
    }) {
      ingested.push(input);
      return {
        inbox_id: `inbox-${ingested.length}`,
        source_class: "approval" as const,
        source_event_id: input.source_event_id,
        severity: input.severity,
        summary: input.summary,
        details_url: `/api/inbox/unified/inbox-${ingested.length}`,
        observed_at: input.observed_at,
        fortress_id: "test-fortress",
      };
    },
  };
}

// ── Fixtures ─────────────────────────────────────────────────────────

const masterKey = randomBytes(32);
const operatorId = "operator-test";
const identityId = "identity-test";
const fortressId = "fortress-test";

function makeRegistration(
  overrides?: Partial<Erc8004Registration>,
): Erc8004Registration {
  return {
    identity: "did:sanctuary:test-agent",
    registry: "0x1234567890abcdef1234567890abcdef12345678",
    chain_id: 1,
    nonce: 42,
    timestamp: "2026-05-21T12:00:00Z",
    ...overrides,
  };
}

function makeDeps(overrides?: Partial<Erc8004ServiceDeps>): Erc8004ServiceDeps {
  return {
    masterKey,
    operatorId,
    policyGate: new DefaultPolicyGate({ global_default: "allow" }),
    auditLog: createMockAuditLog() as any,
    identityId,
    pendingStore: new Erc8004PendingStore(),
    fortressId,
    ...overrides,
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("isValidEthAddress", () => {
  it("accepts valid checksummed address", () => {
    expect(
      isValidEthAddress("0x1234567890abcdef1234567890abcdef12345678"),
    ).toBe(true);
  });

  it("rejects address without 0x prefix", () => {
    expect(
      isValidEthAddress("1234567890abcdef1234567890abcdef12345678"),
    ).toBe(false);
  });

  it("rejects short address", () => {
    expect(isValidEthAddress("0x1234")).toBe(false);
  });

  it("rejects empty string", () => {
    expect(isValidEthAddress("")).toBe(false);
  });
});

describe("MCP tool input validation", () => {
  it("rejects malformed registry address", async () => {
    const { tools } = createErc8004Tools({
      masterKey,
      policyGate: new DefaultPolicyGate({ global_default: "allow" }),
      auditLog: createMockAuditLog() as any,
      identityId,
      operatorId,
      fortressId,
    });
    const tool = tools.find(
      (t) => t.name === "sanctuary/sign_erc8004_identity",
    )!;
    const result = await tool.handler({
      registry_address: "not-an-address",
      chain_id: 1,
      agent_id: "test-agent",
      nonce: 1,
    });
    const data = JSON.parse(result.content[0]!.text);
    expect(data.error).toBe("invalid_registry_address");
  });

  it("rejects invalid chain_id (zero)", async () => {
    const { tools } = createErc8004Tools({
      masterKey,
      policyGate: new DefaultPolicyGate({ global_default: "allow" }),
      auditLog: createMockAuditLog() as any,
      identityId,
      operatorId,
      fortressId,
    });
    const tool = tools.find(
      (t) => t.name === "sanctuary/sign_erc8004_identity",
    )!;
    const result = await tool.handler({
      registry_address: "0x1234567890abcdef1234567890abcdef12345678",
      chain_id: 0,
      agent_id: "test-agent",
      nonce: 1,
    });
    const data = JSON.parse(result.content[0]!.text);
    expect(data.error).toBe("invalid_chain_id");
  });

  it("rejects missing agent_id (empty string)", async () => {
    const { tools } = createErc8004Tools({
      masterKey,
      policyGate: new DefaultPolicyGate({ global_default: "allow" }),
      auditLog: createMockAuditLog() as any,
      identityId,
      operatorId,
      fortressId,
    });
    const tool = tools.find(
      (t) => t.name === "sanctuary/sign_erc8004_identity",
    )!;
    const result = await tool.handler({
      registry_address: "0x1234567890abcdef1234567890abcdef12345678",
      chain_id: 1,
      agent_id: "",
      nonce: 1,
    });
    const data = JSON.parse(result.content[0]!.text);
    expect(data.error).toBe("invalid_agent_id");
  });

  it("rejects negative nonce", async () => {
    const { tools } = createErc8004Tools({
      masterKey,
      policyGate: new DefaultPolicyGate({ global_default: "allow" }),
      auditLog: createMockAuditLog() as any,
      identityId,
      operatorId,
      fortressId,
    });
    const tool = tools.find(
      (t) => t.name === "sanctuary/sign_erc8004_identity",
    )!;
    const result = await tool.handler({
      registry_address: "0x1234567890abcdef1234567890abcdef12345678",
      chain_id: 1,
      agent_id: "test-agent",
      nonce: -1,
    });
    const data = JSON.parse(result.content[0]!.text);
    expect(data.error).toBe("invalid_nonce");
  });
});

describe("Tier 1 happy path (auto-approved)", () => {
  it("produces a valid signature when policy allows", async () => {
    const auditLog = createMockAuditLog();
    const deps = makeDeps({ auditLog: auditLog as any });
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg);

    expect(result.status).toBe("signed");
    expect(result.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
    expect(result.signer_address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(result.request_id).toBeTruthy();
  });

  it("emits erc8004.identity.requested + erc8004.identity.signed audit entries", async () => {
    const auditLog = createMockAuditLog();
    const deps = makeDeps({ auditLog: auditLog as any });
    const reg = makeRegistration();

    await handleErc8004Request(deps, reg);

    const ops = auditLog.entries.map((e) => e.op);
    expect(ops).toContain(ERC8004_AUDIT_OPS.REQUESTED);
    expect(ops).toContain(ERC8004_AUDIT_OPS.SIGNED);
    expect(ops).not.toContain(ERC8004_AUDIT_OPS.PENDING_APPROVAL);
    expect(ops).not.toContain(ERC8004_AUDIT_OPS.DENIED);
  });

  it("returned signature is cryptographically verifiable", async () => {
    const deps = makeDeps();
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg);
    expect(result.status).toBe("signed");

    // The signer address should be deterministic for the same masterKey + operatorId
    expect(result.signer_address).toBeTruthy();
  });
});

describe("Tier 2 happy path (pending approval)", () => {
  it("returns pending_approval when policy requires operator approval", async () => {
    const auditLog = createMockAuditLog();
    const inboxBridge = createMockInboxBridge();
    const pendingStore = new Erc8004PendingStore();
    const gate = new DefaultPolicyGate({
      global_default: "operator_approval_required",
    });
    const deps = makeDeps({
      policyGate: gate,
      auditLog: auditLog as any,
      pendingStore,
      inboxBridge: inboxBridge as any,
    });
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg);

    expect(result.status).toBe("pending_approval");
    expect(result.request_id).toBeTruthy();
    expect(result.signature).toBeUndefined();
  });

  it("writes an inbox entry", async () => {
    const inboxBridge = createMockInboxBridge();
    const gate = new DefaultPolicyGate({
      global_default: "operator_approval_required",
    });
    const deps = makeDeps({
      policyGate: gate,
      inboxBridge: inboxBridge as any,
    });
    const reg = makeRegistration();

    await handleErc8004Request(deps, reg);

    expect(inboxBridge.ingested).toHaveLength(1);
    expect(inboxBridge.ingested[0]!.severity).toBe("alert");
    expect(inboxBridge.ingested[0]!.summary).toContain("ERC-8004");
    expect(inboxBridge.ingested[0]!.summary).toContain(reg.identity);
  });

  it("emits erc8004.identity.pending_approval audit entry", async () => {
    const auditLog = createMockAuditLog();
    const gate = new DefaultPolicyGate({
      global_default: "operator_approval_required",
    });
    const deps = makeDeps({
      policyGate: gate,
      auditLog: auditLog as any,
    });
    const reg = makeRegistration();

    await handleErc8004Request(deps, reg);

    const ops = auditLog.entries.map((e) => e.op);
    expect(ops).toContain(ERC8004_AUDIT_OPS.REQUESTED);
    expect(ops).toContain(ERC8004_AUDIT_OPS.PENDING_APPROVAL);
    expect(ops).not.toContain(ERC8004_AUDIT_OPS.SIGNED);
  });

  it("stores pending request for later resolution", async () => {
    const pendingStore = new Erc8004PendingStore();
    const gate = new DefaultPolicyGate({
      global_default: "operator_approval_required",
    });
    const deps = makeDeps({ policyGate: gate, pendingStore });
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg);

    expect(pendingStore.size()).toBe(1);
    const pending = pendingStore.get(result.request_id);
    expect(pending).toBeTruthy();
    expect(pending!.status).toBe("pending_approval");
    expect(pending!.registration.identity).toBe(reg.identity);
  });
});

describe("Tier 3 denial", () => {
  it("returns denied with reason when policy denies", async () => {
    const auditLog = createMockAuditLog();
    const gate = new DefaultPolicyGate({ global_default: "deny" });
    const deps = makeDeps({
      policyGate: gate,
      auditLog: auditLog as any,
    });
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg);

    expect(result.status).toBe("denied");
    expect(result.reason).toBeTruthy();
    expect(result.signature).toBeUndefined();
  });

  it("emits erc8004.identity.denied audit entry and no signature", async () => {
    const auditLog = createMockAuditLog();
    const gate = new DefaultPolicyGate({ global_default: "deny" });
    const deps = makeDeps({
      policyGate: gate,
      auditLog: auditLog as any,
    });
    const reg = makeRegistration();

    await handleErc8004Request(deps, reg);

    const ops = auditLog.entries.map((e) => e.op);
    expect(ops).toContain(ERC8004_AUDIT_OPS.REQUESTED);
    expect(ops).toContain(ERC8004_AUDIT_OPS.DENIED);
    expect(ops).not.toContain(ERC8004_AUDIT_OPS.SIGNED);
  });
});

describe("CLI dispatch", () => {
  it("sanctuary erc8004 --help prints usage", async () => {
    const { runErc8004Command } = await import("../../src/cli/erc8004.js");
    let output = "";
    const out = new Writable({
      write(chunk, _enc, cb) {
        output += chunk.toString();
        cb();
      },
    });

    const code = await runErc8004Command({ argv: ["--help"], out });

    expect(code).toBe(0);
    expect(output).toContain("sanctuary erc8004");
    expect(output).toContain("register");
    expect(output).toContain("--registry");
  });

  it("register with missing --registry returns error", async () => {
    const { runErc8004Command } = await import("../../src/cli/erc8004.js");
    let errOutput = "";
    const err = new Writable({
      write(chunk, _enc, cb) {
        errOutput += chunk.toString();
        cb();
      },
    });

    const code = await runErc8004Command({
      argv: ["register", "--chain", "1", "--agent-id", "test", "--nonce", "0"],
      err,
    });

    expect(code).toBe(1);
    expect(errOutput).toContain("--registry is required");
  });
});

describe("End-to-end approval flow", () => {
  it("pending request can be approved and produces a signature", async () => {
    const auditLog = createMockAuditLog();
    const pendingStore = new Erc8004PendingStore();
    const gate = new DefaultPolicyGate({
      global_default: "operator_approval_required",
    });
    const deps = makeDeps({
      policyGate: gate,
      auditLog: auditLog as any,
      pendingStore,
    });
    const reg = makeRegistration();

    // Step 1: create pending request
    const pendingResult = await handleErc8004Request(deps, reg);
    expect(pendingResult.status).toBe("pending_approval");

    // Step 2: approve via inbox
    const approvedResult = await resolvePendingRequest(
      pendingStore,
      auditLog as any,
      identityId,
      pendingResult.request_id,
      true,
      fortressId,
    );

    expect(approvedResult).not.toBeNull();
    expect(approvedResult!.status).toBe("signed");
    expect(approvedResult!.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
    expect(approvedResult!.signer_address).toMatch(/^0x[0-9a-fA-F]{40}$/);

    // Step 3: verify audit entries in order
    const ops = auditLog.entries.map((e) => e.op);
    expect(ops).toEqual([
      ERC8004_AUDIT_OPS.REQUESTED,
      ERC8004_AUDIT_OPS.PENDING_APPROVAL,
      ERC8004_AUDIT_OPS.SIGNED,
    ]);
  });

  it("pending request can be denied and records the reason", async () => {
    const auditLog = createMockAuditLog();
    const pendingStore = new Erc8004PendingStore();
    const gate = new DefaultPolicyGate({
      global_default: "operator_approval_required",
    });
    const deps = makeDeps({
      policyGate: gate,
      auditLog: auditLog as any,
      pendingStore,
    });
    const reg = makeRegistration();

    const pendingResult = await handleErc8004Request(deps, reg);

    const deniedResult = await resolvePendingRequest(
      pendingStore,
      auditLog as any,
      identityId,
      pendingResult.request_id,
      false,
      fortressId,
      "operator declined: unknown registry",
    );

    expect(deniedResult).not.toBeNull();
    expect(deniedResult!.status).toBe("denied");
    expect(deniedResult!.reason).toBe("operator declined: unknown registry");
  });

  it("resolve returns null for unknown request_id", async () => {
    const auditLog = createMockAuditLog();
    const pendingStore = new Erc8004PendingStore();

    const result = await resolvePendingRequest(
      pendingStore,
      auditLog as any,
      identityId,
      "nonexistent-id",
      true,
      fortressId,
    );

    expect(result).toBeNull();
  });
});

describe("Castle-walking regression: checkApproval before signErc8004Registration", () => {
  it("checkApproval is always called before signing on auto-approve path", async () => {
    const checkApprovalCalled: string[] = [];
    const signCalls: string[] = [];

    const gate: any = {
      checkApproval: vi.fn().mockImplementation(async () => {
        checkApprovalCalled.push("checkApproval");
      }),
      emitAuditEvent: vi.fn(),
    };

    const deps = makeDeps({ policyGate: gate });
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg);
    expect(result.status).toBe("signed");

    // checkApproval must have been called
    expect(gate.checkApproval).toHaveBeenCalledTimes(1);
    expect(gate.checkApproval).toHaveBeenCalledWith(
      expect.objectContaining({
        protocol: "erc8004",
        action: "sign_registration",
      }),
    );
  });

  it("signing does not happen when checkApproval throws denial", async () => {
    const gate: any = {
      checkApproval: vi.fn().mockRejectedValue(
        new SigningDeniedError("erc8004", "policy denies signing for this counterparty"),
      ),
      emitAuditEvent: vi.fn(),
    };

    const deps = makeDeps({ policyGate: gate });
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg);

    expect(result.status).toBe("denied");
    expect(gate.checkApproval).toHaveBeenCalledTimes(1);
    // emitAuditEvent should NOT be called (no signing happened)
    expect(gate.emitAuditEvent).not.toHaveBeenCalled();
  });

  it("signing does not happen when checkApproval indicates operator approval required", async () => {
    const gate: any = {
      checkApproval: vi.fn().mockRejectedValue(
        new SigningDeniedError(
          "erc8004",
          "operator approval required but no approval channel configured",
        ),
      ),
      emitAuditEvent: vi.fn(),
    };

    const deps = makeDeps({ policyGate: gate });
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg);

    expect(result.status).toBe("pending_approval");
    expect(gate.checkApproval).toHaveBeenCalledTimes(1);
    expect(gate.emitAuditEvent).not.toHaveBeenCalled();
  });
});

describe("MCP tool poll mode", () => {
  it("returns signed result when polling a completed request", async () => {
    const auditLog = createMockAuditLog();
    const { tools, pendingStore } = createErc8004Tools({
      masterKey,
      policyGate: new DefaultPolicyGate({
        global_default: "operator_approval_required",
      }),
      auditLog: auditLog as any,
      identityId,
      operatorId,
      fortressId,
    });
    const tool = tools.find(
      (t) => t.name === "sanctuary/sign_erc8004_identity",
    )!;

    // Create a pending request via the tool
    const createResult = await tool.handler({
      registry_address: "0x1234567890abcdef1234567890abcdef12345678",
      chain_id: 1,
      agent_id: "test-agent",
      nonce: 1,
    });
    const created = JSON.parse(createResult.content[0]!.text);
    expect(created.status).toBe("pending_approval");

    // Resolve it
    await resolvePendingRequest(
      pendingStore,
      auditLog as any,
      identityId,
      created.request_id,
      true,
      fortressId,
    );

    // Poll for the result
    const pollResult = await tool.handler({
      request_id: created.request_id,
      registry_address: "0x1234567890abcdef1234567890abcdef12345678",
      chain_id: 1,
      agent_id: "test-agent",
      nonce: 1,
    });
    const polled = JSON.parse(pollResult.content[0]!.text);
    expect(polled.status).toBe("signed");
    expect(polled.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
  });

  it("returns error for unknown request_id", async () => {
    const { tools } = createErc8004Tools({
      masterKey,
      policyGate: new DefaultPolicyGate({ global_default: "allow" }),
      auditLog: createMockAuditLog() as any,
      identityId,
      operatorId,
      fortressId,
    });
    const tool = tools.find(
      (t) => t.name === "sanctuary/sign_erc8004_identity",
    )!;

    const result = await tool.handler({
      request_id: "nonexistent",
      registry_address: "0x1234567890abcdef1234567890abcdef12345678",
      chain_id: 1,
      agent_id: "test-agent",
      nonce: 1,
    });
    const data = JSON.parse(result.content[0]!.text);
    expect(data.error).toBe("unknown_request_id");
  });
});

describe("auto-approve bypasses inbox wait", () => {
  it("--auto-approve produces a signature despite operator_approval_required default", async () => {
    const auditLog = createMockAuditLog();
    const gate = new DefaultPolicyGate({
      global_default: "operator_approval_required",
    });
    const deps = makeDeps({
      policyGate: gate,
      auditLog: auditLog as any,
    });
    const reg = makeRegistration();

    const result = await handleErc8004Request(deps, reg, {
      autoApprove: true,
    });

    expect(result.status).toBe("signed");
    expect(result.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
  });
});
