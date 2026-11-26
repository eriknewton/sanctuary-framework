/**
 * sanctuary_active_protections reads the audit log as an agent reader: a
 * refused broker request leaves its output byte-equal to a world without
 * that request, and two kinds of refused broker request read back alike.
 * The operator's feature-health and custody panels keep every row.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Backend } from "../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/disclosure/broker/backend-interface.js";
import { Broker } from "../../src/disclosure/broker/broker.js";
import { createBrokerMcpServer } from "../../src/broker-mcp/broker-server.js";
import { AuditLog, BROKER_OPS, runInCallScope, settleCallOutcome } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { COOPERATIVE_TOOL_NAMES } from "../../src/agent-native/tool-names.js";
import { ApprovalProofStore } from "../../src/agent-native/safety-base.js";
import { buildFeatureHealthPanel, SLICE1_FEATURE_REGISTRY } from "../../src/principal-policy/feature-health.js";
import { buildCustodyExitPanel } from "../../src/principal-policy/posture.js";
import { recordingNamespaceInserts } from "../helpers/cooperative-test-options.js";

const IDENTITY = "did:sanctuary:protections";
// One fixed instant for every world, so no reading depends on when a world ran.
const FROZEN_AT = Date.parse("2026-11-26T00:00:00.000Z");
const ISO_TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/g;
// Must match the audit_ref shape `audit:<operation>:<16 hex>` the cooperative surface returns.
const AUDIT_REF = /audit:[a-z_]+:[0-9a-f]{16}/g;

type Handler = (req: unknown, extra: unknown) => Promise<{ isError?: boolean; content: Array<{ text: string }> }>;
// The registry row the broker's token rows feed; the operator panel's count of it must include a refused request.
const SECRET_BROKER_FEATURE = "secret_broker";

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"], now: FROZEN_AT });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function backend(): Backend {
  const store = new Map([["openai-api-key", "value"], ["bound-key", "value"]]);
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() { return true; },
    async addSecret(n, v) { store.set(n, v); },
    async readSecret(n) {
      const v = store.get(n);
      if (v === undefined) throw new SecretNotFoundError(n);
      return v;
    },
    async rotateSecret(n, v) { store.set(n, v); },
    async deleteSecret(n) { store.delete(n); },
    async listSecretNames() { return Array.from(store.keys()); },
  };
}

/** One world: a broker server and the cooperative surface over one audit log, with no bound session. */
async function world() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const broker = new Broker({
    backend: backend(),
    auditLog,
    surrogateBoundSecrets: new Set(["bound-key"]),
    grants: [
      { skill: "gmail-triage", secret: "openai-api-key", scope: "read" },
      { skill: "gmail-triage", secret: "bound-key", scope: "read" },
    ],
    principalIdentityId: IDENTITY,
  });
  const server = createBrokerMcpServer(broker, {
    skill: "gmail-triage",
    agentId: "nsa",
    identityId: IDENTITY,
    tenantId: "tenant-alpha",
    fortressId: "fortress-alpha",
    audience: "sanctuary-broker",
  });
  const brokerHandler = (server as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers.get("tools/call")!;
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(stateStore, storage, masterKey, "recovery-key", auditLog,
    { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => undefined });
  await identityManager.load();
  const { tools } = createAgentNativeCooperativeTools({
    baselineNamespaceInserts: recordingNamespaceInserts(),
    identityManager,
    namespaceRegistry,
    auditLog,
    currentSessionBinding: () => undefined,
    primitiveTools: l1Tools,
    storage,
    approvalProofStore: new ApprovalProofStore(),
    // A conclusive absence, so the broker rows are judged on their audit evidence alone.
    resolveBrokerProducerKey: async () => ({ keyB64url: null, observation: "absent" }),
  });
  const protections = tools.find((t) => t.name === COOPERATIVE_TOOL_NAMES.activeProtections)!;
  return {
    auditLog,
    requestToken: async (secret: string) => {
      const result = await brokerHandler({ method: "tools/call", params: { name: "broker/request_token", arguments: { skill: "gmail-triage", secret } } }, { signal: new AbortController().signal });
      expect(result.isError).toBe(true);
    },
    /**
     * The tool's whole result, every content block plus isError and every envelope field, serialized with
     * timestamps and its own audit reference normalized; a difference in any block is a difference here.
     */
    read: async () => {
      await auditLog.flush();
      const result = await protections.handler({}, "agent:protections", {});
      return JSON.stringify(result).replace(ISO_TIMESTAMP, "<timestamp>").replace(AUDIT_REF, "<audit_ref>");
    },
  };
}

describe("sanctuary_active_protections follows the agent visibility rule", () => {
  it("a refused broker token request with no grant leaves the output byte-equal to a world without it", async () => {
    const control = await world();
    const treatment = await world();
    await treatment.requestToken("never-granted");
    expect(await treatment.read()).toBe(await control.read());
  });

  it("a no-grant refusal and a surrogate-bound refusal read back byte-equal to each other", async () => {
    const noGrant = await world();
    const surrogateBound = await world();
    await noGrant.requestToken("never-granted");
    await surrogateBound.requestToken("bound-key");
    expect(await noGrant.read()).toBe(await surrogateBound.read());
  });

  it("the operator's feature-health panel still counts the refused request", async () => {
    const control = await world();
    const treatment = await world();
    await treatment.requestToken("never-granted");
    await control.auditLog.flush();
    await treatment.auditLog.flush();
    const brokerRow = async (auditLog: AuditLog, agentVisible?: true) =>
      (await buildFeatureHealthPanel({ auditLog, originMachine: "local", registry: SLICE1_FEATURE_REGISTRY, protectionClaimSubject: null, agentVisible }))
        .rows.find((row) => row.feature_id === SECRET_BROKER_FEATURE)!;
    const operatorRows = (await treatment.auditLog.query({ limit: 1_000 })).entries.map((e) => e.operation);
    expect(operatorRows).toContain(BROKER_OPS.TOKEN_DENIED);
    // Polarity: the operator panel itself shows the refused request, one more than a world without it.
    const operator = await brokerRow(treatment.auditLog);
    const operatorControl = await brokerRow(control.auditLog);
    expect(operatorControl.invocation_count).toBe(0);
    expect(operator.invocation_count).toBe(1);
    expect(operator.status).toBe("active");
    expect(operator.last_evidence_at).not.toBeNull();
    // The agent panel over the same log leaves it out.
    const agent = await brokerRow(treatment.auditLog, true);
    expect(agent.invocation_count).toBe(0);
    expect(agent).toEqual(operatorControl);
  });

  it("the custody panel an agent caller builds leaves out a refused call's custody row, and the operator's keeps it", async () => {
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    await runInCallScope(async (scope) => {
      await log.append("l1", "custody_rollback_suspected", "system", {});
      settleCallOutcome(scope, "refused");
    });
    await log.flush();
    const agent = await buildCustodyExitPanel({ auditLog: log, originMachine: "local", agentVisible: true });
    const operator = await buildCustodyExitPanel({ auditLog: log, originMachine: "local" });
    expect(agent.rollback_freeze_suspected).toBe(false);
    expect(operator.rollback_freeze_suspected).toBe(true);
  });
});
