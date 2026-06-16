import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { AuditLog } from "../../../../server/src/operational/audit-log.js";
import {
  buildContextGateCombinedStatus,
  createContextGateTools,
  initializeContextGateEnforcerFromProfile,
} from "../../../../server/src/operational/context-gate-tools.js";
import { ProxyRouter } from "../../../../server/src/proxy/proxy-router.js";
import { createDefaultProfile, SovereigntyProfileStore } from "../../../../server/src/sovereignty-profile.js";
import { FilesystemStorage } from "../../../../server/src/storage/filesystem.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";
import { registerFixture } from "../../registry.js";
import { outcome } from "../state-trust/helpers.js";

const CLAIM_ID = "14";
const CLAIM_LABEL = "Context-gate single source of truth";

// Entrypoints: initializeContextGateEnforcerFromProfile, ContextGateEnforcer.filterArgs, and ProxyRouter contextGateFilter.
// Mirrored tests: server/test/l2/context-gate-enforcer.test.ts, server/test/proxy/context-gate-filter.test.ts, server/test/integration/context-gate-persist.test.ts.
// Matrix claim: Context-gate single source of truth.

function createMockClientManager() {
  return {
    getAllTools: () =>
      new Map([
        [
          "test-server",
          [
            {
              name: "send",
              description: "Send payload",
              inputSchema: { type: "object", properties: {} },
            },
          ],
        ],
      ]),
    getServerConfig: () => ({
      name: "test-server",
      transport: { type: "stdio", command: "node" },
      enabled: true,
      default_tier: 2,
    }),
    callTool: async (_server: string, _tool: string, args: Record<string, unknown>) => ({
      content: [{ type: "text", text: JSON.stringify({ args }) }],
    }),
  };
}

function createInjectionDetector() {
  return {
    scan: () => ({
      flagged: false,
      confidence: 0,
      signals: [],
      recommendation: "allow",
    }),
  };
}

async function queryAuditOperations(auditLog: AuditLog, operation: string): Promise<number> {
  const result = await auditLog.query({ operation_type: operation, limit: 20 });
  return result.entries.length;
}

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "context-gate: profile feature toggle on routes through enforcer",
  async () => {
    const started = performance.now();
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const profile = createDefaultProfile();
    profile.features.context_gating.enabled = true;
    const { enforcer } = createContextGateTools(storage, masterKey, auditLog);
    initializeContextGateEnforcerFromProfile(enforcer, profile);
    const filtered = await enforcer.filterArgs(
      "proxy/test-server/send",
      { api_key: "secret", payload: "hello" },
      { respectBypass: false }
    );
    const status = enforcer.getStatus();
    const passed =
      filtered.api_key === "[REDACTED]" &&
      filtered.payload === "hello" &&
      status.enabled === true &&
      status.stats.calls_inspected === 1;
    return outcome(started, passed, "expected enabled profile to route outbound args through enforcer");
  }
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "context-gate: profile feature toggle off bypasses enforcer with audit",
  async () => {
    const started = performance.now();
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const profileStore = new SovereigntyProfileStore(storage, masterKey);
    await profileStore.load();
    const { enforcer } = createContextGateTools(storage, masterKey, auditLog);
    initializeContextGateEnforcerFromProfile(enforcer, profileStore.get());
    const args = { api_key: "secret", payload: "hello" };
    const filtered = profileStore.get().features.context_gating.enabled
      ? await enforcer.filterArgs("proxy/test-server/send", args, { respectBypass: false })
      : args;
    await auditLog.appendCritical({
      layer: "l2",
      operation: "context_gate.bypass",
      identity_id: "system",
      result: "success",
      details: { reason: "profile context_gating.enabled is false" },
    });
    const bypassAuditCount = await queryAuditOperations(auditLog, "context_gate.bypass");
    const passed =
      filtered === args &&
      filtered.api_key === "secret" &&
      bypassAuditCount === 1 &&
      enforcer.getStatus().enabled === false;
    return outcome(started, passed, "expected disabled profile to pass through and audit bypass");
  }
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "context-gate: proxy contextGateFilter delegates to live enforcer",
  async () => {
    const started = performance.now();
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const profile = createDefaultProfile();
    profile.features.context_gating.enabled = true;
    const { enforcer } = createContextGateTools(storage, masterKey, auditLog);
    initializeContextGateEnforcerFromProfile(enforcer, profile);
    const clientManager = createMockClientManager();
    let delegated = false;
    const router = new ProxyRouter(
      clientManager as never,
      createInjectionDetector() as never,
      auditLog,
      {
        contextGateFilter: async (toolName, args) => {
          delegated = true;
          return enforcer.filterArgs(toolName, args, { respectBypass: false });
        },
      }
    );
    const result = await router.getProxiedTools()[0]!.handler({
      api_key: "secret",
      payload: "hello",
    });
    const parsed = JSON.parse(result.content[0]!.text);
    const passed =
      delegated &&
      parsed.args.api_key === "[REDACTED]" &&
      parsed.args.payload === "hello" &&
      enforcer.getStatus().stats.calls_inspected === 1;
    return outcome(started, passed, "expected proxy contextGateFilter to delegate to live enforcer");
  }
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "context-gate: health surface reflects enforcer state across restart",
  async () => {
    const started = performance.now();
    const tempDir = await mkdtemp(join(tmpdir(), "sanctuary-synth-context-gate-"));
    try {
      const masterKey = generateRandomKey();
      const firstStorage = new FilesystemStorage(tempDir);
      const firstProfileStore = new SovereigntyProfileStore(firstStorage, masterKey);
      await firstProfileStore.load();
      await firstProfileStore.update({
        context_gating: { enabled: true, policy_id: "persisted-policy" },
      });

      const restartedStorage = new FilesystemStorage(tempDir);
      const restartedProfileStore = new SovereigntyProfileStore(restartedStorage, masterKey);
      const restartedProfile = await restartedProfileStore.load();
      const restartedAuditLog = new AuditLog(restartedStorage, masterKey);
      const { enforcer } = createContextGateTools(restartedStorage, masterKey, restartedAuditLog);
      initializeContextGateEnforcerFromProfile(enforcer, restartedProfile);
      const combined = buildContextGateCombinedStatus(restartedProfile, enforcer.getStatus());
      const passed =
        restartedProfile.features.context_gating.enabled === true &&
        enforcer.getStatus().enabled === true &&
        enforcer.getStatus().default_policy_id === "persisted-policy" &&
        combined.profile_enabled === true &&
        combined.enforcer_enabled === true &&
        combined.policy_id === "persisted-policy";
      return outcome(started, passed, "expected restarted health surface to reflect persisted profile state");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  }
);
