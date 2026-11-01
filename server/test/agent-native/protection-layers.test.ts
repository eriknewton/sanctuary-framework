import { describe, expect, it } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";
import { evaluateFeatureHealth, SLICE1_FEATURE_REGISTRY } from "../../src/principal-policy/feature-health.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const names = ["Identity", "Encrypted vault", "Mantle binding", "Approval gates", "Signed record",
  "Castle Wall", "Context gate", "Local model routing", "Sentinels", "Query privacy",
  "Credential stand-ins", "Exit", "Inbound protection"];
const guarantees = ["state_encrypted_at_rest", "approval_gate_mediated",
  "append_only_audit_for_critical_operations", "opaque_memory_namespace_handles"];

async function setup() {
  const storage = new MemoryStorage();
  const key = generateRandomKey();
  const auditLog = new AuditLog(storage, key);
  let binding: SessionBinding | undefined;
  const primitives = createCognitiveTools(new StateStore(storage, key), storage, key, "recovery-key", auditLog,
    { currentSessionBinding: () => binding });
  await primitives.identityManager.load();
  const created = await primitives.tools.find(t => t.name === "identity_create")!.handler({ label: "protections-test" });
  const identity = JSON.parse(created.content[0]!.text);
  binding = { identity_id: identity.identity_id, requester_identity_fingerprint: fingerprintIdentityId(identity.identity_id) };
  const facade = createAgentNativeCooperativeTools({ ...primitives, primitiveTools: primitives.tools,
    auditLog, storage, currentSessionBinding: () => binding });
  const tool = facade.tools.find(t => t.name === "sanctuary_active_protections")!;
  return { auditLog, tool, binding };
}

describe("protection layers", () => {
  it("returns every layer once in order, preserves guarantees, and summarizes every row", async () => {
    const { tool } = await setup();
    const result = JSON.parse((await tool.handler({})).content[0]!.text);
    expect(result.guarantees).toEqual(guarantees);
    expect(result.layers).toBeDefined();
    expect(result.layers.map((r: { name: string }) => r.name)).toEqual(names);
    expect(new Set(result.layers.map((r: { id: string }) => r.id)).size).toBe(names.length);
    expect(result.summary.split("\n")).toEqual(result.layers.map((r: { name: string; status: string }) =>
      `${r.name}: ${r.status.replace("_", " ")}`));
    expect(result.audit_ref).toEqual(expect.any(String));
    expect(tool.description).toContain("every layer");
    expect(result.layers.at(-1)).toMatchObject({ name: "Inbound protection", status: "not_built" });
  });

  it("keeps every layer without evidence unknown, except the unbuilt inbound layer", async () => {
    const { composeProtectionLayers } = await import("../../src/agent-native/protection-layers.js");
    const rows = composeProtectionLayers({});
    expect(rows.map(r => r.name)).toEqual(names);
    expect(rows.slice(0, -1).every(r => r.status === "unknown" && r.basis === "no evidence source wired")).toBe(true);
    expect(rows.at(-1)?.status).toBe("not_built");
  });

  it("uses observed identity presence and absence, never a default on", async () => {
    const { composeProtectionLayers } = await import("../../src/agent-native/protection-layers.js");
    expect(composeProtectionLayers({ identityLoaded: true })[0]?.status).toBe("on");
    expect(composeProtectionLayers({ identityLoaded: false })[0]?.status).toBe("off");
    expect(composeProtectionLayers({})[0]?.status).toBe("unknown");
  });

  it("reads real approval activity through the cooperative consumer and keeps quiet evidence unknown", async () => {
    const { tool, auditLog, binding } = await setup();
    const read = async () => JSON.parse((await tool.handler({})).content[0]!.text).layers;
    expect((await read()).find((r: { id: string }) => r.id === "approval_gates").status).toBe("unknown");
    await auditLog.appendCritical({ layer: "l2", operation: "cross_harness_approval_resolved",
      identity_id: binding!.identity_id!, result: "success", details: {} });
    expect((await read()).find((r: { id: string }) => r.id === "approval_gates"))
      .toMatchObject({ status: "on", basis: "feature health: approval_gates" });
  });

  it("preserves feature-health integrity and off verdicts", async () => {
    const { composeProtectionLayers } = await import("../../src/agent-native/protection-layers.js");
    const feature = SLICE1_FEATURE_REGISTRY.find(r => r.id === "castle_wall_egress")!;
    const row = evaluateFeatureHealth({ feature, entries: [], originMachine: "test", now: Date.now(),
      freshnessWindowMs: 60_000, integrityOk: true }); // One minute evidence window.
    const layers = (status: typeof row.status, basis: typeof row.basis, integrity = true) =>
      composeProtectionLayers({ featureHealth: { rows: [{ ...row, status, basis }], audit_integrity_ok: integrity } });
    expect(layers("active", "fresh_enforcement_evidence").find(r => r.id === "castle_wall")?.status).toBe("on");
    expect(layers("unknown", "intentionally_stopped").find(r => r.id === "castle_wall")?.status).toBe("off");
    expect(layers("active", "fresh_enforcement_evidence", false).find(r => r.id === "castle_wall")?.status).toBe("unknown");
  });

  it("keeps screening readiness separate from the unbuilt inbound layer", async () => {
    const { composeProtectionLayers } = await import("../../src/agent-native/protection-layers.js");
    for (const ready of [true, false]) {
      expect(composeProtectionLayers({ toolOutputScreenReady: ready }).at(-1)).toMatchObject({
        status: "not_built", basis: `capability: not built; tool-output screening readiness: ${ready ? "on" : "off"}`,
      });
    }
  });

  it("wires construction evidence through the real server tool handler", async () => {
    const { createSanctuaryServer } = await import("../../src/index.js");
    const home = await createTempHome("protection-layers");
    const previousIdentity = process.env.SANCTUARY_SESSION_IDENTITY_ID;
    process.env.SANCTUARY_SESSION_IDENTITY_ID = "protection-test-session";
    let app: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;
    try {
      app = await createSanctuaryServer({ storage: new MemoryStorage(), passphrase: TEST_PASSPHRASE });
      const handler = (app.server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get("tools/call")!;
      const response = await handler({ method: "tools/call", params: { name: "sanctuary_active_protections", arguments: {} } }, {});
      const result = JSON.parse(response.content[0].text);
      expect(result.guarantees).toEqual(guarantees);
      expect(result.layers.find((r: { id: string }) => r.id === "encrypted_vault")).toMatchObject({ status: "on" });
      expect(result.layers.at(-1)).toMatchObject({ status: "not_built", basis: expect.stringContaining("screening readiness: off") });
    } finally {
      try { await app?.cleanup(); } finally {
        if (previousIdentity === undefined) delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
        else process.env.SANCTUARY_SESSION_IDENTITY_ID = previousIdentity;
        await home.cleanup();
      }
    }
  });

  it("shares the posture home's full inventory and recomputes it when evidence is superseded", async () => {
    const { buildHome, reconcilePostureHomeJoiner } = await import("../../src/principal-policy/posture-routes.js");
    const { createPosturePanelStore } = await import("../../src/principal-policy/panel-producer.js");
    const { createDashboardReadFlightMap } = await import("../../src/dashboard/read-response.js");
    const { composeProtectionLayers } = await import("../../src/agent-native/protection-layers.js");
    const { auditLog, binding } = await setup();
    await auditLog.appendCritical({ layer: "l2", operation: "cross_harness_approval_resolved",
      identity_id: binding!.identity_id!, result: "success", details: {} });
    const home = await buildHome({ auditLog, originMachine: "test", listAgents: () => [],
      detectInstalledHarnesses: async () => [], resolvePinnedProducerKey: () => null,
      resolveBrokerPinnedProducerKey: () => null, panelStore: createPosturePanelStore(),
      readFlightMap: createDashboardReadFlightMap() });
    expect(home.protection_layers?.map(r => r.name)).toEqual(names);
    expect(home.protection_layers).toEqual(composeProtectionLayers({ featureHealth: home.feature_health, custodyExit: home.custody_exit }));
    expect(home.protection_layers?.find(r => r.id === "approval_gates")?.status).toBe("on");
    const superseded = reconcilePostureHomeJoiner(home, 0, 1); // A follower observed one newer audit sequence.
    expect(superseded.protection_layers?.find(r => r.id === "approval_gates")?.status).toBe("unknown");
    expect(home.protection_layers?.find(r => r.id === "approval_gates")?.status).toBe("on");
  });

  it("renders the shared inventory in the dashboard and caps expired wall evidence", async () => {
    const { getClientScript } = await import("../../src/dashboard/v1_1/client.js");
    const { composeProtectionLayers } = await import("../../src/agent-native/protection-layers.js");
    const script = getClientScript();
    const start = script.indexOf("function postureLayerLines()");
    const end = script.indexOf("async function onAutoTriggerRecommendation", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const render = new Function("state", "sourceLoaded", "evidenceCurrent", `
      const HUB = "/api/hub";
      const deriveSeal = () => ({ freshness: {} });
      const heldApprovalItems = () => [];
      const approvalQueueEvidence = () => ({});
      ${script.slice(start, end)}
      return postureLayerLines();
    `);
    const inventory = composeProtectionLayers({ identityLoaded: true });
    const state = { posture: { home: { protection_layers: inventory, castle_wall: { arm_state: "unknown" } } } };
    const layerLines = (loaded: boolean, current: boolean) =>
      (render(state, () => loaded, () => current) as Array<{ k: string; v: string; unknown: boolean }>)
        .filter(r => names.includes(r.k));
    expect(layerLines(true, true).map(r => r.k)).toEqual(names);
    expect(layerLines(true, true).map(r => r.v.toLowerCase())).toEqual(inventory.map(r => r.status.replace("_", " ")));
    expect(layerLines(false, true).map(r => r.v.toLowerCase())).toEqual(composeProtectionLayers({}).map(r => r.status.replace("_", " ")));
    inventory.find(r => r.id === "castle_wall")!.status = "on";
    expect(layerLines(true, false).find(r => r.k === "Castle Wall")).toMatchObject({ v: "Unknown", unknown: true });
    state.posture.home.castle_wall.arm_state = "coarse_only";
    expect(layerLines(true, false).find(r => r.k === "Castle Wall")).toMatchObject({
      v: "Unknown; coarse-only (exclusive egress not live)", unknown: true,
    });
  });
});
