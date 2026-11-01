import { afterEach, describe, expect, it, vi } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";
import { evaluateFeatureHealth, SLICE1_FEATURE_REGISTRY } from "../../src/principal-policy/feature-health.js";
import * as healthSource from "../../src/principal-policy/feature-health.js";
import * as custodySource from "../../src/principal-policy/posture.js";
import { DEFAULT_ENFORCEMENT_FRESHNESS_MS } from "../../src/principal-policy/posture.js";
import { composeProtectionLayers, type ProtectionEvidence } from "../../src/agent-native/protection-layers.js";
import { capStalePanel } from "../../src/principal-policy/panel-producer.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const names = ["Identity", "Encrypted vault", "Mantle binding", "Approval gates", "Signed record",
  "Castle Wall", "Context gate", "Local model routing", "Sentinels", "Query privacy",
  "Credential stand-ins", "Exit", "Inbound protection"];
const guarantees = ["state_encrypted_at_rest", "approval_gate_mediated",
  "append_only_audit_for_critical_operations", "opaque_memory_namespace_handles"];

async function setup(extra: Partial<Parameters<typeof createAgentNativeCooperativeTools>[0]> = {}) {
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
    auditLog, storage, currentSessionBinding: () => binding, ...extra });
  const tool = facade.tools.find(t => t.name === "sanctuary_active_protections")!;
  return { auditLog, tool, binding, primitives };
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
      composeProtectionLayers({ featureHealth: { rows: [{ ...row, status, basis, last_evidence_at: new Date().toISOString() }], audit_integrity_ok: integrity, window_end: new Date().toISOString() } });
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
    expect(home.protection_layers).toEqual(composeProtectionLayers({ featureHealth: home.feature_health, custodyExit: home.custody_exit, custodyObservation: home.panels!.custody_exit }));
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


afterEach(() => vi.restoreAllMocks());

const observedAt = Date.parse("2026-11-01T12:00:00Z");
const currentObservation = { state: "fresh" as const, completed_at: new Date(observedAt).toISOString() };
const failures = ["throws", "fallback", "stale", "integrity false"] as const;

async function currentPanels() {
  const { auditLog } = await setup();
  const health = await healthSource.buildFeatureHealthPanel({ auditLog, originMachine: "test", now: observedAt, protectionClaimSubject: null });
  for (const row of health.rows) {
    row.status = "active";
    row.last_evidence_at = new Date(observedAt).toISOString();
  }
  const custody = await custodySource.buildCustodyExitPanel({ auditLog, originMachine: "test", now: observedAt });
  return { health, custody };
}

describe("current protection evidence", () => {
  for (const id of ["approval_gates", "castle_wall", "query_privacy", "credential_stand_ins", "signed_record", "exit"]) {
    for (const failure of failures) {
      it(`${id}: ${failure} never earns on through composer or cooperative consumer`, async () => {
        const { health, custody } = await currentPanels();
        const { auditLog, tool } = await setup();
        vi.spyOn(Date, "now").mockReturnValue(observedAt);
        const evidence: ProtectionEvidence = { featureHealth: health, custodyExit: custody,
          custodyObservation: currentObservation, auditChain: "verified", now: observedAt };
        if (failure === "throws") {
          vi.spyOn(healthSource, "buildFeatureHealthPanel").mockRejectedValue(new Error("unavailable"));
          vi.spyOn(custodySource, "buildCustodyExitPanel").mockRejectedValue(new Error("unavailable"));
          vi.spyOn(auditLog, "getAuditChainVerdict").mockRejectedValue(new Error("unavailable"));
          delete evidence.featureHealth;
          delete evidence.custodyExit;
          delete evidence.auditChain;
        } else if (failure === "fallback") {
          evidence.featureHealth = capStalePanel("feature_health", health);
          evidence.custodyExit = { ...custody, audit_integrity_ok: false };
          evidence.custodyObservation = { state: "unavailable", completed_at: null };
        } else if (failure === "stale") {
          // One millisecond beyond the existing feature-health freshness window.
          evidence.now = observedAt + DEFAULT_ENFORCEMENT_FRESHNESS_MS + 1;
          // Advance during the read so the cooperative observation's start also expires.
          vi.spyOn(healthSource, "buildFeatureHealthPanel").mockImplementation(async () => {
            vi.spyOn(Date, "now").mockReturnValue(evidence.now!);
            return health;
          });
        } else {
          evidence.featureHealth = { ...health, audit_integrity_ok: false };
          evidence.custodyExit = { ...custody, audit_integrity_ok: false };
          evidence.auditChain = "findings";
        }
        if (failure !== "throws") {
          if (failure !== "stale") vi.spyOn(healthSource, "buildFeatureHealthPanel").mockResolvedValue(evidence.featureHealth as healthSource.FeatureHealthPanel);
          vi.spyOn(custodySource, "buildCustodyExitPanel").mockResolvedValue(evidence.custodyExit!);
        }
        const direct = composeProtectionLayers(evidence).find(row => row.id === id)!;
        expect(direct.status).toBe("unknown");
        const result = JSON.parse((await tool.handler({})).content[0]!.text);
        expect(result.layers.find((row: { id: string }) => row.id === id).status).toBe("unknown");
      });
    }
  }

  it("Exit names a failed audit read and never promotes its constant export label", async () => {
    const { tool, auditLog } = await setup();
    vi.spyOn(auditLog, "query").mockRejectedValue(new Error("unavailable"));
    const custodyExit = await custodySource.buildCustodyExitPanel({ auditLog, originMachine: "test" });
    expect(custodyExit.exit_state).toBe("export_available");
    const rows = composeProtectionLayers({ custodyExit, custodyObservation: currentObservation, now: observedAt });
    expect(rows.find(row => row.id === "exit")).toMatchObject({ status: "unknown", basis: expect.stringContaining("audit read") });
    const result = JSON.parse((await tool.handler({})).content[0]!.text);
    expect(result.layers.find((row: { id: string }) => row.id === "exit"))
      .toMatchObject({ status: "unknown", basis: expect.stringContaining("audit read") });
  });

  it("Exit requires a fresh complete observation and verified integrity", async () => {
    const { custody } = await currentPanels();
    const read = (extra: Partial<ProtectionEvidence>) => composeProtectionLayers({ custodyExit: custody, now: observedAt, ...extra }).find(row => row.id === "exit")!;
    expect(read({}).status).toBe("unknown");
    expect(read({ custodyObservation: currentObservation }).status).toBe("on");
    expect(read({ custodyObservation: { state: "unavailable", completed_at: null } }))
      .toMatchObject({ status: "unknown", basis: expect.stringContaining("fallback") });
    expect(read({ custodyObservation: { ...currentObservation, state: "stale" } }))
      .toMatchObject({ status: "unknown", basis: expect.stringContaining("stale") });
  });

  for (const [id, featureId] of [["approval_gates", "approval_gates"], ["credential_stand_ins", "secret_broker"]]) {
    it(`${id}: bounds activity by the existing freshness window on both surfaces`, async () => {
      const { health } = await currentPanels();
      const { tool } = await setup();
      health.rows = health.rows.filter(row => row.feature_id === featureId);
      vi.spyOn(healthSource, "buildFeatureHealthPanel").mockResolvedValue(health);
      for (const [age, status] of [[DEFAULT_ENFORCEMENT_FRESHNESS_MS, "on"], [DEFAULT_ENFORCEMENT_FRESHNESS_MS + 1, "unknown"], [23 * 60 * 60 * 1000, "unknown"]] as const) {
        // Twenty-three hours is inside the digest but outside current evidence.
        health.rows[0]!.last_evidence_at = new Date(observedAt - age).toISOString();
        vi.spyOn(Date, "now").mockReturnValue(observedAt);
        const direct = composeProtectionLayers({ featureHealth: health, now: observedAt }).find(row => row.id === id)!;
        const result = JSON.parse((await tool.handler({})).content[0]!.text);
        for (const row of [direct, result.layers.find((row: { id: string }) => row.id === id)]) {
          expect(row.status).toBe(status);
          if (status === "unknown") expect(row.basis).toContain("activity in the last 24 hours, not current");
        }
      }
    });
  }

  it("a down broker daemon lowers fresh token activity to off on both surfaces", async () => {
    const { health } = await currentPanels();
    const { tool } = await setup();
    health.rows.find(row => row.feature_id === "secret_broker_daemon")!.status = "fault";
    vi.spyOn(Date, "now").mockReturnValue(observedAt);
    vi.spyOn(healthSource, "buildFeatureHealthPanel").mockResolvedValue(health);
    expect(composeProtectionLayers({ featureHealth: health, now: observedAt }).find(row => row.id === "credential_stand_ins")?.status).toBe("off");
    const result = JSON.parse((await tool.handler({})).content[0]!.text);
    expect(result.layers.find((row: { id: string }) => row.id === "credential_stand_ins").status).toBe("off");
  });
});


describe("live Castle Wall wording", () => {
  for (const [arm, value] of [["degraded", "degraded"], ["locked_down", "locked down"], ["armed", "enforcing"], ["unknown", "not enforcing"]]) {
    it(`preserves ${value} from the live seal with a conflicting composer row`, async () => {
      const { getClientScript } = await import("../../src/dashboard/v1_1/client.js");
      const script = getClientScript();
      const start = script.indexOf("function postureLayerLines()");
      const end = script.indexOf("async function onAutoTriggerRecommendation", start);
      const render = new Function("state", "deriveSeal", `
        const HUB = "/api/hub";
        const sourceLoaded = () => true;
        const evidenceCurrent = () => true;
        const heldApprovalItems = () => [];
        const approvalQueueEvidence = () => ({});
        ${script.slice(start, end)}
        return postureLayerLines();
      `);
      const inventory = composeProtectionLayers({});
      inventory.find(row => row.id === "castle_wall")!.status = "on";
      const lines = render({ posture: { home: { protection_layers: inventory } } }, () => ({ arm, freshness: { current: true } }));
      expect(lines.find((line: { k: string }) => line.k === "Castle Wall (boundary)"))
        .toMatchObject({ v: value, warn: arm !== "armed" });
    });
  }
});


describe("evidence consumer boundaries", () => {
  for (const failure of failures) {
    it(`Credential stand-ins: daemon ${failure} cannot support on`, async () => {
      const { health } = await currentPanels();
      const { tool } = await setup();
      const daemon = health.rows.find(row => row.feature_id === "secret_broker_daemon")!;
      if (failure === "stale") daemon.last_evidence_at = new Date(observedAt - DEFAULT_ENFORCEMENT_FRESHNESS_MS - 1).toISOString();
      else if (failure === "integrity false") daemon.audit_integrity_ok = false;
      else daemon.status = "unknown"; // The producer projects unreadable and fallback observations as unknown.
      vi.spyOn(Date, "now").mockReturnValue(observedAt);
      vi.spyOn(healthSource, "buildFeatureHealthPanel").mockResolvedValue(health);
      expect(composeProtectionLayers({ featureHealth: health, now: observedAt }).find(row => row.id === "credential_stand_ins")?.status).toBe("unknown");
      const result = JSON.parse((await tool.handler({})).content[0]!.text);
      expect(result.layers.find((row: { id: string }) => row.id === "credential_stand_ins").status).toBe("unknown");
    });
  }

  for (const id of ["approval_gates", "castle_wall", "credential_stand_ins", "query_privacy"]) {
    it(`${id}: row integrity false is restrictive even with a clean panel`, async () => {
      const { health } = await currentPanels();
      const { tool } = await setup();
      health.rows.forEach(row => { row.audit_integrity_ok = false; });
      vi.spyOn(Date, "now").mockReturnValue(observedAt);
      vi.spyOn(healthSource, "buildFeatureHealthPanel").mockResolvedValue(health);
      expect(composeProtectionLayers({ featureHealth: health, now: observedAt }).find(row => row.id === id)?.status).toBe("unknown");
      const result = JSON.parse((await tool.handler({})).content[0]!.text);
      expect(result.layers.find((row: { id: string }) => row.id === id).status).toBe("unknown");
    });
  }

  for (const failure of ["fallback", "stale"] as const) {
    it(`Exit: posture home propagates ${failure} provenance`, async () => {
      const { buildHome } = await import("../../src/principal-policy/posture-routes.js");
      const { createPosturePanelStore } = await import("../../src/principal-policy/panel-producer.js");
      const { createDashboardReadFlightMap } = await import("../../src/dashboard/read-response.js");
      const { custody } = await currentPanels();
      const { auditLog } = await setup();
      const panelStore = createPosturePanelStore({ now: () => observedAt });
      const read = panelStore.read.bind(panelStore);
      vi.spyOn(panelStore, "read").mockImplementation(async (id, sequence, produce, key) => id === "custody_exit"
        ? { value: failure === "fallback" ? undefined : custody,
          status: { ...panelStore.snapshot(id).status, state: failure === "fallback" ? "unavailable" : "stale",
            completed_at: currentObservation.completed_at } } as Awaited<ReturnType<typeof read>>
        : read(id, sequence, produce, key));
      const home = await buildHome({ auditLog, originMachine: "test", listAgents: () => [], now: () => observedAt,
        detectInstalledHarnesses: async () => [], resolvePinnedProducerKey: () => null,
        resolveBrokerPinnedProducerKey: () => null, panelStore, readFlightMap: createDashboardReadFlightMap() });
      expect(home.custody_exit.exit_state).toBe("export_available");
      expect(home.protection_layers?.find(row => row.id === "exit"))
        .toMatchObject({ status: "unknown", basis: expect.stringContaining(failure) });
    });
  }

  it("Identity uses a new lookup on every call and denies a throwing lookup", async () => {
    const { tool, primitives } = await setup();
    const get = vi.spyOn(primitives.identityManager, "get");
    get.mockReturnValue(undefined);
    expect(composeProtectionLayers({ identityLoaded: false })[0]?.status).toBe("off");
    let result = JSON.parse((await tool.handler({})).content[0]!.text);
    expect(result.layers.find((row: { id: string }) => row.id === "identity").status).toBe("off");
    get.mockImplementation(() => { throw new Error("unavailable"); });
    result = JSON.parse((await tool.handler({})).content[0]!.text);
    expect(result).toHaveProperty("denied", true);
    expect(result).not.toHaveProperty("layers");
  });

  it("Encrypted vault reports construction only and denies an unreadable construction source", async () => {
    const { tool } = await setup();
    const result = JSON.parse((await tool.handler({})).content[0]!.text);
    expect(result.layers.find((row: { id: string }) => row.id === "encrypted_vault").status).toBe("unknown");
    expect(composeProtectionLayers({ encryptedStateStoreConstructed: false })[1]?.status).toBe("off");
    const { primitives, auditLog, binding } = await setup();
    const facade = createAgentNativeCooperativeTools({ ...primitives, primitiveTools: primitives.tools,
      auditLog, currentSessionBinding: () => binding,
      get stateStore(): StateStore { throw new Error("unavailable"); } });
    const response = JSON.parse((await facade.tools.find(tool => tool.name === "sanctuary_active_protections")!.handler({})).content[0]!.text);
    expect(response).toHaveProperty("denied", true);
    expect(response).not.toHaveProperty("layers");
  });

  it("Inbound protection remains not built when its separate screening source throws", async () => {
    const { tool } = await setup({ responseScreen: { assertReady() { throw new Error("unavailable"); } } });
    expect(composeProtectionLayers({ toolOutputScreenReady: false }).at(-1)?.status).toBe("not_built");
    const result = JSON.parse((await tool.handler({})).content[0]!.text);
    expect(result.layers.at(-1)).toMatchObject({ status: "not_built", basis: expect.stringContaining("screening readiness: off") });
  });
});
