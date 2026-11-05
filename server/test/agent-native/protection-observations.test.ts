/** Shared protection observations. */
import { afterEach, expect, it, vi } from "vitest";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";
import * as healthSource from "../../src/principal-policy/feature-health.js";
import * as custodySource from "../../src/principal-policy/posture.js";
import { composeProtectionLayers, type ProtectionLayerRow } from "../../src/agent-native/protection-layers.js";
import { buildHome, reconcilePostureHomeJoiner } from "../../src/principal-policy/posture-routes.js";
import { createPosturePanelStore, capStalePanel } from "../../src/principal-policy/panel-producer.js";
import { createDashboardReadFlightMap } from "../../src/dashboard/read-response.js";
import { createTempHome } from "../helpers/temp-fortress.js";

const observedAt = Date.parse("2026-11-05T12:00:00Z"); // Shared fixed evaluation instant.
const FIRST_CONTENT = 0; // The text response occupies the first content block.
const LAST_ROW = -1; // Inbound protection is the final inventory row.
const completedAt = new Date(observedAt).toISOString();
const fresh = { state: "fresh" as const, completed_at: completedAt };
const guarantees = ["state_encrypted_at_rest", "approval_gate_mediated",
  "append_only_audit_for_critical_operations", "opaque_memory_namespace_handles"];
afterEach(() => vi.restoreAllMocks());

async function fixture() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  let binding: SessionBinding | undefined;
  const currentSessionBinding = () => binding;
  const primitives = createCognitiveTools(stateStore, storage, masterKey, "recovery-key", auditLog, { currentSessionBinding });
  await primitives.identityManager.load();
  const created = await primitives.tools.find(tool => tool.name === "identity_create")!.handler({ label: "observed-session" });
  const { identity_id } = JSON.parse(created.content[FIRST_CONTENT]!.text);
  binding = { identity_id, requester_identity_fingerprint: fingerprintIdentityId(identity_id) };
  const runtime = { identityManager: primitives.identityManager, stateStore, currentSessionBinding,
    responseScreen: { assertReady() {} } };
  const health = await healthSource.buildFeatureHealthPanel({ auditLog, originMachine: "local", protectionClaimSubject: null });
  health.window_end = completedAt;
  health.audit_integrity_ok = true;
  health.rows = health.rows.map(row => ({ ...row, audit_integrity_ok: true, status: "active" as const,
    last_evidence_at: completedAt, basis: "fresh_enforcement_evidence" as const }));
  const custody = await custodySource.buildCustodyExitPanel({ auditLog, originMachine: "local" });
  custody.audit_integrity_ok = true;
  vi.spyOn(Date, "now").mockReturnValue(observedAt);
  const healthRead = vi.spyOn(healthSource, "buildFeatureHealthPanel").mockResolvedValue(health);
  const custodyRead = vi.spyOn(custodySource, "buildCustodyExitPanel").mockResolvedValue(custody);
  const chain = await auditLog.getAuditChainVerdict();
  const chainRead = vi.spyOn(auditLog, "getAuditChainVerdict").mockRejectedValue(new Error("chain unavailable"));
  const makeTool = (sources = runtime) => createAgentNativeCooperativeTools({ ...primitives, ...sources,
    primitiveTools: primitives.tools, auditLog, storage,
    resolveBrokerProducerKey: async () => ({ keyB64url: null, observation: "absent" })
  }).tools.find(tool => tool.name === "sanctuary_active_protections")!;
  const readTool = async () => JSON.parse((await makeTool().handler({})).content[FIRST_CONTENT]!.text) as {
    layers: ProtectionLayerRow[]; summary: string; guarantees: string[]; audit_ref: string;
  };
  const panelStore = createPosturePanelStore({ now: () => observedAt });
  const deps = { auditLog, originMachine: "local", listAgents: () => [], detectInstalledHarnesses: async () => [],
    resolvePinnedProducerKey: () => null, resolveBrokerPinnedProducerKey: () => null,
    resolveEnforcementAvailability: async () => ({ status: "undetermined" as const, reason: "unavailable",
      observed_at: null, freshness_window_ms: custodySource.DEFAULT_ENFORCEMENT_FRESHNESS_MS, active_connection_count: 0 }), // No observed enforcement connections.
    panelStore, readFlightMap: createDashboardReadFlightMap(), now: () => observedAt,
    protectionRuntime: () => runtime };
  return { storage, masterKey, runtime, auditLog, health, custody, healthRead, custodyRead, chainRead, chain,
    makeTool, readTool, deps, setBinding: (value: SessionBinding | undefined) => { binding = value; } };
}
function status(rows: ProtectionLayerRow[] | undefined, id: string) {
  return rows?.find(row => row.id === id)?.status;
}

import { associateProtectionHome, observeProtectionJoiner, observeProtections, protectionRuntimeUnavailable, type QualifiedProtectionPanels } from "../../src/agent-native/protection-observations.js";
import { protectionEvidenceKeys, protectionEvidenceSchema, type ProtectionObservationSnapshot } from "../../src/agent-native/protection-layers.js";

it("protection surfaces share every observed layer", async () => {
  const homeDirectory = await createTempHome("shared-observations");
  try {
    const f = await fixture();
    const panels: QualifiedProtectionPanels = { featureHealth: f.health, custodyExit: f.custody,
      custodyObservation: fresh, now: observedAt, auditChain: undefined };
    const snapshot = observeProtections(f.runtime, panels);
    expect(snapshot.identityLoaded, "bound identity observation").toBe(true);
    expect(snapshot.encryptedStateStoreConstructed, "constructed vault observation").toBe(true);
    expect(Object.keys(snapshot).sort()).toEqual([...protectionEvidenceKeys].sort());
    const result = await f.readTool();
    const home = await buildHome(f.deps);
    expect(status(result.layers, "identity"), "Identity status").toBe("on");
    expect(status(home.protection_layers, "encrypted_vault"), "Encrypted vault status").toBe("on");
    expect(status(home.protection_layers, "approval_gates")).toBe("on");
    expect(status(home.protection_layers, "exit")).toBe("on");
    expect(result.layers).toEqual(home.protection_layers);
    const detached = reconcilePostureHomeJoiner(structuredClone(home), 0, 1); // One later sequence with no local association.
    expect(status(detached.protection_layers, "identity"), "detached subject unavailable").toBe("unknown");
    expect(status(detached.protection_layers, "encrypted_vault"), "detached construction unavailable").toBe("unknown");
    const follower = reconcilePostureHomeJoiner(home, 0, 1); // One newer audit sequence caps panel observations.
    const nextFollower = reconcilePostureHomeJoiner(follower, 1, 2); // A second follower retains the local association.
    expect(status(nextFollower.protection_layers, "identity")).toBe("on");
    expect(status(nextFollower.protection_layers, "encrypted_vault")).toBe("on");
    expect(result.layers).toEqual(composeProtectionLayers(snapshot));
    const inventory = composeProtectionLayers({});
    expect(result.layers).toHaveLength(inventory.length);
    expect(new Set(result.layers.map(row => row.id))).toEqual(new Set(inventory.map(row => row.id)));
    expect(new Set(result.layers.map(row => row.id)).size).toBe(inventory.length);
    expect(result.guarantees).toEqual(guarantees);
    expect(result.summary.split("\n")).toEqual(result.layers.map(row => `${row.name}: ${row.status.replace("_", " ")}`));
    expect(result.audit_ref).toEqual(expect.any(String));

    // The mapped fixture requires a meaningful supported and unavailable value for every schema key.
    const fields: { [K in keyof ProtectionObservationSnapshot]-?: { supported: Exclude<ProtectionObservationSnapshot[K], undefined>; unavailable: undefined } } = {
      identityLoaded: { supported: true, unavailable: undefined },
      encryptedStateStoreConstructed: { supported: false, unavailable: undefined },
      auditChain: { supported: "verified_suffix_only", unavailable: undefined },
      featureHealth: { supported: f.health, unavailable: undefined },
      custodyExit: { supported: f.custody, unavailable: undefined },
      custodyObservation: { supported: fresh, unavailable: undefined },
      // First millisecond beyond the shared freshness window, so a supplied instant is distinguishable from the mocked clock.
      now: { supported: observedAt + custodySource.DEFAULT_ENFORCEMENT_FRESHNESS_MS + 1, unavailable: undefined },
      toolOutputScreenReady: { supported: false, unavailable: undefined },
    };
    expect(Object.keys(fields).sort()).toEqual([...protectionEvidenceKeys].sort());
    for (const key of Object.keys(fields) as Array<keyof typeof fields>) {
      for (const value of [fields[key].supported, fields[key].unavailable]) {
        const evidence = { ...snapshot, [key]: value };
        expect(protectionEvidenceSchema.parse(evidence)).toEqual(evidence);
        expect(Object.keys(evidence).sort()).toEqual([...protectionEvidenceKeys].sort());
      }
      // A value of the wrong shape is refused, and every supported value changes the composed rows.
      expect(protectionEvidenceSchema.safeParse({ ...snapshot, [key]: "not an observation" }).success, `${key} shape`).toBe(false);
      expect(composeProtectionLayers({ ...snapshot, [key]: fields[key].supported }), `${key} composes`)
        .not.toEqual(composeProtectionLayers({ ...snapshot, [key]: fields[key].unavailable }));
    }
    expect(status(composeProtectionLayers({ encryptedStateStoreConstructed: false }), "encrypted_vault")).toBe("off");
    const absent = observeProtections(protectionRuntimeUnavailable, { featureHealth: undefined, custodyExit: undefined,
      custodyObservation: undefined, now: undefined, auditChain: undefined });
    expect(Object.keys(absent).sort()).toEqual([...protectionEvidenceKeys].sort());
    expect(Object.values(absent).every(value => value === undefined)).toBe(true);
    expect(composeProtectionLayers(absent)).toEqual(inventory);
    const get = vi.spyOn(f.runtime.identityManager, "get").mockReturnValue(undefined);
    expect(observeProtections(f.runtime, panels).identityLoaded).toBe(false);
    get.mockImplementation(() => { throw new Error("identity unavailable"); });
    expect(observeProtections(f.runtime, panels).identityLoaded).toBeUndefined();
    expect(status((await f.readTool()).layers, "identity")).toBe("unknown");
    get.mockRestore();
    expect(observeProtections({ ...f.runtime, stateStore: undefined }, panels).encryptedStateStoreConstructed).toBeUndefined();
    const failedScreen = observeProtections({ ...f.runtime, responseScreen: { assertReady() { throw new Error("not ready"); } } }, panels);
    expect(failedScreen.toolOutputScreenReady).toBe(false);
    expect(composeProtectionLayers(failedScreen).at(LAST_ROW)).toEqual({ id: "inbound_protection", name: "Inbound protection",
      status: "not_built", basis: "capability: not built; tool-output screening readiness: off" });
    for (const health of [capStalePanel("feature_health", f.health), { ...f.health, audit_integrity_ok: false }]) {
      expect(status(composeProtectionLayers(observeProtections(f.runtime, { ...panels, featureHealth: health })), "approval_gates")).toBe("unknown");
    }
    const expired = observeProtections(f.runtime, { ...panels,
      now: observedAt + custodySource.DEFAULT_ENFORCEMENT_FRESHNESS_MS + 1 }); // First millisecond beyond the shared freshness window.
    expect(status(composeProtectionLayers(expired), "approval_gates")).toBe("unknown");
    expect(status(composeProtectionLayers(expired), "exit")).toBe("unknown");
    expect(observeProtections({ ...f.runtime, identityManager: undefined }, panels).identityLoaded).toBeUndefined();
    expect(observeProtections({ ...f.runtime, currentSessionBinding: () => ({ identity_id: "unbound" }) }, panels).identityLoaded).toBeUndefined();
    for (const state of ["unavailable", "stale"] as const) {
      const observed = observeProtections(f.runtime, { ...panels, custodyObservation: { state, completed_at: completedAt } });
      expect(observed.custodyExit?.audit_integrity_ok).toBe(true);
      expect(observed.custodyExit?.exit_state).toBe("export_available");
      expect(status(composeProtectionLayers(observed), "exit"), "unavailable custody remains unknown").toBe("unknown");
    }
    f.custodyRead.mockRejectedValue(new Error("custody unavailable"));
    expect(status((await f.readTool()).layers, "exit")).toBe("unknown");
    f.custodyRead.mockResolvedValue(f.custody);
    const verdict = { ...f.chain, status: "verified_suffix_only" as const };
    f.chainRead.mockResolvedValue(verdict);
    const chained = await f.readTool();
    const signed = chained.layers.find(row => row.id === "signed_record");
    expect(signed?.basis, "settled chain basis").toBe("audit chain: verified_suffix_only; signed checkpoint: no evidence source wired");
    expect(signed?.status).toBe("unknown");
    expect(chained.layers).toEqual(composeProtectionLayers(observeProtections(f.runtime, { ...panels, auditChain: verdict.status })));
    f.setBinding(undefined);
    const denied = JSON.parse((await f.makeTool().handler({})).content[FIRST_CONTENT]!.text);
    expect(denied.denied).toBe(true);
    expect(denied.layers).toBeUndefined();
    await f.auditLog.flush();
  } finally { await homeDirectory.cleanup(); }
});

it("a joined home keeps its runtime sources and composes each snapshot fresh", () => {
  const home = {};
  associateProtectionHome(home, { runtime: () => ({ ...protectionRuntimeUnavailable }), now: () => observedAt });
  const panels = { featureHealth: undefined, custodyExit: undefined, custodyObservation: fresh, auditChain: undefined };
  const first = observeProtectionJoiner(home, panels);
  // The association a follower re-registers carries only the sources; a retained snapshot would go stale behind them.
  expect(first).toHaveProperty("observation");
  expect(Object.keys(first.observation).sort()).toEqual(["now", "runtime"]);
  expect(first.snapshot).not.toBe(observeProtectionJoiner(home, panels).snapshot);
});
