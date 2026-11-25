// fail-before-exempt: base has no local results to leak; the control proves the scan.
import { afterEach, describe, expect, it, vi } from "vitest";
import { SanctuaryContextReader, ConciergeService, type ConciergeSelectorLike } from "../../src/concierge/index.js";
import { CONCIERGE_READ_SURFACES } from "../../src/concierge/concierge-types.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import type { SubstrateHandle, SubstrateResponse } from "../../src/intelligence/index.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { LOCAL_RESULTS_NAMESPACE } from "../../src/local-recompile/store-record.js";
import { join } from "node:path";
import { FORTRESS_STATE_DIRECTORY } from "../../src/core/custody-markers.js";
import { LocalOperatorStores } from "../../src/local-recompile/operator-surface.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { resolveCustodyLockRoot } from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";
import { openWorld, waitForJobEnds, type World } from "./helpers/armed-world.js";
import { isAlive, localTaskPid } from "./helpers/local-task-server.js";

vi.mock("../../src/intelligence/model-manifest.js", async (original) => {
  // Must match Q5E_PRIVATE_KEY in test/intelligence/q5e-fixtures.ts, which imports this module and so cannot be imported here.
  const { ed25519 } = await import("@noble/curves/ed25519");
  const key = ed25519.getPublicKey(new Uint8Array(32).fill(41));
  return { ...await original<typeof import("../../src/intelligence/model-manifest.js")>(), loadPinnedModelManifestKey: () => Uint8Array.from(key) };
});

// A world boot, one job to commit and the concierge's reads, on a loaded machine.
const WORLD_TIMEOUT_MS = 180_000;

const RESULT_SENTINEL = "RESULT-SENTINEL-3b8e";
const RECORD_SENTINEL = "RECORD-SENTINEL-c41d";
const CONTROL_SENTINEL = "CONTROL-SENTINEL-55a0";
// Must match the namespaces SanctuaryContextReader.readStateStore lists in src/concierge/sanctuary-context-reader.ts.
const CONTROL_NAMESPACE = "sanctuary.tasks";

const worlds: World[] = [];
const auditLogs: AuditLog[] = [];
afterEach(async () => {
  const failures: unknown[] = [];
  // The reader appends its own audit row without awaiting it; flush before the directory goes.
  for (const log of auditLogs.splice(0)) await log.flush().catch((error) => failures.push(error));
  for (const world of worlds.splice(0).reverse()) {
    const workerPid = localTaskPid(world.server.runtime);
    try {
      await world.close();
      expect(isAlive(workerPid)).toBe(false);
      expect(isAlive(world.fake.pid)).toBe(false);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) throw failures[0];
});

/** A hosted concierge whose provider call is recorded instead of sent. */
function recordingHostedSelector() {
  const outbound: string[] = [];
  const response: SubstrateResponse = { servedBy: "frontier-with-filter", failureClass: null, body: { kind: "summarize", text: "ok" }, completedAt: "2026-11-23T00:00:00.000Z", latencyMs: 1 };
  const selector: ConciergeSelectorLike = {
    getSubstrate: vi.fn(async (): Promise<SubstrateHandle> => ({
      surface: "concierge",
      substrate: "frontier-with-filter",
      badge: { surface: "concierge", substrate: "frontier-with-filter", labelKey: "intelligence.substrate.frontier-with-filter.label", tradeoffKey: "intelligence.substrate.frontier-with-filter.tradeoff", status: "green" },
      capability: { summarize: true, classify: false, redact: false },
      displayLabel: "hosted",
    })),
    invokeSummarize: vi.fn(async (...args: unknown[]) => {
      outbound.push(JSON.stringify(args));
      return response;
    }),
    getOperatorVisibleStatus: vi.fn(async () => ({ version: "1.2", generatedAt: "2026-11-23T00:00:00.000Z", hardware: { totalRamGb: 16, cpuArch: "other", tier: "mid", recommendedLocalModel: "x", ollamaReachable: false, ollamaModels: [] }, surfaces: [] })) as never,
    getConfig: () => ({ fallback: { concierge: "degrade-silent" } }) as never,
  };
  return { selector, outbound };
}

/**
 * A fortress where a summary job ran to commit through the real path: sanctuary_local_task through
 * the router and the gate, then the worker and the fake model. The record it read and the summary it
 * committed both carry sentinels.
 */
async function fortressWithCommittedResult() {
  const opened = await openWorld({
    records: [{ namespace: "notes", key: "one", value: `meeting notes ${RECORD_SENTINEL}` }],
    fakeScript: { reply: `summary of the notes ${RESULT_SENTINEL}` },
  });
  worlds.push(opened);
  const answer = await opened.server.call({ kind: "summarize", sources: { refs: [{ namespace: "notes", key: "one" }] }, instruction: "Summarize." });
  expect(JSON.parse(answer.text).status).toBe("submitted");
  const rows = await waitForJobEnds(opened, 1);
  expect(rows.map((row) => row.kind)).toContain("job_committed");
  const storage = new FilesystemStorage(join(opened.storagePath, FORTRESS_STATE_DIRECTORY));
  // The committed result does hold the sentinel, so a leak of it would be seen.
  const keys = deriveLocalStoreKeys(opened.masterKey);
  const runtimeRoot = resolveCustodyLockRoot(process.getuid!(), { env: process.env, platform: process.platform });
  const stores = new LocalOperatorStores(storage, keys, { runtimeRoot });
  keys.oplogKey.fill(0);
  keys.resultsKey.fill(0);
  try {
    const [result] = await stores.listResults();
    expect(JSON.stringify(await stores.viewResult(result!.request_id))).toContain(RESULT_SENTINEL);
  } finally {
    stores.close();
  }
  const encKey = derivePurposeKey(opened.masterKey, "identity-encryption");
  const { storedIdentity: identity } = createIdentity("operator", encKey, "recovery-key");
  await persistStoredIdentity(storage, opened.masterKey, identity);
  const stateStore = new StateStore(storage, opened.masterKey);
  const write = (namespace: string, key: string, value: string) =>
    stateStore.write(namespace, key, value, identity.identity_id, identity.encrypted_private_key, encKey, { provenance: { origin_actor: "operator" } });
  const auditLog = new AuditLog(storage, opened.masterKey);
  auditLogs.push(auditLog);
  return { fixture: { path: opened.storagePath }, identity, stateStore, write, auditLog };
}

function reader(world: Awaited<ReturnType<typeof fortressWithCommittedResult>>) {
  return new SanctuaryContextReader({
    auditLog: world.auditLog,
    identityManager: { listWithRotationCount: () => [], list: () => [] },
    inboxSources: {
      listPendingApprovals: () => [],
      listRecentBlockedEgress: () => [],
      listRecentPrivacyEvents: () => [],
      listActiveBudgetWarnings: () => [],
      listActiveRecoveryPrompts: () => [],
      listRecentAgentErrors: () => [],
    },
    stateStore: world.stateStore,
    fortressId: "fortress-a",
    storagePath: world.fixture.path,
    identityId: world.identity.identity_id,
  });
}

describe("the hosted concierge and local results", () => {
  it("no outbound request carries a local result, its source record, or the results store name", async () => {
    const world = await fortressWithCommittedResult();
    const { selector, outbound } = recordingHostedSelector();
    const service = new ConciergeService({ reader: reader(world), selector });
    for (const question of ["summarize everything", "show the audit log", "what local results exist", "show state"]) {
      await service.ask({ question, stream: false, includePayloads: true, maxAuditEntries: 100 });
    }
    expect(outbound.length).toBeGreaterThan(0);
    const bundle = await reader(world).readContext({ question: "all", includePayloads: true });
    expect(bundle.read_surfaces).toEqual([...CONCIERGE_READ_SURFACES]);
    for (const body of outbound) {
      expect(body).not.toContain(RESULT_SENTINEL);
      expect(body).not.toContain(RECORD_SENTINEL);
      expect(body).not.toContain(LOCAL_RESULTS_NAMESPACE);
    }
  }, WORLD_TIMEOUT_MS);

  it("the scan is live: a sentinel in an ordinary state record does reach the recorder", async () => {
    const world = await fortressWithCommittedResult();
    await world.write(CONTROL_NAMESPACE, "fortress-a/task-1", `control ${CONTROL_SENTINEL}`);
    const { selector, outbound } = recordingHostedSelector();
    const service = new ConciergeService({ reader: reader(world), selector });
    await service.ask({ question: "show state", stream: false, includePayloads: true });
    expect(outbound.some((body) => body.includes(CONTROL_SENTINEL))).toBe(true);
  }, WORLD_TIMEOUT_MS);
});
