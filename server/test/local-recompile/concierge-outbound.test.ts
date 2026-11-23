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
import { persistStoredIdentity } from "../util/persist-stored-identity.js";
import { operatorFixture, type OperatorFixture } from "./helpers/operator-fixture.js";

const RESULT_SENTINEL = "RESULT-SENTINEL-3b8e";
const RECORD_SENTINEL = "RECORD-SENTINEL-c41d";
const CONTROL_SENTINEL = "CONTROL-SENTINEL-55a0";
// Must match the namespaces SanctuaryContextReader.readStateStore lists in src/concierge/sanctuary-context-reader.ts.
const CONTROL_NAMESPACE = "sanctuary.tasks";

const fixtures: OperatorFixture[] = [];
const auditLogs: AuditLog[] = [];
afterEach(async () => {
  // The reader appends its own audit row without awaiting it; flush before the directory goes.
  for (const log of auditLogs.splice(0)) await log.flush();
  for (const fixture of fixtures.splice(0)) await fixture.close();
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

async function fortressWithCommittedResult() {
  const fixture = await operatorFixture();
  fixtures.push(fixture);
  const encKey = derivePurposeKey(fixture.masterKey, "identity-encryption");
  const { storedIdentity: identity } = createIdentity("operator", encKey, "recovery-key");
  await persistStoredIdentity(fixture.storage, fixture.masterKey, identity);
  const stateStore = new StateStore(fixture.storage, fixture.masterKey);
  const write = (namespace: string, key: string, value: string) =>
    stateStore.write(namespace, key, value, identity.identity_id, identity.encrypted_private_key, encKey);
  // The record a summary job reads, and the committed summary of it.
  await write("notes", "one", `meeting notes ${RECORD_SENTINEL}`);
  await fixture.seed(1, `summary of the notes ${RESULT_SENTINEL} ${RECORD_SENTINEL}`);
  const auditLog = new AuditLog(fixture.storage, fixture.masterKey);
  auditLogs.push(auditLog);
  await auditLog.appendCritical({ layer: "l2", operation: "local_request_submitted", identity_id: "agent:test", result: "success", details: { request_id: "0".repeat(31) + "1" } });
  await auditLog.flush();
  return { fixture, identity, stateStore, write, auditLog };
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
  });

  it("the scan is live: a sentinel in an ordinary state record does reach the recorder", async () => {
    const world = await fortressWithCommittedResult();
    await world.write(CONTROL_NAMESPACE, "fortress-a/task-1", `control ${CONTROL_SENTINEL}`);
    const { selector, outbound } = recordingHostedSelector();
    const service = new ConciergeService({ reader: reader(world), selector });
    await service.ask({ question: "show state", stream: false, includePayloads: true });
    expect(outbound.some((body) => body.includes(CONTROL_SENTINEL))).toBe(true);
  });
});
