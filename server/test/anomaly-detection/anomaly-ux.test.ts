/**
 * WP-V1.3-2 Chi-3 Anomaly subscription UX + drift visualization
 * regression suite.
 *
 * Coverage:
 *   - Catalog shape + helpers (findCatalogEntry, catalogKey).
 *   - Subscription-store round-trip + dedupe.
 *   - HTTP routes: detectors catalog (+ VIEW_OPENED audit), subscribed
 *     list, subscribe/unsubscribe round-trip (+ dispatcher audit
 *     events), findings filtering to anomaly:* prefix, findings detail
 *     (+ FINDING_DRILLED audit), classifier-state per-agent training
 *     snapshot, 400 on missing classifier query, 404 on unknown
 *     detector/classifier.
 *   - CLI: detectors list, subscribe writes subscription file,
 *     list-subscribed reads it.
 *   - Multi-fortress isolation: separate dispatchers do not share
 *     detector state.
 *   - Castle-walking: routes do not surface outbound network.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import { useTestPassphrase } from "../helpers/temp-fortress.js";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import {
  AnomalyPipelineDispatcher,
  ANOMALY_AUDIT_OPS,
  ANOMALY_SENTINEL_ID_PREFIX,
  type AnomalyClassifier,
} from "../../src/anomaly-detection/anomaly-pipeline.js";
import {
  ANOMALY_CATALOG,
  catalogKey,
  findCatalogEntry,
} from "../../src/anomaly-detection/anomaly-catalog.js";
import {
  ANOMALY_API_PREFIX,
  ANOMALY_UX_AUDIT_OPS,
  handleAnomalyRoute,
} from "../../src/anomaly-detection/anomaly-routes.js";
import {
  anomalySubscriptionsPath,
  loadAnomalySubscriptions,
  saveAnomalySubscriptions,
} from "../../src/anomaly-detection/anomaly-subscription-store.js";
import {
  PerAgentActivityDetector,
  PER_AGENT_ACTIVITY_DETECTOR_ID,
} from "../../src/anomaly-detection/detectors/per-agent-activity-detector.js";
import {
  DEFAULT_MIN_SAMPLES_FOR_PREDICTION,
  ROLLING_BASELINE_CLASSIFIER_ID,
} from "../../src/anomaly-detection/classifiers/rolling-baseline.js";
import { CUSUM_CLASSIFIER_ID } from "../../src/anomaly-detection/classifiers/cusum.js";
import { PSI_CLASSIFIER_ID } from "../../src/anomaly-detection/classifiers/psi.js";
import {
  CrossAgentTimingDetector,
  CROSS_AGENT_TIMING_DETECTOR_ID,
} from "../../src/anomaly-detection/detectors/cross-agent-timing-detector.js";
import {
  ToolCallSequenceDetector,
  TOOL_CALL_SEQUENCE_DETECTOR_ID,
} from "../../src/anomaly-detection/detectors/tool-call-sequence-detector.js";
import {
  AuditEventClassDistributionDetector,
  AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
  AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID,
  DEFAULT_AUDIT_EVENT_CLASS_PSI_THRESHOLD,
  DEFAULT_BASELINE_SAMPLE_COUNT,
} from "../../src/anomaly-detection/detectors/audit-event-class-distribution-detector.js";
import { ClassifierStateStore } from "../../src/anomaly-detection/classifier-state-store.js";
import { runAnomalyCommand } from "../../src/cli/anomaly.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const IDENTITY = "identity_test";

function makeRig(opts?: { fortressId?: string }): {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  findingStore: SentinelFindingStore;
  dispatcher: AnomalyPipelineDispatcher;
  fortressId: string;
} {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const findingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId,
  });
  const dispatcher = new AnomalyPipelineDispatcher({
    findingStore,
    auditLog,
    storage,
    masterKey,
    fortressId,
    identityId: IDENTITY,
    tickIntervalMs: 0,
  });
  return { storage, masterKey, auditLog, findingStore, dispatcher, fortressId };
}

// The POST/DELETE subscribe routes are DEFAULT-DENY mutations: they require the
// operator bearer even on loopback (requireToken suppresses the loopback
// shortcut). GET reads stay loopback-readable. The rig wires a fixed operator
// token; non-GET calls send it via `MUTATION_AUTH`.
const ANOMALY_AUTH_TOKEN = "anomaly-ux-operator-token";
const MUTATION_AUTH = { Authorization: `Bearer ${ANOMALY_AUTH_TOKEN}` };

async function makeServer(rig: ReturnType<typeof makeRig>): Promise<{
  base: string;
  close: () => Promise<void>;
}> {
  const server: Server = createServer(async (req, res) => {
    const handled = await handleAnomalyRoute(
      {
        authConfig: {
          loopbackAutoAuth: true,
          authToken: ANOMALY_AUTH_TOKEN,
        },
        dispatcher: rig.dispatcher,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        identityId: IDENTITY,
        storage: rig.storage,
        masterKey: rig.masterKey,
        fortressId: rig.fortressId,
      },
      req,
      res,
    );
    if (!handled) {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((resolve) =>
        server.close(() => {
          resolve();
        }),
      ),
  };
}

/**
 * Invoke the anomaly route handler in-process, without a socket. HTTP
 * transport delivers one request event per event-loop turn, so two
 * handlers only overlap across macrotask awaits; invocations started
 * together in-process interleave at EVERY await point of the handler,
 * which is the scheduling the concurrency assertions below must hold
 * under (register id: ic-sweep-auto-trigger-thresholds-consumed).
 */
function invokeSubscribeInProcess(
  rig: ReturnType<typeof makeRig>,
  detectorId: string,
  classifierId: string,
  method: "POST" | "DELETE" = "POST",
): Promise<{
  status: number;
  body: {
    ok: boolean;
    error?: string;
    data?: { subscribed?: boolean; removed?: boolean };
  };
}> {
  const req = {
    method,
    url: `${ANOMALY_API_PREFIX}/${detectorId}/subscribe?classifier=${classifierId}`,
    headers: {
      host: "127.0.0.1",
      authorization: `Bearer ${ANOMALY_AUTH_TOKEN}`,
    },
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as IncomingMessage;
  let status = 0;
  let payload = "";
  const res = {
    writeHead(code: number): ServerResponse {
      status = code;
      return this as unknown as ServerResponse;
    },
    end(chunk?: unknown): void {
      if (typeof chunk === "string") payload = chunk;
    },
  } as unknown as ServerResponse;
  return handleAnomalyRoute(
    {
      authConfig: { loopbackAutoAuth: true, authToken: ANOMALY_AUTH_TOKEN },
      dispatcher: rig.dispatcher,
      findingStore: rig.findingStore,
      auditLog: rig.auditLog,
      identityId: IDENTITY,
      storage: rig.storage,
      masterKey: rig.masterKey,
      fortressId: rig.fortressId,
    },
    req,
    res,
  ).then(() => ({
    status,
    body: JSON.parse(payload) as {
      ok: boolean;
      error?: string;
      data?: { subscribed?: boolean; removed?: boolean };
    },
  }));
}

class CollectStream extends Writable {
  chunks: Buffer[] = [];
  override _write(chunk: Buffer, _enc: string, cb: () => void): void {
    this.chunks.push(Buffer.from(chunk));
    cb();
  }
  get text(): string {
    return Buffer.concat(this.chunks).toString("utf8");
  }
}

describe("Chi-3 — catalog + subscription store", () => {
  it("ANOMALY_CATALOG includes per-agent-activity with rolling-baseline classifier", () => {
    expect(
      ANOMALY_CATALOG.some(
        (e) =>
          e.detectorId === PER_AGENT_ACTIVITY_DETECTOR_ID &&
          e.classifierId === ROLLING_BASELINE_CLASSIFIER_ID,
      ),
    ).toBe(true);
  });

  it("ANOMALY_CATALOG exposes Chi-4 and Chi-5 detector classifier tuples", () => {
    const expected = [
      {
        detectorId: CROSS_AGENT_TIMING_DETECTOR_ID,
        classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
        ctor: CrossAgentTimingDetector,
        tunables: [
          "minSamplesForPrediction",
          String(DEFAULT_MIN_SAMPLES_FOR_PREDICTION),
        ],
      },
      {
        detectorId: TOOL_CALL_SEQUENCE_DETECTOR_ID,
        classifierId: ROLLING_BASELINE_CLASSIFIER_ID,
        ctor: ToolCallSequenceDetector,
        tunables: [
          "minSamplesForPrediction",
          String(DEFAULT_MIN_SAMPLES_FOR_PREDICTION),
        ],
      },
      {
        detectorId: AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
        classifierId: AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID,
        ctor: AuditEventClassDistributionDetector,
        tunables: [
          "psiThreshold",
          String(DEFAULT_AUDIT_EVENT_CLASS_PSI_THRESHOLD),
          "baselineSampleCount",
          String(DEFAULT_BASELINE_SAMPLE_COUNT),
        ],
      },
    ];

    for (const row of expected) {
      const entry = findCatalogEntry(row.detectorId, row.classifierId);
      expect(entry).toBeDefined();
      expect(entry!.factory()).toBeInstanceOf(row.ctor);
      for (const tunable of row.tunables) {
        expect(entry!.description).toContain(tunable);
      }
    }
  });

  it("catalogKey + findCatalogEntry helpers work", () => {
    const key = catalogKey(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      ROLLING_BASELINE_CLASSIFIER_ID,
    );
    expect(key).toBe(
      `${PER_AGENT_ACTIVITY_DETECTOR_ID}__${ROLLING_BASELINE_CLASSIFIER_ID}`,
    );
    expect(
      findCatalogEntry(
        PER_AGENT_ACTIVITY_DETECTOR_ID,
        ROLLING_BASELINE_CLASSIFIER_ID,
      ),
    ).toBeDefined();
    expect(findCatalogEntry("unknown-detector", "unknown-classifier")).toBeUndefined();
  });

  it("anomaly-subscription-store round-trips and dedupes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "chi3-sub-"));
    try {
      await saveAnomalySubscriptions(dir, [
        { detector_id: "d1", classifier_id: "c1" },
        { detector_id: "d1", classifier_id: "c1" },
        { detector_id: "d2", classifier_id: "c1" },
      ]);
      const loaded = await loadAnomalySubscriptions(dir);
      expect(loaded.length).toBe(2);
      expect(anomalySubscriptionsPath(dir)).toBe(
        join(dir, "anomaly-subscriptions.json"),
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("Chi-3 — HTTP routes", () => {
  it("GET /api/anomaly/detectors returns the catalog and emits VIEW_OPENED audit", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${ANOMALY_API_PREFIX}/detectors`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { catalog: Array<{ detector_id: string; classifier_id: string }> };
      };
      expect(body.ok).toBe(true);
      expect(
        body.data.catalog.some(
          (c) => c.detector_id === PER_AGENT_ACTIVITY_DETECTOR_ID,
        ),
      ).toBe(true);
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const viewOpened = audit.entries.filter(
        (e: AuditEntry) => e.operation === ANOMALY_UX_AUDIT_OPS.VIEW_OPENED,
      );
      expect(viewOpened.length).toBeGreaterThanOrEqual(1);
    } finally {
      await close();
    }
  });

  it("POST + DELETE /api/anomaly/:detector/subscribe round-trips and emits dispatcher audit events", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const subRes = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${ROLLING_BASELINE_CLASSIFIER_ID}`,
        { method: "POST", headers: MUTATION_AUTH },
      );
      expect(subRes.status).toBe(200);

      const subscribed = await fetch(`${base}${ANOMALY_API_PREFIX}/subscribed`);
      const body = (await subscribed.json()) as {
        data: { subscribed: string[] };
      };
      expect(body.data.subscribed).toContain(PER_AGENT_ACTIVITY_DETECTOR_ID);

      const unsubRes = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${ROLLING_BASELINE_CLASSIFIER_ID}`,
        { method: "DELETE", headers: MUTATION_AUTH },
      );
      expect(unsubRes.status).toBe(200);

      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const ops = audit.entries.map((e) => e.operation);
      expect(ops).toContain(ANOMALY_AUDIT_OPS.DETECTOR_REGISTERED);
      expect(ops).toContain(ANOMALY_AUDIT_OPS.DETECTOR_UNREGISTERED);
    } finally {
      await close();
    }
  });

  // ── Default-deny: the subscribe MUTATIONS require the operator bearer ────
  // even on loopback (the co-resident-agent invariant-7 hole). The rig has
  // loopbackAutoAuth ON, so a no-bearer GET read still works, but the POST and
  // DELETE subscribe mutations now 401 without the operator bearer.
  it("POST .../subscribe on loopback with NO bearer is REJECTED (401) — default-deny mutation", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${ROLLING_BASELINE_CLASSIFIER_ID}`,
        { method: "POST" },
      );
      // Was 200 under the flat gate (loopback auto-auth released the mutation);
      // now 401 because requireToken suppresses the loopback shortcut.
      expect(res.status).toBe(401);
      // And no detector was registered as a side effect.
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const ops = audit.entries.map((e) => e.operation);
      expect(ops).not.toContain(ANOMALY_AUDIT_OPS.DETECTOR_REGISTERED);
    } finally {
      await close();
    }
  });

  it("DELETE .../subscribe on loopback with NO bearer is REJECTED (401) — default-deny mutation", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${ROLLING_BASELINE_CLASSIFIER_ID}`,
        { method: "DELETE" },
      );
      expect(res.status).toBe(401);
    } finally {
      await close();
    }
  });

  it("GET .../subscribed on loopback with NO bearer still works (read unaffected by default-deny)", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${ANOMALY_API_PREFIX}/subscribed`);
      expect(res.status).toBe(200);
    } finally {
      await close();
    }
  });

  it("unsubscribes one classifier tuple without disabling siblings on the same detector", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const rolling = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${ROLLING_BASELINE_CLASSIFIER_ID}`,
        { method: "POST", headers: MUTATION_AUTH },
      );
      expect(rolling.status).toBe(200);
      const cusum = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${CUSUM_CLASSIFIER_ID}`,
        { method: "POST", headers: MUTATION_AUTH },
      );
      expect(cusum.status).toBe(200);
      expect(
        rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID),
      ).toEqual([ROLLING_BASELINE_CLASSIFIER_ID, CUSUM_CLASSIFIER_ID]);

      const unsubCusum = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${CUSUM_CLASSIFIER_ID}`,
        { method: "DELETE", headers: MUTATION_AUTH },
      );
      expect(unsubCusum.status).toBe(200);
      expect(
        rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID),
      ).toEqual([ROLLING_BASELINE_CLASSIFIER_ID]);
      expect(rig.dispatcher.listDetectors()).toContain(
        PER_AGENT_ACTIVITY_DETECTOR_ID,
      );
    } finally {
      await close();
    }
  });

  // ── Concurrency capability: subscribes in flight together on one ─────────
  // detector converge on a single live registration that carries every
  // classifier the callers were told is subscribed. The dispatcher
  // serializes registry mutation per detector id (register id:
  // ic-sweep-auto-trigger-thresholds-consumed). Both invocations are
  // started synchronously via invokeSubscribeInProcess so their handlers
  // interleave at every await point.
  it("concurrent fresh subscribes for two classifier tuples on one detector both take effect", async () => {
    const rig = makeRig();
    const [psi, cusum] = await Promise.all([
      invokeSubscribeInProcess(
        rig,
        PER_AGENT_ACTIVITY_DETECTOR_ID,
        PSI_CLASSIFIER_ID,
      ),
      invokeSubscribeInProcess(
        rig,
        PER_AGENT_ACTIVITY_DETECTOR_ID,
        CUSUM_CLASSIFIER_ID,
      ),
    ]);
    expect(psi.status).toBe(200);
    expect(cusum.status).toBe(200);
    expect(psi.body.data?.subscribed).toBe(true);
    expect(cusum.body.data?.subscribed).toBe(true);
    // Both classifiers the callers were told are subscribed are live on
    // the detector.
    const live = rig.dispatcher.listDetectorClassifiers(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
    );
    expect(live).toContain(PSI_CLASSIFIER_ID);
    expect(live).toContain(CUSUM_CLASSIFIER_ID);
    // Single registration: the detector list holds exactly one entry for
    // the id.
    expect(rig.dispatcher.listDetectors()).toEqual([
      PER_AGENT_ACTIVITY_DETECTOR_ID,
    ]);
  });

  it("concurrent same-classifier subscribes converge on one live classifier instance", async () => {
    const rig = makeRig();
    const [first, second] = await Promise.all([
      invokeSubscribeInProcess(
        rig,
        PER_AGENT_ACTIVITY_DETECTOR_ID,
        CUSUM_CLASSIFIER_ID,
      ),
      invokeSubscribeInProcess(
        rig,
        PER_AGENT_ACTIVITY_DETECTOR_ID,
        CUSUM_CLASSIFIER_ID,
      ),
    ]);
    // Idempotent outcome: both callers get the subscribed-200 shape.
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(first.body.data?.subscribed).toBe(true);
    expect(second.body.data?.subscribed).toBe(true);
    // Exactly one live CUSUM instance on exactly one registration.
    const live = rig.dispatcher.listDetectorClassifiers(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
    );
    expect(live.filter((id) => id === CUSUM_CLASSIFIER_ID)).toHaveLength(1);
    expect(rig.dispatcher.listDetectors()).toEqual([
      PER_AGENT_ACTIVITY_DETECTOR_ID,
    ]);
  });

  it("a subscribe overlapping an in-flight unsubscribe settles against a live registration", async () => {
    const rig = makeRig();
    // Detector whose teardown stays in flight until open() is called,
    // holding the registry mid-teardown while the subscribe arrives.
    class GatedTeardownDetector extends PerAgentActivityDetector {
      private release!: () => void;
      private readonly gate = new Promise<void>((resolve) => {
        this.release = resolve;
      });
      open(): void {
        this.release();
      }
      override async unsubscribe(): Promise<void> {
        await this.gate;
        await super.unsubscribe();
      }
    }
    const detector = new GatedTeardownDetector();
    await rig.dispatcher.registerDetector(detector);
    const teardown = rig.dispatcher.unregisterDetector(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
    );
    const post = invokeSubscribeInProcess(
      rig,
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      ROLLING_BASELINE_CLASSIFIER_ID,
    );
    detector.open();
    const [removed, res] = await Promise.all([teardown, post]);
    expect(removed).toBe(true);
    expect(res.status).toBe(200);
    expect(res.body.data?.subscribed).toBe(true);
    // `subscribed: true` is backed by a live registration: the subscribe
    // settles after the teardown completes and registers afresh, so the
    // detector and its classifier are live once both calls resolve.
    expect(rig.dispatcher.listDetectors()).toEqual([
      PER_AGENT_ACTIVITY_DETECTOR_ID,
    ]);
    expect(
      rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID),
    ).toEqual([ROLLING_BASELINE_CLASSIFIER_ID]);
  });

  it("a primary unsubscribe overlapping an in-flight dependent subscribe refuses on the settled classifier set", async () => {
    const rig = makeRig();
    await rig.dispatcher.registerDetector(new PerAgentActivityDetector());
    // Dependent classifier whose attach stays in flight until released,
    // so the primary DELETE arrives while the attach is queued ahead of
    // it on the detector's mutation chain.
    const dependentClassifier: AnomalyClassifier = {
      classifierId: CUSUM_CLASSIFIER_ID,
      observe: async () => {},
      predict: async () => ({
        anomaly_score: 0,
        explanation: [],
        feature_contributions: [],
        baseline_ready: false,
      }),
      train: async () => ({
        trained_at: new Date(0).toISOString(),
        sample_count: 0,
        agent_count: 0,
      }),
    };
    let releaseFactory!: () => void;
    const factoryGate = new Promise<void>((resolve) => {
      releaseFactory = resolve;
    });
    const attach = rig.dispatcher.addClassifierToDetector(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      async () => {
        await factoryGate;
        return dependentClassifier;
      },
    );
    const primaryDelete = invokeSubscribeInProcess(
      rig,
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      ROLLING_BASELINE_CLASSIFIER_ID,
      "DELETE",
    );
    releaseFactory();
    const [attached, res] = await Promise.all([attach, primaryDelete]);
    expect(attached).toBe(true);
    // The primary-with-dependents refusal fires on the classifier set as
    // committed by the attach queued ahead of the DELETE, so the
    // attach's registration survives.
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("primary_classifier_has_dependents");
    expect(rig.dispatcher.listDetectors()).toEqual([
      PER_AGENT_ACTIVITY_DETECTOR_ID,
    ]);
    expect(
      rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID),
    ).toEqual([ROLLING_BASELINE_CLASSIFIER_ID, CUSUM_CLASSIFIER_ID]);
  });

  it("subscribe without ?classifier= returns 400", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe`,
        { method: "POST", headers: MUTATION_AUTH },
      );
      expect(res.status).toBe(400);
      expect(rig.dispatcher.listDetectors()).toEqual([]);
    } finally {
      await close();
    }
  });

  it("subscribe with unknown detector/classifier returns 404", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/no-such-detector/subscribe?classifier=no-classifier`,
        { method: "POST", headers: MUTATION_AUTH },
      );
      expect(res.status).toBe(404);
      expect(rig.dispatcher.listDetectors()).toEqual([]);
    } finally {
      await close();
    }
  });

  it("subscribe refuses classifier_not_attachable (409) and leaves the live detector and its classifiers unchanged", async () => {
    const rig = makeRig();
    // A detector live under an explicit non-default classifier: the
    // rolling-baseline tuple's catalog entry carries no classifierFactory,
    // so the route has no way to attach it to this detector and must
    // refuse before touching the dispatcher.
    const explicitCusum: AnomalyClassifier = {
      classifierId: CUSUM_CLASSIFIER_ID,
      observe: async () => {},
      predict: async () => ({
        anomaly_score: 0,
        explanation: [],
        feature_contributions: [],
        baseline_ready: false,
      }),
      train: async () => ({
        trained_at: new Date(0).toISOString(),
        sample_count: 0,
        agent_count: 0,
      }),
    };
    await rig.dispatcher.registerDetector(
      new PerAgentActivityDetector({ classifier: explicitCusum }),
    );
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${ROLLING_BASELINE_CLASSIFIER_ID}`,
        { method: "POST", headers: MUTATION_AUTH },
      );
      expect(res.status).toBe(409);
      const body = (await res.json()) as { ok: boolean; error: string };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("classifier_not_attachable");
      // Refusal invariant (anomaly-routes.ts): a refused subscribe leaves
      // the detector list and its attached classifiers exactly as they
      // were -- the live registration survives, nothing new attaches.
      expect(rig.dispatcher.listDetectors()).toEqual([
        PER_AGENT_ACTIVITY_DETECTOR_ID,
      ]);
      expect(
        rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID),
      ).toEqual([CUSUM_CLASSIFIER_ID]);
    } finally {
      await close();
    }
  });

  it("GET /api/anomaly/findings narrows to anomaly:* prefix and excludes Phi-1 sentinel findings", async () => {
    const rig = makeRig();
    // Seed one anomaly finding + one phi-1 sentinel finding.
    await rig.findingStore.saveFinding({
      finding_id: "anom-1",
      sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}${PER_AGENT_ACTIVITY_DETECTOR_ID}`,
      severity: "warn",
      summary: "drift fixture",
      details: { detector_id: PER_AGENT_ACTIVITY_DETECTOR_ID },
      observed_at: "2026-05-09T12:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: rig.fortressId,
    });
    await rig.findingStore.saveFinding({
      finding_id: "phi-1",
      sentinel_id: "egress-volume",
      severity: "info",
      summary: "phi-1 fixture",
      details: {},
      observed_at: "2026-05-09T12:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: rig.fortressId,
    });
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${ANOMALY_API_PREFIX}/findings`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: { findings: Array<{ finding_id: string; sentinel_id: string }> };
      };
      const ids = body.data.findings.map((f) => f.finding_id);
      expect(ids).toContain("anom-1");
      expect(ids).not.toContain("phi-1");
    } finally {
      await close();
    }
  });

  it("GET /api/anomaly/findings/:id returns full drift detail and emits FINDING_DRILLED audit", async () => {
    const rig = makeRig();
    const findingId = randomUUID();
    await rig.findingStore.saveFinding({
      finding_id: findingId,
      sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}${PER_AGENT_ACTIVITY_DETECTOR_ID}`,
      severity: "alert",
      summary: "drift fixture",
      agent_id: "agent_alpha",
      details: {
        detector_id: PER_AGENT_ACTIVITY_DETECTOR_ID,
        classifier_id: ROLLING_BASELINE_CLASSIFIER_ID,
        anomaly_score: 7.2,
        feature_contributions: [
          {
            feature_name: "egress_volume_bytes",
            observed: 4_000_000,
            baseline_mean: 250_000,
            baseline_stddev: 60_000,
            z_score: 62.5,
          },
        ],
        explanation: ["egress_volume_bytes drifted +62.5 sigma"],
      },
      observed_at: "2026-05-09T12:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: rig.fortressId,
    });
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/findings/${findingId}`,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: {
          finding: {
            details: { feature_contributions: Array<{ feature_name: string }> };
          };
        };
      };
      expect(
        body.data.finding.details.feature_contributions[0]!.feature_name,
      ).toBe("egress_volume_bytes");
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const drills = audit.entries.filter(
        (e) => e.operation === ANOMALY_UX_AUDIT_OPS.FINDING_DRILLED,
      );
      expect(drills.length).toBe(1);
      expect(drills[0]!.details?.["finding_id"]).toBe(findingId);
    } finally {
      await close();
    }
  });

  it("GET /api/anomaly/findings/:id rejects non-anomaly findings (Sentinels view stays distinct)", async () => {
    const rig = makeRig();
    const findingId = randomUUID();
    await rig.findingStore.saveFinding({
      finding_id: findingId,
      sentinel_id: "egress-volume",
      severity: "info",
      summary: "phi-1 fixture",
      details: {},
      observed_at: "2026-05-09T12:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: rig.fortressId,
    });
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/findings/${findingId}`,
      );
      expect(res.status).toBe(404);
    } finally {
      await close();
    }
  });

  it("GET /api/anomaly/classifier-state returns per-agent training snapshot", async () => {
    const rig = makeRig();
    const stateStore = new ClassifierStateStore({
      storage: rig.storage,
      masterKey: rig.masterKey,
      fortressId: rig.fortressId,
    });
    await stateStore.saveState(ROLLING_BASELINE_CLASSIFIER_ID, "agent_alpha", {
      sample_count: 42,
    });
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/classifier-state?detector_id=${PER_AGENT_ACTIVITY_DETECTOR_ID}&classifier_id=${ROLLING_BASELINE_CLASSIFIER_ID}`,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: {
          agent_count: number;
          per_agent: Array<{ agent_id: string; sample_count: number | null }>;
        };
      };
      expect(body.data.agent_count).toBe(1);
      expect(body.data.per_agent[0]!.agent_id).toBe("agent_alpha");
      expect(body.data.per_agent[0]!.sample_count).toBe(42);
    } finally {
      await close();
    }
  });

  it("GET /api/anomaly/classifier-state without query params returns 400", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/classifier-state`,
      );
      expect(res.status).toBe(400);
    } finally {
      await close();
    }
  });

  it("returns 404 for unknown paths under /api/anomaly", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${ANOMALY_API_PREFIX}/nonsense`);
      expect(res.status).toBe(404);
    } finally {
      await close();
    }
  });
});

describe("Chi-3 — CLI subcommands", () => {
  // Pin the passphrase so deriveFortressMasterKey never falls through to the
  // OS keyring: against a fresh temp fortress that resolver would GENERATE
  // and store a new login-keychain entry on every run.
  let restorePassphrase: () => void;
  beforeEach(() => {
    restorePassphrase = useTestPassphrase();
  });
  afterEach(() => {
    restorePassphrase();
  });

  it("anomaly detectors list emits the catalog entries", async () => {
    const out = new CollectStream();
    const err = new CollectStream();
    const code = await runAnomalyCommand({
      argv: ["detectors", "list"],
      out,
      err,
    });
    expect(code).toBe(0);
    expect(out.text).toContain(PER_AGENT_ACTIVITY_DETECTOR_ID);
    expect(out.text).toContain(ROLLING_BASELINE_CLASSIFIER_ID);
  });

  it("anomaly subscribe writes a subscription tuple that list-subscribed reads back", async () => {
    const dir = await mkdtemp(join(tmpdir(), "chi3-cli-"));
    try {
      const subscribeOut = new CollectStream();
      const subscribeErr = new CollectStream();
      const subCode = await runAnomalyCommand({
        argv: [
          "subscribe",
          PER_AGENT_ACTIVITY_DETECTOR_ID,
          "--classifier",
          ROLLING_BASELINE_CLASSIFIER_ID,
        ],
        out: subscribeOut,
        err: subscribeErr,
        storagePath: dir,
      });
      expect(subCode).toBe(0);
      expect(subscribeOut.text).toContain("Subscribed");

      const listOut = new CollectStream();
      const listErr = new CollectStream();
      const listCode = await runAnomalyCommand({
        argv: ["list-subscribed"],
        out: listOut,
        err: listErr,
        storagePath: dir,
      });
      expect(listCode).toBe(0);
      expect(listOut.text).toContain(PER_AGENT_ACTIVITY_DETECTOR_ID);
      expect(listOut.text).toContain(ROLLING_BASELINE_CLASSIFIER_ID);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("anomaly subscribe rejects unknown detector + classifier pair", async () => {
    const dir = await mkdtemp(join(tmpdir(), "chi3-cli-bad-"));
    try {
      const out = new CollectStream();
      const err = new CollectStream();
      const code = await runAnomalyCommand({
        argv: ["subscribe", "no-such-detector", "--classifier", "no-classifier"],
        out,
        err,
        storagePath: dir,
      });
      expect(code).toBe(2);
      expect(err.text).toContain("Unknown");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("Chi-3 — multi-fortress isolation + Castle-walking", () => {
  it("two fortresses keep their dispatcher detector state independent", async () => {
    const rigA = makeRig({ fortressId: FORTRESS_A });
    const rigB = makeRig({ fortressId: FORTRESS_B });
    const entry = findCatalogEntry(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      ROLLING_BASELINE_CLASSIFIER_ID,
    );
    expect(entry).toBeDefined();
    await rigA.dispatcher.registerDetector(entry!.factory());
    expect(rigA.dispatcher.listDetectors()).toContain(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
    );
    expect(rigB.dispatcher.listDetectors()).toEqual([]);
  });

  it("Castle-walking: subscribing + listing + reading findings never opens an outbound socket", async () => {
    // This is structurally guaranteed by the absence of any
    // outbound-capable surface in handleAnomalyRoute / runAnomalyCommand
    // (no fetch, no client, no socket). The assertion here is shape-
    // checking the route's exported audit-op enum + the absence of any
    // outbound-side audit event after a full round-trip.
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      await fetch(`${base}${ANOMALY_API_PREFIX}/detectors`);
      await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${ROLLING_BASELINE_CLASSIFIER_ID}`,
        { method: "POST", headers: MUTATION_AUTH },
      );
      const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
      const ops = new Set(audit.entries.map((e) => e.operation));
      // No outbound ops should appear (no proxy_call, no
      // query_anonymity_headers_stripped, no intelligence_substrate_*).
      expect([...ops].some((op) => op.startsWith("proxy_call:"))).toBe(false);
      expect(ops.has("query_anonymity_headers_stripped")).toBe(false);
      expect(ops.has("intelligence_substrate_invoked")).toBe(false);
    } finally {
      await close();
    }
  });
});
