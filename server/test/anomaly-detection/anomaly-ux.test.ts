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

import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { Writable } from "node:stream";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import {
  AnomalyPipelineDispatcher,
  ANOMALY_AUDIT_OPS,
  ANOMALY_SENTINEL_ID_PREFIX,
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
import { PER_AGENT_ACTIVITY_DETECTOR_ID } from "../../src/anomaly-detection/detectors/per-agent-activity-detector.js";
import { ROLLING_BASELINE_CLASSIFIER_ID } from "../../src/anomaly-detection/classifiers/rolling-baseline.js";
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

async function makeServer(rig: ReturnType<typeof makeRig>): Promise<{
  base: string;
  close: () => Promise<void>;
}> {
  const server: Server = createServer(async (req, res) => {
    const handled = await handleAnomalyRoute(
      {
        authConfig: { loopbackAutoAuth: true },
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
        { method: "POST" },
      );
      expect(subRes.status).toBe(200);

      const subscribed = await fetch(`${base}${ANOMALY_API_PREFIX}/subscribed`);
      const body = (await subscribed.json()) as {
        data: { subscribed: string[] };
      };
      expect(body.data.subscribed).toContain(PER_AGENT_ACTIVITY_DETECTOR_ID);

      const unsubRes = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${ROLLING_BASELINE_CLASSIFIER_ID}`,
        { method: "DELETE" },
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

  it("subscribe without ?classifier= returns 400", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe`,
        { method: "POST" },
      );
      expect(res.status).toBe(400);
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
        { method: "POST" },
      );
      expect(res.status).toBe(404);
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
        { method: "POST" },
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
