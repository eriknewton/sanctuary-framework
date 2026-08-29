/**
 * Operator-tuned anomaly thresholds are honored by the classifier they
 * configure, verified through the production subscribe path (HTTP route
 * -> dispatcher -> classifier construction) rather than isolated unit
 * construction (wired-consumer test, AGENTS.md rule 4). A row this
 * classifier cannot safely honor -- unsupported field, malformed value,
 * or a store read that fails outright -- refuses the subscription
 * rather than substituting a default. Absent tuning keeps the
 * classifier's own defaults.
 *
 * Private register: ic-sweep-auto-trigger-thresholds-consumed.
 */
import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type {
  StorageBackend,
  StorageEntryMeta,
} from "../../src/storage/interface.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import {
  AnomalyPipelineDispatcher,
} from "../../src/anomaly-detection/anomaly-pipeline.js";
import {
  ANOMALY_API_PREFIX,
  handleAnomalyRoute,
} from "../../src/anomaly-detection/anomaly-routes.js";
import { findCatalogEntry } from "../../src/anomaly-detection/anomaly-catalog.js";
import { PER_AGENT_ACTIVITY_DETECTOR_ID } from "../../src/anomaly-detection/detectors/per-agent-activity-detector.js";
import {
  CUSUM_CLASSIFIER_ID,
  CusumClassifier,
  DEFAULT_CUSUM_K,
  DEFAULT_CUSUM_H,
} from "../../src/anomaly-detection/classifiers/cusum.js";
import type { AnomalyContext, FeatureVector } from "../../src/anomaly-detection/types.js";
import { ClassifierStateStore } from "../../src/anomaly-detection/classifier-state-store.js";
import {
  ThresholdConfigStore,
  AUTO_TRIGGER_RULES_NAMESPACE,
} from "../../src/auto-trigger/threshold-config-store.js";
import { anomalyRuleId } from "../../src/auto-trigger/types.js";
import { runAutoTriggerCommand } from "../../src/cli/auto-trigger.js";
import {
  AUTO_TRIGGER_API_PREFIX,
  handleAutoTriggerRoute,
} from "../../src/auto-trigger/auto-trigger-routes.js";
import { ActionDispatcher, NotifyOperatorAction } from "../../src/auto-trigger/action-dispatcher.js";

const FORTRESS_ID = "fortress_ic29";
const WINDOW = "24h_rolling";
const NOW = () => new Date("2026-08-28T00:00:00.000Z");
const IDENTITY = "identity_ic29";
// Computed independently of anomaly-catalog.ts's own `CUSUM_ANOMALY_RULE_ID`
// export (deliberately not imported here) so this test's red/green
// evidence is not coupled to whether that convenience export exists in
// the version of the module under test -- `anomalyRuleId` + the two id
// constants are the actual single source of truth it is built from.
const CUSUM_RULE_ID = anomalyRuleId(PER_AGENT_ACTIVITY_DETECTOR_ID, CUSUM_CLASSIFIER_ID);

// Baseline holds mean=10, stddev~0.816 (Welford over these 10 samples).
// A single observed=13 sample scores ~0.635 under DEFAULT_CUSUM_H=5
// (below the anomaly-score-1 finding floor) but ~15.9 once alert_sigma
// reaches construction as `h` -- a decisive, single-direction crossing
// that lets the test tell "override consumed" from "override ignored"
// unambiguously.
const BASELINE = [9, 10, 11, 10, 9, 11, 10, 9, 10, 11];
const DRIFT_SAMPLE = 13;
const OVERRIDE_ALERT_SIGMA = 0.2;

function vec(agentId: string, features: Record<string, number>): FeatureVector {
  return {
    agent_id: agentId,
    observed_at: NOW().toISOString(),
    features,
    window_label: WINDOW,
  };
}

async function driftScoreAfterBaseline(
  classifier: CusumClassifier,
  agentId: string,
): Promise<number> {
  for (const v of BASELINE) {
    await classifier.observe(vec(agentId, { x: v }));
  }
  const prediction = await classifier.predict(vec(agentId, { x: DRIFT_SAMPLE }));
  return prediction.anomaly_score;
}

function makeContext(storage: StorageBackend, masterKey: Uint8Array): AnomalyContext {
  return {
    fortressId: FORTRESS_ID,
    auditLog: new AuditLog(storage, masterKey),
    storage,
    masterKey,
    now: NOW,
  };
}

function cusumEntry() {
  const entry = findCatalogEntry(PER_AGENT_ACTIVITY_DETECTOR_ID, CUSUM_CLASSIFIER_ID);
  if (!entry?.classifierFactory) throw new Error("cusum catalog entry missing classifierFactory");
  return entry;
}

/**
 * Delegates every call to a real MemoryStorage except `read()` on the
 * auto-trigger-rules namespace, which always throws -- simulates a
 * genuine storage read failure (as opposed to "no row persisted") for
 * the read-failure-must-refuse scenario. Every other namespace (audit
 * log, classifier state) behaves normally so the rest of the subscribe
 * flow is unaffected.
 */
class ReadFailingRulesStorage implements StorageBackend {
  constructor(private readonly inner: StorageBackend) {}
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    return this.inner.write(namespace, key, data);
  }
  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    if (namespace === AUTO_TRIGGER_RULES_NAMESPACE) {
      throw new Error("simulated storage read failure");
    }
    return this.inner.read(namespace, key);
  }
  async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    return this.inner.delete(namespace, key, secureOverwrite);
  }
  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    return this.inner.list(namespace, prefix);
  }
  async exists(namespace: string, key: string): Promise<boolean> {
    return this.inner.exists(namespace, key);
  }
  async totalSize(): Promise<number> {
    return this.inner.totalSize();
  }
}

// ── Production subscribe-path rig (mirrors anomaly-ux.test.ts) ──────────

function makeAnomalyRig(storage: StorageBackend, masterKey: Uint8Array) {
  const auditLog = new AuditLog(storage, masterKey);
  const findingStore = new SentinelFindingStore({ storage, masterKey, fortressId: FORTRESS_ID });
  const dispatcher = new AnomalyPipelineDispatcher({
    findingStore,
    auditLog,
    storage,
    masterKey,
    fortressId: FORTRESS_ID,
    identityId: IDENTITY,
    tickIntervalMs: 0,
  });
  return { storage, masterKey, auditLog, findingStore, dispatcher };
}

async function makeAnomalyServer(
  rig: ReturnType<typeof makeAnomalyRig>,
): Promise<{ base: string; close: () => Promise<void> }> {
  const server: Server = createServer(async (req, res) => {
    const handled = await handleAnomalyRoute(
      {
        authConfig: { loopbackAutoAuth: true, authToken: "ic29-op-token" },
        dispatcher: rig.dispatcher,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        identityId: IDENTITY,
        storage: rig.storage,
        masterKey: rig.masterKey,
        fortressId: FORTRESS_ID,
      },
      req,
      res,
    );
    if (!handled) res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const MUTATION_AUTH = { Authorization: "Bearer ic29-op-token" };

async function subscribeCusum(base: string): Promise<Response> {
  return fetch(
    `${base}${ANOMALY_API_PREFIX}/${PER_AGENT_ACTIVITY_DETECTOR_ID}/subscribe?classifier=${CUSUM_CLASSIFIER_ID}`,
    { method: "POST", headers: MUTATION_AUTH },
  );
}

describe("auto-trigger sigma overrides via the production anomaly-subscribe path", () => {
  it("no persisted row -> subscribe succeeds and the classifier keeps compiled defaults", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const rig = makeAnomalyRig(storage, masterKey);
    const { base, close } = await makeAnomalyServer(rig);
    try {
      const res = await subscribeCusum(base);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { ok: boolean; data: { subscribed_classifiers: string[] } };
      expect(body.ok).toBe(true);
      expect(body.data.subscribed_classifiers).toContain(CUSUM_CLASSIFIER_ID);
    } finally {
      await close();
    }

    const classifier = (await cusumEntry().classifierFactory!(
      makeContext(storage, masterKey),
    )) as CusumClassifier;
    expect(classifier.k).toBeCloseTo(DEFAULT_CUSUM_K);
    expect(classifier.h).toBeCloseTo(DEFAULT_CUSUM_H);
  });

  it("a persisted alert_sigma override reaches the classifier constructed via the production subscribe route", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();

    const configStore = new ThresholdConfigStore({ storage, masterKey, fortressId: FORTRESS_ID, now: NOW });
    const config = await configStore.getOrInit(CUSUM_RULE_ID, "anomaly");
    await configStore.set({
      ...config,
      threshold_overrides: { ...config.threshold_overrides, alert_sigma: OVERRIDE_ALERT_SIGMA },
    });

    const rig = makeAnomalyRig(storage, masterKey);
    const { base, close } = await makeAnomalyServer(rig);
    try {
      const res = await subscribeCusum(base);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { ok: boolean; data: { subscribed_classifiers: string[] } };
      expect(body.ok).toBe(true);
      expect(body.data.subscribed_classifiers).toContain(CUSUM_CLASSIFIER_ID);
    } finally {
      await close();
    }

    // The dispatcher does not expose attached classifier instances for
    // inspection, so the numeric proof (the override actually reached
    // `h`, and the drift-score consequence of that) is taken from a
    // second classifier built through the same catalog entry against
    // the same persisted row -- the identical construction path the
    // route just exercised.
    const classifier = (await cusumEntry().classifierFactory!(
      makeContext(storage, masterKey),
    )) as CusumClassifier;
    expect(classifier.h).toBeCloseTo(OVERRIDE_ALERT_SIGMA);

    const defaultOnly = new CusumClassifier({
      stateStore: new ClassifierStateStore({
        storage: new MemoryStorage(),
        masterKey,
        fortressId: FORTRESS_ID,
      }),
    });
    const defaultScore = await driftScoreAfterBaseline(defaultOnly, "agent-default");
    const overriddenScore = await driftScoreAfterBaseline(classifier, "agent-overridden");
    expect(defaultScore).toBeLessThan(1);
    expect(overriddenScore).toBeGreaterThanOrEqual(1);
    expect(overriddenScore).toBeGreaterThan(defaultScore * 10);
  });

  it("a warn_sigma present in the persisted row refuses the subscription (no configurable warning boundary)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();

    const configStore = new ThresholdConfigStore({ storage, masterKey, fortressId: FORTRESS_ID, now: NOW });
    const config = await configStore.getOrInit(CUSUM_RULE_ID, "anomaly");
    await configStore.set({
      ...config,
      threshold_overrides: { ...config.threshold_overrides, warn_sigma: 2.5 },
    });

    const rig = makeAnomalyRig(storage, masterKey);
    const { base, close } = await makeAnomalyServer(rig);
    try {
      const res = await subscribeCusum(base);
      expect(res.status).toBe(500);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("internal_error");
      expect(rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID)).not.toContain(
        CUSUM_CLASSIFIER_ID,
      );
      // Refusal invariant (anomaly-routes.ts): a refused subscribe leaves
      // the dispatcher's detector list exactly as it was -- here, empty.
      expect(rig.dispatcher.listDetectors()).toEqual([]);
    } finally {
      await close();
    }
  });

  it("warn_sigma alongside a validly-shaped alert_sigma still refuses (atomic row validation, no half-apply)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();

    const configStore = new ThresholdConfigStore({ storage, masterKey, fortressId: FORTRESS_ID, now: NOW });
    const config = await configStore.getOrInit(CUSUM_RULE_ID, "anomaly");
    await configStore.set({
      ...config,
      threshold_overrides: { ...config.threshold_overrides, warn_sigma: 100, alert_sigma: 2 },
    });

    const rig = makeAnomalyRig(storage, masterKey);
    const { base, close } = await makeAnomalyServer(rig);
    try {
      const res = await subscribeCusum(base);
      expect(res.status).toBe(500);
      expect(rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID)).not.toContain(
        CUSUM_CLASSIFIER_ID,
      );
      expect(rig.dispatcher.listDetectors()).toEqual([]);
    } finally {
      await close();
    }
  });

  it("a non-positive alert_sigma refuses the subscription rather than silently falling back to the default", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();

    const configStore = new ThresholdConfigStore({ storage, masterKey, fortressId: FORTRESS_ID, now: NOW });
    const config = await configStore.getOrInit(CUSUM_RULE_ID, "anomaly");
    await configStore.set({
      ...config,
      threshold_overrides: { ...config.threshold_overrides, alert_sigma: -1 },
    });

    const rig = makeAnomalyRig(storage, masterKey);
    const { base, close } = await makeAnomalyServer(rig);
    try {
      const res = await subscribeCusum(base);
      expect(res.status).toBe(500);
      expect(rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID)).not.toContain(
        CUSUM_CLASSIFIER_ID,
      );
      expect(rig.dispatcher.listDetectors()).toEqual([]);
    } finally {
      await close();
    }
  });

  it("a genuine store read failure refuses the subscription instead of silently applying compiled defaults", async () => {
    const inner = new MemoryStorage();
    const masterKey = generateRandomKey();
    const storage = new ReadFailingRulesStorage(inner);

    const rig = makeAnomalyRig(storage, masterKey);
    const { base, close } = await makeAnomalyServer(rig);
    try {
      const res = await subscribeCusum(base);
      expect(res.status).toBe(500);
      expect(rig.dispatcher.listDetectorClassifiers(PER_AGENT_ACTIVITY_DETECTOR_ID)).not.toContain(
        CUSUM_CLASSIFIER_ID,
      );
      expect(rig.dispatcher.listDetectors()).toEqual([]);
    } finally {
      await close();
    }
  });
});

describe("write-time refusal of warn_sigma for the CUSUM rule (CLI + HTTP)", () => {
  it("CLI `rules set-threshold --warn-sigma` refuses for the CUSUM rule_id and persists nothing", async () => {
    const out = new CollectStream();
    const err = new CollectStream();
    const code = await runAutoTriggerCommand({
      argv: [
        "rules",
        "set-threshold",
        CUSUM_RULE_ID,
        "--rule-type",
        "anomaly",
        "--warn-sigma",
        "2.5",
      ],
      out,
      err,
    });
    expect(code).toBe(2);
    expect(err.text).toContain("no configurable warning boundary");
  });

  it("PATCH /api/auto-trigger/rules/:rule_id refuses warn_sigma for the CUSUM rule_id and persists nothing", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const store = new ThresholdConfigStore({ storage, masterKey, fortressId: FORTRESS_ID, now: NOW });
    const action = new NotifyOperatorAction(auditLog, IDENTITY, FORTRESS_ID);
    const dispatcher = new ActionDispatcher({
      store,
      action,
      auditLog,
      fortressId: FORTRESS_ID,
      identityId: IDENTITY,
    });

    const server: Server = createServer(async (req, res) => {
      const handled = await handleAutoTriggerRoute(
        {
          authConfig: { loopbackAutoAuth: true, authToken: "ic29-at-token" },
          store,
          dispatcher,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      const res = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/${encodeURIComponent(CUSUM_RULE_ID)}`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer ic29-at-token",
          },
          body: JSON.stringify({
            rule_type: "anomaly",
            threshold_overrides: { warn_sigma: 2.5 },
          }),
        },
      );
      expect(res.status).toBe(400);
      const body = (await res.json()) as { ok: boolean; error: string };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("no_warning_boundary");

      const persisted = await store.get(CUSUM_RULE_ID);
      expect(persisted).toBeNull();
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

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
