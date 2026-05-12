/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-5 Audit-event class distribution detector.
 *
 * Composes the Chi-5 extractor with detector-local categorical PSI. Unlike
 * the generic Chi-2 numeric PSI classifier, this classifier compares the
 * whole categorical audit-event class mix for an agent in one score and
 * emits per-class attribution.
 */

import { AnomalyDetector } from "../types.js";
import type {
  AnomalyClassifier,
  AnomalyContext,
  AnomalyFinding,
  AnomalyPrediction,
  FeatureContribution,
  FeatureVector,
  TrainingResult,
} from "../types.js";
import type { AuditEntry } from "../../l2-operational/audit-log.js";
import {
  ANOMALY_SENTINEL_ID_PREFIX,
  severityFromAnomalyScore,
} from "../types.js";
import { ClassifierStateStore } from "../classifier-state-store.js";
import {
  AUDIT_EVENT_CLASS_DISTRIBUTION_EXTRACTOR_ID,
  DEFAULT_AUDIT_EVENT_CLASS_WINDOW_MS,
  type AuditEventClassDistributionOptions,
  buildAuditEventClassDistributions,
  extractAuditEventClassDistribution,
} from "../feature-extractors/audit-event-class-distribution.js";

export const AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID =
  AUDIT_EVENT_CLASS_DISTRIBUTION_EXTRACTOR_ID;
export const AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID =
  "audit-event-class-distribution:psi" as const;

export const DEFAULT_AUDIT_EVENT_CLASS_PSI_THRESHOLD = 0.25;
export const DEFAULT_BASELINE_SAMPLE_COUNT = 7;
export const DEFAULT_BASELINE_HISTORY_MS = 7 * 24 * 60 * 60 * 1000;

const PSI_SMOOTHING_EPSILON = 1e-4;

export interface PerClassDriftAttribution {
  class_name: string;
  baseline_proportion: number;
  current_proportion: number;
  absolute_delta: number;
  relative_delta: number | null;
  direction: "up" | "down" | "flat";
  psi_contribution: number;
}

interface AgentDistributionState {
  observation_count: number;
  last_observed_at: string | null;
  baseline_samples: Record<string, number>[];
  baseline_proportions: Record<string, number> | null;
}

export interface AuditEventClassDistributionPsiClassifierOptions {
  stateStore: ClassifierStateStore;
  psiThreshold?: number;
  baselineSampleCount?: number;
}

export class AuditEventClassDistributionPsiClassifier
  implements AnomalyClassifier
{
  readonly classifierId = AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID;
  readonly psiThreshold: number;
  private readonly stateStore: ClassifierStateStore;
  private readonly baselineSampleCount: number;
  private readonly cache = new Map<string, AgentDistributionState>();
  private readonly dirty = new Set<string>();

  constructor(opts: AuditEventClassDistributionPsiClassifierOptions) {
    this.stateStore = opts.stateStore;
    this.psiThreshold =
      opts.psiThreshold ?? DEFAULT_AUDIT_EVENT_CLASS_PSI_THRESHOLD;
    this.baselineSampleCount =
      opts.baselineSampleCount ?? DEFAULT_BASELINE_SAMPLE_COUNT;
  }

  async observe(vector: FeatureVector): Promise<void> {
    const state = await this.loadOrInit(vector.agent_id);
    const proportions = proportionsFromVector(vector);
    if (state.baseline_proportions === null) {
      state.baseline_samples.push(proportions);
      if (state.baseline_samples.length >= this.baselineSampleCount) {
        state.baseline_proportions = averageProportions(
          state.baseline_samples,
        );
      }
    }
    state.observation_count += 1;
    state.last_observed_at = vector.observed_at;
    this.dirty.add(vector.agent_id);
  }

  async predict(vector: FeatureVector): Promise<AnomalyPrediction> {
    const state = await this.loadOrInit(vector.agent_id);
    const current = proportionsFromVector(vector);
    if (state.baseline_proportions === null) {
      return emptyPrediction(false);
    }
    const baseline = state.baseline_proportions;
    const psi = computeCategoricalPsi(baseline, current);
    const attributions = computePerClassDriftAttribution(baseline, current);
    const explanation = attributions.slice(0, 3).map(formatAttribution);
    return {
      anomaly_score: psi >= this.psiThreshold ? psiToScore(psi, this.psiThreshold) : 0,
      explanation,
      feature_contributions: attributionsToFeatureContributions(attributions),
      baseline_ready: true,
    };
  }

  async train(): Promise<TrainingResult> {
    for (const agentId of [...this.dirty]) {
      const state = this.cache.get(agentId);
      if (!state) continue;
      await this.stateStore.saveState(this.classifierId, agentId, state);
      this.dirty.delete(agentId);
    }
    let sampleCount = 0;
    for (const state of this.cache.values()) {
      sampleCount += state.observation_count;
    }
    return {
      trained_at: new Date().toISOString(),
      sample_count: sampleCount,
      agent_count: this.cache.size,
    };
  }

  async resetBaseline(agentId: string): Promise<void> {
    const state = await this.loadOrInit(agentId);
    state.baseline_samples = [];
    state.baseline_proportions = null;
    this.dirty.add(agentId);
  }

  async seedBaseline(
    agentId: string,
    proportions: Record<string, number>,
    observedAt: string,
  ): Promise<boolean> {
    const state = await this.loadOrInit(agentId);
    if (state.baseline_proportions !== null) return false;
    state.baseline_samples = [proportions];
    state.baseline_proportions = { ...proportions };
    state.observation_count += 1;
    state.last_observed_at = observedAt;
    this.dirty.add(agentId);
    return true;
  }

  getAgentState(agentId: string): AgentDistributionState | undefined {
    return this.cache.get(agentId);
  }

  private async loadOrInit(
    agentId: string,
  ): Promise<AgentDistributionState> {
    const cached = this.cache.get(agentId);
    if (cached) return cached;
    const persisted =
      await this.stateStore.loadState<AgentDistributionState>(
        this.classifierId,
        agentId,
      );
    const state = persisted ?? {
      observation_count: 0,
      last_observed_at: null,
      baseline_samples: [],
      baseline_proportions: null,
    };
    this.cache.set(agentId, state);
    return state;
  }
}

export interface AuditEventClassDistributionDetectorOptions {
  classifier?: AuditEventClassDistributionPsiClassifier;
  psiThreshold?: number;
  baselineSampleCount?: number;
  extractor?: AuditEventClassDistributionOptions;
}

export class AuditEventClassDistributionDetector extends AnomalyDetector {
  readonly detectorId = AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID;
  readonly description =
    "Audit-event class distribution detector: per-agent categorical PSI over audit operation mix, with top per-class drift attribution.";
  readonly classifier: AuditEventClassDistributionPsiClassifier;
  private readonly explicitClassifier: boolean;
  private readonly psiThreshold: number | undefined;
  private readonly baselineSampleCount: number | undefined;
  private readonly extractorOptions: AuditEventClassDistributionOptions | undefined;

  constructor(opts?: AuditEventClassDistributionDetectorOptions) {
    super();
    this.explicitClassifier = opts?.classifier !== undefined;
    this.classifier = opts?.classifier ?? new PendingDistributionClassifier();
    this.psiThreshold = opts?.psiThreshold;
    this.baselineSampleCount = opts?.baselineSampleCount;
    this.extractorOptions = opts?.extractor;
  }

  override async subscribe(context: AnomalyContext): Promise<void> {
    await super.subscribe(context);
    if (this.explicitClassifier) return;
    const stateStore = new ClassifierStateStore({
      storage: context.storage,
      masterKey: context.masterKey,
      fortressId: context.fortressId,
      now: context.now,
    });
    const realClassifier = new AuditEventClassDistributionPsiClassifier({
      stateStore,
      ...(this.psiThreshold !== undefined
        ? { psiThreshold: this.psiThreshold }
        : {}),
      ...(this.baselineSampleCount !== undefined
        ? { baselineSampleCount: this.baselineSampleCount }
        : {}),
    });
    (this as { classifier: AuditEventClassDistributionPsiClassifier }).classifier =
      realClassifier;
  }

  async featureExtract(context: AnomalyContext): Promise<FeatureVector[]> {
    return extractAuditEventClassDistribution(context, this.extractorOptions);
  }

  override async evaluate(): Promise<AnomalyFinding[]> {
    const ctx = this.requireContext();
    const vectors = await this.featureExtract(ctx);
    const findings: AnomalyFinding[] = [];
    for (const vector of vectors) {
      await this.primeBaselineFromHistory(ctx, vector.agent_id);
      const prediction = await this.classifier.predict(vector);
      if (!prediction.baseline_ready) {
        await this.classifier.observe(vector);
        await this.evaluateAdditionalClassifiers(vector, findings);
        continue;
      }
      const current = proportionsFromVector(vector);
      const baseline =
        this.classifier.getAgentState(vector.agent_id)?.baseline_proportions ??
        {};
      const psi = computeCategoricalPsi(baseline, current);
      if (psi < this.classifier.psiThreshold) {
        await this.classifier.observe(vector);
        await this.evaluateAdditionalClassifiers(vector, findings);
        continue;
      }
      const perClassDrift = computePerClassDriftAttribution(
        baseline,
        current,
      );
      findings.push(
        buildDistributionFinding(
          this,
          this.classifier,
          vector,
          psi,
          prediction,
          perClassDrift,
          baseline,
          current,
        ),
      );
      await this.evaluateAdditionalClassifiers(vector, findings);
      continue;
    }
    return findings;
  }

  private async evaluateAdditionalClassifiers(
    vector: FeatureVector,
    findings: AnomalyFinding[],
  ): Promise<void> {
    for (const classifier of this.getAllClassifiers()) {
      if (classifier.classifierId === this.classifier.classifierId) continue;
      const prediction = await classifier.predict(vector);
      if (!prediction.baseline_ready) {
        await classifier.observe(vector);
        continue;
      }
      const severity = severityFromAnomalyScore(prediction.anomaly_score);
      if (severity === null) {
        await classifier.observe(vector);
        continue;
      }
      findings.push(
        buildAdditionalClassifierFinding(
          this,
          classifier,
          vector,
          prediction,
          severity,
        ),
      );
    }
  }

  private async primeBaselineFromHistory(
    context: AnomalyContext,
    agentId: string,
  ): Promise<void> {
    const state = this.classifier.getAgentState(agentId);
    if (state?.baseline_proportions !== null && state !== undefined) return;
    const windowMs =
      this.extractorOptions?.windowMs ?? DEFAULT_AUDIT_EVENT_CLASS_WINDOW_MS;
    const now = context.now();
    const baselineEnd = new Date(now.getTime() - windowMs);
    const baselineStart = new Date(
      baselineEnd.getTime() - DEFAULT_BASELINE_HISTORY_MS,
    );
    const result = await context.auditLog.query({
      since: baselineStart.toISOString(),
      limit: this.extractorOptions?.queryLimit ?? 50_000,
    });
    const historicalEntries = result.entries.filter((entry: AuditEntry) => {
      const ts = Date.parse(entry.timestamp);
      if (ts < baselineStart.getTime() || ts >= baselineEnd.getTime()) {
        return false;
      }
      return entry.identity_id === agentId;
    });
    const baseline = buildAuditEventClassDistributions(
      historicalEntries,
      baselineStart.toISOString(),
      baselineEnd.toISOString(),
    ).find((distribution) => distribution.agent_id === agentId);
    if (!baseline || baseline.total_events === 0) return;
    await this.classifier.seedBaseline(
      agentId,
      baseline.class_proportions,
      baseline.window_end,
    );
  }
}

function buildAdditionalClassifierFinding(
  detector: AuditEventClassDistributionDetector,
  classifier: AnomalyClassifier,
  vector: FeatureVector,
  prediction: AnomalyPrediction,
  severity: AnomalyFinding["severity"],
): AnomalyFinding {
  const top = prediction.explanation.slice(0, 3).join("; ");
  return {
    finding_id: "",
    sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}${detector.detectorId}`,
    severity,
    summary: `${detector.detectorId}/${classifier.classifierId} ${severity}: agent ${vector.agent_id} drifted ${prediction.anomaly_score.toFixed(2)} from audit-event distribution baseline. Top contributors: ${top || "(none)"}.`,
    details: {
      detector_id: detector.detectorId,
      classifier_id: classifier.classifierId,
      anomaly_score: prediction.anomaly_score,
      window_label: vector.window_label,
      observed_features: vector.features,
      feature_contributions: prediction.feature_contributions,
      explanation: prediction.explanation,
    },
    observed_at: vector.observed_at,
    agent_id: vector.agent_id,
    evidence_audit_ids: [],
    fortress_id: "",
  };
}

export function createAuditEventClassDistributionPsiClassifier(
  context: AnomalyContext,
  opts?: Omit<AuditEventClassDistributionPsiClassifierOptions, "stateStore">,
): AuditEventClassDistributionPsiClassifier {
  const stateStore = new ClassifierStateStore({
    storage: context.storage,
    masterKey: context.masterKey,
    fortressId: context.fortressId,
    now: context.now,
  });
  return new AuditEventClassDistributionPsiClassifier({
    stateStore,
    ...opts,
  });
}

export function computePerClassDriftAttribution(
  baseline: Record<string, number>,
  current: Record<string, number>,
): PerClassDriftAttribution[] {
  return allClasses(baseline, current)
    .map((className) => {
      const baselineProportion = baseline[className] ?? 0;
      const currentProportion = current[className] ?? 0;
      const absoluteDelta = currentProportion - baselineProportion;
      const bp = baselineProportion + PSI_SMOOTHING_EPSILON;
      const cp = currentProportion + PSI_SMOOTHING_EPSILON;
      const direction: PerClassDriftAttribution["direction"] =
        absoluteDelta > 0 ? "up" : absoluteDelta < 0 ? "down" : "flat";
      return {
        class_name: className,
        baseline_proportion: baselineProportion,
        current_proportion: currentProportion,
        absolute_delta: absoluteDelta,
        relative_delta:
          baselineProportion === 0
            ? null
            : absoluteDelta / baselineProportion,
        direction,
        psi_contribution: (cp - bp) * Math.log(cp / bp),
      };
    })
    .sort((a, b) => {
      const abs = Math.abs(b.absolute_delta) - Math.abs(a.absolute_delta);
      if (abs !== 0) return abs;
      const psi = b.psi_contribution - a.psi_contribution;
      if (psi !== 0) return psi;
      return a.class_name.localeCompare(b.class_name);
    });
}

export function computeCategoricalPsi(
  baseline: Record<string, number>,
  current: Record<string, number>,
): number {
  let psi = 0;
  for (const className of allClasses(baseline, current)) {
    const bp = (baseline[className] ?? 0) + PSI_SMOOTHING_EPSILON;
    const cp = (current[className] ?? 0) + PSI_SMOOTHING_EPSILON;
    psi += (cp - bp) * Math.log(cp / bp);
  }
  return psi;
}

function buildDistributionFinding(
  detector: AuditEventClassDistributionDetector,
  classifier: AuditEventClassDistributionPsiClassifier,
  vector: FeatureVector,
  psi: number,
  prediction: AnomalyPrediction,
  perClassDrift: PerClassDriftAttribution[],
  baseline: Record<string, number>,
  current: Record<string, number>,
): AnomalyFinding {
  const top = perClassDrift.slice(0, 3).map(formatAttribution).join("; ");
  const severity = psiToScore(psi, classifier.psiThreshold) >= 6
    ? "alert"
    : "warn";
  return {
    finding_id: "",
    sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}${detector.detectorId}`,
    severity,
    summary: `${detector.detectorId}/${classifier.classifierId} ${severity}: agent ${vector.agent_id} audit-event distribution shifted. PSI=${psi.toFixed(3)}. Top drift: ${top || "(none)"}.`,
    details: {
      detector_id: detector.detectorId,
      classifier_id: classifier.classifierId,
      anomaly_score: psiToScore(psi, classifier.psiThreshold),
      psi_score: psi,
      psi_threshold: classifier.psiThreshold,
      window_label: vector.window_label,
      observed_features: vector.features,
      baseline_class_proportions: baseline,
      current_class_proportions: current,
      per_class_drift: perClassDrift,
      feature_contributions: prediction.feature_contributions,
      explanation: prediction.explanation,
    },
    observed_at: vector.observed_at,
    agent_id: vector.agent_id,
    evidence_audit_ids: [],
    fortress_id: "",
  };
}

function proportionsFromVector(vector: FeatureVector): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(vector.features)) {
    if (!key.startsWith("class_proportion:")) continue;
    if (!Number.isFinite(value)) continue;
    out[key.slice("class_proportion:".length)] = value;
  }
  return out;
}

function averageProportions(
  samples: Record<string, number>[],
): Record<string, number> {
  const totals: Record<string, number> = {};
  for (const sample of samples) {
    for (const className of Object.keys(sample)) {
      totals[className] = (totals[className] ?? 0) + (sample[className] ?? 0);
    }
  }
  const averaged: Record<string, number> = {};
  for (const className of Object.keys(totals).sort()) {
    averaged[className] = (totals[className] ?? 0) / samples.length;
  }
  return averaged;
}

function allClasses(
  a: Record<string, number>,
  b: Record<string, number>,
): string[] {
  return [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
}

function psiToScore(psi: number, threshold: number): number {
  if (!Number.isFinite(psi) || !Number.isFinite(threshold) || threshold <= 0) {
    return 0;
  }
  return (psi / threshold) * 6;
}

function attributionsToFeatureContributions(
  attributions: PerClassDriftAttribution[],
): FeatureContribution[] {
  return attributions.map((a) => ({
    feature_name: `class_proportion:${a.class_name}`,
    observed: a.current_proportion,
    baseline_mean: a.baseline_proportion,
    baseline_stddev: 0,
    z_score: a.absolute_delta,
  }));
}

function formatAttribution(a: PerClassDriftAttribution): string {
  const sign = a.absolute_delta >= 0 ? "+" : "";
  const pct =
    a.relative_delta === null
      ? "new"
      : `${sign}${(a.relative_delta * 100).toFixed(0)}%`;
  return `${a.class_name} ${(a.baseline_proportion * 100).toFixed(1)}% -> ${(a.current_proportion * 100).toFixed(1)}% (${pct})`;
}

function emptyPrediction(baselineReady: boolean): AnomalyPrediction {
  return {
    anomaly_score: 0,
    explanation: [],
    feature_contributions: [],
    baseline_ready: baselineReady,
  };
}

class PendingDistributionClassifier
  extends AuditEventClassDistributionPsiClassifier
{
  constructor() {
    super({
      stateStore: {} as ClassifierStateStore,
    });
  }

  override async observe(): Promise<void> {
    throw new Error(
      "anomaly-detector: classifier accessed before subscribe()",
    );
  }

  override async predict(): Promise<never> {
    throw new Error(
      "anomaly-detector: classifier accessed before subscribe()",
    );
  }

  override async train(): Promise<never> {
    throw new Error(
      "anomaly-detector: classifier accessed before subscribe()",
    );
  }
}
