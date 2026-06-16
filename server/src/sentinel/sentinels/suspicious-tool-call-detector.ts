/**
 * Sanctuary v1.3 WP-V1.3-1 Phi-4 Suspicious-Tool-Call Detector.
 *
 * Fourth of five baseline sentinels. Surfaces tool calls whose
 * argument shape, call frequency, or permission combination looks
 * unusual against the fortress's recent history.
 *
 * Three rule-based layers + an optional LLM-assist fallback:
 *
 *   Layer A — signature patterns (cheap, deterministic)
 *     Reads `gate_*:*` audit entries (the only audit shape that
 *     captures `args_summary`). Matches per-call against:
 *       - Truncation marker repetition (large payload signal: every
 *         args value >100 chars appears as `<100>...` — repeated
 *         truncation across many fields signals bulk extraction).
 *       - URL-encoded blob (>=5 `%XX` sequences in any visible value).
 *       - Base64-like chunk (>=40 contiguous `[A-Za-z0-9+/=]` chars).
 *       - Shell metacharacters (`;`, `|`, `&&`, backticks, `$(`)
 *         in a visible value.
 *       - Novel signature (tool name + sorted arg-key set never
 *         observed in the baseline window).
 *
 *   Layer B — frequency anomaly (statistical, per-tool baseline)
 *     Per-tool 24h-window count vs. a 7-day rolling baseline. Same
 *     +3σ warn / +6σ alert thresholds as Phi-1 EgressVolumeWatcher,
 *     same `populatedBaselineWindows >= 7` warm-up gate.
 *
 *   Layer C — permission-combination novelty (heuristic)
 *     Buckets tool calls into approximate "tasks" (1h contiguous
 *     bursts) and tracks the sorted tool-name set per task. Fires
 *     `warn` on first occurrence of a novel combination; `alert`
 *     when 2+ novel combinations land within the same 24h window.
 *
 *   LLM-assist fallback (optional, substrate-selector routed)
 *     Layer A signature matches that are ambiguous (e.g. base64
 *     blob that could be a legitimate auth token OR an exfiltration
 *     payload) escalate to `selector.invokeClassify` on the
 *     `sentinel-scoring` surface. The classifier returns
 *     `benign | suspicious` with a confidence; only `suspicious +
 *     confidence >= 0.5` produces a finding. Failure-class
 *     responses degrade to no-finding (the rule-based layers
 *     already produced a finding when warranted).
 *
 * Castle-walking discipline:
 *   - No outbound network surface. The substrate selector is the
 *     single LLM-capable handle and respects no-outbound-by-default
 *     by routing through the operator's chosen substrate (local
 *     Ollama by default).
 *   - All findings carry the contributing audit-entry tuples in
 *     `evidence_audit_ids` so the operator can trace back to source.
 *
 * Audit contract drift (flagged in PR body):
 *   The spawn prompt envisions per-AGENT baselines. The current
 *   audit-log surface stamps `identity_id: "system"` on every
 *   `gate_*:*` and `proxy_call:*` entry; per-agent attribution
 *   lives in `args_summary.agent_identity_id` for tools that take
 *   a counterparty arg, and elsewhere is structurally absent. Phi-4
 *   ships per-tool baselines today; per-agent attribution is a
 *   forward-compat extension point that lights up automatically
 *   when audit events grow an `agent_id` field.
 *
 *   Argument inspection is bounded by `summarizeArgs()` which
 *   truncates each string value to 100 chars + "..." marker.
 *   Layer A signatures detect truncation + visible-prefix patterns
 *   only; full-payload inspection (e.g. >1KB base64 decode) is
 *   not possible against the audit surface and is deferred to
 *   WP-V1.3-2 ML-based anomaly detection.
 */

import { Sentinel } from "../sentinel.js";
import {
  type SentinelFinding,
  type SentinelSeverity,
} from "../types.js";
import type { AuditEntry } from "../../operational/audit-log.js";

export const SUSPICIOUS_TOOL_CALL_SENTINEL_ID =
  "suspicious-tool-call" as const;

/** Audit operation prefixes the detector observes. */
const GATE_PREFIXES = [
  "gate_allow:",
  "gate_allow_proxy:",
  "gate_deny:",
  "gate_unclassified:",
] as const;

/** Layer B sigma thresholds (mirrors Phi-1). */
const WARN_SIGMA = 3;
const ALERT_SIGMA = 6;
/** Days of history required before threshold checks run (mirrors Phi-1). */
const BASELINE_WINDOWS = 7;

/** Layer C novel-combination 24h `alert` threshold. */
const ALERT_NOVEL_COMBINATIONS = 2;

/** Approximate task-window length for Layer C bucketing (1h). */
const TASK_WINDOW_MS = 60 * 60 * 1000;
/** Layer A truncation count that elevates "large payload" to `warn`. */
const TRUNCATION_WARN_THRESHOLD = 5;
/** Max audit entries to scan per evaluation. */
const QUERY_LIMIT = 10_000;

/** Layer A signature kinds. Stable for finding details payload. */
export type SignatureKind =
  | "truncation_burst"
  | "url_encoded_blob"
  | "base64_chunk"
  | "shell_metachar"
  | "novel_signature";

/** Layer A regex/threshold definitions. Exported for tests. */
export const SIGNATURE_PATTERNS = {
  /** >=5 percent-encoded sequences in a single visible value. */
  urlEncodedThreshold: 5,
  /** >=40 contiguous base64 chars in a single visible value. */
  base64MinRun: 40,
  /** Shell metacharacter set. */
  shellMetacharRegex: /(?:&&|\|\||;|\$\(|`|\|\s)/,
} as const;

interface ToolCallObservation {
  /** Stable tool/operation key (post-prefix-strip). */
  tool: string;
  /** True when the source audit op was `gate_allow_proxy:*`. */
  proxy: boolean;
  /** Audit entry timestamp (ms since epoch). */
  ts: number;
  /** Original audit entry for evidence threading. */
  entry: AuditEntry;
  /** Args-summary snapshot, when present on the audit entry. */
  argsSummary: Record<string, unknown>;
}

interface PerToolWindow {
  /** Window 0 = current 24h. Windows 1..7 = prior days. */
  windows: { count: number; evidenceIds: string[] }[];
  /** Last-seen arg-key signatures (sorted-keys-joined-with-comma). */
  knownSignatures: Set<string>;
}

interface TaskBucket {
  /** Task window start (ms). */
  startTs: number;
  /** Sorted unique tool keys observed in this task. */
  tools: string[];
}

/** Optional LLM-assist classifier handle. The detector accepts the
 * full `SentinelContext.substrateSelector` and only invokes
 * `invokeClassify` on the `sentinel-scoring` surface. */
type ClassifyFn = (items: string[]) => Promise<
  | { kind: "classify"; results: { category: string; confidence: number }[] }
  | { kind: "failure"; message: string }
  | null
>;

export class SuspiciousToolCallDetector extends Sentinel {
  readonly sentinelId = SUSPICIOUS_TOOL_CALL_SENTINEL_ID;
  readonly description =
    "Surfaces tool calls whose argument shape, call frequency, or permission combination looks unusual for the fortress's recent history. Rule-based heuristics with optional LLM-assist on ambiguous matches.";

  /** Servers we have already produced an `info` baseline-established finding for. */
  private readonly baselineEstablished = new Set<string>();
  /** Memoized known novel-combination keys (sorted-tools-csv). */
  private readonly knownCombinations = new Set<string>();
  /** Tasks observed where a novel combination already produced a finding. */
  private readonly novelCombinationsReported = new Set<string>();

  async evaluate(): Promise<SentinelFinding[]> {
    const ctx = this.requireContext();
    const now = ctx.now();
    const dayMs = 24 * 60 * 60 * 1000;
    const windowSpanMs = (BASELINE_WINDOWS + 1) * dayMs;
    const sinceIso = new Date(now.getTime() - windowSpanMs).toISOString();

    const queryResult = await ctx.auditLog.query({
      since: sinceIso,
      layer: "l2",
      limit: QUERY_LIMIT,
    });

    const observations: ToolCallObservation[] = [];
    for (const entry of queryResult.entries) {
      const obs = this.observationFromEntry(entry);
      if (obs && obs.ts <= now.getTime()) observations.push(obs);
    }

    if (observations.length === 0) return [];

    const findings: SentinelFinding[] = [];

    // Layer A — signature scan over the most recent 24h.
    const layerAFindings = await this.runLayerA(observations, now, ctx);
    findings.push(...layerAFindings);

    // Layer B — frequency anomaly per-tool.
    const layerBFindings = this.runLayerB(observations, now);
    findings.push(...layerBFindings);

    // Layer C — permission-combination novelty.
    const layerCFindings = this.runLayerC(observations, now);
    findings.push(...layerCFindings);

    return findings;
  }

  /** Reset memoization between test runs. Mirrors Phi-1's reset hook. */
  resetMemo(): void {
    this.baselineEstablished.clear();
    this.knownCombinations.clear();
    this.novelCombinationsReported.clear();
  }

  // ── Layer A ───────────────────────────────────────────────────────

  private async runLayerA(
    observations: ToolCallObservation[],
    now: Date,
    ctx: { substrateSelector?: { invokeClassify?: unknown } | undefined },
  ): Promise<SentinelFinding[]> {
    const dayMs = 24 * 60 * 60 * 1000;
    const recent = observations.filter(
      (o) => now.getTime() - o.ts <= dayMs,
    );
    if (recent.length === 0) return [];

    const findings: SentinelFinding[] = [];

    // Build per-tool known-signature memory from the historical
    // window (entries older than current 24h).
    const historical = observations.filter(
      (o) => now.getTime() - o.ts > dayMs,
    );
    const perTool = new Map<string, PerToolWindow>();
    const ensureTool = (tool: string): PerToolWindow => {
      let w = perTool.get(tool);
      if (!w) {
        w = {
          windows: Array.from({ length: BASELINE_WINDOWS + 1 }, () => ({
            count: 0,
            evidenceIds: [],
          })),
          knownSignatures: new Set(),
        };
        perTool.set(tool, w);
      }
      return w;
    };
    for (const o of historical) {
      ensureTool(o.tool).knownSignatures.add(this.signatureOf(o.argsSummary));
    }

    const classify = this.classifyHandle(ctx);

    for (const obs of recent) {
      const matches = this.matchSignatures(obs);
      if (matches.length === 0) continue;

      // Novel-signature is a soft signal; gate the others normally.
      const ambiguous = matches.every((m) => m === "base64_chunk");
      if (ambiguous && classify) {
        const verdict = await this.consultClassifier(classify, obs);
        if (verdict !== "suspicious") continue;
      }

      findings.push(
        this.buildLayerAFinding(obs, matches, now, classify ? "llm-assist" : "rule-based"),
      );
    }

    // Novel-signature pass is layered on top so historical baseline
    // bootstraps the comparison set.
    for (const obs of recent) {
      const tool = obs.tool;
      const sig = this.signatureOf(obs.argsSummary);
      const known = perTool.get(tool)?.knownSignatures;
      if (known && known.size > 0 && !known.has(sig)) {
        findings.push(
          this.buildNovelSignatureFinding(obs, sig, now),
        );
      }
    }

    return findings;
  }

  private matchSignatures(obs: ToolCallObservation): SignatureKind[] {
    const out: SignatureKind[] = [];
    const truncCount = countTruncatedValues(obs.argsSummary);
    if (truncCount >= TRUNCATION_WARN_THRESHOLD) out.push("truncation_burst");

    let urlBlob = false;
    let base64Blob = false;
    let shellChars = false;
    for (const value of Object.values(obs.argsSummary)) {
      if (typeof value !== "string") continue;
      if (countUrlEncoded(value) >= SIGNATURE_PATTERNS.urlEncodedThreshold) {
        urlBlob = true;
      }
      if (longestBase64Run(value) >= SIGNATURE_PATTERNS.base64MinRun) {
        base64Blob = true;
      }
      if (SIGNATURE_PATTERNS.shellMetacharRegex.test(value)) {
        shellChars = true;
      }
    }
    if (urlBlob) out.push("url_encoded_blob");
    if (base64Blob) out.push("base64_chunk");
    if (shellChars) out.push("shell_metachar");
    return out;
  }

  private signatureOf(argsSummary: Record<string, unknown>): string {
    return Object.keys(argsSummary).sort().join(",");
  }

  private buildLayerAFinding(
    obs: ToolCallObservation,
    matches: SignatureKind[],
    now: Date,
    detectionPath: "rule-based" | "llm-assist",
  ): SentinelFinding {
    const severity: SentinelSeverity = matches.includes("shell_metachar")
      ? "alert"
      : "warn";
    const summary = `${obs.tool}: tool-call argument matches signature ${matches.join(", ")} (${detectionPath}).`;
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity,
      summary: truncateSummary(summary),
      details: {
        layer: "A",
        tool: obs.tool,
        proxy: obs.proxy,
        signatures: matches,
        detection_path: detectionPath,
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: [`${obs.entry.timestamp}:${obs.entry.operation}`],
      fortress_id: "",
    };
  }

  private buildNovelSignatureFinding(
    obs: ToolCallObservation,
    signature: string,
    now: Date,
  ): SentinelFinding {
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity: "warn",
      summary: truncateSummary(
        `${obs.tool}: novel argument-key signature observed (${signature || "<no-args>"}).`,
      ),
      details: {
        layer: "A",
        tool: obs.tool,
        proxy: obs.proxy,
        signatures: ["novel_signature" satisfies SignatureKind],
        detection_path: "rule-based",
        novel_signature: signature,
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: [`${obs.entry.timestamp}:${obs.entry.operation}`],
      fortress_id: "",
    };
  }

  // ── Layer B ───────────────────────────────────────────────────────

  private runLayerB(
    observations: ToolCallObservation[],
    now: Date,
  ): SentinelFinding[] {
    const dayMs = 24 * 60 * 60 * 1000;
    const perTool = new Map<string, PerToolWindow>();

    for (const obs of observations) {
      const ageMs = now.getTime() - obs.ts;
      if (ageMs < 0) continue;
      const windowIdx = Math.floor(ageMs / dayMs);
      if (windowIdx > BASELINE_WINDOWS) continue;
      let w = perTool.get(obs.tool);
      if (!w) {
        w = {
          windows: Array.from({ length: BASELINE_WINDOWS + 1 }, () => ({
            count: 0,
            evidenceIds: [],
          })),
          knownSignatures: new Set(),
        };
        perTool.set(obs.tool, w);
      }
      const bucket = w.windows[windowIdx]!;
      bucket.count += 1;
      if (windowIdx === 0 && bucket.evidenceIds.length < 50) {
        bucket.evidenceIds.push(`${obs.entry.timestamp}:${obs.entry.operation}`);
      }
    }

    const findings: SentinelFinding[] = [];
    for (const [tool, w] of perTool.entries()) {
      const f = this.evaluateToolFrequency(tool, w, now);
      if (f) findings.push(f);
    }
    return findings;
  }

  private evaluateToolFrequency(
    tool: string,
    w: PerToolWindow,
    now: Date,
  ): SentinelFinding | null {
    const current = w.windows[0]!;
    const baseline = w.windows.slice(1);
    const populated = baseline.filter((b) => b.count > 0).length;
    if (populated < BASELINE_WINDOWS) {
      this.baselineEstablished.add(tool);
      return null;
    }

    const counts = baseline.map((b) => b.count);
    const mean = counts.reduce((sum, c) => sum + c, 0) / counts.length;
    const variance =
      counts.reduce((sum, c) => sum + (c - mean) ** 2, 0) / counts.length;
    const stddev = Math.sqrt(variance);

    const wasEstablished = this.baselineEstablished.has(tool);
    this.baselineEstablished.add(tool);
    if (!wasEstablished) {
      // Mirrors Phi-1: emit an `info` once per tool when the baseline
      // first crosses the warm-up threshold. Subsequent ticks only
      // fire on threshold breach.
      return {
        finding_id: "",
        sentinel_id: this.sentinelId,
        severity: "info",
        summary: truncateSummary(
          `${tool}: tool-call baseline established (mean ${mean.toFixed(1)} calls/24h, stddev ${stddev.toFixed(1)} over ${BASELINE_WINDOWS} prior days).`,
        ),
        details: {
          layer: "B",
          tool,
          baseline_mean: mean,
          baseline_stddev: stddev,
          baseline_counts: counts,
          current_count: current.count,
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: [],
        fortress_id: "",
      };
    }

    const warnT = mean + WARN_SIGMA * stddev;
    const alertT = mean + ALERT_SIGMA * stddev;
    if (current.count > alertT) {
      return this.buildLayerBAnomaly(
        tool,
        current,
        mean,
        stddev,
        ALERT_SIGMA,
        "alert",
        now,
      );
    }
    if (current.count > warnT) {
      return this.buildLayerBAnomaly(
        tool,
        current,
        mean,
        stddev,
        WARN_SIGMA,
        "warn",
        now,
      );
    }
    return null;
  }

  private buildLayerBAnomaly(
    tool: string,
    current: { count: number; evidenceIds: string[] },
    mean: number,
    stddev: number,
    sigma: number,
    severity: "warn" | "alert",
    now: Date,
  ): SentinelFinding {
    const ratio = mean === 0 ? Infinity : current.count / mean;
    const ratioStr = Number.isFinite(ratio)
      ? `${ratio.toFixed(1)}x normal`
      : "no prior baseline";
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity,
      summary: truncateSummary(
        `${tool}: tool-call rate is ${ratioStr}: ${current.count} calls in last 24h, baseline ${mean.toFixed(1)} (stddev ${stddev.toFixed(1)}). Crossed +${sigma} sigma.`,
      ),
      details: {
        layer: "B",
        tool,
        current_count: current.count,
        baseline_mean: mean,
        baseline_stddev: stddev,
        sigma_threshold: sigma,
        ratio,
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: current.evidenceIds,
      fortress_id: "",
    };
  }

  // ── Layer C ───────────────────────────────────────────────────────

  private runLayerC(
    observations: ToolCallObservation[],
    now: Date,
  ): SentinelFinding[] {
    const dayMs = 24 * 60 * 60 * 1000;

    // Bucket observations into approximate "task" windows.
    // A task is a contiguous burst of calls; gap > TASK_WINDOW_MS
    // starts a new task.
    const sorted = [...observations].sort((a, b) => a.ts - b.ts);
    const tasks: TaskBucket[] = [];
    for (const obs of sorted) {
      const last = tasks[tasks.length - 1];
      if (!last || obs.ts - last.startTs > TASK_WINDOW_MS) {
        tasks.push({ startTs: obs.ts, tools: [obs.tool] });
        continue;
      }
      if (!last.tools.includes(obs.tool)) last.tools.push(obs.tool);
    }

    const recentTaskKeys: string[] = [];
    const findings: SentinelFinding[] = [];

    // Single-task pass to bootstrap known combinations from history.
    for (const task of tasks) {
      const ageMs = now.getTime() - task.startTs;
      const key = task.tools.slice().sort().join(",");
      if (ageMs > dayMs) {
        // Historical: contributes to known set, never fires.
        this.knownCombinations.add(key);
        continue;
      }
      // Skip single-tool tasks for novelty purposes — those are
      // covered by Layer A's novel-signature path.
      if (task.tools.length < 2) continue;
      if (!this.knownCombinations.has(key)) {
        this.knownCombinations.add(key);
        if (!this.novelCombinationsReported.has(key)) {
          this.novelCombinationsReported.add(key);
          recentTaskKeys.push(key);
          findings.push(
            this.buildLayerCFinding(task, key, "warn", now),
          );
        }
      }
    }

    if (recentTaskKeys.length >= ALERT_NOVEL_COMBINATIONS) {
      // Promote the first warn finding to an alert by appending an
      // aggregate finding that captures both keys.
      const aggregate: SentinelFinding = {
        finding_id: "",
        sentinel_id: this.sentinelId,
        severity: "alert",
        summary: truncateSummary(
          `multi-novel-combination: ${recentTaskKeys.length} novel tool-permission combinations within last 24h.`,
        ),
        details: {
          layer: "C",
          novel_combinations: recentTaskKeys,
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: [],
        fortress_id: "",
      };
      findings.push(aggregate);
    }

    return findings;
  }

  private buildLayerCFinding(
    task: TaskBucket,
    key: string,
    severity: "warn" | "alert",
    now: Date,
  ): SentinelFinding {
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity,
      summary: truncateSummary(
        `novel-permission-combination: tools=[${task.tools.join(",")}] observed in single task burst (${task.tools.length} distinct tools).`,
      ),
      details: {
        layer: "C",
        combination_key: key,
        tools: task.tools,
        task_started_at: new Date(task.startTs).toISOString(),
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: [],
      fortress_id: "",
    };
  }

  // ── LLM-assist ────────────────────────────────────────────────────

  private classifyHandle(
    ctx: { substrateSelector?: { invokeClassify?: unknown } | undefined },
  ): ClassifyFn | null {
    const selector = ctx.substrateSelector;
    if (!selector) return null;
    const fn = selector.invokeClassify as
      | ((
          surface: string,
          req: { kind: "classify"; items: string[]; categories: string[] },
        ) => Promise<{
          body:
            | {
                kind: "classify";
                results: { category: string; confidence: number }[];
              }
            | { kind: "failure"; message: string };
          failureClass: string | null;
        }>)
      | undefined;
    if (typeof fn !== "function") return null;

    return async (items) => {
      try {
        const resp = await fn.call(selector, "sentinel-scoring", {
          kind: "classify",
          items,
          categories: ["benign", "suspicious"],
        });
        if (resp.failureClass) return { kind: "failure", message: "substrate failure" };
        if (resp.body.kind === "classify") {
          return { kind: "classify", results: resp.body.results };
        }
        return { kind: "failure", message: resp.body.message };
      } catch {
        return null;
      }
    };
  }

  private async consultClassifier(
    classify: ClassifyFn,
    obs: ToolCallObservation,
  ): Promise<"suspicious" | "benign" | "unknown"> {
    const item = JSON.stringify({
      tool: obs.tool,
      proxy: obs.proxy,
      args_summary: obs.argsSummary,
    });
    const result = await classify([item]);
    if (!result || result.kind !== "classify") return "unknown";
    const top = result.results[0];
    if (!top) return "unknown";
    if (top.category === "suspicious" && top.confidence >= 0.5) {
      return "suspicious";
    }
    if (top.category === "benign") return "benign";
    return "unknown";
  }

  // ── helpers ───────────────────────────────────────────────────────

  private observationFromEntry(
    entry: AuditEntry,
  ): ToolCallObservation | null {
    const op = entry.operation;
    let tool: string | null = null;
    let proxy = false;
    for (const prefix of GATE_PREFIXES) {
      if (op.startsWith(prefix)) {
        tool = op.slice(prefix.length);
        proxy = prefix === "gate_allow_proxy:";
        break;
      }
    }
    if (!tool) return null;
    const ts = Date.parse(entry.timestamp);
    if (!Number.isFinite(ts)) return null;
    const argsSummary = extractArgsSummary(entry.details);
    return { tool, proxy, ts, entry, argsSummary };
  }
}

// ── pure helpers (exported for tests) ──────────────────────────────────

export function countTruncatedValues(
  args: Record<string, unknown>,
): number {
  let n = 0;
  for (const v of Object.values(args)) {
    if (typeof v === "string" && v.endsWith("...")) n += 1;
  }
  return n;
}

export function countUrlEncoded(value: string): number {
  const matches = value.match(/%[0-9a-fA-F]{2}/g);
  return matches ? matches.length : 0;
}

export function longestBase64Run(value: string): number {
  const matches = value.match(/[A-Za-z0-9+/=]{40,}/g);
  if (!matches) return 0;
  return matches.reduce((max, m) => (m.length > max ? m.length : max), 0);
}

function extractArgsSummary(
  details: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!details) return {};
  const summary = details["args_summary"];
  if (summary && typeof summary === "object" && !Array.isArray(summary)) {
    return summary as Record<string, unknown>;
  }
  return {};
}

function truncateSummary(s: string): string {
  return s.length > 240 ? s.slice(0, 237) + "..." : s;
}
