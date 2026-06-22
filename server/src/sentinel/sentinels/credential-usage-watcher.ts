/**
 * Sanctuary v1.3 WP-V1.3-1 Phi-2 Credential Usage Watcher.
 *
 * Second of five baseline sentinels. Surfaces two distinct anomaly
 * classes around an agent's credential consumption before Castle Wall
 * (Layer 1) or the broker's per-call gate (Layer 3) blocks the next
 * request:
 *
 *   - RATE-SPIKE: per (agent, secret) pair, the count of credential
 *     reads in the past 24h exceeded the rolling 7-day baseline by
 *     3 sigma (warn) or 6 sigma (alert).
 *   - NEW-PAIR: an agent used two secrets together within a 24h
 *     window for the first time. One unfamiliar pair surfaces a
 *     `warn`; three or more unfamiliar pairs in one 24h window
 *     escalate to `alert`.
 *
 * Algorithm:
 *
 *   1. Read the last 8 days of L3 broker audit entries.
 *   2. Filter to `broker_secret_read` and `broker_token_issued`
 *      successes (failures are policy-gate hits and a different
 *      signal class; the token-denied audit op covers those).
 *   3. Group by `details.agent` (the wrapped agent id) and
 *      `details.secret` (the secret id). The audit payload shape
 *      comes from `disclosure/broker/token-issuer.ts`.
 *   4. Bucket into 24h windows ending at `now()`. Window 0 = current
 *      24h, windows 1..7 = the prior 7 days. Same shape Phi-1's
 *      egress-volume watcher uses.
 *   5. For each (agent, secret): compute mean + stddev of the 7
 *      baseline-window counts; compare the current count.
 *   6. For each agent: compute the set of unordered secret-pair
 *      fingerprints used in window 0 (cross-product of all distinct
 *      secrets the agent touched in the window). Compute the
 *      historical pair set from windows 1..7. Pairs that appear in
 *      window 0 but never in the historical set fire the new-pair
 *      finding.
 *   7. Skip threshold checks during warmup (fewer than 7 populated
 *      baseline windows) per the same pattern as the egress-volume
 *      watcher.
 *
 * Determinism: pure with respect to (audit-log snapshot, now()).
 *
 * Castle-walking: read-only against the audit log. No outbound
 * network. Findings carry the audit-entry tuples that triggered
 * them so the operator can trace each spike or pair back to source.
 *
 * Operator-friendly summaries (one per finding):
 *   - "Cline agent used `db_admin_token` 47 times in last 24h, baseline 8.2 +/- 2.1 (5.7x normal). Crossed +3 sigma threshold."
 *   - "OpenClaw agent used `stripe_secret` and `aws_root` together for the first time today. This combination does not appear in historical sessions."
 */

import { Sentinel } from "../sentinel.js";
import type { AuditEntry } from "../../operational/audit-log.js";
import type { SentinelFinding } from "../types.js";

export const CREDENTIAL_USAGE_SENTINEL_ID = "credential-usage" as const;

/** Sigma thresholds for the rate-spike path. */
const WARN_SIGMA = 3;
const ALERT_SIGMA = 6;
/** Number of new pairs in one 24h window that escalates warn -> alert. */
const NEW_PAIR_ALERT_COUNT = 3;
/** Days of history required before threshold checks run. */
const BASELINE_WINDOWS = 7;
/** Max audit-log entries to consider per evaluation. */
const QUERY_LIMIT = 20_000;
/** Broker audit-op prefixes the watcher consumes. */
const BROKER_SECRET_READ_OP = "broker_secret_read";
const BROKER_TOKEN_ISSUED_OP = "broker_token_issued";

/** Per (agent, secret) window-aligned snapshot. */
interface SecretCountWindow {
  count: number;
  evidence_audit_ids: string[];
}

interface AgentSecretSnapshot {
  /** Window 0 = current 24h ending at now. Windows 1..7 = prior days. */
  windows: SecretCountWindow[];
}

/** Per-agent aggregate state for pair-fingerprint detection. */
interface AgentPairState {
  /** Distinct secret ids used in the current window. */
  currentSecrets: Set<string>;
  /** Audit evidence tuples drawn from the current window, capped at 50. */
  currentEvidence: string[];
  /** Distinct secret ids used in each baseline window (1..7). */
  baselineSecretsByWindow: Set<string>[];
  /** Whether the agent has any audit activity in the baseline windows. */
  baselinePopulatedWindows: number;
}

export class CredentialUsageWatcher extends Sentinel {
  readonly sentinelId = CREDENTIAL_USAGE_SENTINEL_ID;
  readonly description =
    "Watches per-agent credential reads. Emits warn/alert when a specific (agent, secret) usage rate exceeds the rolling 7-day baseline, or when an agent uses an unfamiliar combination of secrets together in one 24h window.";

  /**
   * Memoization of (agent, secret) pairs whose baseline has been
   * established. Same shape Phi-1 uses to avoid re-emitting `info`
   * findings on every tick after a baseline first establishes.
   *
   * Phi-2 deliberately does NOT emit `info` findings: per-pair
   * baselines on a busy fortress would be too noisy. The memo is
   * kept here for parity with Phi-1's reset hook so tests can clear
   * state between runs.
   */
  private readonly baselineEstablished = new Set<string>();

  /** Reset memoization. Tests use this between runs. */
  resetBaselineMemo(): void {
    this.baselineEstablished.clear();
  }

  async evaluate(): Promise<SentinelFinding[]> {
    const ctx = this.requireContext();
    const now = ctx.now();
    const windowMs = 24 * 60 * 60 * 1000;
    const windowSpanMs = (BASELINE_WINDOWS + 1) * windowMs;
    const sinceIso = new Date(now.getTime() - windowSpanMs).toISOString();

    const queryResult = await ctx.auditLog.query({
      since: sinceIso,
      layer: "l3",
      limit: QUERY_LIMIT,
    });
    const entries = queryResult.entries.filter(isCredentialAuditEntry);

    // Per (agent, secret) count windows: aggregated for the rate-
    // spike path. Per-agent pair state: aggregated for the new-pair
    // path. Both are derived from the same entry stream so we walk
    // entries once.
    const byPair = new Map<string, AgentSecretSnapshot>();
    const byAgent = new Map<string, AgentPairState>();

    for (const entry of entries) {
      const agentId = extractAgentId(entry);
      const secretId = extractSecretId(entry);
      if (agentId === null || secretId === null) continue;
      const auditAge = now.getTime() - new Date(entry.timestamp).getTime();
      if (auditAge < 0) continue;
      const windowIdx = Math.floor(auditAge / windowMs);
      if (windowIdx > BASELINE_WINDOWS) continue;

      const pairKey = `${agentId}\x00${secretId}`;
      let pairSnapshot = byPair.get(pairKey);
      if (!pairSnapshot) {
        pairSnapshot = {
          windows: Array.from({ length: BASELINE_WINDOWS + 1 }, () => ({
            count: 0,
            evidence_audit_ids: [],
          })),
        };
        byPair.set(pairKey, pairSnapshot);
      }
      const bucket = pairSnapshot.windows[windowIdx]!;
      bucket.count += 1;
      if (windowIdx === 0 && bucket.evidence_audit_ids.length < 50) {
        bucket.evidence_audit_ids.push(
          `${entry.timestamp}:${entry.operation}`,
        );
      }

      let agentState = byAgent.get(agentId);
      if (!agentState) {
        agentState = {
          currentSecrets: new Set(),
          currentEvidence: [],
          baselineSecretsByWindow: Array.from(
            { length: BASELINE_WINDOWS },
            () => new Set<string>(),
          ),
          baselinePopulatedWindows: 0,
        };
        byAgent.set(agentId, agentState);
      }
      if (windowIdx === 0) {
        agentState.currentSecrets.add(secretId);
        if (agentState.currentEvidence.length < 50) {
          agentState.currentEvidence.push(
            `${entry.timestamp}:${entry.operation}`,
          );
        }
      } else {
        const baselineIdx = windowIdx - 1;
        agentState.baselineSecretsByWindow[baselineIdx]!.add(secretId);
      }
    }

    const findings: SentinelFinding[] = [];

    // Rate-spike path. One finding per (agent, secret) whose current
    // window exceeded the warn or alert threshold.
    for (const [pairKey, snapshot] of byPair.entries()) {
      const [agentId, secretId] = pairKey.split("\x00") as [string, string];
      const finding = this.evaluateRateSpike(
        agentId,
        secretId,
        snapshot,
        now,
      );
      if (finding) findings.push(finding);
    }

    // New-pair path. One finding per agent whose current window
    // introduced unfamiliar secret pairs.
    for (const [agentId, agentState] of byAgent.entries()) {
      // Update populated-window count after the entry walk so warmup
      // gating is honest.
      agentState.baselinePopulatedWindows =
        agentState.baselineSecretsByWindow.filter((s) => s.size > 0).length;
      const finding = this.evaluateNewPairs(agentId, agentState, now);
      if (finding) findings.push(finding);
    }

    return findings;
  }

  private evaluateRateSpike(
    agentId: string,
    secretId: string,
    snapshot: AgentSecretSnapshot,
    now: Date,
  ): SentinelFinding | null {
    const currentWindow = snapshot.windows[0]!;
    const baselineWindows = snapshot.windows.slice(1);

    const populated = baselineWindows.filter((w) => w.count > 0).length;
    if (populated < BASELINE_WINDOWS) {
      // Warmup: not enough history to threshold against. Memoize so
      // a future tick can detect the transition cleanly, but emit
      // nothing yet.
      return null;
    }

    const counts = baselineWindows.map((w) => w.count);
    const mean = counts.reduce((sum, c) => sum + c, 0) / counts.length;
    const variance =
      counts.reduce((sum, c) => sum + (c - mean) ** 2, 0) / counts.length;
    const stddev = Math.sqrt(variance);

    const pairKey = `${agentId}\x00${secretId}`;
    this.baselineEstablished.add(pairKey);

    const warnThreshold = mean + WARN_SIGMA * stddev;
    const alertThreshold = mean + ALERT_SIGMA * stddev;

    if (currentWindow.count > alertThreshold) {
      return this.buildRateFinding(
        agentId,
        secretId,
        currentWindow,
        mean,
        stddev,
        now,
        "alert",
        ALERT_SIGMA,
      );
    }
    if (currentWindow.count > warnThreshold) {
      return this.buildRateFinding(
        agentId,
        secretId,
        currentWindow,
        mean,
        stddev,
        now,
        "warn",
        WARN_SIGMA,
      );
    }
    return null;
  }

  private buildRateFinding(
    agentId: string,
    secretId: string,
    currentWindow: SecretCountWindow,
    mean: number,
    stddev: number,
    now: Date,
    severity: "warn" | "alert",
    sigma: number,
  ): SentinelFinding {
    const ratio = mean === 0 ? Number.POSITIVE_INFINITY : currentWindow.count / mean;
    const ratioStr = Number.isFinite(ratio)
      ? `${ratio.toFixed(1)}x normal`
      : "no prior baseline";
    const summary = `${agentId} agent used ${secretId} ${currentWindow.count} times in last 24h, baseline ${mean.toFixed(1)} +/- ${stddev.toFixed(1)} (${ratioStr}). Crossed +${sigma} sigma threshold.`;
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity,
      agent_id: agentId,
      summary,
      details: {
        agent_id: agentId,
        secret_id: secretId,
        current_count: currentWindow.count,
        baseline_mean: mean,
        baseline_stddev: stddev,
        sigma_threshold: sigma,
        ratio: Number.isFinite(ratio) ? ratio : null,
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: currentWindow.evidence_audit_ids,
      fortress_id: "",
    };
  }

  private evaluateNewPairs(
    agentId: string,
    state: AgentPairState,
    now: Date,
  ): SentinelFinding | null {
    if (state.baselinePopulatedWindows < BASELINE_WINDOWS) {
      // Warmup. The new-pair detector requires every baseline window
      // populated, mirroring the rate-spike path.
      return null;
    }
    if (state.currentSecrets.size < 2) return null;

    const currentPairs = enumerateUnorderedPairs(state.currentSecrets);
    const historicalPairs = new Set<string>();
    for (const secretSet of state.baselineSecretsByWindow) {
      for (const pair of enumerateUnorderedPairs(secretSet)) {
        historicalPairs.add(pair);
      }
    }

    const newPairs: Array<[string, string]> = [];
    for (const pair of currentPairs) {
      if (historicalPairs.has(pair)) continue;
      const [a, b] = pair.split("\x00") as [string, string];
      newPairs.push([a, b]);
    }

    if (newPairs.length === 0) return null;

    const severity: "warn" | "alert" =
      newPairs.length >= NEW_PAIR_ALERT_COUNT ? "alert" : "warn";

    const summary = buildNewPairSummary(agentId, newPairs);
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity,
      agent_id: agentId,
      summary,
      details: {
        agent_id: agentId,
        new_pairs: newPairs,
        new_pair_count: newPairs.length,
        historical_pair_count: historicalPairs.size,
        current_pair_count: currentPairs.size,
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: state.currentEvidence,
      fortress_id: "",
    };
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/** True for the broker audit ops Phi-2 consumes. */
function isCredentialAuditEntry(entry: AuditEntry): boolean {
  if (entry.result !== "success") return false;
  return (
    entry.operation === BROKER_SECRET_READ_OP ||
    entry.operation === BROKER_TOKEN_ISSUED_OP
  );
}

function extractAgentId(entry: AuditEntry): string | null {
  const details = entry.details as Record<string, unknown> | undefined;
  if (!details) return null;
  const agent = details["agent"];
  return typeof agent === "string" && agent.length > 0 ? agent : null;
}

function extractSecretId(entry: AuditEntry): string | null {
  const details = entry.details as Record<string, unknown> | undefined;
  if (!details) return null;
  const secret = details["secret"];
  return typeof secret === "string" && secret.length > 0 ? secret : null;
}

/**
 * Enumerate canonical unordered pairs from a set of secret ids. Pair
 * keys use a NUL separator so they round-trip through `split("\x00")`
 * cleanly; secret ids are operator-controlled strings but the broker
 * already validates them. Sorting the two ids before joining ensures
 * `(A, B)` and `(B, A)` collapse to one canonical key.
 */
function enumerateUnorderedPairs(secrets: Set<string>): Set<string> {
  const out = new Set<string>();
  const arr = [...secrets].sort();
  for (let i = 0; i < arr.length; i += 1) {
    for (let j = i + 1; j < arr.length; j += 1) {
      out.add(`${arr[i]}\x00${arr[j]}`);
    }
  }
  return out;
}

function buildNewPairSummary(
  agentId: string,
  newPairs: Array<[string, string]>,
): string {
  const first = newPairs[0]!;
  if (newPairs.length === 1) {
    return `${agentId} agent used ${first[0]} and ${first[1]} together for the first time today. This combination does not appear in historical sessions.`;
  }
  return `${agentId} agent introduced ${newPairs.length} unfamiliar credential pairs in the last 24h. First: ${first[0]} + ${first[1]}. This pattern is new for this agent.`;
}
