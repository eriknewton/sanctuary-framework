/**
 * Sanctuary v1.3 WP-V1.3-1 Phi-3 Cross-Agent Chatter Watcher.
 *
 * Detects unusual inter-agent communication patterns:
 *  - Per-pair rate spikes: a (sender, recipient) pair's 24h message
 *    count crossing +3 sigma (warn) or +6 sigma (alert) over the
 *    rolling 7-day baseline.
 *  - New-partner detection: an agent suddenly communicating with a
 *    counterpart never seen in its historical graph (warn). When the
 *    same source agent surfaces 3 or more new partners in one 24h
 *    window, escalate to alert (multi-new-partner pattern, classic
 *    lateral-movement shape).
 *
 * Audit-log signal sources unioned by this watcher:
 *  - `v1.1_local_handoff` (Tau-3 in-process coordination): canonical
 *    inter-agent signal with explicit sender + recipient agent ids.
 *  - `cross_harness_approval_aggregated`,
 *    `cross_harness_approval_resolved` (Upsilon-1 cross-harness
 *    aggregator): models wrapped-agent -> operator chatter as a pair
 *    where the recipient is the synthetic `operator` node.
 *
 * NOT included at v1.3 (deviation, documented in PR body):
 *  - `composition_*` events are mesh-only signed envelopes; they do
 *    not flow through the audit log today. When composition wires its
 *    emissions through `auditLog.append`, this watcher's union
 *    extends to cover them; until then, composition activity is
 *    invisible to chatter detection.
 *  - Federation peer-registry events (`federation_peer_register`,
 *    etc.) describe trust topology, not active messaging.
 *
 * Castle-walking: no outbound network. Reads server-local audit log
 * only. Findings carry the audit_log_entry_id of every contributing
 * entry so the operator can trace the spike or new partner back to
 * source.
 *
 * Multi-fortress isolation: the SentinelContext provides a
 * fortress-scoped audit log. The watcher never crosses that boundary;
 * each fortress's chatter graph is independent.
 */

import { Sentinel } from "../sentinel.js";
import type { SentinelFinding } from "../types.js";
import type { AuditEntry } from "../../operational/audit-log.js";

export const CROSS_AGENT_CHATTER_SENTINEL_ID = "cross-agent-chatter" as const;

const WARN_SIGMA = 3;
const ALERT_SIGMA = 6;
const BASELINE_WINDOWS = 7;
const QUERY_LIMIT = 10_000;
const MULTI_NEW_PARTNER_ALERT_THRESHOLD = 3;
/**
 * Synthetic recipient node used for wrapped-agent -> operator events
 * from the Upsilon-1 cross-harness aggregator. Surface this as a
 * stable string so the operator can recognize it in finding details.
 */
const OPERATOR_PSEUDO_AGENT = "operator" as const;

const HANDOFF_OP = "v1.1_local_handoff";
const CROSS_HARNESS_OPS = new Set<string>([
  "cross_harness_approval_aggregated",
  "cross_harness_approval_resolved",
]);

interface PairWindow {
  count: number;
  evidence_audit_ids: string[];
}

interface PairSnapshot {
  /** Window 0 = current 24h ending at now. Windows 1..7 = prior days. */
  windows: PairWindow[];
}

/** Internal representation of an inter-agent event extracted from audit. */
interface InterAgentEvent {
  sender: string;
  recipient: string;
  timestampMs: number;
  auditId: string;
}

/** Pair key derivation. Stable, lowercase, separator forbidden in agent ids. */
function pairKey(sender: string, recipient: string): string {
  return `${sender}|${recipient}`;
}

function pairFromKey(key: string): { sender: string; recipient: string } {
  const idx = key.indexOf("|");
  return { sender: key.slice(0, idx), recipient: key.slice(idx + 1) };
}

export class CrossAgentChatterWatcher extends Sentinel {
  readonly sentinelId = CROSS_AGENT_CHATTER_SENTINEL_ID;
  readonly description =
    "Watches inter-agent communication patterns. Surfaces per-pair rate spikes (3 or 6 sigma over the rolling 7-day baseline) and new-partner appearances. Escalates to alert when one source agent picks up 3 or more new partners in 24h (lateral-movement shape).";

  /** Pair keys we have already produced a baseline-established info finding for. */
  private readonly baselineEstablished = new Set<string>();

  async evaluate(): Promise<SentinelFinding[]> {
    const ctx = this.requireContext();
    const now = ctx.now();
    const windowMs = 24 * 60 * 60 * 1000;
    const windowSpanMs = (BASELINE_WINDOWS + 1) * windowMs;
    const sinceIso = new Date(now.getTime() - windowSpanMs).toISOString();
    const queryResult = await ctx.auditLog.query({
      since: sinceIso,
      layer: "l2",
      limit: QUERY_LIMIT,
    });

    const events = extractInterAgentEvents(queryResult.entries);
    const byPair = new Map<string, PairSnapshot>();
    for (const event of events) {
      const auditAgeMs = now.getTime() - event.timestampMs;
      if (auditAgeMs < 0) continue;
      const windowIdx = Math.floor(auditAgeMs / windowMs);
      if (windowIdx > BASELINE_WINDOWS) continue;
      const key = pairKey(event.sender, event.recipient);
      let snap = byPair.get(key);
      if (!snap) {
        snap = { windows: [] };
        for (let i = 0; i <= BASELINE_WINDOWS; i += 1) {
          snap.windows.push({ count: 0, evidence_audit_ids: [] });
        }
        byPair.set(key, snap);
      }
      const bucket = snap.windows[windowIdx]!;
      bucket.count += 1;
      if (windowIdx === 0 && bucket.evidence_audit_ids.length < 50) {
        bucket.evidence_audit_ids.push(event.auditId);
      }
    }

    const findings: SentinelFinding[] = [];

    // Pass 1: per-pair rate-spike findings (and one-shot baseline-info per pair).
    for (const [key, snap] of byPair.entries()) {
      const finding = this.evaluatePair(key, snap, now);
      if (finding) findings.push(finding);
    }

    // Pass 2: new-partner detection per source agent.
    const newPartnersBySource = computeNewPartners(byPair);
    for (const [source, partners] of newPartnersBySource.entries()) {
      const finding = this.buildNewPartnerFinding(source, partners, now);
      if (finding) findings.push(finding);
    }

    return findings;
  }

  /** Reset baseline-established memoization. Tests use this between runs. */
  resetBaselineMemo(): void {
    this.baselineEstablished.clear();
  }

  private evaluatePair(
    key: string,
    snap: PairSnapshot,
    now: Date,
  ): SentinelFinding | null {
    const currentWindow = snap.windows[0]!;
    const baselineWindows = snap.windows.slice(1);
    const populated = baselineWindows.filter((w) => w.count > 0).length;
    if (populated < BASELINE_WINDOWS) {
      return null;
    }

    const counts = baselineWindows.map((w) => w.count);
    const mean = counts.reduce((s, c) => s + c, 0) / counts.length;
    const variance =
      counts.reduce((s, c) => s + (c - mean) ** 2, 0) / counts.length;
    const stddev = Math.sqrt(variance);
    const wasEstablished = this.baselineEstablished.has(key);
    this.baselineEstablished.add(key);

    if (!wasEstablished) {
      const pair = pairFromKey(key);
      return {
        finding_id: "",
        sentinel_id: this.sentinelId,
        severity: "info",
        summary: `cross-agent-chatter baseline established for ${pair.sender} -> ${pair.recipient}: mean ${mean.toFixed(1)} msgs/24h, stddev ${stddev.toFixed(1)} (over ${BASELINE_WINDOWS} prior days).`,
        details: {
          sender_agent_id: pair.sender,
          recipient_agent_id: pair.recipient,
          baseline_mean: mean,
          baseline_stddev: stddev,
          baseline_windows: counts,
          current_count: currentWindow.count,
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: [],
        fortress_id: "",
      };
    }

    const warnThreshold = mean + WARN_SIGMA * stddev;
    const alertThreshold = mean + ALERT_SIGMA * stddev;

    if (currentWindow.count > alertThreshold) {
      return this.buildRateSpike(key, snap, mean, stddev, now, "alert", ALERT_SIGMA);
    }
    if (currentWindow.count > warnThreshold) {
      return this.buildRateSpike(key, snap, mean, stddev, now, "warn", WARN_SIGMA);
    }
    return null;
  }

  private buildRateSpike(
    key: string,
    snap: PairSnapshot,
    mean: number,
    stddev: number,
    now: Date,
    severity: "warn" | "alert",
    sigma: number,
  ): SentinelFinding {
    const pair = pairFromKey(key);
    const cur = snap.windows[0]!;
    const ratio = mean === 0 ? Infinity : cur.count / mean;
    const ratioStr = Number.isFinite(ratio)
      ? `${ratio.toFixed(1)}x normal`
      : "no prior baseline";
    const summary = `${pair.sender} -> ${pair.recipient} chatter rate is ${ratioStr}: ${cur.count} cross-agent messages in last 24h, baseline ${mean.toFixed(1)} (stddev ${stddev.toFixed(1)}). Crossed +${sigma} sigma threshold.`;
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity,
      summary,
      details: {
        sender_agent_id: pair.sender,
        recipient_agent_id: pair.recipient,
        current_count: cur.count,
        baseline_mean: mean,
        baseline_stddev: stddev,
        sigma_threshold: sigma,
        ratio,
      },
      observed_at: now.toISOString(),
      agent_id: pair.sender,
      evidence_audit_ids: cur.evidence_audit_ids,
      fortress_id: "",
    };
  }

  private buildNewPartnerFinding(
    source: string,
    info: NewPartnerInfo,
    now: Date,
  ): SentinelFinding | null {
    if (info.partners.length === 0) return null;
    const severity: "warn" | "alert" =
      info.partners.length >= MULTI_NEW_PARTNER_ALERT_THRESHOLD
        ? "alert"
        : "warn";
    const partnerList = info.partners.join(", ");
    const baselinePartnerList =
      info.priorPartners.length === 0
        ? "no prior partners"
        : info.priorPartners.join(", ");
    const summary =
      severity === "alert"
        ? `${source} began communicating with ${info.partners.length} new partners in 24h (${partnerList}). Prior partners: ${baselinePartnerList}. Multi-new-partner pattern crossed alert threshold (>=${MULTI_NEW_PARTNER_ALERT_THRESHOLD}).`
        : `${source} began communicating with a new partner today: ${partnerList}. Prior partners: ${baselinePartnerList}.`;
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity,
      summary,
      details: {
        sender_agent_id: source,
        new_partners: info.partners,
        prior_partners: info.priorPartners,
        new_partner_count: info.partners.length,
        multi_new_partner_threshold: MULTI_NEW_PARTNER_ALERT_THRESHOLD,
      },
      observed_at: now.toISOString(),
      agent_id: source,
      evidence_audit_ids: info.evidenceAuditIds,
      fortress_id: "",
    };
  }
}

interface NewPartnerInfo {
  partners: string[];
  priorPartners: string[];
  evidenceAuditIds: string[];
}

/**
 * For each source agent, compute the set of partners seen in the
 * current 24h window that were never seen in any of the 7 baseline
 * windows. Returns one entry per source agent with at least one new
 * partner.
 */
function computeNewPartners(
  byPair: Map<string, PairSnapshot>,
): Map<string, NewPartnerInfo> {
  const currentBySource = new Map<string, Map<string, string[]>>();
  const priorBySource = new Map<string, Set<string>>();

  for (const [key, snap] of byPair.entries()) {
    const { sender, recipient } = pairFromKey(key);
    if (snap.windows[0] && snap.windows[0].count > 0) {
      let recipMap = currentBySource.get(sender);
      if (!recipMap) {
        recipMap = new Map();
        currentBySource.set(sender, recipMap);
      }
      recipMap.set(recipient, snap.windows[0].evidence_audit_ids);
    }
    const priorTouched = snap.windows
      .slice(1)
      .some((w) => w.count > 0);
    if (priorTouched) {
      let set = priorBySource.get(sender);
      if (!set) {
        set = new Set();
        priorBySource.set(sender, set);
      }
      set.add(recipient);
    }
  }

  const out = new Map<string, NewPartnerInfo>();
  for (const [sender, recipMap] of currentBySource.entries()) {
    const prior = priorBySource.get(sender) ?? new Set<string>();
    if (prior.size === 0) {
      // No baseline graph at all; the new-partner classifier is not
      // meaningful yet (every partner would be "new"). Skip.
      continue;
    }
    const newPartners: string[] = [];
    const evidence: string[] = [];
    for (const [recipient, recipEvidence] of recipMap.entries()) {
      if (!prior.has(recipient)) {
        newPartners.push(recipient);
        for (const id of recipEvidence) {
          if (evidence.length < 50) evidence.push(id);
        }
      }
    }
    if (newPartners.length === 0) continue;
    newPartners.sort();
    out.set(sender, {
      partners: newPartners,
      priorPartners: [...prior].sort(),
      evidenceAuditIds: evidence,
    });
  }
  return out;
}

/**
 * Project audit entries into the canonical InterAgentEvent shape.
 * Skips entries that don't carry an extractable pair (e.g. malformed
 * details).
 */
function extractInterAgentEvents(
  entries: readonly AuditEntry[],
): InterAgentEvent[] {
  const out: InterAgentEvent[] = [];
  for (const entry of entries) {
    const op = entry.operation;
    if (op === HANDOFF_OP) {
      const details = entry.details as Record<string, unknown> | undefined;
      const sender = optionalString(details, "sender_agent_id");
      const recipient = optionalString(details, "recipient_agent_id");
      if (!sender || !recipient || sender === recipient) continue;
      out.push({
        sender,
        recipient,
        timestampMs: Date.parse(entry.timestamp),
        auditId: `${entry.timestamp}:${entry.operation}`,
      });
      continue;
    }
    if (CROSS_HARNESS_OPS.has(op)) {
      const details = entry.details as Record<string, unknown> | undefined;
      const sender =
        optionalString(details, "source_harness") ??
        optionalString(details, "source_agent_id");
      if (!sender) continue;
      out.push({
        sender,
        recipient: OPERATOR_PSEUDO_AGENT,
        timestampMs: Date.parse(entry.timestamp),
        auditId: `${entry.timestamp}:${entry.operation}`,
      });
    }
  }
  return out;
}

function optionalString(
  details: Record<string, unknown> | undefined,
  key: string,
): string | null {
  if (!details) return null;
  const value = details[key];
  if (typeof value !== "string" || value.length === 0) return null;
  return value;
}
