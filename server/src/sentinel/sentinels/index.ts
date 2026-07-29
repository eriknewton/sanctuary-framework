/**
 * Sanctuary v1.3 sentinel catalog.
 *
 * Each entry is a factory the registry calls per-fortress.
 *
 * Phi-1: egress-volume (first-order, audit-log based)
 * Phi-2: credential-usage (first-order, audit-log based)
 * Phi-3: cross-agent-chatter (first-order, audit-log based)
 * Phi-4: suspicious-tool-call (first-order, audit-log based)
 * Phi-5: anomaly-trigger (meta-sentinel, finding-store based)
 * Phi-6: ebpf-syscall-watcher (kernel observation, Linux only)
 * Phi-7: auditd-tail-watcher (cross-platform audit log observation)
 */

import {
  EgressVolumeWatcher,
  EGRESS_VOLUME_SENTINEL_ID,
} from "./egress-volume-watcher.js";
import {
  CrossAgentChatterWatcher,
  CROSS_AGENT_CHATTER_SENTINEL_ID,
} from "./cross-agent-chatter-watcher.js";
import {
  CredentialUsageWatcher,
  CREDENTIAL_USAGE_SENTINEL_ID,
} from "./credential-usage-watcher.js";
import {
  SuspiciousToolCallDetector,
  SUSPICIOUS_TOOL_CALL_SENTINEL_ID,
} from "./suspicious-tool-call-detector.js";
import {
  AnomalyTriggerWatcher,
  ANOMALY_TRIGGER_SENTINEL_ID,
} from "./anomaly-trigger.js";
import {
  EbpfSyscallWatcher,
  EBPF_SYSCALL_SENTINEL_ID,
} from "./ebpf-syscall-watcher.js";
import {
  AuditdTailWatcher,
  AUDITD_TAIL_SENTINEL_ID,
} from "./auditd-tail-watcher.js";
import {
  AgentEgressWatcher,
  AGENT_EGRESS_SENTINEL_ID,
} from "./agent-egress-watcher.js";
import type { SentinelCatalogEntry } from "../sentinel-registry.js";

export const PHI1_BASELINE_CATALOG: SentinelCatalogEntry[] = [
  {
    sentinelId: EGRESS_VOLUME_SENTINEL_ID,
    description:
      "Watches outbound proxy-call volume per upstream server and surfaces anomalous spikes against a rolling 7-day baseline.",
    factory: () => new EgressVolumeWatcher(),
  },
  {
    sentinelId: CROSS_AGENT_CHATTER_SENTINEL_ID,
    description:
      "Watches inter-agent communication patterns. Surfaces per-pair rate spikes (3 or 6 sigma over the rolling 7-day baseline) and new-partner appearances. Escalates to alert when one source agent picks up 3 or more new partners in 24h.",
    factory: () => new CrossAgentChatterWatcher(),
  },
  {
    sentinelId: CREDENTIAL_USAGE_SENTINEL_ID,
    description:
      "Watches per-agent credential reads. Surfaces (agent, secret) usage that exceeds a rolling 7-day baseline, and unfamiliar secret combinations the agent uses for the first time in one 24h window.",
    factory: () => new CredentialUsageWatcher(),
  },
  {
    sentinelId: SUSPICIOUS_TOOL_CALL_SENTINEL_ID,
    description:
      "Surfaces tool calls whose argument shape, call frequency, or permission combination looks unusual for the fortress's recent history.",
    factory: () => new SuspiciousToolCallDetector(),
  },
  {
    sentinelId: ANOMALY_TRIGGER_SENTINEL_ID,
    description:
      "Meta-sentinel. Watches for patterns ACROSS other sentinels' findings: compound suspicious behavior on one agent, fortress-wide finding-count spikes, and novel cross-sentinel combinations. Closes WP-V1.3-1 Sentinel Baseline Pack.",
    factory: () => new AnomalyTriggerWatcher(),
  },
  {
    sentinelId: EBPF_SYSCALL_SENTINEL_ID,
    description:
      "Observes process spawn, file access, and unfiltered outbound connect syscalls via eBPF (Linux only). Stub mode on non-Linux platforms.",
    factory: () => new EbpfSyscallWatcher(),
  },
  {
    sentinelId: AUDITD_TAIL_SENTINEL_ID,
    description:
      "Tails platform audit log as cross-platform fallback for kernel observation when eBPF is unavailable.",
    factory: () => new AuditdTailWatcher(),
  },
  {
    sentinelId: AGENT_EGRESS_SENTINEL_ID,
    description:
      "Watches the confined agent's default-deny egress denials and the periodic as-agent-uid endpoint probe; " +
      "alerts on a sustained deny burst to one host or a failed provisioned-endpoint probe (a silently degraded agent).",
    factory: () => new AgentEgressWatcher(),
  },
];

export {
  EgressVolumeWatcher,
  EGRESS_VOLUME_SENTINEL_ID,
  CrossAgentChatterWatcher,
  CROSS_AGENT_CHATTER_SENTINEL_ID,
  CredentialUsageWatcher,
  CREDENTIAL_USAGE_SENTINEL_ID,
  SuspiciousToolCallDetector,
  SUSPICIOUS_TOOL_CALL_SENTINEL_ID,
  AnomalyTriggerWatcher,
  ANOMALY_TRIGGER_SENTINEL_ID,
  EbpfSyscallWatcher,
  EBPF_SYSCALL_SENTINEL_ID,
  AuditdTailWatcher,
  AUDITD_TAIL_SENTINEL_ID,
  AgentEgressWatcher,
  AGENT_EGRESS_SENTINEL_ID,
};
