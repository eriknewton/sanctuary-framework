/**
 * Sanctuary v1.3 WP-V1.3-1 catalog of baseline sentinels.
 *
 * Each entry is a factory the registry calls per-fortress.
 *
 * Phi-1 ships:
 *   - egress-volume
 *
 * Phi-2 adds:
 *   - credential-usage
 *
 * Phi-3 adds:
 *   - cross-agent-chatter
 *
 * Phi-4 adds:
 *   - suspicious-tool-call
 *
 * Phi-5 will register the final entry here:
 *   - anomaly-trigger (meta-sentinel)
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
};
