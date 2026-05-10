/**
 * Sanctuary v1.3 WP-V1.3-1 Phi-1 catalog of baseline sentinels.
 *
 * Each entry is a factory the registry calls per-fortress.
 *
 * Phi-1 ships:
 *   - egress-volume (this file)
 *
 * Phi-2 through Phi-5 will register additional entries here:
 *   - credential-usage (Phi-2)
 *   - cross-agent-chatter (Phi-3)
 *   - suspicious-tool-call (Phi-4)
 *   - anomaly-trigger (Phi-5; meta-sentinel)
 */

import {
  EgressVolumeWatcher,
  EGRESS_VOLUME_SENTINEL_ID,
} from "./egress-volume-watcher.js";
import {
  CrossAgentChatterWatcher,
  CROSS_AGENT_CHATTER_SENTINEL_ID,
} from "./cross-agent-chatter-watcher.js";
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
];

export {
  EgressVolumeWatcher,
  EGRESS_VOLUME_SENTINEL_ID,
  CrossAgentChatterWatcher,
  CROSS_AGENT_CHATTER_SENTINEL_ID,
};
