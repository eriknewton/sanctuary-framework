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
import type { SentinelCatalogEntry } from "../sentinel-registry.js";

export const PHI1_BASELINE_CATALOG: SentinelCatalogEntry[] = [
  {
    sentinelId: EGRESS_VOLUME_SENTINEL_ID,
    description:
      "Watches outbound proxy-call volume per upstream server and surfaces anomalous spikes against a rolling 7-day baseline.",
    factory: () => new EgressVolumeWatcher(),
  },
];

export { EgressVolumeWatcher, EGRESS_VOLUME_SENTINEL_ID };
