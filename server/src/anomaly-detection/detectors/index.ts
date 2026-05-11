/**
 * Sanctuary v1.3 WP-V1.3-2 Anomaly detector catalog.
 *
 * Forward-compat catalog of detector factories the Chi-3 operator UX
 * (CLI + dashboard) consumes. Each entry is a thin factory the
 * dispatcher calls per-fortress when the operator subscribes. Chi-3's
 * subscription surface picks up new entries here automatically; no
 * Chi-3 code change is needed when Chi-4+ adds a new detector.
 *
 * Chi-1 ships:    per-agent-activity (Chi-1 PR #189)
 * Chi-4 ships:    cross-agent-timing, tool-call-sequence (this PR)
 * Chi-5+ ships:   audit-event-class distribution drift,
 *                 credential-use sequence patterns, etc.
 *
 * Pattern mirrors Phi-1's `PHI1_BASELINE_CATALOG`. Default
 * subscription set is empty; operator opts in.
 *
 * CTO call (Chi-4 build): Chi-3 (PR #197) was assumed to land before
 * Chi-4 by the spawn prompt's "Chi-3 just landed" note, but PR #197
 * is still open at Chi-4 build time. Chi-4 ships this catalog
 * file as the forward-compat surface; if Chi-3's PR introduces an
 * incompatible catalog shape (different field names, different
 * subscription wiring), a small reconciliation commit lands during
 * Chi-3 + Chi-4 merge cascade. The two new entries here are
 * additive-only against any reasonable catalog shape.
 */

import {
  PerAgentActivityDetector,
  PER_AGENT_ACTIVITY_DETECTOR_ID,
} from "./per-agent-activity-detector.js";
import {
  CrossAgentTimingDetector,
  CROSS_AGENT_TIMING_DETECTOR_ID,
} from "./cross-agent-timing-detector.js";
import {
  ToolCallSequenceDetector,
  TOOL_CALL_SEQUENCE_DETECTOR_ID,
} from "./tool-call-sequence-detector.js";
import type { AnomalyDetector } from "../types.js";

export interface AnomalyDetectorCatalogEntry {
  detectorId: string;
  description: string;
  factory: () => AnomalyDetector;
}

export const ANOMALY_DETECTOR_CATALOG: AnomalyDetectorCatalogEntry[] = [
  {
    detectorId: PER_AGENT_ACTIVITY_DETECTOR_ID,
    description:
      "Per-agent statistical drift over a 24h rolling window. Tool-call count, egress volume, credential-use rate, audit-event count, recent-receipt count.",
    factory: () => new PerAgentActivityDetector(),
  },
  {
    detectorId: CROSS_AGENT_TIMING_DETECTOR_ID,
    description:
      "Per-agent-pair co-fire rate, inter-event time distribution, and Pearson correlation strength. Catches lockstep / co-firing patterns that per-agent baselines miss.",
    factory: () => new CrossAgentTimingDetector(),
  },
  {
    detectorId: TOOL_CALL_SEQUENCE_DETECTOR_ID,
    description:
      "Per-agent tool-call sequence shape: distinct tools used, max sequence length, 3-gram Shannon entropy, 2-gram repeat-pattern score. Catches data-exfiltration-shaped repeats.",
    factory: () => new ToolCallSequenceDetector(),
  },
];

export {
  PerAgentActivityDetector,
  PER_AGENT_ACTIVITY_DETECTOR_ID,
  CrossAgentTimingDetector,
  CROSS_AGENT_TIMING_DETECTOR_ID,
  ToolCallSequenceDetector,
  TOOL_CALL_SEQUENCE_DETECTOR_ID,
};
