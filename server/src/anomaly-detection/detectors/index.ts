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
 * Chi-4 ships:    cross-agent-timing, tool-call-sequence
 * Chi-5 ships:    audit-event-class distribution drift
 * Chi-6 ships:    credential-use-sequence, cross-agent-distribution
 * Chi-7 ships:    time-of-day-activity (time-of-day-conditioned
 *                 baselines; this PR)
 * Chi-8+ ships:   root-cause hints, etc.
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
import {
  AuditEventClassDistributionDetector,
  AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
} from "./audit-event-class-distribution-detector.js";
import {
  CredentialUseSequenceDetector,
  CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
} from "./credential-use-sequence-detector.js";
import {
  CrossAgentDistributionDetector,
  CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
} from "./cross-agent-distribution-detector.js";
import {
  TimeOfDayActivityDetector,
  TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
} from "./time-of-day-activity-detector.js";
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
  {
    detectorId: AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
    description:
      "Per-agent audit-event class distribution PSI over the operation mix, with top per-class drift attribution. Catches behavioral-mix shifts at stable event volume.",
    factory: () => new AuditEventClassDistributionDetector(),
  },
  {
    detectorId: CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
    description:
      "Per-agent credential-use sequence shape: credential-event count, distinct credentials used, repeated credential-pair score, max 5-minute burst. Catches credential enumeration and burst-dump shapes.",
    factory: () => new CredentialUseSequenceDetector(),
  },
  {
    detectorId: CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
    description:
      "Per-agent peer-relative activity z-scores plus peer count over a 24h window. Catches one agent diverging from its cohort when fortress-wide drift masks self-history baselines.",
    factory: () => new CrossAgentDistributionDetector(),
  },
  {
    detectorId: TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
    description:
      "Per-agent activity counts and proportions across four fixed six-hour UTC time-of-day bands plus active-band count over a 24h window. Catches off-hours activity shifts at constant volume that count-based baselines miss.",
    factory: () => new TimeOfDayActivityDetector(),
  },
];

export {
  PerAgentActivityDetector,
  PER_AGENT_ACTIVITY_DETECTOR_ID,
  CrossAgentTimingDetector,
  CROSS_AGENT_TIMING_DETECTOR_ID,
  ToolCallSequenceDetector,
  TOOL_CALL_SEQUENCE_DETECTOR_ID,
  AuditEventClassDistributionDetector,
  AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
  CredentialUseSequenceDetector,
  CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
  CrossAgentDistributionDetector,
  CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
  TimeOfDayActivityDetector,
  TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
};
