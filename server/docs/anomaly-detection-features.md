# Anomaly Detection Feature Vectors

## Overview

Sanctuary anomaly detection is the Castle Layer 2 Sentinel subsystem for server-local statistical drift detection. It observes existing audit-log activity, projects it into numeric feature vectors, scores those vectors against per-fortress classifier state, and emits anomaly findings into the same finding store and operator inbox path used by rule-based Sentinels.

It is not a real-time enforcement gate. The anomaly dispatcher does not block a tool call while it is happening. It runs on its own tick, persists classifier state, records audit events, and emits findings for operator review and downstream auto-trigger routing. Enforcement remains owned by the policy gate, approval channel, and auto-trigger ladder.

Operator control is split across the `sanctuary anomaly` CLI and the HTTP routes under `/api/anomaly/*`. The source exposes catalog inspection, subscribe and unsubscribe, finding list and detail, and classifier-state inspection. Source note: the prompt refers to dashboard configuration knobs; current source provides the authenticated HTTP surface for that dashboard integration, but the v1.1 dashboard client does not currently contain a dedicated anomaly configuration panel.

## The `FeatureVector` Type

The canonical type is defined in `server/src/anomaly-detection/types.ts`:

```ts
export interface FeatureVector {
  agent_id: string;
  observed_at: string;
  features: Record<string, number>;
  window_label: string;
}
```

`features` is numeric-only by Chi-1 design. Every feature is keyed by a stable string identifier and maps to a finite number. The numeric-only shape keeps the trainable surface small, compatible with the Chi-1 rolling baseline, and composable with Chi-2 classifiers such as CUSUM and PSI through the same classifier interface.

Feature names are detector-local, stable strings. Current examples include:

| Detector | Feature names |
| --- | --- |
| `per-agent-activity` | `tool_call_count`, `egress_call_count`, `credential_use_count`, `audit_event_count`, `recent_receipt_count` |
| `cross-agent-timing` | `co_fire_rate_24h`, `inter_event_time_p50_ms`, `inter_event_time_p99_ms`, `correlation_strength` |
| `tool-call-sequence` | `distinct_tools_used`, `max_sequence_length`, `ngram_3_histogram_entropy`, `repeat_pattern_score` |
| `audit-event-class-distribution` | `total_events`, `class_count:<audit-operation>`, `class_proportion:<audit-operation>` |
| `credential-use-sequence` | `credential_event_count`, `distinct_credentials_used`, `repeat_pair_score`, `burst_max_5min` |
| `cross-agent-distribution` | `peer_z:<activity-feature>`, `peer_count` |
| `time-of-day-activity` | `band_count:<band>`, `band_proportion:<band>`, `active_band_count` |

Reserved namespaces are detector-owned. `audit-event-class-distribution` owns `class_count:*` and `class_proportion:*`; `cross-agent-distribution` owns `peer_z:*`; `time-of-day-activity` owns `band_count:*` and `band_proportion:*`; other detectors currently use unprefixed fixed feature names. New detectors should avoid reusing another detector's prefixed namespace unless they intentionally share feature semantics.

`agent_id` is the classifier bucket. Most detectors use an audit-log `identity_id`; blank identities fall into the synthetic `system` bucket. `cross-agent-timing` uses a canonical unordered pair key, `<agent-a>|<agent-b>`. `observed_at` is an ISO timestamp for the vector observation. `window_label` is a diagnostic label such as `24h_rolling` or `5min_sliding`.

## Detector Catalog

There are two useful meanings of "catalog" in the current source:

1. The operator-facing `ANOMALY_CATALOG` in `server/src/anomaly-detection/anomaly-catalog.ts`.
2. The shipped detector classes under `server/src/anomaly-detection/detectors/`.

Source note: `ANOMALY_CATALOG` now registers all seven shipped detectors, including the alternative CUSUM and PSI classifier tuples for `per-agent-activity`. An earlier revision of this note predated the Chi-4 through Chi-7 catalog registrations.

| Detector | Feature space | Primary classifier id | Defaults | Detects | Finding shape |
| --- | --- | --- | --- | --- | --- |
| `per-agent-activity` | 24-hour per-agent counts for tool calls, proxy egress, credential use, audit events, and receipt/reputation activity | `rolling-baseline` | Minimum 7 observations before prediction. Severity mapping: score `<1` no finding, `1..3` info, `3..6` warn, `>=6` alert. | Point drift in an agent's activity volume or mix. | `sentinel_id` is `anomaly:per-agent-activity`; details include `detector_id`, `classifier_id`, `anomaly_score`, `window_label`, `observed_features`, `feature_contributions`, and `explanation`. |
| `cross-agent-timing` | 24-hour unordered agent-pair timing features: co-fire count within 60s, p50 and p99 inter-event time, Pearson correlation over 5-minute buckets | `rolling-baseline` | Same rolling-baseline defaults when constructed without an explicit classifier. | Agent pairs that begin firing together, stop correlating, or show unusual timing distribution. | Same standard anomaly finding shape, with `agent_id` set to the pair key. |
| `tool-call-sequence` | 5-minute per-agent sequence features for proxy tool calls: distinct tools, sequence length, 3-gram entropy, repeated 2-gram score | `rolling-baseline` | Same rolling-baseline defaults when constructed without an explicit classifier. | Unusual tool ordering, repeated call pairs, or entropy shifts that count-based detectors miss. | Same standard anomaly finding shape. |
| `audit-event-class-distribution` | 24-hour per-agent audit-operation distribution: total events plus per-operation class counts and proportions | `audit-event-class-distribution:psi` | PSI threshold `0.25`; baseline sample count `7`; 7-day prior-window priming when history exists. | Categorical distribution shift in the audit operation mix. | `sentinel_id` is `anomaly:audit-event-class-distribution`; details also include `psi_score`, `psi_threshold`, `baseline_class_proportions`, `current_class_proportions`, and `per_class_drift`. |
| `credential-use-sequence` | 24-hour per-agent credential-consumption shape: broker credential-event count, distinct credentials used, repeated credential-pair score, max events in any 5-minute bucket | `rolling-baseline` | Same rolling-baseline defaults when constructed without an explicit classifier. Agent attribution prefers `details.agent`, then `identity_id`, then the `system` bucket; the credential token prefers `details.secret`, falling back to the operation name. | Credential enumeration breadth, hammered credential pairs, and burst-dump shapes that total counts miss. | Same standard anomaly finding shape. |
| `cross-agent-distribution` | 24-hour per-agent activity features re-expressed as z-scores against the peer cohort in the same window (stddev floor `0.5`), plus peer count | `rolling-baseline` | Same rolling-baseline defaults when constructed without an explicit classifier. Vectors emit only when two or more agents are observed (at least one peer). | One agent diverging from its peers even when fortress-wide drift masks self-history baselines. | Same standard anomaly finding shape. |
| `time-of-day-activity` | 24-hour per-agent audit-event counts and proportions across four fixed six-hour UTC bands (`night` 00-06, `morning` 06-12, `afternoon` 12-18, `evening` 18-24), plus active-band count | `rolling-baseline` | Same rolling-baseline defaults when constructed without an explicit classifier. The 24h window equals one full day, so each band's count covers exactly its six hours. Bands are fixed UTC intervals (deterministic conditioning, not operator-local time). Agent attribution mirrors Chi-1: `identity_id`, else the `system` bucket; zero-activity agents emit no vector. | An agent shifting WHEN it acts (off-hours activity, diurnal-shape change) even at stable volume and operation mix, which count-based baselines cannot see. | Same standard anomaly finding shape. |

Shipped classifiers:

| Classifier | ID | Defaults | Detection mode |
| --- | --- | --- | --- |
| Rolling baseline | `rolling-baseline` | Minimum 7 observations; stddev floor `0.5` | Per-feature running mean and variance with an aggregate z-score. |
| CUSUM | `cusum` | Minimum 7 observations; `k = 0.5`; `h = 5`; stddev floor `0.5` | Persistent upward or downward mean shift accumulated across samples. |
| PSI | `psi` | 30 training samples; current-window min 10; current-window max 100; 10 bins | Per-feature distribution shape shift. PSI `<0.1` maps to no finding, `0.1` maps to warn score 3, `0.25` maps to alert score 6. |
| Audit-event categorical PSI | `audit-event-class-distribution:psi` | PSI threshold `0.25`; baseline sample count 7 | Whole categorical audit-operation mix shift with per-class attribution. |

The standard alert summary format is:

```text
<detector-id>/<classifier-id> <severity>: agent <agent-id> drifted <score> sigma from baseline. Top contributors: <explanations>.
```

The audit-event distribution detector uses a detector-specific summary that includes the raw PSI score and top class drift.

## Classifier ID Namespace

Generic classifiers use plain classifier IDs: `rolling-baseline`, `cusum`, and `psi`. Detector-local classifiers use `<detector-id>:<classifier-name>`, for example `audit-event-class-distribution:psi`.

That convention avoids collisions in the encrypted classifier-state store. State is keyed by classifier ID and agent ID inside the `_anomaly_classifier_state` namespace. A detector-local classifier that needs detector-specific state semantics should not reuse a generic ID, because generic `psi` and categorical distribution PSI do not persist the same state shape.

The current source also uses classifier IDs in finding details and audit records, so stable IDs are part of the operator-visible contract. The IDs are storage-key-safe because they are bounded ASCII identifiers containing letters, digits, hyphens, and colons; they are passed through the storage abstraction as logical keys rather than interpolated into shell commands.

## Baseline Priming And Online Warmup

All classifiers follow the predict-then-observe invariant. A detector scores a vector against the current baseline before deciding whether to absorb it. Warmup samples are observed until `baseline_ready` becomes `true`. In-baseline samples are absorbed. Drift samples emit findings and are not absorbed into the classifier that fired, preventing the outlier from immediately contaminating its own baseline.

`baseline_ready` is returned on every `AnomalyPrediction`. It is `false` while a classifier has insufficient state for meaningful scoring. Rolling baseline and CUSUM require 7 prior observations by default. Generic PSI requires locked training bins and at least 10 current-window samples. Audit-event categorical PSI requires either a seeded baseline or 7 online baseline samples.

Chi-5 adds prior-window priming for `audit-event-class-distribution`. Before scoring an agent, the detector queries a 7-day baseline window ending one current detection window before `now`. When matching historical audit events exist, it seeds baseline proportions from that prior window. Sparse deployments fall back to online warmup through `observe()`.

## Drift Attribution

Standard classifiers return `feature_contributions`:

```ts
{
  feature_name: string;
  observed: number;
  baseline_mean: number;
  baseline_stddev: number;
  z_score: number;
}
```

The rolling baseline and CUSUM sort contributions by absolute z-score. Generic PSI includes a diagnostic z-score against an estimated training mean and stddev, while `explanation` carries the PSI bucket attribution.

The audit-event class distribution detector also emits `per_class_drift` entries:

```ts
{
  class_name: string;
  baseline_proportion: number;
  current_proportion: number;
  absolute_delta: number;
  relative_delta: number | null;
  direction: "up" | "down" | "flat";
  psi_contribution: number;
}
```

The top three classes are rendered into the alert summary and explanation. Source note: the prompt's example names `before_proportion`, `after_proportion`, and `percent_change`; the current source uses `baseline_proportion`, `current_proportion`, and `relative_delta`.

## Root-Cause Hints

Chi-8 adds an operator-facing root-cause hint layer on top of the existing drift attribution. When the dispatcher routes a finding, it attaches a `root_cause_hints` array into the finding details:

```ts
{
  feature_names: string[];
  direction: "above_baseline" | "below_baseline";
  z_score: number | null;
  likely_cause: string;
  source: "detector" | "generic";
}
```

Hints are a pure, deterministic function of attribution the finding already carries: `detector_id`, `feature_contributions`, and, for `audit-event-class-distribution`, `per_class_drift`. The implementation is `server/src/anomaly-detection/root-cause-hints.ts`; the single wiring seam is `routeFinding` in `server/src/anomaly-detection/anomaly-pipeline.ts`, so every detector, including ones with custom `evaluate()` overrides, gets hints without per-detector changes.

Selection and direction rules:

- A contribution earns a hint when its absolute z-score is at least 1, matching the severity floor in `severityFromAnomalyScore`. Positive z-scores map to `above_baseline`, negative to `below_baseline`.
- Hints are sorted highest absolute z-score first, then by feature name, and capped at 5 per finding.
- `per_class_drift` entries produce up to 3 additional class hints (top absolute proportion delta, `flat` entries skipped, `z_score` null because the attribution is delta-based). The mirrored `class_proportion:*` contributions are skipped to avoid double-hinting.
- All seven shipped detectors have detector-specific hint text keyed off their real emitted feature names, including the prefixed namespaces (`band_count:*`, `band_proportion:*`, `peer_z:*`, `class_count:*`, `class_proportion:*`). Examples: a `distinct_credentials_used` spike on `credential-use-sequence` reads as the credential-enumeration shape; a `band_proportion:night` spike on `time-of-day-activity` reads as off-hours activity; a `co_fire_rate_24h` spike on `cross-agent-timing` reads as lockstep coordination.
- Unknown detector ids and unknown feature names degrade to a generic hint built only from the contribution stats (feature name, observed value, baseline mean, sigma). Malformed or missing attribution degrades to an empty array. Hint generation never throws into the dispatcher.

Degradation and sovereignty posture:

- Fail-closed wiring: `enrichDetailsWithRootCauseHints` wraps hint generation so a thrown error degrades to an empty hints array, and a details copy failure degrades to the original details unchanged. The finding itself is the security signal and always survives.
- Hints are built only from numeric contribution stats, feature names, audit-operation class names, and detector ids. No raw audit payloads, secrets, or key material can reach a hint.
- Data-dependent names are sanitized at the parse boundary before they reach hint text or `feature_names`: audit operation names can be composed from runtime strings (tool names, for example), so characters outside a small safe charset are replaced with `_` and names are capped at 100 characters. Legitimate detector feature keys pass through unchanged. This keeps hint text from becoming a control-character, ANSI-escape, or unbounded-payload injection channel into the dashboard and CLI.
- No classifier, scoring, severity, or persisted classifier-state change. The layer annotates finding details at routing time only.

## Audit Event Shape

Anomaly audit events are appended with layer `l2` and `identity_id` set to the dispatcher or route dependency identity. The anomaly subsystem emits the following operation names.

| Operation | Status | Details schema |
| --- | --- | --- |
| `anomaly_detector_registered` | default | `{ detector_id: string, fortress_id: string }` |
| `anomaly_detector_unregistered` | default | `{ detector_id: string, fortress_id: string }` |
| `anomaly_finding_emitted` | default | `{ detector_id: string, finding_id: string, severity: "info" | "warn" | "alert", anomaly_score: number | null, classifier_id?: string, agent_id?: string, fortress_id: string }` |
| `anomaly_evaluation_failed` | failure | `{ detector_id: string, error_message: string, fortress_id: string }` |
| `anomaly_training_completed` | default | `{ detector_id: string, classifier_id: string, trained_at: string, sample_count: number, agent_count: number, fortress_id: string }` |
| `anomaly_training_failed` | failure | `{ detector_id: string, classifier_id: string, error_message: string, fortress_id: string }` |
| `anomaly_classifier_subscribed` | default | `{ detector_id: string, classifier_id: string, fortress_id: string }` |
| `anomaly_classifier_unsubscribed` | default | `{ detector_id: string, classifier_id: string, fortress_id: string }` |
| `anomaly_cusum_drift_detected` | default | `{ detector_id: string, finding_id: string, severity: "info" | "warn" | "alert", anomaly_score: number | null, agent_id?: string, fortress_id: string }` |
| `anomaly_psi_distribution_shift_detected` | default | `{ detector_id: string, finding_id: string, severity: "info" | "warn" | "alert", anomaly_score: number | null, agent_id?: string, fortress_id: string }` |
| `operator_anomaly_view_opened` | default | `{ fortress_id: string, opened_at: string }` |
| `operator_anomaly_finding_drilled` | default | `{ finding_id: string, detector_id: string | null, classifier_id: string | null, severity: "info" | "warn" | "alert", fortress_id: string }` |

Source note: the prompt mentioned `anomaly_alert_emitted`, `anomaly_threshold_updated`, and `anomaly_classifier_attached`. Those exact operation names are not emitted by the anomaly subsystem on this branch. The source emits `anomaly_finding_emitted`, `anomaly_classifier_subscribed`, and `anomaly_classifier_unsubscribed`.

## Operator Configuration Surface

CLI entry point: `sanctuary anomaly`.

| Command | Behavior |
| --- | --- |
| `sanctuary anomaly detectors list` | Prints `ANOMALY_CATALOG` detector and classifier tuples. |
| `sanctuary anomaly list-subscribed` | Reads `<storage>/anomaly-subscriptions.json`. |
| `sanctuary anomaly subscribe <detector-id> --classifier <id>` | Adds a catalog tuple to the subscription file. |
| `sanctuary anomaly unsubscribe <detector-id> --classifier <id>` | Removes a tuple from the subscription file. |
| `sanctuary anomaly findings [--since <iso>] [--severity <info|warn|alert>] [--detector-id <id>] [--agent-id <id>] [--limit <n>]` | Lists anomaly findings from the encrypted sentinel finding store. |
| `sanctuary anomaly findings show <finding-id>` | Prints the full anomaly finding JSON. |
| `sanctuary anomaly classifier-state <detector-id> --classifier <id>` | Lists per-agent classifier state for a catalog tuple. |

HTTP routes are mounted under `/api/anomaly` and use the shared console auth middleware.

| Route | Behavior |
| --- | --- |
| `GET /api/anomaly/detectors` | Returns `{ catalog: [{ detector_id, classifier_id, description }] }` and emits `operator_anomaly_view_opened`. |
| `GET /api/anomaly/subscribed` | Returns the dispatcher's active detector IDs. |
| `POST /api/anomaly/:detector_id/subscribe?classifier=<id>` | Registers the catalog detector in the running dispatcher. |
| `DELETE /api/anomaly/:detector_id/subscribe?classifier=<id>` | Unregisters the detector from the running dispatcher. |
| `GET /api/anomaly/findings` | Lists anomaly findings with `limit`, `since`, `severity`, `detector_id`, and `agent_id` filters. |
| `GET /api/anomaly/findings/:finding_id` | Returns one anomaly finding and emits `operator_anomaly_finding_drilled`. |
| `GET /api/anomaly/classifier-state?detector_id=<id>&classifier_id=<id>` | Returns per-agent classifier sample counts for a catalog tuple. |

There is no anomaly-specific threshold update route in `server/src/anomaly-detection/anomaly-routes.ts`. Auto-trigger thresholds for anomaly findings live in the separate auto-trigger subsystem, whose anomaly rule ID format is `anomaly__<detector-id>__<classifier-id>`.

## Castle-Walking Properties

The anomaly subsystem preserves the operator-sovereign posture:

| Property | Current behavior |
| --- | --- |
| Pure server-local observation | Feature extractors read the local audit log through `AnomalyContext.auditLog`. |
| No outbound network | Detectors and classifiers do not call external services. |
| No LLM inference | Classifiers are deterministic statistical code. The substrate selector is not exercised. |
| No new runtime dependency | The subsystem uses existing TypeScript code, audit log, storage, finding store, and crypto primitives. |
| Per-fortress state | `ClassifierStateStore` derives storage keys from the fortress master key and stores state under `_anomaly_classifier_state`. |
| Unified operator surface | Findings are `SentinelFinding` shaped and use `sentinel_id` prefix `anomaly:` so inbox and auto-trigger consumers can distinguish anomaly findings without parallel infrastructure. |

These constraints matter because anomaly detection inspects sensitive operational behavior. Keeping extraction, state, scoring, and findings local prevents a monitoring subsystem from becoming an exfiltration or centralized telemetry path.

## Extension Points For Chi-9+

Chi-8 landed root-cause hints (named in the detector catalog's forward list since Chi-7): the dispatcher enriches finding details with `root_cause_hints` built from existing `feature_contributions` and `per_class_drift`, so no detector, classifier, or state-shape change was needed. Chi-7 landed time-of-day-conditioned baselines (the `time-of-day-activity` detector, named in the forward list since Chi-6): per-band features make the generic rolling baseline learn a separate mean and variance per six-hour UTC band per agent, so no classifier change was needed. Chi-6 landed cross-agent distribution comparison (`cross-agent-distribution`) and credential-use sequence patterns (`credential-use-sequence`, named in the forward list since Chi-4). Future detectors can add feature extractors and detector classes without changing `FeatureVector` as long as their feature payload stays numeric; new detectors that want detector-specific hint text add entries to the hint tables in `root-cause-hints.ts`, and detectors without entries degrade to generic stat-only hints automatically. Detector-local classifiers should use the `<detector-id>:<classifier-name>` namespace when their persisted state shape differs from a generic classifier.

## Source Verification Notes

This document was verified against:

- `server/src/anomaly-detection/types.ts`
- `server/src/anomaly-detection/detectors/*.ts`
- `server/src/anomaly-detection/feature-extractors/*.ts`
- `server/src/anomaly-detection/classifiers/*.ts`
- `server/src/anomaly-detection/anomaly-catalog.ts`
- `server/src/anomaly-detection/anomaly-routes.ts`
- `server/src/anomaly-detection/anomaly-pipeline.ts`
- `server/src/cli/anomaly.ts`

Declared prompt deviations:

- The prompt path `server/src/anomaly-detection/cli/anomaly.ts` does not exist; the CLI implementation is `server/src/cli/anomaly.ts`.
- The source emits `anomaly_finding_emitted`, not `anomaly_alert_emitted`.
- The source does not emit `anomaly_threshold_updated` from the anomaly subsystem.
- The source uses `anomaly_classifier_subscribed` and `anomaly_classifier_unsubscribed`, not `anomaly_classifier_attached`.
- The operator-facing anomaly catalog currently lists only `per-agent-activity` plus `rolling-baseline`, although additional detectors and classifiers are present in source.
- The current v1.1 dashboard client does not expose a dedicated anomaly configuration panel; the authenticated HTTP routes provide the server-side surface.
