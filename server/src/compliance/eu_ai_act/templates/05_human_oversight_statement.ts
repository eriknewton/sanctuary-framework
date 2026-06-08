/**
 * Sanctuary MCP Server — EU AI Act Template: Human Oversight Statement
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Document 05 of the EU AI Act Compliance Bundle.
 *
 * Covers the human oversight requirements of Article 14 and the
 * Annex IV §2(e) assessment of human oversight measures.
 */

import { HEADER_TEMPLATE, FOOTER_TEMPLATE } from "./shared.js";

export const HUMAN_OVERSIGHT_STATEMENT_TEMPLATE = `${HEADER_TEMPLATE}
## Introduction

This document is the Human Oversight Statement for the high-risk
AI system identified above, prepared in accordance with Article 14
of Regulation (EU) 2024/1689. It documents the technical substrate
Sanctuary provides for human oversight and identifies the
operational facts (operator roles, training, authority) that the
enterprise must supply.

Sanctuary's human oversight substrate is the Principal Policy gate
with its approval channel. Every operation classified as Tier 1
blocks execution until a human principal approves or denies via
the configured out-of-band channel. Every Tier 2 anomaly triggers
the same approval path when baseline deviation is detected. Tier 3
operations proceed automatically but are captured in the audit log
for after-the-fact human review.

**Important scope note:** Sanctuary's intervention model is
**pre-execution gating**, not mid-stream interruption. An approval
denial halts the next tool call before it executes; it does not
kill an in-flight LLM stream or subprocess. Whether this model
satisfies Article 14(4)(e) ("intervene on the operation [...] or
interrupt the system through a 'stop' button or similar procedure
that allows the system to come to a halt in a safe state") is an
operational judgement the enterprise must make for the specific
deployment. The Sanctuary claim is: pre-execution gating provides
a safe-state halt before the next consequential action; mid-stream
interruption requires additional controls outside Sanctuary.

---

## Principal Policy Configuration (Auto-Filled)

| Field | Value |
|---|---|
| Approval channel type | \`{{ approval_channel_type }}\` |
| Approval channel timeout | {{ approval_channel_timeout_seconds }} seconds |
| On timeout | **deny** (SEC-002: \`auto_deny\` removed — timeout always denies) |
| Tier 1 rule count (always require approval) | {{ tier1_rule_count }} |
| Tier 2 anomaly rules | new_namespace_access: \`{{ tier2_new_namespace_access }}\`, new_counterparty: \`{{ tier2_new_counterparty }}\`, frequency_spike_multiplier: {{ tier2_frequency_spike_multiplier }}, first_session_policy: \`{{ tier2_first_session_policy }}\` |
| Tier 3 auto-allow tool count | {{ tier3_rule_count }} |
| Baseline tracker state | \`{{ baseline_tracker_state }}\` |

The full Principal Policy is machine-readable via
\`principal_policy_view\`. The baseline tracker state is exposed via
\`principal_baseline_view\`. Both tools are read-only and classified
Tier 1 (always require out-of-band operator approval): the agent
cannot read the policy or its baseline without an explicit human
approval, so an auditor invokes them through the approval channel
against a live Sanctuary instance to independently verify every
value above.

---

## Reporting Period Oversight Activity (Auto-Filled)

During the reporting period **{{ period_start }} → {{ period_end }}**,
the Sanctuary oversight gate recorded the following activity:

| Outcome | Count |
|---|---|
| Gate allow (Tier 3 auto-allow or approved Tier 1/2) | {{ gate_allow_count }} |
| Gate allow_proxy (Sanctuary MCP-proxy pass-through) | {{ gate_allow_proxy_count }} |
| Gate deny (approval denied or timeout) | {{ gate_deny_count }} |
| Gate escalate (Tier 2 anomaly raised for human review) | {{ gate_escalate_count }} |
| Gate unclassified (no matching rule, default behaviour applied) | {{ gate_unclassified_count }} |
| Injection-detection events | {{ injection_detected_count }} |

Individual entries are queryable via \`monitor_audit_log\` with
\`layer: "l2"\` filter and exportable in SIEM-compatible format via
\`audit_export_siem\`.

---

## Article 14 and Annex IV §2(e) Row Coverage

{{ rows_rendered }}

---

## Enterprise-Supplied Oversight Facts

The following human-oversight facts are the enterprise's
responsibility and are not emitted by Sanctuary. They must be
filled in before this document is used for regulatory submission:

- **Identity of assigned overseers:** who are the natural persons
  with Article 14 oversight authority for this deployment?
- **Competence and training:** what training have they received,
  and how is their competence assessed?
- **Authority scope:** what is the written authority of each
  overseer — can they halt the system, override outputs, reverse
  decisions?
- **Automation-bias mitigation:** what training, interface
  design, or process measures address automation bias per Article
  14(4)(b)?
- **Stop-button workflow mapping:** how does the Sanctuary approval
  channel integrate with the enterprise's operational stop-button
  procedure?
- **Output interpretation support:** what tools, dashboards, or
  reference materials support the overseers in correctly
  interpreting the agent's outputs per Article 14(4)(c)?
- **Escalation procedure:** when does an overseer escalate to a
  different authority (security, legal, C-suite)?

${FOOTER_TEMPLATE}`;
