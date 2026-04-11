/**
 * Sanctuary MCP Server — EU AI Act Template: Article 26 Deployer Log
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Document 02 of the EU AI Act Compliance Bundle.
 *
 * Covers the deployer obligations under Article 26 of Regulation
 * (EU) 2024/1689: use in accordance with instructions, human
 * oversight assignment, input data relevance, operation monitoring,
 * log retention, worker notification, DPIA, and EU database
 * registration.
 */

import { HEADER_TEMPLATE, FOOTER_TEMPLATE } from "./shared.js";

export const ARTICLE_26_DEPLOYER_LOG_TEMPLATE = `${HEADER_TEMPLATE}
## Introduction

This document is the Article 26 Deployer Log for the high-risk AI
system identified above, prepared in accordance with the deployer
obligations of Article 26 of Regulation (EU) 2024/1689.

Unlike the Annex IV Technical Documentation (which is authored by
the **provider**), this document is authored by the **deployer** —
the natural or legal person using the high-risk AI system under its
authority. In many enterprise deployments the provider and deployer
are the same legal entity; in others they are distinct. The
\`{{ provider_legal_name }}\` field in the header identifies the
entity acting as deployer for the purposes of this document.

The document maps each Article 26 obligation to the evidence that
the Sanctuary Framework auto-emits, and identifies the operational
and governance facts that only the deployer can supply.

---

## Deployer Operation Summary

During the reporting period **{{ period_start }} → {{ period_end }}**,
the Sanctuary Framework runtime for this agent recorded the
following aggregate operation metrics. These are auto-filled from
the encrypted audit log via \`monitor_audit_log\` and
\`audit_export_siem\`:

| Metric | Value |
|---|---|
| Total audit entries | {{ audit_total_entries }} |
| L1 (Cognitive) entries | {{ audit_l1_count }} |
| L2 (Operational) entries | {{ audit_l2_count }} |
| L3 (Disclosure) entries | {{ audit_l3_count }} |
| L4 (Reputation) entries | {{ audit_l4_count }} |
| Gate decisions — allow | {{ gate_allow_count }} |
| Gate decisions — allow_proxy | {{ gate_allow_proxy_count }} |
| Gate decisions — deny | {{ gate_deny_count }} |
| Gate decisions — escalate | {{ gate_escalate_count }} |
| Gate decisions — unclassified | {{ gate_unclassified_count }} |
| Injection-detection events | {{ injection_detected_count }} |
| Unique identities involved | {{ unique_identity_count }} |
| Unique operation types | {{ unique_operation_count }} |

Detailed event data is available in the companion file
\`03_article_12_automatic_logs.md\` and its associated SIEM export.

---

## Article 26 Obligations — Row-by-Row

{{ rows_rendered }}

${FOOTER_TEMPLATE}`;
