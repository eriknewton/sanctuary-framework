/**
 * Sanctuary MCP Server — EU AI Act Template: Article 12 Automatic Logs
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Document 03 of the EU AI Act Compliance Bundle.
 *
 * Covers Article 12 automatic record-keeping requirements: logging
 * capability over lifetime, post-market monitoring support, risk
 * management support, required log content for Annex III §1(a)
 * systems, and Article 19(1) log retention.
 *
 * This document is Markdown narrative paired with structured SIEM
 * export data. The raw CEF/OCSF payload is emitted as a separate
 * file in the bundle; this document summarises and contextualises
 * it for compliance review.
 */

import { HEADER_TEMPLATE, FOOTER_TEMPLATE } from "./shared.js";

export const ARTICLE_12_AUTOMATIC_LOGS_TEMPLATE = `${HEADER_TEMPLATE}
## Introduction

This document is the Article 12 Automatic Record-Keeping narrative
for the high-risk AI system identified above, prepared in
accordance with Article 12 and Article 19(1) of Regulation (EU)
2024/1689.

The Sanctuary Framework provides structural automatic logging via
its Principal Policy gate, which intercepts every MCP tool call
before execution and appends an authenticated entry to the L2
audit log. No code path exists to bypass this logging. The full
implementation is described below; the raw audit export in
SIEM-compatible format accompanies this document as a separate
file.

---

## Logging Architecture Summary (Auto-Filled)

Sanctuary's Article 12 implementation has the following structural
properties, each independently verifiable against the v{{ sanctuary_version }}
source:

| Property | Mechanism | Verifiable via |
|---|---|---|
| Automatic capture on every tool call | \`router.ts\` wraps all tool invocations through \`ApprovalGate.evaluate()\`; the gate appends an audit entry on every outcome path (\`gate_allow\`, \`gate_allow_proxy\`, \`gate_deny\`, \`gate_escalate\`, \`gate_unclassified\`, \`injection_detected\`) | Source: \`server/src/router.ts\`, \`server/src/principal-policy/gate.ts\` |
| Append-only API | The \`AuditLog\` class exposes only \`append()\` and read methods (\`query()\`, \`size\`). No update or delete method is exposed. | Source: \`server/src/operational/audit-log.ts\` |
| Confidentiality at rest | AES-256-GCM authenticated encryption with an HKDF-derived per-purpose key (\`audit-log\` purpose string) | Source: \`server/src/core/encryption.ts\`, \`server/src/core/key-derivation.ts\` |
| SIEM-compatible export | CEF (Common Event Format, newline-delimited) and OCSF (Open Cybersecurity Schema Framework, JSON array) emitted by the \`audit_export_siem\` tool | Run: \`audit_export_siem\` with \`format: "cef"\` or \`format: "ocsf"\` |
| Gate decision taxonomy | Every entry carries a structured operation string prefixed with \`gate_*\` or \`injection_detected:\`, directly filterable via the \`filter_decision\` and \`operation_type\` parameters | Run: \`audit_export_siem\` with \`filter_decision\` set |

---

## Reporting Period Summary (Auto-Filled)

| Field | Value |
|---|---|
| Period start | {{ period_start }} |
| Period end | {{ period_end }} |
| Total entries captured | {{ audit_total_entries }} |
| L1 entries | {{ audit_l1_count }} |
| L2 entries | {{ audit_l2_count }} |
| L3 entries | {{ audit_l3_count }} |
| L4 entries | {{ audit_l4_count }} |
| Gate allow | {{ gate_allow_count }} |
| Gate allow_proxy | {{ gate_allow_proxy_count }} |
| Gate deny | {{ gate_deny_count }} |
| Gate escalate | {{ gate_escalate_count }} |
| Gate unclassified | {{ gate_unclassified_count }} |
| Injection-detection events | {{ injection_detected_count }} |

**Full SIEM export:** see the accompanying file
\`03_article_12_automatic_logs_siem.json\` in this bundle for the
complete OCSF-formatted audit entries. Ingest into your SIEM
(Splunk, Datadog, QRadar, or equivalent) for post-market monitoring
workflows under Article 72.

---

## Article 12 Obligations — Row-by-Row

{{ rows_rendered }}

---

## Known Caveats and Residual Risk

The following caveats are disclosed honestly and are specific to
Sanctuary Framework v{{ sanctuary_version }}:

1. **Audit log entries are not Ed25519-signed.** The authenticated
   encryption provides integrity against unauthorised third parties
   without the master key. It does not provide non-repudiation
   against a compromised-master-key insider, because the encryption
   is symmetric. If your threat model requires per-entry
   non-repudiation, supplement this logging with an external append-
   only log service (e.g., a separate SIEM with write-once storage).

2. **Persistence is fire-and-forget.** If disk write fails, the
   entry lives only in memory and is lost at process exit. This is
   a durability concern under Article 12(1)'s "over the lifetime of
   the system" clause. The mitigation is to ensure the Sanctuary
   storage path is on reliable storage and monitored for write
   failures.

3. **Retention policy is deployer-declared.** Sanctuary persists
   entries indefinitely by default but does not enforce the
   Article 19(1) six-month minimum retention. The deployer must
   configure archival to meet the statutory retention.

These caveats are documented for audit transparency and do not
affect the Article 12(1) capability claim that the system
"technically allows for the automatic recording of events over
the lifetime of the system."

${FOOTER_TEMPLATE}`;
