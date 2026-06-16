# Article 12 Automatic Record-Keeping

*Automatic logging and retention under Articles 12 and 19(1) of Regulation (EU) 2024/1689*

---

| Field | Value |
|---|---|
| **Regulation** | EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10 |
| **Coverage matrix version** | v1 |
| **Bundle generated** | 2026-04-10T12:00:00.000Z |
| **Reporting period** | 2026-04-01T00:00:00.000Z → 2026-04-30T23:59:59.999Z |
| **Agent DID** | `did:sanctuary:meridian-hr-screening-agent` |
| **Legal provider** | Meridian Financial Holdings, Inc. |
| **Provider contact** | ai-compliance@meridian.example.com |
| **Intended purpose** | Automated CV screening and candidate shortlisting for open requisitions |
| **Annex III classification** | §4 employment, workers management, self-employment |
| **Signer DID** | `did:key:z7QGcerokfUuai3m1bqsYJXTl-M2VQCiaH4laBp4AW1izyg` |
| **Signer public key (base64url)** | `nHq6JH1Lmot5tW6rGCV05fjNlUAomh-JWgaeAFtYs8o` |

---


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
properties, each independently verifiable against the v0.8.0
source:

| Property | Mechanism | Verifiable via |
|---|---|---|
| Automatic capture on every tool call | `router.ts` wraps all tool invocations through `ApprovalGate.evaluate()`; the gate appends an audit entry on every outcome path (`gate_allow`, `gate_allow_proxy`, `gate_deny`, `gate_escalate`, `gate_unclassified`, `injection_detected`) | Source: `server/src/router.ts`, `server/src/principal-policy/gate.ts` |
| Append-only API | The `AuditLog` class exposes only `append()` and read methods (`query()`, `size`). No update or delete method is exposed. | Source: `server/src/operational/audit-log.ts` |
| Confidentiality at rest | AES-256-GCM authenticated encryption with an HKDF-derived per-purpose key (`audit-log` purpose string) | Source: `server/src/core/encryption.ts`, `server/src/core/key-derivation.ts` |
| SIEM-compatible export | CEF (Common Event Format, newline-delimited) and OCSF (Open Cybersecurity Schema Framework, JSON array) emitted by the `audit_export_siem` tool | Run: `audit_export_siem` with `format: "cef"` or `format: "ocsf"` |
| Gate decision taxonomy | Every entry carries a structured operation string prefixed with `gate_*` or `injection_detected:`, directly filterable via the `filter_decision` and `operation_type` parameters | Run: `audit_export_siem` with `filter_decision` set |

---

## Reporting Period Summary (Auto-Filled)

| Field | Value |
|---|---|
| Period start | 2026-04-01T00:00:00.000Z |
| Period end | 2026-04-30T23:59:59.999Z |
| Total entries captured | 47 |
| L1 entries | 6 |
| L2 entries | 41 |
| L3 entries | 0 |
| L4 entries | 0 |
| Gate allow | 24 |
| Gate allow_proxy | 12 |
| Gate deny | 3 |
| Gate escalate | 0 |
| Gate unclassified | 0 |
| Injection-detection events | 2 |

**Full SIEM export:** see the accompanying file
`03_article_12_automatic_logs_siem.json` in this bundle for the
complete OCSF-formatted audit entries. Ingest into your SIEM
(Splunk, Datadog, QRadar, or equivalent) for post-market monitoring
workflows under Article 72.

---

## Article 12 Obligations — Row-by-Row

### Article 12(1) — Automatic logging of events over lifetime

**Coverage:** **FULL** — auto-emitted from Sanctuary, zero enterprise input required, machine-verifiable

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "High-risk AI systems shall technically allow for the automatic recording of events ('logs') over the lifetime of the system."

**Evidence emitted by Sanctuary:**

Every tool call in the Sanctuary runtime automatically produces an audit entry via the Principal Policy gate. Router.ts wraps all tool invocations through gate.evaluate(), which appends to the audit log on every outcome path (gate_allow, gate_allow_proxy, gate_deny, gate_escalate, gate_unclassified, injection_detected). Entries are persisted as AES-256-GCM authenticated ciphertext under an HKDF-derived audit-log key and are queryable via monitor_audit_log or exportable in CEF/OCSF via audit_export_siem. No tool call bypasses the audit path.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`

**Enterprise input required:**

_(none — this row is fully auto-emitted)_

---

### Article 12(2)(a) — Logs enable identification of Article 79(1) risks

**Coverage:** **FULL** — auto-emitted from Sanctuary, zero enterprise input required, machine-verifiable

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The logging capabilities shall enable the recording of events relevant for identifying situations that may result in the AI system presenting a risk within the meaning of Article 79(1) [...] and for facilitating the post-market monitoring referred to in Article 72."

**Evidence emitted by Sanctuary:**

The audit_export_siem tool exports audit log entries in two SIEM-standard formats: Common Event Format (CEF, newline-delimited) and Open Cybersecurity Schema Framework (OCSF, JSON array). Both formats are directly ingestible by Splunk, Datadog, QRadar, and any other enterprise SIEM platform, which are the standard substrate for Article 72 post-market monitoring pipelines. Exports support time-window filters (since / until), tool name filters, gate decision filters (approve / deny / auto-allow), layer filters (l1 / l2 / l3 / l4), and result filters (success / failure). Bulk exports up to 1000 events per call.

**Evidence emitter tools:**

- `audit_export_siem`
- `monitor_audit_log`

**Enterprise input required:**

_(none — this row is fully auto-emitted)_

---

### Article 12(2)(b) — Logs facilitate monitoring operation per Article 26(5)

**Coverage:** **FULL** — auto-emitted from Sanctuary, zero enterprise input required, machine-verifiable

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The logging capabilities shall enable the recording of events relevant for [...] facilitating the monitoring of the operation of the high-risk AI system referred to in Article 26(5)."

**Evidence emitted by Sanctuary:**

Gate decisions are logged with structured operation prefixes (gate_allow:, gate_allow_proxy:, gate_deny:, gate_escalate:, gate_unclassified:, injection_detected:) directly filterable via audit_export_siem's filter_decision enum (approve / deny / auto-allow) and via monitor_audit_log's operation_type parameter. The Principal Policy baseline anomaly tracker state (behavioural model, known-namespaces, frequency baselines, anomaly thresholds) is queryable via principal_baseline_view. Together these provide the machine-queryable substrate for deployer operation monitoring under Article 26(5).

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`
- `principal_baseline_view`

**Enterprise input required:**

_(none — this row is fully auto-emitted)_

---

### Article 12(3) — Required log content for Annex III §1(a) systems

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "For high-risk AI systems referred to in point 1(a) of Annex III, the logging capabilities shall provide, at a minimum: (a) recording of the period of each use of the system [...]; (b) the reference database against which input data has been checked by the system; (c) the input data for which the search has led to a match; (d) the identification of the natural persons involved in the verification of the results [...]."

**Evidence emitted by Sanctuary:**

Auto-filled where the agent routes through Sanctuary: period of use (audit log timestamps with since/until filters), tool inputs (captured in audit entry details field), and identification of principals who approved Tier 1 operations (captured via identity_id in audit entries and identity provenance via identity_list). Gate decisions are bound to the identity that requested the operation.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`
- `identity_list`

**Enterprise input required:**

Reference database identifier (the external database the agent queries) — only captured if the agent explicitly logs it to Sanctuary state. Natural-person verifier identification beyond the Sanctuary principal identity (e.g., the human operator's HR record or employee ID). Input data captured only when the agent passes it through a Sanctuary tool call.

---

### Article 19(1) — Log retention for at least six months

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Providers of high-risk AI systems shall keep the logs referred to in Article 12(1), automatically generated by their high-risk AI systems, to the extent such logs are under their control. [...] the logs shall be kept for a period appropriate to the intended purpose of the high-risk AI system, of at least six months [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Sanctuary's audit log persists entries indefinitely by default (no automatic purge). Entries are exportable at any time via audit_export_siem for archival to enterprise storage.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`

**Enterprise input required:**

The enterprise's declared log retention policy (how long logs are kept, in which storage tier, who has access), the archival pipeline configuration feeding enterprise long-term storage, and the written policy document satisfying the 'period appropriate to the intended purpose' requirement.

---



---

## Known Caveats and Residual Risk

The following caveats are disclosed honestly and are specific to
Sanctuary Framework v0.8.0:

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


---

## Document Signature

This document is cryptographically signed by the provider's primary
Ed25519 identity (DID `did:key:z7QGcerokfUuai3m1bqsYJXTl-M2VQCiaH4laBp4AW1izyg`, public key
`nHq6JH1Lmot5tW6rGCV05fjNlUAomh-JWgaeAFtYs8o`). The signature for this document is recorded
in the bundle manifest `00_bundle_manifest.json` under the entry
with this filename, alongside its SHA-256 digest.

**Verification procedure:** compute the SHA-256 of this file's raw
byte content, compare it against the `sha256` field for this file
in the bundle manifest, then verify the `signature` field against
the SHA-256 using the signer's public key with Ed25519. A successful
check proves this document was emitted by the named Sanctuary
instance and has not been altered since generation.

---

## Disclaimer

**This document is not legal advice.** It is a technical artifact
generated by the Sanctuary Framework EU AI Act Compliance Artifact
Generator. It is not a legal interpretation of Regulation (EU)
2024/1689 and does not constitute a legal opinion. Consult qualified
legal counsel before filing or relying on this document for
regulatory submissions, self-assessment, or CE marking procedures.

The coverage claims in this document reflect the state of the
Sanctuary Framework v0.8.0 runtime as of the
generation timestamp above. The coverage matrix is versioned
(`v1`) and aligned to the regulation text
identified by `EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10`; if the European Commission
publishes implementing acts, delegated acts, or guidance that
modifies the applicable requirements, this document must be
regenerated against the updated matrix.

---

*Generated by [Sanctuary Framework](https://github.com/eriknewton/sanctuary-framework)
v0.8.0 · Author: Erik Newton · License: Apache-2.0*
