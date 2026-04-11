# Article 26 Deployer Log

*Deployer obligations under Article 26 of Regulation (EU) 2024/1689*

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

This document is the Article 26 Deployer Log for the high-risk AI
system identified above, prepared in accordance with the deployer
obligations of Article 26 of Regulation (EU) 2024/1689.

Unlike the Annex IV Technical Documentation (which is authored by
the **provider**), this document is authored by the **deployer** —
the natural or legal person using the high-risk AI system under its
authority. In many enterprise deployments the provider and deployer
are the same legal entity; in others they are distinct. The
`Meridian Financial Holdings, Inc.` field in the header identifies the
entity acting as deployer for the purposes of this document.

The document maps each Article 26 obligation to the evidence that
the Sanctuary Framework auto-emits, and identifies the operational
and governance facts that only the deployer can supply.

---

## Deployer Operation Summary

During the reporting period **2026-04-01T00:00:00.000Z → 2026-04-30T23:59:59.999Z**,
the Sanctuary Framework runtime for this agent recorded the
following aggregate operation metrics. These are auto-filled from
the encrypted audit log via `monitor_audit_log` and
`audit_export_siem`:

| Metric | Value |
|---|---|
| Total audit entries | 47 |
| L1 (Cognitive) entries | 6 |
| L2 (Operational) entries | 41 |
| L3 (Disclosure) entries | 0 |
| L4 (Reputation) entries | 0 |
| Gate decisions — allow | 24 |
| Gate decisions — allow_proxy | 12 |
| Gate decisions — deny | 3 |
| Gate decisions — escalate | 0 |
| Gate decisions — unclassified | 0 |
| Injection-detection events | 2 |
| Unique identities involved | 2 |
| Unique operation types | 6 |

Detailed event data is available in the companion file
`03_article_12_automatic_logs.md` and its associated SIEM export.

---

## Article 26 Obligations — Row-by-Row

### Article 26(1) — Use in accordance with instructions for use

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Deployers of high-risk AI systems shall take appropriate technical and organisational measures to ensure they use such systems in accordance with the instructions for use accompanying the systems [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: declaration of use in accordance with instructions].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Deployer-facing attestation, not a Sanctuary primitive.

---

### Article 26(2) — Assign human oversight to competent natural persons

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Deployers shall assign human oversight to natural persons who have the necessary competence, training and authority, as well as the necessary support."

**Evidence emitted by Sanctuary:**

Auto-filled: Sanctuary's approval channel configuration (stderr / dashboard / webhook) provides the technical substrate to which the enterprise binds its assigned human overseers. The Principal Policy Tier 1 rule list documents which operations require human approval.

**Evidence emitter tools:**

- `principal_policy_view`

**Enterprise input required:**

Identity of assigned overseers, their competence assessment, training records, authority scope, and the support infrastructure provided to them.

---

### Article 26(4) — Input data relevance and representativeness

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "[...] deployers shall ensure that input data is relevant and sufficiently representative in view of the intended purpose of the high-risk AI system."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: declaration of input data relevance and representativeness].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Input data governance is a deployer responsibility outside Sanctuary's runtime scope.

---

### Article 26(5) — Monitor operation and inform provider of incidents

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Deployers shall monitor the operation of the high-risk AI system on the basis of the instructions for use [...]. When deployers have reason to consider that the use in accordance with the instructions for use may result in that AI system presenting a risk [...] they shall, without undue delay, inform the provider [...] and suspend the use of that system."

**Evidence emitted by Sanctuary:**

Auto-filled: the runtime monitoring substrate — encrypted audit log queryable and exportable in SIEM-standard formats, health dashboard, and anomaly baseline tracker. Provides the technical means to monitor and detect risk situations.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`
- `monitor_health`
- `principal_baseline_view`

**Enterprise input required:**

The enterprise's incident response workflow, the 'inform provider' communication channel and contacts, the suspension procedure, and the documented risk-detection criteria.

---

### Article 26(6) — Deployers keep logs for at least six months

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Deployers of high-risk AI systems shall keep the logs automatically generated by that high-risk AI system, to the extent such logs are under their control, for a period appropriate to the intended purpose of the high-risk AI system, of at least six months [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Sanctuary's audit log persists entries indefinitely by default and is exportable for archival at any time via audit_export_siem in CEF/OCSF formats suitable for long-term SIEM retention.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`

**Enterprise input required:**

The enterprise's declared log retention policy, long-term archival pipeline, access control on archived logs, and written policy document satisfying the 'period appropriate to the intended purpose' requirement.

---

### Article 26(7) — Inform workers and workers' representatives (employment)

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Before putting into service or using a high-risk AI system at the workplace, deployers who are employers shall inform workers' representatives and the affected workers that they will be subject to the use of the high-risk AI system."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: worker and workers' representative notification evidence].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Labour-relations obligation outside Sanctuary's scope.

---

### Article 26(9) — Data protection impact assessment per GDPR Art. 35

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Where applicable, deployers of high-risk AI systems shall use the information provided under Article 13 of this Regulation to comply with their obligation to carry out a data protection impact assessment under Article 35 of Regulation (EU) 2016/679 [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: DPIA under GDPR Article 35, where applicable].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

DPIA is a GDPR governance document. Sanctuary's transparency artefacts (SHR, audit log) may feed into a DPIA, but the assessment itself is enterprise-authored.

---

### Article 26(8) — Registration in EU database for Annex III systems

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Deployers of high-risk AI systems referred to in Annex III that [...] are public authorities, [...] or deployers acting on their behalf, shall register themselves, select the system and register its use in the EU database referred to in Article 71 [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: EU database registration under Article 71, where applicable].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

Registration in the EU database is a legal procedural step the enterprise performs directly with the European Commission.

---




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
