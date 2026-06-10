# Human Oversight Statement

*Human oversight measures under Article 14 of Regulation (EU) 2024/1689*

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
| Approval channel type | `stderr` |
| Approval channel timeout | 300 seconds |
| On timeout | **deny** (SEC-002: `auto_deny` removed — timeout always denies) |
| Tier 1 rule count (always require approval) | 12 |
| Tier 2 anomaly rules | new_namespace_access: `approve`, new_counterparty: `approve`, frequency_spike_multiplier: 5, first_session_policy: `approve` |
| Tier 3 auto-allow tool count | 60 |
| Baseline tracker state | `loaded` |

The full Principal Policy is machine-readable via
`principal_policy_view`. The baseline tracker state is exposed via
`principal_baseline_view`. Both tools are Tier 3 (read-only) and
can be invoked by an auditor against a live Sanctuary instance to
independently verify every value above.

---

## Reporting Period Oversight Activity (Auto-Filled)

During the reporting period **2026-04-01T00:00:00.000Z → 2026-04-30T23:59:59.999Z**,
the Sanctuary oversight gate recorded the following activity:

| Outcome | Count |
|---|---|
| Gate allow (Tier 3 auto-allow or approved Tier 1/2) | 24 |
| Gate allow_proxy (MCP-proxy pass-through) | 12 |
| Gate deny (approval denied or timeout) | 3 |
| Gate escalate (Tier 2 anomaly raised for human review) | 0 |
| Gate unclassified (no matching rule, default behaviour applied) | 0 |
| Injection-detection events | 2 |

Individual entries are queryable via `monitor_audit_log` with
`layer: "l2"` filter and exportable in SIEM-compatible format via
`audit_export_siem`.

---

## Article 14 and Annex IV §2(e) Row Coverage

### Article 14(4)(a)-(c) — Oversight enables understanding and interpretation

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "[The measures shall enable the persons to whom human oversight is assigned to]: (a) [...] properly understand the relevant capacities and limitations of the high-risk AI system [...]; (b) [...] remain aware of [...] automation bias [...]; (c) [...] correctly interpret the high-risk AI system's output [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: SHR is designed to be human-readable with explicit per-layer status flags and honest degradation declarations. Principal Policy is inspectable YAML that a human overseer can read directly. Tool inventory (via manifest) gives the oversight persons a complete list of what the agent can do.

**Evidence emitter tools:**

- `shr_generate`
- `principal_policy_view`
- `manifest`

**Enterprise input required:**

Training materials for human overseers, the specific automation-bias awareness program, how oversight persons are trained to correctly interpret agent output, and any UI tools the enterprise provides to support oversight.

---

### Article 14(4)(e) — Intervention, interruption, and stop button

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "[The measures shall enable the persons to whom human oversight is assigned to]: (e) [...] intervene on the operation of the high-risk AI system or interrupt the system through a 'stop' button or similar procedure that allows the system to come to a halt in a safe state."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy approval channel configuration (stderr / dashboard / webhook), Tier 1 require-approval rule count, denial-on-timeout behaviour, and gate decision semantics. These collectively document Sanctuary's pre-execution intervention capability — every Tier 1 tool call is halted pending human approval.

**Evidence emitter tools:**

- `principal_policy_view`
- `sovereignty_audit`

**Enterprise input required:**

The enterprise's declared mapping between Sanctuary's approval channel and its Article 14(4)(e) stop-button workflow, the operational procedure for invoking the stop button, and acceptance that pre-execution gating satisfies the 'halt in a safe state' requirement for the specific agent.

---

### Article 14(4)(d) — Decide not to use or to disregard the output

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "[The measures shall enable the persons to whom human oversight is assigned to]: (d) [...] decide, in any particular situation, not to use the high-risk AI system or to otherwise disregard, override or reverse the output of the high-risk AI system [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy denial semantics — every Tier 1 operation defaults to deny on approval timeout, providing a structural 'decide not to use' control at the policy layer. Tier 1 tools include export, import, key rotation, and secure delete.

**Evidence emitter tools:**

- `principal_policy_view`

**Enterprise input required:**

The enterprise's declared mapping between Sanctuary's deny semantics and its Art. 14(4)(d) decision-not-to-use workflow, and operator authority to invoke the decision.

---

### Article 14(4) chapeau — Operator competence, training, and authority

**Coverage:** **MANUAL ONLY** — Sanctuary has no visibility, enterprise authors this section

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "[Human oversight measures shall be commensurate with the risks, level of autonomy and context of use of the high-risk AI system] [...] ensured through [...] the following types of measures, as appropriate to the circumstances [...]."

**Evidence emitted by Sanctuary:**

[MANUAL INPUT REQUIRED: operator identities, roles, competence, training program, and authority to override].

**Evidence emitter tools:**

_(none — this row is manual_only)_

**Enterprise input required:**

People-and-process facts that Sanctuary cannot observe or emit.

---

### Annex IV §2(e) — Assessment of human oversight measures per Article 14

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "Assessment of the human oversight measures needed in accordance with Article 14, including an assessment of the technical measures needed to facilitate the interpretation of the outputs of AI systems by the deployers [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy approval channel configuration (stderr / dashboard / webhook), Tier 1 require-approval rule count, Tier 2 anomaly-triggered approval rule count, Tier 3 auto-allow tool list, baseline anomaly tracker status, and denial-on-timeout behaviour. The template pre-populates the technical-measures half of the human oversight assessment.

**Evidence emitter tools:**

- `principal_policy_view`
- `sovereignty_audit`
- `shr_generate`
- `principal_baseline_view`

**Enterprise input required:**

Operator identities, roles, training, authority, and escalation procedures; mapping between Sanctuary's approval channel and the enterprise's stop-button workflow; rationale for why the chosen oversight tier is appropriate to the risk profile of the deployed agent.

---



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
