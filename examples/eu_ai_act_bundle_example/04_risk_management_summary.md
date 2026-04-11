# Risk Management Summary

*Risk management posture under Article 9 of Regulation (EU) 2024/1689*

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

This document is the Risk Management Summary for the high-risk AI
system identified above, prepared in accordance with Article 9 of
Regulation (EU) 2024/1689. It aggregates the Sanctuary Framework
evidence relevant to risk identification, risk analysis, risk
treatment, and residual risk acceptance for the deployed agent.

This document does not replace the enterprise's overall risk
management system documentation. It supplies the runtime-control
half of that system — the mechanisms, policies, and monitoring
data that Sanctuary automatically emits. The enterprise must wrap
these mechanisms in an Article 9-compliant risk management
framework with identified risks, residual risk analysis, risk
treatment plans, and periodic review cadence.

---

## Runtime Control Inventory (Auto-Filled)

The following Sanctuary controls are active for this agent and
collectively form the runtime risk-mitigation substrate referenced
by Article 9:

### Principal Policy Gate (L2 Operational Isolation)

Every MCP tool call passes through the `ApprovalGate.evaluate()`
method before execution. The gate applies the three-tier Principal
Policy:

- **Tier 1 — Always require human approval:** 12 rules defined.
  Operations in this tier (state export/import, key rotation, secure
  delete, reputation import, and similar irreversible or sensitive
  actions) are blocked pending out-of-band approval via the
  configured channel (`stderr`). Default behaviour
  on timeout: **deny**.
- **Tier 2 — Anomaly-triggered approval:** 6 rules
  defined. Baseline tracker at `principal_baseline_view` monitors
  new namespaces, new counterparties, and frequency spikes. First-
  session policy: `approve`.
- **Tier 3 — Auto-allow with audit logging:** 60
  tools listed. These are read-only or low-risk operations that
  proceed without approval but are still captured in the audit log.

### L2 Process Hardening

Runtime hardening of the Sanctuary process via seccomp/entitlement
restrictions where supported by the host operating system.

### L2 Outbound Context Gating

Per-provider field-level policies applied to agent context before
any outbound call. 0 context gate
policies are currently configured, enforced via the context gate
enforcer (active: unknown).

### Prompt Injection Detector

The `InjectionDetector` subsystem runs as a pre-check inside the
Principal Policy gate on every tool call. Detection signals are
written to the audit log with the prefix `injection_detected:` and
are filterable via `monitor_audit_log` and `audit_export_siem`.
During the reporting period 2026-04-01T00:00:00.000Z → 2026-04-30T23:59:59.999Z,
the detector flagged **2** events.

### L3 Selective Disclosure

Pedersen commitments on Ristretto255, Schnorr proofs, and bit-
decomposition range proofs. Allows the agent to prove claims about
its data without revealing the underlying values — a core control
for data minimisation under Article 10 and GDPR data minimisation
obligations.

### L4 Verifiable Reputation

Ed25519-signed attestations in EAS-compatible format with
sovereignty-gated trust tiers. Supports attestation-based trust
decisions without requiring trust in any single attestor.

---

## Risk-Management-Relevant Coverage Rows

### Annex IV §2(b) — Design specifications and key design choices

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The design specifications of the system, namely the general logic of the AI system [...] the key design choices including the rationale and assumptions made [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: machine-readable Principal Policy YAML (tier rules, approval channel configuration, anomaly thresholds), context gating policy manifest, sovereignty profile, and the full MCP tool inventory. Together these constitute the declarative design specification of the Sanctuary sovereignty layer.

**Evidence emitter tools:**

- `principal_policy_view`
- `context_gate_list_policies`
- `sovereignty_profile_get`
- `manifest`

**Enterprise input required:**

Agent-level business logic, decision algorithms, the rationale for key design choices (why this policy, why these thresholds), assumptions made during development, and any non-Sanctuary architectural components.

---

### Annex IV §2(h) — Cybersecurity measures

**Coverage:** **FULL** — auto-emitted from Sanctuary, zero enterprise input required, machine-verifiable

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A detailed description of the cybersecurity measures put in place [...]."

**Evidence emitted by Sanctuary:**

Machine-verifiable inventory of Sanctuary's cybersecurity primitives, every item reproducible by running the listed tools against a live instance: (1) L1 Cognitive Sovereignty — AES-256-GCM namespace encryption with HKDF per-namespace key derivation, Argon2id master key derivation, Ed25519 self-custodied identity, Merkle integrity tracking; reported by sovereignty_audit and shr_generate under layers.l1. (2) L2 Operational Isolation — three-tier Principal Policy gate with out-of-band approval channel, tool-call audit logging, and denial-on-timeout semantics; reported by principal_policy_view and shr_generate under layers.l2. (3) L2 Outbound context gating — per-provider field policies classifying agent context as allow / redact / hash / summarize / deny before any outbound call; reported by context_gate_list_policies and context_gate_enforcer_status. (4) L3 Selective Disclosure — Pedersen commitments on Ristretto255, Schnorr proofs, and bit-decomposition range proofs; reported by sovereignty_audit and shr_generate under layers.l3. (5) L4 Verifiable Reputation — Ed25519-signed attestations in EAS-compatible format with sovereignty-gated trust tiers; reported by sovereignty_audit and shr_generate under layers.l4. (6) Execution attestation — cryptographic execution attestation via exec_attest. The full tool inventory of this Sanctuary instance is reproducible by running manifest.

**Evidence emitter tools:**

- `sovereignty_audit`
- `shr_generate`
- `manifest`
- `principal_policy_view`
- `context_gate_list_policies`
- `context_gate_enforcer_status`
- `exec_attest`

**Enterprise input required:**

_(none — this row is fully auto-emitted)_

---

### Annex IV §5 — Risk management system per Article 9

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "A detailed description of the risk management system in accordance with Article 9 [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: Principal Policy tier structure (Tier 1 block, Tier 2 anomaly-triggered, Tier 3 auto-allow), baseline anomaly tracker configuration, outbound context gating policies, and sovereignty audit gap analysis with prioritised recommendations. These constitute Sanctuary's runtime risk management controls.

**Evidence emitter tools:**

- `principal_policy_view`
- `principal_baseline_view`
- `sovereignty_audit`
- `context_gate_list_policies`

**Enterprise input required:**

Enterprise-level risk register, residual risk analysis, risk treatment plan, acceptance criteria for residual risks, periodic risk review cadence, and the link between identified risks and the Sanctuary controls above.

---

### Article 15(5) — Cybersecurity measures appropriate to the risks

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "High-risk AI systems shall be resilient against attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities. The technical solutions aiming to ensure the cybersecurity of high-risk AI systems shall be appropriate to the relevant circumstances and the risks."

**Evidence emitted by Sanctuary:**

Auto-filled: the full cybersecurity measures inventory (see Annex IV §2(h) row for complete description). Sanctuary emits the list of measures with structured status flags.

**Evidence emitter tools:**

- `sovereignty_audit`
- `shr_generate`
- `principal_policy_view`
- `context_gate_list_policies`

**Enterprise input required:**

Appropriateness assertion: the enterprise must declare that the Sanctuary-reported measures are appropriate to the specific risks of the deployment context (risk-matched narrative linking identified risks to selected controls).

---

### Article 15(5) first subparagraph — Resilience against unauthorised third-party alteration

**Coverage:** **FULL** — auto-emitted from Sanctuary, zero enterprise input required, machine-verifiable

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "High-risk AI systems shall be resilient against attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities."

**Evidence emitted by Sanctuary:**

Resilience against unauthorised third-party alteration is enforced across multiple subsystems, each independently verifiable via an MCP tool call: (1) L1 state store — AES-256-GCM authenticated encryption with HKDF per-namespace keys, Merkle root per namespace, monotonic version counter per (namespace, key), and anti-rollback checks on every read; reported by monitor_health (state_integrity flag) and via version numbers returned by state_list. (2) L1 audit log — AES-256-GCM authenticated ciphertext persisted under an HKDF-derived audit-log key; confidentiality and integrity against third-party tampering (no signature-based non-repudiation — see review_notes). (3) L1 identity — Ed25519 self-custodied keypairs; signed identity operations (sign, rotate, verify) and signed SHR generation; reported by shr_generate signature block. (4) L2 execution gate — every tool call routed through router.ts -> ApprovalGate.evaluate() -> Principal Policy tier check before execution; no bypass path; reported by principal_policy_view and the audit log trail of gate_* entries. (5) L2 outbound context gating — per-provider field policies applied before any outbound call; reported by context_gate_enforcer_status.

**Evidence emitter tools:**

- `sovereignty_audit`
- `shr_generate`
- `monitor_health`
- `state_list`
- `principal_policy_view`
- `context_gate_enforcer_status`

**Enterprise input required:**

_(none — this row is fully auto-emitted)_

---

### Article 15(5) second subparagraph — Resilience against data and model poisoning

**Coverage:** **PARTIAL** — Sanctuary emits structured evidence, enterprise supplies business context

**Regulation text (verbatim, EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10):**

> "The technical solutions to address AI specific vulnerabilities shall include, where appropriate, measures to prevent, detect, respond to, resolve and control for attacks trying to manipulate the training data set ('data poisoning'), or pre-trained components used in training ('model poisoning'), inputs designed to cause the AI model to make a mistake ('adversarial examples' or 'model evasion'), [...]."

**Evidence emitted by Sanctuary:**

Auto-filled: the Principal Policy gate runs a prompt injection detector pre-check on every tool call; when flagged, the gate appends 'injection_detected:*' entries to the audit log, which are visible via monitor_audit_log and exportable via audit_export_siem. The detector covers role override, security bypass, encoding evasion, data exfiltration, and prompt stuffing signals at runtime.

**Evidence emitter tools:**

- `monitor_audit_log`
- `audit_export_siem`

**Enterprise input required:**

Training-time threats (data poisoning, model poisoning) are entirely outside Sanctuary's runtime scope — training data governance is the model provider's responsibility. The runtime adversarial-input detection is partial coverage of the 'adversarial examples' subset of Art. 15(5).

---



---

## Residual Risk and Mitigations

The following residual risks are disclosed honestly and are
specific to Sanctuary Framework v0.8.0:

- **No TEE attestation.** The runtime self-reports its environment
  type without a hardware root of trust. The SHR degradation flag
  `NO_TEE` is set automatically. Mitigation: deploy Sanctuary on
  TEE-capable hardware in production, or accept the process-level
  isolation boundary as sufficient for the deployment context.
- **Training-time threats are out of scope.** Data poisoning,
  model poisoning, and backdoor injection at training time are
  outside Sanctuary's runtime scope. Mitigation: rely on the
  model provider's training-pipeline controls and declare the
  provider's governance in the Annex IV §2(d) manual section.
- **Audit log retention is deployer-declared.** See the Article 12
  automatic logs document for details and mitigation.

---

## Enterprise-Supplied Risk Framework

The enterprise must supply the following to complete the Article 9
risk management documentation. These are listed as
`[MANUAL INPUT REQUIRED: ...]` markers throughout this document
and the Annex IV §5 row below:

- Risk register for the specific deployment
- Residual risk analysis and acceptance criteria
- Risk treatment plan linking identified risks to the Sanctuary
  controls above (or compensating controls)
- Periodic risk review cadence
- Risk ownership and accountability structure


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
