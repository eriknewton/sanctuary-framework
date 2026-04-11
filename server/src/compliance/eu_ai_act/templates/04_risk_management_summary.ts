/**
 * Sanctuary MCP Server — EU AI Act Template: Risk Management Summary
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Document 04 of the EU AI Act Compliance Bundle.
 *
 * Summarises the risk management posture under Article 9, referencing
 * the Annex IV §5 and Annex IV §2(h) rows, the Article 15 resilience
 * rows, and the runtime control inventory from the Principal Policy
 * and context gating subsystems.
 */

import { HEADER_TEMPLATE, FOOTER_TEMPLATE } from "./shared.js";

export const RISK_MANAGEMENT_SUMMARY_TEMPLATE = `${HEADER_TEMPLATE}
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

Every MCP tool call passes through the \`ApprovalGate.evaluate()\`
method before execution. The gate applies the three-tier Principal
Policy:

- **Tier 1 — Always require human approval:** {{ tier1_rule_count }} rules defined.
  Operations in this tier (state export/import, key rotation, secure
  delete, reputation import, and similar irreversible or sensitive
  actions) are blocked pending out-of-band approval via the
  configured channel (\`{{ approval_channel_type }}\`). Default behaviour
  on timeout: **deny**.
- **Tier 2 — Anomaly-triggered approval:** {{ tier2_rule_count }} rules
  defined. Baseline tracker at \`principal_baseline_view\` monitors
  new namespaces, new counterparties, and frequency spikes. First-
  session policy: \`{{ first_session_policy }}\`.
- **Tier 3 — Auto-allow with audit logging:** {{ tier3_rule_count }}
  tools listed. These are read-only or low-risk operations that
  proceed without approval but are still captured in the audit log.

### L2 Process Hardening

Runtime hardening of the Sanctuary process via seccomp/entitlement
restrictions where supported by the host operating system.

### L2 Outbound Context Gating

Per-provider field-level policies applied to agent context before
any outbound call. {{ context_gate_policy_count }} context gate
policies are currently configured, enforced via the context gate
enforcer (active: {{ context_gate_enforcer_active }}).

### Prompt Injection Detector

The \`InjectionDetector\` subsystem runs as a pre-check inside the
Principal Policy gate on every tool call. Detection signals are
written to the audit log with the prefix \`injection_detected:\` and
are filterable via \`monitor_audit_log\` and \`audit_export_siem\`.
During the reporting period {{ period_start }} → {{ period_end }},
the detector flagged **{{ injection_detected_count }}** events.

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

{{ rows_rendered }}

---

## Residual Risk and Mitigations

The following residual risks are disclosed honestly and are
specific to Sanctuary Framework v{{ sanctuary_version }}:

- **No TEE attestation.** The runtime self-reports its environment
  type without a hardware root of trust. The SHR degradation flag
  \`NO_TEE\` is set automatically. Mitigation: deploy Sanctuary on
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
\`[MANUAL INPUT REQUIRED: ...]\` markers throughout this document
and the Annex IV §5 row below:

- Risk register for the specific deployment
- Residual risk analysis and acceptance criteria
- Risk treatment plan linking identified risks to the Sanctuary
  controls above (or compensating controls)
- Periodic risk review cadence
- Risk ownership and accountability structure

${FOOTER_TEMPLATE}`;
