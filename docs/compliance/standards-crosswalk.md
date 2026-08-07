---
title: Sanctuary Standards Compliance-Evidence Crosswalk
description: A capability-to-control map from shipped Sanctuary primitives to the agent-security standards buyers, insurers, and procurement now cite. Not a compliance certification.
author: Erik Newton
review_status: draft-for-review
last_full_verification: 2026-07-05
---

# Sanctuary Standards Compliance-Evidence Crosswalk

## What this is (and is not)

This document maps capabilities Sanctuary already ships to the agent-security controls that enterprise buyers, cyber-insurers, and government procurement are now writing into their requirements. The mid-2026 landscape converged fast: OWASP's Top 10 for Agentic Applications, ISO/IEC 42001, SOC 2, the proposed US GSAR federal-contractor clause, and the EU Cyber Resilience Act all now describe tamper-evident logging, per-action human oversight, and provable data control as things a deployer must be able to demonstrate.

**Honesty contract.** This is a capability-to-control *map*, not a compliance certification. Sanctuary is a control *provider*; running it does not by itself make a deployer compliant. Every row marked SHIPPED traces to a merged pull request or a coordinator-verified drill; every PARTIAL states its bound; every GAP is named, not hidden. Where a claim could read as a certification, it has been softened to a capability statement.

This crosswalk is a companion to the more granular [EU AI Act Coverage Matrix](eu_ai_act_coverage_matrix_v1.md), which maps Sanctuary primitives clause-by-clause to Regulation (EU) 2024/1689.

---

## The standards in scope (what actually bites, and when)

| Standard | What it requires that Sanctuary touches | Timing / force |
|---|---|---|
| **OWASP Top 10 for Agentic Applications 2026** | Tamper-evident logging of agent actions/tool calls; log integrity; append-only/non-repudiation; identity/privilege-abuse controls; tool-misuse containment | Industry threat model; the de-facto agent-security baseline auditors cite now |
| **ISO/IEC 42001** (AI management systems) | Event logging (A.6.2.8); human-oversight controls (Annex A.9) | Becoming a procurement gate |
| **SOC 2 Type 2** | Privileged actions attributable to an accountable human; an "action attributable only to an autonomous agent" is an accountability gap | A gate to open enterprise sales conversations |
| **US GSAR 552.239-7001** (PROPOSED, comment closed Apr 2026) | Government data ownership; eyes-off handling; logical segregation; secure deletion with written certification; data localization; no-train-on-customer-data; tamper-evident logging; forensic retention; open standards/no-lock-in | PROPOSED federal-contractor clause. Verify final-rule status before any deck cites it as binding |
| **EU Cyber Resilience Act** | Incident/vulnerability reporting (24h/72h/14-day); evidence generation | Reporting obligations from Sep 2026 |
| **EU AI Act Art 50 / Art 12,14,26** | Art 50 transparency; high-risk tamper-evident logging (Art 12), human oversight (Art 14), deployer log retention (Art 26) | Art 50 in 2026; high-risk Art 12/14/26 deferred to Dec 2027 (Annex III) / 2028 (Annex I). Position as "get ahead of the 2027 wall," not an Aug-2026 mandate |
| **NIST AI RMF + Agent Standards Initiative** | Govern-function logging; the forthcoming Agent Interoperability Profile (identity/auth/logging) | Voluntary; the reference standard to map to as it lands |

---

## The crosswalk (capability to control)

Legend: **SHIPPED** = merged and, where relevant, drilled. **PARTIAL** = shipped with a stated bound. **GAP** = not built, named honestly.

### 1. Tamper-evident / non-repudiation logging
_(OWASP logging; ISO A.6.2.8; GSAR tamper-evident logging + forensic retention; AI Act Art 12; CRA evidence)_

- **PARTIAL:** hash-chained, tamper-evident audit log. Every persisted state change produces a queryable audit entry; entries carry a per-entry `prev_hash` + `entry_hash` sequence and support checkpoint signatures when a checkpoint signer is supplied. Production boot paths currently do not supply that signer, so production checkpoints are written unsigned, and `audit-chain verify --no-strict` can return PASS with findings. Any reordering, truncation, or entry edit is detectable by strict verification. This is *tamper-evidence*; non-repudiation is at checkpoint granularity only after the production signer and false-PASS verifier gap close. Open defect: **IC-05, IC-06** (`docs/audit/inert-capability-register.md`).
- **SHIPPED:** Enforcement Receipts, external anchoring (opt-in). Sigstore Rekor transparency-log anchoring + an auditor pack + fork detection + log-attested freshness (PR #468/#487/#489). This is the strongest single evidence artifact: a third-party-verifiable proof the audit trail was not altered. Anchoring is opt-in and salted-hash-only. Cross-host verify was drilled (a checkpoint emitted on host A verifies on host B; a tampered checkpoint fails on both).
- **SHIPPED:** anti-rollback anchoring. Custody-MAC-anchored monotonic anchors (config-downgrade gate #805; fleet ledger anti-rollback #871) prevent a silent rewind of the record.
- **GAP (named):** per-flow, rule-attributed audit trail. Today the audit is per-uid / per-operation, not per-*flow* with the specific policy rule that fired attributed to each action. Do not claim "audited per-rule per-flow."

### 2. Human oversight / approval gates
_(OWASP human-agent-trust; ISO A.9; SOC 2 accountable-human; AI Act Art 14; CA AB 316)_

- **SHIPPED:** Tier-1 approval gates on the highest-consequence operations. The default policy classifies as Tier-1 (human approval required before execution): state export, state import, raw identity signing, key rotation, governor reset, secure delete, and reputation import. This is the "privileged action attributable to an accountable human" that SOC 2 auditors ask for and that AB 316 makes legally consequential.
- **GAP (named), 2026-08-07 correction:** plain-English policy view + promote-approval-to-standing-rule (PR #839) was listed here as SHIPPED. Withdraw that. `EnglishPolicyActivator` is never constructed in any boot path and its required `PolicyActivationStore` has no construction site in `server/src` at all, so both production binding sites omit the field and every English-policy route returns 503. The plain-English panel never renders a policy and the "Always allow" control always fails. Do not cite this as an Art 14 "understand, interpret, override" control. Open defect: **IC-13** (`docs/audit/inert-capability-register.md`).
- **PARTIAL:** per-action attribution. Approvals are attributable to the operator credential; full per-*action* human-vs-agent attribution across a long autonomous run is bounded (ties to the per-flow gap above).

### 3. Provable data control / eyes-off / custody
_(GSAR data ownership + eyes-off + segregation; the sovereignty wedge)_

- **SHIPPED:** operator-held custody, vendor not in the data path. Encrypted state lives in the operator's own storage path; private keys exist only encrypted at rest and transiently in memory for signing, and are never exposed in any response, log, or error (a hard architectural constraint). There is no vendor-held decryption key. Maps to GSAR "eyes-off" and "government owns the data."
- **SHIPPED:** encrypted-at-rest with a strong KDF. Argon2id master-key derivation + AES-256-GCM, fail-closed (no plaintext fallback if encryption fails).
- **SHIPPED:** zero unrequested outbound by default (PR #869/#870). The update-check probe is opt-in (off unless explicitly enabled); no state content leaves the local path except through an explicit, approval-gated export. Maps to GSAR "no external data movement without intent."

### 4. Secure deletion
_(GSAR secure-deletion-with-written-certification; AI Act data-lifecycle)_

- **SHIPPED:** Tier-1-gated secure delete. A 3-pass random-byte overwrite before unlink, gated behind human approval. Honest bound baked into the tool's own copy: on copy-on-write / journaled / SSD (flash-FTL) media the original blocks may persist, so at-rest confidentiality rests on encryption rather than on the overwrite alone.
- **PARTIAL / phase-2 candidate:** a signed deletion *certificate*. Sanctuary performs the deletion; a signed, exportable certificate of deletion (the artifact GSAR literally names) is a small, high-value add that rides the existing Enforcement-Receipts channel. Not yet built.

### 5. Data portability / no lock-in
_(GSAR open-standards/no-lock-in; EU sovereignty procurement)_

- **PARTIAL:** Exit MVP. CLI user-state export, a completeness manifest, atomic activation, offline `verify-exit-bundle`, and reputation import/export parity exist, but the whole exit guarantee is partial: dashboard export omits the state re-key key, import hides skipped-entry counters, and imported bundles from a fortress that rotated identity keys can silently lose pre-rotation state. Open defect: **IC-07, IC-08, IC-09** (`docs/audit/inert-capability-register.md`).
- **GAP (named):** provable clean-erasure exit. Full crypto-shred exit is blocked by deterministic HKDF; today's exit is honestly "narrow / user-state." Do not claim provable-clean-erasure.

### 6. Enforcement (the wall)
_(OWASP tool-misuse / rogue-agent containment)_

- **SHIPPED (macOS only):** Castle Wall enforces a signed operator policy with a clean per-uid allow/deny demo plus attended reboot-survival, drilled and coordinator-verified on macOS. A signed policy-distribution rail (PR #789) was drilled loopback and cross-machine. Standing honest caveat: this is enforcement of a signed operator policy with a per-uid allow/deny demo, NOT "audited per-rule per-flow."
- **GAP (named), 2026-08-07 correction:** this row previously read "on macOS and on Linux (Linux evidence is CI-authoritative)". Linux is withdrawn from the SHIPPED claim. The Linux kernel modules pass integration tests against a real kernel, and the shipped `castle-wall-daemon` binary installs no nftables table, binds no NFQUEUE, creates no cgroup scope, and never calls the deny-by-default evaluator; the shipped systemd unit is `Type=notify` while the daemon never signals readiness, so the documented activation path cannot reach `active`. Do not cite Linux Castle Wall as an enforcement control. Open defect: **IC-02, IC-03, IC-04** (`docs/audit/inert-capability-register.md`); `ASSURANCE_MATRIX.md` carries this row as `not_implemented`.
- **PARTIAL:** fine-grained per-action egress. The coarse network-destination wall is proven; the fine-grained "exclusive-egress" build (Unified Protect) is drilled on both macOS families (Tahoe 26.5.1 arm64 and Sonoma 14.6.1 x86_64, N=3 each) but is not yet a one-command GA install, and the full external "unbypassable" claim still owes LaunchDaemon self-confinement plus a kernel wall on a second OS family. Those two drill legs are two macOS releases, one operating system; see `docs/audit/unified-protect-enforcement-status.md`. State this bound wherever the wall is described.

### 7. Identity / privilege
_(OWASP identity-abuse; NIST Agent Standards identity/auth)_

- **SHIPPED:** policy-read invariant. The agent cannot read or infer the Principal Policy at runtime; denials return generic messages that do not reveal which tier or rule fired. Ed25519 operator identity, with an available PQC-hybrid signature suite (ed25519 + ML-DSA) selectable for identity operations.
- **SHIPPED:** honest attestation state. Global and per-agent attestation are surfaced with an evidence-based rule: green only when enforcement is actually real, never on daemon self-report alone.

---

## One-page auditor-facing summary

> Sanctuary provides operator-controlled, cryptographically verifiable controls that map to the agent-security controls your framework requires:
>
> - **Tamper-evident audit trail** (hash-chained, with checkpoint signatures only when a signer is wired) with optional external transparency-log anchoring that is third-party verifiable. Production checkpoints are currently unsigned, and `audit-chain verify --no-strict` can return PASS with findings. Open defect: **IC-05, IC-06**. Maps to OWASP logging, ISO 42001 A.6.2.8, GSAR tamper-evident logging + forensic retention, EU CRA evidence, AI Act Art 12 (preparedness).
> - **Human-approval gates** on the operations the policy classifies Tier-1 (export, import, key rotation, secure delete, reputation import), attributable to the operator credential. Maps to SOC 2 accountable-human, ISO A.9, AI Act Art 14, CA AB 316.
> - **Operator-held custody**, vendor not in the data path, encrypted at rest, zero unrequested outbound. Maps to GSAR data ownership + eyes-off, EU sovereignty procurement.
> - **Tier-1-gated secure delete** (phase 2: signed deletion certificate). Maps to GSAR secure-deletion-with-certification.
> - **Data-portability / exit bundle** with offline verification, partial until dashboard export carries the state re-key key, import surfaces skipped-entry counters, and rotated-key imports preserve pre-rotation state. Open defect: **IC-07, IC-08, IC-09**. Maps to GSAR open-standards/no-lock-in.
> - **Signed-operator-policy enforcement** (per-uid allow/deny, reboot-surviving, macOS only). Maps to OWASP tool-misuse / rogue-agent containment. Linux is withdrawn from this claim: the shipped daemon installs no kernel enforcement, and the Assurance Matrix row is `not_implemented`. Open defect: **IC-02, IC-03, IC-04**.
>
> Honest boundaries (we never overclaim): production audit checkpoints are currently unsigned and `audit-chain verify --no-strict` can return PASS with findings; full exit remains partial across dashboard export, skipped import counters, and rotated-key imports; per-flow rule-attributed audit and provable-clean-erasure exit remain roadmap work; secure delete is best-effort overwrite with at-rest confidentiality resting on encryption; the fine-grained exclusive-egress wall is drilled and still owes a one-command GA install plus a second-OS-family kernel wall before any bare "unbypassable" claim.

---

## Next steps (ranked)

1. Build the signed deletion certificate (phase-2, small, high-value; rides the existing Enforcement-Receipts channel; closes the single most literal GSAR gap).
2. Re-verify the [EU AI Act Coverage Matrix](eu_ai_act_coverage_matrix_v1.md) against the current tree in the same review pass. Its `next_review_due` (2026-06-01) is overdue, and its audit-log review notes must match PR #274's hash chain plus conditional checkpoint-signature bounds. The two documents must agree before either is used externally.
3. Verify GSAR final-rule status and pull the exact OWASP Agentic Top-10 control text before any of this is used in a customer deck.
4. Map to the NIST Agent Interoperability Profile when it lands, to keep the crosswalk current with the US government's reference standard.

---

## Sources

Evidence anchors: OWASP Top 10 for Agentic Applications 2026; ISO/IEC 42001; GSAR 552.239-7001 (PROPOSED status); EU CRA reporting (Sep 2026) plus the Digital Omnibus high-risk deferral to Dec 2027; NIST AI Agent Standards Initiative; CA AB 316. Sanctuary capability rows trace to merged pull requests: #274 (tamper-evident audit chain plus conditional checkpoint signatures), #468/#487/#489 (Enforcement Receipts / Rekor anchoring), #789 (signed policy-distribution rail), #805/#871 (anti-rollback anchoring), #839 (plain-English policy + promote-to-standing-rule), #869/#870 (zero unrequested outbound).

---

**NOT LEGAL ADVICE.** This crosswalk is a technical mapping from Sanctuary primitives to third-party standards; it is not a legal interpretation of any standard or regulation and does not constitute a legal opinion or a claim of certification. Consult qualified counsel before relying on any compliance artifact derived from this document.

---

_Sanctuary Framework · Author: Erik Newton · License: Apache-2.0_
