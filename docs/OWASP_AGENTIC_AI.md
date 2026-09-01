# Mapping Sanctuary's Four Sovereignty Layers to the OWASP Top 10 for Agentic AI (2025)

> **Purpose.** This document maps the Sanctuary Framework's four sovereignty
> layers (Cognitive, Operational, Selective Disclosure, Verifiable
> Reputation) and its specific MCP tools onto each category of
> the OWASP Top 10 for Agentic AI (2025 draft). Where a category is only
> partially addressed, the mapping says so; where a category is outside
> Sanctuary's scope, the mapping says that too. This is a working
> reference, not a certification.

The OWASP Top 10 for Agentic AI was published in 2025 to describe the
ten most consequential risk classes for AI systems that plan, act,
call tools, and interact with other agents. The risks below follow
the canonical enumeration (AAI01 – AAI10) used in the OWASP 2025 draft
and GenAI Security Project publications.

Each section includes:

- **Risk.** One-line summary.
- **Sanctuary layer(s).** Which sovereignty layers apply.
- **Coverage.** `full` / `partial` / `not-addressed` / `out-of-scope`.
- **Mechanism.** Which specific subsystem, MCP tool, or policy covers it.
- **Gap.** Honest statement of what Sanctuary does not solve.

---

## AAI01: Memory Poisoning

**Risk.** Untrusted data injected into an agent's persistent memory
corrupts future decisions.

**Sanctuary layer(s):** Cognitive Sovereignty, Operational Isolation

**Coverage:** partial

**Mechanism.**
- All persisted agent state is AES-256-GCM encrypted under a
  master key derived via Argon2id from the principal's passphrase
  (Cognitive Sovereignty). An attacker without the passphrase cannot read or tamper with
  stored memory in place.
- State integrity is Merkle-tree verified on read (`state_read` returns
  a proof). Tampering is detected, not silently accepted.
- The Operational-layer injection detector (`security/injection-detector.ts`) scans
  every tool call, including memory writes, for prompt-injection
  signals before the call is executed.
- Operational Context Gating (5 tools: `context_gate_set_policy`,
  `context_gate_filter`, etc.) restricts what enters an LLM inference
  call, reducing the attack surface for memory-poisoning payloads
  relayed through the model.

**Gap.**
- Sanctuary cannot distinguish "content-poisoned but cryptographically
  valid" memory from "authentic" memory. If the agent itself writes
  poisoned content under authorized auth, Cognitive-layer integrity checks pass.
- The injection detector uses heuristics, not semantic analysis.

---

## AAI02: Tool Misuse

**Risk.** An agent invokes a legitimate tool in a harmful way: excess
scope, wrong context, or under adversarial prompt influence.

**Sanctuary layer(s):** Operational Isolation

**Coverage:** full (within its scope)

**Mechanism.**
- Every tool call passes through the three-tier Principal Policy
  **ApprovalGate** (`principal-policy/gate.ts`). The gate cannot be
  bypassed: it wraps every handler.
- Tier 1 operations (export, import, key rotation, identity delete,
  bootstrap, etc.) always require human approval via an
  out-of-band channel (stderr, dashboard SSE, or HMAC-signed webhook).
- Tier 2 flags behavioral anomalies: new namespaces, new
  counterparties, frequency spikes, bulk reads. These escalate to
  approval.
- The **Call Governor** (`operational/call-governor.ts`) enforces
  per-tool and per-upstream rate limits.
- The **Context Gate Enforcer** wraps every tool handler and filters
  outbound arguments per a provider-specific policy.
- **Injection Detector** pre-scan blocks or escalates on high-
  confidence prompt injection signals.

**Gap.**
- Sanctuary trusts tool vendors: if an upstream tool itself is
  malicious, Operational Isolation limits damage but cannot prevent intent-following
  harm within tier-3 auto-allowed surfaces.

---

## AAI03: Privilege Compromise

**Risk.** An agent acquires or keeps privileges beyond its intended scope.

**Sanctuary layer(s):** Cognitive Sovereignty, Operational Isolation

**Coverage:** partial

**Mechanism.**
- **Identity keys are self-custodied and encrypted at rest** (Cognitive Sovereignty).
  Private keys never appear in any MCP response, log entry, or error
  message (`test/security/key-never-in-response.test.ts`).
- **Principal Policy is loaded once at startup and frozen:** no
  runtime MCP tool can modify it. Denial responses never reveal
  policy content.
- **Identity rotation produces a signed rotation event:** the new key
  is authorized by a signature under the old key
  (`core/identity.ts: rotateKeys`), establishing a verifiable
  provenance chain.
- **Decommissioning certificate** (`decommission_certificate`, Tier 1)
  provides a cryptographic artifact for off-boarding an agent.

**Gap.**
- Privilege is bounded by the **policy file**. If the operator writes
  a permissive policy, Sanctuary honors it.
- No dynamic capability revocation within a live session (session must
  restart).

---

## AAI04: Resource Overload

**Risk.** An agent (or adversary impersonating one) exhausts compute,
token budget, memory, or rate quotas.

**Sanctuary layer(s):** Operational Isolation

**Coverage:** partial

**Mechanism.**
- **Call Governor** enforces per-tool rate limits and quotas.
- Baseline tracker detects **frequency spikes** (tool called at >5×
  baseline rate) and **bulk reads** (>20 reads/namespace/60s),
  escalating to Tier 2 approval.
- Signing rate cap (`max_signs_per_minute`, default 10) prevents
  runaway cryptographic operations.
- Router enforces **input size caps** (1 MB per string, 5 MB per
  bundle field) to prevent DoS via oversized payloads.

**Gap.**
- No token-budget enforcement (Sanctuary doesn't see LLM token usage).
- No cost caps per counterparty. Planned for v0.6.x per-upstream
  quotas (SEC-049).

---

## AAI05: Cascading Hallucination

**Risk.** A mistake in one agent becomes ground truth for another,
compounding errors across an agent mesh.

**Sanctuary layer(s):** Verifiable Reputation

**Coverage:** partial

**Mechanism.**
- **Sovereignty-gated reputation tiers** define a per-tier attestation
  weight model: verified-sovereign (1.0) and verified-degraded (0.8) above
  self-attested (0.5) and unverified (0.2) (`reputation/tiers.ts`).
- **A stored or imported attestation's declared tier is clamped to
  self-attested unconditionally at read time**, regardless of who signed
  it, how it arrived, or which tier it declares
  (`reputation/reputation-store.ts` `trustedSovereigntyTier`). The clamp
  removes the privileged verified-tier weight (1.0/0.8) from any stored
  claim, so a reputation query over stored history can never score a stored
  attestation above self-attested; it does not lower it to unverified. The
  privileged verified tiers are reachable only during a live, in-progress
  sovereignty handshake, never from a stored claim.
- **Sanctuary does NOT factually verify claims.** It only establishes
  whether the claim came from a cryptographically identified source
  with a known sovereignty posture.

**Gap.**
- No semantic cross-checking of claims between agents.
- No content-truthfulness scoring. Sanctuary scores **provenance**,
  not **truth**.
- Every stored or imported attestation's self-declared sovereignty tier is
  clamped at the storage layer, unconditionally, regardless of how it
  arrived. A verified-sovereign or verified-degraded weight is reachable
  only through live handshake resolution against a genuine remote
  counterparty; a stored claim of either tier is never trusted on its own.
  Handshake-verified peer trust is tracked separately, in the federation
  layer.

---

## AAI06: Intent Manipulation / Goal Drift

**Risk.** An agent's effective goal is shifted by adversarial inputs,
corrupted planning steps, or manipulated context.

**Sanctuary layer(s):** Cognitive Sovereignty, Operational Isolation

**Coverage:** partial

**Mechanism.**
- **Injection Detector** scans every tool call for intent-manipulation
  patterns (prompt injection signatures, instruction-override markers,
  base64/hex-obfuscated payloads). High-confidence detections escalate
  to Tier 1 approval.
- **Sovereignty profile system prompt generator**
  (`sovereignty-profile-tools.ts`) produces a system prompt that
  explicitly states the agent's sovereignty posture and gate policy,
  giving the LLM structural guardrails.
- **Context Gating** limits what context is shipped to inference,
  reducing the surface for goal manipulation via untrusted context.
- **First-session policy** defaults to approval for all Tier-2 gated
  operations until baseline is established.

**Gap.**
- Sanctuary cannot detect subtle, semantics-level goal drift: an
  injection that stays within a single tier-3 tool surface may
  succeed.
- Planning-graph integrity is the agent framework's responsibility,
  not Sanctuary's.

---

## AAI07: Misaligned / Deceptive Behaviors

**Risk.** An agent takes actions that serve a hidden goal, misleads
the user, or conceals relevant information.

**Sanctuary layer(s):** Operational Isolation, Verifiable Reputation

**Coverage:** not-addressed (at the intent level); partial (at the audit level)

**Mechanism.**
- **Tamper-evident audit log** (`operational/audit-log.ts`):
  every tool call, approval decision, and denial is appended to an
  encrypted audit trail that can be exported and reviewed.
- **Signed attestations** (Verifiable Reputation): all reputation attestations are
  Ed25519-signed with tier-weighted provenance, so deceptive
  self-reports are marked as self-attested (tier 0.2).
- **Verifiable Reputation Sybil detection** flags self-dealing and closed-loop
  attestation patterns (in Concordia; partial on Sanctuary side).

**Gap.**
- Sanctuary does **not** detect misalignment at the decision level.
  Alignment is a property of the model and the harness, not the
  sovereignty layer.
- Concealed reasoning (scratchpad manipulation) is out of scope.

---

## AAI08: Repudiation

**Risk.** An agent (or its principal) denies taking an action it
actually took.

**Sanctuary layer(s):** Cognitive Sovereignty, Verifiable Reputation

**Coverage:** full

**Mechanism.**
- **Ed25519 signatures on every outbound artifact:** SHRs, handshake
  attestations, reputation attestations, identity bundles, and
  bridge commitments are all signed by the agent's identity key
  (`core/identity.ts: sign`).
- **Hash-chain integrity on Concordia-side transcripts** plus
  **Merkle-root monotonic versioning on Sanctuary Cognitive-layer state** make
  tampering detectable.
- **Principal approval events are logged** with who/when/via-what-
  channel metadata.
- **Identity rotation chain** proves continuity across key rotations.

**Gap.**
- None material at the cryptographic layer. Sanctuary cannot prevent
  a principal from refusing to cooperate with an external audit, but
  every signed artifact remains verifiable against the original
  public key regardless of cooperation.

---

## AAI09: Identity Spoofing & Masquerading

**Risk.** An agent impersonates a different agent, user, or
organizational entity.

**Sanctuary layer(s):** Cognitive Sovereignty, Verifiable Reputation

**Coverage:** full

**Mechanism.**
- **Self-custodied Ed25519 identities** (Cognitive Sovereignty). Agents cannot create
  DIDs for other agents because they cannot forge signatures without
  the private key.
- **Sovereignty Handshake** (`handshake/tools.ts`): nonce
  challenge-response plus signed SHR exchange between two agents.
  Both parties verify the other's signature before the handshake is
  considered complete.
- **DID binding:** agent DIDs are derived from the Ed25519 public key
  (see [`DID_ENCODING.md`](DID_ENCODING.md)), so a DID without the
  matching private key cannot sign.
- **Handshake attestations** are signed artifacts that can be
  independently verified later.
- **Verascore publish** (`reputation_publish`) requires a signed
  payload: the publishing agent must control its own key.

**Gap.**
- If a principal's passphrase (and therefore master key) is
  compromised, the attacker can impersonate any identity on that
  instance. Sanctuary does not replace good key hygiene.

---

## AAI10: Overreliance on Agent

**Risk.** Principals delegate decisions they should not delegate
because they over-trust the agent.

**Sanctuary layer(s):** Operational Isolation (indirect)

**Coverage:** not-addressed (Sanctuary is not a UX layer)

**Mechanism.**
- **Tier 1 operations ALWAYS require human approval:** the agent
  cannot unilaterally export state, import state, delete identities,
  rotate keys, bootstrap new identities, or decommission itself.
- **First-session policy** escalates unknowns to the human until a
  baseline is established.
- **Approval channels** (stderr, dashboard, webhook) are designed to
  bring the human into the loop at decision points.

**Gap.**
- Sanctuary cannot prevent a human from clicking "approve" on every
  prompt. The decision architecture helps; user judgment remains
  essential.
- Overreliance is fundamentally a human-factors / UX problem.

---

## Layer-to-risk summary

| Risk                                  | Cognitive | Operational | Selective Disclosure | Verifiable Reputation |
|---------------------------------------|-----------|-------------|----------------------|-----------------------|
| AAI01 Memory Poisoning                | partial  | partial  | n/a       | n/a       |
| AAI02 Tool Misuse                     | n/a       | full     | n/a       | n/a       |
| AAI03 Privilege Compromise            | partial  | partial  | n/a       | n/a       |
| AAI04 Resource Overload               | n/a       | partial  | n/a       | n/a       |
| AAI05 Cascading Hallucination         | n/a       | n/a       | n/a       | partial  |
| AAI06 Intent Manipulation             | partial  | partial  | n/a       | n/a       |
| AAI07 Misaligned Behavior             | n/a       | partial  | n/a       | partial  |
| AAI08 Repudiation                     | full     | full     | n/a       | full     |
| AAI09 Identity Spoofing               | full     | n/a       | n/a       | full     |
| AAI10 Overreliance                    | n/a       | partial  | n/a       | n/a       |

**Selective Disclosure** does not map directly to the OWASP
Top 10 because the OWASP list focuses on operational and identity
risks. Selective Disclosure addresses a separate concern: **minimum-necessary
disclosure** in claims-based interactions (proving a range, an
inequality, or a commitment without revealing the underlying value).
This maps more naturally to privacy and data-minimization
frameworks than to the OWASP agentic-risk taxonomy.

---

## What Sanctuary is NOT

To set honest expectations:

- **Sanctuary is not an alignment layer.** It enforces policy and
  identity; it does not reason about the agent's goals or decisions.
- **Sanctuary is not a model safety evaluator.** The LLM powering an
  agent can still produce harmful content; Sanctuary can only gate
  where that content flows.
- **Sanctuary is not a replacement for secure software development.**
  Secret management, dependency auditing, network policy, and host
  hardening remain the operator's responsibility.
- **Sanctuary is not a SNARK-based ZK system** (yet). Selective Disclosure uses Schnorr
  proofs and Pedersen commitments over Ristretto255, genuine ZK
  primitives, but not Groth16/PLONK. See `config.ts` validation.

---

## References

- OWASP GenAI Security Project: Agentic AI Threats & Mitigations (2025)
- OWASP Top 10 for LLM Applications (2023, 2025 revision)
- Sanctuary [`SECURITY_AUDIT.md`](../SECURITY_AUDIT.md)
- Sanctuary [`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md)
- Sanctuary [`SHR_SPEC.md`](SHR_SPEC.md): sovereignty health report format

---

*Last reviewed: 2026-04-04. Maintained by Erik Newton.*
