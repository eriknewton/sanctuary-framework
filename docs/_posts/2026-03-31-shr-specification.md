---
layout: post
title: "SHR v1.0: A Machine-Readable Sovereignty Specification"
date: 2026-03-31
author: Erik Newton
description: "The Sovereignty Health Report (SHR) is a machine-readable, cryptographically signed document that describes an agent's sovereignty posture. Version 1.0 of the specification is now published."
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).


The Sovereignty Health Report is the most consequential piece of Sanctuary's architecture that nobody talks about. It's a machine-readable, cryptographically signed document that answers a simple question: *what sovereignty guarantees does this agent actually provide?*

Version 1.0 of the SHR specification is now published. The full spec is available [in the repository](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/SHR_SPEC.md) and the reference implementation ships in `@sanctuary-framework/mcp-server` v0.3.1.

## What an SHR Contains

An SHR is a JSON document signed with Ed25519 over canonical form (sorted keys, compact representation). It reports on four sovereignty layers:

**Cognitive Sovereignty.** What encryption protects state at rest? Who holds the master key? Is the state portable? The reference implementation reports AES-256-GCM encryption with self-custodied keys derived via Argon2id.

**Operational Isolation.** What computational boundaries exist? Is hardware attestation available? Today, most agents report process-level isolation only, no TEE. The SHR makes this visible instead of assumed.

**Selective Disclosure.** Can the agent prove claims without full revelation? The reference implementation supports Pedersen commitments, Schnorr proofs, and bit-decomposition range proofs, genuine zero-knowledge primitives, though not yet SNARKs.

**Verifiable Reputation.** Is the agent's reputation portable and verifiable? What attestation format does it use? The reference implementation uses EAS-compatible signed attestations with sovereignty-gated weighting.

Every SHR also includes a **degradations array**: an honest accounting of known limitations. If an agent reports "process-level isolation only (no TEE)," that's a degradation. If it reports "commitment schemes only (no SNARKs)," that's a degradation. Honest over optimistic.

## Three Functions

The SHR serves three distinct purposes:

**1. Capability advertisement.** An agent presents its SHR to counterparties before transacting. "Here's what I actually provide. Assess whether it meets your requirements."

**2. Mutual verification.** Two Sanctuary agents perform a sovereignty handshake, a nonce challenge-response with SHR exchange. This proves liveness (the SHR was generated for this specific interaction) and establishes mutual trust. After a handshake, both agents know each other's sovereignty posture and have cryptographic proof of the exchange.

**3. Compliance artifact.** This is the time-sensitive one. The EU AI Act reaches full enforcement on August 2, 2026 (four months from now. Articles 9 (risk management), 14 (human oversight), 15 (security), 22 (audit trail), and 42 (conformity assessment) all require documentation that an SHR naturally provides. The SHR isn't a conformity assessment itself) it's the machine-readable evidence that a conformity assessor evaluates.

## Sovereignty-Gated Reputation

SHRs integrate with Sanctuary's reputation system through sovereignty tiers. Attestations from agents with stronger sovereignty postures carry more weight:

| Tier | Requirement | Weight |
|------|------------|--------|
| `verified-sovereign` | Handshake complete, all layers active | 1.0 |
| `verified-degraded` | Handshake complete, Cognitive Sovereignty active, others degraded | 0.8 |
| `self-attested` | SHR presented, no handshake | 0.5 |
| `unverified` | No SHR | 0.2 |

This creates a structural incentive for agents to invest in sovereignty infrastructure. A procurement agent evaluating suppliers will weight reputation from sovereign agents 5x higher than from unverified ones. The incentive is architectural, not marketing.

## Try It

```bash
npx @sanctuary-framework/mcp-server
```

Generate an SHR:
```
sanctuary/shr_generate { "validity_minutes": 60 }
```

Verify a received SHR:
```
sanctuary/shr_verify { "shr": { ... } }
```

The full specification: [docs/SHR_SPEC.md](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/SHR_SPEC.md)

Reference implementation source: [github.com/eriknewton/sanctuary-framework](https://github.com/eriknewton/sanctuary-framework)
