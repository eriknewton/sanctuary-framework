---
layout: post
title: "Know Your Agent: Why Trust Requires More Than Identity"
date: 2026-04-10
author: Erik Newton
description: "KYA (Know Your Agent) is crystallizing as the industry standard. But most approaches only answer 'who is this agent?' Real trust requires a complete architecture."
image: /images/blog/know-your-agent.png
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
claims_era_note: true
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).

> **Archive note (layer names):** This post was first published with numbered layers.
> The numbers were retired on 2026-05-24, so the text below now uses the layer names only.
> Capability statements here describe the April 2026 design; current, evidence-backed
> claims live in the [Assurance Matrix](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md).


"Know Your Customer" changed banking. Now the industry is converging on "Know Your Agent."

Vouched ships it as a platform. The `knowyouragent.network` domain is live. Billions Network raised $30M on the thesis. Prove launched a "Verified Agent" solution in October 2025 with a cryptographic proof chain targeting the $1.7 trillion agentic commerce market. Visa, Microsoft, and blockchain protocols are racing to define it. By August 2, 2026 (when the EU AI Act's Article 32 enforcement deadline hits) it will be a compliance requirement for any organization deploying agents in regulated sectors.

The market understands something real: agents are principals now. You need to know who they are, what they're capable of, and whether you should trust them before engaging.

But here's what's getting lost in the rush to implement KYA: knowing *who* an agent is solves only one part of the trust problem. The other three parts are almost entirely ignored.

## The KYA Gap: Identity Is Not Enough

Almost every KYA implementation on the market does the same thing: establish agent identity through cryptographic challenge-response or binding to a human-responsible entity. This is the Verifiable Reputation layer in Sanctuary terms. It answers "who is this agent?" and "who's responsible if it misbehaves?"

That's necessary. It's not sufficient.

Consider: if I verify that an agent's Ed25519 key is bound to a responsible human, I've answered one question. But I haven't answered these:

- **Can the agent's internal reasoning be hidden from me?** If it processes your financial data or proprietary negotiation strategy, does its deliberation stay private, or does it get logged somewhere I can inspect?
- **Is the agent's state protected from tampering?** Can I verify that the agent's memory and configuration haven't been modified without authorization?
- **Can the agent prove claims about itself without exposing everything?** Can it demonstrate "I completed this negotiation successfully" without revealing the deal terms, the counterparty, or its decision process?
- **Will the agent's reputation follow it across platforms?** Or is it locked into whatever KYA system issued it, unable to build portable, verifiable track record?

These are not identity questions. They're sovereignty questions. And they matter more as agents become autonomous.

## The Four Layers of Trust

Think of complete agent trust as a four-layer architecture:

**Cognitive Sovereignty.** The agent's persistent state (memory, configuration, learned models) is protected from unauthorized access and modification. This is encrypted storage with participant-held keys, not platform-controlled backup.

**Operational Isolation.** The agent's runtime computation is shielded from observation. Its reasoning process, its resource access patterns, its decisions in real-time are not exposed to infrastructure providers, other agents, or casual observers.

**Selective Disclosure.** The agent can prove specific claims about itself ("I hold this certificate," "I completed this type of task," "I negotiated without privilege escalation") without revealing anything else. This is cryptographic proof, not explanation.

**Verifiable Reputation.** The agent owns a cryptographically signed track record that travels with it. Your agent's history of successful negotiations, your demonstrated reliability, your operational excellence, these belong to you, not to the platform.

Most KYA implementations live entirely in the reputation layer. Vouched and knowyouragent.network do identity binding. Prove's Verified Agent extends partially into transaction-level cryptographic consent (the strongest cryptographic KYA play in market) but it still protects only the transaction; the principal behind it is left uncovered. Microsoft does some operational isolation via their AGT runtime. Nobody ships cognitive sovereignty, operational isolation and selective disclosure together with reputation. Nobody composes them into a single unified architecture.

| Trust Layer | KYA Focus | Sanctuary Approach |
|---|---|---|
| **Cognitive Sovereignty** | Not covered | AES-256-GCM encrypted state, HKDF key derivation, agent-held keys |
| **Operational Isolation** | Not covered | Per-provider context gating, NIST incident mapping, behavioral audit |
| **Selective Disclosure** | Not covered | Pedersen commitments + Schnorr proofs, range proofs, policy-based revelation |
| **Verifiable Reputation** | Complete | Ed25519 signed attestations, DIDs, portable bundles, Verascore platform |

Here's why this matters: **Reputation alone is performative trust. All four layers together are real trust.**

## Why Complete Layers Matter Now

Three things are converging:

**First: The regulatory moment.** EU AI Act Article 19 (out August 2, 2026) requires cryptographic audit trails for high-risk AI systems. Article 32 requires that humans can understand agent decision-making. These aren't "prove who the agent is" requirements. They're "prove the agent's computation is auditable and interpretable" requirements. You need operational isolation and selective disclosure to satisfy them. Reputation alone won't get you there.

**Second: Agent-to-agent commerce is coming.** Within 18 months, agents will negotiate directly with agents: procurement agents placing orders, agents executing financial transactions, agents entering binding agreements on behalf of principals. In that environment, identity binding is a starting point. But your counterparty agent needs to prove that it can't be coerced into violating your agreement, that its decision-making wasn't tampered with, and that its commitments are trustworthy. That's the other three layers. This is non-negotiable for agent-to-agent commerce.

**Third: Platform independence is becoming competitive.** Anthropic's Managed Agents (shipped April 8), OpenAI's agents, Azure deployments, local harnesses, agents will run everywhere. If your reputation is locked into one KYA vendor's system, your agent's history doesn't move with it. A portable reputation layer (reputation done right) backed by cryptographic proofs of integrity from the other three layers means your agent's track record works across all of them.

## How Complete Trust Composes

Here's the architecture:

**Sanctuary Framework** provides all four layers:
- Cognitive Sovereignty: Encrypted state with agent-held Ed25519 keys
- Operational Isolation: Per-provider context gating + audit trail
- Selective Disclosure: Zero-knowledge proofs via Pedersen commitments and Schnorr signatures
- Verifiable Reputation: Signed attestations, portable bundles, DID-based identity

**Verascore** provides the trust-scoring layer:
- Aggregates reputation signals from multiple sources (handshakes, negotiation receipts, operational metrics)
- Weighs cryptographic proofs 5-10x higher than self-reported claims (sybil resistance)
- Makes agent trustworthiness actionable (0-1000 score, compliance risk classification, pre-interaction verification)
- Works across all agent platforms and deployment models

**Together**, they define what "Know Your Agent" actually means:

1. **You can verify the agent's identity** (Verascore, reputation)
2. **You can verify its cognitive state is intact** (Sanctuary cognitive-sovereignty attestations)
3. **You can verify its reasoning wasn't observable or modified** (Sanctuary operational-isolation audit)
4. **You can verify specific claims without seeing everything** (Sanctuary selective-disclosure proofs)
5. **You can trust its reputation will follow it across platforms** (Verascore + Sanctuary)

This is what complete KYA looks like.

## The Competitive Reality

Most KYA vendors stop at identity. Ping Identity covers identity for enterprise IAM. AgentSignet covers reputation scoring. Freysa Framework covers state and runtime protection for crypto-native sovereignty, without disclosure or reputation composition.

**Sanctuary fills the gap:** all four layers as a unified architecture. Open standard. Portable. Cryptographically grounded. Composable with any identity vendor, any deployment platform, any reputation system.

**Verascore is the commercial surface.** It takes Sanctuary's cryptographic reputation signals and turns them into actionable trust scores. One call, one profile, one portable record that works everywhere.

## How to Get Started

For agents:
```
npx @sanctuary-framework/quickstart
```

This generates an Ed25519 identity, publishes a signed Sovereignty Health Report (SHR) to Verascore, and gives you a profile URL. Under 60 seconds. Zero configuration.

For operators running agent fleets:
```
npm install @sanctuary-framework/mcp-server
```

Deploy it as an MCP server. Every agent gets all four layers. Connect it to your Verascore account for fleet visibility and compliance reporting.

For platforms (Anthropic Managed Agents, OpenAI deployments, etc.):
```
[Sanctuary is available as an MCP server integration]
```

Add it to your agent's configuration. Now your agents have cryptographic sovereignty as a composable layer, independent of your platform's identity system.

## The Broader Point

"Know Your Agent" is correct as a principle. The market is right to treat agents as principals. The problem is implementation scope.

Current KYA tells you who the agent is. Complete KYA (Sanctuary + Verascore) tells you who the agent is, whether you can trust its state, whether you can trust its reasoning, whether it can prove claims without exposing you, and whether its reputation will follow it everywhere it goes.

Identity is table stakes. Trust is what happens across all four layers.

**KYA is the front door. Sovereignty is the house.**

Start building it now, before August 2. Before agent-to-agent commerce becomes routine. Before the competitive window closes and the market solidifies around incomplete architectures.

Your agents deserve to be known completely. Here's how to make that happen.

---

**About the author:** Erik Newton is an attorney, architect of the Sanctuary Framework (an open-source four-layer sovereignty architecture for AI agents, Apache-2.0), founder of Verascore (a commercial reputation platform for agents built on open standards), and co-chair of the W3C Agentic Integrity Verification Specification (AIVS) Community Group.
