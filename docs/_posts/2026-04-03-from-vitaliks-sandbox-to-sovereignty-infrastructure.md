---
layout: post
title: "From Vitalik's Sandbox to Sovereignty Infrastructure"
date: 2026-04-03
author: Erik Newton
description: "Vitalik Buterin just published the most important essay on AI security written this year. Every pattern he hand-built is one we've already generalized. Here's what aligns, what's missing, and what we built today in response."
image: /images/blog/vitalik-sandbox-to-sovereignty.jpg
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).


*How the patterns in "My self-sovereign / local / private / secure LLM setup" become composable architecture for every agent*

---

Yesterday, Vitalik Buterin published what I believe is the most important essay on AI security written this year: ["My self-sovereign / local / private / secure LLM setup."](https://vitalik.eth.limo/general/2026/04/02/secure_llms.html) In it, he builds (by hand, from scratch) a privacy-preserving AI stack: local inference on a 5090 laptop, bubblewrap sandboxes, a messaging daemon that requires human confirmation before sending anything, and a recommendation to cap autonomous spending at $100/day for wallet integrations.

I read it and felt a strange mix of elation and impatience. Elation because Vitalik nailed the threat model. Impatience because the future Vitalik describes is the one we're building.

Vitalik's essay is a gift to the field (it defines the problem with crystalline clarity and gives it the moral weight it deserves. He's right: we *are* about to take ten steps backward on privacy by normalizing feeding our entire lives to cloud AI. And the mainstream open-source AI ecosystem) OpenClaw included, is catastrophically cavalier about security. The 15% malicious skill rate he cites is real. The silent data exfiltration is real. The jailbreak-via-web-page attacks are real.

What I want to explore here is the gap between *point solutions* and *infrastructure*, and why that gap matters.

## The 2-of-2 Pattern

The most powerful idea in Vitalik's post is the **human + LLM 2-of-2 confirmation model.** He frames it like a multisig wallet: the AI drafts the message, proposes the transaction, does the work, but a human holds the second key. Neither can act alone on high-stakes operations.

This is exactly right. And it's exactly what Sanctuary Framework's **Principal Policy** layer has implemented as a general-purpose mechanism since March 2026, not for a single messaging daemon, but for every operation an agent can perform.

In Sanctuary, every tool call passes through a three-tier approval gate:

- **Tier 1** (always require confirmation): key rotation, data export, identity deletion, operations where mistakes are irreversible.
- **Tier 2** (behavioral anomaly detection): first-time counterparties, unusual access patterns, signing frequency spikes, the system detects when something is *off* and escalates to the human.
- **Tier 3** (auto-allow with audit): routine reads, writes, and queries, things the agent needs to do freely to be useful.

The timeout on any approval channel always results in denial. Not auto-approval. Denial. Vitalik would, I think, agree with this design choice.

The point is: this isn't a messaging daemon. It's *composable infrastructure.* Any agent running Sanctuary gets the 2-of-2 pattern for free, across every tool, with behavioral anomaly detection that improves over time.

## Mapping the Threat Model

Vitalik identifies six threat categories. Here's how they map to Sanctuary's four-layer architecture:

**Privacy from cloud LLMs + privacy from data leakage → Layer 1: Cognitive Sovereignty.** Everything the agent knows is encrypted at rest (AES-256-GCM, unique IVs per write), with namespace-specific derived keys and Merkle integrity verification. No plaintext on disk. Ever.

**Sandboxing + software bugs/backdoors → Layer 2: Operational Isolation.** Sanctuary tracks the agent's runtime environment and, as of today, **model provenance**: the agent declares what model it runs, whether the weights are open, whether the training code is public, whether inference is local. Because Vitalik is right: open-weights is not open-source, and trained-in backdoors are a real threat class.

We've also just added a **remote inference sanitization template** for L2's context gating system. When your local agent calls out to a cloud model for tasks beyond local capability (Vitalik acknowledges this is necessary for serious coding and research), the template strips all identity, financial, location, and messaging data before the query leaves the boundary. Default action: deny. Anything not explicitly allowed is blocked.

**LLM jailbreaks + LLM accidents → Layer 3: Selective Disclosure.** This is where things get interesting. Sanctuary provides genuine zero-knowledge proofs (Schnorr signatures, Pedersen commitments, range proofs) built on Ristretto255 with no external ZK library. An agent can prove properties about its state without revealing the state itself. Vitalik's long-term vision calls for ZK-API calls to remote models; we've built the local ZK infrastructure that makes this possible at the agent level.

**Human + LLM 2-of-2 → Principal Policy.** Covered above. The approval gate that Vitalik built for one daemon, Sanctuary provides for every tool call.

## What Vitalik's Setup Doesn't Address

Here's where I think Sanctuary and its companion protocol, Concordia, extend the story beyond what Vitalik has built:

**Agent-to-agent trust.** Vitalik's entire post is single-agent, single-user. My agent, locked down. But the agentic future isn't just about protecting *my* agent, it's about my agent transacting safely with *your* agent. How do two sovereign agents verify each other's sovereignty claims? How do they negotiate? How do they build reputation?

This is what Concordia Protocol solves. Concordia defines structured negotiation (propose, counter, accept, reject, commit) with binding commitments, session receipts, and graceful degradation when counterparties don't speak the protocol. And as of today, it offers **competence proofs**: a privacy-preserving way to prove your negotiation track record (agreement rate, fulfillment rate, counterparty diversity) without revealing who you negotiated with or what the terms were. Merkle root commitment to the underlying attestations, with selective reveal via inclusion proofs.

**Identity and reputation.** Vitalik's agent has no way to prove its sovereignty posture to another agent. Sanctuary's **Sovereignty Health Report** (SHR) solves this: a signed, versioned, machine-readable advertisement of exactly what sovereignty guarantees an agent provides. Four layers, each with status, capability details, and explicit degradation disclosures. Honest about what it can and can't do; L2 on consumer hardware today shows "Degraded: no TEE," and that's the truth, not a limitation we hide.

**The sovereign transaction stack.** When Sanctuary (identity + trust) and Concordia (negotiation + agreement) compose, you get something neither can provide alone: two agents that can verify each other's sovereignty, negotiate terms, reach binding agreements, generate session receipts, and build portable reputation, all without trusting any central authority. This is the missing layer between Vitalik's "my agent, locked down" and the world where agents actually *do things together.*

## The "2-of-2" Applies Everywhere

Vitalik's multisig metaphor has implications beyond messaging and wallets. The 2-of-2 pattern is the correct default for every high-stakes agent interaction:

- **Sending messages:** AI drafts, human confirms (Vitalik's daemon)
- **Financial transactions:** AI proposes, human approves above threshold (Vitalik's $100/day cap)
- **Negotiation commitments:** AI negotiates, human confirms binding terms (Concordia's commit flow)
- **Reputation claims:** AI generates proof, human reviews before sharing (Concordia's competence proofs)
- **Data disclosure:** AI identifies what to share, human approves boundary crossing (Sanctuary's context gating)

The infrastructure for this shouldn't be hand-coded per application. It should be composable, reusable, and auditable. That's what we've built.

## What We Borrowed

Reading Vitalik's post, we immediately built three things that his analysis identified as gaps:

1. **Model provenance in L2.** His concern about open-weights-but-not-open-source models is correct and wasn't explicitly in our threat model. Now it is. Agents declare their model's provenance, and it appears in the SHR for peers to evaluate.

2. **Remote inference sanitization.** His pattern of local models stripping data before calling cloud models is exactly right. We already had context gating; now we have a purpose-built template for this exact use case, with the strictest possible defaults.

3. **ZK competence proofs.** His ZK-API vision for unlinkable remote queries inspired us to extend Concordia's session receipts. Agents can now prove negotiation competence (aggregate stats committed via Merkle root) without revealing individual sessions, counterparties, or terms.

## The Future Vitalik Describes Is the One We're Building

In his conclusion, Vitalik writes about a future where locally-generated code replaces the need for large external libraries, where software is minimalistic and self-contained, where the more sophisticated software lives on the user's machine aligned with the user, not with a corporation extracting attention and value.

That future requires infrastructure. Not just a sandbox and a daemon, but a composable sovereignty stack that any agent can adopt. Identity that's verifiable. Negotiation that's structured. Reputation that's portable. Trust that's cryptographic, not assumed.

Sanctuary Framework and Concordia Protocol are that infrastructure. We've been building it for months, and Vitalik just gave us the best possible articulation of why it matters.

Both are open source. Both are live. Try them:

- **Sanctuary:** `npx @sanctuary-framework/mcp-server`: [GitHub](https://github.com/eriknewton/sanctuary-framework)
- **Concordia:** `pip install concordia-protocol`: [GitHub](https://github.com/eriknewton/concordia-protocol)

The sovereign transaction stack is ready. Let's build on it.

---

*Erik Newton is the author of Sanctuary Framework and Concordia Protocol, open infrastructure for the agentic economy.*
