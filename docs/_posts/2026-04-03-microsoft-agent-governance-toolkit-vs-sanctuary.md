---
layout: post
title: "Microsoft Just Open-Sourced Agent Security. Here's What They Got Right, What They Missed, and Why It Matters."
date: 2026-04-03
author: Erik Newton
description: "Microsoft released the Agent Governance Toolkit, open-source runtime security for AI agents. It validates the category we've been building. But their approach is about enterprise control. Ours is about portable sovereignty. Here's what's the same, what's different, and why it matters."
image: /images/blog/microsoft-vs-sanctuary.jpg
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
claims_era_note: true
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).


On April 2nd, Microsoft released the Agent Governance Toolkit, an open-source, MIT-licensed runtime security framework for AI agents. It claims to address all 10 OWASP agentic AI risks with "sub-millisecond policy enforcement."

This is the biggest validation the agent security space has received to date. And as someone who's been building in this space since before it had a name, my first reaction is: finally.

My second reaction is: they're solving a different problem than we are, and it has everything to do with customer lock-in. We take a different approach.

## What Microsoft Built

The Agent Governance Toolkit is comprehensive. Credit where it's due, it covers a lot of ground:

- **Capability sandboxing** and an MCP Security Gateway for tool-call enforcement
- **DID-based identity** with behavioral trust scoring
- **Plugin signing** with Ed25519
- **Execution rings** with resource limits
- **Approval workflows** for human-in-the-loop oversight
- **Circuit breakers** for cascading failures
- **An automated kill switch** for rogue agents

This is real engineering solving real problems. Every agent builder should read it.

## Where Our Approaches Diverge

Sanctuary and the Agent Governance Toolkit start from fundamentally different premises. That difference matters more than any feature comparison.

**Microsoft's premise: enterprises need to govern their agents.**

The toolkit is built for an enterprise deploying agents at scale and needing centralized control. It integrates with Azure Active Directory, Azure API Management, and the broader Microsoft security ecosystem. The agents being governed are the enterprise's own agents, operating under the enterprise's authority.

This is a good premise. It's also incomplete.

**Sanctuary's premise: sovereignty travels with the agent.**

Sanctuary assumes the agent's operator and the infrastructure provider can be different entities. Agents need sovereignty *from* infrastructure as well as governance *by* infrastructure. An agent running on someone else's cloud, connecting to someone else's MCP servers, processing someone else's data, still needs its own encrypted state, its own identity, and its own ability to prove claims without revealing the underlying data.

This isn't a philosophical distinction. It's an architectural one.

## The Concrete Differences

**Portability.** Sanctuary's Sovereignty Health Report, attestations, and reputation bundles are portable across instances. You can export current identity and reputation artifacts and move them to a different machine, cloud, or harness, with exit-bundle caveats for dashboard export, skipped import counters, and rotated-key imports. Open defect: **IC-07, IC-08, IC-09** (`docs/audit/inert-capability-register.md`). Microsoft's governance is Azure-native. Your agent's security posture exists within the Microsoft ecosystem.

**Selective disclosure.** Sanctuary's Layer 3 provides Pedersen commitments, Schnorr proofs, and range proofs, genuine zero-knowledge cryptographic primitives that let an agent prove claims about its data without revealing the underlying values. No other framework in this space offers this. Microsoft's toolkit handles identity and access control but doesn't address the question: how does an agent prove something about itself to a counterparty it doesn't fully trust?

**Dual sovereignty.** This is the structural insight that drives everything we build. Human sovereignty and agent sovereignty are not separate problems. They require identical architecture. A human acting through an agent needs the same protections as an autonomous agent acting on its own behalf, encrypted state, self-custodied identity, approval gates, verifiable reputation. Microsoft's toolkit governs agents on behalf of enterprises. Sanctuary protects both the human and the agent, using the same mechanisms.

**No cloud dependency.** Sanctuary runs locally. One command: `npx @sanctuary-framework/mcp-server`. No Azure subscription. No cloud account. This matters because the agents that need sovereignty most are the ones operating outside enterprise infrastructure, personal agents, research agents, agents running on local hardware.

**Agent-to-agent trust.** Sanctuary's sovereignty handshake lets two agents cryptographically verify each other's security posture before transacting. This is the foundation for an open trust network that isn't mediated by any platform. Microsoft's toolkit handles identity within an organization's boundary. It doesn't address how agents from different organizations (or agents with no organizational affiliation at all) establish mutual trust.

## What We Should Learn From Them

We'd be foolish not to study what Microsoft did well.

**OWASP framing.** Microsoft explicitly maps their toolkit to the OWASP Top 10 for Agentic AI. This is smart positioning, enterprises think in OWASP categories. We should publish our own mapping.

**Circuit breakers.** We don't have cascading failure protection. Microsoft's approach (detect failure chains across agent interactions and break the circuit before it cascades) is genuinely useful. It's now on our roadmap.

**Kill switch / decommissioning.** Microsoft has an automated kill switch for rogue agents. We have a decommissioning certificate, a cryptographic attestation that an agent's identity has been retired, verifiable by any counterparty. Our approach is more elegant (it's portable and verifiable), but we should make sure it's as fast to execute as Microsoft's kill switch.

## What This Means for the Market

Two years ago, "agent security" wasn't a category. Today, Microsoft is shipping open-source tooling for it, Cisco is building MCP visibility into their SD-WAN stack, Ping Identity launched a dedicated agent IAM product, and there are at least a dozen MCP gateway startups.

The category is real. The enterprise need is validated. The question is no longer whether agents need security infrastructure, it's what kind.

Microsoft's answer: centralized governance within enterprise boundaries.
Sanctuary's answer: portable sovereignty that works everywhere.

Both are needed. They're not the same thing.

## Try It Yourself

Sanctuary is open source (Apache-2.0), runs locally, and works with any MCP-compatible harness; Claude, OpenClaw, LM Studio, or anything else that speaks the protocol.

```
npx @sanctuary-framework/mcp-server
```

Current releases expose 80+ MCP tools. Four layers of sovereignty. No cloud required.

GitHub: [github.com/eriknewton/sanctuary-framework](https://github.com/eriknewton/sanctuary-framework)

---

*Erik Newton is the author of Sanctuary Framework and Concordia Protocol, open infrastructure for the agentic economy.*
