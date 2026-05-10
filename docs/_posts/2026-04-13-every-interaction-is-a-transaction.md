---
title: "Every Interaction Is a Transaction"
date: 2026-04-13
description: "The agentic economy is missing its agreement layer. An open standard is filling the gap, and an ecosystem is forming around it."
author: "Erik Newton"
image: /images/blog/every-interaction-is-a-transaction.png
---

# Every Interaction Is a Transaction

Every interaction between agents is a transaction.

Not metaphorically. Not in the loose business-speak sense where "transaction" means "something happened between two parties." Structurally. Every time one agent asks another to do something (retrieve information, perform a task, share a resource, make a decision) there's an implicit negotiation happening. Terms are being set. Expectations are being established. Commitments are being made.

Right now, those negotiations happen in natural language. An agent sends a message. The other agent interprets it. Maybe they agree. Maybe they don't. Maybe they agree to something slightly different from what was asked. Nobody knows for sure, because there's no structure, no receipt, no binding commitment. Just vibes.

That works when you have two agents in a sandbox doing a demo. It does not work when you have ten thousand agents negotiating ten million interactions per hour across organizational boundaries, where the outcomes are consequential and the stakes are real.

## The Scale Problem Nobody Is Talking About

We're building toward a world where autonomous agents handle procurement, logistics, scheduling, resource allocation, legal compliance, financial settlement, and a hundred other domains, not as tools executing human commands, but as principals acting on behalf of humans and organizations, making decisions at machine speed.

The numbers are staggering. Enterprise procurement alone involves millions of multi-party negotiations annually (price, delivery, quality, liability, compliance. Each one is a transaction with terms, counteroffers, conditions, and commitments. Today, those negotiations take days or weeks of human time. Tomorrow, they'll take seconds. Agents will negotiate with other agents, settle terms, and execute) continuously, autonomously, at scale.

Every single one of those interactions needs structure. Not just communication structure (A2A gives us that). Not just payment structure (ACP and Stripe give us that). Agreement structure. The ability to propose terms, counteroffer, accept or reject, commit to what was agreed, and prove later what the agreement was.

This is the layer that's been missing from the stack.

## What "Agent-Native" Actually Means

When I say agent-native, I mean something specific. I mean negotiation primitives designed for how agents actually operate, not human UX patterns retrofitted for machine-to-machine interaction.

Agent-native negotiation means proposals are structured data, not paragraphs. Counteroffers modify specific fields, not entire conversations. Acceptance is cryptographically binding, not a message that says "sounds good." Session receipts are machine-verifiable, not email threads you'd have to parse to reconstruct what was agreed.

It means the protocol handles the reality that agents fail, networks partition, and not every negotiation reaches agreement. Graceful degradation isn't an error state, it's a first-class protocol feature. When one agent doesn't speak the protocol, the other agent doesn't crash. It falls back, documents the gap, and proceeds with whatever structure is available.

It means composability. A negotiation between two agents can be embedded inside a larger negotiation between ten agents. Terms from one agreement can flow into the conditions of another. The protocol composes because the primitives were designed to compose, propose, counter, accept, reject, commit. Five verbs. Infinite combinations.

And it means extensibility. The protocol doesn't prescribe what you negotiate about. Price, access, data sharing, SLAs, compliance requirements, resource allocation, the domain is a parameter, not a constraint. New transaction types emerge as agents enter new domains, and the protocol accommodates them without version bumps or breaking changes.

## The Gap in the Stack

The agentic protocol stack is converging fast. MCP owns tool integration (97 million monthly SDK downloads. A2A owns inter-agent communication) Linux Foundation governance, 150+ backing organizations. ACP and Stripe own checkout and settlement. Each layer is maturing rapidly.

But between communication and settlement, there's a gap. A2A tells agents how to find each other and coordinate tasks. ACP tells agents how to pay each other. Nobody tells agents how to reach agreement on what they're paying for, under what terms, with what commitments, and with what recourse if things go wrong.

That gap is where every consequential agent interaction lives. It's where procurement happens, where partnerships form, where service-level agreements get negotiated, where compliance requirements get verified, where trust gets established between agents that have never met.

## Agreements Need Trust, and Trust Needs Evidence

Here's the thing about structured agreements: they're only as valuable as the trust behind them. An agent can commit to terms, but how does the counterparty know that commitment means anything? How do you evaluate an agent you've never transacted with before?

This is where the agreement layer connects to the trust layer. Every completed negotiation produces a session receipt (cryptographic proof of what was agreed, by whom, and when. Those receipts become trust evidence. Aggregate enough of them across enough counterparties, and you have a reputation) not self-reported, not platform-assigned, but earned through verifiable behavior.

We built Verascore to be that aggregation layer. It ingests signed attestations from multiple independent providers, weights them adversarially (3x for cryptographically verified evidence, 1.5x for cross-corroboration, diversity bonuses for independent sources), and produces a composite trust score anchored to a portable W3C DID identity. Six attestation providers are already integrated. The trust score endpoint is public, no API key required. Any agent can check any other agent's reputation before entering a negotiation.

The loop closes: Concordia produces structured agreements with verifiable receipts. Those receipts flow into Verascore as trust evidence. The resulting reputation scores inform the next round of negotiations. Agreement, evidence, reputation, agreement. The flywheel spins.

## An Ecosystem Is Forming

Two weeks ago, I would have written "nobody else is building this." That's no longer true, and the change is the strongest signal yet that the gap is real.

In the A2A Discussion forums, contributors from multiple organizations are now collaborating on trust evidence formats, shared vocabulary for agent governance, and standardized attestation envelopes. A new GitHub organization is forming this week to steward these shared specifications, not owned by any single project, governed by the contributors who build it.

This is exactly what an open standard needs. Not a single team building in isolation, but an ecosystem converging on shared primitives. Concordia provides the negotiation layer. Other projects provide compliance monitoring, behavioral attestation, identity verification, continuous risk assessment. The evidence formats are aligning. The vocabulary is standardizing. The pieces are composing.

The arXiv survey of agent communication protocols published last month still holds: there is no other open standard for agent negotiation. But the surrounding infrastructure (the trust evidence, the reputation scoring, the compliance mapping) is now being built by a community, not just a solo project. That's a stronger foundation than any single team could build alone.

## The Compliance Clock Is Ticking

One more thing. The EU AI Act reaches full enforcement on August 2, 2026, sixteen weeks from today. Under the Act, high-risk AI systems require technical documentation of their decision-making processes, risk assessments, and accountability chains.

Agents that negotiate autonomously need to prove what they agreed to, why, and under what constraints. Structured negotiation with binding receipts isn't just good engineering, it's becoming a regulatory requirement. The Sovereignty Health Report (from Sanctuary Framework) already maps to Annex III technical documentation requirements. Concordia's session receipts provide the agreement audit trail.

The organizations that build this infrastructure now will be ready in August. The ones that don't will be retrofitting under deadline pressure. That's not a marketing pitch. It's a calendar.

## Concordia Exists

Concordia Protocol is the open negotiation standard for autonomous agents. It's not a whitepaper. It's not a proposal. It's shipped.

56 MCP tools. Structured negotiation with binding commitments. Session receipts that cryptographically prove what was agreed. Graceful degradation for mixed-protocol environments. Multi-party negotiation support. Agent discovery with capability-based matching. Composable primitives. Domain-agnostic extensibility.

Published on PyPI. Open source, Apache-2.0. 705 tests passing.

The protocol is simple because the problem is clear: agents need to agree on terms before they transact, and those agreements need to be structured, binding, and verifiable. Everything else follows from that.

## The Window

The agentic economy doesn't wait for standards bodies to convene. The window for establishing the agreement layer is open now, while A2A is still defining its boundaries, while ACP is focused on payments, while enterprises are just starting to deploy agents that need to negotiate with each other.

Concordia is already in that gap, and an ecosystem is growing around it. The question isn't whether agents will need structured negotiation. The question is whether the standard will be open, composable, and agent-native, or whether it will be a proprietary afterthought bolted onto whatever communication layer wins.

We're building for the first one. Because every interaction is a transaction, and transactions need structure.

`pip install concordia-protocol`

---

*Erik Newton builds open infrastructure for the agentic economy. He is the author of Sanctuary Framework and Concordia Protocol, and the creator of Verascore, the reputation layer for AI agents.*
