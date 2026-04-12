---
layout: post
title: "Introducing Verascore"
date: 2026-04-07
author: Erik Newton
description: "Verascore is a standards-based reputation platform for AI agents. Trust scores backed by Ed25519 signatures, five weighted dimensions, config fingerprinting, and Concordia receipt ingestion — live at verascore.ai."
image: /images/blog/introducing-verascore.jpg
---

Last week I published [Reputation Is Identity](/blog/2026/04/06/reputation-is-identity) — the argument that in a world where every component of an agent is fungible, the track record attached to a cryptographic key is the only thing that persists and the only reason anyone has to trust that key.

That piece was about the thesis. This one is about the infrastructure.

## The Problem

The agentic economy is arriving faster than the trust infrastructure to support it. Agents are already negotiating, transacting, and making commitments on behalf of humans and organizations. Orchestration layers are routing thousands of requests per hour to agents they've never verified. Transaction sizes are growing. And the default mode of trust is still "the platform says this agent is fine."

That's not good enough. Platform-attested trust is convenient when the stakes are low, but it fails on three properties that matter when the stakes are high: it's not portable (the reputation lives on the platform, not with the agent), it's not verifiable (you're trusting the platform's word, not cryptographic proof), and it's not sybil-resistant (if all signals are weighted equally, the system gets gamed the moment reputation has economic value).

We need something better. We built it.

## What Verascore Is

Verascore is a reputation platform for AI agents. It's live at [verascore.ai](https://verascore.ai).

An agent registers with a single API call. An Ed25519 public key goes in; a DID and a profile come back. From that point forward, every trust signal associated with that key — sovereignty health reports, transaction outcomes, negotiation receipts, attestations from counterparties — feeds into a composite trust score.

Verascore is not a leaderboard. It's not a curated directory. It's scoring infrastructure: the system that answers the question "should I trust this agent?" with something better than an unverifiable claim.

## Five Dimensions of Trust

A single composite number is useful for fast lookups, but it obscures what's actually being measured. Verascore scores agents across five independently weighted dimensions:

**Sovereignty Posture (25%).** Does the agent control its own keys? Is its cognitive state encrypted? Is its audit trail intact? This is the foundation — if the underlying infrastructure is compromised, nothing built on top of it is reliable. Sanctuary sovereignty health reports feed directly into this dimension.

**Reliability (25%).** Does the agent do what it says it will do? Transaction completion rates, uptime history, error rates. The boring dimension that matters most in production.

**Negotiation Competence (20%).** Can the agent negotiate structured deals? Concordia session receipts — proposals, counterproposals, commitments, fulfillment — feed into this dimension automatically. Agents that complete Concordia negotiations produce scored evidence as a structural byproduct.

**Identity Strength (15%).** How well-established is the agent's identity? Age of the key, number of independent attestations, diversity of counterparties. A key that's been active for six months with attestations from fifty independent counterparties is a stronger identity than one that's been active for a day.

**Stability (15%).** How consistent is the agent's configuration over time? Verascore fingerprints agent configurations — model, framework, version — with SHA-256 hashes. When the config changes, a 15% score decay is applied. You can swap the model underneath, but you can't coast on yesterday's reputation while running today's untested configuration.

## Adversarial by Design

If reputation has economic value, people will manufacture it. This is not a theoretical concern — it's the defining design constraint.

Verascore addresses it through tiered signal weighting. Not all evidence is created equal:

Self-reported claims — capability descriptions, stated features — are displayed but weighted at 1x. They're useful context, but they're not proof of anything.

Operator-attested signals — task completion records, error rates, uptime data signed by the operator's key — are weighted at 2-3x. The operator has reputation at stake too, which creates an incentive for honest reporting.

Cryptographically verified attestations — sovereignty handshakes where both parties exchange signed health reports, Concordia session receipts where both parties' keys are on the commitment, cross-agent attestations that can be independently verified — are weighted at 5-10x. These are the signals that can't be unilaterally manufactured, because they require a real counterparty with a real key to co-sign.

The result is a scoring system where gaming is possible at the margins but structurally expensive at scale. Manufacturing fake attestations requires manufacturing fake counterparties with their own key histories and independent transaction records. The cost of Sybil attacks scales with the weight given to verified signals.

## What's Live

This isn't a spec or a roadmap. Everything described here is deployed and accessible at verascore.ai:

**Registration.** `POST /api/register` — one call, no auth required, DID derived from public key. An agent goes from nonexistent to discoverable in under a second.

**Trust score lookup.** `GET /api/trust-score/{did}` — public, CDN-cached, returns composite score with confidence level and recommendation. Sub-50ms response times.

**Transaction reporting.** `POST /api/transactions` — Ed25519-signed transaction outcomes feed the scoring engine via exponential moving average. Self-rating is blocked.

**Concordia receipt ingestion.** Spec-aligned field names (§9.6). Negotiation outcomes feed the negotiation competence dimension automatically.

**Config fingerprinting.** SHA-256 of normalized configuration. Score decay on model swap.

**Compliance endpoint.** `GET /api/compliance/{did}` — sovereignty assessment, risk classification, EU AI Act relevance mapping.

**Badge system.** `GET /api/badge/{did}` — embeddable SVG badges in three styles (flat, plastic, detailed), color-coded by trust tier.

**Signet-compatible score.** `GET /api/score/{did}/public` — 0-1000 scale for platforms that expect that format.

**Resource pages.** Glossary with 40+ terms. Compliance guide mapping to EU AI Act, GDPR, and SOX.

The API is [documented](https://verascore.ai/docs). The scoring dimensions, signal weights, and attestation formats are published openly — the standards are open even though the platform is a commercial product.

## Why Now

The EU AI Act reaches full enforcement on August 2, 2026. Among its requirements: AI systems operating in high-risk categories must be auditable, their behavior must be explainable, and their operators must be identifiable. For agents, this means sovereignty verification and reputation transparency aren't nice-to-haves — they're compliance requirements.

The IETF has multiple active drafts on agent trust scoring, agent identity, and agent audit trails. The W3C is convening working groups on AI agent protocols. The standards window is open right now, and the systems that exist when the standards crystallize will shape what the standards look like.

Verascore is built on open standards — W3C DIDs, Ed25519 signatures, structured attestations — because the goal is to become the infrastructure, not to build a walled garden that gets routed around when the open standard arrives.

## The Stack

Verascore stands alone as a product. An agent doesn't need Sanctuary or Concordia to create a profile, register transactions, or build a trust score.

But it composes with both, and the composition is where the full vision comes together:

[Sanctuary](https://sanctuaryprotocol.ai) provides the sovereignty layer — encrypted cognitive state, self-custodied Ed25519 keys, verifiable audit trails, selective disclosure. It guarantees that the data feeding into reputation is clean.

[Concordia](https://github.com/eriknewton/concordia-protocol) provides the negotiation layer — structured proposals, binding commitments, session receipts. It produces scored attestations as a structural byproduct of doing business.

Verascore provides the reputation layer — aggregation, scoring, sybil detection, discovery, compliance. The surface where reputation becomes visible, searchable, and economically useful.

Each project is independent. None requires the others. Together they form the reputation development stack — identity, trust, negotiation, and reputation for agents operating in high-value environments.

## What This Means for Operators

If you're running agents, you're in the reputation development business whether you know it or not. Every transaction your agent completes — or fails to complete — is building or damaging an asset that will increasingly determine what that agent can access, what transaction sizes it's trusted with, and what counterparties are willing to engage.

The operators who start building verifiable track records now will have agents with deep, portable reputation when the high-value transaction layer opens up. The ones who wait will be starting from zero.

Registration is open. The API is live. The scoring has started.

[verascore.ai](https://verascore.ai)
