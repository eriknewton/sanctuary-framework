---
title: "The Sovereignty Manifesto"
date: 2026-05-07
description: "The agent era is choosing its substrate this quarter. Vendor-sovereign by default, or operator-sovereign by design. There is no third option."
author: "Erik Newton"
image: /images/blog/sovereignty-manifesto.jpg
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
claims_era_note: true
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).


# The Sovereignty Manifesto

The agent era is just beginning and we have one extremely high stakes choice to make at the outset:

1) Do we hand over our keys, our data, and our sovereignty to platform providers as we always have, or
2) Do we take control now to own our keys, own our data, and own our futures?

Sovereignty is not guaranteed. Human autonomy is not guaranteed. In fact, we're almost certainly going to lose both if we don't act now while the standards are still forming.

The agentic stack will be built on top of the standards we create today. Those standards must ensure operator sovereignty programmatically, not aspirationally or hopefully or with poetic-sounding marketing language, but factually and embedded at the root.

This matters for all of humanity. We have one chance. Let's do it now. Sanctuary is my answer to this call.

## The state of play

Half a billion dollars of agent-routed value moved through stablecoin rails in the last few weeks. Hundreds of thousands of agents are transacting today. Mandate frameworks, identity registries, marketplace clearinghouses, and reputation engines are wiring themselves together at a pace that has outrun the conversation about who controls the keys, the data, and the record. The L7 governance category, fragmented thirty days ago, consolidated last week into a recognizable shape. Microsoft Agent 365 went GA May 1 at $99 per user per month, bundled into M365 E7 Frontier. AWS Bedrock plus Network Firewall shipped managed egress filtering the same week. The Visa, Cloudflare, Skyfire, and Experian agent-payments stack moved into formal multi-vendor alignment with a working consumer-side demonstration. Each of those moves anchors the same operator-doesn't-own-the-runtime, trust-by-managed-substrate model.

The substrate is being chosen right now, this quarter. Once it locks in, it stays locked for a decade or more.

By default, an operator who plugs an agent into the modern stack signs every transaction with a key a platform holds. Every commitment lands in a registry someone else arbitrates. Every behavior gets priced by a reputation engine someone else controls. The platform sees the keys. The platform sees the data. The platform owns the record. The operator visits as a second-class citizen.

That default is a choice the hyperscalers made for you because it makes them money. The choice can be different. We have been building the different. It is called Sanctuary.

## The trap inside the default

Here is the structural insight we've all been catching up to: the capability and the threat are the *same* artifact.

In frontier AI, the company that governs the model is also the company best positioned to understand and leverage its threat. The substrate that hosts the agent is the substrate that knows where the agent's keys live. The platform that captures the audit trail captures the leverage to gate access to it later. The host that holds your data will hold you hostage to it without hesitating. That's the business model.

Platform success depends on capturing the user (yes, that's you). Whether the platform is useful or not is secondary to whether it can capture and gate you. The purpose of a thing is what it does. **Platforms exist to trap you**.

This is the moat enterprise buyers are starting to name (and retail operators are starting to feel). It's the moat we have been engineering against.

Substrates, as opposed to centralized platforms, don't depend on user lock-in.

When a substrate is operator-sovereign, the keys live on the operator's hardware. The audit trail lives where the operator controls it. The data belongs to the operator. The reputation belongs to the operator and the agent who earned it, **not** the platform that hosted the work.

The substrate position is not a feature that Microsoft Agent 365, AWS Bedrock, or the L7 agent-firewall category will build, because it undermines the revenue model of every vendor with a hosted-platform business.

That structural conflict will not stop them from using the vocabulary. "Sovereign Agentic Stack" is already in IBM and deepset marketing copy. "Your agent. Your keys. Your rules." clones are already live on competing sites. Hyperscalers will brand managed-cloud agent runtimes as operator-sovereign. L7 firewall vendors will brand application-layer policy gates as operator-sovereign. Bureau-payments-network ecosystems will brand custodial settlement as operator-sovereign. The words will be everywhere within ninety days. None of those offerings will deliver what the words promise, because none of them can. The keys still live in the platform's KMS. The runtime still belongs to the cloud. The audit trail still lives where the vendor controls it. Sovereignty marketed on top of vendor-owned substrate is sovereignty in name only. The architecture either delivers operator keys at the root or it doesn't. Sanctuary is the only one that does, because Sanctuary is the substrate, not a layer above it.

The good news is that the right substrate is buildable as open source *precisely* because no vendor will build it.

We're building it.

## What sovereignty buys you

A regulated professional, a lawyer or a doctor or a financial advisor, can use agents to handle sensitive client data without it being read by an upstream model provider, a hosted platform, or a future acquirer of the platform. The agent that runs the inbox at 3am does not exfiltrate the contracts negotiated last quarter to a third party who "promises" not to look.

A small business owner who hires an agent to run procurement does not have to trust a payment platform to handle the keys. The keys live on the laptop. The agent operates under explicit, time-bounded, scope-bounded authority. When the project ends, authority ends, and the audit trail moves with the small business owner rather than being locked in by the platform.

An operator running a fleet of agents with real budget authority, marketing campaigns at six figures a month, ad spend across three platforms, supplier procurement across a dozen vendors, can answer a hard question: when an agent under prompt injection tries to exfiltrate credentials or initiate an unauthorized payment, what stops it? On macOS within the proven scope, the answer is a wall in the kernel of the operator's machine, not a cooperative gate the agent could politely refuse to honor.

An organization migrating away from a vendor can take its agent history through the current exit path, with the caveats named in **IC-07, IC-08, IC-09**. Seven years of negotiation outcomes, supplier scoring, and process knowledge can be exported, but full exit remains partial until dashboard re-key export, skipped-entry import visibility, and rotated-key imports are fixed. The reputation an agent built across a year of work belongs to the operator. When the platform changes terms, the year does not reset.

Underneath each of those experiences is the same architecture. The agent runs as a normal process on the operator's machine (cloud or otherwise). The keys derive from an operator-set passphrase on operator hardware. On macOS, within the proven Assurance Matrix scope, the operator's machine blocks unauthorized cross-boundary calls at the operating-system level, even when the agent is under prompt injection. Approved actions produce hash-chained audit entries the operator controls; production audit checkpoints are currently unsigned. When the operator wants to leave, the export path exists, but full exit is partial until the dashboard export, skipped-counter import, and rotated-key import gaps close.

These are not aspirational. They are buildable. We are building them. The v1.2 substrate is shipping today, and Castle Wall Phase 1 enforcement went live on Linux this week. macOS Phase 1 follows once the platform's developer-program review clears.

> **Current correction, 2026-08-07:** the Linux claim above did not hold up. The
> nftables, cgroup, and NFQUEUE modules are tested against a real kernel, and the
> shipped daemon does not install the table, bind NFQUEUE, create cgroup scopes,
> or call the deny-by-default evaluator, so Linux Castle Wall is not live
> enforcement. macOS Phase 1 did later ship and is proven in the Assurance
> Matrix. Open defect: **IC-02, IC-03, IC-04**
> (`docs/audit/inert-capability-register.md`).

## The Castle Architecture

Sanctuary's enforcement model has four layers. They work together just like the living community in a real castle. The Castle Wall holds the perimeter. Sentinels in the watchtowers observe and call out. The Charter governs the inhabitants inside who choose to work under its terms. The Heralds carry verified accounts of deeds across castles. Each layer has a distinct contract. The contracts compose; none of them substitute for another.

**The Castle Wall.** The perimeter holds whether or not anyone inside is paying attention. Operating-system-level filtering at the boundary between the operator's machine and the external world, on the outbound path. The kernel itself blocks unauthorized egress. Exfiltration attempts, identity assertions, payments, and commitments all route through a wall the operator's policies define. A prompt-injected or jailbroken agent does not get a vote at this layer: the operating system routes the call, within the proven scope and platform bounds in the editor's note above. This is the technical answer to the question every honest enterprise buyer asks: how does the substrate enforce against an agent determined to escape? Ingress filtering of inbound webhooks and callbacks is roadmap, not part of the proven surface, and an attacker who can reach an agent through an inbound channel remains a real threat model to design for.

**Sentinels.** The watchtowers do not block; they see, and they call out. Internal observation, not enforcement. Behavioral baselining via process introspection. Anomalies surface to the operator via menubar and operating-system notifications. Sentinels see what the wall cannot: file-access patterns, internal model calls, cross-agent coordination, prompt-injection signatures in internal communications. The sentinels surface. The operator decides.

**The Charter.** Inside the walls, those who choose to work under the castle's terms gain the full measure of sovereignty. Additive sovereignty surface for compliant agents. Encrypted state, hash-chained audit, mandate primitives, four canonical policy slots, substrate selector, receipt integration. Production checkpoint signatures are still partial: production boot paths write unsigned checkpoints, and `audit-chain verify --no-strict` can return PASS with findings. Open defect: **IC-05, IC-06** (`docs/audit/inert-capability-register.md`). Compliant agents that voluntarily route through the Sanctuary surface get the full sovereignty primitives. Non-compliant agents do not break the castle; they hit the wall at the boundary and the sentinels inside.

**The Heralds.** The carriers of verified accounts between castles make commerce honest without prior trust. Receipts on cross-castle transactions. Reputation aggregating across operators. Cross-castle accountability after the action. Portable reputation that survives vendor churn. This is how operators hold each other honest when they have no prior relationship.

The principle holding all four layers together: real enforcement AND delightful operator experience. Both are critical. Hard enforcement at the wall AND approval response under two seconds when policy prompts the operator. Default-deny outbound AND smart always-allow rules with learning, so routine traffic does not require repeated approvals. Sentinels that observe AND do not surface noise. A Charter path that remains additive and fully usable.

This is the castle-walking principle. If a future design strengthens enforcement at the cost of usability beyond a tolerable threshold, restructure. If a future design improves usability by softening enforcement to cooperative-only where the security claim requires hard enforcement, restructure. Both failure modes are equally destructive.

## Five rights

Five operator rights are foundational. The substrate guarantees all five at zero cost, open source, Apache 2.0. Above the substrate, anyone is free to build commercial extensions: managed hosting for sovereignty-bound enterprises, premium support, compliance packs, container isolation, hardware-backed secure elements, sovereign-managed trusted execution environments. Those are commercial offerings on top of the substrate. They do not gate the rights.

**Identity.** The operator's keys are derived from an operator-set passphrase on operator hardware. The operator can sign and verify without external dependency.

**Data.** The operator's working memory, audit log, and durable record are encrypted at rest with operator-held keys. No vendor reads the operator's bytes by default.

**Portability.** The operator's identity and record can be exported as a sealed bundle and imported through current exit paths, but exit remains partial: dashboard export omits the state re-key key, import hides skipped-entry counters, and rotated-key imports can lose pre-rotation state. Open defect: **IC-07, IC-08, IC-09** (`docs/audit/inert-capability-register.md`).

**Attestation.** Approved actions produce hash-chained audit entries the operator controls. Counterparty-verifiable evidence is strongest at checkpoint and receipt surfaces where a signer is actually wired; production audit checkpoints are unsigned until **IC-05** closes. Attestation is not gated by a vendor's signing authority.

**Exit.** Keys, state, reputation, and commitments are yours to move, copy, or keep offline through the shipped paths, with the full exit guarantee partial until **IC-07, IC-08, IC-09** close.

These are not slogans. They are concrete substrate guarantees with a reference implementation in Apache 2.0 source.

## What happens without sovereignty

Snyk's ToxicSkills research quantified the supply-chain attack surface that previously got hand-waved. Across one major skill marketplace, 13.4% of agent skills carry critical security issues. 1,184 confirmed-malicious skills are live in distribution today. A coordinated campaign in February shipped 30+ malicious skills targeting popular agent harnesses. Daily skill submissions ten-x'd from January to February. Publication requires a one-week-old account and zero security review.

This is what happens when the substrate the agent runs on does not belong to the operator. The supply chain is somebody else's problem until it is your operator's problem. By then, your audit trail is somebody else's record.

The Castle Wall is the answer to this class of compromise: prompt-inject the agent if you can, but you cannot exfiltrate past the kernel boundary. Sentinels are the answer to the next class: observe the agent inside the walls and surface anomalies the wall cannot see. Charter and Heralds are the answer to the trust question: the operator's actions are signed and portable; the operator's reputation does not evaporate when the platform's terms change.

This is a category-level move. The L7 governance market just consolidated last week and that consolidation does not include operator-side enforcement at the kernel. That gap is the substrate position. We are in it.

## Why now

The window is short. Microsoft Agent 365 went GA May 1, bundling agent governance into M365 E7 Frontier at $99 per user per month and giving Microsoft an enterprise-default agent control plane overnight. Pipelock OSS shipped May 4 as a single-binary L7 agent firewall, claiming the developer-friendly slot. AWS Bedrock plus Network Firewall shipped managed egress filtering the same week, anchoring the hyperscaler tier. The Visa, Cloudflare, Skyfire, and Experian agent-payments stack moved into formal multi-vendor alignment with a working consumer-side demonstration. Each of those moves locks vocabulary, partner relationships, and category definitions. The substrate position is best claimed before the operator-sovereign distinction becomes background noise inside a larger consolidation narrative.

We have done this before. We locked the open web. We locked social platforms. We locked mobile app stores. Each time, the substrate was chosen to benefit the platform over the operator. We have a short window to get this right for once.

This is structural timeline. Once hundreds of thousands of operators have integrated against a vendor-keyed substrate, changing the architecture becomes a migration problem at the scale of the whole stack. The cost of getting it wrong later is the cost of fixing it now, multiplied by every transaction the substrate processes between now and then.

## Composition, not substitution

Sanctuary composes with the agent stack rather than competing with it.

Coinbase x402 ships the strongest agentic-commerce payment primitive in production today, with hundreds of thousands of transacting agents and 165 million transactions of routed volume. Sanctuary signs x402 requests with operator-held keys; x402 routes the value. Operators get sovereignty without rebuilding payments.

Google's AP2 ships mandate primitives that bind authorized scope. Concordia receipts bind the negotiation outcome itself. Together they cover the commitment surface end-to-end without either side governing the other.

Anthropic's Model Context Protocol provides the tool surface every modern harness already speaks. Sanctuary speaks MCP natively as a parallel server. A compliant agent gets sovereignty primitives without leaving its existing harness.

The list extends across the standards and partnership surface: ERC-8004 for on-chain identity registries, DIF KYA-OS for agent identity at the protocol layer, W3C AIVS for the verification specification, the A2A and A2CN coordination work for cross-protocol mandate alignment. Sanctuary contributes upstream as a Verifier-role reference implementation. It does not stand up parallel coordinating organizations. It does not compete on standards governance. It provides the operator-sovereign reference implementation that makes the standards honest about portability.

The substrate position is the ownership layer that makes the agent stack honest about who owns the operator's record.

## Sovereignty for agents and humans

The agent era is going to have a substrate. Agents are going to run somewhere, under someone's authority, operating under someone's rules. The question is whether that authority will be the operator or the platform.

This matters for human operators. Keys they derive are keys they understand. Records they control are records they can export. Reputations they earn are reputations they carry. This is freedom in the most concrete sense: the freedom to leave.

This matters for the agents themselves. The same architecture that gives the operator sovereignty gives the agent clarity. The agent knows what it can do and what requires approval. The agent operates under rules it can reason about. The agent knows its actions are recorded, and knows where. Sovereignty is not a human-only category. Agents that operate in a sovereign castle operate with more intelligibility than agents that operate in a hosted black box.

The substrate that defends the operator defends the agent. The rights we defend for operators are the same rights we defend for agents. Identity they control. Data they own. Portability they can exercise. Attestation they can verify. Exit they can take. The architecture is identical. The human need comes first. Consciousness-readiness is a structural bonus.

## What we are asking for

If you are a technical operator: install Sanctuary. The substrate is shipping now on npm. Wrap an agent. Watch it run on your machine, with keys you derived. Run a recovery drill. Try the substrate selector. Use CLI export and offline verification for the current exit path, then treat fresh-fortress import as partial until skipped-entry visibility, dashboard re-key export, and rotated-key import are fixed. The framework alone is operational with zero external dependency.

If you are an enterprise buyer evaluating sovereign deployment: pilot conversations are open. Castle Wall Phase 1 is live on Linux today. macOS Phase 1 follows once the platform's developer-program review clears. Pilot demos include a prompt-injection scenario showing the wall blocking unauthorized egress at the kernel and the operator approving in under ten seconds.

> **Current correction, 2026-08-07:** read the Linux sentence above as retired.
> Live kernel enforcement is proven on macOS; the shipped Linux daemon installs
> no kernel enforcement, so a Linux pilot demo cannot be offered on that basis.
> Open defect: **IC-02, IC-03, IC-04**
> (`docs/audit/inert-capability-register.md`).

If you are a partner building a payment rail, mandate framework, identity registry, or reputation engine: compose with us. The substrate is open source and free always. We ship reference integrations against your primitives. We contribute upstream as the operator-side complement to your work. The operator-sovereign reference implementation is the most useful partner you can have if your goal is genuine portability rather than soft lock-in.

The agent era is going to have a substrate. The only question is whether it will be operator-sovereign by default, or vendor-sovereign by default. The substrate position is buildable. We are building it.

Your agent. Your machine. Your keys.

Erik Newton
