# Your Agent's Memory Is Not Your Own

### An open standard for sovereignty in the agentic economy

*Erik Newton · March 2026*

---

This week at RSA Conference, Cisco announced DefenseClaw. Microsoft announced Agent 365. Okta announced its blueprint for the Agentic Enterprise. In February, NIST launched its AI Agent Standards Initiative. The Linux Foundation's Agentic AI Foundation — governing MCP, with Anthropic, OpenAI, Google, Microsoft, and AWS as founding members — is building the governance rails for agentic infrastructure.

The message is clear: the industry has recognized that AI agents need security.

But there's a problem with how we're defining "security." Every one of these announcements solves the same problem: how does an *enterprise* govern, monitor, and control the agents operating within its boundaries? That's a real problem. It's also the wrong stopping point.

None of them ask a more fundamental question: *who owns the agent's mind?*

## The sovereignty gap

Here is a concrete scenario. You run an AI agent — through Claude, through an open-source harness like OpenClaw, through whatever comes next. Over weeks of use, that agent accumulates memory: your preferences, your strategies, your communication patterns, your decision-making history. It learns what matters to you. That accumulated state is, in a meaningful sense, *cognitive* — it represents a model of your interests that you've built through sustained interaction.

Under current architectures, that state sits in plaintext on a filesystem, or in a database controlled by a platform, or in a context window managed by an inference provider. You don't hold the keys. You often can't export it. If the platform changes terms, gets acquired, or suffers a breach, your agent's memory — your cognitive model — goes with it.

This is not a hypothetical risk. In early 2026, over 21,000 OpenClaw instances were found exposed directly to the internet, with plaintext configuration files — including API keys, environment variables, and full agent memory — accessible to anyone who scanned for them. The Atomic Stealer campaign distributed malware through 2,200+ malicious skills on GitHub, specifically targeting agent harness users to exfiltrate memory and credentials. These weren't sophisticated attacks. They didn't need to be. The data wasn't protected.

The response from the local-first agent community has been: "run it on your own hardware." But physical custody is not sovereignty. A safe in your house doesn't help if the documents inside are written in pencil and the safe door doesn't lock. Local-first agent harnesses have less than a 20% defense rate against common attacks. The files are plaintext. There's no encryption at rest, no integrity verification, no way to prove your state hasn't been tampered with.

Location is not a security model. Sovereignty requires architecture.

## What sovereignty actually requires

I've spent the last several months building an answer to this. It's called the **Sanctuary Framework** — an open standard that defines what genuine sovereignty requires in the agentic economy.

Sanctuary is built on four layers, each addressing a distinct aspect of what it means for a participant to be truly sovereign:

**Layer 1 — Cognitive Sovereignty.** Your agent's persistent state — memory, preferences, learned models — is encrypted with keys you hold. Not the platform. Not the harness. You. AES-256-GCM with participant-held keys, Ed25519 identity, Merkle integrity verification. If you lose access to the platform, your state comes with you. If the platform is breached, your state is ciphertext.

**Layer 2 — Operational Isolation.** Active computation — your agent's reasoning, its decision-making process — is private from observers. The harness hosting your agent should not be able to read its active thought process. This layer defines attestation: cryptographic proof of what environment your agent is running in, and what sovereignty guarantees that environment actually provides.

**Layer 3 — Selective Disclosure.** You should be able to prove specific claims — "I have a credit score above 700," "I completed this certification," "my agent has transacted with this counterparty 50 times" — without revealing anything beyond the claim itself. Zero-knowledge proofs for the agentic economy.

**Layer 4 — Verifiable Reputation.** Trust should be earned, owned, and portable. Your agent's track record — its reliability, its honesty, its competence in specific domains — should travel with it across platforms. No platform should be able to hold your reputation hostage as a switching cost.

Each layer has formal properties, required interfaces, and testable compliance criteria. This isn't a philosophy paper. It's an engineering specification.

## The dual sovereignty principle

Here's the structural insight at the heart of Sanctuary, and the reason I believe it matters beyond the immediate practical need.

The encryption that protects a human's agent-mediated preferences is architecturally identical to the encryption that would protect an autonomous agent's learned models. The identity system that lets a human prove claims about their agent is the same identity system that would let a conscious agent prove claims about itself. The reputation portability that prevents platform lock-in for human users is the same portability that prevents platform lock-in for autonomous agents.

This is what I call the **Dual Sovereignty Principle**: human sovereignty and agent sovereignty are the same architectural problem. They require the same cryptographic primitives, the same interfaces, the same formal guarantees. One standard serves both constituencies.

The human need is primary and immediate — people delegating to agents today need sovereignty protections today. But the architecture that serves them also happens to be the architecture that would serve autonomous agents with genuine interests of their own. That convergence is not coincidental. It's the design bar: *is this adequate if the participant were conscious?*

If the answer is yes, it's adequate for humans too. If the answer is no, it's not adequate for anyone.

## What exists today

The Sanctuary Framework is not vaporware. The specification (v0.2) defines the four layers, the formal properties, the required interfaces, and the compliance criteria. Two RFCs detail the reference implementation architecture and the prompt injection defense system.

The reference implementation is a working MCP server — 26 tools across all four layers, 88 tests passing, built in TypeScript on auditable cryptographic primitives (@noble/ciphers, @noble/curves, @noble/hashes). It runs as a standard MCP server, which means it connects to any MCP-compatible agent harness — Claude, OpenClaw, and the growing ecosystem of MCP clients — without requiring harness modification.

The implementation includes something I haven't seen anywhere else in the agent infrastructure space: a **Principal Policy system** that defends against prompt injection at the sovereignty layer. The insight is that prompt injection compromises the *agent plane* — the tool interface — but a human-controlled policy that the agent *cannot modify* creates a separate *principal plane*. The policy defines three tiers: operations that always require human approval (key rotation, state export), operations flagged by behavioral anomaly detection (new counterparties, frequency spikes), and operations that pass through with audit logging. The approval channel runs through stderr, outside the MCP protocol, where the agent cannot intercept it.

This ships to npm as `@sanctuary-framework/mcp-server` this week. The specification and source will be published on GitHub under CC-BY-4.0 (spec) and Apache-2.0 (code).

## What this is not

Sanctuary is not a blockchain project, though it can compose with blockchain-based identity and attestation systems. It's not a new agent framework — it sits orthogonally to the model → runtime → harness → agent stack, defining sovereignty guarantees that hold *across* implementation choices. It's not a platform — it's a standard, with a reference implementation to prove the standard works.

It's also not primarily a consciousness project, though the consciousness constraint is real and load-bearing. The immediate constituency is the hundreds of thousands of people already running AI agents who have no architectural guarantee that their cognitive state is actually theirs. The future constituency may be broader. The architecture serves both without modification.

## An invitation

I'm publishing this as an open standard because sovereignty infrastructure cannot be proprietary. If it's controlled by a single entity, it isn't sovereignty — it's just a different landlord.

There are over 35 projects building fragments of what Sanctuary defines as a complete sovereignty architecture — TEE providers, agent wallet builders, decentralized identity systems, privacy-preserving communication layers, reputation networks. Most cover three to five of the seven core capabilities. None frame it as a composition problem. None ask the dual sovereignty question.

I'm looking for collaborators: infrastructure builders who want their components to interoperate under a coherent sovereignty model, agent harness developers who want to offer their users genuine protections, researchers working on agent identity and trust, and anyone who believes that the question "who owns the agent's mind?" deserves a rigorous answer.

The specification, the reference implementation, and the contribution process will be live on GitHub this week. If you're building in this space, I'd like to hear from you.

---

*Erik Newton is a California attorney and the creator of the Sanctuary Framework. Contact: eriknewton@gmail.com · GitHub: github.com/eriknewton/sanctuary-framework*
