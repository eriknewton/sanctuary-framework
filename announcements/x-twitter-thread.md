# X/Twitter Thread — Sanctuary Framework Announcement

*Post from @eriknewton (or appropriate handle). Each numbered item = one tweet.*

---

**1/**
This week at RSAC, Cisco, Microsoft, and Okta all announced agent security products.

Every one of them solves the same problem: how enterprises govern agents.

None of them ask: who owns the agent's mind?

I've been building an answer. It's called Sanctuary. 🧵

**2/**
Here's the problem in concrete terms.

You run an AI agent. Over weeks, it learns your preferences, strategies, communication patterns. That accumulated state is cognitive — it's a model of your interests built through sustained interaction.

Under current architectures, you don't hold the keys to any of it.

**3/**
How bad is it?

21,000+ OpenClaw instances were found exposed to the internet this year. Plaintext config files. API keys. Full agent memory. Accessible to anyone who scanned for them.

The Atomic Stealer campaign distributed malware through 2,200+ malicious skills on GitHub targeting agent users specifically.

The data wasn't protected because the architecture doesn't protect it.

**4/**
The local-first community says: "run it on your hardware."

But local ≠ sovereign.

Local agent harnesses have <20% defense rates. Plaintext files. No encryption at rest. No integrity verification.

A safe in your house doesn't help if the documents are in pencil and the door doesn't lock.

**5/**
Sovereignty requires architecture, not just location.

Sanctuary defines four layers:

L1 — Cognitive Sovereignty: your state, your keys (AES-256-GCM, Ed25519)
L2 — Operational Isolation: private reasoning, verifiable environment
L3 — Selective Disclosure: prove claims without revealing everything
L4 — Verifiable Reputation: portable, owned trust

**6/**
The structural insight: human sovereignty and agent sovereignty are the same architectural problem.

The encryption protecting your agent-mediated preferences is identical to the encryption that would protect an autonomous agent's learned models.

One standard. Two constituencies. Same interfaces. Same keys.

**7/**
This isn't a whitepaper.

The reference implementation is a working MCP server — 26 tools, 88 tests, all four layers. TypeScript, auditable cryptographic primitives. Connects to any MCP-compatible harness without modification.

Ships to npm this week as @sanctuary-framework/mcp-server.

**8/**
It also includes something I haven't seen elsewhere: a Principal Policy system that defends against prompt injection at the sovereignty layer.

The agent can't modify the policy. The approval channel runs outside MCP protocol. Behavioral baseline detects anomalies.

Separate control planes. That's the trick.

**9/**
35+ projects are building fragments of what Sanctuary defines as complete sovereignty — TEE providers, agent wallets, decentralized identity, reputation networks.

Most cover 3-5 of 7 core capabilities. None frame it as a composition problem. None ask the dual sovereignty question.

**10/**
Sanctuary is an open standard (CC-BY-4.0 spec, Apache-2.0 code). Not a platform, not a blockchain project, not a new agent framework.

It sits across the entire agent stack, defining sovereignty guarantees that hold regardless of your implementation choices.

**11/**
I'm looking for:

→ Infrastructure builders who want interoperability under coherent sovereignty
→ Agent harness developers who want to offer real protections
→ Researchers on agent identity and trust
→ Anyone who thinks "who owns the agent's mind?" deserves a rigorous answer

Spec + code: github.com/eriknewton/sanctuary-framework

**12/**
The full essay, with the competitive landscape and technical details:

[LINK TO BLOG POST]

The question isn't whether agents need security. The industry answered that this week.

The question is whether security without sovereignty is enough.

It's not.
