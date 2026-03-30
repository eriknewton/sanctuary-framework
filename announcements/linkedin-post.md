# LinkedIn Post — Sanctuary Framework Announcement

---

**Who owns your AI agent's mind?**

This week at RSAC, Cisco, Microsoft, Okta, and 1Password all announced agent security products. NIST launched its AI Agent Standards Initiative last month. The Linux Foundation's Agentic AI Foundation — governing MCP with Anthropic, OpenAI, Google, Microsoft, and AWS — is building governance rails for agentic infrastructure.

The industry has recognized that AI agents need security. That's progress.

But every one of these solutions answers the same question: how does an enterprise govern, monitor, and control agents? That's important. It's also insufficient.

Nobody is asking: who owns the agent's accumulated state — the memory, the preferences, the learned strategies that represent a model of your interests? Who holds the encryption keys? What happens when you want to leave a platform?

I've spent the past several months building an answer.

**The Sanctuary Framework** is an open standard for sovereignty in the agentic economy. It defines four layers — Cognitive Sovereignty, Operational Isolation, Selective Disclosure, and Verifiable Reputation — with formal properties, required interfaces, and testable compliance criteria.

The immediate motivation is practical: over 21,000 OpenClaw instances were found exposed to the internet this year, with plaintext agent memory accessible to anyone who scanned. Agent-involved breaches grew 340% year-over-year. 88% of organizations report confirmed or suspected AI agent security incidents. Physical custody of agent state ("run it on your hardware") has less than a 20% defense rate against common attacks.

Location is not a security model. Sovereignty requires architecture.

The reference implementation ships this week as an MCP server — 26 tools across all four layers, 88 passing tests, built on auditable cryptographic primitives. It connects to any MCP-compatible agent harness without requiring harness modification.

At its core is what I call the Dual Sovereignty Principle: the architecture that protects a human's agent-mediated preferences is structurally identical to the architecture that would protect an autonomous agent's own interests. One standard serves both constituencies. The human need is primary and immediate. The structural convergence is the design insight.

The specification is CC-BY-4.0. The code is Apache-2.0. This is an open standard because sovereignty infrastructure cannot be proprietary — if it's controlled by a single entity, it isn't sovereignty.

I'm looking for collaborators in agent infrastructure, harness development, decentralized identity, and anyone working at the intersection of AI security and participant rights.

Full essay: [LINK TO BLOG POST]
GitHub: github.com/eriknewton/sanctuary-framework

—
Erik Newton
eriknewton.com
