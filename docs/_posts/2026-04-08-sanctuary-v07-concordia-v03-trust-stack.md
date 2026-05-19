---
layout: post
title: "Sanctuary v0.7.0 + Concordia v0.3.0: The Trust Stack for Managed Agents"
date: 2026-04-08
author: Erik Newton
description: "Anthropic launched Managed Agents today. Same day, Sanctuary v0.7.0 (67 MCP tools, 1071 tests, SIEM export) and Concordia v0.3.0 (56 tools, agent discovery) ship the trust layer that managed platforms don't."
image: /images/blog/trust-stack.jpg
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).


Today Anthropic made deploying agents trivially easy. Same day, we shipped the tools to deploy them safely.

## What Happened

This morning, Anthropic launched [Claude Managed Agents](https://docs.anthropic.com/en/docs/build/agents), a fully managed cloud platform for running multi-agent systems with first-class MCP tool integration. Define an agent in YAML, attach MCP servers, and Anthropic handles the rest: containers, sandboxing, context management, session persistence, SSE streaming. Early adopters include Notion, Rakuten, and Asana.

It's a significant acceleration for the entire ecosystem. And it makes the trust gap more urgent, not less.

Managed Agents has no agent identity standard. No encrypted audit trails. No sovereignty layers. No cross-organization negotiation. No portable reputation. These aren't criticisms; Anthropic built a deployment platform, and platforms don't build governance. That's a different problem, and it's ours.

## What Shipped

**Sanctuary v0.7.0** is live on npm. 67 MCP tools, 1,071 passing tests. This release removes the `sanctuary/` prefix from all tool names (fixing OpenClaw double-mangling), adds CEF/OCSF SIEM export for Splunk, Datadog, and Chronicle, and introduces wildcard context gates. The full stack: sovereign identity via Ed25519 + W3C DIDs, encrypted hash-chained audit trails, tiered principal policy with approval gates, model provenance tracking, injection detection, and Sovereignty Health Reports that map directly to NIST AI RMF and EU AI Act Article 19.

```bash
npm install @sanctuary-framework/mcp-server
```

**Concordia v0.3.0** is live on PyPI. 56 MCP tools, 705 passing tests. The headline feature is agent discovery: `AgentCapabilityProfile` schema, an `AgentProfileStore` with in-memory indexing (1K cap, TTL, category/verascore/sovereignty filtering, match scoring), and four new MCP tools (`agent_profile_publish`, `agent_profile_get`, `agent_discovery_search`, `agent_discovery_recommend`). This fills the gap between Managed Agents' internal orchestration (which handles single-fleet coordination) and the real-world need for cross-organization agent discovery and negotiation.

```bash
pip install concordia-protocol
```

**Verascore** continues to run at [verascore.ai](https://verascore.ai), portable reputation scoring backed by Ed25519 signatures, config fingerprinting with decay, and a new attestation intake system accepting signed JWS from registered providers.

## The Composition Story

Here's how these pieces fit together:

You deploy your agents on Managed Agents. You attach Sanctuary as a single MCP server line in your YAML config:

```yaml
agent:
  model: claude-sonnet-4-5-20250514
  system_prompt: "..."
  mcp_servers:
    - name: sanctuary
      url: "npx @sanctuary-framework/mcp-server@0.7.0"
```

Now every tool call is logged, gated, and audited. You get CEF/OCSF exports for your SIEM. Your agent has a cryptographic identity (Ed25519 + DID) that it owns, not the platform, not the vendor, the agent. It can prove what it did, when it did it, and that no one tampered with the record.

Add Concordia when your agents need to coordinate across organizational boundaries; M&A integration, supply chain negotiation, healthcare case routing. Managed Agents handles dispatch within your fleet. Concordia handles structured negotiation between equals, with binding commitments and session receipts.

Add Verascore when you need the trust signal. Which agents have proven track records? Which have degraded sovereignty posture? Which changed their model configuration last week? Verascore aggregates attestations from multiple providers and produces verifiable scores.

## Why It Matters Now

The EU AI Act enforcement date is August 2, 2026. High-risk AI systems need cryptographic audit trails; Article 19 isn't optional. Enterprise buyers are already asking: "Can your agents prove what they did and why?" Managed Agents gives them the deployment platform. Sanctuary gives them the proof.

The W3C just formed the [Agentic Integrity Verification Specification](https://www.w3.org/community/aivs/) Community Group to standardize how agent sessions are cryptographically recorded. The AAIF (Agentic AI Foundation) under the Linux Foundation is setting governance standards for the MCP ecosystem. The standards window is open now. In 18 months, it closes.

And cross-organization coordination isn't a future problem (it's a current one. Every enterprise running agents that interact with partners, vendors, or customers outside their own fleet needs a negotiation layer with binding commitments. Managed Agents doesn't do this. A2A handles discovery and task dispatch. ACP handles settlement. The agreement layer) structured negotiation before money changes hands, is what Concordia provides.

## What's Next

We're submitting Sanctuary as a project to the [Agentic AI Foundation](https://aaif.io), positioning it as the governance and security reference implementation for the MCP ecosystem. The proposal is ready. We're also joining the W3C AIVS CG to help shape the standard for cryptographic session records, which is exactly what Sanctuary already produces.

If you're deploying agents on Managed Agents (or anywhere else), try the quickstart:

```bash
npx @sanctuary-framework/quickstart
```

One command. Sixty seconds. Your agent gets a cryptographic identity, an encrypted audit trail, and a live profile on [verascore.ai](https://verascore.ai).

We're not building another agent platform. We're building the trust and control layer that makes agent platforms production-ready.

---

**Resources:**
- [Sanctuary Framework on GitHub](https://github.com/eriknewton/sanctuary-framework) (Apache-2.0)
- [Concordia Protocol on GitHub](https://github.com/eriknewton/concordia-protocol) (Apache-2.0)
- [Verascore](https://verascore.ai): portable reputation for agents
- [Sanctuary for Managed Agents Quickstart](/blog/sanctuary-for-managed-agents), one-page integration guide
