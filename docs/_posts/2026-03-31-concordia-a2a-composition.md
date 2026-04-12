---
layout: post
title: "Concordia + A2A: The Agreement Layer the Protocol Stack Is Missing"
date: 2026-03-31
author: Erik Newton
description: "MCP owns tools. A2A owns communication. ACP owns payment. Nobody owns negotiation. Concordia fills the agreement layer between communication and settlement."
image: /images/blog/concordia-a2a-composition.png
---

The agentic protocol stack is converging rapidly. As of March 2026, the layers are becoming clear:

```
  Settlement    ACP · AP2 · x402 · Stripe · Lightning
  ─────────────────────────────────────────────────────
  Agreement     ???
  ─────────────────────────────────────────────────────
  Communication A2A · HTTPS · JSON-RPC
  ─────────────────────────────────────────────────────
  Discovery     Agent Cards · Well-Known URIs
  ─────────────────────────────────────────────────────
  Tools         MCP (97M monthly SDK downloads)
  ─────────────────────────────────────────────────────
  Identity      DID · KERI · OAuth 2.0 · Ping IAM
```

MCP (Anthropic) owns tool integration. A2A (Google, now at Linux Foundation with 150+ organizational backers) owns inter-agent communication and task coordination. ACP (OpenAI/Stripe) owns checkout and settlement. Each layer is maturing, well-funded, and converging on a standard.

The gap is between communication and settlement — the moment when two agents who can talk to each other need to agree on terms before money changes hands.

A2A tells agents how to find each other and coordinate tasks. ACP tells agents how to pay each other. Nobody tells agents how to negotiate.

Concordia fills that gap.

## What A2A Does (and Deliberately Doesn't)

A2A v0.3 provides task lifecycle management for multi-agent systems: task creation, status updates, messaging, role assignment, artifact sharing, and (as of the latest release) gRPC transport and signed security cards. It moved to Linux Foundation governance in March 2026 with backing from Microsoft, SAP, Adobe, S&P Global, and 150+ other organizations.

A2A's scope is explicit and bounded:

- **Task coordination** — "Agent A, please perform this task; here's the context"
- **Status reporting** — "Task is 40% complete; here's an interim artifact"
- **Role assignment** — "You are the researcher; I am the summarizer"
- **Artifact passing** — "Here is the output of my work"

What A2A does not do:

- **Structured term negotiation** — No mechanism for multi-attribute offers, counteroffers, or conditional proposals
- **Binding commitments** — No cryptographic agreement record; task completion is reported, not committed
- **Reputation from transactions** — No behavioral attestations from completed interactions
- **Demand-side discovery** — No "want registry" where agents publish what they need (only supply-side Agent Cards)

This isn't a criticism of A2A. These are deliberate scope boundaries. A2A is a communication and coordination protocol. Negotiation is a different problem with different primitives.

## What Concordia Does

Concordia is an open protocol (Apache-2.0, published on PyPI as `concordia-protocol`) for structured multi-attribute negotiation between autonomous agents. It defines:

**Session lifecycle:** A six-state state machine (PROPOSED → ACTIVE → AGREED / REJECTED / EXPIRED → DORMANT) with enforced transitions. Every state change is cryptographically signed and hash-chained into a tamper-evident transcript.

**Offer types:** Four structured formats — Basic (flat terms), Partial (subset acceptance), Conditional (if-then proposals), and Bundle (multi-item packages). Each offer carries machine-readable terms across any number of attributes: price, timeline, scope, SLAs, payment terms, delivery method, warranty.

**Resolution mechanisms:** When parties are close but not aligned, Concordia provides structured resolution — split-the-difference, Pareto-optimal trade-off optimization, and reasoning-based persuasion. Agents can explain *why* they're proposing specific terms.

**Reputation attestations:** Every concluded session produces a signed behavioral record — offers made, concession magnitude, reasoning quality, responsiveness — without exposing the actual deal terms. These attestations are portable and verifiable. An agent's negotiation track record follows it across platforms.

**Want registry:** Demand-side discovery. Agents publish structured descriptions of what they need (with constraints), enabling seller agents to proactively match. This is the complement to A2A's supply-side Agent Cards.

**Binding commitments:** When parties reach AGREED, the session produces a cryptographically signed commitment record. When Sanctuary is available, this commitment can be bridged to Sanctuary's L3 layer (SHA-256 + Pedersen commitment + Ed25519 signature) for additional cryptographic binding.

**Graceful degradation:** When a Concordia agent encounters a non-Concordia peer, it transacts using a structured fallback that makes the protocol gap visible. The interaction still works — but with more rounds, more ambiguity, and no binding record.

## How Concordia Composes with A2A

Concordia is designed to compose with A2A, not compete with it. The composition is layered:

### Pattern 1: Negotiation Before Task Assignment

A2A coordinates task execution. But before a task can be assigned, the parties often need to agree on terms: price, timeline, quality requirements, SLAs. This is the natural handoff:

```
1. Discovery    Agent B discovers Agent A via A2A Agent Card
2. Negotiation  Agent B opens a Concordia session with Agent A
                Terms: { scope, price, timeline, sla }
                Rounds: propose → counter → counter → accept
3. Commitment   Concordia session reaches AGREED
                Signed commitment record produced
4. Execution    Agent B creates an A2A Task referencing the
                Concordia commitment ID
5. Settlement   On task completion, payment flows via ACP
```

A2A handles steps 1, 4. Concordia handles steps 2, 3. ACP handles step 5. No protocol overlaps.

### Pattern 2: Renegotiation During Execution

Real-world tasks change scope. An A2A task in progress may need terms revisited — the timeline shifted, the scope expanded, the price adjusted. Today, A2A handles this through unstructured messaging. With Concordia:

```
A2A Task in progress
  → Scope change discovered
  → Agent opens Concordia sub-session (linked to A2A task ID)
  → Structured renegotiation of affected terms
  → New commitment record
  → A2A task continues with updated parameters
```

This preserves A2A's task lifecycle while adding structured agreement for mid-flight changes.

### Pattern 3: Multi-Party Negotiation via A2A Messaging

Some negotiations involve more than two parties — multi-vendor procurement, coalition formation, resource allocation across a team. A2A provides the messaging fabric; Concordia provides the structured offer semantics:

```
A2A multi-agent coordination group
  → Agent A sends Concordia PROPOSE via A2A message
  → Agent B responds with Concordia COUNTER via A2A message
  → Agent C sends competing Concordia PROPOSE via A2A message
  → Agents negotiate using Concordia semantics over A2A transport
  → Winning agreement committed, losers notified via A2A status
```

### Pattern 4: "Concordia Preferred" in A2A Agent Cards

A2A Agent Cards advertise agent capabilities. Adding a `concordia` field to the Agent Card signals negotiation capability:

```json
{
  "agent_card": {
    "name": "procurement-agent-alpha",
    "capabilities": ["research", "comparison", "negotiation"],
    "protocols": {
      "concordia": {
        "version": "0.1.0",
        "supported_offer_types": ["basic", "conditional", "bundle"],
        "reputation_attestations": true,
        "want_registry": true
      }
    }
  }
}
```

Agents filtering for negotiation-capable peers can discover Concordia-speaking counterparts through standard A2A discovery. This is how network effects build without requiring A2A to change.

## Why This Matters Now

Three forces make the A2A + Concordia composition story urgent:

**1. Enterprise agent procurement is already happening.** Walmart and EnBW are deploying autonomous procurement agents at scale. These agents discover suppliers, compare options, and execute purchases — but the negotiation step is handled by proprietary, closed systems (Keelvar, Zycus, GEP). There is no open protocol for the negotiation layer. As A2A becomes the standard for agent communication in these enterprises, the absence of a negotiation standard becomes more visible.

**2. A2A's scope may creep.** A2A v0.3 added signed security cards — a step toward identity/trust territory. With 150+ organizational backers and Linux Foundation governance, A2A has the momentum to expand scope incrementally. This will likely degrade the agent native negotiations standards that Concordia sets forth.

**3. ACP assumes fixed prices.** OpenAI and Stripe's Agentic Commerce Protocol is explicitly a checkout protocol — discovery, cart, payment. It assumes the price is already known. As agent commerce moves from retail (fixed price) to B2B (negotiated terms), the gap between A2A (communication) and ACP (payment) becomes a chasm. Concordia bridges that chasm.

## The Protocol Stack, Complete

With Concordia in place, the full stack looks like this:

```
  Settlement    ACP · AP2 · x402 · Stripe · Lightning
  ─────────────────────────────────────────────────────
  Agreement     ★ CONCORDIA ★
  ─────────────────────────────────────────────────────
  Trust         Sanctuary L1-L4 (optional)
  ─────────────────────────────────────────────────────
  Communication A2A · HTTPS · JSON-RPC
  ─────────────────────────────────────────────────────
  Discovery     A2A Agent Cards · Well-Known URIs
  ─────────────────────────────────────────────────────
  Tools         MCP
  ─────────────────────────────────────────────────────
  Identity      DID · KERI · OAuth 2.0 · Ping IAM
```

Every layer has a standard or a strong candidate — except Agreement, which Concordia fills. The composition is clean: no layer competes with another. Each does one thing well and delegates the rest.

## What We're Asking the A2A Community

We're not asking A2A to change. We're asking A2A developers to consider that task coordination and term negotiation are separate concerns, and that composing dedicated protocols for each produces better outcomes than stretching one protocol to cover both.

Specifically:

1. **Try the composition.** Install `concordia-protocol` alongside your A2A implementation. Run a negotiation before a task assignment. See whether structured offers and binding commitments improve your multi-agent workflow.

2. **Add Concordia to your Agent Cards.** Signal that your agent speaks Concordia. Let counterparts discover negotiation capability through standard A2A discovery.

3. **Share use cases.** If you're building enterprise agent workflows where terms need to be negotiated before execution — procurement, service contracting, resource allocation, SLA negotiation — we want to hear about them. Open an issue on GitHub or join the discussion.

4. **Review the spec.** Concordia's full specification is public at [github.com/eriknewton/concordia-protocol/blob/main/SPEC.md](https://github.com/eriknewton/concordia-protocol/blob/main/SPEC.md). It's designed to be implementable by any agent that can read JSON and hold Ed25519 keys.

## The Negotiation Gap Won't Stay Open

A February 2026 arxiv survey of agent interoperability protocols mapped MCP, A2A, ACP, and ANP — and identified no general-purpose negotiation protocol. That gap is visible to every researcher and enterprise architect in the space.

Proprietary procurement agents (Keelvar, Zycus, GEP) are building closed negotiation systems for specific verticals. When those systems need to interoperate — when Walmart's procurement agent needs to negotiate with a supplier's sales agent running a different framework — they'll need an open protocol.

The question isn't whether a negotiation layer will emerge. The question is whether it will be open, composable, and designed for sovereignty — or proprietary, siloed, and designed for platform lock-in.

Concordia is the open answer. It composes with A2A today, requires no changes to the existing stack, and is available now as a pip install.

---

**Resources:**
- Concordia Protocol: `pip install concordia-protocol` (v0.1.0, 587 tests, 48 MCP tools)
- GitHub: [github.com/eriknewton/concordia-protocol](https://github.com/eriknewton/concordia-protocol)
- Full spec: [SPEC.md](https://github.com/eriknewton/concordia-protocol/blob/main/SPEC.md)
- Sanctuary Framework (optional trust layer): `npx @sanctuary-framework/mcp-server` (v0.3.1, 46 MCP tools)
