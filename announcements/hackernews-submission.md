# Hacker News Submission

## Title (80 char max):
Sanctuary: An open standard for sovereignty in the agentic economy

## URL:
[LINK TO BLOG POST]

---

## If "Show HN" format preferred:

### Title:
Show HN: Sanctuary – MCP server for agent sovereignty (encrypted state, portable reputation)

### URL:
github.com/eriknewton/sanctuary-framework

### Text (for Show HN, since it allows a text body):

Sanctuary is an open standard + reference implementation for sovereignty in the agentic economy. The core insight: the architecture protecting a human's agent-mediated preferences is identical to the architecture protecting an autonomous agent's own state.

Four layers: Cognitive Sovereignty (AES-256-GCM encrypted state with participant-held keys), Operational Isolation (attestation, audit), Selective Disclosure (commitment schemes, disclosure policies), Verifiable Reputation (signed attestations, portable trust).

The reference implementation is a TypeScript MCP server — 26 tools, 88 tests, connects to any MCP-compatible harness without modification. Includes a Principal Policy system (prompt injection defense via separated control planes — the agent can't modify the approval policy, and the approval channel runs outside MCP protocol).

Motivation: 21K+ OpenClaw instances exposed to the internet with plaintext memory. Agent-involved breaches up 340% YoY. Local-first harnesses have <20% defense rates. "Run it on your hardware" is not a sovereignty model — it's a location policy.

Spec: CC-BY-4.0. Code: Apache-2.0. Looking for collaborators.

npm: @sanctuary-framework/mcp-server (shipping this week)
