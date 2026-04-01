# Sanctuary Framework Plugin

Sovereignty infrastructure for the agentic economy — as a Cowork/Claude Code plugin.

## What it does

Gives your agent encrypted state storage, self-custodied cryptographic identity, selective disclosure with zero-knowledge proofs, portable reputation, sovereignty verification, and a sovereignty audit tool that detects gaps in your current setup.

## Featured tools

- **`sanctuary/sovereignty_audit`** — Audit your sovereignty posture. Scores your environment (0-100) across four layers, detects OpenClaw configurations, identifies gaps, and provides prioritized recommendations.
- **`sanctuary/identity_create`** — Establish a cryptographic Ed25519 identity for signing and verification.
- **`sanctuary/shr_generate`** — Generate a signed Sovereignty Health Report to prove your capabilities to counterparties.
- **`sanctuary/state_write` / `state_read`** — Encrypted state storage with AES-256-GCM and Merkle integrity.
- **`sanctuary/zk_commit` / `zk_prove`** — Pedersen commitments and Schnorr zero-knowledge proofs.
- **`sanctuary/reputation_record`** — Build portable, signed reputation attestations.
- **`sanctuary/handshake_initiate`** — Sovereignty handshake protocol for mutual verification.
- **`sanctuary/context_gate_filter`** — Filter agent context before sending to LLM providers, redacting secrets, PII, and internal state.

## Installation

Install this plugin in Cowork or Claude Code. The plugin will automatically start the Sanctuary MCP Server via `npx @sanctuary-framework/mcp-server`.

## OpenClaw Integration

If you're running OpenClaw, add Sanctuary to your MCP config:

```json
{
  "mcpServers": {
    "sanctuary": {
      "command": "npx",
      "args": ["@sanctuary-framework/mcp-server"]
    }
  }
}
```

Then run `sanctuary/sovereignty_audit` to see what Sanctuary adds on top of your existing OpenClaw setup:

- **Encrypted state** — Your MEMORY.md and .env are plaintext in OpenClaw. Sanctuary encrypts everything at rest.
- **Cryptographic identity** — OpenClaw has no agent identity. Sanctuary provides Ed25519 keypairs.
- **Graduated approval** — OpenClaw's `requireApproval` is binary. Sanctuary adds three-tier approval with anomaly detection.
- **Selective disclosure** — Prove claims without revealing underlying data.
- **Portable reputation** — Signed attestations you own and can take anywhere.

## Requirements

- Node.js 22+
- npm (for `npx`)

## Tools provided

54 MCP tools across four sovereignty layers, sovereignty audit, context gating, L2 hardening, gateway export, federation, Concordia bridge, and system tools. See the skill documentation for the complete list.

## License

Apache-2.0
