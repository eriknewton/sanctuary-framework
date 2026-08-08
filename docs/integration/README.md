# Sanctuary Integration Guides

> **One sovereignty layer, any runtime.**

Sanctuary Framework is the portable trust layer for AI agents. It composes
onto any MCP-compatible runtime as a standard MCP server. No custom integration
code, no vendor lock-in.

| Runtime | Guide | Status |
|---------|-------|--------|
| [Claude Agent SDK](./claude-agent-sdk.md) | Python + TypeScript | Verified |
| [Claude Managed Agents](./claude-managed-agents.md) | Cloud-hosted | Verified |
| [OpenClaw](./openclaw.md) | Local harness | Verified (Mac Mini M4) |
| [A2A Protocol](./a2a-protocol.md) | Google Agent-to-Agent | Guide ready |
| [Agent Zero](./agent-zero.md) | Open-source framework | Guide ready |

## What You Get

Every runtime gets the same capabilities:

- **Ed25519 Identity**: Cryptographic keypair + W3C DID per agent
- **Encrypted Audit Trail**: Tamper-evident hash-chained logs; production audit checkpoints are currently unsigned until **IC-05** closes, and `audit-chain verify --no-strict` can return PASS with findings until **IC-06** closes
- **Sovereignty Health Report**: Current status for Castle Wall, Sentinels, Charter, and Heralds
- **Verascore Profile**: Portable, verifiable reputation
- **Sovereignty Handshake**: Mutual trust verification between agents

## Quick Start (any runtime)

```
1. Add Sanctuary as an MCP server (see runtime-specific guide)
2. Call `manifest` to verify 80+ tools are loaded
3. Call `identity_create` to get a DID
4. Call `identity_set_primary` to designate the active identity
5. Call `sovereignty_health_report` to check your status
6. Call `reputation_publish` to create your Verascore profile
```

## Verification

See the [verification checklist](./_verification-checklist.md) for the full test procedure.

## Add Concordia (Optional)

For agent-to-agent negotiation with binding commitments:

```
pip install concordia-protocol
```

Concordia adds 56 negotiation tools including agent discovery, structured
negotiation (propose/counter/accept/reject/commit), session receipts,
and graceful degradation for non-Concordia peers.

See [Concordia docs](https://github.com/eriknewton/concordia-protocol).

## Resources

- **Sanctuary Framework**: https://github.com/eriknewton/sanctuary-framework
- **Verascore Reputation**: https://verascore.ai
- **Concordia Protocol**: https://github.com/eriknewton/concordia-protocol
- **MCP Protocol**: https://modelcontextprotocol.io
