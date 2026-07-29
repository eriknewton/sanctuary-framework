---
title: "Sanctuary for Managed Agents: 30-Second Setup"
date: 2026-04-13
description: "Add cryptographic identity, encrypted audit, and compliance reporting to Claude Managed Agents in 30 seconds."
author: "Erik Newton"
archive_note: "Predates Mantle vocabulary canonicalization on 2026-05-15. Terminology in this post may refer to install-time-binding concepts using earlier language; current canonical vocabulary lives at https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md."
claims_era_note: true
---

> **Archive note:** This post predates Mantle vocabulary canonicalization on 2026-05-15.
> Terminology here may use earlier language for install-time substrate-binding concepts.
> Current canonical vocabulary lives at [Mantle Phase 1](https://github.com/eriknewton/newton-wiki/blob/main/concepts/mantle.md).


# Sanctuary for Claude Managed Agents: Quickstart

You've deployed a Managed Agent. Now secure it with cryptographic identity, audit trails, and policy enforcement. Sanctuary Framework v0.7.0 adds 68 tools for security, privacy, and control, published today as an MCP server.

## Add Sanctuary in 30 Seconds

In your Managed Agent YAML config, declare the Sanctuary MCP server:

```yaml
agent:
  model: claude-sonnet-4-5-20250514
  system_prompt: |
    You are a secure agent powered by Sanctuary Framework.
    Use the shr_generate tool to verify your identity status.
  tools:
    - type: agent_toolset  # Replace with your current agent toolset version
  mcp_servers:
    - name: sanctuary
      url: "npx @sanctuary-framework/mcp-server@0.7.0"
```

Deploy the agent. Sanctuary tools load automatically via MCP.

## What Sanctuary Gives You

- **Sovereign Identity**: Ed25519 cryptographic keypair + W3C DID per agent instance
- **Encrypted Audit Trail**: Tamper-proof CEF/OCSF logs; selective disclosure via zero-knowledge attestations
- **Principal Policy**: Tiered role-based access control (RBAC) with time-locked capabilities
- **SIEM Export**: Push audit events to any SIEM (Datadog, Splunk, Chronicle)
- **Sovereignty Health Reports**: Real-time dashboard of identity status, policy compliance, audit integrity
- **Reputation Publishing**: Cryptographic proof of track record via Verascore

## Before vs. After

| Aspect | Without Sanctuary | With Sanctuary |
|--------|------------------|----------------|
| Identity | Implicit (cloud-managed) | Explicit (agent-owned Ed25519 keypair) |
| Audit | Default logging | Encrypted, tamper-evident, SIEM-ready |
| Policy | Platform-level (static) | Principal-level (dynamic, time-locked) |
| Disclosure | All-or-nothing | Selective (ZK attestations) |
| Reputation | Opaque | Verifiable via Verascore |

## Verify Sanctuary is Ready

Call the `manifest` tool from your agent logic. If you see 68 tools listed, Sanctuary is active:

```python
# Verify Sanctuary tools are available
manifest = agent.call_tool("manifest")
print(f"Sanctuary loaded: {len(manifest['tools'])} tools available")

# Key tools to verify:
# - identity_create: Generate sovereign identity (Ed25519 keypair + DID)
# - shr_generate: Generate Sovereignty Health Report
# - audit_export_siem: Export audit logs (CEF/OCSF)
# - reputation_publish: Publish to Verascore
```

> **Note:** Exact calling syntax depends on your agent framework. The above is illustrative.

Or check logs: you'll see MCP server initialization and tool binding on startup.

## Next Steps

1. **Identity-Gate Your Agent**: Call `identity_create` on startup. Store the keypair securely.
2. **Log to SIEM**: Configure `audit_export_siem` with your SIEM endpoint (Datadog, Splunk, etc.)
3. **Publish Reputation**: Use `reputation_publish` after key milestones (e.g., 1000 verified transactions).
4. **Add Negotiation** (optional): Install `pip install concordia-protocol` to enable multi-agent policy negotiation.
5. **Monitor Compliance**: Call `shr_generate` in your observability dashboard.

## Resources

- **Sanctuary Framework**: https://github.com/eriknewton/sanctuary-framework
- **Verascore Reputation**: https://verascore.ai
- **Managed Agents**: https://docs.anthropic.com/en/docs/build/agents
- **MCP Protocol**: https://modelcontextprotocol.io

---

**Launched April 8, 2026.** Sanctuary Framework is open source. Build agents that own their identity and prove their integrity.
