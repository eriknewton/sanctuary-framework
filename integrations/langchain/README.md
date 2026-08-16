# Sanctuary + LangChain Integration

Use Sanctuary's sovereignty infrastructure with LangChain agents.

## Overview

This integration uses the official `langchain-mcp-adapters` package to connect LangChain agents to Sanctuary's MCP server. Sanctuary's 80+ tools become LangChain tools - no custom adapter required.

What you get: encrypted state, cryptographic identity, selective disclosure, and verifiable reputation for any LangChain agent - without changing your agent code.

## Quick Start

### 1. Install dependencies

```bash
pip install langchain-mcp-adapters langchain-openai langgraph
```

### 2. Start Sanctuary

```bash
npx @sanctuary-framework/mcp-server
```

### 3. Connect from LangChain

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

async with MultiServerMCPClient(
    {
        "sanctuary": {
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "transport": "stdio",
        }
    }
) as client:
    tools = client.get_tools()
    agent = create_react_agent(ChatOpenAI(model="gpt-4"), tools)

    # Your agent now has sovereignty infrastructure
    result = await agent.ainvoke({
        "messages": [{"role": "user", "content": "Create a sovereign identity"}]
    })
```

## Sovereignty-Aware Patterns

### Handling Tier 1 Approvals

Sanctuary's Principal Policy requires human approval for high-risk operations (state export, key rotation, identity deletion). In a LangChain agent workflow, these operations will block until approved.

**Recommended pattern:** Run Sanctuary with the dashboard enabled, then reload to inspect new pending approvals; for live delivery use webhook or stderr until **IC-12** closes:

```bash
npx @sanctuary-framework/mcp-server --dashboard
```

Then configure your agent to use the dashboard URL for approval routing. See `examples/sovereign_agent.py` for a complete working example.

### Multi-Agent Composition

When running multiple LangChain agents, each can have its own Sanctuary identity:

```python
async with MultiServerMCPClient(
    {
        "agent_alice": {
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "env": {"SANCTUARY_STORAGE_PATH": "~/.sanctuary/alice"},
            "transport": "stdio",
        },
        "agent_bob": {
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "env": {"SANCTUARY_STORAGE_PATH": "~/.sanctuary/bob"},
            "transport": "stdio",
        },
    }
) as client:
    tools = client.get_tools()
    # Each agent's tools are namespaced: agent_alice/identity_create, agent_bob/identity_create
```

### Sovereignty Health Reports in Agent Metadata

Use Sanctuary's SHR (Sovereignty Health Report) as agent capability metadata:

```python
# Generate SHR for this agent's sovereignty posture
shr_result = await agent.ainvoke({
    "messages": [{"role": "user", "content": "Generate a sovereignty health report"}]
})
# The SHR can be shared with other agents as a trust signal
```

## Adding Concordia (Negotiation)

If you also need structured negotiation between agents, add [Concordia Protocol](https://pypi.org/project/concordia-protocol/):

```bash
pip install concordia-protocol
```

```python
async with MultiServerMCPClient(
    {
        "sanctuary": {
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "transport": "stdio",
        },
        "concordia": {
            "command": "python",
            "args": ["-m", "concordia"],
            "transport": "stdio",
        },
    }
) as client:
    tools = client.get_tools()
    # Agent now has sovereignty (Sanctuary) + negotiation (Concordia)
```

Sanctuary and Concordia compose but neither depends on the other. Use either alone or both together.

## Available Sanctuary Tools

All 80+ Sanctuary tools are exposed as LangChain tools. Key categories:

**L1 - Cognitive Sovereignty:** `state_read`, `state_write`, `state_list`, `state_export`, `state_import`, `state_delete`

**L1 - Identity:** `identity_create`, `identity_list`, `identity_sign`, `identity_verify`, `identity_rotate`

**L2 - Operational Isolation:** `exec_attest`, `principal_policy_view`, `principal_baseline_view`, `monitor_health`, `monitor_audit_log`

**L3 - Selective Disclosure:** `proof_commitment`, `proof_reveal`, `disclosure_set_policy`, `disclosure_evaluate`, `zk_commit`, `zk_prove`, `zk_verify`, `zk_range_prove`, `zk_range_verify`

**L4 - Verifiable Reputation:** `reputation_record`, `reputation_query`, `reputation_query_weighted`, `reputation_export`, `reputation_import`, `bootstrap_create_escrow`, `bootstrap_provide_guarantee`

**Cross-Cutting:** `shr_generate`, `shr_verify`, `handshake_initiate`, `handshake_respond`, `handshake_complete`, `handshake_status`, `federation_peers`, `federation_trust_evaluate`, `federation_status`, `manifest`

## Requirements

- Node.js 22+ (for Sanctuary MCP server)
- Python 3.10+ (for LangChain)
- `langchain-mcp-adapters` >= 0.1.0
- `@sanctuary-framework/mcp-server` >= 0.3.1

## License

Apache-2.0
