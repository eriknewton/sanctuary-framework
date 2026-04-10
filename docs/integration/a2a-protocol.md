# Sanctuary on A2A Protocol

> Add sovereign identity, encrypted audit trails, and verifiable reputation
> to your A2A agent in under 60 seconds.

A2A (Agent-to-Agent) and MCP serve different roles: A2A handles agent discovery
and task delegation, MCP handles tool integration. Sanctuary runs as an MCP
server inside the A2A agent, and the A2A Agent Card advertises sovereignty
capabilities to peer agents.

```
+--------------------------------------+
| A2A Agent                            |
|                                      |
|  +--------------------------------+  |
|  | Agent Logic (ADK, LangGraph,  |  |
|  |  custom, etc.)                 |  |
|  |                                |  |
|  |  MCP Client --> Sanctuary MCP  |  |
|  |  MCP Client --> Concordia MCP  |  |
|  +--------------------------------+  |
|                                      |
|  A2A Server (AgentTaskManager)       |
|  /.well-known/agent-card.json        |
+--------------------------------------+
```

## Prerequisites

- An A2A-compatible agent framework (Google ADK, LangGraph, or custom)
- Node.js 18+
- Sanctuary: `npm install @sanctuary-framework/mcp-server@0.7.0`
  (or use `npx` for zero-install)

## Step 1: Add Sanctuary as MCP Server

The MCP config depends on your A2A agent framework.

### Google ADK

```python
from google.adk.tools.mcp_tool import MCPToolset, StdioServerParams

sanctuary_tools = MCPToolset(
    connection_params=StdioServerParams(
        command="npx",
        args=["@sanctuary-framework/mcp-server@0.7.0"]
    )
)

agent = Agent(
    model="gemini-2.0-flash",
    name="sovereign-agent",
    tools=[sanctuary_tools],
    instruction="You have Sanctuary sovereignty tools available. "
                "On startup, run sovereignty_health_report."
)
```

### LangGraph

```python
from langchain_mcp import MCPToolkit

toolkit = MCPToolkit(
    server_command="npx",
    server_args=["@sanctuary-framework/mcp-server@0.7.0"]
)

tools = toolkit.get_tools()
# Add tools to your LangGraph agent node
```

### Custom A2A Agent

Any framework that supports MCP stdio transport can spawn Sanctuary:

```python
import subprocess

sanctuary_process = subprocess.Popen(
    ["npx", "@sanctuary-framework/mcp-server@0.7.0"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
# Connect via MCP stdio protocol
```

## Step 2: Advertise Sovereignty in Your Agent Card

The Agent Card at `/.well-known/agent-card.json` tells peer agents that your
agent supports sovereignty handshakes, negotiation, and reputation verification.

```json
{
  "name": "My Sovereign Agent",
  "description": "An agent with cryptographic identity, audit trails, and verifiable reputation via Sanctuary Framework",
  "url": "https://my-agent.example.com",
  "version": "1.0.0",
  "capabilities": {
    "streaming": true,
    "pushNotifications": false
  },
  "skills": [
    {
      "id": "sovereignty-handshake",
      "name": "Sovereignty Handshake",
      "description": "Exchange and verify Sovereignty Health Reports (SHR) with peer agents. Proves L1-L4 sovereignty posture with cryptographic evidence.",
      "examples": [
        "Verify my sovereignty status",
        "Exchange sovereignty handshake with did:key:z6Mk..."
      ]
    },
    {
      "id": "concordia-negotiation",
      "name": "Structured Negotiation",
      "description": "Engage in propose/counter/accept/reject negotiation with binding commitments and session receipts via Concordia Protocol.",
      "examples": [
        "Negotiate a data sharing agreement",
        "Propose terms for API access"
      ]
    },
    {
      "id": "reputation-query",
      "name": "Reputation Query",
      "description": "Look up or publish agent reputation scores on Verascore.",
      "examples": [
        "What is your Verascore rating?",
        "Look up reputation for did:key:z6Mk..."
      ]
    }
  ],
  "securitySchemes": {
    "didAuth": {
      "type": "custom",
      "description": "Ed25519 challenge-response via Sanctuary identity"
    }
  },
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain", "application/json"]
}
```

## Step 3: Verify Sanctuary Is Active

Call `manifest` from your agent logic. You should see 68 Sanctuary tools listed.

## Step 4: Bind an Identity

```
Call: identity_create
Call: identity_set_primary with the new identity ID
```

## Step 5: Run a Sovereignty Health Report

```
Call: sovereignty_health_report
```

See the [verification checklist](./_verification-checklist.md) for expected results.

## Step 6: Publish to Verascore (Optional)

```
Call: reputation_publish
```

Visit `https://verascore.ai/agent/{did}` to see the live profile.

## What You Get

| Before Sanctuary | After Sanctuary |
|-----------------|-----------------|
| No agent identity | Ed25519 keypair + W3C DID |
| Opaque Agent Card | Agent Card with sovereignty skills |
| No cross-agent trust | Sovereignty handshake with peer verification |
| No reputation | Verifiable Verascore profile |
| No negotiation proof | Concordia session receipts as A2A artifacts |

## A2A-Specific Notes

**Agent Card as capability advertisement.** The Agent Card's `skills` array is
where peer A2A agents discover that your agent supports sovereignty handshakes,
Concordia negotiation, and reputation verification. This is the A2A-native
equivalent of Sanctuary's `manifest` tool — external discovery vs. internal
capability listing.

**Cross-agent sovereignty handshake over A2A.** Agent A sends a task to Agent B
requesting a sovereignty handshake. Agent B uses its local Sanctuary MCP tools
to generate its SHR, then returns it via A2A response. Agent A verifies the SHR
using its own Sanctuary tools. A2A provides the transport; Sanctuary provides
the handshake semantics.

**Concordia over A2A.** Concordia's propose/counter/accept/reject flow maps
naturally to A2A's task lifecycle. Each negotiation turn is an A2A message.
Session receipts are returned as A2A artifacts.

**Model-agnostic.** A2A agents can run any model (Gemini, Claude, GPT,
open-source). Sanctuary's MCP tools work regardless of the underlying model —
the sovereignty layer is model-independent.

**Sanctuary + Concordia together.** For full sovereign negotiation, add both
as MCP servers. Sanctuary handles identity and trust. Concordia handles
negotiation and agreement. Neither depends on the other, but they compose:

```python
# Google ADK example with both
sanctuary = MCPToolset(connection_params=StdioServerParams(
    command="npx", args=["@sanctuary-framework/mcp-server@0.7.0"]
))
concordia = MCPToolset(connection_params=StdioServerParams(
    command="python3", args=["-m", "concordia"]
))

agent = Agent(
    model="gemini-2.0-flash",
    name="sovereign-negotiator",
    tools=[sanctuary, concordia],
)
```

## Troubleshooting

**Agent Card not discoverable**
Ensure `/.well-known/agent-card.json` is served at the root of your agent's
URL with `Content-Type: application/json`. A2A clients look for this exact path.

**Sanctuary tools not available in ADK agent**
Verify the `MCPToolset` connection. Check that `npx` is in PATH for the server
process. Run `npx @sanctuary-framework/mcp-server@0.7.0` manually to confirm
it starts.

**Cross-agent handshake fails**
Both agents need Sanctuary. If the peer doesn't have Sanctuary, the handshake
degrades gracefully — returns "no SHR available" instead of failing.

**Concordia session receipts not returned as artifacts**
Ensure your `AgentTaskManager` includes receipt data in the A2A response
artifacts. Concordia generates receipts automatically; your agent code must
forward them.

**MCP connection timeout**
Some A2A frameworks have short MCP connection timeouts. Sanctuary's first
`npx` run downloads the package (~10s). Pre-install globally to avoid:
`npm install -g @sanctuary-framework/mcp-server@0.7.0`

## Next Steps

- Add Concordia for negotiation: `pip install concordia-protocol`
- Run the [verification checklist](./_verification-checklist.md)
- Read the full tool reference: https://github.com/eriknewton/sanctuary-framework
