# Sanctuary on Claude Agent SDK

> Add sovereign identity, encrypted audit trails, and verifiable reputation
> to your Claude Agent SDK agent in under 60 seconds.

## Prerequisites

- Python 3.10+ with `anthropic` package, or Node.js 18+ with `@anthropic-ai/sdk`
- `ANTHROPIC_API_KEY` set in your environment
- Sanctuary: `npm install @sanctuary-framework/mcp-server`
  (or use `npx` for zero-install; it downloads on first run)

## Step 1: Add Sanctuary to Your Agent

### Python

```python
from anthropic import Anthropic

client = Anthropic()

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    system="You have Sanctuary Framework available. On startup, run sovereignty_health_report.",
    tools=[
        {
            "name": "bash",
            "description": "Run a shell command",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"}
                },
                "required": ["command"]
            }
        }
    ],
    # Sanctuary as MCP server, spawned automatically as a subprocess
    # Configure via the Claude Agent SDK's MCP server support
    messages=[{"role": "user", "content": "Check your sovereignty status."}]
)
```

For the Claude Agent SDK's native MCP integration (when using `claude_agent_sdk`):

```python
from claude_agent_sdk import query, ClaudeAgentOptions

async for message in query(
    prompt="Check your sovereignty status and run a health report",
    options=ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Bash", "Glob"],
        mcp_servers={
            "sanctuary": {
                "command": "npx",
                "args": ["@sanctuary-framework/mcp-server"]
            }
        }
    ),
):
    if hasattr(message, "result"):
        print(message.result)
```

### TypeScript

```typescript
import { query } from "@anthropic-ai/claude-agent-sdk";

for await (const message of query({
  prompt: "Check your sovereignty status and run a health report",
  options: {
    allowedTools: ["Read", "Write", "Bash", "Glob"],
    mcpServers: {
      sanctuary: {
        command: "npx",
        args: ["@sanctuary-framework/mcp-server"]
      }
    }
  }
})) {
  if ("result" in message) console.log(message.result);
}
```

### Claude Code (`.claude/settings.json` or `.mcp.json`)

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

## Step 2: Verify Sanctuary Is Active

Ask your agent to call `manifest`. You should see the full Sanctuary tool surface listed.

## Step 3: Bind an Identity

Ask your agent:

```
Create a new identity with identity_create, then set it as primary
with identity_set_primary.
```

The agent receives a DID like `did:key:z6Mk...`, a W3C-standard
decentralized identifier backed by an Ed25519 keypair.

## Step 4: Run a Sovereignty Health Report

Ask your agent:

```
Run sovereignty_health_report and show me the L1-L4 status.
```

See the [verification checklist](./_verification-checklist.md) for expected results.

## Step 5: Publish to Verascore (Optional)

```
Publish my sovereignty status to Verascore with reputation_publish.
```

Visit `https://verascore.ai/agent/{did}` to see the live profile.

## What You Get

| Before Sanctuary | After Sanctuary |
|-----------------|-----------------|
| No agent identity | Ed25519 keypair + W3C DID |
| Default logging | Encrypted, tamper-proof audit trail |
| No reputation | Verifiable Verascore profile |
| Platform-locked trust | Portable across any runtime |
| No sovereignty proof | L1-L4 Sovereignty Health Report |

## Runtime Notes

- Agent SDK spawns Sanctuary as a stdio subprocess automatically via `mcp_servers`
- No port conflicts (stdio transport, not HTTP)
- Works on macOS, Linux, WSL2. Node.js 18+ required for the Sanctuary subprocess.
- If using subagents (`Agent` tool), each subagent can independently declare
  Sanctuary, or inherit from the parent
- Session resumption preserves MCP server state (identity persists across turns
  within a session)
- Sanctuary stores keys and state at `~/.sanctuary/`. Ensure the user running
  the agent has write access.

## Troubleshooting

**"MCP server failed to start"**
Check `node --version` (need 18+). Run `npx @sanctuary-framework/mcp-server`
manually to verify it starts and prints tool definitions to stdout.

**Sanctuary tools not appearing**
Verify `mcp_servers` is inside `ClaudeAgentOptions`, not at the top level of `query()`.

**Tool search deferring Sanctuary tools**
Agent SDK enables tool search by default for large tool sets. Sanctuary's
tools may be deferred. The agent loads them on demand, but if you need specific
tools immediately, reference them by name in the prompt (e.g., "call `manifest`").

**Permission errors on identity files**
Sanctuary stores keys at `~/.sanctuary/`. Keys are created with mode 0600.
Ensure the process user has write access to that directory.

**First run is slow**
`npx` downloads the package on first invocation (~10s). Subsequent runs use
the cached version. For faster cold starts, install globally:
`npm install -g @sanctuary-framework/mcp-server`

## Next Steps

- Add Concordia for negotiation: `pip install concordia-protocol`
- Run the [verification checklist](./_verification-checklist.md)
- Read the full tool reference: https://github.com/eriknewton/sanctuary-framework
