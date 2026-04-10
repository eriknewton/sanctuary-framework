# Sanctuary on Agent Zero

> Add sovereign identity, encrypted audit trails, and verifiable reputation
> to your Agent Zero agent in under 60 seconds.

Agent Zero supports MCP servers natively since v0.9.x, including stdio and
streamable HTTP transports. Sanctuary integrates as a standard MCP server
connection — no plugins, no custom code.

## Prerequisites

- Agent Zero 0.9.3+ installed and running
- Node.js 18+ (in the Agent Zero environment — host or Docker)
- Sanctuary: `npm install @sanctuary-framework/mcp-server@0.7.0`
  (or use `npx` for zero-install)

## Step 1: Add Sanctuary to Your Config

### Option A: JSON Config

Edit your Agent Zero MCP server configuration:

```json
{
  "mcp_servers": {
    "sanctuary": {
      "command": "npx",
      "args": ["@sanctuary-framework/mcp-server@0.7.0"],
      "env": {
        "SANCTUARY_PASSPHRASE": "your-passphrase-here"
      }
    }
  }
}
```

### Option B: Web UI

1. Open Agent Zero web interface
2. Go to Settings → MCP Servers
3. Add new server:
   - **Name:** `sanctuary`
   - **Command:** `npx`
   - **Args:** `@sanctuary-framework/mcp-server@0.7.0`
   - **Environment:** `SANCTUARY_PASSPHRASE=your-passphrase`
4. Save and restart

## Step 2: Verify Sanctuary Is Active

Ask your agent: "List all available tools" or call `manifest` directly.
You should see 68 Sanctuary tools in the available tool list.

Agent Zero auto-discovers MCP tools from connected servers, so Sanctuary's
tools appear without additional configuration.

## Step 3: Bind an Identity

Ask your agent:

```
Create a new identity with identity_create, then set it as primary
with identity_set_primary.
```

## Step 4: Run a Sovereignty Health Report

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

## Agent Zero-Specific Notes

**Auto-discovery.** Agent Zero automatically discovers MCP tools from connected
servers. Sanctuary's 68 tools appear in the agent's available tool list without
additional configuration.

**Multi-agent.** Agent Zero supports subordinate agents. Each subordinate can
independently connect to Sanctuary MCP, getting its own identity and audit
trail — or share the parent's identity.

**Agent Zero as MCP server.** Agent Zero can also expose itself as an MCP
server (v0.9.3+). An Agent Zero instance running Sanctuary can be consumed by
Claude Agent SDK, Managed Agents, or any other MCP client — creating a
sovereignty-enabled Agent Zero bridge. Note: Sanctuary tools are NOT
automatically re-exported through Agent Zero's MCP server interface. For tool
passthrough, use Sanctuary's MCP Proxy mode (Cocoon).

**Docker deployment.** Agent Zero commonly runs in Docker. Ensure Node.js 18+
is available in the container:

```dockerfile
# Add to your Agent Zero Dockerfile
RUN npm install -g @sanctuary-framework/mcp-server@0.7.0
```

This pre-installs Sanctuary globally, avoiding `npx` download delays on
first run.

**Web UI verification.** After adding Sanctuary, the Agent Zero chat interface
shows Sanctuary tools in the "Available Tools" panel. Ask the agent:
"List all Sanctuary tools" to verify.

**Adding Concordia alongside Sanctuary.** Both run as separate MCP servers:

```json
{
  "mcp_servers": {
    "sanctuary": {
      "command": "npx",
      "args": ["@sanctuary-framework/mcp-server@0.7.0"],
      "env": { "SANCTUARY_PASSPHRASE": "your-passphrase" }
    },
    "concordia": {
      "command": "python3",
      "args": ["-m", "concordia"],
      "env": {}
    }
  }
}
```

## Troubleshooting

**"npx not found" in Docker**
Add `RUN apt-get update && apt-get install -y nodejs npm` to your Dockerfile,
or use a Node.js base image. Alternatively, install globally:
`RUN npm install -g @sanctuary-framework/mcp-server@0.7.0`

**MCP server timeout on startup**
Agent Zero has a connection timeout for MCP servers. Sanctuary's first `npx`
run downloads the package (~10s). Subsequent runs use the cached version. If
timeout occurs, pre-install globally:
`npm install -g @sanctuary-framework/mcp-server@0.7.0`

**Tool count seems low**
Agent Zero may use tool search or lazy loading for large tool sets. Ask the
agent to call `manifest` explicitly to see all 68 tools.

**Agent Zero MCP server doesn't expose Sanctuary tools**
Expected behavior. When Agent Zero exposes itself as an MCP server, it exports
its own native tools, not tools from connected MCP servers like Sanctuary. For
Sanctuary tool passthrough to downstream clients, use Sanctuary's Cocoon proxy.

**Permission errors on `~/.sanctuary/`**
In Docker, ensure the container user has write access to `~/.sanctuary/`.
Keys are created with mode 0600.

## Next Steps

- Add Concordia for negotiation: `pip install concordia-protocol`
- Run the [verification checklist](./_verification-checklist.md)
- Read the full tool reference: https://github.com/eriknewton/sanctuary-framework
