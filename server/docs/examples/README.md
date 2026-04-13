# Sanctuary Configuration Examples

## parallel-mcp-config.json

Reference MCP configuration for running Sanctuary alongside another MCP server in the same agent session.

Replace `your-agent-server` with your agent's actual MCP server config. Both servers appear as separate tool providers — the agent sees tools from both.

Set `SANCTUARY_PASSPHRASE` via environment variable or a `.env` file with `chmod 600` permissions. See the [Deployment Guide](../DEPLOYMENT.md) for passphrase management details.
