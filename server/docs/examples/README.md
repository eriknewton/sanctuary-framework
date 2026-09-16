# Sanctuary Configuration Examples

## parallel-mcp-config.json

Reference MCP configuration for running Sanctuary alongside another MCP server
in the same agent session.

This shape is not the recommended install path. Both servers appear as separate
tool providers, so calls made directly to `your-agent-server` do not pass
through Sanctuary's cooperative policy gate. Castle Wall, when installed and
armed on macOS, remains an independent OS-level egress boundary.

Prefer `sanctuary protect`, which preserves existing MCP entries and makes
Sanctuary the cooperative gateway. The JSON example assumes the fortress has
already been provisioned and has host-local custody. Replace the fortress path
with its absolute path. If enrolled host-local custody is unavailable, this
example fails closed; use the operator-managed startup path in the Deployment
Guide instead. Never copy a passphrase or recovery key into harness
configuration. See the [Deployment Guide](../DEPLOYMENT.md).
