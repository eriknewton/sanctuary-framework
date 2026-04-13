# Deployment Guide — Running Sanctuary as a Persistent Service

This guide covers running Sanctuary as a long-lived MCP server alongside another agent's MCP server. It is written for people who run servers.

## System Requirements

- Node.js >= 22.0.0
- npm >= 10.0.0

## Installation Options

### npx (dev/testing only)

```bash
npx @sanctuary-framework/mcp-server
```

Always pulls the latest version. Network-dependent on every cold start — bad for systemd restart loops where the process might cycle and hit npm repeatedly.

### Global install

```bash
npm install -g @sanctuary-framework/mcp-server@0.8.0
```

Faster startup (no network on launch), but version pinning is manual. You must remember to update.

### Local project install (recommended for production)

```bash
mkdir sanctuary && cd sanctuary
npm init -y
npm install @sanctuary-framework/mcp-server@0.8.0 --save-exact
```

Pin an exact version. No network on restart. Update deliberately with `npm update`. This is the recommended approach for persistent services.

## Passphrase Management

Generate a passphrase:

```bash
openssl rand -base64 32
```

Store it in a gitignored env file:

```bash
echo 'SANCTUARY_PASSPHRASE="your-generated-passphrase"' > ~/.config/sanctuary/sanctuary.env
chmod 600 ~/.config/sanctuary/sanctuary.env
```

> **WARNING:** Your Sanctuary passphrase is the only way to decrypt your agent's state. If the passphrase is lost, all encrypted data is unrecoverable by design. Back up the passphrase to a separate secrets manager, encrypted USB, or password vault. Do not store it alongside the encrypted state.

## Parallel MCP Server Configuration

Sanctuary runs alongside your agent's own MCP server. Both appear as separate tool providers in the same session.

### npx variant

```json
{
  "mcpServers": {
    "your-agent-server": {
      "url": "http://localhost:8766/mcp"
    },
    "sanctuary": {
      "command": "npx",
      "args": ["@sanctuary-framework/mcp-server"],
      "env": {
        "SANCTUARY_PASSPHRASE": "your-passphrase-here"
      }
    }
  }
}
```

### Local install variant (recommended)

```json
{
  "mcpServers": {
    "your-agent-server": {
      "url": "http://localhost:8766/mcp"
    },
    "sanctuary": {
      "command": "node",
      "args": ["./sanctuary/node_modules/.bin/sanctuary-mcp-server"],
      "env": {
        "SANCTUARY_PASSPHRASE": "your-passphrase-here"
      }
    }
  }
}
```

See [`docs/examples/parallel-mcp-config.json`](examples/parallel-mcp-config.json) for a reference config file.

## systemd Service Unit

Create `/etc/systemd/user/sanctuary-mcp.service`:

### Using local install (recommended)

```ini
[Unit]
Description=Sanctuary MCP Server
After=network.target

[Service]
Type=simple
EnvironmentFile=%h/.config/sanctuary/sanctuary.env
ExecStart=/usr/bin/node %h/sanctuary/node_modules/.bin/sanctuary-mcp-server
Restart=on-failure
RestartSec=5s
WorkingDirectory=%h

[Install]
WantedBy=default.target
```

### Using npx

```ini
[Unit]
Description=Sanctuary MCP Server
After=network.target

[Service]
Type=simple
EnvironmentFile=%h/.config/sanctuary/sanctuary.env
ExecStart=/usr/bin/npx @sanctuary-framework/mcp-server
Restart=on-failure
RestartSec=5s
WorkingDirectory=%h

[Install]
WantedBy=default.target
```

Enable and start:

```bash
systemctl --user daemon-reload
systemctl --user enable sanctuary-mcp
systemctl --user start sanctuary-mcp
```

## Bootstrap and First Run

After installation, run these tools in your first agent session:

1. **`sanctuary_bootstrap`** — Creates an Ed25519 identity, generates a Sovereignty Health Report, and optionally publishes to Verascore. Save the DID it returns.

2. **`sovereignty_audit`** — Runs a four-layer gap analysis and produces a baseline posture score (0–100). Use this to verify everything initialized correctly.

## Principal Policy for Always-On Agents

The default Principal Policy gates `sanctuary_bootstrap` as Tier 1 (requires human approval). For persistent agents with latency constraints, use the `persistent-agent` policy template which auto-allows routine operations and only gates destructive or external-facing actions.

Copy the template to your Sanctuary config:

```bash
cp node_modules/@sanctuary-framework/mcp-server/src/principal-policy/templates/persistent-agent.yaml \
   ~/.sanctuary/principal-policy.yaml
```

Or reference it in the [template directory](../src/principal-policy/templates/persistent-agent.yaml).

## Rollback

Remove from Claude Code:

```bash
claude mcp remove sanctuary
```

If Cocoon was enabled:

```bash
npx @sanctuary-framework/mcp-server cocoon --unwrap
```

Sanctuary's encrypted state remains in `~/.sanctuary/` until manually deleted.
