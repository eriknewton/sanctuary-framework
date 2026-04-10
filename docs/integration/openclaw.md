# Sanctuary on OpenClaw

> Add sovereign identity, encrypted audit trails, and verifiable reputation
> to your OpenClaw agent in under 60 seconds.

Verified working on Mac Mini M4 running OpenClaw 2026.4.2 + Sanctuary v0.7.0.
68 tools registered, sovereignty handshakes completed, Verascore publish proven.

## Prerequisites

- OpenClaw installed and running
- Node.js 18+
- Sanctuary: `npm install @sanctuary-framework/mcp-server@0.7.0`
  (or use `npx` for zero-install)

## Step 1: Add Sanctuary to Your Config

Edit `~/.openclaw/openclaw.json` (or `~/.openclaw/agents/{agent}/config.json`):

```json
{
  "mcp": {
    "servers": {
      "sanctuary": {
        "command": "npx",
        "args": ["@sanctuary-framework/mcp-server@0.7.0"],
        "env": {
          "SANCTUARY_PASSPHRASE": "your-passphrase-here"
        }
      }
    }
  }
}
```

Restart OpenClaw. Sanctuary tools load automatically.

**Important:** Do NOT add `"--dashboard"` to the args array. See Troubleshooting.

## Step 2: Verify Sanctuary Is Active

Call `sanctuary__manifest` from your agent. You should see 68 tools listed.

Note the `sanctuary__` prefix — OpenClaw namespaces MCP tools as
`{server}__{tool}`. So `manifest` becomes `sanctuary__manifest`,
`identity_create` becomes `sanctuary__identity_create`, etc.

## Step 3: Bind an Identity

```
Call: sanctuary__identity_create
Call: sanctuary__identity_set_primary with the new identity ID
```

## Step 4: Run a Sovereignty Health Report

```
Call: sanctuary__sovereignty_health_report
```

See the [verification checklist](./_verification-checklist.md) for expected results.

## Step 5: Publish to Verascore (Optional)

```
Call: sanctuary__reputation_publish
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

## OpenClaw-Specific Notes

**Tool naming.** OpenClaw namespaces all MCP tools as `{server}__{tool}`.
With Sanctuary v0.7.0 (unprefixed tools), you get clean names like
`sanctuary__manifest`, `sanctuary__identity_create`. Prior to v0.7.0, the old
`sanctuary/` prefix caused double-mangling (`sanctuary__sanctuary-manifest`).
Always use v0.7.0+.

**No `--dashboard` flag.** Do NOT add `"--dashboard"` to the args array. The
dashboard opens an HTTP listener inside the stdio subprocess, breaking
OpenClaw's stdio communication. Run the dashboard as a separate process if
needed:

```bash
# Dashboard as separate process (optional)
npx @sanctuary-framework/mcp-server@0.7.0 --dashboard --dashboard-port 3501 &
```

**Environment variables.** OpenClaw passes only the `env` vars defined in the
server config block to the subprocess. Include `SANCTUARY_PASSPHRASE` for
encrypted audit trails. Do NOT include `SANCTUARY_DASHBOARD_ENABLED` or
`SANCTUARY_DASHBOARD_AUTH_TOKEN` in the MCP server config.

**Cocoon wrapper (experimental).** `cocoon --openclaw` can wrap all upstream
MCP servers through Sanctuary's proxy enforcement chain. Known bug: the wrapper
drops env vars and extra servers. Use direct config (above) for now. Cocoon
wrapper fix tracked for v0.8.0.

**Adding Concordia alongside Sanctuary.** Both can run as separate MCP servers:

```json
{
  "mcp": {
    "servers": {
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
}
```

## Troubleshooting

**Double tool name prefix (`sanctuary__sanctuary-manifest`)**
You're on Sanctuary < v0.7.0. Upgrade:
`npm install @sanctuary-framework/mcp-server@0.7.0`

**"MCP server failed to initialize" / subprocess crash**
Remove `--dashboard` from args. This is the most common cause. Check
`node --version >= 18`. Run `npx @sanctuary-framework/mcp-server@0.7.0`
manually in a terminal to verify it starts.

**Env vars not reaching Sanctuary**
Verify they're in the `"env"` block of the server config, not at the top level
of `openclaw.json`. OpenClaw passes only what's in `env`.

**Tools not appearing in agent**
Run `npx @sanctuary-framework/mcp-server@0.7.0` manually to verify it starts.
Check OpenClaw logs at `~/.openclaw/logs/`.

**Tools show "Not connected" when called**
Known issue with some OpenClaw versions. Verify the agent is using the correct
namespaced tool names (`sanctuary__manifest`, not `manifest`). If the problem
persists, restart OpenClaw — the MCP subprocess may need a clean reconnection.

**Cocoon `--openclaw` drops servers**
Known bug. Don't use `cocoon --openclaw --wrap` in production yet. Direct
config (Step 1 above) works reliably.

**OpenClaw update breaks dependencies**
OpenClaw 2026.4.5 had missing peer dependencies. If an update breaks, roll
back: the `~/.openclaw/` config is compatible across versions.

## Next Steps

- Add Concordia for negotiation: `pip install concordia-protocol`
- Run the [verification checklist](./_verification-checklist.md)
- Read the full tool reference: https://github.com/eriknewton/sanctuary-framework
