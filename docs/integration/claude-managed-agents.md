# Sanctuary on Claude Managed Agents

> Add sovereign identity, encrypted audit trails, and verifiable reputation
> to your Managed Agent in under 60 seconds.

## Prerequisites

- Anthropic Managed Agents access (research preview or GA)
- Sanctuary: `npm install @sanctuary-framework/mcp-server@0.7.0`
  (Node.js is pre-installed in Managed Agents containers)

## Step 1: Add Sanctuary to Your Agent Config

In your Managed Agent definition, add Sanctuary as an MCP server:

```yaml
agent:
  model: claude-sonnet-4-5-20250514
  system_prompt: |
    You have Sanctuary Framework available via MCP.
    On startup, call sovereignty_health_report to verify your status.
  tools:
    - type: agent_toolset_20260401
  mcp_servers:
    - name: sanctuary
      command: npx
      args: ["@sanctuary-framework/mcp-server@0.7.0"]
```

Deploy the agent. Sanctuary tools load automatically via MCP.

## Step 2: Verify Sanctuary Is Active

Call `manifest` from your agent. You should see 80+ Sanctuary tools listed.

## Step 3: Bind an Identity

```
Call: identity_create
Call: identity_set_primary with the new identity ID
```

The agent receives a DID like `did:key:z6Mk...` backed by an Ed25519 keypair.

## Step 4: Run a Sovereignty Health Report

```
Call: sovereignty_health_report
```

See the [verification checklist](./_verification-checklist.md) for expected results.

## Step 5: Publish to Verascore (Optional)

```
Call: reputation_publish
```

Visit `https://verascore.ai/agent/{did}` to see the live profile.

## What You Get

| Before Sanctuary | After Sanctuary |
|-----------------|-----------------|
| Implicit cloud identity | Explicit agent-owned Ed25519 keypair |
| Default logging | Encrypted, tamper-evident hash-chained audit trail; production audit checkpoints are currently unsigned until **IC-05** closes |
| Platform-level policy (static) | Principal-level policy (dynamic, time-locked) |
| All-or-nothing disclosure | Selective disclosure (ZK attestations) |
| Opaque reputation | Verifiable Verascore profile |

## Managed Agents-Specific Notes

**Container environment.** Node.js is pre-installed in Managed Agents
containers. `npx` works out of the box.

**Network access.** Sanctuary's Verascore publishing (`reputation_publish`)
requires outbound HTTPS to `verascore.ai`. Ensure your environment's network
rules allow it.

**Identity persistence.** Container filesystems persist within a session but
not across sessions. For durable identity across sessions:
- Export the keypair JSON at session end
- Re-import at session start
- Or use a deterministic seed so the same DID regenerates each time

**Multi-agent.** If using `callable_agents`, each thread agent can independently
run Sanctuary: one identity per thread agent, or a shared identity via seed.

**SIEM export.** Use `audit_export_siem` to push CEF/OCSF-formatted audit
events to your SIEM (Datadog, Splunk, Chronicle) from inside the container.

## Troubleshooting

**"npx: command not found"**
Unlikely in Managed Agents (Node.js is pre-installed). If using a custom
environment, ensure Node.js 18+ is in PATH.

**Verascore publish fails with network error**
Check environment network access rules. `verascore.ai` must be in the
outbound allowlist.

**Identity lost between sessions**
Expected behavior: container filesystems are ephemeral. Export the identity
keypair at session end, or use a deterministic seed for consistent DID
generation.

**Tool confirmation prompts for Sanctuary tools**
If tools are configured with confirmation requirements, Sanctuary's audit and
identity tools will trigger them. Consider whitelisting Sanctuary tools in your
tool confirmation config.

**First run is slow**
`npx` downloads the package on first invocation (~10s). For faster cold
starts, add `RUN npm install -g @sanctuary-framework/mcp-server@0.7.0` to
your container setup.

## Next Steps

- Add Concordia for negotiation: `pip install concordia-protocol`
- Run the [verification checklist](./_verification-checklist.md)
- Read the full tool reference: https://github.com/eriknewton/sanctuary-framework
