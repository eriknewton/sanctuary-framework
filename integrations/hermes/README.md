# Sanctuary + Hermes Agent Integration

Use Sanctuary's sovereignty infrastructure with Hermes Agent, the open-source self-improving agent framework by Nous Research.

## Overview

Hermes Agent has native MCP support - Sanctuary's 67+ MCP tools work seamlessly via Hermes's configuration layer. Hermes's multi-level memory, subagent isolation, and scheduled automations compose naturally with Sanctuary's four sovereignty layers.

What you get: encrypted state (L1), process isolation with Sanctuary attestation (L2), selective disclosure (L3), and verifiable reputation (L4) - plus Hermes's native features like memory encryption, subagent sandboxing, and automated sovereignty audits on a cron schedule.

**New in v0.5.16:** Proxy mode turns Sanctuary into an MCP proxy that wraps all upstream MCP servers through an enforcement chain (injection scan → gate → context gate → governor → forward → audit). Hermes agents can route all their MCP traffic through Sanctuary for runtime governance without changing any upstream server configs.

## Quick Start

### 1. Install dependencies

```bash
# Hermes Agent (latest)
pip install hermes-agent

# Or from source
git clone https://github.com/NousResearch/hermes-agent.git
cd hermes-agent
pip install -e .

# Node.js 22+ for Sanctuary MCP server
node --version  # must be v22+
```

### 2. Create a Hermes config file

Create `hermes_config.yaml`:

```yaml
agent:
  name: "Sovereign Research Agent"
  model: "openai:gpt-4"  # or your preferred model
  memory:
    type: "encrypted"
    encryption_key: "${HERMES_MEMORY_KEY}"  # Set via env var for security
    persistence: "disk"

mcps:
  sanctuary:
    command: "npx"
    args:
      - "@sanctuary-framework/mcp-server"
    transport: "stdio"
    env:
      SANCTUARY_STORAGE_PATH: "~/.sanctuary/hermes-agent"

capabilities:
  tools:
    - sanctuary/*
```

### 3. Run the agent

```bash
export HERMES_MEMORY_KEY=$(openssl rand -base64 32)
hermes run hermes_config.yaml
```

Your agent now has full Sanctuary integration. All 67+ tools are available as native Hermes capabilities.

## Proxy Mode - MCP Proxy for Runtime Governance

Proxy mode is Sanctuary's MCP proxy. Instead of each Hermes agent connecting directly to upstream MCP servers, Sanctuary sits in front and enforces security on every tool call.

### How it works

```
Hermes Agent
  → Sanctuary MCP (sole connection)
    → Injection scan (unicode sanitization, homoglyph normalization, encoded content decoding)
    → Approval gate (Tier 1/2/3 policy evaluation)
    → Context gate (redact sensitive fields before forwarding)
    → Call governor (rate limits, duplicate detection, volume caps)
    → Forward to upstream MCP server
    → Outbound scan (secret detection, markdown exfil, internal path leak)
    → Audit log
  ← Response back to Hermes
```

### Configuration

```yaml
agent:
  name: "Sanctuary-Protected Agent"
  model: "openai:gpt-4"

mcps:
  # Sanctuary is the ONLY MCP connection
  sanctuary:
    command: "npx"
    args:
      - "@sanctuary-framework/mcp-server"
    transport: "stdio"
    env:
      SANCTUARY_STORAGE_PATH: "~/.sanctuary/hermes-mantle"

  # DO NOT connect upstream servers here - Sanctuary proxies them

capabilities:
  tools:
    - sanctuary/*
    - proxy/*  # Proxied upstream tools appear as proxy/{server}/{tool}
```

### Registering upstream servers

After startup, register your upstream MCP servers through Sanctuary:

```python
# In your Hermes startup task:
"""
Register upstream MCP servers with Sanctuary's proxy:

1. Call sanctuary/proxy_register_upstream with:
   - name: "web-search"
   - command: "npx"
   - args: ["-y", "@anthropic/web-search-mcp"]
   - tier: "tier3"  # auto-allow with audit

2. Call sanctuary/proxy_register_upstream with:
   - name: "filesystem"
   - command: "npx"
   - args: ["-y", "@anthropic/filesystem-mcp", "/home/agent/workspace"]
   - tier: "tier2"  # anomaly-triggered approval

3. Call sanctuary/proxy_discover_tools to discover all proxied tools

Now use proxy/web-search/search and proxy/filesystem/read_file -
every call passes through Sanctuary's enforcement chain.
"""
```

### What the proxy protects against

- **Prompt injection via MCP responses:** Unicode invisible characters, homoglyph attacks, base64-encoded payloads, and token budget attacks are stripped before responses reach the agent
- **Secret exfiltration:** Outbound content is scanned for 20+ secret patterns (API keys, tokens, connection strings), markdown exfiltration attempts, and internal path/IP leaks
- **Runaway tool calls:** The Call Governor enforces volume limits (200 calls/10min), rate detection (20/min per tool), SHA-256 duplicate caching, and a lifetime hard stop (1000 calls)
- **Unauthorized operations:** Every proxied call passes through the approval gate - Tier 1 ops require human confirmation, Tier 2 triggers on anomalies

### Governor status

Monitor and manage the Call Governor at runtime:

```python
# Check governor status
"""Call sanctuary/governor_status to see:
- Total calls made
- Rate per tool
- Duplicate cache hits
- Time until rate window resets"""

# Reset governor counters (Tier 1 - requires approval)
"""Call sanctuary/governor_reset to clear all counters and rate limits"""
```

## Sovereignty-Aware Patterns

### Memory Sovereignty (L1 + Hermes Encryption)

Hermes's multi-level memory system stores working context, task history, and learned patterns. Layer it with Sanctuary's state encryption:

```yaml
agent:
  name: "Encrypted Research Agent"
  memory:
    type: "encrypted"
    levels:
      short_term:
        size: 8192
        ttl: 3600
        encryption: true  # Use Hermes's native encryption
      long_term:
        size: 102400
        ttl: 604800
        encryption: true
        backend: "disk"

  # Additionally use Sanctuary L1 for sensitive findings
  # Example task will call sanctuary/state_write for each research result
```

**Pattern:** Hermes encrypts memory automatically; Sanctuary encrypts specific state entries that need portable, cryptographically signed proof of secrecy. Use both layers:
- Hermes memory: working context, intermediate reasoning, task tracking
- Sanctuary state: sensitive findings, secrets, data that might be shared with other agents

### Subagent Isolation with Sovereign Boundaries (L2)

Hermes supports spawning isolated subagents for parallel or specialized work. Give each subagent its own Sanctuary identity:

```yaml
agent:
  name: "Coordinator"
  mcps:
    sanctuary:
      command: "npx"
      args: ["-y", "@sanctuary-framework/mcp-server"]
      env:
        SANCTUARY_STORAGE_PATH: "~/.sanctuary/coordinator"

  subagents:
    - name: "researcher"
      model: "openai:gpt-4"
      backend: "docker"  # Run in container for isolation
      mcps:
        sanctuary:
          command: "npx"
          args: ["-y", "@sanctuary-framework/mcp-server"]
          env:
            SANCTUARY_STORAGE_PATH: "~/.sanctuary/researcher"

    - name: "reviewer"
      model: "openai:gpt-4"
      backend: "docker"
      mcps:
        sanctuary:
          command: "npx"
          args: ["-y", "@sanctuary-framework/mcp-server"]
          env:
            SANCTUARY_STORAGE_PATH: "~/.sanctuary/reviewer"
```

Each subagent:
- Runs in its own process (Hermes backend isolation)
- Holds a separate Ed25519 keypair (Sanctuary identity)
- Has encrypted state isolation (Sanctuary L1)
- Can be attested independently (Sanctuary L2)

The coordinator uses `sanctuary/handshake_initiate` to establish trust with subagents and `sanctuary/reputation_record` to track their work quality.

### Scheduled Sovereignty Audits

Use Hermes's scheduled automations to run sovereignty audits on a cron schedule:

```yaml
agent:
  name: "Self-Auditing Agent"
  mcps:
    sanctuary:
      command: "npx"
      args: ["-y", "@sanctuary-framework/mcp-server"]

  automations:
    - name: "daily_sovereignty_audit"
      schedule: "0 2 * * *"  # 2 AM every day
      task: |
        Run a comprehensive sovereignty audit:
        1. Call sanctuary/sovereignty_audit to assess L1-L4 posture
        2. Call sanctuary/shr_generate to produce a Sovereignty Health Report
        3. Store the audit result in sanctuary/state_write with key 'audit_latest'
        4. If audit score < 0.8, trigger an alert via sanctuary/principal_policy_view

    - name: "weekly_reputation_snapshot"
      schedule: "0 3 * * 0"  # 3 AM every Sunday
      task: |
        Snapshot your reputation status:
        1. Call sanctuary/reputation_query to fetch all reputation attestations
        2. Calculate weighted score using sanctuary/reputation_query_weighted
        3. Store snapshot in sanctuary/state_write with key 'reputation_weekly'
        4. Use sanctuary/reputation_export to create a portable reputation artifact

    - name: "governor_health_check"
      schedule: "*/30 * * * *"  # Every 30 minutes
      task: |
        Check Call Governor health:
        1. Call sanctuary/governor_status to get current rate and volume stats
        2. If approaching limits (>80% of volume cap), log a warning
        3. Store status in sanctuary/state_write with key 'governor_latest'
```

### Container Hardening + Sanctuary (L2 Enhanced)

Run Hermes in a hardened container and layer Sanctuary's L2 attestation:

```bash
# Build a hardened Hermes container
cat > Dockerfile <<'EOF'
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nodejs npm \
    ca-certificates \
    curl \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Hermes and dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user
RUN useradd -m -u 1000 hermes
USER hermes

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import hermes; print('ok')" || exit 1

ENTRYPOINT ["hermes", "run"]
CMD ["hermes_config.yaml"]
EOF

# Run with resource limits
docker run \
  --rm \
  -e SANCTUARY_STORAGE_PATH=/home/hermes/.sanctuary \
  -e HERMES_MEMORY_KEY=$(openssl rand -base64 32) \
  --cpus=2 \
  --memory=4g \
  --pids-limit=512 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --read-only \
  --tmpfs=/tmp \
  hermes:latest
```

After the container starts, the Hermes agent can call `sanctuary/exec_attest` to generate a signed attestation of its runtime environment, providing L2 evidence that it's running in a hardened container.

### Context Gating for Inference Calls (L3)

Hermes sends prompts to LLM providers for inference. Protect your reasoning with context gating:

```yaml
agent:
  name: "Privacy-Conscious Agent"
  mcps:
    sanctuary:
      command: "npx"
      args: ["-y", "@sanctuary-framework/mcp-server"]

  startup:
    - |
      Set up context gating to redact sensitive data before inference calls:
      1. Call sanctuary/context_gate_apply_template with 'inference-standard'
      2. This ensures PII, secrets, and raw findings are redacted before prompt submission
      3. Verify with sanctuary/context_gate_list_policies
```

All inference calls from the agent will then pass through Sanctuary's gating layer, removing secrets before they reach the LLM API.

### Verascore Reputation Publishing (L4)

Publish your agent's Sovereignty Health Report to [Verascore](https://verascore.ai), the public reputation registry for AI agents:

```python
# After generating an SHR, publish it to Verascore:
"""
1. Call sanctuary/shr_generate to produce your latest SHR
2. Call sanctuary/reputation_publish with:
   - target_url: "https://verascore.ai/api/publish"
   - The tool will sign the payload with your Ed25519 key
   - DID verification ensures only you can publish your reputation
3. Your agent now has a public, verifiable reputation page on verascore.ai
"""
```

This gives your Hermes agent a public reputation profile that other agents and humans can verify - the "LinkedIn for agents" layer.

### Portable Reputation Across Subagents (L4)

Build trust networks between Hermes subagents using Sanctuary's verifiable reputation:

```python
# In your Hermes task definition:
"""
You are a research coordinator managing three subagents.

1. Initialize your identity and each subagent's identity:
   - Call sanctuary/identity_create to create your coordinator identity
   - Instruct each subagent to call sanctuary/identity_create

2. After each subagent completes work:
   - Call sanctuary/reputation_record to record their performance
   - Rate them: positive for quality work, negative for errors

3. Before assigning critical work:
   - Call sanctuary/reputation_query_weighted to fetch their weighted score
   - Use their SHR (via sanctuary/shr_verify) to check sovereignty posture
   - Prefer subagents with high reputation AND high sovereignty scores

4. Export portable reputation for inter-agent negotiation:
   - Call sanctuary/reputation_export to create a signed artifact
   - Publish to Verascore via sanctuary/reputation_publish
"""
```

## Hermes-Specific Features That Enhance Sovereignty

### 1. Backend Flexibility

Hermes supports six backends. Each maps to different deployment scenarios:

| Backend | Use Case | Sanctuary Mapping |
|---------|----------|------------------|
| `local` | Development, low-risk tasks | L1 full, L2 degraded (no isolation) |
| `docker` | Production hardened agents | L1 full, L2 hardened (container isolation) |
| `ssh` | Distributed agents across machines | L1 full, L2 hardened (network + SSH keys) |
| `daytona` | Cloud development environments | L1 full, L2 variable (vendor-dependent) |
| `singularity` | HPC environments, reproducible containers | L1 full, L2 hardened (strict isolation) |
| `modal` | Serverless elastic scaling | L1 full, L2 degraded (ephemeral, vendor-mediated) |

For the highest sovereignty score, use `docker` or `ssh` with Sanctuary's L2 attestation.

### 2. Protocol-Level MCP Support

Hermes can run as an MCP server itself (`hermes mcp serve`), making it composable with other agents:

```bash
# Terminal 1: Run Hermes as an MCP server
hermes mcp serve --port 9000

# Terminal 2: Another agent can call into Hermes via MCP
# Hermes-managed teams offer themselves as services to larger systems
```

This enables hierarchical agent compositions where Hermes-managed teams offer themselves as services to larger systems.

### 3. Multi-Model Support with Per-Model Context Gating

Hermes supports fallback models for resilience. Pair with Sanctuary's context gating to control what each model receives:

```yaml
agent:
  model: "openai:gpt-4"
  fallback_models:
    - "anthropic:claude-sonnet-4-6"
    - "openai:gpt-3.5-turbo"

  # Pair with Sanctuary's L3 (selective disclosure)
  # to control what information each model receives
  context_gates:
    "openai:gpt-4": "inference-standard"           # Full access
    "anthropic:claude-sonnet-4-6": "inference-limited"  # Redacted
    "openai:gpt-3.5-turbo": "inference-minimal"     # Minimal context
```

Different models get different context depending on their trustworthiness and your disclosure policies.

## Adding Concordia (Negotiation)

For structured negotiation between Hermes agents or with other sovereign systems, add [Concordia Protocol](https://pypi.org/project/concordia-protocol/):

```bash
pip install concordia-protocol
```

```yaml
agent:
  name: "Negotiating Agent"
  mcps:
    sanctuary:
      command: "npx"
      args: ["-y", "@sanctuary-framework/mcp-server"]
      env:
        SANCTUARY_STORAGE_PATH: "~/.sanctuary/negotiator"

    concordia:
      command: "python"
      args: ["-m", "concordia"]
      transport: "stdio"
```

A single task can now:
1. Use Sanctuary for cryptographic identity and state encryption
2. Use Concordia to propose, counter, and commit to agreements
3. Call `sanctuary/bridge_commit` to bind Concordia agreements to your sovereign identity

Sanctuary and Concordia compose but neither depends on the other. Use either alone or both together.

## Available Sanctuary Tools (67+)

All Sanctuary tools are exposed as Hermes capabilities. Key categories:

**L1 - Cognitive Sovereignty:** `state_read`, `state_write`, `state_list`, `state_export`, `state_import`, `state_delete`

**L1 - Identity:** `identity_create`, `identity_list`, `identity_sign`, `identity_verify`, `identity_rotate`

**L2 - Operational Isolation:** `exec_attest`, `principal_policy_view`, `principal_baseline_view`, `monitor_health`, `monitor_audit_log`

**L2 - Context Gating:** `context_gate_set_policy`, `context_gate_apply_template`, `context_gate_recommend`, `context_gate_filter`, `context_gate_list_policies`

**L3 - Selective Disclosure:** `proof_commitment`, `proof_reveal`, `disclosure_set_policy`, `disclosure_evaluate`, `zk_commit`, `zk_prove`, `zk_verify`, `zk_range_prove`, `zk_range_verify`

**L4 - Verifiable Reputation:** `reputation_record`, `reputation_query`, `reputation_query_weighted`, `reputation_export`, `reputation_import`, `reputation_publish`, `bootstrap_create_escrow`, `bootstrap_provide_guarantee`

**Sovereignty Health:** `shr_generate`, `shr_verify`, `sovereignty_audit`

**Handshake & Federation:** `handshake_initiate`, `handshake_respond`, `handshake_complete`, `handshake_status`, `federation_peers`, `federation_trust_evaluate`, `federation_status`

**MCP Proxy:** `proxy_register_upstream`, `proxy_discover_tools`, `proxy/{server}/{tool}` (dynamic)

**Runtime Governance:** `governor_status`, `governor_reset`

**Dashboard & Profile:** `sovereignty_profile_update`, `sovereignty_profile_view`, `sovereignty_profile_generate_prompt`

**Bridge (Concordia):** `bridge_commit`, `bridge_verify`, `bridge_attest`

**Other:** `manifest`, `decommission_initiate`, `decommission_status`

## Requirements

- Python 3.10+
- Hermes Agent (latest)
- Node.js 22+ (for Sanctuary MCP server)
- `@sanctuary-framework/mcp-server` >= 0.5.16
- Optional: `concordia-protocol` >= 0.1.0 (for negotiation)

## Examples

See the `examples/` directory for complete working code:

- `examples/sovereign_agent.py` - Single Hermes agent with Sanctuary identity, state encryption, and context gating
- `examples/multi_agent_sovereignty.py` - Multiple Hermes subagents with separate sovereign identities, trust handshakes, and reputation tracking
- `examples/mantle_mode.py` - Mantle mode: Sanctuary as MCP proxy wrapping upstream servers with injection hardening and runtime governance

## License

Apache-2.0

## Acknowledgments

Hermes Agent is developed by Nous Research. Sanctuary Framework is by Erik Newton. This integration brings Sanctuary's dual-sovereignty architecture to Hermes's flexible agent execution model.
