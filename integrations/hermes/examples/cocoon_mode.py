"""
Cocoon Mode Example — Sanctuary as MCP Proxy for Hermes Agents

Demonstrates Sanctuary's Cocoon mode where Sanctuary is the sole MCP
connection and proxies all upstream MCP servers through an enforcement chain:

  Hermes Agent
    → Sanctuary MCP (sole connection)
      → Injection scan (unicode, homoglyphs, encoded content, token budget)
      → Approval gate (Tier 1/2/3 policy)
      → Context gate (redact before forwarding)
      → Call Governor (rate limits, volume caps, duplicate detection)
      → Forward to upstream MCP server
      → Outbound scan (secrets, exfil, path leaks)
      → Audit log
    ← Sanitized response back to Hermes

This pattern provides:
  - Runtime governance over ALL MCP tool calls (not just Sanctuary's)
  - Injection hardening on upstream MCP responses
  - Secret exfiltration prevention on outbound content
  - Rate limiting and volume caps via Call Governor
  - Full audit trail of every proxied operation
  - No changes needed to upstream MCP server configurations

Requirements:
    pip install hermes-agent
    Node.js 22+ (for Sanctuary MCP server)
    @sanctuary-framework/mcp-server >= 0.5.16

Usage:
    export HERMES_MEMORY_KEY=$(openssl rand -base64 32)
    python cocoon_mode.py
"""

import os
import asyncio
from pathlib import Path

try:
    from hermes import HermesAgent
    from hermes.config import AgentConfig
except ImportError:
    print("Hermes Agent not found. Install with: pip install hermes-agent")
    print("Or clone from: https://github.com/NousResearch/hermes-agent")
    exit(1)


def generate_cocoon_config() -> dict:
    """
    Generate a Hermes config where Sanctuary is the ONLY MCP connection.

    Key difference from standard config: no upstream MCP servers are configured
    in Hermes's mcps block. Instead, upstream servers are registered with
    Sanctuary's proxy at runtime, and their tools appear under the proxy/*
    namespace.
    """
    return {
        "agent": {
            "name": "Cocoon-Protected Research Agent",
            "description": (
                "A Hermes agent running in Cocoon mode — all MCP traffic "
                "is proxied through Sanctuary's enforcement chain for "
                "injection hardening, rate limiting, and audit logging."
            ),
            "model": "openai:gpt-4",

            "memory": {
                "type": "encrypted",
                "encryption_key": os.getenv("HERMES_MEMORY_KEY", ""),
                "persistence": "disk",
            },

            # Sanctuary is the ONLY MCP connection
            "mcps": {
                "sanctuary": {
                    "command": "npx",
                    "args": ["@sanctuary-framework/mcp-server"],
                    "transport": "stdio",
                    "env": {
                        "SANCTUARY_STORAGE_PATH": str(
                            Path.home() / ".sanctuary" / "hermes-cocoon"
                        ),
                    },
                }
                # No other MCP servers here — Sanctuary proxies them
            },

            "capabilities": {
                "tools": [
                    "sanctuary/*",  # Sanctuary's 67+ native tools
                    "proxy/*",      # Proxied upstream tools
                ],
            },

            "startup": [
                {
                    "name": "cocoon_setup",
                    "description": "Initialize Cocoon mode with upstream servers",
                    "prompt": """Set up Cocoon mode — Sanctuary as MCP proxy:

1. Create your sovereign identity:
   - Call sanctuary/identity_create for your Ed25519 keypair

2. Apply context gating for inference privacy:
   - Call sanctuary/context_gate_apply_template with 'inference-standard'

3. Register upstream MCP servers with the proxy:

   a) Register a web search server:
      Call sanctuary/proxy_register_upstream with:
      - name: "web-search"
      - command: "npx"
      - args: ["-y", "@anthropic/web-search-mcp"]
      - tier: "tier3"  (auto-allow with audit logging)

   b) Register a filesystem server:
      Call sanctuary/proxy_register_upstream with:
      - name: "filesystem"
      - command: "npx"
      - args: ["-y", "@anthropic/filesystem-mcp", "/tmp/hermes-workspace"]
      - tier: "tier2"  (anomaly-triggered approval for sensitive operations)

4. Discover all available proxied tools:
   - Call sanctuary/proxy_discover_tools
   - This will list tools like proxy/web-search/search,
     proxy/filesystem/read_file, etc.

5. Verify governance is active:
   - Call sanctuary/governor_status
   - Confirm rate limits and volume caps are enforced

6. Run sanctuary/sovereignty_audit for initial posture

Report: identity created, context gating active, upstream servers registered,
proxied tools discovered, governor state, and audit score.""",
                }
            ],
        }
    }


async def main():
    """Run the Cocoon mode demonstration."""

    print("=" * 80)
    print("COCOON MODE — Sanctuary as MCP Proxy for Hermes Agent")
    print("=" * 80)
    print()
    print("In Cocoon mode, Sanctuary is the agent's sole MCP connection.")
    print("All upstream MCP servers are proxied through Sanctuary's")
    print("enforcement chain:")
    print()
    print("  Hermes → Sanctuary → [injection scan → gate → context gate")
    print("    → governor → forward → outbound scan → audit] → upstream")
    print()
    print("This provides runtime governance over ALL tool calls, not just")
    print("Sanctuary's own tools.")
    print()

    config_dict = generate_cocoon_config()

    try:
        agent = HermesAgent.from_config(config_dict)
    except Exception as e:
        print(f"Error initializing agent: {e}")
        print()
        print("Set HERMES_MEMORY_KEY if not already set:")
        print("  export HERMES_MEMORY_KEY=$(openssl rand -base64 32)")
        return

    # ── PHASE 1: COCOON SETUP ────────────────────────────────────────────

    print("=" * 80)
    print("PHASE 1: COCOON SETUP")
    print("=" * 80)
    print()
    print("Creating identity, registering upstream servers, discovering tools...")
    print()

    startup_result = await agent.startup()
    print(startup_result)
    print()

    # ── PHASE 2: PROXIED TOOL USAGE ──────────────────────────────────────

    print("=" * 80)
    print("PHASE 2: PROXIED TOOL USAGE")
    print("=" * 80)
    print()

    proxied_task = {
        "name": "use_proxied_tools",
        "description": "Use upstream MCP tools through Sanctuary's proxy",
        "prompt": """Use the proxied upstream tools through Sanctuary's enforcement chain.

Every call you make passes through: injection scan → approval gate →
context gate → Call Governor → forward → outbound scan → audit log.

1. Use proxy/filesystem/write_file to create a file at
   /tmp/hermes-workspace/research_notes.txt with some research findings
   about agent sovereignty.

2. Use proxy/filesystem/read_file to read the file back and verify
   the content is intact.

3. After each proxied call, check sanctuary/governor_status to see:
   - How many calls have been made
   - Rate per tool
   - Any duplicate cache hits

4. Check sanctuary/monitor_audit_log to see the audit trail for your
   proxied operations — each call is logged with the enforcement chain
   results (injection scan pass/fail, gate decision, governor stats).

Report the file content, governor stats, and audit log entries.""",
    }

    print("Using proxied tools through Sanctuary enforcement chain...")
    print()
    proxied_result = await agent.run_task(proxied_task)
    print(proxied_result)
    print()

    # ── PHASE 3: INJECTION HARDENING DEMONSTRATION ───────────────────────

    print("=" * 80)
    print("PHASE 3: INJECTION HARDENING")
    print("=" * 80)
    print()

    injection_task = {
        "name": "injection_hardening_demo",
        "description": "Demonstrate injection hardening on proxied responses",
        "prompt": """Demonstrate Sanctuary's injection hardening on proxied responses.

When Sanctuary proxies an upstream MCP response, it applies:
- Unicode invisible character stripping (zero-width spaces, joiners, etc.)
- Homoglyph normalization (Cyrillic, Armenian, Cherokee confusables)
- Encoded content decoding (base64, hex, HTML entities)
- Token budget attack detection
- Outbound secret scanning (20+ patterns: API keys, tokens, etc.)
- Markdown exfiltration detection
- Internal path/IP leak detection

1. Write a test file using proxy/filesystem/write_file that contains
   some text mixed with notes about these security protections.

2. Read it back via proxy/filesystem/read_file — the response passes
   through the injection scanner before reaching you.

3. Store a summary of the injection hardening capabilities in
   sanctuary/state_write with key 'injection_hardening_summary'.

4. Check sanctuary/governor_status — report the total proxied calls,
   rate stats, and whether any calls were deduplicated.

5. Check sanctuary/monitor_audit_log for injection scan results.

Report: what injection protections are active, governor stats,
and audit log showing the enforcement chain in action.""",
    }

    print("Demonstrating injection hardening on proxied responses...")
    print()
    injection_result = await agent.run_task(injection_task)
    print(injection_result)
    print()

    # ── PHASE 4: GOVERNANCE REPORT ───────────────────────────────────────

    print("=" * 80)
    print("PHASE 4: GOVERNANCE REPORT")
    print("=" * 80)
    print()

    governance_task = {
        "name": "governance_report",
        "description": "Generate final governance report",
        "prompt": """Generate a final governance report for this Cocoon mode session.

1. Call sanctuary/governor_status for comprehensive stats:
   - Total calls made (both Sanctuary native and proxied)
   - Rate per tool
   - Duplicate cache hits
   - Distance from volume limits (200/10min)
   - Distance from lifetime limit (1000 calls)

2. Call sanctuary/monitor_audit_log for the full audit trail.

3. Call sanctuary/sovereignty_audit for final posture assessment.

4. Generate a final SHR using sanctuary/shr_generate.

5. Publish to Verascore using sanctuary/reputation_publish:
   - target_url: "https://verascore.ai/api/publish"

6. Store the governance report in sanctuary/state_write
   with key 'cocoon_governance_report'.

Report:
  - Total proxied calls and their outcomes
  - Injection scan results (any blocked content?)
  - Governor stats (rates, volumes, duplicates)
  - Final sovereignty posture score
  - Verascore publish confirmation""",
    }

    print("Generating final governance report...")
    print()
    governance_result = await agent.run_task(governance_task)
    print(governance_result)
    print()

    # ── SUMMARY ──────────────────────────────────────────────────────────

    print("=" * 80)
    print("COCOON MODE DEMONSTRATION COMPLETE")
    print("=" * 80)
    print()
    print("Cocoon mode provided:")
    print("  - Single MCP connection (Sanctuary) proxying all upstream servers")
    print("  - Injection hardening on every proxied response")
    print("  - Outbound secret scanning on every proxied request")
    print("  - Call Governor rate limiting and volume caps")
    print("  - Full audit trail of every tool call (native + proxied)")
    print("  - Context gating to control what reaches upstream servers")
    print("  - Sovereignty posture monitoring throughout")
    print()
    print("No upstream MCP server configurations needed to change.")
    print("Sanctuary sat transparently between the agent and its tools.")
    print()
    print(f"Storage: {Path.home() / '.sanctuary' / 'hermes-cocoon'}")
    print("Reputation: https://verascore.ai")
    print()


if __name__ == "__main__":
    asyncio.run(main())
