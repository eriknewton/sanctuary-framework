"""
Sovereign Hermes Agent Example — Encrypted Research with Full Sovereignty

Demonstrates a single Hermes agent with:
  - Sanctuary identity (Ed25519 keypair + DID)
  - Encrypted state storage (L1 cognitive sovereignty)
  - Context gating to redact inference calls (L3 selective disclosure)
  - Sovereignty audit for continuous posture monitoring (L2/L4)
  - Memory encryption (Hermes native) layered with Sanctuary

The agent conducts research on agent sovereignty, storing findings as encrypted
state entries, and generates a Sovereignty Health Report to prove its posture.

Requirements:
    pip install hermes-agent
    Node.js 22+ (for Sanctuary MCP server)

Usage:
    export HERMES_MEMORY_KEY=$(openssl rand -base64 32)
    hermes run sovereign_agent_config.yaml

Or run this script directly (requires hermes package to be importable):
    python sovereign_agent.py
"""

import os
import json
import asyncio
from pathlib import Path

# If running Hermes from source or installed package
try:
    from hermes import HermesAgent
    from hermes.config import AgentConfig
except ImportError:
    print("Hermes Agent not found. Install with: pip install hermes-agent")
    print("Or clone from: https://github.com/nous-research/hermes-agent")
    exit(1)


def generate_hermes_config() -> dict:
    """Generate a Hermes config with Sanctuary integration."""
    return {
        "agent": {
            "name": "Sovereign Research Agent",
            "description": "An agent with full sovereignty via Sanctuary MCP integration",
            "model": "openai:gpt-4",  # Use your preferred model

            "memory": {
                "type": "encrypted",
                "encryption_key": os.getenv("HERMES_MEMORY_KEY", ""),
                "persistence": "disk",
                "levels": {
                    "short_term": {
                        "size": 8192,
                        "ttl": 3600,
                        "encryption": True,
                    },
                    "long_term": {
                        "size": 102400,
                        "ttl": 604800,
                        "encryption": True,
                        "backend": "disk",
                    },
                },
            },

            "mcps": {
                "sanctuary": {
                    "command": "npx",
                    "args": ["@sanctuary-framework/mcp-server"],
                    "transport": "stdio",
                    "env": {
                        "SANCTUARY_STORAGE_PATH": str(Path.home() / ".sanctuary" / "hermes-research"),
                    },
                }
            },

            "capabilities": {
                "tools": ["sanctuary/*"],
            },

            "startup": [
                {
                    "name": "setup_sovereignty",
                    "description": "Initialize sovereign identity and context gating",
                    "prompt": """Initialize your sovereign identity:
1. Call sanctuary/identity_create to generate your Ed25519 keypair
2. Apply the 'inference-standard' context gating template
3. Run sanctuary/sovereignty_audit to assess your initial posture
4. Generate a Sovereignty Health Report using sanctuary/shr_generate

Report your identity public key, context gating status, and SHR summary.""",
                }
            ],
        }
    }


async def main():
    """Run the sovereign agent."""

    print("=" * 70)
    print("SOVEREIGN HERMES AGENT — Research with Full Sovereignty")
    print("=" * 70)
    print()
    print("This agent demonstrates:")
    print("  • Sovereign identity via Sanctuary (L1)")
    print("  • Encrypted state storage (L1)")
    print("  • Context gating for inference privacy (L3)")
    print("  • Continuous sovereignty auditing (L2/L4)")
    print("  • Memory encryption (Hermes native)")
    print()
    print("Startup phase: Creating identity and context gating...")
    print()

    # Generate config
    config_dict = generate_hermes_config()

    # Initialize agent with Sanctuary MCP support
    try:
        agent = HermesAgent.from_config(config_dict)
    except Exception as e:
        print(f"Error initializing agent: {e}")
        print()
        print("If you haven't set HERMES_MEMORY_KEY, set it now:")
        print("  export HERMES_MEMORY_KEY=$(openssl rand -base64 32)")
        return

    # Run startup tasks (identity creation, context gating)
    print("Running startup tasks...")
    startup_result = await agent.startup()
    print(f"Startup result: {startup_result}")
    print()

    # Main research task
    research_task = {
        "name": "conduct_research",
        "description": "Research agent sovereignty and store findings securely",
        "prompt": """Conduct research on agent sovereignty in the AI ecosystem.
Store your findings as encrypted state entries using sanctuary/state_write:

1. Key 'finding_architecture':
   The difference between local-first execution and architecturally sovereign design.
   Local ≠ Sovereign. Explain why custody of compute location doesn't grant
   cryptographic control over identity or verifiable reputation.

2. Key 'finding_threats':
   Current threats to agent state and identity (API key exposure, plaintext logs,
   context leakage in inference calls, vendor mediation of negotiation).

3. Key 'finding_regulatory':
   EU AI Act enforcement (August 2, 2026) creates compliance requirements for
   agent transparency and accountability. How does Sovereignty Health Reporting
   satisfy these requirements?

After writing each finding:
- Read it back using sanctuary/state_read to verify encryption round-trip
- Note the result in your memory

Then call sanctuary/sovereignty_audit again to assess how your research process
has affected your sovereignty posture (should remain stable).

Report all three findings and your final audit score.""",
    }

    print("Running research task...")
    print("=" * 70)
    research_result = await agent.run_task(research_task)
    print(research_result)
    print("=" * 70)
    print()

    # Generate final Sovereignty Health Report
    shr_task = {
        "name": "final_shr",
        "description": "Generate final Sovereignty Health Report",
        "prompt": """Generate a final Sovereignty Health Report using sanctuary/shr_generate.

The SHR is a signed JSON document certifying your sovereignty posture across
all four layers:
  - L1: Cognitive Sovereignty (encrypted state, identity)
  - L2: Operational Isolation (process attestation, resource limits)
  - L3: Selective Disclosure (what you reveal vs. withhold to peers)
  - L4: Verifiable Reputation (signed attestations from other agents)

Report the SHR content and your overall sovereignty health score.

Then check your audit log using sanctuary/monitor_audit_log to see a record
of all sovereignty operations you've performed during this session.""",
    }

    print("Generating final Sovereignty Health Report...")
    print("=" * 70)
    shr_result = await agent.run_task(shr_task)
    print(shr_result)
    print("=" * 70)
    print()

    # List all encrypted state entries
    state_task = {
        "name": "list_state",
        "description": "List all encrypted state entries",
        "prompt": """List all encrypted state entries you've created using sanctuary/state_list.

For each entry, report:
- The key name
- Whether it's encrypted (it should be)
- The timestamp it was written
- A summary of the content (without exposing the plaintext value)

This demonstrates that all your research findings are encrypted at rest.""",
    }

    print("Listing encrypted state entries...")
    print("=" * 70)
    state_result = await agent.run_task(state_task)
    print(state_result)
    print("=" * 70)
    print()

    print("=" * 70)
    print("AGENT SHUTDOWN")
    print("=" * 70)
    print()
    print("Agent completed successfully. All state is encrypted at rest.")
    print(f"Storage path: {Path.home() / '.sanctuary' / 'hermes-research'}")
    print()
    print("To inspect encrypted state manually:")
    print(f"  ls -la {Path.home() / '.sanctuary' / 'hermes-research'}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
