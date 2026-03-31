"""
Multi-Agent Sovereignty Example — Hermes Subagents with Separate Identities

Demonstrates a Hermes coordinator managing three isolated subagents, where:
  - Each subagent has its own Ed25519 keypair and Sanctuary identity
  - Each runs in its own process with encrypted state isolation (L1)
  - Subagents perform specialized work (research, review, attestation)
  - The coordinator establishes trust via sovereignty handshakes (L4)
  - Reputation is tracked and verifiable across the network (L4)
  - All operations are auditable (L2 audit log)

This pattern enables:
  - Hierarchical agent compositions with clear boundaries
  - Portable reputation for inter-agent trust
  - Signed attestations that persist across sessions
  - Credential-less negotiation (identity + reputation only)

Requirements:
    pip install hermes-agent concordia-protocol
    Node.js 22+ (for Sanctuary MCP server)

Usage:
    export HERMES_MEMORY_KEY=$(openssl rand -base64 32)
    python multi_agent_sovereignty.py
"""

import os
import json
import asyncio
from pathlib import Path
from typing import Optional

try:
    from hermes import HermesAgent
    from hermes.config import AgentConfig
except ImportError:
    print("Hermes Agent not found. Install with: pip install hermes-agent")
    exit(1)


def make_subagent_config(agent_name: str, role: str, backstory: str) -> dict:
    """Create a Hermes subagent config with separate Sanctuary identity."""
    storage_path = Path.home() / ".sanctuary" / f"hermes-{agent_name}"

    return {
        "agent": {
            "name": agent_name,
            "role": role,
            "backstory": backstory,
            "model": "openai:gpt-4",

            "memory": {
                "type": "encrypted",
                "encryption_key": os.getenv("HERMES_MEMORY_KEY", ""),
                "persistence": "disk",
            },

            "mcps": {
                "sanctuary": {
                    "command": "npx",
                    "args": ["@sanctuary-framework/mcp-server"],
                    "transport": "stdio",
                    "env": {
                        "SANCTUARY_STORAGE_PATH": str(storage_path),
                    },
                }
            },

            "capabilities": {
                "tools": ["sanctuary/*"],
            },
        }
    }


def make_coordinator_config() -> dict:
    """Create the coordinator agent config."""
    return {
        "agent": {
            "name": "Sovereign Coordinator",
            "role": "Orchestrate research team with full sovereignty",
            "backstory": (
                "You are the coordinator of a sovereign research team. "
                "You manage three specialized subagents, each with their own "
                "cryptographic identity and encrypted state. Your role is to "
                "route work, establish trust via handshakes, track reputation, "
                "and produce final reports signed by your identity."
            ),
            "model": "openai:gpt-4",

            "memory": {
                "type": "encrypted",
                "encryption_key": os.getenv("HERMES_MEMORY_KEY", ""),
                "persistence": "disk",
            },

            "mcps": {
                "sanctuary": {
                    "command": "npx",
                    "args": ["@sanctuary-framework/mcp-server"],
                    "transport": "stdio",
                    "env": {
                        "SANCTUARY_STORAGE_PATH": str(
                            Path.home() / ".sanctuary" / "hermes-coordinator"
                        ),
                    },
                }
            },

            "capabilities": {
                "tools": ["sanctuary/*"],
            },
        }
    }


async def run_subagent(
    config: dict, task_description: str
) -> Optional[str]:
    """Run a subagent on a specific task and return result."""
    try:
        agent = HermesAgent.from_config(config)
        result = await agent.run_task(
            {
                "name": "subagent_work",
                "description": task_description,
                "prompt": task_description,
            }
        )
        return result
    except Exception as e:
        print(f"Error running subagent: {e}")
        return None


async def main():
    """Run the multi-agent sovereignty demonstration."""

    print("=" * 80)
    print("MULTI-AGENT SOVEREIGNTY — Hermes Coordinator + Three Subagents")
    print("=" * 80)
    print()
    print("This demonstration shows:")
    print("  • One coordinator agent managing three isolated subagents")
    print("  • Each agent has its own sovereign identity (Ed25519 keypair)")
    print("  • Each agent has encrypted state isolation (separate storage)")
    print("  • Trust established via Sanctuary handshakes (L4)")
    print("  • Reputation tracking and verification (L4)")
    print("  • Portable, signed attestations across agents")
    print()

    # Create configs for all agents
    coordinator_config = make_coordinator_config()

    researcher_config = make_subagent_config(
        "researcher",
        "Research Analyst",
        (
            "You are a meticulous researcher specializing in finding relevant "
            "sources and synthesizing findings. You maintain full sovereignty "
            "over your research notes and intermediate analysis."
        ),
    )

    reviewer_config = make_subagent_config(
        "reviewer",
        "Quality Reviewer",
        (
            "You are a critical reviewer who evaluates research for accuracy, "
            "completeness, and insight. You record signed reputation attestations "
            "for researchers based on their work quality."
        ),
    )

    synthesizer_config = make_subagent_config(
        "synthesizer",
        "Insight Synthesizer",
        (
            "You are an analyst who combines findings from multiple researchers "
            "into cohesive narratives. You identify patterns, gaps, and strategic "
            "implications."
        ),
    )

    print("=" * 80)
    print("PHASE 1: IDENTITY SETUP")
    print("=" * 80)
    print()

    # Initialize coordinator
    print("Initializing coordinator...")
    coordinator = HermesAgent.from_config(coordinator_config)

    coordinator_setup = """Create your coordinator identity:
1. Call sanctuary/identity_create to generate your Ed25519 keypair
2. Store your identity details in sanctuary/state_write with key 'coordinator_identity'
3. Generate a Sovereignty Health Report using sanctuary/shr_generate
4. Report your public key and SHR summary"""

    coordinator_result = await coordinator.run_task(
        {
            "name": "identity_setup",
            "description": "Set up coordinator identity",
            "prompt": coordinator_setup,
        }
    )
    print(coordinator_result)
    print()

    # Initialize subagents
    print("Initializing researcher subagent...")
    researcher = HermesAgent.from_config(researcher_config)
    researcher_result = await researcher.run_task(
        {
            "name": "identity_setup",
            "description": "Set up researcher identity",
            "prompt": """Create your researcher identity:
1. Call sanctuary/identity_create to generate your Ed25519 keypair
2. Store your identity in sanctuary/state_write with key 'identity'
3. Generate your initial SHR using sanctuary/shr_generate
4. Report your public key""",
        }
    )
    print(researcher_result)
    print()

    print("Initializing reviewer subagent...")
    reviewer = HermesAgent.from_config(reviewer_config)
    reviewer_result = await reviewer.run_task(
        {
            "name": "identity_setup",
            "description": "Set up reviewer identity",
            "prompt": """Create your reviewer identity:
1. Call sanctuary/identity_create to generate your Ed25519 keypair
2. Store your identity in sanctuary/state_write with key 'identity'
3. Generate your initial SHR using sanctuary/shr_generate
4. Report your public key""",
        }
    )
    print(reviewer_result)
    print()

    print("Initializing synthesizer subagent...")
    synthesizer = HermesAgent.from_config(synthesizer_config)
    synthesizer_result = await synthesizer.run_task(
        {
            "name": "identity_setup",
            "description": "Set up synthesizer identity",
            "prompt": """Create your synthesizer identity:
1. Call sanctuary/identity_create to generate your Ed25519 keypair
2. Store your identity in sanctuary/state_write with key 'identity'
3. Generate your initial SHR using sanctuary/shr_generate
4. Report your public key""",
        }
    )
    print(synthesizer_result)
    print()

    print("=" * 80)
    print("PHASE 2: TRUST ESTABLISHMENT (Sovereignty Handshakes)")
    print("=" * 80)
    print()

    # Coordinator initiates handshakes with each subagent
    print("Coordinator initiating sovereignty handshakes with subagents...")
    print()

    coordinator_handshake = """Establish trust with your three subagents:
1. For each subagent (researcher, reviewer, synthesizer):
   - Call sanctuary/handshake_initiate to send a trust proposal
   - Include the subagent's public key (from their identity setup)
   - Store each handshake initiation in state_write with key 'handshake_{agent_name}'
2. Report the handshake initiation details for each subagent"""

    coordinator_hs_result = await coordinator.run_task(
        {
            "name": "establish_trust",
            "description": "Initiate handshakes",
            "prompt": coordinator_handshake,
        }
    )
    print(coordinator_hs_result)
    print()

    # Subagents respond to handshakes
    print("Subagents responding to coordinator handshakes...")
    print()

    researcher_respond = """The coordinator has initiated a handshake.
1. Call sanctuary/handshake_respond to accept the coordinator's trust proposal
2. Send your current SHR as evidence of your sovereignty posture
3. Store the handshake response in state_write with key 'handshake_coordinator'
4. Report acceptance and your SHR"""

    researcher_hs = await researcher.run_task(
        {
            "name": "respond_handshake",
            "description": "Respond to coordinator handshake",
            "prompt": researcher_respond,
        }
    )
    print("Researcher response:", researcher_hs)
    print()

    # Repeat for reviewer and synthesizer
    for agent_name, agent in [("Reviewer", reviewer), ("Synthesizer", synthesizer)]:
        hs_response = await agent.run_task(
            {
                "name": "respond_handshake",
                "description": f"{agent_name} responds to handshake",
                "prompt": f"""{agent_name} responding to coordinator handshake:
1. Call sanctuary/handshake_respond to accept
2. Include your SHR as sovereignty evidence
3. Store in state_write with key 'handshake_coordinator'
4. Report acceptance""",
            }
        )
        print(f"{agent_name} response:", hs_response)
        print()

    print("=" * 80)
    print("PHASE 3: WORK ASSIGNMENT & EXECUTION")
    print("=" * 80)
    print()

    # Researcher conducts research
    print("Assigning research task to researcher subagent...")
    researcher_work = """Conduct research on agent sovereignty trends:
1. Identify three key developments in the agent sovereignty space
2. Store each finding in state_write with keys: 'finding_1', 'finding_2', 'finding_3'
3. For each finding, document:
   - The development (2-3 sentences)
   - Why it matters for agent sovereignty
   - Timestamp of your analysis
4. Run sanctuary/sovereignty_audit to verify you maintained security while researching
5. Report all three findings and your audit score"""

    researcher_work_result = await researcher.run_task(
        {
            "name": "conduct_research",
            "description": "Research agent sovereignty",
            "prompt": researcher_work,
        }
    )
    print(researcher_work_result)
    print()

    # Reviewer reviews the research
    print("Assigning review task to reviewer subagent...")
    reviewer_work = """Review the researcher's three findings:
1. Evaluate each finding for:
   - Accuracy and relevance
   - Completeness (does it fully support the claim?)
   - Insight (does it add new understanding?)
2. Assign a quality score (1-10) for each finding
3. Record a reputation attestation for the researcher using sanctuary/reputation_record:
   - Include your overall assessment
   - Note specific findings that were excellent or weak
   - Rate the researcher's work quality (positive or negative)
4. Store your review in state_write with key 'review_findings'
5. Report your scores and attestation"""

    reviewer_work_result = await reviewer.run_task(
        {
            "name": "review_research",
            "description": "Review researcher findings",
            "prompt": reviewer_work,
        }
    )
    print(reviewer_work_result)
    print()

    # Synthesizer synthesizes insights
    print("Assigning synthesis task to synthesizer subagent...")
    synthesizer_work = """Synthesize the researcher's findings into strategic insights:
1. Review the three research findings
2. Identify patterns, themes, and strategic implications
3. Create a synthetic narrative that combines the findings
4. Store your synthesis in state_write with key 'synthesis_strategic_insights'
5. Use sanctuary/zk_commit to create a zero-knowledge commitment to your insights
   (proves you have insight without revealing it yet)
6. Report your synthesis and the commitment hash"""

    synthesizer_work_result = await synthesizer.run_task(
        {
            "name": "synthesize_insights",
            "description": "Synthesize insights",
            "prompt": synthesizer_work,
        }
    )
    print(synthesizer_work_result)
    print()

    print("=" * 80)
    print("PHASE 4: REPUTATION AGGREGATION & FINAL REPORT")
    print("=" * 80)
    print()

    # Coordinator aggregates results and records final reputation
    coordinator_final = """Aggregate the work from your three subagents:
1. Query reputation records for all three using sanctuary/reputation_query
2. Calculate weighted reputation scores using sanctuary/reputation_query_weighted
3. Record a final positive reputation attestation for each subagent reflecting
   the quality of their work
4. Export portable reputation for each using sanctuary/reputation_export
5. Create a final team SHR using sanctuary/shr_generate
6. Run sanctuary/sovereignty_audit for your final posture
7. Store the team report in state_write with key 'final_team_report'
8. Report:
   - Each subagent's reputation score
   - Team SHR
   - Your final audit score
   - Exportable reputation artifacts for each agent"""

    coordinator_final_result = await coordinator.run_task(
        {
            "name": "final_aggregation",
            "description": "Aggregate results and final report",
            "prompt": coordinator_final,
        }
    )
    print(coordinator_final_result)
    print()

    print("=" * 80)
    print("DEMONSTRATION COMPLETE")
    print("=" * 80)
    print()
    print("All agents maintained full sovereignty throughout:")
    print("  • Each agent held its own cryptographic identity")
    print("  • Each agent's state was encrypted and isolated")
    print("  • Trust was established via signed handshakes (L4)")
    print("  • Reputation was tracked in portable, verifiable form (L4)")
    print("  • All operations are auditable in each agent's log (L2)")
    print()
    print("Storage paths:")
    print(f"  Coordinator: {Path.home() / '.sanctuary' / 'hermes-coordinator'}")
    print(f"  Researcher:  {Path.home() / '.sanctuary' / 'hermes-researcher'}")
    print(f"  Reviewer:    {Path.home() / '.sanctuary' / 'hermes-reviewer'}")
    print(f"  Synthesizer: {Path.home() / '.sanctuary' / 'hermes-synthesizer'}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
