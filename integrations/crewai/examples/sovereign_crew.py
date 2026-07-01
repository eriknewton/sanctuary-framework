"""
Sovereign CrewAI Example — Research Crew with Full Sovereignty

Demonstrates a two-agent CrewAI crew where each agent has its own
Sanctuary identity, encrypted state, and sovereignty audit capability.

Requirements:
    pip install 'crewai[tools]' crewai-tools[mcp]
    Node.js 22+ (for Sanctuary MCP server)

Usage:
    python sovereign_crew.py
"""

from crewai import Agent, Task, Crew, Process

# --- Agent Definitions ---

researcher = Agent(
    role="Sovereign Research Analyst",
    goal=(
        "Conduct research while maintaining full sovereignty over all state. "
        "Encrypt all findings. Hold your own cryptographic identity. "
        "Never expose raw data to external providers."
    ),
    backstory=(
        "You are a research analyst with strict data sovereignty requirements. "
        "All your intermediate findings, notes, and analysis must be encrypted "
        "at rest using Sanctuary's L1 cognitive sovereignty. You generate a "
        "Sovereignty Health Report after setup to prove your posture."
    ),
    mcps=[
        {
            "name": "sanctuary",
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "env": {"SANCTUARY_STORAGE_PATH": "~/.sanctuary/researcher"},
            "transport": "stdio",
        }
    ],
    verbose=True,
)

reviewer = Agent(
    role="Sovereign Quality Reviewer",
    goal=(
        "Review research findings for accuracy and completeness. "
        "Maintain your own independent sovereign identity. "
        "Record reputation attestations for the researcher based on quality."
    ),
    backstory=(
        "You are an independent quality reviewer. You hold your own "
        "cryptographic identity separate from the researcher. After reviewing "
        "findings, you record a signed reputation attestation — positive or "
        "negative — that becomes part of the researcher's portable reputation."
    ),
    mcps=[
        {
            "name": "sanctuary",
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "env": {"SANCTUARY_STORAGE_PATH": "~/.sanctuary/reviewer"},
            "transport": "stdio",
        }
    ],
    verbose=True,
)

# --- Task Definitions ---

setup_sovereignty = Task(
    description=(
        "1. Create a sovereign identity using sanctuary/identity_create.\n"
        "2. Apply the 'inference-standard' context gating template using "
        "sanctuary/context_gate_apply_template to protect outbound inference calls.\n"
        "3. Run a sovereignty audit using sanctuary/sovereignty_audit.\n"
        "4. Report your identity public key, context gating status, and audit score."
    ),
    expected_output=(
        "Your Ed25519 public key, confirmation that context gating is active "
        "with the inference-standard template, and your sovereignty audit score "
        "with any gap recommendations."
    ),
    agent=researcher,
)

conduct_research = Task(
    description=(
        "Research the current state of agent sovereignty in the AI ecosystem. "
        "Store your findings as encrypted state entries:\n"
        "- Key 'finding_1': The gap between local-first and architecturally sovereign\n"
        "- Key 'finding_2': Current threats to agent state (plaintext storage, API key exposure)\n"
        "- Key 'finding_3': Regulatory pressure from EU AI Act (August 2, 2026 enforcement)\n"
        "\n"
        "Use sanctuary/state_write for each finding. Then read them back with "
        "sanctuary/state_read to confirm encryption round-trip works."
    ),
    expected_output=(
        "Three encrypted research findings stored and verified. "
        "Report the keys and a summary of each finding."
    ),
    agent=researcher,
    context=[setup_sovereignty],
)

review_and_attest = Task(
    description=(
        "1. Create your own sovereign identity using sanctuary/identity_create.\n"
        "2. Review the researcher's three findings for accuracy and completeness.\n"
        "3. Record a reputation attestation for the researcher using "
        "sanctuary/reputation_record. Rate the quality of the research "
        "(positive or negative) with a brief justification.\n"
        "4. Generate your own SHR to prove your reviewer identity is sovereign."
    ),
    expected_output=(
        "Your reviewer identity public key, your assessment of each finding, "
        "the reputation attestation you recorded (with rating and justification), "
        "and your SHR summary."
    ),
    agent=reviewer,
    context=[conduct_research],
)

# --- Crew Assembly ---

sovereign_crew = Crew(
    agents=[researcher, reviewer],
    tasks=[setup_sovereignty, conduct_research, review_and_attest],
    process=Process.sequential,
    verbose=True,
)

# --- Execution ---

if __name__ == "__main__":
    print("=" * 60)
    print("SOVEREIGN CREW — Research with Full Sovereignty")
    print("=" * 60)
    print()
    print("This demo creates two agents with independent sovereign")
    print("identities, encrypted state, context gating, and portable")
    print("reputation — all via Sanctuary's MCP tools.")
    print()

    result = sovereign_crew.kickoff()

    print()
    print("=" * 60)
    print("CREW RESULT")
    print("=" * 60)
    print(result)
