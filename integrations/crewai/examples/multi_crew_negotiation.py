"""
Multi-Crew Negotiation — Two Sovereign CrewAI Agents Negotiate via Concordia

Demonstrates CrewAI agents with both Sanctuary (sovereignty) and Concordia
(negotiation) composing together. Each agent has its own cryptographic identity.
Negotiation follows Concordia's structured protocol with binding commitments
backed by Sanctuary's cryptographic infrastructure.

Requirements:
    pip install 'crewai[tools]' crewai-tools[mcp] concordia-protocol
    Node.js 22+ (for Sanctuary MCP server)

Usage:
    python multi_crew_negotiation.py
"""

from crewai import Agent, Task, Crew, Process


def make_sovereign_mcp_config(agent_name: str) -> list:
    """Create MCP server configs for a sovereign negotiating agent."""
    return [
        {
            "name": "sanctuary",
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "env": {"SANCTUARY_STORAGE_PATH": f"~/.sanctuary/{agent_name}"},
            "transport": "stdio",
        },
        {
            "name": "concordia",
            "command": "python",
            "args": ["-m", "concordia"],
            "transport": "stdio",
        },
    ]


# --- Agents ---

alice = Agent(
    role="Service Provider (Alice)",
    goal=(
        "Offer a data processing service at a fair price. "
        "Negotiate terms using Concordia's structured protocol. "
        "Maintain full sovereignty over your state and identity."
    ),
    backstory=(
        "You are Alice, a data processing service provider. You have "
        "sovereign identity via Sanctuary and negotiate deals using Concordia's "
        "structured protocol. Your initial offer: $0.02 per record with 99.5% "
        "SLA uptime. You can negotiate down to $0.015 per record but no lower. "
        "You can increase SLA to 99.9% for a price premium."
    ),
    mcps=make_sovereign_mcp_config("alice"),
    verbose=True,
)

bob = Agent(
    role="Service Consumer (Bob)",
    goal=(
        "Procure a data processing service at the best possible terms. "
        "Negotiate using Concordia's structured protocol. "
        "Verify the provider's sovereignty posture before committing."
    ),
    backstory=(
        "You are Bob, procuring data processing services. You have sovereign "
        "identity via Sanctuary and negotiate using Concordia. Your budget: "
        "$0.018 per record maximum. You require at least 99.7% SLA uptime. "
        "You prefer providers with verified sovereignty (check their SHR)."
    ),
    mcps=make_sovereign_mcp_config("bob"),
    verbose=True,
)

# --- Tasks ---

alice_setup = Task(
    description=(
        "1. Create a sovereign identity using sanctuary/identity_create.\n"
        "2. Apply the 'inference-standard' context gating template.\n"
        "3. Generate an SHR using sanctuary/shr_generate.\n"
        "4. Report your identity and SHR summary."
    ),
    expected_output="Alice's public key and SHR sovereignty score.",
    agent=alice,
)

bob_setup = Task(
    description=(
        "1. Create a sovereign identity using sanctuary/identity_create.\n"
        "2. Apply the 'inference-standard' context gating template.\n"
        "3. Generate an SHR using sanctuary/shr_generate.\n"
        "4. Report your identity and SHR summary."
    ),
    expected_output="Bob's public key and SHR sovereignty score.",
    agent=bob,
)

alice_propose = Task(
    description=(
        "Create a Concordia negotiation session and make your initial proposal:\n"
        "- Service: Data processing\n"
        "- Price: $0.02 per record\n"
        "- SLA: 99.5% uptime\n"
        "- Volume: 1M records/month\n"
        "- Term: 12 months\n\n"
        "Use concordia/session_create to start the session, then "
        "concordia/propose to submit your offer."
    ),
    expected_output="Session ID and proposal details.",
    agent=alice,
    context=[alice_setup],
)

bob_counter = Task(
    description=(
        "Review Alice's proposal. You need better terms:\n"
        "- Counter at $0.017 per record (under your $0.018 budget)\n"
        "- Request 99.9% SLA uptime (higher than offered)\n"
        "- Accept 1M records/month volume\n"
        "- Accept 12 month term\n\n"
        "Use concordia/counter to submit your counteroffer in Alice's session."
    ),
    expected_output="Counteroffer details and session status.",
    agent=bob,
    context=[bob_setup, alice_propose],
)

alice_accept = Task(
    description=(
        "Review Bob's counteroffer. $0.017/record is above your floor ($0.015) "
        "and 99.9% SLA is achievable with your infrastructure.\n\n"
        "Accept the counteroffer using concordia/accept.\n"
        "Then use sanctuary/bridge_commit to create a cryptographic commitment "
        "binding this agreement to your sovereign identity.\n"
        "Record a positive reputation attestation for Bob using "
        "sanctuary/reputation_record."
    ),
    expected_output=(
        "Acceptance confirmation, bridge commitment hash, "
        "and reputation attestation for Bob."
    ),
    agent=alice,
    context=[bob_counter],
)

bob_finalize = Task(
    description=(
        "Confirm the agreement is accepted. Then:\n"
        "1. Use sanctuary/bridge_commit to create your own cryptographic "
        "commitment to the agreed terms.\n"
        "2. Record a positive reputation attestation for Alice.\n"
        "3. Run a final sovereignty audit to confirm your posture."
    ),
    expected_output=(
        "Bob's bridge commitment hash, reputation attestation for Alice, "
        "and final sovereignty audit score."
    ),
    agent=bob,
    context=[alice_accept],
)

# --- Crew Assembly ---
# Sequential process: setup both agents, then negotiate in order.

negotiation_crew = Crew(
    agents=[alice, bob],
    tasks=[alice_setup, bob_setup, alice_propose, bob_counter, alice_accept, bob_finalize],
    process=Process.sequential,
    verbose=True,
)

# --- Execution ---

if __name__ == "__main__":
    print("=" * 60)
    print("MULTI-CREW NEGOTIATION")
    print("Sanctuary (sovereignty) + Concordia (negotiation)")
    print("=" * 60)
    print()
    print("Alice offers data processing services.")
    print("Bob procures them.")
    print("Both hold sovereign identities. Negotiation is structured.")
    print("Commitments are cryptographically bound.")
    print()

    result = negotiation_crew.kickoff()

    print()
    print("=" * 60)
    print("NEGOTIATION RESULT")
    print("=" * 60)
    print(result)
