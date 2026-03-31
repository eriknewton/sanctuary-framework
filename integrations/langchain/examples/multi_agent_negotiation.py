"""
Sanctuary + Concordia + LangChain: Multi-Agent Negotiation

Two sovereign agents, each with their own cryptographic identity and
encrypted state, negotiate a service agreement using Concordia Protocol.

This demonstrates the full sovereign transaction stack:
- Sanctuary provides identity, encryption, and reputation
- Concordia provides structured negotiation and binding commitments
- LangChain provides agent orchestration

Prerequisites:
    pip install langchain-mcp-adapters langchain-openai langgraph concordia-protocol
    npm install -g @sanctuary-framework/mcp-server

Usage:
    export OPENAI_API_KEY=sk-...
    python multi_agent_negotiation.py

Author: Erik Newton
License: Apache-2.0
"""

import asyncio
import os
import tempfile

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI


async def main():
    """Two sovereign agents negotiate a service agreement."""

    # Each agent gets its own Sanctuary instance (separate storage paths)
    # and they share a single Concordia server for negotiation.
    alice_storage = tempfile.mkdtemp(prefix="sanctuary-alice-")
    bob_storage = tempfile.mkdtemp(prefix="sanctuary-bob-")

    async with MultiServerMCPClient(
        {
            # Alice's sovereignty infrastructure
            "alice_sanctuary": {
                "command": "npx",
                "args": ["@sanctuary-framework/mcp-server"],
                "env": {
                    **os.environ,
                    "SANCTUARY_STORAGE_PATH": alice_storage,
                },
                "transport": "stdio",
            },
            # Bob's sovereignty infrastructure
            "bob_sanctuary": {
                "command": "npx",
                "args": ["@sanctuary-framework/mcp-server"],
                "env": {
                    **os.environ,
                    "SANCTUARY_STORAGE_PATH": bob_storage,
                },
                "transport": "stdio",
            },
            # Shared negotiation protocol
            "concordia": {
                "command": "python",
                "args": ["-m", "concordia"],
                "transport": "stdio",
            },
        }
    ) as client:
        tools = client.get_tools()
        print(f"Loaded {len(tools)} tools across 3 servers")

        model = ChatOpenAI(model="gpt-4o")

        # ── Phase 1: Both agents create sovereign identities ─────────
        print("\n── Phase 1: Identity Creation ──")
        agent = create_react_agent(model, tools)

        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "You are orchestrating two agents. "
                            "First, use alice_sanctuary to create an identity labeled 'alice'. "
                            "Then use bob_sanctuary to create an identity labeled 'bob'. "
                            "Report both identity IDs."
                        ),
                    }
                ]
            }
        )

        for msg in result["messages"]:
            if hasattr(msg, "content") and msg.content:
                print(msg.content)

        # ── Phase 2: Negotiate a service agreement ───────────────────
        print("\n── Phase 2: Negotiation ──")
        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Now use concordia to negotiate a service agreement: "
                            "Alice offers data processing services at $0.10/record "
                            "with 99.9% uptime SLA. Bob wants $0.08/record with "
                            "99.95% uptime. Negotiate to a compromise using "
                            "Concordia's propose/counter/accept flow. "
                            "Record the outcome as reputation attestations for "
                            "both agents using their respective Sanctuary instances."
                        ),
                    }
                ]
            }
        )

        for msg in result["messages"]:
            if hasattr(msg, "content") and msg.content:
                print(msg.content)

        print("\n── Negotiation complete ──")
        print(f"Alice storage: {alice_storage}")
        print(f"Bob storage: {bob_storage}")


if __name__ == "__main__":
    asyncio.run(main())
