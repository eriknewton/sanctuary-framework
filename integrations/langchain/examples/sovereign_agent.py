"""
Sanctuary + LangChain: Sovereign Agent Example

Demonstrates a LangChain agent with full sovereignty infrastructure:
- Encrypted state storage (AES-256-GCM)
- Cryptographic identity (Ed25519)
- Selective disclosure (commitment schemes)
- Verifiable reputation (EAS-compatible attestations)

Prerequisites:
    pip install langchain-mcp-adapters langchain-openai langgraph
    npm install -g @sanctuary-framework/mcp-server

Usage:
    export OPENAI_API_KEY=sk-...
    python sovereign_agent.py

Author: Erik Newton
License: Apache-2.0
"""

import asyncio
import os

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI


async def main():
    """Create a sovereign LangChain agent backed by Sanctuary."""

    # Connect to Sanctuary MCP server via stdio transport.
    # The server manages all cryptographic operations locally —
    # no data leaves the machine unless explicitly exported.
    async with MultiServerMCPClient(
        {
            "sanctuary": {
                "command": "npx",
                "args": ["@sanctuary-framework/mcp-server"],
                "transport": "stdio",
            }
        }
    ) as client:
        # All 46 Sanctuary tools become LangChain tools
        tools = client.get_tools()
        print(f"Loaded {len(tools)} Sanctuary tools")

        # Create a ReAct agent with sovereignty infrastructure
        model = ChatOpenAI(model="gpt-4o")
        agent = create_react_agent(model, tools)

        # ── Step 1: Create a sovereign identity ──────────────────────
        print("\n── Creating sovereign identity ──")
        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Create a new identity with the label 'langchain-agent'. "
                            "Then store a key-value pair in encrypted state: "
                            "namespace 'config', key 'agent_type', value 'langchain-react'. "
                            "Finally, generate a Sovereignty Health Report."
                        ),
                    }
                ]
            }
        )

        # Print the agent's response
        for msg in result["messages"]:
            if hasattr(msg, "content") and msg.content:
                print(msg.content)

        # ── Step 2: Demonstrate selective disclosure ─────────────────
        print("\n── Demonstrating selective disclosure ──")
        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Create a zero-knowledge commitment to the value 42 "
                            "with the label 'negotiation_score'. Then prove that "
                            "this value is in the range 0-100 without revealing it."
                        ),
                    }
                ]
            }
        )

        for msg in result["messages"]:
            if hasattr(msg, "content") and msg.content:
                print(msg.content)

        # ── Step 3: Record reputation ────────────────────────────────
        print("\n── Recording reputation attestation ──")
        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Record a reputation attestation for the current identity "
                            "with context 'langchain-demo', score 0.95, and category "
                            "'reliability'. Then query the weighted reputation."
                        ),
                    }
                ]
            }
        )

        for msg in result["messages"]:
            if hasattr(msg, "content") and msg.content:
                print(msg.content)


if __name__ == "__main__":
    asyncio.run(main())
