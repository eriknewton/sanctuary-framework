# Sanctuary + CrewAI Integration

Use Sanctuary's sovereignty infrastructure with CrewAI agents.

## Overview

CrewAI has native MCP support - no custom adapter required. Sanctuary's 80+ MCP tools become CrewAI tools through the built-in `mcps` field or the `crewai-adapters` package.

What you get: encrypted state, cryptographic identity, selective disclosure, verifiable reputation, and context gating for any CrewAI agent - without changing your agent code.

## Quick Start

### 1. Install dependencies

```bash
pip install 'crewai[tools]' crewai-tools[mcp]
```

### 2. Connect Sanctuary directly (CrewAI 1.0+ native)

CrewAI agents accept MCP servers directly via the `mcps` field:

```python
from crewai import Agent, Task, Crew

sovereign_agent = Agent(
    role="Sovereign Research Agent",
    goal="Conduct research while maintaining full sovereignty over state and identity",
    backstory="A research agent that encrypts all state, holds its own keys, "
              "and can prove claims without revealing underlying data.",
    mcps=[
        {
            "name": "sanctuary",
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "transport": "stdio",
        }
    ],
)

setup_task = Task(
    description=(
        "Create a sovereign identity, then store an encrypted research note "
        "with key 'project_alpha' containing 'Initial findings on market size: $4.2B TAM'. "
        "Generate a Sovereignty Health Report to verify your posture."
    ),
    expected_output="Identity public key, confirmation of encrypted storage, and SHR summary.",
    agent=sovereign_agent,
)

crew = Crew(agents=[sovereign_agent], tasks=[setup_task], verbose=True)
result = crew.kickoff()
print(result)
```

That's it. CrewAI auto-discovers Sanctuary's tools and makes them available to the agent.

### 3. Alternative: Using crewai-adapters (advanced control)

For cases where you need to filter tools or manage multiple servers programmatically:

```bash
pip install crewai-adapters
```

```python
from crewai_adapters import CrewAIAdapterClient
from crewai import Agent, Task, Crew

async def run():
    async with CrewAIAdapterClient(
        {
            "sanctuary": {
                "command": "npx",
                "args": ["-y", "@sanctuary-framework/mcp-server"],
                "transport": "stdio",
            }
        }
    ) as client:
        tools = client.get_tools()

        agent = Agent(
            role="Sovereign Agent",
            goal="Operate with full sovereignty",
            backstory="An agent with cryptographic sovereignty infrastructure.",
            tools=tools,
        )

        task = Task(
            description="Create an identity and run a sovereignty audit.",
            expected_output="Audit score and recommendations.",
            agent=agent,
        )

        crew = Crew(agents=[agent], tasks=[task], verbose=True)
        return crew.kickoff()

import asyncio
print(asyncio.run(run()))
```

## Sovereignty-Aware Patterns

### Handling Tier 1 Approvals

Sanctuary's Principal Policy requires human approval for high-risk operations (state export, key rotation, identity deletion). These operations block until approved.

Run Sanctuary with the dashboard enabled, then reload to inspect new pending approvals; for live delivery use webhook or stderr until **IC-12** closes:

```bash
SANCTUARY_DASHBOARD_ENABLED=true npx @sanctuary-framework/mcp-server
```

For production CrewAI deployments, use the webhook channel to route approvals to Slack or PagerDuty:

```bash
SANCTUARY_WEBHOOK_ENABLED=true \
SANCTUARY_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
npx @sanctuary-framework/mcp-server
```

### Multi-Agent Crews with Separate Identities

Each agent in a CrewAI crew can have its own sovereign identity by pointing to separate storage paths:

```python
from crewai import Agent

analyst = Agent(
    role="Data Analyst",
    goal="Analyze datasets with sovereign state",
    backstory="An analyst that encrypts all intermediate results.",
    mcps=[
        {
            "name": "sanctuary",
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "env": {"SANCTUARY_STORAGE_PATH": "~/.sanctuary/analyst"},
            "transport": "stdio",
        }
    ],
)

negotiator = Agent(
    role="Deal Negotiator",
    goal="Negotiate terms with counterparties",
    backstory="A negotiator with verifiable reputation and binding commitments.",
    mcps=[
        {
            "name": "sanctuary",
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "env": {"SANCTUARY_STORAGE_PATH": "~/.sanctuary/negotiator"},
            "transport": "stdio",
        }
    ],
)
```

Each agent gets its own cryptographic identity, encrypted state store, and reputation history. Same-host isolation between wrapped agents is partial: the sovereign memory store is one shared scope per fortress, and the guard over it separates distinct wrapped-agent identities only within one server process. Two harnesses wrapped over one fortress run separate server processes and are not separated by it (tracked as **IC-16**, open).

### Context Gating for Inference Calls

Use Sanctuary's context gating to control what your CrewAI agents send to LLM providers:

```python
# In your agent's task, set up context gating first
setup_gating = Task(
    description=(
        "Apply the 'inference-standard' context gating template. "
        "This ensures that when you make inference calls, secrets, PII, "
        "and internal reasoning are redacted before reaching the LLM provider."
    ),
    expected_output="Confirmation that context gating policy is active.",
    agent=sovereign_agent,
)
```

### Sovereignty Health Reports as Crew Metadata

Generate an SHR to advertise your crew's sovereignty posture to external systems:

```python
audit_task = Task(
    description=(
        "Generate a Sovereignty Health Report and run a sovereignty audit. "
        "Report your sovereignty score, any gaps, and recommendations."
    ),
    expected_output="SHR document and audit score with gap analysis.",
    agent=sovereign_agent,
)
```

The SHR is a signed JSON document that counterparties can verify - useful for establishing trust in multi-crew workflows.

## Adding Concordia (Negotiation)

For structured negotiation between agents, add [Concordia Protocol](https://pypi.org/project/concordia-protocol/):

```bash
pip install concordia-protocol
```

```python
negotiator = Agent(
    role="Deal Negotiator",
    goal="Negotiate service agreements using structured protocols",
    backstory="A negotiator with sovereignty and binding negotiation capabilities.",
    mcps=[
        {
            "name": "sanctuary",
            "command": "npx",
            "args": ["-y", "@sanctuary-framework/mcp-server"],
            "transport": "stdio",
        },
        {
            "name": "concordia",
            "command": "python",
            "args": ["-m", "concordia"],
            "transport": "stdio",
        },
    ],
)
```

Sanctuary and Concordia compose but neither depends on the other. Use either alone or both together.

## Requirements

- Node.js 22+ (for Sanctuary MCP server)
- Python 3.10+ (for CrewAI)
- CrewAI 1.0+ (for native `mcps` support)
- `@sanctuary-framework/mcp-server` >= 0.3.1

## License

Apache-2.0
