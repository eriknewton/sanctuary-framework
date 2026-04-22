# Coding Assistant

A full-access coding agent with bidirectional memory and output sync, a daily token budget, and egress to your model provider and developer services.

## What this agent does

- Reads and writes to all four slots (memory, credentials, plans, outputs).
- Syncs memory and outputs bidirectionally with peer agents in the mesh.
- Makes inference calls to your configured model provider.
- Accesses package registries and documentation sites for development tasks.

## What this agent does not do

- It cannot exceed the daily token budget (default: 500,000 tokens/day).
- It cannot reach endpoints outside the egress allowlist.
- It cannot share credentials with other agents without explicit operator policy.

## What you will need to set

1. **Model provider endpoint.** Replace the placeholder domain with your actual LLM inference endpoint (e.g., your provider's API domain).
2. **Developer service endpoints.** Add or replace package registries and documentation sites your agent needs.
3. **Daily token budget.** The default is 500,000 tokens/day. Adjust based on your workload and cost tolerance.
4. **Agent identity.** Provide an agent ID when initializing.
5. **Retention windows.** Memory: 7 days. Plans: 30 days. Outputs: 90 days. Credentials: indefinite. Adjust as needed.
