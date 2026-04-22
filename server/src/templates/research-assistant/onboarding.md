# Research Assistant

A read-only research agent that fetches information from approved sources and writes summaries to your fortress outputs.

## What this agent does

- Reads from external research sources you configure in the egress allowlist.
- Writes research summaries to the outputs slot for your review.
- Does not access credentials, plans, or memory from other agents.

## What this agent does not do

- It cannot share credentials or access secrets.
- It cannot modify plans or coordinate with other agents.
- It cannot make outbound requests to destinations outside the egress allowlist.

## What you will need to set

1. **Egress allowlist.** Replace the placeholder domains in the egress configuration with your actual research data providers and model inference endpoint.
2. **Agent identity.** Provide an agent ID when initializing (used for policy binding and audit trail).
3. **Review cadence.** Outputs are retained for 30 days by default. Adjust if your review cycle is longer.
