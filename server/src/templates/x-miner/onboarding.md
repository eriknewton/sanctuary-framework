# X-Miner

A data-mining sub-agent that reads from the xAI Grok API to surface insights from X.

## What this is for

This template lights up the multi-agent data-mining pattern: an operator orchestrator delegates external data collection to a dedicated sub-agent. The X-Miner reads from X via the xAI Grok API and writes structured summaries to the outputs slot. The orchestrator consumes those outputs without needing direct access to the X data source.

## How to use it

1. **Get an xAI API key.** Sign up at xAI and generate an API key for the Grok API.
2. **Initialize the template.** Run `sanctuary template init x-miner --agent-id my-x-miner` or use the "Add Agent" button in the console.
3. **Store the API key.** Use the secret broker to store your xAI API key as a per-agent credential. The X-Miner's policy restricts credential access to this agent only.
4. **Query.** Send queries through the orchestrator. The X-Miner will fetch results from Grok and write summaries to its outputs slot.
5. **Review.** Check the outputs slot for mined data. Outputs are retained for 90 days by default.

## When to customize

- **Budget caps.** The default is 100,000 tokens/day and $5 USD/month. Adjust if your data-mining volume is higher.
- **Retention.** Memory is retained for 30 days and outputs for 90 days. Extend outputs retention if you need a longer archive window.
- **Additional egress.** If your workflow requires accessing other APIs alongside xAI (for example, enrichment services), add their domains to the egress allowlist.
