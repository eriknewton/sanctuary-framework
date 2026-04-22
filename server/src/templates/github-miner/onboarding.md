# GitHub-Miner

A data-mining sub-agent that reads from the GitHub API to surface repository, issue, and pull request insights.

## What this is for

This template lights up the multi-agent data-mining pattern for GitHub: an operator orchestrator delegates repository intelligence to a dedicated sub-agent. The GitHub-Miner reads from the GitHub REST API and writes structured summaries to the outputs slot. The orchestrator consumes those outputs without needing direct access to GitHub.

## How to use it

1. **Get a GitHub personal access token.** Generate a fine-grained personal access token at GitHub with read access to the repositories you want to mine.
2. **Initialize the template.** Run `sanctuary template init github-miner --agent-id my-github-miner` or use the "Add Agent" button in the console.
3. **Store the token.** Use the secret broker to store your GitHub token as a per-agent credential. The GitHub-Miner's policy restricts credential access to this agent only.
4. **Query.** Send queries through the orchestrator. The GitHub-Miner will fetch results from the GitHub API and write summaries to its outputs slot.
5. **Review.** Check the outputs slot for mined data. Outputs are retained for 90 days by default.

## When to customize

- **Budget caps.** The default is 100,000 tokens/day and $5 USD/month. Adjust if your mining volume is higher.
- **Retention.** Memory is retained for 30 days and outputs for 90 days. Extend outputs retention if you need a longer archive window.
- **Model provider.** The default model provider is Anthropic. You can switch to Mistral or another provider if your workflow prefers a different inference backend.
- **Additional egress.** The default egress allowlist includes `api.github.com` only. If your workflow requires accessing GitHub's GraphQL API or other enrichment services, add their domains.
