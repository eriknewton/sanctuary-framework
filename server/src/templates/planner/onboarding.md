# Planner

A planning agent that writes and revises plans for your review. Operates entirely offline with no egress and no budget.

## What this agent does

- Writes and revises plans in the plans slot.
- Other agents in the mesh can read-only inspect this agent's plans.
- Reads memory and outputs for context (read-only).

## What this agent does not do

- It cannot access credentials.
- It cannot make outbound network requests (empty egress allowlist).
- It cannot spend tokens or money (no budget configured).
- It cannot execute plans; it only writes them for your approval.

## What you will need to set

1. **Agent identity.** Provide an agent ID when initializing.
2. **Retention windows.** Plans and outputs: 90 days each. Adjust based on your planning cycle length.
3. **Peer agents.** If you want other agents to inspect this planner's output, they will need a channel opened to read the plans slot.
