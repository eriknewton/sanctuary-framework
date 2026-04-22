# Handoff Coordinator

An agent that coordinates escrow-style handoffs between other agents in your fortress. Every handoff is gated by a commitment boundary check.

## What this agent does

- Reads and writes to plans and outputs to manage handoffs.
- Delegates tasks to peer agents and holds results in escrow.
- Every handoff produces a commitment that passes the boundary gate.
- Declares the intra-mesh-escrow commitment class for structured handoffs.

## What this agent does not do

- It cannot access credentials or memory.
- It cannot make outbound network requests (empty egress allowlist).
- It cannot spend tokens or money (no budget configured).
- It cannot bypass the commitment boundary; every handoff is gated.

## What you will need to set

1. **Agent identity.** Provide an agent ID when initializing.
2. **Peer agents.** The coordinator needs at least two peer agents to coordinate between. Ensure those agents have compatible channel policies.
3. **Retention windows.** Plans and outputs: 30 days each. Adjust if your handoff workflows span longer periods.
