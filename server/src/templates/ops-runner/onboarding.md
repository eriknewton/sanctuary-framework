# Ops Runner

An operations agent that runs authorized tasks against scoped credentials, with a monthly USD budget and operator-controlled egress.

## What this agent does

- Accepts operator-authorized tasks via the commitment boundary.
- Accesses scoped credentials (one credential at a time, named by ID).
- Writes task results to the outputs slot for operator review.
- Tracks spend against a monthly USD budget.

## What this agent does not do

- It cannot access credentials beyond the scope the operator configures.
- It cannot make outbound requests until the operator fills the egress allowlist.
- It cannot exceed the monthly USD budget (default: $100/month).
- It cannot act without first proposing a commitment that passes the boundary gate.

## What you will need to set

1. **Egress allowlist.** This template ships with an empty allowlist. You must add every service endpoint your ops agent needs to reach.
2. **Credential scope.** When initializing, specify which credential ID the agent may access.
3. **Monthly USD budget.** The default is $100/month. Adjust based on the cost of the APIs your agent calls.
4. **Agent identity.** Provide an agent ID when initializing.
5. **Retention windows.** Plans: 30 days. Outputs: 90 days. Credentials: indefinite. Adjust as needed.
