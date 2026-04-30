# Integrate Your Harness With Sanctuary

This guide is for harness developers (Claude Code, Cline, Cursor, OpenClaw, Hermes, Mastra, Aider, LangGraph, and any future agent harness) who want their wrapped agents to deliver direct-agent chat replies, expose attestable usage events, or surface their managed-child stdin under a Sanctuary fortress.

Sanctuary speaks MCP. Anything that can run an MCP server as a sibling stdio child of the harness can integrate with zero changes to the harness's core protocol. This guide covers what Sanctuary exposes, the Tier B adapter contract for stronger integration, and the wake-mechanism options for direct-agent chat.

## What Sanctuary exposes

### `chat/poll_inbox` and `chat/send_reply`

Both ship in the standalone `sanctuary chat-server` MCP server. `sanctuary wrap` registers it alongside `sanctuary` so any harness running in a wrapped fortress automatically has access.

- `chat/poll_inbox` (no inputs): returns `{messages, session_id, cursor, session_state}`. Empty `messages` array on an active session with no pending operator messages. Generic error when no active session exists for this agent. The chat-server is bound to a single `(agent_id, identity_id)` at construction; cross-agent reads are rejected.
- `chat/send_reply` (`{session_id, body}`): delivers a reply on the session. Body trimmed; must be non-empty. Cross-agent isolation: the session must exist and belong to this chat-server's bound agent_id. Returns the persisted message record.

Wire format and full contract: `server/src/mcp/chat-server.ts`. Test the contract live: `server/test/mcp/chat-server-tools.test.ts`.

### Tier B adapter interface

Adapters at `server/src/agent-contract/adapters/` (claude-code.ts, cline.ts, hermes.ts, mastra.ts) implement the v0.1 Tier B contract. The contract is small:

- `usageEvent(input)`: emit a Sanctuary-canonicalized usage event (commitment-bounded, attestable). Operators get a portable record of what the agent did and why; replay-capable for audit and reputation.
- `transport.send(input)`: write into the managed child's stdin. v1.2.0 reserves this surface for adapter-specific use; the F10 wake-mechanism build does not use it. Future Tier B integrations can use it for synchronous prompt injection.

Reference shape: `server/src/agent-contract/adapters/tier-b-sdk.ts`. Spec: `Review/Sanctuary/Agent_Contract_V0.1_Spec_2026-04-21.md` §5.

### Other Sanctuary MCP tools

The main `sanctuary` MCP server exposes ~75 tools across L1 (encrypted state, identity), L2 (approval gates, context gating, audit log), L3 (selective disclosure, commitments), and L4 (signed attestations, reputation). Useful surfaces for harness developers:

- `state_read` / `state_write`: encrypted per-agent state under the wrap fortress.
- `identity_create` / `identity_sign` / `identity_verify`: per-agent Ed25519 identity, exportable.
- `monitor_audit_log`: replay the agent's audit chain.
- `proof_commitment` / `proof_reveal`: selective-disclosure commitments (agent claims something about its data without revealing the data).
- `reputation_record` / `reputation_query`: signed attestations bound to the agent's identity.
- `manifest`: full tool list with schemas.

Run `sanctuary manifest` to see the live tool catalogue.

## Wake-mechanism options

Sanctuary's chat tools are pull-based: the agent calls `chat/poll_inbox` when its runtime decides to. The wake-mechanism question is "what makes the agent's runtime decide to call?" Five viable patterns today, ranked by autonomy:

### 1. Harness-native event hook (e.g. Claude Code Stop hook)

Best for harnesses that fire a hook event on every agent-turn boundary. Sanctuary's F10 build (v1.2.0) installs a Stop hook into `~/.claude/settings.json` that drains the inbox via `sanctuary chat-poll` and reinjects pending messages as the next instruction.

Pattern: `decision: "block"` + `reason: "<operator message>; reply via chat/send_reply"`. The harness reads the block + reason, the agent reads the reason as its next instruction.

Recursion guard: when the hook returns block + reason, the next event fires with `stop_hook_active: true`. The hook script detects this and exits 0 without polling.

Coexistence: Sanctuary's hook is tagged with a sentinel matcher (`SanctuaryChatPoll`) so operator-installed hooks at the same event class continue firing alongside.

If your harness has a similar event-hook surface (`onTurnEnd`, `afterToolCall`, etc.), this is the highest-fidelity integration. Reference implementation: `server/src/cocoon/claude-code-hooks.ts` + `server/scripts/sanctuary-chat-stop-hook.sh`.

### 2. System-prompt augmentation

Universal fallback. Pin a paragraph instructing the agent to call `chat/poll_inbox` at the start of every turn and reply via `chat/send_reply` if there are messages. Works for every harness in v1.2.0 because every harness has a persistent-system-prompt surface.

The exact snippet ships in `server/docs/operator-chat-setup.md`. Operators copy-paste; no harness code change.

### 3. Cron-based polling (for harnesses with built-in scheduler)

OpenClaw, Mastra (with Inngest), and other harnesses with cron primitives can register a scheduled task that polls the inbox every N seconds independent of operator-typed turns. Closest match to fully-autonomous behaviour without push notifications.

OpenClaw cron-task wake is a v1.2.x deliverable gated on contacting OpenClaw maintainers to confirm the cron API surface. Mastra Inngest workflow snippet ships in `server/docs/operator-chat-setup.md`.

### 4. Channel-routed wake (for channel-event-driven harnesses)

Hermes routes operator messages through Telegram, Discord, or other channels. A Sanctuary-emitted webhook into a Hermes channel could trigger a turn the same way an external user message would. Deferred to v1.2.x pending Hermes-deployment-shape research.

### 5. MCP push notifications (`notifications/list_changed`)

The clean future. The MCP spec (2025-06-18) defines server-pushed notifications. Sanctuary's chat-server is ready to emit them; the gating issue is harness adoption. Claude Code declares the schema but does not register a handler (anthropics/claude-code#13646). Cline's resource-list-changed is broken (cline/cline#1394). Cursor lacks support (open RFE).

When Claude Code, Cline, and Cursor all close their respective issues, Sanctuary v1.3 will land push notifications and operators can deprecate per-harness wake mechanisms.

## How to add a Tier B adapter

1. Create `server/src/agent-contract/adapters/<your-harness>.ts` mirroring the shape of `claude-code.ts`. Implement the `TierBAdapter` interface from `tier-b-sdk.ts`.
2. Register your harness in `server/src/cocoon/config-reader.ts`: add the `AgentPlatform` enum case, the candidate config paths under `getPlatformPaths()`, and the platform-detection logic.
3. Add a flag to `server/src/cocoon/cli.ts` (`--<your-harness>`) so operators can wrap with `sanctuary wrap --<your-harness>`.
4. If your harness supports a hook-event surface like Claude Code's Stop hook, add a corresponding installer in `server/src/cocoon/<your-harness>-hooks.ts` mirroring `claude-code-hooks.ts`.
5. Add the operator-facing setup section in `server/docs/operator-chat-setup.md` so end users have a clear path.

Open a PR; the maintainer reviews and lands. Composition partners are not competitors; we ship integration with you.

## Composition posture

Every named harness in this guide is a composition partner. Sanctuary's design posture is "ship the rights substrate; let operators choose their harness." We do not name competitors in public-facing copy because Sanctuary's value proposition holds regardless of which harness an operator runs.

If you're building a new harness, integrate with Sanctuary as a partner. Contribute upstream. Ship reference adapters that operators can copy.

## Filing feedback

Open an issue at https://github.com/eriknewton/sanctuary-framework/issues with:

- Your harness name, version, and repository link.
- The integration pattern you tried (Tier B adapter? hook event? system-prompt augmentation? cron?).
- What worked and what did not.
- The relevant `~/.sanctuary/audit-log.enc` entries (decrypt via `sanctuary audit query --tail 50`).

The maintainer reviews issues directly. There is no separate triage queue; this is a small team.

## See also

- `server/docs/operator-chat-setup.md`: the operator-facing setup snippets you'll point your users at.
- `server/docs/v1.2-direct-agent-chat-known-gaps.md`: the operator-workflow matrix and v1.3 roadmap.
- `Review/Sanctuary/Agent_Contract_V0.1_Spec_2026-04-21.md`: the full Tier B adapter contract.
- `Review/Sanctuary/Autonomous_Poll_Wake_Mechanism_Research_Brief_2026-04-30.md`: the cross-harness wake-mechanism research that informed F10.
- `server/src/mcp/chat-server.ts`: the wire-level chat-tool contracts.
- `server/src/agent-contract/adapters/`: reference Tier B adapters for Claude Code, Cline, Hermes, Mastra.
