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

Sanctuary's chat tools are pull-based: the agent calls `chat/poll_inbox` when its runtime decides to. The wake-mechanism question is "what makes the agent's runtime decide to call?" The unified pattern shipped in v1.2.0 is **voluntary poll triggered by per-harness instruction surface**. Each harness has an instruction surface where operator-supplied context is read on session start; pinning the Sanctuary augmentation snippet there causes the agent to voluntarily call `chat/poll_inbox` after every turn.

### The unified augmentation pattern

Every harness in v1.2.0 uses the same pattern at different surfaces:

| Harness | Instruction surface |
|---|---|
| Claude Code | `~/.claude/CLAUDE.md` (auto-installed via `sanctuary wrap --install-hooks`) |
| Cline | Custom Instructions field |
| Cursor | `.cursorrules` (or `.cursor/rules/sanctuary.mdc`) |
| OpenClaw | persistent system prompt or pinned skill |
| Hermes | agent system prompt |
| Mastra | `instructions` field on the `Agent` class |

The augmentation text is operator-supplied context. The harness reads it on session start and the agent treats it as part of its operator's instruction. Claude (and other models with similar safety training) acts on it voluntarily because it presents as the operator's own context, not as an external mid-stream injection. The trust model mirrors the broker-server pattern that has worked since Sanctuary v0.10.0: Sanctuary exposes tools, the agent voluntarily calls them.

Reference implementation for Claude Code auto-install: `server/src/cocoon/claude-code-augmentation.ts`. The exact augmentation text shipped in v1.2.0 is at `SANCTUARY_AUGMENTATION_BODY` in that file.

### Why not Stop-hook injection

An earlier F10 design (PR #99) used the Claude Code Stop hook with `decision: "block"` plus `reason: "<operator message>; reply via tool X"` to inject pending operator messages between turns. Field testing 2026-04-30 confirmed Claude's safety training correctly classifies the injection-shape payload as a prompt-injection attempt and refuses. This is not a bug in the safety training; it is a design-level mismatch.

The augmentation pattern works WITH safety training. We chose to compose with the agent's instruction layer (the trusted shape) rather than work around the safety layer. PR #99 was closed in favor of the reshape; the Stop-hook installer code never landed on `main`.

### Cron-based polling (for harnesses with built-in scheduler)

OpenClaw, Mastra (with Inngest), and other harnesses with cron primitives can register a scheduled task that polls the inbox every N seconds independent of operator-typed turns. Closest match to fully-autonomous behaviour without push notifications.

OpenClaw cron-task wake is a v1.2.x deliverable gated on contacting OpenClaw maintainers to confirm the cron API surface. Mastra Inngest workflow snippet ships in `server/docs/operator-chat-setup.md`.

### Channel-routed wake (for channel-event-driven harnesses)

Hermes routes operator messages through Telegram, Discord, or other channels. A Sanctuary-emitted webhook into a Hermes channel could trigger a turn the same way an external user message would. Deferred to v1.2.x pending Hermes-deployment-shape research.

### MCP push notifications (`notifications/list_changed`)

The clean future. The MCP spec (2025-06-18) defines server-pushed notifications. Sanctuary's chat-server is ready to emit them; the gating issue is harness adoption. Claude Code declares the schema but does not register a handler (anthropics/claude-code#13646). Cline's resource-list-changed is broken (cline/cline#1394). Cursor lacks support (open RFE).

When Claude Code, Cline, and Cursor all close their respective issues, Sanctuary v1.3 will land push notifications and operators can deprecate per-harness wake mechanisms.

## How to add a Tier B adapter

1. Create `server/src/agent-contract/adapters/<your-harness>.ts` mirroring the shape of `claude-code.ts`. Implement the `TierBAdapter` interface from `tier-b-sdk.ts`.
2. Register your harness in `server/src/cocoon/config-reader.ts`: add the `AgentPlatform` enum case, the candidate config paths under `getPlatformPaths()`, and the platform-detection logic.
3. Add a flag to `server/src/cocoon/cli.ts` (`--<your-harness>`) so operators can wrap with `sanctuary wrap --<your-harness>`.
4. If your harness has a file-based instruction surface (like `~/.claude/CLAUDE.md` for Claude Code), consider adding an auto-installer mirror at `server/src/cocoon/<your-harness>-augmentation.ts` so `sanctuary wrap --<your-harness> --install-hooks` works the same way as the Claude Code surface.
5. Add the operator-facing setup section in `server/docs/operator-chat-setup.md` so end users have a clear path.

Open a PR; the maintainer reviews and lands. Composition partners are not competitors; we ship integration with you.

## Composition posture

Every named harness in this guide is a composition partner. Sanctuary's design posture is "ship the rights substrate; let operators choose their harness." We do not name competitors in public-facing copy because Sanctuary's value proposition holds regardless of which harness an operator runs.

If you're building a new harness, integrate with Sanctuary as a partner. Contribute upstream. Ship reference adapters that operators can copy.

## Filing feedback

Open an issue at https://github.com/eriknewton/sanctuary-framework/issues with:

- Your harness name, version, and repository link.
- The integration pattern you tried (Tier B adapter? auto-augmentation? system-prompt augmentation? cron?).
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
- `server/src/cocoon/claude-code-augmentation.ts`: the reference auto-installer for the unified augmentation pattern.
