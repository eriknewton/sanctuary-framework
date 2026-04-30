# Operator Chat Setup, Per Harness

Sanctuary's direct-agent chat surface (in the dashboard, under any wrapped agent) lets you message a wrapped agent and read its replies. The wrapped agent receives those messages through `chat/poll_inbox` and replies through `chat/send_reply`, both exposed by the `sanctuary-chat` MCP server that `sanctuary wrap` registers alongside `sanctuary`.

The remaining piece is the wake mechanism: when does the agent's runtime decide to poll? That is harness-level behaviour, not MCP-server behaviour. Sanctuary handles Claude Code automatically. Other harnesses use a one-time system-prompt augmentation. This document covers both.

## Quick reference

| Harness | Wake mechanism | Setup step |
|---|---|---|
| Claude Code | Stop hook (autonomous on every turn-end) | `sanctuary wrap --claude-code --install-hooks` (default-on; opt-out with `--no-install-hooks`) |
| Cline | System-prompt augmentation | Paste the snippet below into Cline's custom-instructions field |
| Cursor | System-prompt augmentation | Paste the snippet below into `.cursorrules` in your project root |
| OpenClaw | System-prompt augmentation | Paste the snippet below into your operator's persistent system prompt or pinned skill |
| Hermes | System-prompt augmentation | Paste the snippet below into the agent's system prompt |
| Mastra | System-prompt augmentation OR Inngest workflow | Paste the snippet OR add the workflow snippet below for full autonomy |

## Honesty floor

What works after setup:

- Operator types a message in the Sanctuary dashboard. Tier 1 approval gates the session. Dashboard polls every 2s for replies.
- For Claude Code with the Stop hook installed: any time Claude finishes a turn (after operator typed in Claude Code, or after a tool call cycle ends), the hook drains the inbox and reinjects pending messages as the next instruction. End-to-end latency: ~3-5 seconds when Claude is in or just-finished a turn.
- For Cline / Cursor / OpenClaw / Hermes / Mastra with the augmentation pinned: the agent polls at the start of every turn. Replies arrive on the next harness turn, which fires when you type in the harness's input surface.

What does not work in v1.2.0:

- Waking an idle session that has not been used since you sent a dashboard message. Type any character in the harness to bring it into a turn.
- Push notifications via MCP. The spec primitive (`notifications/list_changed`) exists; the harness ecosystem does not handle it consistently as of April 2026. Deferred to v1.3.

## Claude Code (autonomous via Stop hook)

`sanctuary wrap --claude-code --install-hooks` installs a Stop hook entry at `~/.claude/settings.json`. The hook is tagged with the `SanctuaryChatPoll` matcher so it coexists with operator hooks; both fire at every Claude turn-end. Re-running wrap is idempotent for the structural shape; env values refresh to the most-recent fortress (most-recent wrap wins).

Latency: ~3-5 seconds after Claude turn-end. If Claude is sitting idle at the prompt, type any character (e.g. `/help`) to drain the inbox.

Opt-out: `sanctuary wrap --claude-code --no-install-hooks`. Use the Claude Code system-prompt augmentation below as the manual fallback.

Manual fallback (for `--no-install-hooks` or for operators who prefer the augmentation path): paste the Claude Code variant of the snippet below into `~/.claude/CLAUDE.md`.

## System-prompt augmentation snippet

Paste this into the harness's persistent system-prompt surface. It is harness-agnostic; the only variation is where the harness reads its system prompt from.

```
You are operating inside Sanctuary Framework. The operator can message
you directly through the Sanctuary dashboard's direct-agent chat
surface. Two MCP tools handle the channel:

  chat/poll_inbox: returns pending operator messages on this agent's
                   active session. Returns empty when nothing new.
  chat/send_reply: delivers your response back to the operator on the
                   bound session id.

At the start of every turn, before doing anything else:

  1. Call chat/poll_inbox. If it returns one or more operator messages,
     read them carefully.
  2. For each operator message, call chat/send_reply with the bound
     session_id and your response body. Write a thoughtful, complete
     reply, not a one-line acknowledgement.
  3. Only after the operator inbox is empty, continue with whatever
     task you were working on.

If chat/poll_inbox returns "no active chat session", that is normal:
no operator session is open. Continue with your task without
mentioning the chat tools.
```

### Cline

Where to paste: VS Code → Settings → Cline → Custom Instructions (alternatively, Cline's `.clinerules` if your version supports project-level instructions).

After paste: restart any active Cline conversation. Subsequent turns will include the chat-poll step.

### Cursor

Where to paste: a `.cursorrules` file at the root of your project (or under `.cursor/rules/sanctuary.mdc` if you use the rules directory layout).

After paste: open a new Cursor chat. Subsequent turns include the chat-poll step.

### OpenClaw

Where to paste: your OpenClaw operator's persistent system prompt, or a pinned skill that fires at the start of every turn. The exact surface depends on your OpenClaw deployment shape; consult OpenClaw's documentation for the current pinning mechanism.

OpenClaw also supports cron-based wake. A future v1.2.x deliverable may ship a Sanctuary-registered cron task that polls the inbox every N seconds independent of the operator's typing. Tracked as a v1.2.x follow-up; v1.2.0 ships the system-prompt augmentation path only.

### Hermes

Where to paste: the agent's system prompt in your Hermes deployment configuration.

Hermes is channel-event driven (Telegram, Discord, etc. trigger turns). For operators routing dashboard messages through a Hermes channel, a future v1.2.x deliverable may ship a webhook adapter so dashboard messages flow into a Hermes channel automatically. Tracked as a v1.2.x follow-up; v1.2.0 ships the system-prompt augmentation path only.

### Mastra (system-prompt augmentation)

Where to paste: the agent's system prompt in your Mastra agent config (the `instructions` field on the `Agent` class, or wherever your codebase defines the persistent prompt).

After paste: redeploy the Mastra agent so subsequent turns include the chat-poll step.

### Mastra (Inngest workflow, full autonomy)

If you run Mastra with Inngest as your durable workflow scheduler, you can poll Sanctuary on a cron schedule independent of operator-typed turns. Add a workflow that calls Sanctuary's chat tools every N seconds:

```typescript
import { inngest } from "./inngest-client";
import { mcp } from "./your-sanctuary-mcp-client";

export const sanctuaryChatPoll = inngest.createFunction(
  {
    id: "sanctuary-chat-poll",
    name: "Drain Sanctuary operator inbox",
  },
  { cron: "*/30 * * * * *" },
  async ({ step }) => {
    const result = await step.run("poll-inbox", async () => {
      return await mcp.callTool("chat/poll_inbox", {});
    });
    if (!result || !result.messages || result.messages.length === 0) {
      return { drained: 0 };
    }
    for (const message of result.messages) {
      await step.run(`reply-${message.message_id}`, async () => {
        const reply = await yourAgent.respond(message.body);
        await mcp.callTool("chat/send_reply", {
          session_id: result.session_id,
          body: reply,
        });
      });
    }
    return { drained: result.messages.length };
  },
);
```

Cron expression `*/30 * * * * *` polls every 30 seconds; tune to your preference. The workflow above is a sketch; adapt the agent-call shape to your existing Mastra surface.

## Verifying the setup works

After pasting the augmentation (or installing the Stop hook for Claude Code):

1. Open the Sanctuary dashboard, click the wrapped agent in the agent list, click "Open chat".
2. Approve the Tier 1 inbox item that pops up; the chat surface opens.
3. Type "what tools are available to you" and submit.
4. Switch to your harness. Type any prompt to bring the harness into a turn (Claude Code with the Stop hook: any single character works; other harnesses: any normal prompt).
5. Watch the Sanctuary dashboard chat. The agent's reply should render within a few seconds of its turn ending.

If no reply arrives within ~30 seconds:

- Check `~/.sanctuary/audit-log.enc` (via `sanctuary audit query`): look for `direct_agent_session_open`, `operator_direct_agent_chat`, and `agent_direct_agent_reply` events. The first two confirm the operator side worked; the absence of the third means the agent's runtime did not call `chat/send_reply`.
- For Claude Code with the Stop hook: re-run `sanctuary wrap --claude-code --install-hooks` and check the console line. The output should say `Stop hook installed` or `Stop hook already present`. If it says `Stop hook install failed`, the error message contains the cause.
- For other harnesses: confirm the augmentation snippet is actually loaded by the harness's runtime. Some harnesses cache the system prompt; restart the harness or open a new conversation.

## Filing feedback

If you hit a setup issue not covered here, open an issue at https://github.com/eriknewton/sanctuary-framework/issues with:

- The harness name and version.
- The output of `sanctuary --version`.
- The relevant lines from `~/.sanctuary/audit-log.enc` (decrypt via `sanctuary audit query --tail 50`).
- The augmentation snippet you pasted (or `Stop hook installed` console line for Claude Code).

## See also

- `server/docs/v1.2-direct-agent-chat-known-gaps.md` for the full operator-workflow matrix and the v1.3 push-notifications roadmap.
- `server/docs/integrate-with-sanctuary.md` for the harness-developer integration guide.
- `server/src/mcp/chat-server.ts` for the wire-level chat tool contracts.
