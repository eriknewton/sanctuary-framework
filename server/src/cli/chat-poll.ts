/**
 * Sanctuary MCP Server — `sanctuary chat-poll` CLI subcommand (v1.2.x F10).
 *
 * Drains the wrapped agent's direct-chat inbox in-process, advances the
 * persisted poll cursor, and emits the result on stdout. Used by the
 * Claude Code Stop hook to inject pending operator messages as the next
 * Claude instruction; also operator-debuggable from the shell.
 *
 * Behaviour mirrors the chat-server's `chat/poll_inbox` handler: filters
 * to operator-role messages on the bound active session, scoped by the
 * persisted cursor, advances the cursor when at least one message is
 * returned. Cross-agent isolation is preserved at the same per-agent
 * index; this subcommand never reads another agent's session.
 *
 * Output formats:
 *
 *   --format json (default) — single JSON object on stdout, one line:
 *     {
 *       "session_id": "<id> | null",
 *       "messages": [...],
 *       "cursor": "<id> | null",
 *       "session_state": "active" | "none"
 *     }
 *
 *   --format flat — one tab-separated record per pending message:
 *     <session_id>\t<message_id>\t<created_at>\t<body>
 *     Empty stdout when no pending messages. Bash-friendly.
 *
 * Exit codes:
 *
 *   0 — success (with or without messages)
 *   1 — error (no agent id, fortress unreadable, master key derivation fails)
 *
 * No subprocess spawn: opens `openOperatorChat()` directly. Pays the
 * Argon2id cost once per invocation; Stop-hook latency is ~500-1500ms
 * on top of the Claude turn time. Acceptable for v1.2.0; v1.3 may
 * introduce a shared cocoon daemon to amortize key derivation.
 */

import type { OperatorChatService } from "../chat/operator-chat-service.js";

export interface ChatPollArgs {
  argv: string[];
  /** Output stream (stdout in prod). */
  out?: NodeJS.WritableStream;
  /** Error stream (stderr in prod). */
  err?: NodeJS.WritableStream;
  /**
   * Override the chat-handle factory. Production uses
   * `openOperatorChat()`; tests inject a stub service to avoid touching
   * a real fortress.
   */
  openChat?: () => Promise<{
    service: OperatorChatService;
    close: () => Promise<void>;
  }>;
}

export type ChatPollFormat = "json" | "flat";

interface ParsedChatPollOptions {
  agentId: string | undefined;
  format: ChatPollFormat;
  quiet: boolean;
  helpRequested: boolean;
}

function parseChatPollArgv(argv: string[]): ParsedChatPollOptions {
  const opts: ParsedChatPollOptions = {
    agentId: undefined,
    format: "json",
    quiet: false,
    helpRequested: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--agent-id":
        opts.agentId = argv[++i];
        break;
      case "--format": {
        const next = argv[++i];
        if (next === "json" || next === "flat") {
          opts.format = next;
        } else {
          // Surface unknown format as a non-fatal warning; defaults to json
          // so the hook script's parsing path stays consistent.
          opts.format = "json";
        }
        break;
      }
      case "--quiet":
      case "-q":
        opts.quiet = true;
        break;
      case "--help":
      case "-h":
        opts.helpRequested = true;
        break;
    }
  }

  return opts;
}

function printChatPollHelp(out: NodeJS.WritableStream): void {
  out.write(`
  sanctuary chat-poll. Drain the wrapped agent's direct-chat inbox.

  Usage:
    sanctuary chat-poll --agent-id <agent-id> [--format json|flat] [--quiet]

  Options:
    --agent-id <id>    Wrapped-agent identifier (defaults to
                       SANCTUARY_AGENT_ID env var when set by
                       \`sanctuary wrap\`).
    --format json      JSON object on stdout (default; single line).
    --format flat      Tab-separated record per pending message
                       (session_id\\tmessage_id\\tcreated_at\\tbody).
                       Empty stdout when no pending messages.
    --quiet, -q        Suppress non-error stderr output.
    --help, -h         Show this help.

  Behaviour:
    Reads the active direct-chat session bound to the agent, filters to
    pending operator messages newer than the persisted poll cursor,
    advances the cursor when at least one message is returned. No
    subprocess spawn: opens the operator-chat service in-process.

  Exit codes:
    0  success (with or without messages)
    1  error (missing agent id, fortress unreadable, key derivation
       failure)
`);
}

export async function runChatPoll(args: ChatPollArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const opts = parseChatPollArgv(args.argv);

  if (opts.helpRequested) {
    printChatPollHelp(out);
    return 0;
  }

  const agentId = opts.agentId ?? process.env.SANCTUARY_AGENT_ID;
  if (!agentId) {
    err.write(
      "sanctuary chat-poll: --agent-id <id> required (or SANCTUARY_AGENT_ID env var).\n",
    );
    return 1;
  }

  const factory =
    args.openChat ??
    (async () => {
      const { openOperatorChat } = await import("../chat/open.js");
      return openOperatorChat({});
    });

  let handle: { service: OperatorChatService; close: () => Promise<void> };
  try {
    handle = await factory();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    err.write(`sanctuary chat-poll: failed to open chat service: ${msg}\n`);
    return 1;
  }

  try {
    const session = await handle.service.findActiveSessionForAgent(agentId);

    // session_state mirrors chat-server's enum so hook scripts and
    // operator-debug runs see the same shape.
    if (!session) {
      if (opts.format === "json") {
        out.write(
          JSON.stringify({
            session_id: null,
            messages: [],
            cursor: null,
            session_state: "none",
          }) + "\n",
        );
      }
      // flat format emits nothing on empty inbox / no session.
      return 0;
    }

    const sessionState =
      session.closed_at
        ? "closed"
        : Date.parse(session.expires_at) <= Date.now()
          ? "expired"
          : "active";

    if (sessionState !== "active") {
      if (opts.format === "json") {
        out.write(
          JSON.stringify({
            session_id: session.session_id,
            messages: [],
            cursor: session.last_polled_message_id ?? null,
            session_state: sessionState === "closed" ? "closed" : "expired",
          }) + "\n",
        );
      }
      return 0;
    }

    const history = await handle.service.getDirectAgentHistory(agentId);
    const cursor = session.last_polled_message_id ?? null;
    let cursorIdx = -1;
    if (cursor) {
      cursorIdx = history.findIndex((m) => m.message_id === cursor);
    }
    const newer = history
      .filter(
        (m) => m.role === "operator" && m.session_id === session.session_id,
      )
      .filter((m) => {
        if (cursorIdx < 0) return true;
        const idx = history.findIndex((h) => h.message_id === m.message_id);
        return idx > cursorIdx;
      });

    let newCursor = session.last_polled_message_id ?? null;
    if (newer.length > 0) {
      const lastId = newer[newer.length - 1]!.message_id;
      await handle.service.advancePollCursor(session.session_id, lastId);
      newCursor = lastId;
    }

    if (opts.format === "flat") {
      for (const m of newer) {
        // Tab-separated; body is last so embedded tabs are preserved
        // intact for downstream readers that split on first three tabs.
        const safeBody = m.body.replace(/[\r\n]+/g, " ");
        out.write(
          `${m.session_id}\t${m.message_id}\t${m.created_at}\t${safeBody}\n`,
        );
      }
    } else {
      out.write(
        JSON.stringify({
          session_id: session.session_id,
          messages: newer,
          cursor: newCursor,
          session_state: "active",
        }) + "\n",
      );
    }

    if (!opts.quiet && newer.length > 0) {
      err.write(
        `sanctuary chat-poll: drained ${newer.length} message${
          newer.length === 1 ? "" : "s"
        } from session ${session.session_id}.\n`,
      );
    }

    return 0;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    err.write(`sanctuary chat-poll: poll failed: ${msg}\n`);
    return 1;
  } finally {
    try {
      await handle.close();
    } catch {
      /* best-effort drain */
    }
  }
}
