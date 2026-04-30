/**
 * `sanctuary chat-poll` CLI subcommand — coverage for v1.2.0 F10.
 *
 *  - Empty inbox / no active session → JSON empty array; exit 0.
 *  - Pending operator message → JSON object with message + cursor; exit 0.
 *  - --format flat emits tab-separated records.
 *  - Cursor advances after a non-empty drain (stub mock asserts).
 *  - Closed / expired session → empty messages, session_state="closed"|"expired".
 *  - Cross-agent isolation: another agent's session is invisible.
 *  - Missing --agent-id → error to stderr, exit 1.
 *  - Service open failure → error to stderr, exit 1.
 *
 * No fortress, no encryption, no real chat-server. Tests inject a stub
 * service via `args.openChat`.
 */

import { describe, it, expect, vi } from "vitest";
import { Writable } from "node:stream";
import { runChatPoll } from "../../src/cli/chat-poll.js";
import type { OperatorChatService } from "../../src/chat/operator-chat-service.js";
import type {
  OperatorChatMessage,
  OperatorChatSession,
} from "../../src/chat/operator-chat-types.js";

interface StubServiceOpts {
  session: OperatorChatSession | null;
  history?: OperatorChatMessage[];
}

function makeStubService(opts: StubServiceOpts) {
  const findCalls: string[] = [];
  const advanceCalls: { sessionId: string; lastSeenMessageId: string }[] = [];
  const service = {
    findActiveSessionForAgent: vi.fn(async (agentId: string) => {
      findCalls.push(agentId);
      if (!opts.session) return null;
      if (opts.session.agent_id !== agentId) return null;
      return opts.session;
    }),
    getDirectAgentHistory: vi.fn(async () => opts.history ?? []),
    advancePollCursor: vi.fn(async (sessionId: string, lastSeenMessageId: string) => {
      advanceCalls.push({ sessionId, lastSeenMessageId });
    }),
  } as unknown as OperatorChatService;
  return { service, findCalls, advanceCalls };
}

function makeBuffers() {
  let outBuf = "";
  let errBuf = "";
  const out = new Writable({
    write(chunk, _enc, cb) {
      outBuf += chunk.toString();
      cb();
    },
  });
  const err = new Writable({
    write(chunk, _enc, cb) {
      errBuf += chunk.toString();
      cb();
    },
  });
  return {
    out,
    err,
    getOut: () => outBuf,
    getErr: () => errBuf,
  };
}

const ACTIVE_SESSION: OperatorChatSession = {
  session_id: "sess-active-1",
  agent_id: "agent:claude_code:fortressA",
  approval_inbox_item_id: "approval-1",
  created_at: "2026-04-30T12:00:00.000Z",
  expires_at: "2099-04-30T12:00:00.000Z",
  last_polled_message_id: null,
};

function operatorMessage(id: string, body: string, ts: string): OperatorChatMessage {
  return {
    message_id: id,
    surface: "direct-agent",
    agent_id: ACTIVE_SESSION.agent_id,
    session_id: ACTIVE_SESSION.session_id,
    role: "operator",
    body,
    created_at: ts,
  };
}

describe("sanctuary chat-poll subcommand (v1.2.0 F10)", () => {
  it("empty inbox: JSON output with empty messages, exit 0", async () => {
    const { service } = makeStubService({ session: ACTIVE_SESSION, history: [] });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", ACTIVE_SESSION.agent_id],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(bufs.getOut().trim());
    expect(parsed.session_id).toBe(ACTIVE_SESSION.session_id);
    expect(parsed.messages).toEqual([]);
    expect(parsed.session_state).toBe("active");
  });

  it("no active session: JSON output with session_state=none, exit 0", async () => {
    const { service } = makeStubService({ session: null });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", "agent:claude_code:somefortress"],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(bufs.getOut().trim());
    expect(parsed.session_id).toBeNull();
    expect(parsed.messages).toEqual([]);
    expect(parsed.session_state).toBe("none");
  });

  it("pending operator messages: JSON output with messages, cursor advanced", async () => {
    const m1 = operatorMessage("msg-1", "hello agent", "2026-04-30T12:01:00.000Z");
    const m2 = operatorMessage("msg-2", "what files have you touched", "2026-04-30T12:02:00.000Z");
    const { service, advanceCalls } = makeStubService({
      session: ACTIVE_SESSION,
      history: [m1, m2],
    });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", ACTIVE_SESSION.agent_id],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(bufs.getOut().trim());
    expect(parsed.messages).toHaveLength(2);
    expect(parsed.messages[0].message_id).toBe("msg-1");
    expect(parsed.messages[1].message_id).toBe("msg-2");
    expect(parsed.cursor).toBe("msg-2");
    expect(advanceCalls).toEqual([
      { sessionId: ACTIVE_SESSION.session_id, lastSeenMessageId: "msg-2" },
    ]);
  });

  it("--format flat emits tab-separated records, one per pending message", async () => {
    const m1 = operatorMessage("msg-1", "hello", "2026-04-30T12:01:00.000Z");
    const m2 = operatorMessage("msg-2", "second message", "2026-04-30T12:02:00.000Z");
    const { service } = makeStubService({
      session: ACTIVE_SESSION,
      history: [m1, m2],
    });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", ACTIVE_SESSION.agent_id, "--format", "flat", "--quiet"],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    const lines = bufs.getOut().trim().split("\n");
    expect(lines).toHaveLength(2);
    const [sid1, mid1, ts1, body1] = lines[0]!.split("\t");
    expect(sid1).toBe(ACTIVE_SESSION.session_id);
    expect(mid1).toBe("msg-1");
    expect(ts1).toBe("2026-04-30T12:01:00.000Z");
    expect(body1).toBe("hello");
    const [, mid2, , body2] = lines[1]!.split("\t");
    expect(mid2).toBe("msg-2");
    expect(body2).toBe("second message");
  });

  it("flat format: empty inbox emits no stdout", async () => {
    const { service } = makeStubService({ session: ACTIVE_SESSION, history: [] });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", ACTIVE_SESSION.agent_id, "--format", "flat"],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    expect(bufs.getOut()).toBe("");
  });

  it("cross-agent isolation: another agent's session is invisible", async () => {
    const sessionForA: OperatorChatSession = { ...ACTIVE_SESSION };
    const { service } = makeStubService({ session: sessionForA });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", "agent:claude_code:fortressB"],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(bufs.getOut().trim());
    expect(parsed.session_state).toBe("none");
    expect(parsed.session_id).toBeNull();
  });

  it("expired session: emits expired state, no message drain", async () => {
    const expired: OperatorChatSession = {
      ...ACTIVE_SESSION,
      expires_at: "2020-01-01T00:00:00.000Z",
    };
    const { service, advanceCalls } = makeStubService({
      session: expired,
      history: [
        operatorMessage("msg-1", "hello", "2026-04-30T12:01:00.000Z"),
      ],
    });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", ACTIVE_SESSION.agent_id],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(bufs.getOut().trim());
    expect(parsed.session_state).toBe("expired");
    expect(parsed.messages).toEqual([]);
    expect(advanceCalls).toEqual([]);
  });

  it("missing --agent-id and no SANCTUARY_AGENT_ID env: exit 1 with stderr message", async () => {
    const prior = process.env.SANCTUARY_AGENT_ID;
    delete process.env.SANCTUARY_AGENT_ID;
    try {
      const bufs = makeBuffers();
      const code = await runChatPoll({
        argv: [],
        out: bufs.out,
        err: bufs.err,
        openChat: async () => {
          throw new Error("openChat should not be called");
        },
      });
      expect(code).toBe(1);
      expect(bufs.getErr()).toMatch(/--agent-id <id> required/);
    } finally {
      if (prior !== undefined) process.env.SANCTUARY_AGENT_ID = prior;
    }
  });

  it("openChat factory failure: exit 1 with stderr message", async () => {
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", ACTIVE_SESSION.agent_id],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => {
        throw new Error("could not derive master key");
      },
    });
    expect(code).toBe(1);
    expect(bufs.getErr()).toMatch(/failed to open chat service/);
    expect(bufs.getErr()).toMatch(/could not derive master key/);
  });

  it("flat format strips embedded newlines from body for clean parsing", async () => {
    const messy = operatorMessage(
      "msg-1",
      "line one\nline two\rline three",
      "2026-04-30T12:01:00.000Z",
    );
    const { service } = makeStubService({
      session: ACTIVE_SESSION,
      history: [messy],
    });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: [
        "--agent-id",
        ACTIVE_SESSION.agent_id,
        "--format",
        "flat",
        "--quiet",
      ],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    const lines = bufs.getOut().trim().split("\n");
    expect(lines).toHaveLength(1);
    const cols = lines[0]!.split("\t");
    expect(cols).toHaveLength(4);
    expect(cols[3]).toBe("line one line two line three");
  });

  it("cursor scoping: messages with cursor advance only return newer entries", async () => {
    const m1 = operatorMessage("msg-1", "old", "2026-04-30T12:01:00.000Z");
    const m2 = operatorMessage("msg-2", "new", "2026-04-30T12:02:00.000Z");
    const sessionWithCursor: OperatorChatSession = {
      ...ACTIVE_SESSION,
      last_polled_message_id: "msg-1",
    };
    const { service, advanceCalls } = makeStubService({
      session: sessionWithCursor,
      history: [m1, m2],
    });
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--agent-id", ACTIVE_SESSION.agent_id],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => ({ service, close: async () => {} }),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(bufs.getOut().trim());
    expect(parsed.messages).toHaveLength(1);
    expect(parsed.messages[0].message_id).toBe("msg-2");
    expect(advanceCalls).toEqual([
      { sessionId: ACTIVE_SESSION.session_id, lastSeenMessageId: "msg-2" },
    ]);
  });

  it("--help: prints help and exits 0 without opening chat service", async () => {
    let factoryCalled = false;
    const bufs = makeBuffers();
    const code = await runChatPoll({
      argv: ["--help"],
      out: bufs.out,
      err: bufs.err,
      openChat: async () => {
        factoryCalled = true;
        throw new Error("must not be called");
      },
    });
    expect(code).toBe(0);
    expect(factoryCalled).toBe(false);
    expect(bufs.getOut()).toMatch(/sanctuary chat-poll/);
  });
});
