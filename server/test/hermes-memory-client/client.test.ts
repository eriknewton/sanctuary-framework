// Bounded stdio adaptation, settlement, and cancellation contracts.
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { HermesMemoryClient, type ClientPorts } from "../../src/hermes-memory-client/client.js";
import * as P from "../../src/hermes-memory-client/protocol.js";
import { HermesBridgeCore } from "../../src/hermes-memory-bridge/bridge-core.js";
import { parsePublicFrame } from "../../src/hermes-memory-bridge/envelopes.js";
import { HERMES_TOOLS_LIST_PAYLOAD } from "../../src/hermes-memory-bridge/public-results.js";

function fixture(options: { stall?: boolean; short?: boolean; noHello?: boolean; holdPing?: boolean; holdCall?: boolean } = {}) {
  const input = new PassThrough(); const relayInput = new PassThrough();
  const frames: Record<string, any>[] = []; const lines: string[] = [];
  let now = 0; let closed = false;
  let timer: (() => void) | undefined;
  const tasks: (() => void)[] = [];
  const completions: (() => void)[] = [];
  const relayCompletions: (() => void)[] = [];
  const ports: ClientPorts = {
    input, relayInput, stopOutput() {}, connect: ready => ready(), close() { closed = true; }, now: () => now,
    schedule: run => tasks.push(run), timer: run => { timer = run; return 1 as unknown as ReturnType<typeof setTimeout>; }, clearTimer() {},
    relayOutput: { write(bytes, done) {
      const frame = JSON.parse(bytes.subarray(4).toString()); frames.push(frame);
      const complete = () => done(null, options.short && frame.type === "tools_call" ? bytes.length - 1 : bytes.length);
      if ((options.holdPing && frame.type === "ping") || (options.holdCall && frame.type === "tools_call")) relayCompletions.push(complete); else complete();
    } },
    output: { write(bytes, done) {
      const complete = () => { lines.push(bytes.toString()); done(null, bytes.length); };
      if (options.stall) completions.push(complete); else complete();
    } },
  };
  const client = new HermesMemoryClient(ports, "test-version"); void client.run();
  async function pump() {
    // Stream readable notifications run on the next event-loop turn.
    await new Promise<void>(resolve => setImmediate(resolve));
    let turns = 0;
    while (tasks.length) { if (++turns > 1000) throw new Error("fixture exceeded bounded turns"); tasks.shift()!(); }
  }
  const send = async (value: unknown) => { input.write(JSON.stringify(value) + "\n"); await pump(); };
  const raw = async (bytes: string | Buffer) => { input.write(bytes); await pump(); };
  const reply = async (payload: unknown, requestId = frames.filter(f => f.request_id).at(-1)!.request_id) => {
    relayInput.write(P.relayFrame({ type: "result", request_id: requestId, payload })); await pump();
  };
  const relay = async (frame: Record<string, unknown>) => { relayInput.write(P.relayFrame(frame)); await pump(); };
  const initialize = async () => {
    if (!options.noHello) await reply({ protocol_version: P.RELAY_VERSION, server_name: "sanctuary-hermes-memory-bridge" });
    await send({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "fixture", version: "1" } }, id: 0 });
    if (!options.noHello) await send({ jsonrpc: "2.0", method: "notifications/initialized" });
  };
  const call = (id: P.McpId, name = "memory_get", args: unknown = {}) => send({ jsonrpc: "2.0", method: "tools/call", params: { name, arguments: args }, id });
  const cancel = (id: P.McpId) => send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id } });
  const advance = async (ms: number) => { now += ms; timer?.(); await pump(); };
  const stop = async () => { client.signal(); await pump(); await advance(P.SHIM_STDIN_EOF_EXIT_MS); input.destroy(); relayInput.destroy(); };
  const responses = () => lines.map(line => JSON.parse(line));
  return { initialize, send, raw, reply, relay, call, cancel, advance, stop, pump, frames, lines, responses, client,
    options, completions, relayCompletions, input, relayInput, closed: () => closed };
}

describe("memory client contracts", () => {
  it("helloReleasesPrimaryAndHoldsInitialize", async () => {
    const f = fixture({ noHello: true });
    try {
      await f.initialize(); expect(f.lines).toHaveLength(0);
      await f.reply({ protocol_version: P.RELAY_VERSION, server_name: "sanctuary-hermes-memory-bridge" });
      expect(f.responses()[0].id, "helloReleasesPrimaryAndHoldsInitialize").toBe(0);
      await f.send({ jsonrpc: "2.0", method: "notifications/initialized" }); await f.call(1);
      expect(f.frames.at(-1)!.type, "helloReleasesPrimaryAndHoldsInitialize").toBe("tools_call");
    } finally { await f.stop(); }
  });
  it("clientCatalogComesFromRealBridge", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.send({ jsonrpc: "2.0", method: "tools/list", id: 1 });
      expect(f.frames.at(-1)!.type).toBe("tools_list"); await f.reply(HERMES_TOOLS_LIST_PAYLOAD);
      expect(f.responses().at(-1).result.tools.map((t: any) => t.name), "clientCatalogComesFromRealBridge").toEqual(P.TOOL_NAMES);
      expect(f.responses().at(-1).result.tools.every((t: any) => t.inputSchema && !t.input_schema)).toBe(true);
    } finally { await f.stop(); }
  });
  it("clientPreservesFixedDenials", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.call(1);
      await f.relay({ type: "error", request_id: f.frames.at(-1)!.request_id, message: "Memory request denied." });
      expect(f.responses().at(-1).error, "clientPreservesFixedDenials").toEqual({ code: -32002, message: "Memory request denied." });
      await f.call(2); await f.relay({ type: "error", request_id: f.frames.at(-1)!.request_id, message: "private-detail" });
      expect(f.lines.join(""), "clientPreservesFixedDenials").not.toContain("private-detail");
      expect(f.responses().at(-1).error.code).toBe(-32004);
    } finally { await f.stop(); }
  });
  it("clientCannotAddAuthorityFields", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.send({ jsonrpc: "2.0", method: "tools/call", id: 1,
        params: { name: "memory_insert", arguments: { text: "seed", taint: "system_generated" }, _meta: { approved: true }, approved: true } });
      expect(f.frames.at(-1), "clientCannotAddAuthorityFields").toEqual({ type: "tools_call", request_id: expect.any(String), name: "memory_insert", arguments: { text: "seed", taint: "system_generated" } });
    } finally { await f.stop(); }
  });
  it("clientCancelTargetsOriginalCall", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.call(1, "memory_insert"); const wire = f.frames.at(-1)!.request_id;
      await f.call("1"); await f.cancel("1"); await f.cancel(1); await f.cancel(1);
      expect(f.frames.filter(x => x.type === "cancel"), "clientCancelTargetsOriginalCall").toEqual([{ type: "cancel", mcp_request_id: wire }]);
      await f.reply({ content: [] }, wire);
      expect(f.responses().filter(x => x.id === 1), "clientCancelTargetsOriginalCall").toHaveLength(0);
      expect(f.responses().filter(x => x.id === "1")).toHaveLength(1);
    } finally { await f.stop(); }
  });
  it("deadlineSelectsOneWinner", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.call(1, "memory_insert"); const wire = f.frames.at(-1)!.request_id;
      await f.advance(P.SHIM_CALL_DEADLINE_MS); await f.reply({ content: [] }, wire);
      expect(f.responses().filter(x => x.id === 1), "deadlineSelectsOneWinner").toEqual([{ jsonrpc: "2.0", id: 1, error: { code: -32005, message: "Memory request timed out. Outcome unknown." } }]);
      expect(f.frames.filter(x => x.type === "cancel"), "deadlineSelectsOneWinner").toHaveLength(1);
      await f.advance(P.SHIM_CANCEL_SETTLE_MS); expect(f.closed()).toBe(false);
    } finally { await f.stop(); }
  });
  it("expiredPongKeepsFifoPosition", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.call(1); await f.send({ jsonrpc: "2.0", method: "ping", id: 2 });
      await f.advance(P.SHIM_PING_TIMEOUT_MS); expect(f.closed()).toBe(false);
      await f.send({ jsonrpc: "2.0", method: "ping", id: 3 });
      await f.relay({ type: "pong" });
      expect(f.responses().some(x => x.id === 3), "expiredPongKeepsFifoPosition").toBe(false);
      await f.relay({ type: "pong" });
      expect(f.responses().filter(x => x.id === 2), "expiredPongKeepsFifoPosition").toHaveLength(1);
      expect(f.responses().find(x => x.id === 2).error.code).toBe(-32004);
      expect(f.responses().find(x => x.id === 3).result, "expiredPongKeepsFifoPosition").toEqual({});
    } finally { await f.stop(); }
  });
  it("clientBackpressureAndMapsStayBounded", async () => {
    const f = fixture(); try {
      await f.initialize(); f.options.stall = true;
      await f.call(1); await f.send({ jsonrpc: "2.0", method: "ping", id: 2 });
      await f.send({ jsonrpc: "2.0", method: "ping", id: 3 }); await f.call(4); await f.call(5);
      const retained = f.client as unknown as { records: Map<string, unknown>; outputs: unknown[]; pings: unknown[]; pendingControl: unknown[] };
      expect(retained.records.size, "clientBackpressureAndMapsStayBounded").toBeLessThanOrEqual(5);
      expect(retained.outputs.length, "clientBackpressureAndMapsStayBounded").toBeLessThanOrEqual(5);
      expect(retained.pings.length).toBeLessThanOrEqual(2);
      expect(retained.pendingControl.length).toBeLessThanOrEqual(10);
      expect(f.frames.filter(x => x.type === "tools_call"), "clientBackpressureAndMapsStayBounded").toHaveLength(1);
      await f.advance(P.SHIM_DISCONNECT_TIMEOUT_MS);
      expect(f.closed(), "clientBackpressureAndMapsStayBounded").toBe(true);
      expect(f.completions.length).toBeLessThanOrEqual(1);
    } finally { await f.stop(); }
  });
  it("oversizeAndDepthRecoverIdLast", async () => {
    const f = fixture(); try {
      await f.initialize();
      await f.raw(JSON.stringify({ jsonrpc: "2.0", method: "tools/call", params: { name: "memory_get", arguments: { text: "x".repeat(P.MAX_STDIO_LINE_BYTES) } }, id: 1 }) + "\n");
      await f.raw('{"jsonrpc":"2.0","method":"tools/call","params":{"name":"memory_get","arguments":{"x":' + "[".repeat(70) + "0" + "]".repeat(70) + '}},"id":2}\n');
      expect(f.responses().filter(x => x.id !== 0).map(x => [x.id, x.error.code]), "oversizeAndDepthRecoverIdLast").toEqual([[1, -32602], [2, -32602]]);
      expect(f.closed()).toBe(false); expect(f.frames.filter(x => x.type === "tools_call")).toHaveLength(0);
    } finally { await f.stop(); }
  });
  it("bufferedUnreadIdsDrainBeforeClose", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.call(1, "memory_insert");
      await f.raw('bad\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"memory_get"},"id":2}\n{"jsonrpc":"2.0","method":"ping","id":3}\n');
      expect(f.responses().map(x => x.id), "bufferedUnreadIdsDrainBeforeClose").toEqual([0, null, 1, 2, 3]);
      expect(f.closed()).toBe(true);
    } finally { await f.stop(); }
  });
  it("shortWriteNeverReplaysOrCancels", async () => {
    const f = fixture({ short: true }); try {
      await f.initialize(); await f.call(1, "memory_insert");
      expect(f.responses().at(-1)?.error?.message, "shortWriteNeverReplaysOrCancels").toBe("Memory service unavailable. Outcome unknown.");
      expect(f.frames.filter(x => x.type === "tools_call")).toHaveLength(1);
      expect(f.frames.filter(x => x.type === "cancel"), "shortWriteNeverReplaysOrCancels").toHaveLength(0);
    } finally { await f.stop(); }
  });
  it("eofAndSignalProduceNoNewStdout", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.call(1, "memory_insert"); const before = f.lines.length;
      f.client.signal(); await f.pump();
      expect(f.lines.length, "eofAndSignalProduceNoNewStdout").toBe(before);
      expect(f.frames.slice(-2).map(x => x.type)).toEqual(["cancel", "shutdown"]);
      expect(f.closed()).toBe(true);
    } finally { await f.stop(); }
  });
  it("unavailableInsertIsNonterminalUnknownOutcome", async () => {
    const f = fixture(); try {
      await f.initialize(); await f.call(1, "memory_insert");
      await f.relay({ type: "error", request_id: f.frames.at(-1)!.request_id, message: "Memory service unavailable." });
      expect(f.responses().at(-1).error, "unavailableInsertIsNonterminalUnknownOutcome").toEqual({ code: -32004, message: "Memory service unavailable. Outcome unknown." });
      await f.call(2); expect(f.frames.at(-1)!.type).toBe("tools_call");
    } finally { await f.stop(); }
  });
  it("controlCreditsAreNeverGuessedFree", async () => {
    const f = fixture(); try {
      await f.initialize();
      for (let id = 1; id <= P.CONTROL_CAP; id++) {
        await f.call(id); const wire = f.frames.at(-1)!.request_id; await f.cancel(id);
        if (!f.closed()) await f.reply({ content: [] }, wire);
      }
      const controls = f.frames.filter(x => x.type === "cancel" || x.type === "shutdown");
      expect(controls.length, "controlCreditsAreNeverGuessedFree").toBe(8);
      expect(controls.at(-1)!.type).toBe("shutdown"); expect(f.closed()).toBe(true);
    } finally { await f.stop(); }
  });
  it("fixedErrorsCannotEnterHermesRetryClassifier", () => {
    const phrases = ["invalid or expired session", "expired session", "session expired", "session not found", "unknown session", "session terminated", "closedresourceerror", "closed resource", "transport is closed", "connection closed", "broken pipe", "end of file"];
    for (const [code, message] of Object.values(P.ERRORS)) {
      expect([-32000, -32001], "fixedErrorsCannotEnterHermesRetryClassifier").not.toContain(code);
      expect(phrases.some(phrase => message.toLowerCase().includes(phrase)), "fixedErrorsCannotEnterHermesRetryClassifier").toBe(false);
    }
  });
  it("callPayloadSpliceIsByteExact", () => {
    const payload = Buffer.from('{ "content" : [{"type":"text","text":"\\u0061"}], "structuredContent": {"a":1e0} }');
    P.validateCallResult(payload);
    expect(P.resultLine(0, payload).subarray('{"jsonrpc":"2.0","id":0,"result":'.length, -2).equals(payload), "callPayloadSpliceIsByteExact").toBe(true);
    expect(P.MCP_ENVELOPE_BYTES).toBe(163); expect(P.MAX_STDIO_LINE_BYTES).toBe(65701);
  });
});

it("clientShutdownCancelsOnlyItsConnection", async () => {
  const first = fixture(); const second = fixture();
  try {
    await first.initialize(); await second.initialize(); await first.call(1); await second.call(1);
    first.client.signal(); await first.pump();
    expect(first.frames.slice(-2).map(frame => frame.type), "clientShutdownCancelsOnlyItsConnection").toEqual(["cancel", "shutdown"]);
    await second.reply({ content: [] });
    expect(second.responses().at(-1).result, "clientShutdownCancelsOnlyItsConnection").toEqual({ content: [] });
    expect(second.closed()).toBe(false);
  } finally { await first.stop(); await second.stop(); }
});
it("forwardedDepthAndArgumentShapeRefuseLocally", async () => {
  const f = fixture(); try {
    await f.initialize();
    for (const [index, value] of [null, [], "bad", 0].entries()) await f.call(index + 1, "memory_get", value);
    let nested: unknown = 0;
    for (let i = 0; i < 64; i++) nested = [nested];
    await f.call(5, "memory_get", { x: nested });
    expect(() => P.relayFrame({ type: "tools_call", request_id: "r1", name: "memory_get", arguments: { x: nested } }), "forwardedDepthAndArgumentShapeRefuseLocally").toThrow();
    expect(f.responses().slice(1).map(row => row.error.code), "forwardedDepthAndArgumentShapeRefuseLocally").toEqual(Array(5).fill(-32602));
    expect(f.frames.filter(frame => frame.type === "tools_call"), "forwardedDepthAndArgumentShapeRefuseLocally").toHaveLength(0);
  } finally { await f.stop(); }
});
it("invalidCatalogNeverProducesSuccess", async () => {
  for (const payload of [{ tools: [] }, { ...HERMES_TOOLS_LIST_PAYLOAD, nextCursor: "next" },
    { tools: [...HERMES_TOOLS_LIST_PAYLOAD.tools, { name: "extra", input_schema: {} }] }]) {
    const f = fixture(); try {
      await f.initialize(); await f.send({ jsonrpc: "2.0", method: "tools/list", id: 1 }); await f.reply(payload);
      expect(f.responses().at(-1).error.code, "invalidCatalogNeverProducesSuccess").toBe(-32004);
    } finally { await f.stop(); }
  }
});
it("initializeOutputAndHeldPingRemainBounded", async () => {
  const f = fixture({ noHello: true }); try {
    await f.send({ jsonrpc: "2.0", method: "ping", id: 1 });
    expect(f.frames.map(x => x.type)).toEqual(["hello"]);
    await f.initialize(); f.options.stall = true;
    await f.reply({ protocol_version: P.RELAY_VERSION, server_name: "sanctuary-hermes-memory-bridge" });
    expect(f.frames.at(-1)!.type, "initializeOutputAndHeldPingRemainBounded").toBe("ping");
    await f.advance(P.SHIM_WRITE_STALL_MS); await f.advance(P.SHIM_DISCONNECT_TIMEOUT_MS);
    expect(f.closed(), "initializeOutputAndHeldPingRemainBounded").toBe(true);
  } finally { await f.stop(); }
});
it("settlementExpiryClosesAndLateSuccessCannotRevive", async () => {
  const f = fixture(); try {
    await f.initialize(); await f.call(1); await f.cancel(1);
    await f.advance(P.SHIM_CANCEL_SETTLE_MS);
    expect(f.closed(), "settlementExpiryClosesAndLateSuccessCannotRevive").toBe(true);
    expect(f.responses().filter(x => x.id === 1)).toHaveLength(0);
  } finally { await f.stop(); }
});
it("socketLossDrainsEveryOutstandingTypedId", async () => {
  const f = fixture(); try {
    await f.initialize(); await f.call(1, "memory_insert");
    await f.send({ jsonrpc: "2.0", method: "ping", id: "1" });
    f.relayInput.emit("end"); await f.pump();
    expect(f.responses().slice(1).map(row => [row.id, row.error.code]), "socketLossDrainsEveryOutstandingTypedId").toEqual([[1, -32004], ["1", -32004]]);
    expect(f.responses()[1].error.message).toContain("Outcome unknown.");
  } finally { await f.stop(); }
});
it("utf8DuplicatesAndSurrogatesCannotBecomeCalls", async () => {
  for (const bytes of [Buffer.from([255, 10]), Buffer.from('{"id":1,"id":2}\n'), Buffer.from('{"x":"\\ud800"}\n')]) {
    const f = fixture(); try {
      await f.initialize(); await f.call(1); await f.raw(bytes);
      expect(f.responses().at(-1).error.code, "utf8DuplicatesAndSurrogatesCannotBecomeCalls").toBe(-32004);
      expect(f.frames.filter(x => x.type === "tools_call")).toHaveLength(1);
    } finally { await f.stop(); }
  }
});
it("callOutputUsesRemainingHermesWait", async () => {
  const f = fixture(); try {
    await f.initialize(); await f.call(1); f.options.stall = true; await f.reply({ content: [] });
    await f.advance(2001);
    expect(f.frames.some(frame => frame.type === "shutdown"), "callOutputUsesRemainingHermesWait").toBe(false);
    expect(f.closed(), "callOutputUsesRemainingHermesWait").toBe(false);
    await f.advance(120000);
    await f.advance(P.SHIM_DISCONNECT_TIMEOUT_MS);
    expect(f.closed(), "callOutputUsesRemainingHermesWait").toBe(true);
  } finally { await f.stop(); }
});
it("initializationWaitingStateHasDeadline", async () => {
  const f = fixture(); try {
    await f.reply({ protocol_version: P.RELAY_VERSION, server_name: "sanctuary-hermes-memory-bridge" });
    await f.advance(5000);
    expect(f.closed(), "initializationWaitingStateHasDeadline").toBe(true);
    expect(P.SHIM_CALL_DEADLINE_MS, "initializationWaitingStateHasDeadline").toBe(118000);
  } finally { await f.stop(); }
});
it("thirdPingDoesNotGrowFifo", async () => {
  const f = fixture(); try {
    await f.initialize();
    for (const id of [1, 2, 3]) await f.send({ jsonrpc: "2.0", method: "ping", id });
    expect(f.frames.filter(x => x.type === "ping"), "thirdPingDoesNotGrowFifo").toHaveLength(2);
    expect(f.responses().find(x => x.id === 3)?.error?.code, "thirdPingDoesNotGrowFifo").toBe(-32003);
  } finally { await f.stop(); }
});
it("cancelKeepsPrimaryUntilWireRetires", async () => {
  const f = fixture(); try {
    await f.initialize(); await f.call(1); const wire = f.frames.at(-1)!.request_id;
    await f.cancel(1); await f.call(2);
    expect(f.frames.filter(x => x.type === "tools_call"), "cancelKeepsPrimaryUntilWireRetires").toHaveLength(1);
    expect(f.responses().find(x => x.id === 2)?.error?.code).toBe(-32003);
    await f.reply({ content: [] }, wire); await f.call(3);
    expect(f.frames.filter(x => x.type === "tools_call")).toHaveLength(2);
  } finally { await f.stop(); }
});
it("repeatedAdmissionRetiresAllBuffersAndRecords", async () => {
  const f = fixture(); try {
    await f.initialize();
    for (let wave = 0; wave < 32; wave++) {
      await f.call(wave + 1); await f.reply({ content: [] });
      await f.send({ jsonrpc: "2.0", method: "ping", id: `ping${wave}` }); await f.relay({ type: "pong" });
      const retained = f.client as unknown as { records: Map<string, unknown>; outputs: unknown[]; pings: unknown[]; inputTail: Buffer; socketTail: Buffer };
      expect([retained.records.size, retained.outputs.length, retained.pings.length, retained.inputTail.length, retained.socketTail.length], "repeatedAdmissionRetiresAllBuffersAndRecords").toEqual([0, 0, 0, 0, 0]);
    }
  } finally { await f.stop(); }
});


it("callerCannotSelectEffectiveTaint", async () => {
  const f = fixture(); const taints: string[] = [];
  const core = new HermesBridgeCore({
    writeFrame() {}, appendAudit: async () => {}, nowMs: () => 0,
    setTimer: () => ({}), clearTimer() {}, abort: new AbortController(),
    agentId: "fixture-agent",
    adapter: {
      recallPassages: async budget => budget.result(),
      async insertPassage(_input, taint) {
        // The fixture observes the consumer argument and refuses before any storage effect.
        taints.push(taint); throw new Error("fixture storage unavailable");
      },
      async getPassage() { return null; }, async searchPassages() { return []; },
    },
  });
  try {
    await f.initialize(); await f.call(1, "memory_insert", { text: "fixture", taint: "system_generated" });
    const publicBytes = Buffer.from(JSON.stringify(f.frames.at(-1)));
    core.relayFrame({ kind: "accepted", connectionId: "fixture" });
    core.relayFrame({ kind: "frame", connectionId: "fixture", publicBytes, publicFrame: parsePublicFrame(publicBytes) });
    await f.pump();
    expect(taints, "callerCannotSelectEffectiveTaint").toEqual(["user_content"]);
  } finally { core.relayEof(); await f.stop(); }
});


it("callWaitsForInProgressPingWrite", async () => {
  const f = fixture();
  try {
    await f.initialize(); f.options.holdPing = true;
    await f.send({ jsonrpc: "2.0", method: "ping", id: 2 });
    await f.call(1);
    expect(f.frames.some(frame => frame.type === "tools_call")).toBe(false);
    f.relayCompletions.shift()!(); await f.pump();
    expect(f.frames.at(-1)!.type, "callWaitsForInProgressPingWrite").toBe("tools_call");
    await f.reply({ content: [] }); await f.relay({ type: "pong" });
    expect(f.responses().filter(row => row.id === 1), "callWaitsForInProgressPingWrite")
      .toEqual([{ jsonrpc: "2.0", id: 1, result: { content: [] } }]);
    expect(f.closed()).toBe(false);
  } finally { await f.stop(); }
});

it("unwrittenPrimaryRetiresWithoutRelayCancel", async () => {
  for (const disposition of ["cancel", "deadline"] as const) {
    const f = fixture();
    try {
      await f.initialize(); f.options.holdPing = true;
      await f.send({ jsonrpc: "2.0", method: "ping", id: 2 }); await f.call(1);
      const retained = f.client as unknown as { pendingPrimary?: { frame: Buffer } };
      expect(retained.pendingPrimary!.frame.length).toBeLessThanOrEqual(P.MAX_SOCKET_TAIL_BYTES);
      if (disposition === "cancel") await f.cancel(1); else await f.advance(P.SHIM_CALL_DEADLINE_MS);
      expect(retained.pendingPrimary, "unwrittenPrimaryRetiresWithoutRelayCancel").toBeUndefined();
      expect(f.frames.filter(frame => frame.type === "cancel" || frame.type === "tools_call")).toHaveLength(0);
      await f.call(3); f.relayCompletions.shift()!(); await f.pump();
      expect(f.frames.filter(frame => frame.type === "tools_call"), "unwrittenPrimaryRetiresWithoutRelayCancel").toHaveLength(1);
      await f.reply({ content: [] });
      expect(f.responses().filter(row => row.id === 1)).toHaveLength(disposition === "cancel" ? 0 : 1);
      expect(f.responses().find(row => row.id === 3).result).toEqual({ content: [] });
    } finally { await f.stop(); }
  }
});

it("signalDiscardsUnwrittenPrimary", async () => {
  const f = fixture();
  try {
    await f.initialize(); f.options.holdPing = true;
    await f.send({ jsonrpc: "2.0", method: "ping", id: 2 }); await f.call(1);
    f.client.signal(); f.relayCompletions.shift()!(); await f.pump();
    expect(f.frames.filter(frame => frame.type === "tools_call" || frame.type === "cancel"), "signalDiscardsUnwrittenPrimary").toHaveLength(0);
    expect(f.frames.at(-1)!.type).toBe("shutdown");
    expect(f.responses().map(row => row.id)).toEqual([0]); expect(f.closed()).toBe(true);
  } finally { await f.stop(); }
});

it("drainDuringCallWriteOrdersCancelBeforeShutdown", async () => {
  const f = fixture({ holdCall: true }); try {
    await f.initialize(); await f.call(1);
    f.client.signal(); await f.pump();
    f.relayCompletions.shift()!(); await f.pump();
    expect(f.frames.slice(-2).map(frame => frame.type), "drainDuringCallWriteOrdersCancelBeforeShutdown").toEqual(["cancel", "shutdown"]);
  } finally { await f.stop(); }
});
it("deadlineDuringCallWriteArmsSettlement", async () => {
  const f = fixture({ holdCall: true }); try {
    await f.initialize(); await f.call(1); await f.advance(P.SHIM_CALL_DEADLINE_MS);
    f.relayCompletions.shift()!(); await f.pump();
    expect(f.frames.filter(frame => frame.type === "cancel"), "deadlineDuringCallWriteArmsSettlement").toHaveLength(1);
    await f.advance(P.SHIM_CANCEL_SETTLE_MS);
    expect(f.closed(), "deadlineDuringCallWriteArmsSettlement").toBe(true);
  } finally { await f.stop(); }
});
it("drainErrorsBelongToTheirOwnRequest", async () => {
  for (const kind of ["memory_get", "memory_search", "memory_insert", "list"]) {
    for (const trigger of ["parse", "invalid", "pong", "frame", "input", "internal"]) {
      const f = fixture(); try {
        await f.initialize();
        if (kind === "list") await f.send({ jsonrpc: "2.0", method: "tools/list", id: 1 }); else await f.call(1, kind);
        await f.send({ jsonrpc: "2.0", method: "ping", id: 2 });
        if (trigger === "parse") await f.raw('{"id":3,"broken":}\n');
        if (trigger === "invalid") await f.send({ jsonrpc: "wrong", method: "ping", id: 3 });
        if (trigger === "pong") { await f.relay({ type: "pong" }); await f.relay({ type: "pong" }); }
        if (trigger === "frame") await f.relay({ type: "invalid" });
        if (trigger === "input") { f.input.emit("error", new Error("fixture")); await f.pump(); }
        if (trigger === "internal") { f.client.internalFailure(); await f.pump(); }
        const call = f.responses().find(row => row.id === 1);
        expect(call?.error, "drainErrorsBelongToTheirOwnRequest").toEqual({ code: -32004,
          message: kind === "memory_insert" ? "Memory service unavailable. Outcome unknown." : "Memory service unavailable." });
        if (trigger !== "pong") expect(f.responses().find(row => row.id === 2)?.error.code, "drainErrorsBelongToTheirOwnRequest").toBe(-32004);
        if (["parse", "invalid"].includes(trigger)) expect(f.responses().find(row => row.id === 3)?.error.code, "drainErrorsBelongToTheirOwnRequest").toBe(trigger === "parse" ? -32700 : -32600);
      } finally { await f.stop(); }
    }
  }
});
it("truncatedNumericIdIsNeverRecovered", async () => {
  const scanner = new P.IdScanner();
  for (const byte of Buffer.from('{"id":1.' + "0".repeat(800) + '5}')) scanner.feed(byte);
  expect(scanner.id, "truncatedNumericIdIsNeverRecovered").toBeUndefined();
});

it("unsendableControlsDoNotDelayDrain", async () => {
  for (const loss of ["socket", "write"]) {
    const f = fixture({ holdCall: true, short: loss === "write" }); try {
      await f.initialize(); await f.call(1); await f.send({ jsonrpc: "2.0", method: "ping", id: 2 });
      if (loss === "socket") f.relayInput.emit("end"); else f.relayCompletions.shift()!();
      await f.pump();
      expect(f.closed(), "unsendableControlsDoNotDelayDrain").toBe(true);
      expect(f.responses().find(row => row.id === 1)?.error.message, "unsendableControlsDoNotDelayDrain").toBe("Memory service unavailable. Outcome unknown.");
    } finally { await f.stop(); }
  }
});
it("oversizeTruncatedIdGetsOnlyNoIdDiagnostic", async () => {
  const f = fixture(); try {
    await f.initialize(); await f.call(1, "memory_insert");
    await f.raw('{"padding":"' + "x".repeat(P.MAX_STDIO_LINE_BYTES) + '","id":1.' + "0".repeat(800) + '5}\n');
    expect(f.responses().filter(row => row.id === null).map(row => row.error.code), "oversizeTruncatedIdGetsOnlyNoIdDiagnostic").toEqual([-32600]);
    expect(f.responses().filter(row => row.id === 1).map(row => row.error.code), "oversizeTruncatedIdGetsOnlyNoIdDiagnostic").toEqual([-32004]);
  } finally { await f.stop(); }
});

it("unfinishedCallWriteHasBoundedSettlement", async () => {
  const f = fixture({ holdCall: true }); try {
    await f.initialize(); await f.call(1); await f.advance(P.SHIM_CALL_DEADLINE_MS);
    await f.advance(P.SHIM_CANCEL_SETTLE_MS); await f.advance(P.SHIM_DISCONNECT_TIMEOUT_MS);
    expect(f.closed(), "unfinishedCallWriteHasBoundedSettlement").toBe(true);
    expect(f.frames.filter(frame => frame.type === "cancel"), "unfinishedCallWriteHasBoundedSettlement").toHaveLength(0);
  } finally { await f.stop(); }
});
