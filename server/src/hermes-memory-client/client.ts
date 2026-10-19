import { randomBytes } from "node:crypto";
import type { Readable } from "node:stream";
import * as P from "./protocol.js";

type State = "CONNECTING" | "HELD_INITIALIZE" | "AWAIT_INITIALIZE" | "INITIALIZE_OUTPUT" | "AWAIT_INITIALIZED" | "READY" | "STALLED" | "DRAINING" | "CLOSED";
type RecordKind = "hello" | "initialize" | "call" | "list" | "ping" | "local";
type RecordEntry = {
  id?: P.McpId; wire?: string; kind: RecordKind; insert: boolean; wanted: boolean; settled: boolean;
  sent: boolean; cancelSent: boolean; wireDone: boolean; outputDone: boolean; line?: Buffer;
  admitted: number; deadline?: number; settleDeadline?: number; outputDeadline?: number;
};
/** A sink reports the actual accepted byte count, including a short native write. */
export interface ByteSink { write(bytes: Buffer, done: (error: Error | null, written: number) => void): void }
/** Required ports isolate native I/O from settlement while retaining one event loop. */
export interface ClientPorts {
  input: Readable;
  relayInput: Readable;
  relayOutput: ByteSink;
  output: ByteSink;
  connect: (ready: () => void, failed: () => void) => void;
  close: () => void;
  now: () => number;
  schedule: (run: () => void) => void;
  timer: (run: () => void, delay: number) => ReturnType<typeof setTimeout>;
  clearTimer: (timer: ReturnType<typeof setTimeout>) => void;
}

/** Fixed memory facade with bounded admission and no authority or boot dependency. */
export class HermesMemoryClient {
  private state: State = "CONNECTING";
  private savedState: State = "CONNECTING";
  private primary?: RecordEntry;
  private initialization?: { record: RecordEntry; payload: Buffer };
  private readonly records = new Map<string, RecordEntry>();
  private readonly pings: RecordEntry[] = [];
  private readonly outputs: RecordEntry[] = [];
  private readonly lineReader = new P.LineReader();
  private inputTail: Buffer = Buffer.alloc(0);
  private inputOffset = 0;
  private socketTail: Buffer = Buffer.alloc(0);
  private connected = false;
  private helloReady = false;
  private controlCount = 0;
  private shutdownSent = false;
  private relayWriting = false;
  private pendingControl: Buffer[] = [];
  private outputWriting = false;
  private outputOffset = 0;
  private silent = false;
  private scheduled = false;
  private timerHandle?: ReturnType<typeof setTimeout>;
  private connectDeadline: number;
  private initializationDeadline: number;
  private drainDeadline?: number;
  private drainKind: P.ErrorKind = "unavailable";
  private drainReadRemaining = P.MAX_STDIO_LINE_BYTES;
  private serial = 0n;
  private readonly wirePrefix = "r" + randomBytes(16).toString("hex") + "."; // 16 bytes = 128 bits, encoded as 32 hex characters.
  private resolve!: (code: number) => void;
  private readonly completion: Promise<number>;

  constructor(private readonly ports: ClientPorts, private readonly version: string) {
    // Startup refuses absent ports so no optional dependency can disable settlement or output bounds.
    if (Object.values(ports).some(port => port == null) || !version) throw new Error("missing client port");
    this.connectDeadline = ports.now() + P.SHIM_CONNECT_HELLO_TIMEOUT_MS;
    this.initializationDeadline = ports.now() + P.SHIM_INITIALIZATION_TIMEOUT_MS;
    this.completion = new Promise(resolve => { this.resolve = resolve; });
  }
  run(): Promise<number> {
    this.ports.input.on("readable", this.wake);
    this.ports.input.on("end", this.onEof);
    this.ports.input.on("error", this.onInputError);
    this.ports.relayInput.on("readable", this.wake);
    this.ports.relayInput.on("end", this.onSocketLoss);
    this.ports.relayInput.on("error", this.onSocketLoss);
    this.ports.relayInput.on("close", this.onSocketLoss);
    this.primary = this.record("hello");
    this.primary.wire = this.nextWire();
    this.ports.connect(() => this.state_CONNECTING(), this.onSocketLoss);
    this.wake();
    return this.completion;
  }
  private state_CONNECTING(): void {
      if (this.state === "CLOSED") return;
      this.connected = true;
      if (this.state === "DRAINING") { this.shutdown(); this.wake(); return; }
      this.sendPrimary({ type: "hello", request_id: this.primary!.wire,
        protocol_version: P.RELAY_VERSION, client_name: P.CLIENT_NAME });
  }
  private state_HELD_INITIALIZE(): void { this.transition("HELD_INITIALIZE"); }
  private state_AWAIT_INITIALIZE(): void { this.transition("AWAIT_INITIALIZE"); }
  private state_AWAIT_INITIALIZED(): void { this.transition("AWAIT_INITIALIZED"); }
  private state_STALLED(): void {
    this.savedState = this.state; this.state = "STALLED";
  }
  readonly signal = (): void => { this.state_DRAINING("unavailable", true); };
  readonly internalFailure = (): void => { this.state_DRAINING("internal"); };
  private readonly onEof = (): void => { this.state_DRAINING("unavailable", true); };
  private readonly onInputError = (): void => { this.state_DRAINING("parse"); };
  private readonly onSocketLoss = (): void => {
    this.connected = false;
    if (this.primary) this.primary.wireDone = true;
    this.state_DRAINING("unavailable");
  };
  private readonly wake = (): void => {
    if (this.scheduled || this.state === "CLOSED") return;
    this.scheduled = true;
    this.ports.schedule(() => {
      this.scheduled = false;
      try { this.turn(); } catch { this.state_DRAINING("internal"); }
    });
  };
  private transition(state: State): void {
    if (this.state === "STALLED") this.savedState = state; else this.state = state;
    if (["HELD_INITIALIZE", "AWAIT_INITIALIZE", "INITIALIZE_OUTPUT", "AWAIT_INITIALIZED"].includes(state)) {
      this.initializationDeadline = this.ports.now() + P.SHIM_INITIALIZATION_TIMEOUT_MS;
    }
  }
  private current(): State { return this.state === "STALLED" ? this.savedState : this.state; }
  private record(kind: RecordKind, id?: P.McpId): RecordEntry {
    return { kind, id, insert: false, wanted: true, settled: false, sent: false, cancelSent: false,
      wireDone: kind !== "hello" && kind !== "list" && kind !== "call" && kind !== "ping", outputDone: false,
      admitted: this.ports.now() };
  }
  private nextWire(): string {
    // UInt64 exhaustion closes the connection; identity never wraps or aliases a previous request.
    if (this.serial === (1n << 64n) - 1n) throw new Error("wire capacity");
    return this.wirePrefix + (++this.serial).toString();
  }
  private turn(): void {
    if (this.state === "CLOSED") return;
    this.checkDeadlines();
    if (this.state as State === "CLOSED") return;
    this.readRelay();
    this.readInput();
    this.flushOutput();
    this.flushControl();
    this.retire();
    if (this.current() === "DRAINING" && !this.outputWriting && this.outputs.length === 0
      && this.inputOffset === this.inputTail.length && (this.silent || this.ports.input.readableLength === 0 || this.drainReadRemaining === 0)
      && !this.relayWriting && this.pendingControl.length === 0) this.state_CLOSED();
    this.armTimer();
  }
  private readInput(): void {
    if (this.silent || this.state === "CLOSED") return;
    // During drain, one terminal slot is reused only after delivery; buffered IDs remain readable.
    if (this.current() === "DRAINING" && this.outputs.length > 0) return;
    if (this.inputOffset >= this.inputTail.length) {
      const maximum = this.current() === "DRAINING" ? this.drainReadRemaining : P.MAX_STDIO_LINE_BYTES;
      const available = Math.min(maximum, this.ports.input.readableLength);
      if (available === 0) return;
      const bytes = this.ports.input.read(available) as Buffer | null;
      if (!bytes) return;
      this.inputTail = bytes; this.inputOffset = 0;
      if (this.current() === "DRAINING") this.drainReadRemaining -= bytes.length;
    }
    while (this.inputOffset < this.inputTail.length) {
      const line = this.lineReader.take(this.inputTail[this.inputOffset++]);
      if (line) { this.handleLine(line); break; }
    }
    if (this.inputOffset === this.inputTail.length) { this.inputTail = Buffer.alloc(0); this.inputOffset = 0; }
    // One complete line per turn leaves timers and relay reads runnable during coalesced input.
    if (this.inputTail.length || this.ports.input.readableLength) this.wake();
  }
  private handleLine(line: P.InputLine): void {
    if (line.oversize) { this.rejectedBound(line.recovered); return; }
    if (line.bytes.length > P.MAX_STDIO_JSON_BYTES && line.bytes.at(-1) !== 13) { this.rejectedBound(line.recovered); return; }
    let request: Record<string, unknown>;
    try { request = P.parseStrictJsonObject(line.bytes, P.STDIO_DEPTH); }
    catch (error) {
      if (error instanceof P.StrictJsonError && error.code === "depth_exceeded") this.rejectedBound(line.recovered);
      else this.state_DRAINING(error instanceof P.StrictJsonError && error.code === "top_level_not_object" ? "invalid" : "parse");
      return;
    }
    const id = request.id;
    if (this.current() === "DRAINING") {
      if (P.validId(id) && !this.records.has(P.idKey(id))) this.local(id, this.drainKind, true);
      return;
    }
    if (request.jsonrpc !== "2.0" || typeof request.method !== "string" || ("id" in request && !P.validId(id))) {
      if (P.validId(id) && !this.records.has(P.idKey(id))) this.local(id, "invalid", true);
      this.state_DRAINING("invalid"); return;
    }
    if (P.validId(id) && this.records.has(P.idKey(id))) { this.state_DRAINING("invalid"); return; }
    if (!("id" in request)) { this.notification(request); return; }
    if (!P.validId(id)) { this.state_DRAINING("invalid"); return; }
    if (request.method === "initialize") { this.state_INITIALIZE(request, id); return; }
    if (request.method === "ping") { this.ping(id); return; }
    if (this.current() !== "READY") { this.local(id, "invalid", true); this.state_DRAINING("invalid"); return; }
    this.state_READY(request, id);
  }
  private rejectedBound(id: P.McpId | undefined): void {
    if (id === undefined) { this.state_DRAINING("invalid"); return; }
    if (this.records.has(P.idKey(id))) { this.state_DRAINING("invalid"); return; }
    this.local(id, this.current() === "DRAINING" ? this.drainKind : "params", this.current() === "DRAINING");
  }
  private state_INITIALIZE(request: Record<string, unknown>, id: P.McpId): void {
    if (!["CONNECTING", "AWAIT_INITIALIZE"].includes(this.current()) || this.initialization) {
      this.local(id, "invalid", true); this.state_DRAINING("invalid"); return;
    }
    let payload: Buffer;
    try { payload = P.initializeResult(request, this.version); } catch { this.local(id, "params"); return; }
    const record = this.record("initialize", id);
    this.records.set(P.idKey(id), record);
    this.initialization = { record, payload }; // Dedicated initialization output slot, retired after delivery.
    if (!this.helloReady) this.state_HELD_INITIALIZE(); else this.state_INITIALIZE_OUTPUT();
  }
  private state_INITIALIZE_OUTPUT(): void {
    const held = this.initialization!;
    this.transition("INITIALIZE_OUTPUT");
    this.select(held.record, P.resultLine(held.record.id!, held.payload));
  }
  private notification(request: Record<string, unknown>): void {
    if (request.method === "notifications/initialized") {
      if (this.current() !== "AWAIT_INITIALIZED") { this.state_DRAINING("invalid"); return; }
      this.transition("READY"); return;
    }
    if (request.method !== "notifications/cancelled") return;
    if (!P.isRecord(request.params) || !P.validId(request.params.requestId)) { this.state_DRAINING("invalid"); return; }
    const record = this.records.get(P.idKey(request.params.requestId));
    if (!record) return;
    if (record.kind === "initialize") { this.state_DRAINING("invalid"); return; }
    if (record.settled) return;
    record.wanted = false; record.outputDone = true;
    if (record.kind === "call" || record.kind === "list") this.cancel(record);
    this.retire();
  }
  private state_READY(request: Record<string, unknown>, id: P.McpId): void {
    if (request.method !== "tools/list" && request.method !== "tools/call") { this.local(id, "method"); return; }
    let params: ReturnType<typeof P.callParams> | undefined;
    try {
      if (request.method === "tools/list") {
        if (request.params !== undefined && (!P.isRecord(request.params) || "cursor" in request.params)) throw new Error("params");
      } else params = P.callParams(request);
    } catch { this.local(id, "params"); return; }
    if (params && !P.TOOL_NAMES.some(name => name === params!.name)) { this.local(id, "denied"); return; }
    if (this.primary) { this.local(id, "busy"); return; }
    const record = this.record(params ? "call" : "list", id);
    record.insert = params?.name === "memory_insert";
    record.wire = this.nextWire();
    record.deadline = record.admitted + P.SHIM_CALL_DEADLINE_MS;
    let frame: Buffer;
    try { frame = P.relayFrame(params ? { type: "tools_call", request_id: record.wire, ...params }
      : { type: "tools_list", request_id: record.wire }); }
    catch { this.local(id, "params"); return; }
    this.primary = record; this.records.set(P.idKey(id), record);
    this.writePrimary(record, frame);
  }
  private local(id: P.McpId, kind: P.ErrorKind, terminal = false): void {
    const locals = [...this.records.values()].filter(record => record.kind === "local").length;
    if (locals >= (terminal ? 2 : 1)) {
      if (!terminal && locals === 1) { this.local(id, "unavailable", true); this.state_DRAINING("unavailable"); }
      else this.state_DRAINING("unavailable");
      return;
    }
    const record = this.record("local", id); this.records.set(P.idKey(id), record);
    this.select(record, P.errorLine(id, kind));
  }
  private ping(id: P.McpId): void {
    if (this.pings.length >= P.PING_CAP) { this.local(id, "busy"); return; }
    const record = this.record("ping", id); record.deadline = record.admitted + P.SHIM_PING_TIMEOUT_MS;
    this.pings.push(record); this.records.set(P.idKey(id), record);
    if (this.helloReady) this.sendPing(record);
  }
  private sendPing(record: RecordEntry): void {
    if (record.sent) return;
    record.sent = true;
    this.queueControl(P.relayFrame({ type: "ping" }), false);
  }
  private sendPrimary(frame: Record<string, unknown>): void { this.writePrimary(this.primary!, P.relayFrame(frame)); }
  private writePrimary(record: RecordEntry, frame: Buffer): void {
    if (!this.connected || this.relayWriting) { this.state_DRAINING("unavailable"); return; }
    this.relayWriting = true;
    this.ports.relayOutput.write(frame, (error, written) => {
      this.relayWriting = false;
      if (this.state === "CLOSED") return;
      if (error || written !== frame.length) {
        // A short frame is never replayed or followed by an interleaved cancel.
        record.wireDone = true; this.connected = false;
        if (record.id !== undefined) this.select(record, P.errorLine(record.id, "unknown"));
        this.state_DRAINING("unavailable"); return;
      }
      record.sent = true;
      if (this.current() === "DRAINING" || !record.wanted) this.cancel(record);
      this.flushControl(); this.wake();
    });
  }
  private queueControl(frame: Buffer, charged: boolean, shutdown = false): boolean {
    if (!this.connected) return false;
    if (charged) {
      // Native completion is private to the relay, so credits are conservatively retained until close.
      if (this.controlCount >= P.CONTROL_CAP - (shutdown ? 0 : 1)) { this.state_DRAINING("unavailable"); return false; }
      this.controlCount++;
    }
    // The FIFO contains at most the charged controls and the two reserved ping positions.
    if (this.pendingControl.length >= P.CONTROL_CAP + P.PING_CAP) { this.state_DRAINING("unavailable"); return false; }
    this.pendingControl.push(frame); this.flushControl(); return true;
  }
  private flushControl(): void {
    if (this.relayWriting || !this.connected || this.pendingControl.length === 0 || this.state === "CLOSED") return;
    const frame = this.pendingControl.shift()!; this.relayWriting = true;
    this.ports.relayOutput.write(frame, (error, written) => {
      this.relayWriting = false;
      if (error || written !== frame.length) { this.connected = false; this.pendingControl = []; this.state_DRAINING("unavailable"); }
      this.wake();
    });
  }
  private cancel(record: RecordEntry): void {
    if (!record.wire || !record.sent || record.cancelSent || record.wireDone || record.settled) return;
    record.cancelSent = true;
    record.settleDeadline ??= this.ports.now() + P.SHIM_CANCEL_SETTLE_MS;
    this.queueControl(P.relayFrame({ type: "cancel", mcp_request_id: record.wire }), true);
  }
  private shutdown(): void {
    if (this.shutdownSent || !this.connected) return;
    this.shutdownSent = true;
    this.queueControl(P.relayFrame({ type: "shutdown" }), true, true);
  }
  private readRelay(): void {
    if (!this.connected || this.current() === "DRAINING") return;
    const need = this.socketTail.length < P.PREFIX_BYTES ? P.PREFIX_BYTES - this.socketTail.length
      : P.PREFIX_BYTES + this.socketTail.readUInt32BE() - this.socketTail.length;
    if (need < 0 || need + this.socketTail.length > P.MAX_SOCKET_TAIL_BYTES) { this.state_DRAINING("internal"); return; }
    const available = Math.min(need, this.ports.relayInput.readableLength);
    if (available) {
      const bytes = this.ports.relayInput.read(available) as Buffer;
      this.socketTail = Buffer.concat([this.socketTail, bytes]);
    }
    if (this.socketTail.length < P.PREFIX_BYTES) return;
    const size = this.socketTail.readUInt32BE();
    if (size === 0 || size > P.MAX_PUBLIC_FRAME_BYTES) { this.state_DRAINING("internal"); return; }
    if (this.socketTail.length === P.PREFIX_BYTES + size) {
      const bytes = this.socketTail.subarray(P.PREFIX_BYTES); this.socketTail = Buffer.alloc(0);
      try { this.relayMessage(bytes); } catch { this.state_DRAINING("internal"); }
    }
    if (this.ports.relayInput.readableLength) this.wake();
  }
  private relayMessage(bytes: Buffer): void {
    const message = P.parseStrictJsonObject(bytes);
    if (message.type === "pong" && Object.keys(message).length === 1) {
      const record = this.pings.find(item => item.sent && !item.wireDone);
      if (!record) throw new Error("unexpected pong");
      record.wireDone = true; record.deadline = undefined;
      this.select(record, P.resultLine(record.id!, Buffer.from("{}"))); this.retire(); return;
    }
    const record = this.primary;
    if (!record || message.request_id !== record.wire || Object.keys(message).length !== 3) throw new Error("unexpected frame");
    if (message.type !== "result" && message.type !== "error") throw new Error("unexpected frame");
    if (message.type === "error") {
      if (message.message !== "Memory request denied." && message.message !== "Memory service unavailable.") throw new Error("unexpected error");
      record.wireDone = true; record.settleDeadline = undefined; record.deadline = undefined;
      if (record.kind === "hello") { this.state_DRAINING("unavailable"); return; }
      this.select(record, P.errorLine(record.id!, message.message === "Memory request denied." ? "denied" : record.insert ? "unknown" : "unavailable"));
      this.retire(); return;
    }
    if (!P.isRecord(message.payload)) throw new Error("unexpected payload");
    const range = P.memberRanges(bytes).get("payload"); if (!range) throw new Error("missing payload");
    let payload = bytes.subarray(range[0], range[1]);
    if (record.kind === "hello") {
      if (Object.keys(message.payload).length !== 2 || message.payload.protocol_version !== P.RELAY_VERSION
        || message.payload.server_name !== "sanctuary-hermes-memory-bridge") throw new Error("unexpected hello");
      this.primary = undefined; this.helloReady = true;
      if (this.initialization) this.state_INITIALIZE_OUTPUT(); else this.state_AWAIT_INITIALIZE();
      for (const ping of this.pings) this.sendPing(ping);
      return;
    }
    if (record.kind === "list") payload = P.translatedCatalog(payload); else P.validateCallResult(payload);
    const line = P.resultLine(record.id!, payload);
    record.wireDone = true; record.deadline = undefined; record.settleDeadline = undefined;
    this.select(record, line); this.retire();
  }
  private select(record: RecordEntry, line: Buffer): void {
    // Settlement identity belongs to the record, so a late event cannot settle a reused MCP ID.
    if (record.settled) return;
    record.settled = true;
    if (!record.wanted || this.silent) { record.outputDone = true; return; }
    record.line = line;
    record.outputDeadline = record.kind === "call" || record.kind === "list"
      ? record.admitted + P.HERMES_TOOL_TIMEOUT_MS : this.ports.now() + P.SHIM_WRITE_STALL_MS;
    this.outputs.push(record); this.wake();
  }
  private flushOutput(): void {
    if (this.silent || this.outputWriting || this.outputs.length === 0 || this.state === "CLOSED") return;
    const record = this.outputs[0]; const bytes = record.line!.subarray(this.outputOffset);
    this.outputWriting = true;
    if (this.state !== "STALLED" && this.state !== "DRAINING") { this.state_STALLED(); }
    this.ports.output.write(bytes, (error, written) => {
      this.outputWriting = false;
      if (this.state === "CLOSED" || this.silent) return;
      if (error || written <= 0 || written > bytes.length) { this.deadOutput(); return; }
      this.outputOffset += written;
      if (this.outputOffset === record.line!.length) {
        this.outputs.shift(); this.outputOffset = 0; record.line = undefined; record.outputDone = true;
        if (record.kind === "initialize" && this.current() === "INITIALIZE_OUTPUT") {
          this.initialization = undefined; this.state_AWAIT_INITIALIZED();
        }
      }
      if (this.state === "STALLED") this.state = this.savedState;
      this.retire(); this.wake();
    });
  }
  private retire(): void {
    for (const [key, record] of this.records) if (record.outputDone) this.records.delete(key);
    for (let i = this.pings.length - 1; i >= 0; i--) if (this.pings[i].wireDone && this.pings[i].outputDone) this.pings.splice(i, 1);
    if (this.primary?.wireDone && this.primary.outputDone) { this.primary.settleDeadline = undefined; this.primary = undefined; }
  }
  private checkDeadlines(): void {
    const now = this.ports.now();
    if (this.drainDeadline !== undefined) { if (now >= this.drainDeadline) this.state_CLOSED(); return; }
    if (!this.helloReady && now >= this.connectDeadline) { this.state_DRAINING("unavailable"); return; }
    if (["HELD_INITIALIZE", "AWAIT_INITIALIZE", "INITIALIZE_OUTPUT", "AWAIT_INITIALIZED"].includes(this.current()) && now >= this.initializationDeadline) {
      this.state_DRAINING("unavailable"); return;
    }
    for (const record of this.outputs) if (record.outputDeadline !== undefined && now >= record.outputDeadline) { this.deadOutput(); return; }
    const primary = this.primary;
    if (primary?.deadline !== undefined && now >= primary.deadline && !primary.settled) {
      this.cancel(primary); this.select(primary, P.errorLine(primary.id!, "deadline")); primary.deadline = undefined;
    }
    if (primary?.settleDeadline !== undefined && now >= primary.settleDeadline) { this.state_DRAINING("unavailable"); return; }
    for (const ping of this.pings) if (!ping.wireDone && ping.deadline !== undefined && now >= ping.deadline) {
      ping.deadline = undefined; this.select(ping, P.errorLine(ping.id!, "unavailable"));
    }
  }
  private armTimer(): void {
    if (this.timerHandle) this.ports.clearTimer(this.timerHandle);
    if (this.state === "CLOSED") return;
    const deadlines = [this.drainDeadline, this.helloReady ? undefined : this.connectDeadline,
      ["HELD_INITIALIZE", "AWAIT_INITIALIZE", "INITIALIZE_OUTPUT", "AWAIT_INITIALIZED"].includes(this.current()) ? this.initializationDeadline : undefined,
      this.primary?.deadline, this.primary?.settleDeadline, ...this.pings.map(item => item.deadline), ...this.outputs.map(item => item.outputDeadline)]
      .filter((value): value is number => value !== undefined);
    if (deadlines.length) this.timerHandle = this.ports.timer(this.wake, Math.max(1, Math.min(...deadlines) - this.ports.now()));
  }
  private deadOutput(): void {
    if (this.primary) this.cancel(this.primary);
    this.silent = true; this.state_DRAINING("unavailable", true);
  }
  private state_DRAINING(kind: P.ErrorKind, silent = false): void {
    if (this.state === "CLOSED") return;
    if (silent) { this.silent = true; this.outputs.length = 0; this.inputTail = Buffer.alloc(0); this.inputOffset = 0; }
    if (this.current() === "DRAINING") { this.wake(); return; }
    this.state = "DRAINING"; this.drainKind = kind;
    this.drainDeadline = this.ports.now() + P.SHIM_DISCONNECT_TIMEOUT_MS;
    // Cancellation precedes settlement; a selected response never causes a new relay cancel.
    if (this.primary) this.cancel(this.primary);
    if (!silent) for (const record of this.records.values()) this.select(record,
      P.errorLine(record.id!, record.insert && kind === "unavailable" ? "unknown" : kind));
    this.shutdown(); this.wake();
  }
  private state_CLOSED(): void {
    if (this.state === "CLOSED") return;
    this.state = "CLOSED";
    if (this.timerHandle) this.ports.clearTimer(this.timerHandle);
    this.ports.input.off("readable", this.wake); this.ports.input.off("end", this.onEof); this.ports.input.off("error", this.onInputError);
    this.ports.relayInput.off("readable", this.wake); this.ports.relayInput.off("end", this.onSocketLoss);
    this.ports.relayInput.off("error", this.onSocketLoss); this.ports.relayInput.off("close", this.onSocketLoss);
    this.records.clear(); this.outputs.length = 0; this.pings.length = 0; this.pendingControl = [];
    this.socketTail = Buffer.alloc(0); this.inputTail = Buffer.alloc(0); this.primary = undefined; this.initialization = undefined;
    this.ports.close(); this.resolve(0);
  }
}
