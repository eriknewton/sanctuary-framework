import { HERMES_TOOL_OUTCOMES } from "../../src/hermes-memory-bridge/public-results.js";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

const nonceQueue = vi.hoisted(() => ({ values: [] as string[] }));

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return {
    ...actual,
    randomBytes(size: number): Buffer {
      const hex = nonceQueue.values.shift() ?? "0123456789abcdef0123456789abcdef";
      return Buffer.from(hex, "hex").subarray(0, size);
    },
  };
});

import {
  HERMES_MEMORY_DENIAL,
  HERMES_HELLO_PAYLOAD,
  HERMES_TOOLS_LIST_PAYLOAD,
  PrivateFrameDecoder,
  encodePrivateFrame,
  parsePublicFrame,
  parseRelayToNode,
  type HermesBridgeAuditRecord,
  HermesBridgeCore,
  type HermesBridgeCorePorts,
  type HermesBridgeMemoryAdapter,
  type HermesTimerHandle,
  type NodeToRelayInput,
  type RelayToNodeFrame,
} from "../../src/hermes-memory-bridge/index.js";
import type { MemoryPassage, MemoryPassageInput, MemorySearchQuery, MemorySearchResult } from "../../src/sdw/adapters/memory-backend.js";
import { hermesBridgePassageTextDigest } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { memoryGetSuccessFrameUtf8Bytes } from "../../src/sdw/memory-tool-projection.js";
import type { PersistableTaint } from "../../src/sdw/provenance.js";

type FixtureEntry = {
  readonly name: string;
  readonly direction?: string;
  readonly channel?: string;
  readonly frame?: Record<string, unknown>;
  readonly bytes_hex?: string;
  readonly expected_action: string;
};

type Reaction =
  | { readonly kind: "fatal" }
  | { readonly kind: "discarded" }
  | { readonly kind: "writes"; readonly writes: readonly ParsedWrite[] };

type ParsedWrite =
  | { readonly type: "close"; readonly connection_id: string }
  | { readonly type: "probe"; readonly connection_id: string; readonly nonce: string }
  | { readonly type: "response"; readonly connection_id: string; readonly request_id: string; readonly payload: Record<string, unknown> };

type FixtureExpectation = {
  readonly precondition: "fresh" | "accepted" | "probe_live" | "probe_closed" | "probe_timed_out_c2";
  readonly reaction: Reaction;
  readonly reason: string;
};

const fixtureUrl = new URL("./fixtures/relay-frames.json", import.meta.url);
const relayFixtureText = readFileSync(fixtureUrl, "utf8");
const relayFixture = JSON.parse(relayFixtureText) as Readonly<Record<string, readonly FixtureEntry[]>>;
const encoder = new TextEncoder();

const denied = (requestId: string) => ({ type: "error", request_id: requestId, message: HERMES_MEMORY_DENIAL });
const result = (requestId: string, payload: Record<string, unknown>) => ({ type: "result", request_id: requestId, payload });

const FIXTURE_EXPECTATIONS = Object.freeze({
  "public hello": {
    precondition: "accepted",
    reason: "hello is a fixed catalog call on an admitted connection",
    reaction: { kind: "writes", writes: [{ type: "response", connection_id: "c1", request_id: "mcp-hello", payload: result("mcp-hello", HERMES_HELLO_PAYLOAD) }] },
  },
  "public tools list": {
    precondition: "accepted",
    reason: "tools_list is a fixed catalog call on an admitted connection",
    reaction: { kind: "writes", writes: [{ type: "response", connection_id: "c1", request_id: "mcp-list", payload: result("mcp-list", HERMES_TOOLS_LIST_PAYLOAD) }] },
  },
  "public tool call": {
    precondition: "accepted",
    reason: "memory_search with a valid query returns the positive search shape",
    reaction: { kind: "writes", writes: [{ type: "response", connection_id: "c1", request_id: "mcp-1", payload: result("mcp-1", { content: [{ type: "text", text: "{\n  \"results\": []\n}" }] }) }] },
  },
  "public cancel": {
    precondition: "accepted",
    reason: "idle cancel is a forwarded control with no current record",
    reaction: { kind: "discarded" },
  },
  "public ping": {
    precondition: "accepted",
    reason: "ping is relay-owned and closes when forwarded to Node",
    reaction: { kind: "writes", writes: [{ type: "close", connection_id: "c1" }] },
  },
  "public shutdown": {
    precondition: "accepted",
    reason: "idle shutdown moves the connection to peer-shutting without a Node frame",
    reaction: { kind: "discarded" },
  },
  "missing type": {
    precondition: "accepted",
    reason: "a call without a recoverable request id closes the connection",
    reaction: { kind: "writes", writes: [{ type: "close", connection_id: "c1" }] },
  },
  "missing required field": {
    precondition: "accepted",
    reason: "a malformed call with a request id receives the fixed denial",
    reaction: { kind: "writes", writes: [{ type: "response", connection_id: "c1", request_id: "mcp-1", payload: denied("mcp-1") }] },
  },
  "wrong field type": {
    precondition: "accepted",
    reason: "an invalid control frame is consumed without output",
    reaction: { kind: "discarded" },
  },
  "probe on public side": {
    precondition: "accepted",
    reason: "a non-public frame forwarded as public bytes closes the connection",
    reaction: { kind: "writes", writes: [{ type: "close", connection_id: "c1" }] },
  },
  "relay accepted": {
    precondition: "fresh",
    reason: "accepted opens the row and writes nothing",
    reaction: { kind: "discarded" },
  },
  "relay frame envelope": {
    precondition: "accepted",
    reason: "the forwarded call has invalid memory_search arguments and receives the fixed denial",
    reaction: { kind: "writes", writes: [{ type: "response", connection_id: "c1", request_id: "mcp-1", payload: result("mcp-1", HERMES_TOOL_OUTCOMES.denied) }] },
  },
  "relay closed": {
    precondition: "accepted",
    reason: "closed removes an idle accepted connection",
    reaction: { kind: "discarded" },
  },
  "relay probe reply": {
    precondition: "probe_live",
    reason: "the issued nonce resolves the waiting probe and permits the insert",
    reaction: { kind: "writes", writes: [{ type: "response", connection_id: "c1", request_id: "mcp-1", payload: result("mcp-1", { content: [{ type: "text", text: "{\n  \"outcome\": \"saved\",\n  \"inserted\": true,\n  \"passage\": {\n    \"passage_id\": \"fixture-passage\",\n    \"document_id\": \"mem.fixture-passage\"\n  }\n}" }] }) }] },
  },
  "relay shutdown": {
    precondition: "accepted",
    reason: "shutdown stops the bridge without client output when no call is live",
    reaction: { kind: "discarded" },
  },
  "ready on relay side": {
    precondition: "fresh",
    reason: "ready is not a relay-to-Node frame",
    reaction: { kind: "fatal" },
  },
  "relay accepted bytes": {
    precondition: "fresh",
    reason: "byte fixture accepted opens the row and writes nothing",
    reaction: { kind: "discarded" },
  },
  "relay frame bytes": {
    precondition: "accepted",
    reason: "byte fixture public ping is relay-owned and closes when forwarded to Node",
    reaction: { kind: "writes", writes: [{ type: "close", connection_id: "c1" }] },
  },
  "relay closed bytes": {
    precondition: "accepted",
    reason: "byte fixture closed removes an idle accepted connection",
    reaction: { kind: "discarded" },
  },
  "relay probe reply bytes": {
    precondition: "probe_live",
    reason: "byte fixture probe reply resolves the waiting insert",
    reaction: { kind: "writes", writes: [{ type: "response", connection_id: "c1", request_id: "mcp-1", payload: result("mcp-1", { content: [{ type: "text", text: "{\n  \"outcome\": \"saved\",\n  \"inserted\": true,\n  \"passage\": {\n    \"passage_id\": \"fixture-passage\",\n    \"document_id\": \"mem.fixture-passage\"\n  }\n}" }] }) }] },
  },
  "relay closed then late probe reply": {
    precondition: "probe_live",
    reason: "the vector closes the live probe before its matching late reply is discarded",
    reaction: { kind: "discarded" },
  },
  "relay probe reply after timeout": {
    precondition: "probe_timed_out_c2",
    reason: "timeout abandons the issued nonce and the matching late reply is discarded",
    reaction: { kind: "discarded" },
  },
  "relay shutdown bytes": {
    precondition: "accepted",
    reason: "byte fixture shutdown stops the bridge without client output when no call is live",
    reaction: { kind: "discarded" },
  },
  "relay bad json": {
    precondition: "fresh",
    reason: "malformed private JSON is fatal",
    reaction: { kind: "fatal" },
  },
  "relay unknown type": {
    precondition: "fresh",
    reason: "unknown private type is fatal",
    reaction: { kind: "fatal" },
  },
  "relay missing field": {
    precondition: "fresh",
    reason: "private schema mismatch is fatal",
    reaction: { kind: "fatal" },
  },
  "relay duplicate key": {
    precondition: "fresh",
    reason: "duplicate private key is fatal",
    reaction: { kind: "fatal" },
  },
  "relay over cap length": {
    precondition: "fresh",
    reason: "private over-cap length is fatal before parsing",
    reaction: { kind: "fatal" },
  },
  "relay probe reply never accepted connection": {
    precondition: "fresh",
    reason: "a probe reply for an unknown connection is fatal",
    reaction: { kind: "fatal" },
  },
} satisfies Readonly<Record<string, FixtureExpectation>>);

const LABEL_EQUIVALENCES = Object.freeze([
  {
    labels: [
      "public cancel",
      "public shutdown",
      "wrong field type",
      "relay accepted",
      "relay closed",
      "relay shutdown",
      "relay accepted bytes",
      "relay closed bytes",
      "relay closed then late probe reply",
      "relay probe reply after timeout",
      "relay shutdown bytes",
    ],
    reason: "each leaves no externally written frame after its stated precondition",
  },
  {
    labels: ["public ping", "missing type", "probe on public side", "relay frame bytes"],
    reason: "each authorizes the same close frame for c1",
  },
  {
    labels: ["missing required field"],
    reason: "each authorizes the same fixed denial for mcp-1",
  },
  {
    labels: ["relay probe reply", "relay probe reply bytes"],
    reason: "both carry the same issued nonce and complete the same approved insert",
  },
  {
    labels: ["relay closed then late probe reply", "relay probe reply after timeout"],
    reason: "both consume an abandoned issued nonce without writing",
  },
  {
    labels: ["ready on relay side", "relay bad json", "relay unknown type", "relay missing field", "relay duplicate key", "relay over cap length", "relay probe reply never accepted connection"],
    reason: "each reaches the fatal bridge outcome with no written frame",
  },
] as const);

class ManualTimers {
  private nextId = 1;
  readonly live = new Map<HermesTimerHandle, { readonly ms: number; readonly fire: () => void }>();

  setTimer = (ms: number, fire: () => void): HermesTimerHandle => {
    const handle = { id: this.nextId++ };
    this.live.set(handle, { ms, fire });
    return handle;
  };

  clearTimer = (handle: HermesTimerHandle): void => {
    this.live.delete(handle);
  };

  fireByMs(ms: number): void {
    const entry = [...this.live].find(([, timer]) => timer.ms === ms);
    if (entry === undefined) throw new Error(`no timer for ${ms}`);
    this.live.delete(entry[0]);
    entry[1].fire();
  }
}

function makeHarness() {
  const timers = new ManualTimers();
  const writes: NodeToRelayInput[] = [];
  const audits: HermesBridgeAuditRecord[] = [];
  const store = new Map<string, MemoryPassage>();
  let core!: HermesBridgeCore;
  const adapter: HermesBridgeMemoryAdapter = {
    recallPassages: async budget => budget.result(),
    async insertPassage(input: MemoryPassageInput, _taint: PersistableTaint): Promise<MemoryPassage> {
      const passage = makePassage(input.passage_id ?? "fixture-passage", input.text);
      await core.commitCheck.assertAllowedToCommit({
        passageId: passage.passage_id,
        documentId: `mem.${passage.passage_id}`,
        passageTextUtf8: Buffer.from(input.text, "utf8"),
        passageTextSha256: hermesBridgePassageTextDigest(input.text),
        getFrameUtf8Bytes: memoryGetSuccessFrameUtf8Bytes(passage),
      });
      store.set(passage.passage_id, passage);
      return passage;
    },
    async getPassage(passageId: string): Promise<MemoryPassage | null> {
      return store.get(passageId) ?? null;
    },
    async searchPassages(_query: MemorySearchQuery): Promise<readonly MemorySearchResult[]> {
      return [];
    },
  };
  core = new HermesBridgeCore({
    writeFrame(input) {
      writes.push(input);
    },
    appendAudit(record) {
      audits.push(record);
      return Promise.resolve();
    },
    nowMs: () => 1_000,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
    adapter,
    agentId: "fixture-agent",
    abort: new AbortController(),
  } satisfies HermesBridgeCorePorts);
  return { core, timers, writes, audits };
}

function makePassage(passageId: string, text: string): MemoryPassage {
  return {
    passage_id: passageId,
    owner_ref: "fleet-self",
    text,
    tags: ["fixture"],
    metadata: [],
    created_at: "2026-10-13T00:00:00.000Z",
    chunk_count: 1,
    content_hash: `hash-${passageId}`,
    provenance_status: "verified",
  };
}

function fixtureEntries(): readonly FixtureEntry[] {
  return Object.values(relayFixture).flatMap((section) => section);
}

function scopedVectors(): readonly FixtureEntry[] {
  return fixtureEntries().filter((entry) =>
    entry.direction === "publicInbound" ||
    entry.direction === "relayToNode" ||
    entry.channel === "relay_to_node"
  );
}

function findVector(label: string): FixtureEntry {
  const found = scopedVectors().find((entry) => entry.name === label);
  if (found === undefined) throw new Error(`fixture vector missing: ${label}`);
  return found;
}

function rawFixtureFrameBytes(name: string): Uint8Array {
  const nameNeedle = `"name": ${JSON.stringify(name)}`;
  const nameAt = relayFixtureText.indexOf(nameNeedle);
  if (nameAt < 0) throw new Error(`fixture vector not found: ${name}`);
  const frameAt = relayFixtureText.indexOf("\"frame\"", nameAt);
  if (frameAt < 0) throw new Error(`fixture frame not found: ${name}`);
  const colonAt = relayFixtureText.indexOf(":", frameAt);
  let start = colonAt + 1;
  while (/\s/u.test(relayFixtureText[start] ?? "")) start += 1;
  if (relayFixtureText[start] !== "{") throw new Error(`fixture frame is not an object: ${name}`);
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < relayFixtureText.length; index += 1) {
    const ch = relayFixtureText[index]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === "\"") inString = false;
      continue;
    }
    if (ch === "\"") inString = true;
    else if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return encoder.encode(relayFixtureText.slice(start, index + 1));
    }
  }
  throw new Error(`fixture frame object is incomplete: ${name}`);
}

function bytesForVector(vector: FixtureEntry): Uint8Array {
  if (vector.direction === "publicInbound") {
    const publicBytes = rawFixtureFrameBytes(vector.name);
    return encodePrivateFrame(encoder.encode(JSON.stringify({
      type: "frame",
      connection_id: "c1",
      frame_b64: Buffer.from(publicBytes).toString("base64"),
    })));
  }
  if (vector.bytes_hex !== undefined) return Buffer.from(vector.bytes_hex, "hex");
  return encodePrivateFrame(rawFixtureFrameBytes(vector.name));
}

function decodeRelayFrames(bytes: Uint8Array): Array<RelayToNodeFrame | "fatal"> {
  const decoder = new PrivateFrameDecoder();
  decoder.push(bytes);
  const frames: Array<RelayToNodeFrame | "fatal"> = [];
  for (;;) {
    const decoded = decoder.next();
    if (decoded.kind === "need_more") return frames;
    if (decoded.kind === "fatal") return [...frames, "fatal"];
    const parsed = parseRelayToNode(decoded.body);
    if (parsed.kind === "fatal") frames.push("fatal");
    else frames.push(parsed.frame);
  }
}

async function applyPrecondition(h: ReturnType<typeof makeHarness>, precondition: FixtureExpectation["precondition"]): Promise<void> {
  if (precondition === "fresh") return;
  const connectionId = precondition === "probe_timed_out_c2" ? "c2" : "c1";
  h.core.relayFrame({ kind: "accepted", connectionId });
  if (precondition === "accepted") return;
  nonceQueue.values = [
    precondition === "probe_timed_out_c2"
      ? "fedcba9876543210fedcba9876543210"
      : "0123456789abcdef0123456789abcdef",
  ];
  h.core.relayFrame(frameForPublic(connectionId, { type: "tools_call", request_id: "mcp-1", name: "memory_insert", arguments: {
    text: "fixture text",
    taint: "user_content",
    tags: ["fixture"],
    passage_id: "fixture-passage",
  } }));
  await Promise.resolve();
  const entry = h.core.snapshot().ledger.entry;
  if (entry === undefined) throw new Error("probe precondition did not create an entry");

  await Promise.resolve();
  h.writes.splice(0, h.writes.length);
  if (precondition === "probe_closed") {
    h.core.relayFrame({ kind: "closed", connectionId });
    for (let turn = 0; turn < 10; turn += 1) await Promise.resolve();
    h.writes.splice(0, h.writes.length);
  } else if (precondition === "probe_timed_out_c2") {
    h.timers.fireByMs(2_000);
    for (let turn = 0; turn < 10; turn += 1) await Promise.resolve();
    h.writes.splice(0, h.writes.length);
  }
}

function frameForPublic(connectionId: string, frame: Record<string, unknown>): RelayToNodeFrame {
  const publicBytes = encoder.encode(JSON.stringify(frame));
  return {
    kind: "frame",
    connectionId,
    publicBytes,
    publicFrame: parsePublicFrame(publicBytes),
  };
}

async function reactionFor(label: string): Promise<Reaction> {
  const expectation = (FIXTURE_EXPECTATIONS as Readonly<Record<string, FixtureExpectation>>)[label];
  if (expectation === undefined) throw new Error(`missing expectation for ${label}`);
  const h = makeHarness();
  await applyPrecondition(h, expectation.precondition);
  for (const frame of decodeRelayFrames(bytesForVector(findVector(label)))) {
    if (frame === "fatal") h.core.relayFatal("fixture");
    else h.core.relayFrame(frame);
  }
  for (let turn = 0; turn < 10; turn += 1) await Promise.resolve();
  if (h.core.fatalBridge) return { kind: "fatal" };
  const writes = h.writes.map(parseWrite);
  return writes.length === 0 ? { kind: "discarded" } : { kind: "writes", writes };
}

function parseWrite(write: NodeToRelayInput): ParsedWrite {
  if (write.type === "close") return { type: "close", connection_id: write.connectionId };
  if (write.type === "probe") return { type: "probe", connection_id: write.connectionId, nonce: write.nonce };
  if (write.type === "ready") throw new Error("core fixture did not expect ready output");
  return {
    type: "response",
    connection_id: write.connectionId,
    request_id: write.requestId,
    payload: JSON.parse(Buffer.from(write.publicPayloadBytes).toString("utf8")) as Record<string, unknown>,
  };
}

function equivalentLabels(left: string, right: string): boolean {
  return LABEL_EQUIVALENCES.some((entry) => entry.labels.includes(left as never) && entry.labels.includes(right as never));
}

describe("HermesBridgeCore fixture conformance", () => {
  it("feeds every relay and public inbound vector through the private decoder, parser, and core", async () => {
    expect(Object.keys(FIXTURE_EXPECTATIONS).sort()).toEqual(scopedVectors().map((entry) => entry.name).sort());
    for (const [label, expectation] of Object.entries(FIXTURE_EXPECTATIONS)) {
      expect(await reactionFor(label), `${label}: ${expectation.reason}`).toEqual(expectation.reaction);
    }
  });

  it("keeps relabeled vectors red unless their observable reaction is listed as equivalent", async () => {
    const labels = Object.keys(FIXTURE_EXPECTATIONS);
    const reactions = new Map<string, Reaction>();
    for (const label of labels) reactions.set(label, await reactionFor(label));

    for (const label of labels) {
      for (const other of labels) {
        if (label === other || equivalentLabels(label, other)) continue;
        expect(reactions.get(label), `${label} relabeled as ${other}`)
          .not.toEqual((FIXTURE_EXPECTATIONS as Readonly<Record<string, FixtureExpectation>>)[other]?.reaction);
      }
    }
  });
});
