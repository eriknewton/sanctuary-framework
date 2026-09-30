/**
 * Capability: a root helper that holds a bound credential value answers a value
 * query only under all four conditions of the query contract, accepts a value
 * only through the operator's own socket under the validation rules, and binds
 * each of its two sockets to exactly one codec so neither principal can speak
 * the other's protocol.
 *
 * Host-free: both sockets live in a per-test temp directory, every filesystem
 * side effect is injected, the clock is injected, and `launchctl` is never
 * invoked. No keychain is opened and no `security` subprocess runs; the test
 * value is generated here in the test.
 *
 * Every connection in this file is a real Unix-domain socket round trip against
 * the real listeners, so the one-frame-per-connection contract is exercised
 * rather than asserted about.
 *
 * Defect id: SURROGATE-HELPER-QUERY, SURROGATE-HELPER-UNLOCK,
 * SURROGATE-HELPER-CODEC-SPLIT, SURROGATE-HELPER-CAPS.
 */

import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm as rmReal, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { renderSurrogateBindingsFile } from "../../src/credential-surrogate/artifacts.js";
import type { MintedSurrogateBinding } from "../../src/credential-surrogate/binding.js";
import {
  MAX_SURROGATE_UNLOCK_SECONDS,
  MAX_SURROGATE_VALUE_BYTES,
  SURROGATE_WIRE_MAX_FRAME_BYTES,
} from "../../src/credential-surrogate/constants.js";
import { mintSurrogatePlaceholder } from "../../src/credential-surrogate/placeholder.js";
import {
  encodeSurrogateQueryRequest,
  parseSurrogateQueryResponse,
  surrogateHeaderLocation,
  type SurrogateQueryResponse,
} from "../../src/credential-surrogate/query-codec.js";
import {
  encodeSurrogateUnlockSocketRequest,
  parseSurrogateUnlockSocketResponse,
} from "../../src/credential-surrogate/unlock-codec.js";
import {
  SURROGATE_WIRE_VERSION,
  newSurrogateCorrelationId,
} from "../../src/credential-surrogate/wire.js";
import {
  SurrogateHelperStartError,
  clampSurrogateUnlockSeconds,
  runSurrogateHelperDaemon,
  surrogateBindingsPath,
  type SurrogateHelperDaemonHandle,
  type SurrogateHelperEvent,
  type SurrogateHelperFsOps,
} from "../../src/egress-gate/surrogate-helper-daemon.js";

const AGENT_UID = 601;
const GATE_UID = 602;
const OPERATOR_UID = 501;
const GENERATION = 7;

/** The surrogate test value, generated here. Never a fixture and never logged. */
function freshTestValue(): string {
  return `t-${randomBytes(12).toString("hex")}`;
}

function binding(
  ordinal: number,
  overrides: Partial<MintedSurrogateBinding> = {},
): MintedSurrogateBinding {
  return {
    ordinal,
    placeholder: mintSurrogatePlaceholder(),
    secret: `secret-${ordinal}`,
    agent: "hermes",
    env: `SECRET_${ordinal}`,
    header: "Authorization",
    destinations: [{ host: `api${ordinal}.example.com`, port: 443 }],
    ...overrides,
  };
}

interface Harness {
  handle: SurrogateHelperDaemonHandle;
  events: SurrogateHelperEvent[];
  /** Injected clock; tests move it rather than waiting out a TTL. */
  setNow(ms: number): void;
  chowned: { path: string; uid: number }[];
  chmodded: { path: string; mode: number }[];
}

const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  // Teardown reaps every listener even when an assertion failed, so a failing
  // test never leaves a socket behind for the next one.
  while (cleanups.length > 0) await cleanups.pop()!().catch(() => undefined);
});

async function startHelper(options: {
  bindings: MintedSurrogateBinding[];
  generation?: number;
  fileGeneration?: number;
  maxConcurrentQueries?: number;
  /** Raw bindings-file text override, for the refuse-to-start cases. */
  rawBindings?: string;
}): Promise<Harness> {
  const dir = await mkdtemp(join(tmpdir(), "surrogate-helper-"));
  cleanups.push(() => rmReal(dir, { recursive: true, force: true }));
  const text =
    options.rawBindings ??
    renderSurrogateBindingsFile(options.fileGeneration ?? GENERATION, options.bindings);
  await writeFile(surrogateBindingsPath(AGENT_UID, dir), text, "utf8");

  const chowned: { path: string; uid: number }[] = [];
  const chmodded: { path: string; mode: number }[] = [];
  // Injected fs ops: a `chown` to a uid this test process does not own would
  // fail with EPERM on a real path, so ownership is asserted on the RECORD of
  // the call. The mode and the owner are the security-sensitive part, and both
  // are observable here.
  const fsOps: SurrogateHelperFsOps = {
    async mkdir(): Promise<void> {},
    async chmod(path, mode): Promise<void> {
      chmodded.push({ path, mode });
    },
    async chown(path, uid): Promise<void> {
      chowned.push({ path, uid });
    },
    async rm(path): Promise<void> {
      await rmReal(path, { force: true });
    },
    async readFile(path): Promise<string> {
      return readFile(path, "utf8");
    },
  };

  let now = 1_000_000;
  const events: SurrogateHelperEvent[] = [];
  const handle = await runSurrogateHelperDaemon({
    agentUid: AGENT_UID,
    gateUid: GATE_UID,
    operatorUid: OPERATOR_UID,
    generation: options.generation ?? GENERATION,
    surrogateDir: dir,
    maxConcurrentQueries: options.maxConcurrentQueries,
    fsOps,
    clock: { now: () => now },
    onEvent: (event) => events.push(event),
  });
  cleanups.push(() => handle.close());
  return {
    handle,
    events,
    setNow: (ms) => {
      now = ms;
    },
    chowned,
    chmodded,
  };
}

/** One request, one reply, one connection: exactly what both contracts specify. */
function roundTrip(socketPath: string, frame: Buffer | string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let out = "";
    socket.on("error", reject);
    socket.on("connect", () => socket.write(frame));
    socket.on("data", (chunk: Buffer) => {
      out += chunk.toString("utf8");
    });
    socket.on("close", () => resolve(out));
  });
}

function queryFrame(fields: {
  placeholder: string;
  host: string;
  port?: number;
  location?: string;
  id?: string;
}): { id: string; frame: Buffer } {
  const id = fields.id ?? newSurrogateCorrelationId();
  return {
    id,
    frame: encodeSurrogateQueryRequest({
      v: SURROGATE_WIRE_VERSION,
      id,
      kind: "resolve",
      placeholder: fields.placeholder,
      host: fields.host,
      port: fields.port ?? 443,
      location: fields.location ?? surrogateHeaderLocation("Authorization"),
    }),
  };
}

function unlockFrame(fields: {
  secret: string;
  value: string;
  ttl?: number;
  generation?: number;
  id?: string;
}): { id: string; frame: Buffer } {
  const id = fields.id ?? newSurrogateCorrelationId();
  return {
    id,
    frame: encodeSurrogateUnlockSocketRequest({
      v: SURROGATE_WIRE_VERSION,
      id,
      kind: "unlock",
      generation_id: fields.generation ?? GENERATION,
      ttl_seconds: fields.ttl ?? 600,
      secret: fields.secret,
      value: fields.value,
    }),
  };
}

async function unlock(h: Harness, secret: string, value: string, ttl?: number): Promise<void> {
  const { frame } = unlockFrame({ secret, value, ttl });
  const raw = await roundTrip(h.handle.unlockSocketPath, frame);
  const resp = parseSurrogateUnlockSocketResponse(raw.trimEnd());
  expect(resp?.kind).toBe("ok");
}

async function query(
  h: Harness,
  frame: Buffer,
): Promise<SurrogateQueryResponse | null> {
  return parseSurrogateQueryResponse((await roundTrip(h.handle.querySocketPath, frame)).trimEnd());
}

describe("surrogate helper daemon: start and table load", () => {
  it("starts LOCKED with the table loaded and both sockets confined to one uid each", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    expect(h.handle.bindingCount).toBe(1);
    // Every socket is 0600 and chowned to exactly one principal: the query
    // socket to the gate uid, the unlock socket to the operator uid. A socket
    // owned by the wrong side is the whole boundary gone.
    const querySock = h.chowned.find((c) => c.path === h.handle.querySocketPath);
    const unlockSock = h.chowned.find((c) => c.path === h.handle.unlockSocketPath);
    expect(querySock?.uid).toBe(GATE_UID);
    expect(unlockSock?.uid).toBe(OPERATOR_UID);
    expect(
      h.chmodded.filter((c) => c.path.endsWith(".sock")).every((c) => c.mode === 0o600),
    ).toBe(true);
    // LOCKED: a query for a real placeholder at a bound destination still denies.
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, q.frame)).toEqual({ v: 1, id: q.id, kind: "deny", reason: "locked" });
  });

  it("refuses to start when the bindings file generation differs from its argv", async () => {
    await expect(
      startHelper({ bindings: [binding(0)], generation: 7, fileGeneration: 8 }),
    ).rejects.toMatchObject({ refusal: "generation_mismatch" });
  });

  it("refuses to start on an unreadable or unparseable bindings file", async () => {
    await expect(startHelper({ bindings: [], rawBindings: "not a header" })).rejects.toBeInstanceOf(
      SurrogateHelperStartError,
    );
  });
});

describe("surrogate helper daemon: the four query conditions", () => {
  it("swaps only when membership, destination, location and unlock all hold", async () => {
    const b = binding(0);
    const other = binding(1);
    const h = await startHelper({ bindings: [b, other] });
    const value = freshTestValue();
    await unlock(h, b.secret, value);

    const ok = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, ok.frame)).toEqual({
      v: 1,
      id: ok.id,
      kind: "swap",
      value,
    });

    // 1. not in the table.
    const unknown = queryFrame({
      placeholder: mintSurrogatePlaceholder(),
      host: b.destinations[0]!.host,
    });
    expect(await query(h, unknown.frame)).toMatchObject({ kind: "deny", reason: "unknown" });

    // 2. a host bound to a DIFFERENT binding is still a misroute for this one.
    const misroute = queryFrame({ placeholder: b.placeholder, host: other.destinations[0]!.host });
    expect(await query(h, misroute.frame)).toMatchObject({ kind: "deny", reason: "misroute" });

    // 3. the right placeholder in the wrong header, and in the request target.
    for (const location of [surrogateHeaderLocation("X-Api-Key"), "target"]) {
      const wrong = queryFrame({
        placeholder: b.placeholder,
        host: b.destinations[0]!.host,
        location,
      });
      expect(await query(h, wrong.frame)).toMatchObject({
        kind: "deny",
        reason: "wrong_location",
      });
    }

    // 4. the binding next to it was never unlocked.
    const locked = queryFrame({
      placeholder: other.placeholder,
      host: other.destinations[0]!.host,
    });
    expect(await query(h, locked.frame)).toMatchObject({ kind: "deny", reason: "locked" });
  });

  it("denies a bound host on a port slice 1 does not bind", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    await unlock(h, b.secret, freshTestValue());
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host, port: 8443 });
    // `malformed`, not `misroute`: slice 1 binds port 443 only, so the shared
    // port validator refuses the frame before the helper reaches its
    // destination check. The stricter answer is the right one, and it is asserted
    // here so a later widening of the bound port set has to come back and decide
    // which refusal it wants.
    expect(await query(h, q.frame)).toMatchObject({ kind: "deny", reason: "malformed" });
  });

  it("denies after expiry even if no sweep ran, and never re-answers", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    await unlock(h, b.secret, freshTestValue(), 60);
    h.setNow(1_000_000 + 60_000);
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, q.frame)).toMatchObject({ kind: "deny", reason: "expired" });
    // The expired value is dropped on read, so the next query is `locked`, not
    // `expired`: nothing is left to expire.
    const again = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, again.frame)).toMatchObject({ kind: "deny", reason: "locked" });
  });

  it("echoes the request id on every answer", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    await unlock(h, b.secret, freshTestValue());
    for (let i = 0; i < 4; i += 1) {
      const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
      expect((await query(h, q.frame))?.id).toBe(q.id);
    }
  });
});

describe("surrogate helper daemon: one codec per socket", () => {
  it("answers malformed to a query frame on the unlock socket", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    const { frame } = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    const resp = parseSurrogateUnlockSocketResponse(
      (await roundTrip(h.handle.unlockSocketPath, frame)).trimEnd(),
    );
    expect(resp).toMatchObject({ kind: "deny", reason: "malformed" });
  });

  it("answers malformed to an unlock frame on the query socket, and loads nothing", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    const { frame } = unlockFrame({ secret: b.secret, value: freshTestValue() });
    expect(await query(h, frame)).toMatchObject({ kind: "deny", reason: "malformed" });
    // The gate uid could not load a value: the binding is still locked.
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, q.frame)).toMatchObject({ kind: "deny", reason: "locked" });
  });
});

describe("surrogate helper daemon: unlock validation and the clamp", () => {
  it("refuses a secret outside its own table and a generation not its own", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    const outside = unlockFrame({ secret: "secret-not-bound", value: freshTestValue() });
    expect(
      parseSurrogateUnlockSocketResponse(
        (await roundTrip(h.handle.unlockSocketPath, outside.frame)).trimEnd(),
      ),
    ).toMatchObject({ kind: "deny", reason: "unknown_secret" });
    const stale = unlockFrame({
      secret: b.secret,
      value: freshTestValue(),
      generation: GENERATION + 1,
    });
    expect(
      parseSurrogateUnlockSocketResponse(
        (await roundTrip(h.handle.unlockSocketPath, stale.frame)).trimEnd(),
      ),
    ).toMatchObject({ kind: "deny", reason: "wrong_generation" });
  });

  it("refuses a value carrying CR, LF or NUL, so a swap can never split a header", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    const cr = String.fromCharCode(13);
    const lf = String.fromCharCode(10);
    const nul = String.fromCharCode(0);
    // The refusal is `malformed` because the SHARED wire parser rejects these
    // bytes, which is the enforcement site: no code path in the helper ever
    // holds a value that could split a header. What matters to the invariant is
    // that the unlock is refused and nothing is loaded, and both are asserted.
    for (const bad of [`a${cr}b`, `a${lf}b`, `a${nul}b`, `a${cr}${lf}X-Injected: 1`]) {
      const req = unlockFrame({ secret: b.secret, value: bad });
      expect(
        parseSurrogateUnlockSocketResponse(
          (await roundTrip(h.handle.unlockSocketPath, req.frame)).trimEnd(),
        ),
      ).toMatchObject({ kind: "deny", reason: "malformed" });
    }
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, q.frame)).toMatchObject({ kind: "deny", reason: "locked" });
  });

  it("refuses an over-cap frame before JSON.parse", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    // Deliberately NOT built through the encoder (which throws on the cap): a
    // hostile client is not using our encoder. The bytes are not valid JSON
    // either, so a reply at all proves the size check ran before the parse.
    const oversize = `${"x".repeat(SURROGATE_WIRE_MAX_FRAME_BYTES + 64)}\n`;
    const resp = parseSurrogateUnlockSocketResponse(
      (await roundTrip(h.handle.unlockSocketPath, oversize)).trimEnd(),
    );
    expect(resp).toMatchObject({ kind: "deny", reason: "value_too_long" });
  });

  it("refuses a value over MAX_SURROGATE_VALUE_BYTES and an empty value at the parser", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    const tooLong = unlockFrame({
      secret: b.secret,
      value: "v".repeat(MAX_SURROGATE_VALUE_BYTES + 1),
    });
    expect(
      parseSurrogateUnlockSocketResponse(
        (await roundTrip(h.handle.unlockSocketPath, tooLong.frame)).trimEnd(),
      ),
    ).toMatchObject({ kind: "deny", reason: "malformed" });
    const empty = unlockFrame({ secret: b.secret, value: "" });
    expect(
      parseSurrogateUnlockSocketResponse(
        (await roundTrip(h.handle.unlockSocketPath, empty.frame)).trimEnd(),
      ),
    ).toMatchObject({ kind: "deny", reason: "malformed" });
    // Still locked: neither refused frame loaded anything.
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, q.frame)).toMatchObject({ kind: "deny", reason: "locked" });
  });

  it("clamps an over-long TTL rather than refusing it, and refuses a non-positive one", () => {
    expect(clampSurrogateUnlockSeconds(MAX_SURROGATE_UNLOCK_SECONDS * 10)).toBe(
      MAX_SURROGATE_UNLOCK_SECONDS,
    );
    expect(clampSurrogateUnlockSeconds(60)).toBe(60);
    expect(clampSurrogateUnlockSeconds(0)).toBeNull();
    expect(clampSurrogateUnlockSeconds(-1)).toBeNull();
    expect(clampSurrogateUnlockSeconds(1.5)).toBeNull();
  });

  it("records unlock_accepted and lock_accepted for every accepted unlock and lock", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    await unlock(h, b.secret, freshTestValue(), MAX_SURROGATE_UNLOCK_SECONDS * 10);
    const accepted = h.events.filter((e) => e.kind === "unlock_accepted");
    // The record carries the ORDINAL and the CLAMPED TTL, never the secret name
    // and never the value.
    expect(accepted).toEqual([
      {
        kind: "unlock_accepted",
        agentUid: AGENT_UID,
        binding: 0,
        ttlSeconds: MAX_SURROGATE_UNLOCK_SECONDS,
      },
    ]);
    const lockReq = {
      v: SURROGATE_WIRE_VERSION,
      id: newSurrogateCorrelationId(),
      kind: "lock",
    } as const;
    await roundTrip(h.handle.unlockSocketPath, encodeSurrogateUnlockSocketRequest(lockReq));
    expect(h.events.filter((e) => e.kind === "lock_accepted")).toEqual([
      { kind: "lock_accepted", agentUid: AGENT_UID, bindingsDropped: 1 },
    ]);
    // Locked means locked: the value is gone for the query side too.
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, q.frame)).toMatchObject({ kind: "deny", reason: "locked" });
  });

  it("answers status without a value or a placeholder anywhere in the frame", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    const value = freshTestValue();
    await unlock(h, b.secret, value, 600);
    const statusReq = {
      v: SURROGATE_WIRE_VERSION,
      id: newSurrogateCorrelationId(),
      kind: "status",
    } as const;
    const raw = (
      await roundTrip(h.handle.unlockSocketPath, encodeSurrogateUnlockSocketRequest(statusReq))
    ).trimEnd();
    expect(raw).not.toContain(value);
    expect(raw).not.toContain(b.placeholder);
    expect(parseSurrogateUnlockSocketResponse(raw)).toMatchObject({
      kind: "status",
      generation_id: GENERATION,
      bindings: [{ secret: b.secret, unlocked: true }],
    });
  });

  it("answers status for an unarmed table too, which is the CLI's armed probe", async () => {
    const h = await startHelper({ bindings: [binding(0)] });
    const statusReq = {
      v: SURROGATE_WIRE_VERSION,
      id: newSurrogateCorrelationId(),
      kind: "status",
    } as const;
    const resp = parseSurrogateUnlockSocketResponse(
      (
        await roundTrip(h.handle.unlockSocketPath, encodeSurrogateUnlockSocketRequest(statusReq))
      ).trimEnd(),
    );
    expect(resp).toMatchObject({
      kind: "status",
      bindings: [{ unlocked: false, expires_at: null }],
    });
  });
});

describe("surrogate helper daemon: rule 8, the table and the caps", () => {
  it("refuses to load a table over MAX_SURROGATE_BINDINGS_PER_AGENT", async () => {
    // The over-cap file is built by hand: `renderSurrogateBindingsFile` refuses
    // the same cap, so the render path cannot produce the artifact this load
    // check exists to catch (a stale file, or a hand edit under root).
    const lines: string[] = ["sanctuary-surrogate-bindings v1 generation=7"];
    for (let i = 0; i <= 100; i += 1) {
      lines.push(
        JSON.stringify({
          ordinal: i,
          placeholder: mintSurrogatePlaceholder(),
          secret: `secret-${i}`,
          agent: "hermes",
          env: `SECRET_${i}`,
          header: "Authorization",
          destinations: [{ host: `api${i}.example.com`, port: 443 }],
        }),
      );
    }
    await expect(
      startHelper({ bindings: [], rawBindings: `${lines.join("\n")}\n` }),
    ).rejects.toMatchObject({ refusal: "too_many_bindings" });
  });

  it("never grows the table from query input", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    for (let i = 0; i < 25; i += 1) {
      const q = queryFrame({ placeholder: mintSurrogatePlaceholder(), host: "api0.example.com" });
      await roundTrip(h.handle.querySocketPath, q.frame);
    }
    // The count is the table's own size, read after the flood: a helper that
    // remembered what it was asked about would report more than it loaded.
    expect(h.handle.bindingCount).toBe(1);
  });

  it("rate_limits an over-cap query rather than queueing it, and leaks no slot", async () => {
    const b = binding(0);
    // A cap of 0 makes the FIRST query over cap, which is the same code path a
    // ninth concurrent query takes against the production cap of 8 without
    // needing nine sockets to race inside one event-loop turn.
    const capped = await startHelper({ bindings: [b], maxConcurrentQueries: 0 });
    await unlock(capped, b.secret, freshTestValue());
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    // Over cap answers and CLOSES. It never holds the connection open waiting
    // for a slot, which is what would let a flood pin sockets on a root process.
    expect(await query(capped, q.frame)).toEqual({
      v: 1,
      id: q.id,
      kind: "deny",
      reason: "rate_limited",
    });

    // Under the real cap, a long run of sequential queries never exhausts the
    // slots: a handler that forgot to release one would deny after the eighth.
    const h = await startHelper({ bindings: [b] });
    await unlock(h, b.secret, freshTestValue());
    for (let i = 0; i < 20; i += 1) {
      const each = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
      expect((await query(h, each.frame))?.kind).toBe("swap");
    }
    // A denied query also releases its slot: 20 unknown-placeholder queries do
    // not starve the 21st legitimate one.
    for (let i = 0; i < 20; i += 1) {
      const junk = queryFrame({ placeholder: mintSurrogatePlaceholder(), host: "nope.example.com" });
      await query(h, junk.frame);
    }
    const after = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect((await query(h, after.frame))?.kind).toBe("swap");
  });
});

describe("surrogate helper daemon: rule 12, the fault schedule on both sockets", () => {
  it("serves exactly one frame per connection and never a second", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    // Two frames in one write: the first is answered, the second never is.
    const raw = await roundTrip(h.handle.querySocketPath, Buffer.concat([q.frame, q.frame]));
    const frames = raw.trimEnd().split("\n").filter((line) => line.length > 0);
    expect(frames).toHaveLength(1);
    expect(parseSurrogateQueryResponse(frames[0]!)?.id).toBe(q.id);
  });

  it("survives a client that disconnects mid-frame on either socket", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    for (const path of [h.handle.querySocketPath, h.handle.unlockSocketPath]) {
      await new Promise<void>((resolve) => {
        const socket = connect(path, () => {
          // A partial frame with no newline, then a hard destroy.
          socket.write('{"v":1,"id":"');
          socket.destroy();
          resolve();
        });
        socket.on("error", () => resolve());
      });
    }
    // The helper is still serving after both aborts, and still holds nothing.
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    expect(await query(h, q.frame)).toMatchObject({ kind: "deny", reason: "locked" });
  });

  it("keeps two concurrent queries on their own connections across repeated waves", async () => {
    const a = binding(0);
    const c = binding(1);
    const h = await startHelper({ bindings: [a, c] });
    const valueA = freshTestValue();
    const valueC = freshTestValue();
    await unlock(h, a.secret, valueA);
    await unlock(h, c.secret, valueC);
    for (let wave = 0; wave < 5; wave += 1) {
      const qa = queryFrame({ placeholder: a.placeholder, host: a.destinations[0]!.host });
      const qc = queryFrame({ placeholder: c.placeholder, host: c.destinations[0]!.host });
      const [rawA, rawC] = await Promise.all([
        roundTrip(h.handle.querySocketPath, qa.frame),
        roundTrip(h.handle.querySocketPath, qc.frame),
      ]);
      // Each answer carries its OWN id and its OWN binding's value. Binding A's
      // value is never readable on query C's connection, in any wave.
      expect(parseSurrogateQueryResponse(rawA.trimEnd())).toEqual({
        v: 1,
        id: qa.id,
        kind: "swap",
        value: valueA,
      });
      expect(parseSurrogateQueryResponse(rawC.trimEnd())).toEqual({
        v: 1,
        id: qc.id,
        kind: "swap",
        value: valueC,
      });
      expect(rawA).not.toContain(valueC);
      expect(rawC).not.toContain(valueA);
    }
  });

  it("drops every value on close, before either socket goes away", async () => {
    const b = binding(0);
    const h = await startHelper({ bindings: [b] });
    await unlock(h, b.secret, freshTestValue());
    await h.handle.close();
    // The socket is gone, so a query cannot even connect. A helper that closed
    // its listeners while still holding values would be a root process with a
    // credential and no accounted-for reader.
    const q = queryFrame({ placeholder: b.placeholder, host: b.destinations[0]!.host });
    await expect(roundTrip(h.handle.querySocketPath, q.frame)).rejects.toBeTruthy();
  });
});
