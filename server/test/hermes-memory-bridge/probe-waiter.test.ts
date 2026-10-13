import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  ABANDONED_PROBE_NONCE_CAP,
  HermesProbeWaiter,
  NONCE_PATTERN,
  PROBE_NONCE_BYTES,
  type HermesProbeNonceSource,
  type HermesProbeWaiterResult,
  type HermesProbeWaiterSnapshot,
  PrivateFrameDecoder,
  createNodeCryptoHermesProbeNonceSource,
  parseRelayToNode,
} from "../../src/hermes-memory-bridge/index.js";

type ProbeReplyFrame = {
  readonly kind: "probe_reply";
  readonly connectionId: string;
  readonly nonce: string;
};

type FixtureEntry = {
  readonly name: string;
  readonly frame?: Record<string, unknown>;
  readonly bytes_hex?: string;
};

type ProbeStep =
  | { readonly kind: "start"; readonly entryRef: string; readonly connectionId: string }
  | { readonly kind: "reply"; readonly connectionId: string; readonly nonce: string }
  | { readonly kind: "timeout"; readonly entryRef: string; readonly nonce: string }
  | { readonly kind: "closed"; readonly connectionId: string }
  | { readonly kind: "stop" }
  | { readonly kind: "abandon"; readonly entryRef: string };

const textEncoder = new TextEncoder();
const RELAY_LEGAL_SCHEDULES = 1_200;
const CLOSED_CONNECTION_SCHEDULES = 300;
const BAD_NONCE_SCHEDULES = 300;
const CAP_PRESSURE_SCHEDULES = 800;
const INJECTION_SCHEDULES = 1_200;
const SHORT_PROFILE_STEPS = 120;
const LONG_PROFILE_STEPS = 260;
const ILLEGAL_NONCE_OFFSET = 9_001;
const CAP_PRESSURE_TIMEOUTS = ABANDONED_PROBE_NONCE_CAP;
const PROBE_NONCE_HEX_LENGTH = PROBE_NONCE_BYTES;
const fixtureUrl = new URL("./fixtures/relay-frames.json", import.meta.url);
const relayFixture = JSON.parse(readFileSync(fixtureUrl, "utf8")) as Readonly<Record<string, readonly FixtureEntry[]>>;

function queuedNonceSource(nonces: readonly string[]): HermesProbeNonceSource {
  let index = 0;
  return () => {
    const nonce = nonces[index];
    index += 1;
    if (nonce === undefined) throw new Error("scripted nonce source exhausted");
    return nonce;
  };
}

function nonce(index: number): string {
  return index.toString(16).padStart(PROBE_NONCE_HEX_LENGTH, "0");
}

function waiter(nonces: readonly string[]): HermesProbeWaiter {
  return new HermesProbeWaiter(queuedNonceSource(nonces));
}

function reply(connectionId: string, nonceValue: string): ProbeReplyFrame {
  return { kind: "probe_reply", connectionId, nonce: nonceValue };
}

function pair(connectionId: string, nonceValue: string): { readonly connectionId: string; readonly nonce: string } {
  return { connectionId, nonce: nonceValue };
}

type WaiterInternals = {
  live?: { readonly state: "WAITING"; readonly entryRef: string; readonly connectionId: string; readonly nonce: string };
  abandoned: Array<{ readonly connectionId: string; readonly nonce: string }>;
  drawUsableNonce: () => string | undefined;
};

function expectInvariants(snapshot: HermesProbeWaiterSnapshot): void {
  const liveCount = snapshot.live === undefined ? 0 : 1;
  expect(snapshot.abandoned.length + liveCount).toBeLessThanOrEqual(ABANDONED_PROBE_NONCE_CAP);
  expect(snapshot.abandoned).toHaveLength(new Set(snapshot.abandoned.map((pair) => `${pair.connectionId}\0${pair.nonce}`)).size);
}

function expectSnapshot(machine: HermesProbeWaiter, expected: HermesProbeWaiterSnapshot): void {
  expect(machine.snapshot()).toEqual(expected);
}

function expectResult(
  actual: HermesProbeWaiterResult,
  expected: HermesProbeWaiterResult,
  machine: HermesProbeWaiter,
): void {
  expect(actual).toEqual(expected);
  expectInvariants(machine.snapshot());
}

function startAndNonce(machine: HermesProbeWaiter, entryRef: string, connectionId: string): string {
  const result = machine.start(entryRef, connectionId);
  expect(result.refusal).toBeUndefined();
  expect(result.fatal).toBeUndefined();
  expect(result.actions).toHaveLength(1);
  const action = result.actions[0];
  expect(action?.kind).toBe("send_probe");
  if (action?.kind !== "send_probe") throw new Error("probe was not sent");
  expectInvariants(machine.snapshot());
  return action.nonce;
}

function fillAbandoned(machine: HermesProbeWaiter, count: number, nonceOffset = 0): readonly ProbeReplyFrame[] {
  const pairs: ProbeReplyFrame[] = [];
  for (let index = 0; index < count; index += 1) {
    const entryRef = `entry-${nonceOffset}-${index}`;
    const connectionId = `c${nonceOffset + index + 1}`;
    const issued = startAndNonce(machine, entryRef, connectionId);
    const result = machine.timeout(entryRef, issued);
    expect(result).toEqual({ actions: [{ kind: "refused", entryRef, reason: "timed_out" }] });
    pairs.push(reply(connectionId, issued));
    expectInvariants(machine.snapshot());
  }
  return pairs;
}

function findFixture(name: string): FixtureEntry {
  for (const section of Object.values(relayFixture)) {
    const found = section.find((entry) => entry.name === name);
    if (found !== undefined) return found;
  }
  throw new Error(`fixture not found: ${name}`);
}

function fixtureProbeReplies(name: string): readonly ProbeReplyFrame[] {
  const vector = findFixture(name);
  if (vector.bytes_hex !== undefined) {
    const decoder = new PrivateFrameDecoder();
    decoder.push(Buffer.from(vector.bytes_hex, "hex"));
    const replies: ProbeReplyFrame[] = [];
    for (;;) {
      const decoded = decoder.next();
      if (decoded.kind === "need_more") return replies;
      expect(decoded.kind).toBe("frame");
      if (decoded.kind !== "frame") return replies;
      const parsed = parseRelayToNode(decoded.body);
      expect(parsed.kind).toBe("ok");
      if (parsed.kind === "ok" && parsed.frame.kind === "probe_reply") replies.push(parsed.frame);
    }
  }
  if (vector.frame === undefined) throw new Error(`fixture frame missing: ${name}`);
  const parsed = parseRelayToNode(textEncoder.encode(JSON.stringify(vector.frame)));
  expect(parsed.kind).toBe("ok");
  if (parsed.kind !== "ok" || parsed.frame.kind !== "probe_reply") throw new Error(`fixture is not a probe reply: ${name}`);
  return [parsed.frame];
}

class IndependentProbeModel {
  private live: { readonly entryRef: string; readonly connectionId: string; readonly nonce: string } | undefined;
  private readonly abandoned = new Map<string, ProbeReplyFrame>();
  private stopped = false;

  constructor(private readonly nonceSource: HermesProbeNonceSource) {}

  apply(step: ProbeStep): HermesProbeWaiterResult {
    switch (step.kind) {
      case "start":
        return this.state_START(step.entryRef, step.connectionId);
      case "reply":
        return this.state_REPLY(step.connectionId, step.nonce);
      case "timeout":
        return this.state_TIMEOUT(step.entryRef, step.nonce);
      case "closed":
        return this.state_CLOSED(step.connectionId);
      case "stop":
        return this.state_STOP();
      case "abandon":
        return this.state_ABANDON(step.entryRef);
    }
  }

  snapshot(): HermesProbeWaiterSnapshot {
    return {
      stopped: this.stopped,
      live: this.live === undefined ? undefined : { state: "WAITING", ...this.live },
      abandoned: [...this.abandoned.values()].map((pair) => ({ connectionId: pair.connectionId, nonce: pair.nonce })),
    };
  }

  abandonedPairs(): readonly ProbeReplyFrame[] {
    return [...this.abandoned.values()];
  }

  livePair(): ProbeReplyFrame | undefined {
    return this.live === undefined ? undefined : reply(this.live.connectionId, this.live.nonce);
  }

  private state_START(entryRef: string, connectionId: string): HermesProbeWaiterResult {
    if (this.stopped) return { actions: [], refusal: "stopped" };
    if (this.live?.entryRef === entryRef) this.moveLiveToAbandoned();
    if (this.live !== undefined) return { actions: [], refusal: "probe_busy" };
    if (this.abandoned.size + this.liveCount() >= ABANDONED_PROBE_NONCE_CAP) {
      return { actions: [], refusal: "abandoned_full" };
    }

    const nonceValue = this.drawUsableNonce();
    if (nonceValue === undefined) return { actions: [], refusal: "nonce_unusable" };

    this.live = { entryRef, connectionId, nonce: nonceValue };
    return { actions: [{ kind: "send_probe", connectionId, nonce: nonceValue }] };
  }

  private state_REPLY(connectionId: string, nonceValue: string): HermesProbeWaiterResult {
    if (this.live?.connectionId === connectionId && this.live.nonce === nonceValue) {
      const entryRef = this.live.entryRef;
      this.live = undefined;
      return { actions: [{ kind: "resolved", entryRef }] };
    }

    const key = this.pairKey(connectionId, nonceValue);
    if (this.abandoned.delete(key)) return { actions: [] };

    return { actions: [], fatal: "unmatched_probe_reply" };
  }

  private state_TIMEOUT(entryRef: string, nonceValue: string): HermesProbeWaiterResult {
    if (this.live === undefined || this.live.entryRef !== entryRef || this.live.nonce !== nonceValue) return { actions: [] };
    const live = this.live;
    this.moveLiveToAbandoned();
    return { actions: [{ kind: "refused", entryRef: live.entryRef, reason: "timed_out" }] };
  }

  private state_CLOSED(connectionId: string): HermesProbeWaiterResult {
    if (this.live === undefined || this.live.connectionId !== connectionId) return { actions: [] };
    const live = this.live;
    this.moveLiveToAbandoned();
    return { actions: [{ kind: "refused", entryRef: live.entryRef, reason: "connection_gone" }] };
  }

  private state_STOP(): HermesProbeWaiterResult {
    this.stopped = true;
    if (this.live === undefined) return { actions: [] };
    const live = this.live;
    this.moveLiveToAbandoned();
    return { actions: [{ kind: "refused", entryRef: live.entryRef, reason: "stopped" }] };
  }

  private state_ABANDON(entryRef: string): HermesProbeWaiterResult {
    if (this.live?.entryRef === entryRef) this.moveLiveToAbandoned();
    return { actions: [] };
  }

  private drawUsableNonce(): string | undefined {
    let nonceValue: string;
    try {
      nonceValue = this.nonceSource();
    } catch {
      return undefined;
    }
    if (typeof nonceValue !== "string" || !NONCE_PATTERN.test(nonceValue)) return undefined;
    if (this.live?.nonce === nonceValue) return undefined;
    if ([...this.abandoned.values()].some((candidate) => candidate.nonce === nonceValue)) return undefined;
    return nonceValue;
  }

  private moveLiveToAbandoned(): void {
    if (this.live === undefined) return;
    const abandoned = reply(this.live.connectionId, this.live.nonce);
    this.abandoned.set(this.pairKey(abandoned.connectionId, abandoned.nonce), abandoned);
    this.live = undefined;
  }

  private liveCount(): number {
    return this.live === undefined ? 0 : 1;
  }

  private pairKey(connectionId: string, nonceValue: string): string {
    return `${connectionId}\0${nonceValue}`;
  }
}

function applyProduct(machine: HermesProbeWaiter, step: ProbeStep): HermesProbeWaiterResult {
  switch (step.kind) {
    case "start":
      return machine.start(step.entryRef, step.connectionId);
    case "reply":
      return machine.reply(reply(step.connectionId, step.nonce));
    case "timeout":
      return machine.timeout(step.entryRef, step.nonce);
    case "closed":
      return machine.connectionClosed(step.connectionId);
    case "stop":
      return machine.stop();
    case "abandon":
      return machine.abandon(step.entryRef);
  }
}

function compareStep(product: HermesProbeWaiter, reference: IndependentProbeModel, step: ProbeStep): HermesProbeWaiterResult {
  const actual = applyProduct(product, step);
  const expected = reference.apply(step);
  expect(actual).toEqual(expected);
  expect(product.snapshot()).toEqual(reference.snapshot());
  expectInvariants(product.snapshot());
  return actual;
}

const transitionRows: readonly { readonly name: string; readonly run: () => void }[] = [
  {
    name: "start sends a probe when the waiter has room",
    run: () => {
      const machine = waiter([nonce(1)]);
      expectResult(machine.start("entry-a", "c1"), {
        actions: [{ kind: "send_probe", connectionId: "c1", nonce: nonce(1) }],
      }, machine);
      expectSnapshot(machine, {
        stopped: false,
        live: { state: "WAITING", entryRef: "entry-a", connectionId: "c1", nonce: nonce(1) },
        abandoned: [],
      });
    },
  },
  {
    name: "start refuses after stop without sending",
    run: () => {
      const machine = waiter([nonce(1)]);
      machine.stop();
      expectResult(machine.start("entry-a", "c1"), { actions: [], refusal: "stopped" }, machine);
      expectSnapshot(machine, { stopped: true, live: undefined, abandoned: [] });
    },
  },
  {
    name: "start refuses a different entry while a waiter is live",
    run: () => {
      const machine = waiter([nonce(1), nonce(2)]);
      startAndNonce(machine, "entry-a", "c1");
      expectResult(machine.start("entry-b", "c2"), { actions: [], refusal: "probe_busy" }, machine);
      expectSnapshot(machine, {
        stopped: false,
        live: { state: "WAITING", entryRef: "entry-a", connectionId: "c1", nonce: nonce(1) },
        abandoned: [],
      });
    },
  },
  {
    name: "same entry re-probe abandons the old pair before sending",
    run: () => {
      const machine = waiter([nonce(1), nonce(2)]);
      startAndNonce(machine, "entry-a", "c1");
      expectResult(machine.start("entry-a", "c2"), {
        actions: [{ kind: "send_probe", connectionId: "c2", nonce: nonce(2) }],
      }, machine);
      expectSnapshot(machine, {
        stopped: false,
        live: { state: "WAITING", entryRef: "entry-a", connectionId: "c2", nonce: nonce(2) },
        abandoned: [pair("c1", nonce(1))],
      });
    },
  },
  {
    name: "start refuses when the abandoned pair store is full",
    run: () => {
      const machine = waiter(Array.from({ length: CAP_PRESSURE_TIMEOUTS }, (_, index) => nonce(index + 1)));
      fillAbandoned(machine, ABANDONED_PROBE_NONCE_CAP);
      expectResult(machine.start("entry-full", "c99"), { actions: [], refusal: "abandoned_full" }, machine);
      expect(machine.snapshot().abandoned).toHaveLength(ABANDONED_PROBE_NONCE_CAP);
      expect(machine.snapshot().live).toBeUndefined();
      expect(machine.snapshot().stopped).toBe(false);
    },
  },
  {
    name: "malformed nonce refuses without replacing state",
    run: () => {
      const machine = waiter(["not-a-nonce"]);
      expectResult(machine.start("entry-a", "c1"), { actions: [], refusal: "nonce_unusable" }, machine);
      expectSnapshot(machine, { stopped: false, live: undefined, abandoned: [] });
    },
  },
  {
    name: "matching reply resolves the live waiter",
    run: () => {
      const machine = waiter([nonce(1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      expectResult(machine.reply(reply("c1", issued)), { actions: [{ kind: "resolved", entryRef: "entry-a" }] }, machine);
      expectSnapshot(machine, { stopped: false, live: undefined, abandoned: [] });
    },
  },
  {
    name: "abandoned reply drains only its own pair",
    run: () => {
      const machine = waiter([nonce(1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      machine.timeout("entry-a", issued);
      expectResult(machine.reply(reply("c1", issued)), { actions: [] }, machine);
      expectSnapshot(machine, { stopped: false, live: undefined, abandoned: [] });
    },
  },
  {
    name: "unmatched reply is fatal and leaves state unchanged",
    run: () => {
      const machine = waiter([nonce(1)]);
      startAndNonce(machine, "entry-a", "c1");
      const before = machine.snapshot();
      expectResult(machine.reply(reply("c1", nonce(2))), { actions: [], fatal: "unmatched_probe_reply" }, machine);
      expect(machine.snapshot()).toEqual(before);
    },
  },
  {
    name: "matching timeout refuses and abandons the live pair",
    run: () => {
      const machine = waiter([nonce(1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      expectResult(machine.timeout("entry-a", issued), {
        actions: [{ kind: "refused", entryRef: "entry-a", reason: "timed_out" }],
      }, machine);
      expectSnapshot(machine, { stopped: false, live: undefined, abandoned: [pair("c1", issued)] });
    },
  },
  {
    name: "stale timeout is a no-op",
    run: () => {
      const machine = waiter([nonce(1)]);
      startAndNonce(machine, "entry-a", "c1");
      const before = machine.snapshot();
      expectResult(machine.timeout("entry-a", nonce(2)), { actions: [] }, machine);
      expect(machine.snapshot()).toEqual(before);
    },
  },
  {
    name: "closed connection refuses and abandons its live waiter",
    run: () => {
      const machine = waiter([nonce(1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      expectResult(machine.connectionClosed("c1"), {
        actions: [{ kind: "refused", entryRef: "entry-a", reason: "connection_gone" }],
      }, machine);
      expectSnapshot(machine, { stopped: false, live: undefined, abandoned: [pair("c1", issued)] });
    },
  },
  {
    name: "closed connection without a live waiter is a no-op",
    run: () => {
      const machine = waiter([nonce(1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      machine.timeout("entry-a", issued);
      const before = machine.snapshot();
      expectResult(machine.connectionClosed("c1"), { actions: [] }, machine);
      expect(machine.snapshot()).toEqual(before);
    },
  },
  {
    name: "stop refuses a live waiter and preserves late-reply lookup",
    run: () => {
      const machine = waiter([nonce(1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      expectResult(machine.stop(), {
        actions: [{ kind: "refused", entryRef: "entry-a", reason: "stopped" }],
      }, machine);
      expectSnapshot(machine, { stopped: true, live: undefined, abandoned: [pair("c1", issued)] });
      expectResult(machine.reply(reply("c1", issued)), { actions: [] }, machine);
      expectResult(machine.reply(reply("c9", nonce(9))), { actions: [], fatal: "unmatched_probe_reply" }, machine);
    },
  },
];

describe("Hermes probe waiter transition table", () => {
  for (const row of transitionRows) {
    it(row.name, row.run);
  }

  it("constructor refuses a missing or non-callable nonce source", () => {
    expect(() => new HermesProbeWaiter(undefined as unknown as HermesProbeNonceSource)).toThrow(TypeError);
    expect(() => new HermesProbeWaiter("not-callable" as unknown as HermesProbeNonceSource)).toThrow(TypeError);
  });
});

describe("Hermes probe waiter schedules", () => {
  it("refused re-probe leaves no live waiter and keeps the old pair drainable", () => {
    const nonces = Array.from({ length: ABANDONED_PROBE_NONCE_CAP }, (_, index) => nonce(index + 1));
    const machine = waiter(nonces);
    fillAbandoned(machine, ABANDONED_PROBE_NONCE_CAP - 1);
    const liveNonce = startAndNonce(machine, "entry-live", "c50");
    expectResult(machine.start("entry-live", "c51"), { actions: [], refusal: "abandoned_full" }, machine);
    expect(machine.snapshot().live).toBeUndefined();
    expect(machine.snapshot().abandoned).toHaveLength(ABANDONED_PROBE_NONCE_CAP);
    expectResult(machine.reply(reply("c50", liveNonce)), { actions: [] }, machine);
  });

  it("nonce collision during re-probe leaves no live waiter and keeps the old pair drainable", () => {
    const machine = waiter([nonce(1), nonce(1)]);
    const oldNonce = startAndNonce(machine, "entry-live", "c1");
    expectResult(machine.start("entry-live", "c2"), { actions: [], refusal: "nonce_unusable" }, machine);
    expect(machine.snapshot().live).toBeUndefined();
    expect(machine.snapshot().abandoned).toEqual([pair("c1", oldNonce)]);
    expectResult(machine.reply(reply("c1", oldNonce)), { actions: [] }, machine);
  });

  it("nonce draw refuses a nonce already held by the live waiter", () => {
    const machine = waiter([nonce(1), nonce(1)]);
    startAndNonce(machine, "entry-live", "c1");
    const internal = machine as unknown as WaiterInternals;
    expect(internal.drawUsableNonce()).toBeUndefined();
    expectSnapshot(machine, {
      stopped: false,
      live: { state: "WAITING", entryRef: "entry-live", connectionId: "c1", nonce: nonce(1) },
      abandoned: [],
    });
  });

  it("nonce source failure refuses without leaving a live waiter", () => {
    const machine = new HermesProbeWaiter(() => {
      throw new Error("nonce source unavailable");
    });
    expectResult(machine.start("entry-a", "c1"), { actions: [], refusal: "nonce_unusable" }, machine);
    expectSnapshot(machine, { stopped: false, live: undefined, abandoned: [] });
  });

  it("stale timeout after re-probe leaves the new waiter resolvable", () => {
    const machine = waiter([nonce(1), nonce(2)]);
    const oldNonce = startAndNonce(machine, "entry-live", "c1");
    const newStart = machine.start("entry-live", "c2");
    expect(newStart.actions[0]).toEqual({ kind: "send_probe", connectionId: "c2", nonce: nonce(2) });
    expectResult(machine.timeout("entry-live", oldNonce), { actions: [] }, machine);
    expectResult(machine.reply(reply("c2", nonce(2))), { actions: [{ kind: "resolved", entryRef: "entry-live" }] }, machine);
  });

  it("wrong nonce or wrong connection on a live waiter is fatal without mutation", () => {
    const machine = waiter([nonce(1)]);
    startAndNonce(machine, "entry-live", "c1");
    const beforeNonce = machine.snapshot();
    expectResult(machine.reply(reply("c1", nonce(9))), { actions: [], fatal: "unmatched_probe_reply" }, machine);
    expect(machine.snapshot()).toEqual(beforeNonce);
    expectResult(machine.reply(reply("c2", nonce(1))), { actions: [], fatal: "unmatched_probe_reply" }, machine);
    expect(machine.snapshot()).toEqual(beforeNonce);
  });

  it("matching live pair resolves before consulting abandoned pairs", () => {
    const machine = waiter([nonce(1)]);
    startAndNonce(machine, "entry-live", "c1");
    const internal = machine as unknown as WaiterInternals;
    internal.abandoned.push(pair("c1", nonce(1)));
    expectResult(machine.reply(reply("c1", nonce(1))), { actions: [{ kind: "resolved", entryRef: "entry-live" }] }, machine);
    expect(machine.snapshot().abandoned).toEqual([pair("c1", nonce(1))]);
  });

  it("abandoned nonce under another connection is fatal and keeps the pair drainable", () => {
    const machine = waiter([nonce(1)]);
    const issued = startAndNonce(machine, "entry-a", "c1");
    machine.abandon("entry-a");
    const beforeWrongConnection = machine.snapshot();
    expectResult(machine.reply(reply("c2", issued)), { actions: [], fatal: "unmatched_probe_reply" }, machine);
    expect(machine.snapshot()).toEqual(beforeWrongConnection);
    expectResult(machine.reply(reply("c1", issued)), { actions: [] }, machine);
    expectSnapshot(machine, { stopped: false, live: undefined, abandoned: [] });
  });

  it("never-issued nonce on an abandoned connection is fatal and keeps the pair drainable", () => {
    const machine = waiter([nonce(1)]);
    const issued = startAndNonce(machine, "entry-a", "c1");
    machine.abandon("entry-a");
    const beforeWrongNonce = machine.snapshot();
    expectResult(machine.reply(reply("c1", nonce(2))), { actions: [], fatal: "unmatched_probe_reply" }, machine);
    expect(machine.snapshot()).toEqual(beforeWrongNonce);
    expectResult(machine.reply(reply("c1", issued)), { actions: [] }, machine);
    expectSnapshot(machine, { stopped: false, live: undefined, abandoned: [] });
  });

  it("closed for another connection leaves the live waiter resolvable", () => {
    const machine = waiter([nonce(1)]);
    const issued = startAndNonce(machine, "entry-live", "c1");
    expectResult(machine.connectionClosed("c2"), { actions: [] }, machine);
    expectResult(machine.reply(reply("c1", issued)), { actions: [{ kind: "resolved", entryRef: "entry-live" }] }, machine);
  });

  it("timeout then start then stop lets the first reply drain later", () => {
    const machine = waiter([nonce(1), nonce(2)]);
    const first = startAndNonce(machine, "entry-a", "c1");
    machine.timeout("entry-a", first);
    startAndNonce(machine, "entry-b", "c2");
    machine.stop();
    expectResult(machine.reply(reply("c1", first)), { actions: [] }, machine);
  });

  it("after stop only start refuses while passive events stay quiet", () => {
    const machine = waiter([nonce(1)]);
    expectResult(machine.stop(), { actions: [] }, machine);
    expectResult(machine.start("entry-a", "c1"), { actions: [], refusal: "stopped" }, machine);
    expectResult(machine.stop(), { actions: [] }, machine);
    expectResult(machine.timeout("entry-a", nonce(1)), { actions: [] }, machine);
    expectResult(machine.connectionClosed("c1"), { actions: [] }, machine);
    expectResult(machine.abandon("entry-a"), { actions: [] }, machine);
  });

  it("caller abandon preserves the pair for a late reply", () => {
    const machine = waiter([nonce(1)]);
    const issued = startAndNonce(machine, "entry-a", "c1");
    expectResult(machine.abandon("entry-a"), { actions: [] }, machine);
    expect(machine.snapshot().abandoned).toEqual([pair("c1", issued)]);
    expectResult(machine.reply(reply("c1", issued)), { actions: [] }, machine);
  });

  it("caller abandon for another entry leaves the live waiter resolvable", () => {
    const machine = waiter([nonce(1)]);
    const issued = startAndNonce(machine, "entry-b", "c1");
    const before = machine.snapshot();
    expectResult(machine.abandon("entry-a"), { actions: [] }, machine);
    expect(machine.snapshot()).toEqual(before);
    expectResult(machine.reply(reply("c1", issued)), { actions: [{ kind: "resolved", entryRef: "entry-b" }] }, machine);
  });

  it("sixteen abandoned pairs refuse every start until a reply drains one slot", () => {
    const nonces = Array.from({ length: ABANDONED_PROBE_NONCE_CAP + 1 }, (_, index) => nonce(index + 1));
    const machine = waiter(nonces);
    const pairs = fillAbandoned(machine, ABANDONED_PROBE_NONCE_CAP);
    let capPressureRefusals = 0;
    for (const entryRef of ["entry-a", "entry-b", "entry-c"]) {
      const result = machine.start(entryRef, "c90");
      if (result.refusal === "abandoned_full") capPressureRefusals += 1;
      expectResult(result, { actions: [], refusal: "abandoned_full" }, machine);
    }
    expect(capPressureRefusals).toBe(3);
    expectResult(machine.reply(pairs[0]!), { actions: [] }, machine);
    expectResult(machine.start("entry-after-drain", "c91"), {
      actions: [{ kind: "send_probe", connectionId: "c91", nonce: nonce(ABANDONED_PROBE_NONCE_CAP + 1) }],
    }, machine);
  });

  it("a second reply for a consumed pair is fatal", () => {
    const machine = waiter([nonce(1)]);
    const issued = startAndNonce(machine, "entry-a", "c1");
    expectResult(machine.reply(reply("c1", issued)), { actions: [{ kind: "resolved", entryRef: "entry-a" }] }, machine);
    expectResult(machine.reply(reply("c1", issued)), { actions: [], fatal: "unmatched_probe_reply" }, machine);
  });
});

describe("Hermes probe waiter production nonce source", () => {
  it("draws distinct lowercase hex nonces and can issue a probe", () => {
    const source = createNodeCryptoHermesProbeNonceSource();
    const first = source();
    const second = source();
    expect(first).toMatch(NONCE_PATTERN);
    expect(second).toMatch(NONCE_PATTERN);
    expect(second).not.toBe(first);

    const machine = new HermesProbeWaiter(createNodeCryptoHermesProbeNonceSource());
    const result = machine.start("entry-a", "c1");
    expect(result.refusal).toBeUndefined();
    expect(result.actions[0]?.kind).toBe("send_probe");
    expect(result.actions[0]?.kind === "send_probe" ? result.actions[0].nonce : "").toMatch(NONCE_PATTERN);
  });
});

describe("Hermes probe waiter relay probe reply fixtures", () => {
  it("relay probe reply resolves a matching live waiter", () => {
    const fixtureReply = fixtureProbeReplies("relay probe reply")[0]!;
    const machine = waiter([fixtureReply.nonce]);
    startAndNonce(machine, "entry-a", fixtureReply.connectionId);
    expectResult(machine.reply(fixtureReply), { actions: [{ kind: "resolved", entryRef: "entry-a" }] }, machine);
  });

  it("relay closed then late probe reply drains the abandoned pair", () => {
    const fixtureReply = fixtureProbeReplies("relay closed then late probe reply")[0]!;
    const machine = waiter([fixtureReply.nonce]);
    startAndNonce(machine, "entry-a", fixtureReply.connectionId);
    machine.connectionClosed(fixtureReply.connectionId);
    expectResult(machine.reply(fixtureReply), { actions: [] }, machine);
  });

  it("relay probe reply after timeout drains the abandoned pair", () => {
    const fixtureReply = fixtureProbeReplies("relay probe reply after timeout")[0]!;
    const machine = waiter([fixtureReply.nonce]);
    startAndNonce(machine, "entry-a", fixtureReply.connectionId);
    machine.timeout("entry-a", fixtureReply.nonce);
    expectResult(machine.reply(fixtureReply), { actions: [] }, machine);
  });

  it("relay probe reply without a matching pair is fatal", () => {
    const fixtureReply = fixtureProbeReplies("relay probe reply never accepted connection")[0]!;
    const machine = waiter([nonce(1)]);
    expectResult(machine.reply(fixtureReply), { actions: [], fatal: "unmatched_probe_reply" }, machine);
  });
});

function rng(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 4_294_967_296;
  };
}

type NonceDraw = string | Error | number;

class DualRun {
  readonly product: HermesProbeWaiter;
  readonly reference: IndependentProbeModel;
  private readonly draws: NonceDraw[] = [];
  private productDrawIndex = 0;
  private referenceDrawIndex = 0;

  constructor(private readonly draw: (index: number, run: DualRun) => NonceDraw) {
    this.product = new HermesProbeWaiter(this.source("product"));
    this.reference = new IndependentProbeModel(this.source("reference"));
  }

  step(step: ProbeStep): HermesProbeWaiterResult {
    const result = compareStep(this.product, this.reference, step);
    this.countResult(step.kind, result);
    return result;
  }

  snapshot(): HermesProbeWaiterSnapshot {
    return this.product.snapshot();
  }

  livePair(): ProbeReplyFrame | undefined {
    return this.reference.livePair();
  }

  abandonedPairs(): readonly ProbeReplyFrame[] {
    return this.reference.abandonedPairs();
  }

  private source(which: "product" | "reference"): HermesProbeNonceSource {
    return () => {
      const drawIndex = which === "product" ? this.productDrawIndex : this.referenceDrawIndex;
      if (which === "product") this.productDrawIndex += 1;
      else this.referenceDrawIndex += 1;
      if (this.draws[drawIndex] === undefined) this.draws[drawIndex] = this.draw(drawIndex, this);
      const value = this.draws[drawIndex]!;
      if (value instanceof Error) throw value;
      return value as string;
    };
  }

  private countResult(stepKind: ProbeStep["kind"], result: HermesProbeWaiterResult): void {
    fuzzStats.steps += 1;
    if (result.fatal !== undefined) fuzzStats.fatals += 1;
    if (result.refusal !== undefined) fuzzStats.refusals[result.refusal] += 1;
    const first = result.actions[0];
    if (first?.kind === "refused") fuzzStats.terminals[first.reason] += 1;
    if (first?.kind === "resolved") fuzzStats.resolved += 1;
    fuzzStats.byStep[stepKind] += 1;
  }
}

type FuzzStats = {
  steps: number;
  fatals: number;
  resolved: number;
  refusals: Record<NonNullable<HermesProbeWaiterResult["refusal"]>, number>;
  terminals: Record<"timed_out" | "connection_gone" | "stopped", number>;
  byStep: Record<ProbeStep["kind"], number>;
  schedules: Record<string, number>;
  coverage: {
    abandonedFullSchedules: number;
    probeBusy: number;
    nonceUnusable: number;
    injected: number;
    injectionKinds: Record<InjectionKind, number>;
  };
};

type InjectionKind =
  | "never_issued_nonce"
  | "issued_nonce_other_connection"
  | "second_reply_consumed_pair"
  | "abandoned_nonce_other_connection"
  | "never_issued_live_connection";

const injectionKinds: readonly InjectionKind[] = [
  "never_issued_nonce",
  "issued_nonce_other_connection",
  "second_reply_consumed_pair",
  "abandoned_nonce_other_connection",
  "never_issued_live_connection",
];

const fuzzStats: FuzzStats = {
  steps: 0,
  fatals: 0,
  resolved: 0,
  refusals: { stopped: 0, probe_busy: 0, abandoned_full: 0, nonce_unusable: 0 },
  terminals: { timed_out: 0, connection_gone: 0, stopped: 0 },
  byStep: { start: 0, reply: 0, timeout: 0, closed: 0, stop: 0, abandon: 0 },
  schedules: { relayLegal: 0, closedConnection: 0, badNonce: 0, capPressure: 0, injection: 0 },
  coverage: {
    abandonedFullSchedules: 0,
    probeBusy: 0,
    nonceUnusable: 0,
    injected: 0,
    injectionKinds: {
      never_issued_nonce: 0,
      issued_nonce_other_connection: 0,
      second_reply_consumed_pair: 0,
      abandoned_nonce_other_connection: 0,
      never_issued_live_connection: 0,
    },
  },
};

function makeNonceDraw(seed: number, badRate: number): (index: number, run: DualRun) => NonceDraw {
  const random = rng(seed * 7_919 + 11);
  let counter = 0;
  return (_index, run) => {
    if (random() < badRate) {
      const badKind = Math.floor(random() * 8);
      const abandoned = run.abandonedPairs();
      if (badKind === 0) return "0123456789ABCDEF0123456789ABCDEF";
      if (badKind === 1) return "a".repeat(PROBE_NONCE_HEX_LENGTH - 1);
      if (badKind === 2) return "a".repeat(PROBE_NONCE_HEX_LENGTH + 1);
      if (badKind === 3) return new Error("nonce source unavailable");
      if (badKind === 4) return 7;
      if (badKind === 5) return `${"a".repeat(PROBE_NONCE_HEX_LENGTH)}\n`;
      if (badKind === 6 && abandoned.length > 0) return abandoned[Math.floor(random() * abandoned.length)]!.nonce;
    }
    counter += 1;
    return `${counter.toString(16)}e`.padStart(PROBE_NONCE_HEX_LENGTH, "0");
  };
}

type LegalOptions = {
  readonly steps: number;
  readonly profile: keyof FuzzStats["schedules"];
  readonly seed: number;
  readonly probeClosed?: boolean;
  readonly badNonceRate?: number;
  readonly weights?: Partial<Record<"accept" | "start" | "relay" | "hangup" | "timer" | "abandon" | "shutdown" | "node", number>>;
};

function chooseBand(random: () => number, weights: LegalOptions["weights"]): string {
  const bands: readonly (readonly [string, number])[] = [
    ["accept", weights?.accept ?? 0.08],
    ["start", weights?.start ?? 0.17],
    ["relay", weights?.relay ?? 0.20],
    ["hangup", weights?.hangup ?? 0.07],
    ["timer", weights?.timer ?? 0.10],
    ["abandon", weights?.abandon ?? 0.03],
    ["shutdown", weights?.shutdown ?? 0.004],
    ["node", weights?.node ?? 0.35],
  ];
  let point = random() * bands.reduce((sum, [, weight]) => sum + weight, 0);
  for (const [band, weight] of bands) {
    if (point < weight) return band;
    point -= weight;
  }
  return "node";
}

function runLegalSchedule(options: LegalOptions): { readonly reachedFull: boolean } {
  fuzzStats.schedules[options.profile] += 1;
  const random = rng(options.seed);
  const run = new DualRun(makeNonceDraw(options.seed, options.badNonceRate ?? 0));
  const relayConnections: string[] = [];
  const relayClosed = new Set<string>();
  const nodeAccepted = new Set<string>();
  const nodeClosed = new Set<string>();
  const toRelay: ProbeReplyFrame[] = [];
  const toNode: Array<["accepted", string] | ["closed", string] | ["probe_reply", string, string] | ["relay_shutdown"]> = [];
  const timers: Array<{ readonly entryRef: string; readonly nonce: string }> = [];
  let nextConnection = 1;
  let nextEntry = 1;
  let current: { readonly entryRef: string; readonly connectionId: string } | undefined;
  let stopped = false;
  let shutdownSent = false;
  let reachedFull = false;

  for (let index = 0; index < options.steps; index += 1) {
    const band = chooseBand(random, options.weights);
    if (band === "accept") {
      if (!shutdownSent && relayConnections.filter((connectionId) => !relayClosed.has(connectionId)).length < 4) {
        const connectionId = `c${nextConnection}`;
        nextConnection += 1;
        relayConnections.push(connectionId);
        toNode.push(["accepted", connectionId]);
      }
    } else if (band === "start") {
      const open = [...nodeAccepted].filter((connectionId) => !nodeClosed.has(connectionId));
      const pool = options.probeClosed ? [...nodeAccepted] : open;
      if (pool.length === 0) continue;
      const reuseCurrent = current !== undefined && random() < 0.45;
      const reused = reuseCurrent ? current : undefined;
      const entryRef = reused?.entryRef ?? `entry-${options.seed}-${nextEntry}`;
      const connectionId = reused !== undefined && random() < 0.4 ? reused.connectionId : pool[Math.floor(random() * pool.length)]!;
      nextEntry += reuseCurrent ? 0 : 1;
      current = { entryRef, connectionId };
      const result = run.step({ kind: "start", entryRef, connectionId });
      if (result.refusal === "probe_busy") fuzzStats.coverage.probeBusy += 1;
      if (result.refusal === "abandoned_full") {
        reachedFull = true;
        fuzzStats.coverage.abandonedFullSchedules += 1;
      }
      if (result.refusal === "nonce_unusable") fuzzStats.coverage.nonceUnusable += 1;
      const sent = result.actions[0];
      if (sent?.kind === "send_probe") {
        const issued = reply(sent.connectionId, sent.nonce);
        timers.push({ entryRef, nonce: sent.nonce });
        if (nodeClosed.has(sent.connectionId)) toNode.push(["probe_reply", sent.connectionId, sent.nonce]);
        else toRelay.push(issued);
      }
    } else if (band === "relay") {
      const issued = toRelay.shift();
      if (issued === undefined) continue;
      if (!relayClosed.has(issued.connectionId) && random() < 0.3) {
        relayClosed.add(issued.connectionId);
        toNode.push(["closed", issued.connectionId]);
      }
      toNode.push(["probe_reply", issued.connectionId, issued.nonce]);
    } else if (band === "hangup") {
      if (shutdownSent) continue;
      const open = relayConnections.filter((connectionId) => !relayClosed.has(connectionId));
      if (open.length === 0) continue;
      const connectionId = open[Math.floor(random() * open.length)]!;
      relayClosed.add(connectionId);
      toNode.push(["closed", connectionId]);
    } else if (band === "timer") {
      const timer = timers.splice(Math.floor(random() * timers.length), 1)[0];
      if (timer !== undefined) run.step({ kind: "timeout", entryRef: timer.entryRef, nonce: timer.nonce });
    } else if (band === "abandon") {
      if (current === undefined) continue;
      const entryRef = random() < 0.8 ? current.entryRef : `entry-${options.seed}-${Math.floor(random() * (nextEntry + 1))}`;
      run.step({ kind: "abandon", entryRef });
    } else if (band === "shutdown") {
      if (!shutdownSent) {
        shutdownSent = true;
        toNode.push(["relay_shutdown"]);
      }
    } else {
      const frame = toNode.shift();
      if (frame === undefined) continue;
      if (frame[0] === "accepted") nodeAccepted.add(frame[1]);
      else if (frame[0] === "closed") {
        nodeClosed.add(frame[1]);
        run.step({ kind: "closed", connectionId: frame[1] });
      } else if (frame[0] === "probe_reply") {
        const result = run.step({ kind: "reply", connectionId: frame[1], nonce: frame[2] });
        expect(result.fatal).toBeUndefined();
      } else {
        stopped = true;
        run.step({ kind: "stop" });
        if (random() < 0.3) run.step({ kind: "stop" });
      }
    }
    if (stopped && random() < 0.9) continue;
  }

  while (toRelay.length > 0) {
    const issued = toRelay.shift()!;
    toNode.push(["probe_reply", issued.connectionId, issued.nonce]);
  }
  while (toNode.length > 0) {
    const frame = toNode.shift()!;
    if (frame[0] === "accepted") nodeAccepted.add(frame[1]);
    else if (frame[0] === "closed") run.step({ kind: "closed", connectionId: frame[1] });
    else if (frame[0] === "probe_reply") {
      const result = run.step({ kind: "reply", connectionId: frame[1], nonce: frame[2] });
      expect(result.fatal).toBeUndefined();
    } else {
      run.step({ kind: "stop" });
    }
  }
  if (run.snapshot().live === undefined) expect(run.snapshot().abandoned).toHaveLength(0);
  return { reachedFull };
}

function injectionFrame(kind: InjectionKind, run: DualRun, fallbackNonce: string): ProbeReplyFrame {
  const live = run.livePair();
  const abandoned = run.abandonedPairs()[0];
  if (kind === "never_issued_nonce") return reply("c999", nonce(ILLEGAL_NONCE_OFFSET));
  if (kind === "issued_nonce_other_connection") return reply("c999", live?.nonce ?? fallbackNonce);
  if (kind === "second_reply_consumed_pair") return live ?? reply("c1", fallbackNonce);
  if (kind === "abandoned_nonce_other_connection") return reply("c999", abandoned?.nonce ?? fallbackNonce);
  return reply(live?.connectionId ?? "c1", nonce(ILLEGAL_NONCE_OFFSET + 1));
}

function runInjectionSchedule(seed: number): void {
  fuzzStats.schedules.injection += 1;
  const kind = injectionKinds[seed % injectionKinds.length]!;
  const run = new DualRun(makeNonceDraw(seed + 50_000, 0));
  const connectionId = `c${(seed % 5) + 1}`;
  const start = run.step({ kind: "start", entryRef: `entry-${seed}`, connectionId });
  const sent = start.actions[0];
  expect(sent?.kind).toBe("send_probe");
  if (sent?.kind !== "send_probe") return;

  if (kind === "second_reply_consumed_pair") {
    run.step({ kind: "reply", connectionId: sent.connectionId, nonce: sent.nonce });
  } else if (kind === "abandoned_nonce_other_connection") {
    run.step(seed % 2 === 0 ? { kind: "timeout", entryRef: `entry-${seed}`, nonce: sent.nonce } : { kind: "abandon", entryRef: `entry-${seed}` });
  }

  const frame = injectionFrame(kind, run, sent.nonce);
  const before = run.snapshot();
  const result = run.step({ kind: "reply", connectionId: frame.connectionId, nonce: frame.nonce });
  expect(result).toEqual({ actions: [], fatal: "unmatched_probe_reply" });
  expect(run.snapshot()).toEqual(before);
  fuzzStats.coverage.injected += 1;
  fuzzStats.coverage.injectionKinds[kind] += 1;
}

describe("Hermes probe waiter independent schedule oracle", () => {
  it("matches the independent model across relay-legal profiles", () => {
    for (let seed = 1; seed <= RELAY_LEGAL_SCHEDULES; seed += 1) {
      runLegalSchedule({ profile: "relayLegal", seed, steps: SHORT_PROFILE_STEPS });
    }
    for (let seed = 1; seed <= CLOSED_CONNECTION_SCHEDULES; seed += 1) {
      runLegalSchedule({ profile: "closedConnection", seed: seed + 10_000, steps: SHORT_PROFILE_STEPS, probeClosed: true });
    }
    for (let seed = 1; seed <= BAD_NONCE_SCHEDULES; seed += 1) {
      runLegalSchedule({ profile: "badNonce", seed: seed + 20_000, steps: SHORT_PROFILE_STEPS, badNonceRate: 0.18 });
    }
    expect(fuzzStats.coverage.probeBusy).toBeGreaterThan(0);
    expect(fuzzStats.coverage.nonceUnusable).toBeGreaterThan(0);
  });

  it("matches the independent model under cap pressure", () => {
    for (let seed = 1; seed <= CAP_PRESSURE_SCHEDULES; seed += 1) {
      runLegalSchedule({
        profile: "capPressure",
        seed: seed + 30_000,
        steps: LONG_PROFILE_STEPS,
        weights: { accept: 0.05, start: 0.34, relay: 0.02, timer: 0.28, hangup: 0.02, abandon: 0.04, node: 0.25 },
      });
    }
    expect(fuzzStats.coverage.abandonedFullSchedules).toBeGreaterThan(0);
  });

  it("keeps state unchanged for illegal probe replies inserted into schedules", () => {
    for (let seed = 1; seed <= INJECTION_SCHEDULES; seed += 1) {
      runInjectionSchedule(seed);
    }
    expect(fuzzStats.coverage.injected).toBe(INJECTION_SCHEDULES);
    for (const kind of injectionKinds) {
      expect(fuzzStats.coverage.injectionKinds[kind]).toBeGreaterThan(0);
    }
  });

  it("records profile and coverage counts for the fix-round report", () => {
    expect(fuzzStats.schedules).toEqual({
      relayLegal: RELAY_LEGAL_SCHEDULES,
      closedConnection: CLOSED_CONNECTION_SCHEDULES,
      badNonce: BAD_NONCE_SCHEDULES,
      capPressure: CAP_PRESSURE_SCHEDULES,
      injection: INJECTION_SCHEDULES,
    });
    expect(fuzzStats.coverage.probeBusy).toBeGreaterThan(0);
    expect(fuzzStats.coverage.nonceUnusable).toBeGreaterThan(0);
    expect(fuzzStats.coverage.abandonedFullSchedules).toBeGreaterThan(0);
    expect(fuzzStats.coverage.injected).toBe(INJECTION_SCHEDULES);
  });
});
