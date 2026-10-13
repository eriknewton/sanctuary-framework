import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  ABANDONED_PROBE_NONCE_CAP,
  HermesProbeWaiter,
  type HermesProbeNonceSource,
  type HermesProbeWaiterResult,
  type HermesProbeWaiterSnapshot,
  PrivateFrameDecoder,
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
const LEGAL_FUZZ_SCHEDULES = 3_000;
const ILLEGAL_FUZZ_SCHEDULES = 3_000;
const FUZZ_ATTEMPT_VARIANTS = 6;
const ILLEGAL_NONCE_OFFSET = 9_001;
const CAP_PRESSURE_TIMEOUTS = ABANDONED_PROBE_NONCE_CAP;
const fixtureUrl = new URL("./fixtures/relay-frames.json", import.meta.url);
const relayFixture = JSON.parse(readFileSync(fixtureUrl, "utf8")) as Readonly<Record<string, readonly FixtureEntry[]>>;

function queuedNonceSource(nonces: readonly string[]): HermesProbeNonceSource {
  let index = 0;
  return () => {
    const nonce = nonces[index];
    index += 1;
    if (nonce === undefined) return "f".repeat(32);
    return nonce;
  };
}

function nonce(index: number): string {
  return index.toString(16).padStart(32, "0");
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

function removePending(pairs: ProbeReplyFrame[], target: ProbeReplyFrame): void {
  const index = pairs.findIndex((candidate) => candidate.connectionId === target.connectionId && candidate.nonce === target.nonce);
  if (index >= 0) pairs.splice(index, 1);
}

function expectInvariants(snapshot: HermesProbeWaiterSnapshot): void {
  const liveCount = snapshot.live === undefined ? 0 : 1;
  expect(snapshot.abandoned.length + liveCount).toBeLessThanOrEqual(ABANDONED_PROBE_NONCE_CAP);
  expect(snapshot.abandoned).toHaveLength(new Set(snapshot.abandoned.map((pair) => `${pair.connectionId}\0${pair.nonce}`)).size);
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

class ReferenceWaiter {
  private live: { entryRef: string; connectionId: string; nonce: string } | undefined;
  private readonly abandoned: ProbeReplyFrame[] = [];
  private stopped = false;

  constructor(private readonly nonceSource: HermesProbeNonceSource) {}

  apply(step: ProbeStep): HermesProbeWaiterResult {
    switch (step.kind) {
      case "start":
        return this.start(step.entryRef, step.connectionId);
      case "reply":
        return this.reply(step.connectionId, step.nonce);
      case "timeout":
        return this.timeout(step.entryRef, step.nonce);
      case "closed":
        return this.closed(step.connectionId);
      case "stop":
        return this.stop();
      case "abandon":
        return this.abandon(step.entryRef);
    }
  }

  snapshot(): HermesProbeWaiterSnapshot {
    return {
      stopped: this.stopped,
      live: this.live === undefined ? undefined : { state: "WAITING", ...this.live },
      abandoned: this.abandoned.map((pair) => ({ connectionId: pair.connectionId, nonce: pair.nonce })),
    };
  }

  private start(entryRef: string, connectionId: string): HermesProbeWaiterResult {
    if (this.stopped) return { actions: [], refusal: "stopped" };
    if (this.live?.entryRef === entryRef) {
      this.abandoned.push(reply(this.live.connectionId, this.live.nonce));
      this.live = undefined;
    }
    if (this.live !== undefined) return { actions: [], refusal: "probe_busy" };
    if (this.abandoned.length >= ABANDONED_PROBE_NONCE_CAP) {
      return { actions: [], refusal: "abandoned_full" };
    }
    let nonceValue: string;
    try {
      nonceValue = this.nonceSource();
    } catch {
      return { actions: [], refusal: "nonce_unusable" };
    }
    if (!/^[0-9a-f]{32}$/u.test(nonceValue)) return { actions: [], refusal: "nonce_unusable" };
    if (this.abandoned.some((pair) => pair.nonce === nonceValue)) {
      return { actions: [], refusal: "nonce_unusable" };
    }
    this.live = { entryRef, connectionId, nonce: nonceValue };
    return { actions: [{ kind: "send_probe", connectionId, nonce: nonceValue }] };
  }

  private reply(connectionId: string, nonceValue: string): HermesProbeWaiterResult {
    if (this.live?.connectionId === connectionId && this.live.nonce === nonceValue) {
      const entryRef = this.live.entryRef;
      this.live = undefined;
      return { actions: [{ kind: "resolved", entryRef }] };
    }
    const index = this.abandoned.findIndex((pair) => pair.connectionId === connectionId && pair.nonce === nonceValue);
    if (index >= 0) {
      this.abandoned.splice(index, 1);
      return { actions: [] };
    }
    return { actions: [], fatal: "unmatched_probe_reply" };
  }

  private timeout(entryRef: string, nonceValue: string): HermesProbeWaiterResult {
    if (this.live === undefined || this.live.entryRef !== entryRef || this.live.nonce !== nonceValue) {
      return { actions: [] };
    }
    const live = this.live;
    this.abandoned.push(reply(live.connectionId, live.nonce));
    this.live = undefined;
    return { actions: [{ kind: "refused", entryRef: live.entryRef, reason: "timed_out" }] };
  }

  private closed(connectionId: string): HermesProbeWaiterResult {
    if (this.live === undefined || this.live.connectionId !== connectionId) return { actions: [] };
    const live = this.live;
    this.abandoned.push(reply(live.connectionId, live.nonce));
    this.live = undefined;
    return { actions: [{ kind: "refused", entryRef: live.entryRef, reason: "connection_gone" }] };
  }

  private stop(): HermesProbeWaiterResult {
    this.stopped = true;
    if (this.live === undefined) return { actions: [] };
    const live = this.live;
    this.abandoned.push(reply(live.connectionId, live.nonce));
    this.live = undefined;
    return { actions: [{ kind: "refused", entryRef: live.entryRef, reason: "stopped" }] };
  }

  private abandon(entryRef: string): HermesProbeWaiterResult {
    if (this.stopped || this.live === undefined || this.live.entryRef !== entryRef) return { actions: [] };
    this.abandoned.push(reply(this.live.connectionId, this.live.nonce));
    this.live = undefined;
    return { actions: [] };
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

function compareStep(product: HermesProbeWaiter, reference: ReferenceWaiter, step: ProbeStep): HermesProbeWaiterResult {
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
    },
  },
  {
    name: "start refuses after stop without sending",
    run: () => {
      const machine = waiter([nonce(1)]);
      machine.stop();
      expectResult(machine.start("entry-a", "c1"), { actions: [], refusal: "stopped" }, machine);
    },
  },
  {
    name: "start refuses a different entry while a waiter is live",
    run: () => {
      const machine = waiter([nonce(1), nonce(2)]);
      startAndNonce(machine, "entry-a", "c1");
      expectResult(machine.start("entry-b", "c2"), { actions: [], refusal: "probe_busy" }, machine);
      expect(machine.snapshot().live?.entryRef).toBe("entry-a");
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
      expect(machine.snapshot().abandoned).toEqual([pair("c1", nonce(1))]);
    },
  },
  {
    name: "start refuses when the abandoned pair store is full",
    run: () => {
      const machine = waiter(Array.from({ length: CAP_PRESSURE_TIMEOUTS }, (_, index) => nonce(index + 1)));
      fillAbandoned(machine, ABANDONED_PROBE_NONCE_CAP);
      expectResult(machine.start("entry-full", "c99"), { actions: [], refusal: "abandoned_full" }, machine);
      expect(machine.snapshot().abandoned).toHaveLength(ABANDONED_PROBE_NONCE_CAP);
    },
  },
  {
    name: "malformed nonce refuses without replacing state",
    run: () => {
      const machine = waiter(["not-a-nonce"]);
      expectResult(machine.start("entry-a", "c1"), { actions: [], refusal: "nonce_unusable" }, machine);
      expect(machine.snapshot().live).toBeUndefined();
    },
  },
  {
    name: "matching reply resolves the live waiter",
    run: () => {
      const machine = waiter([nonce(1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      expectResult(machine.reply(reply("c1", issued)), { actions: [{ kind: "resolved", entryRef: "entry-a" }] }, machine);
      expect(machine.snapshot().live).toBeUndefined();
    },
  },
  {
    name: "abandoned reply drains only its own pair",
    run: () => {
      const machine = waiter([nonce(1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      machine.timeout("entry-a", issued);
      expectResult(machine.reply(reply("c1", issued)), { actions: [] }, machine);
      expect(machine.snapshot().abandoned).toHaveLength(0);
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
      expect(machine.snapshot().abandoned).toEqual([pair("c1", issued)]);
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
      expect(machine.snapshot().abandoned).toEqual([pair("c1", issued)]);
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
      expectResult(machine.reply(reply("c1", issued)), { actions: [] }, machine);
      expectResult(machine.reply(reply("c9", nonce(9))), { actions: [], fatal: "unmatched_probe_reply" }, machine);
    },
  },
];

describe("Hermes probe waiter transition table", () => {
  for (const row of transitionRows) {
    it(row.name, row.run);
  }
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

describe("Hermes probe waiter fuzz oracle", () => {
  it("matches the reference oracle for legal relay schedules", () => {
    for (let seed = 0; seed < LEGAL_FUZZ_SCHEDULES; seed += 1) {
      const nonceOffset = seed * 64;
      const nonces = Array.from({ length: 64 }, (_, index) => nonce(nonceOffset + index + 1));
      const product = waiter(nonces);
      const reference = new ReferenceWaiter(queuedNonceSource(nonces));
      const issuedPairs: ProbeReplyFrame[] = [];
      const attempts = 1 + (seed % FUZZ_ATTEMPT_VARIANTS);

      for (let attempt = 0; attempt < attempts; attempt += 1) {
        const entryRef = `entry-${seed}-${attempt}`;
        const connectionId = `c${attempt + 1}`;
        const start = compareStep(product, reference, { kind: "start", entryRef, connectionId });
        const sent = start.actions[0];
        if (sent?.kind !== "send_probe") continue;
        issuedPairs.push(reply(sent.connectionId, sent.nonce));

        switch ((seed + attempt) % FUZZ_ATTEMPT_VARIANTS) {
          case 0:
            compareStep(product, reference, { kind: "reply", connectionId: sent.connectionId, nonce: sent.nonce });
            removePending(issuedPairs, reply(sent.connectionId, sent.nonce));
            break;
          case 1:
            compareStep(product, reference, { kind: "timeout", entryRef, nonce: sent.nonce });
            break;
          case 2:
            compareStep(product, reference, { kind: "closed", connectionId: sent.connectionId });
            break;
          case 3:
            compareStep(product, reference, { kind: "abandon", entryRef });
            break;
          case 4:
            {
              const reprobe = compareStep(product, reference, { kind: "start", entryRef, connectionId: `c${attempt + 20}` });
              const next = reprobe.actions[0];
              if (next?.kind === "send_probe") {
                issuedPairs.push(reply(next.connectionId, next.nonce));
                compareStep(product, reference, { kind: "timeout", entryRef, nonce: sent.nonce });
                compareStep(product, reference, { kind: "reply", connectionId: sent.connectionId, nonce: sent.nonce });
                removePending(issuedPairs, reply(sent.connectionId, sent.nonce));
                compareStep(product, reference, { kind: "reply", connectionId: next.connectionId, nonce: next.nonce });
                removePending(issuedPairs, reply(next.connectionId, next.nonce));
              }
            }
            break;
          case 5:
            compareStep(product, reference, { kind: "stop" });
            break;
        }
        if (product.snapshot().stopped) break;
      }

      for (const pair of [...issuedPairs]) {
        const result = compareStep(product, reference, { kind: "reply", connectionId: pair.connectionId, nonce: pair.nonce });
        expect(result.fatal).toBeUndefined();
      }
      expect(product.snapshot().abandoned).toHaveLength(0);
    }
  });

  it("reports a typed fatal for an injected illegal reply", () => {
    for (let seed = 0; seed < ILLEGAL_FUZZ_SCHEDULES; seed += 1) {
      const machine = waiter([nonce(seed + 1)]);
      const issued = startAndNonce(machine, "entry-a", "c1");
      const badPair = seed % 2 === 0 ? reply("c1", nonce(seed + ILLEGAL_NONCE_OFFSET)) : reply("c2", issued);
      const before = machine.snapshot();
      expectResult(machine.reply(badPair), { actions: [], fatal: "unmatched_probe_reply" }, machine);
      expect(machine.snapshot()).toEqual(before);
    }
  });
});
