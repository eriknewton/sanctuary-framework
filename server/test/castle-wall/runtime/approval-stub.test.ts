/**
 * Castle Wall E6.2 default-deny + E6.3 confidence-warning + override
 * tests for the PR 2a approval stub.
 *
 * Uses an injected fake clock so every test runs deterministically without
 * waiting on real timers.
 */

import { describe, it, expect } from "vitest";

import {
  ApprovalStub,
  deriveConfidence,
} from "../../../src/castle-wall/runtime/approval-stub.js";
import type {
  DecisionRequest,
  IpcDestination,
} from "../../../src/castle-wall/ipc/messages.js";

class FakeClock {
  private next = 1;
  private timers = new Map<number, { ms: number; cb: () => void; remaining: number }>();
  setTimer = (cb: () => void, ms: number): unknown => {
    const handle = this.next++;
    this.timers.set(handle, { ms, cb, remaining: ms });
    return handle;
  };
  clearTimer = (handle: unknown): void => {
    this.timers.delete(handle as number);
  };
  /** Advance the clock by `ms` milliseconds; fires expired timers in order. */
  tick(ms: number): void {
    for (const [handle, t] of [...this.timers]) {
      t.remaining -= ms;
      if (t.remaining <= 0) {
        this.timers.delete(handle);
        t.cb();
      }
    }
  }
  pendingCount(): number {
    return this.timers.size;
  }
}

function dest(overrides: Partial<IpcDestination> = {}): IpcDestination {
  return {
    host: "example.com",
    ip: "1.2.3.4",
    port: 443,
    protocol: "tcp",
    hostname_source: "dns",
    opaque: false,
    ...overrides,
  };
}

function req(overrides: Partial<DecisionRequest> = {}): DecisionRequest {
  return {
    type: "decision_request",
    request_id: "req-1",
    surface: "egress",
    destination: dest(),
    agent: { id: "a", template: "t" },
    timeout_seconds: 30,
    ...overrides,
  };
}

describe("castle-wall/runtime/approval-stub : E6.2 default-deny on timeout", () => {
  it("returns timeout_default_deny after promptTimeoutMs elapses", async () => {
    const clock = new FakeClock();
    const stub = new ApprovalStub({
      promptTimeoutMs: 5_000,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
    });
    const promise = stub.process(req());
    expect(stub.pendingCount()).toBe(1);
    clock.tick(5_001);
    const decision = await promise;
    expect(decision.decision).toBe("timeout_default_deny");
    expect(decision.request_id).toBe("req-1");
    expect(stub.pendingCount()).toBe(0);
  });

  it("does not auto-deny before the timeout fires", async () => {
    const clock = new FakeClock();
    const stub = new ApprovalStub({
      promptTimeoutMs: 5_000,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
    });
    const promise = stub.process(req());
    clock.tick(2_000);
    expect(stub.pendingCount()).toBe(1);
    clock.tick(3_001);
    const decision = await promise;
    expect(decision.decision).toBe("timeout_default_deny");
  });
});

describe("castle-wall/runtime/approval-stub : injected operator decision", () => {
  it("propagates an operator allow_once decision", async () => {
    const clock = new FakeClock();
    const stub = new ApprovalStub({
      promptTimeoutMs: 60_000,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
    });
    const promise = stub.process(req());
    expect(stub.injectDecision("req-1", "allow_once")).toBe(true);
    const decision = await promise;
    expect(decision.decision).toBe("allow_once");
    expect(stub.pendingCount()).toBe(0);
  });

  it("returns false when injecting a decision for an unknown request_id", () => {
    const stub = new ApprovalStub({ promptTimeoutMs: 60_000 });
    expect(stub.injectDecision("never-issued", "allow_once")).toBe(false);
  });
});

describe("castle-wall/runtime/approval-stub : shutdown drains pending prompts", () => {
  it("resolves every in-flight prompt with timeout_default_deny on shutdown", async () => {
    const clock = new FakeClock();
    const stub = new ApprovalStub({
      promptTimeoutMs: 60_000,
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
    });
    const p1 = stub.process(req({ request_id: "r1" }));
    const p2 = stub.process(req({ request_id: "r2" }));
    expect(stub.pendingCount()).toBe(2);
    stub.shutdown();
    const [d1, d2] = await Promise.all([p1, p2]);
    expect(d1.decision).toBe("timeout_default_deny");
    expect(d2.decision).toBe("timeout_default_deny");
  });
});

describe("castle-wall/runtime/approval-stub : E6.3 confidence labeling", () => {
  it("opaque destination gets low_opaque", () => {
    expect(deriveConfidence(dest({ opaque: true }))).toBe("low_opaque");
  });

  it("null host gets low_raw_ip", () => {
    expect(deriveConfidence(dest({ host: null }))).toBe("low_raw_ip");
  });

  it("hostname-source dns at 443 stays high", () => {
    expect(deriveConfidence(dest({ hostname_source: "dns" }))).toBe("high");
  });

  it("hostname-source null at 853 (DoT) gets low_doh_dot", () => {
    expect(
      deriveConfidence(dest({ port: 853, hostname_source: null }))
    ).toBe("low_doh_dot");
  });
});

describe("castle-wall/runtime/approval-stub : strict-mode requirement", () => {
  it("requiresStrictConfirmation true for low_opaque when strict", () => {
    const stub = new ApprovalStub({ strictMode: true });
    expect(stub.requiresStrictConfirmation("low_opaque")).toBe(true);
  });

  it("requiresStrictConfirmation false for high confidence", () => {
    const stub = new ApprovalStub({ strictMode: true });
    expect(stub.requiresStrictConfirmation("high")).toBe(false);
  });

  it("requiresStrictConfirmation false when strictMode disabled", () => {
    const stub = new ApprovalStub({ strictMode: false });
    expect(stub.requiresStrictConfirmation("low_opaque")).toBe(false);
  });
});

describe("castle-wall/runtime/approval-stub : buildPromptRequest", () => {
  it("derives confidence + expires_at from the destination", () => {
    const stub = new ApprovalStub({ promptTimeoutMs: 30_000 });
    const prompt = stub.buildPromptRequest(req({ destination: dest({ opaque: true }) }));
    expect(prompt.confidence).toBe("low_opaque");
    expect(typeof prompt.expires_at).toBe("string");
    expect(prompt.rate_limited).toBe(false);
  });
});
