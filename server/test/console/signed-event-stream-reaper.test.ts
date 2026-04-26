/**
 * Sanctuary v1.1 pre-tag fix wave -- SignedEventStream reaper + close()
 *
 * Fix #14: long-lived fortresses with intermittent partitions accumulated
 * SSE clients whose underlying socket never fired "close", leaking
 * keepalive intervals + Response objects forever. Two surfaces verified
 * here: explicit close() detaches a client cleanly, and the reaper
 * forces close after maxMissedKeepalives consecutive write failures.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { ServerResponse } from "node:http";
import { SignedEventStream } from "../../src/console/signed-event-stream.js";

interface MockRes {
  writeHead: ReturnType<typeof vi.fn>;
  write: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
  on: ReturnType<typeof vi.fn>;
}

function makeMockRes(opts?: { writeThrows?: boolean }): MockRes {
  return {
    writeHead: vi.fn(),
    write: vi.fn(() => {
      if (opts?.writeThrows) {
        throw new Error("EPIPE");
      }
      return true;
    }),
    end: vi.fn(),
    on: vi.fn(),
  };
}

describe("SignedEventStream close() and reaper (#14)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("close() removes the client and clears its keepalive interval", () => {
    const stream = new SignedEventStream({ keepaliveMs: 1000 });
    const res = makeMockRes();
    stream.addClient(res as unknown as ServerResponse);
    expect(stream.clientCount).toBe(1);

    stream.close(res as unknown as ServerResponse);

    expect(stream.clientCount).toBe(0);
    expect(res.end).toHaveBeenCalledTimes(1);

    // Advance well past the keepalive interval; if cleanup were broken
    // the timer would still fire and call write again.
    vi.advanceTimersByTime(5000);
    expect(res.write).not.toHaveBeenCalled();
  });

  it("close() is idempotent on an already-removed client", () => {
    const stream = new SignedEventStream({ keepaliveMs: 1000 });
    const res = makeMockRes();
    stream.addClient(res as unknown as ServerResponse);

    stream.close(res as unknown as ServerResponse);
    stream.close(res as unknown as ServerResponse);
    stream.close(res as unknown as ServerResponse);

    expect(stream.clientCount).toBe(0);
    expect(res.end).toHaveBeenCalledTimes(1);
  });

  it("reaps a client after maxMissedKeepalives consecutive write failures", () => {
    const stream = new SignedEventStream({
      keepaliveMs: 1000,
      maxMissedKeepalives: 3,
    });
    const res = makeMockRes({ writeThrows: true });
    stream.addClient(res as unknown as ServerResponse);
    expect(stream.clientCount).toBe(1);

    // Tick 1 — first failed keepalive (1 missed)
    vi.advanceTimersByTime(1000);
    expect(stream.clientCount).toBe(1);

    // Tick 2 — second failed keepalive (2 missed)
    vi.advanceTimersByTime(1000);
    expect(stream.clientCount).toBe(1);

    // Tick 3 — third failed keepalive triggers reap
    vi.advanceTimersByTime(1000);
    expect(stream.clientCount).toBe(0);
    expect(res.end).toHaveBeenCalledTimes(1);

    // Subsequent ticks must NOT call write again (interval cleared)
    res.write.mockClear();
    vi.advanceTimersByTime(5000);
    expect(res.write).not.toHaveBeenCalled();
  });

  it("resets the missed-keepalive counter on a successful write", () => {
    const stream = new SignedEventStream({
      keepaliveMs: 1000,
      maxMissedKeepalives: 3,
    });
    let throwCount = 0;
    const res = {
      writeHead: vi.fn(),
      write: vi.fn(() => {
        // Fail the first 2 writes, succeed the third, then fail forever
        throwCount += 1;
        if (throwCount <= 2) throw new Error("EPIPE");
        if (throwCount === 3) return true;
        throw new Error("EPIPE");
      }),
      end: vi.fn(),
      on: vi.fn(),
    };

    stream.addClient(res as unknown as ServerResponse);

    // First 2 ticks fail; third succeeds and resets counter; 4th and 5th
    // fail; need 6th to actually reach the threshold and reap.
    vi.advanceTimersByTime(1000); // 1 missed
    vi.advanceTimersByTime(1000); // 2 missed
    vi.advanceTimersByTime(1000); // success - counter resets to 0
    expect(stream.clientCount).toBe(1);
    vi.advanceTimersByTime(1000); // 1 missed (new run)
    vi.advanceTimersByTime(1000); // 2 missed
    expect(stream.clientCount).toBe(1);
    vi.advanceTimersByTime(1000); // 3 missed - reap
    expect(stream.clientCount).toBe(0);
  });

  it("closeAll() clears every client's keepalive timer", () => {
    const stream = new SignedEventStream({ keepaliveMs: 1000 });
    const r1 = makeMockRes();
    const r2 = makeMockRes();
    const r3 = makeMockRes();
    stream.addClient(r1 as unknown as ServerResponse);
    stream.addClient(r2 as unknown as ServerResponse);
    stream.addClient(r3 as unknown as ServerResponse);
    expect(stream.clientCount).toBe(3);

    stream.closeAll();
    expect(stream.clientCount).toBe(0);
    expect(r1.end).toHaveBeenCalledTimes(1);
    expect(r2.end).toHaveBeenCalledTimes(1);
    expect(r3.end).toHaveBeenCalledTimes(1);

    // All keepalive timers must be cleared (no further write calls)
    r1.write.mockClear();
    r2.write.mockClear();
    r3.write.mockClear();
    vi.advanceTimersByTime(5000);
    expect(r1.write).not.toHaveBeenCalled();
    expect(r2.write).not.toHaveBeenCalled();
    expect(r3.write).not.toHaveBeenCalled();
  });
});
