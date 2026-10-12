import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_TRANSPARENCY_INTERVAL_MS,
  parseTransparencyInterval,
  startTransparencyScheduler,
  TRANSPARENCY_EMIT_LOCK_TIMEOUT_MS,
  TRANSPARENCY_LOCAL_SIGN_APPEND_BUDGET_MS,
  TRANSPARENCY_STOP_DRAIN_DEADLINE_MS,
  TRANSPARENCY_STOP_DRAIN_MARGIN_MS,
  TransparencySchedulerAbortState,
  TransparencySchedulerAbortedError,
} from "../../src/transparency/scheduler.js";
import { REKOR_SUBMIT_TIMEOUT_MS } from "../../src/transparency/rekor-client.js";

const EXPECTED_STOP_DRAIN_DEADLINE_MS =
  TRANSPARENCY_EMIT_LOCK_TIMEOUT_MS +
  REKOR_SUBMIT_TIMEOUT_MS +
  TRANSPARENCY_LOCAL_SIGN_APPEND_BUDGET_MS +
  TRANSPARENCY_STOP_DRAIN_MARGIN_MS;

describe("parseTransparencyInterval", () => {
  it("defaults to 6 hours when unset", () => {
    expect(parseTransparencyInterval(undefined)).toBe(
      DEFAULT_TRANSPARENCY_INTERVAL_MS
    );
    expect(parseTransparencyInterval("")).toBe(DEFAULT_TRANSPARENCY_INTERVAL_MS);
  });

  it("disables on off/0/disabled", () => {
    expect(parseTransparencyInterval("off")).toBeNull();
    expect(parseTransparencyInterval("0")).toBeNull();
    expect(parseTransparencyInterval("disabled")).toBeNull();
  });

  it("parses unit suffixes", () => {
    expect(parseTransparencyInterval("90s")).toBe(90_000);
    expect(parseTransparencyInterval("30m")).toBe(1_800_000);
    expect(parseTransparencyInterval("6h")).toBe(21_600_000);
    expect(parseTransparencyInterval("1d")).toBe(86_400_000);
    expect(parseTransparencyInterval("120000")).toBe(120_000);
  });

  it("REFUSES invalid or dangerously small values (no silent fallback)", () => {
    expect(() => parseTransparencyInterval("soon")).toThrow(/invalid/);
    expect(() => parseTransparencyInterval("5s")).toThrow(/minimum interval/);
    expect(() => parseTransparencyInterval("-1")).toThrow(/invalid/);
  });
});

describe("startTransparencyScheduler", () => {
  it("emits on each tick and never overlaps in-flight emissions", async () => {
    vi.useFakeTimers();
    try {
      let inFlight = 0;
      let maxInFlight = 0;
      let completed = 0;
      let release: (() => void) | undefined;
      const scheduler = startTransparencyScheduler({
        intervalMs: 1_000,
        emit: () => {
          inFlight++;
          maxInFlight = Math.max(maxInFlight, inFlight);
          return new Promise<void>((resolve) => {
            release = () => {
              inFlight--;
              completed++;
              resolve();
            };
          });
        },
        onError: () => undefined,
      });
      await vi.advanceTimersByTimeAsync(1_000);
      // Second and third ticks fire while the first emission is in flight.
      await vi.advanceTimersByTimeAsync(2_000);
      expect(maxInFlight).toBe(1);
      release!();
      await Promise.resolve();
      expect(maxInFlight).toBe(1);
      expect(completed).toBe(1);
      await scheduler.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it("routes emission failures to onError and keeps ticking", async () => {
    vi.useFakeTimers();
    try {
      const errors: unknown[] = [];
      let attempts = 0;
      const scheduler = startTransparencyScheduler({
        intervalMs: 1_000,
        emit: async () => {
          attempts++;
          throw new Error(`tick ${attempts} refused`);
        },
        onError: (err) => errors.push(err),
      });
      await vi.advanceTimersByTimeAsync(3_000);
      expect(attempts).toBe(3);
      expect(errors).toHaveLength(3);
      await scheduler.stop();
      await vi.advanceTimersByTimeAsync(3_000);
      expect(attempts).toBe(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("stop waits for the current emission to settle", async () => {
    vi.useFakeTimers();
    try {
      let release: (() => void) | undefined;
      let completed = false;
      let stopSettled = false;
      const scheduler = startTransparencyScheduler({
        intervalMs: 1_000,
        emit: () =>
          new Promise<void>((resolve) => {
            release = () => {
              completed = true;
              resolve();
            };
          }),
        onError: () => undefined,
      });
      await vi.advanceTimersByTimeAsync(1_000);
      const stopped = scheduler.stop();
      void stopped.then(() => {
        stopSettled = true;
      });
      await vi.advanceTimersByTimeAsync(3_000);
      expect(completed).toBe(false);
      expect(stopSettled).toBe(false);
      release!();
      await stopped;
      expect(completed).toBe(true);
      expect(stopSettled).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("stop gives up after the named tick-work estimate", async () => {
    vi.useFakeTimers();
    try {
      let attempts = 0;
      let stopSettled = false;
      const scheduler = startTransparencyScheduler({
        intervalMs: 1_000,
        emit: () => {
          attempts += 1;
          return new Promise<void>(() => undefined);
        },
        onError: () => undefined,
      });
      await vi.advanceTimersByTimeAsync(1_000);
      expect(attempts).toBe(1);

      const stopped = scheduler.stop();
      void stopped.then(() => {
        stopSettled = true;
      });
      await vi.advanceTimersByTimeAsync(TRANSPARENCY_STOP_DRAIN_DEADLINE_MS - 1);
      expect(stopSettled).toBe(false);

      await vi.advanceTimersByTimeAsync(1);
      await stopped;
      expect(TRANSPARENCY_STOP_DRAIN_DEADLINE_MS).toBe(
        EXPECTED_STOP_DRAIN_DEADLINE_MS,
      );
      expect(stopSettled).toBe(true);

      await vi.advanceTimersByTimeAsync(3_000);
      expect(attempts).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("stop marks the captured abort state even after an idle tick settles", async () => {
    vi.useFakeTimers();
    try {
      let captured: TransparencySchedulerAbortState | undefined;
      const scheduler = startTransparencyScheduler({
        intervalMs: 1_000,
        emit: async (state) => {
          captured = state;
        },
        onError: () => undefined,
      });
      await vi.advanceTimersByTimeAsync(1_000);
      await Promise.resolve();
      await scheduler.stop();
      expect(captured?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("stop marks the captured abort state before any tick starts", async () => {
    vi.useFakeTimers();
    try {
      let captured: TransparencySchedulerAbortState | undefined;
      const scheduler = startTransparencyScheduler({
        intervalMs: 1_000,
        emit: async () => undefined,
        onError: () => undefined,
        captureAbortState: (state) => {
          captured = state;
        },
      });
      await scheduler.stop();
      expect(captured?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("aborts deadline-straddling emissions before late key work or writes", async () => {
    vi.useFakeTimers();
    try {
      const masterKey = new Uint8Array([7, 7, 7, 7]);
      let releaseEmission: (() => void) | undefined;
      let deriveCalls = 0;
      let macCalls = 0;
      let signCalls = 0;
      let writes = 0;
      const errors: unknown[] = [];
      const scheduler = startTransparencyScheduler({
        intervalMs: 1_000,
        emit: async (state) => {
          await new Promise<void>((resolve) => {
            releaseEmission = resolve;
          });
          // INVARIANT (shutdown/key custody): no await may separate this abort
          // check from the synchronous derived-key operation it gates.
          TransparencySchedulerAbortState.assertNotAborted(
            state,
            "test key derivation"
          );
          expect(masterKey[0]).toBe(7);
          deriveCalls += 1;
          // INVARIANT (shutdown/key custody): no await may separate this abort
          // check from the synchronous MAC operation it gates.
          TransparencySchedulerAbortState.assertNotAborted(state, "test MAC");
          macCalls += 1;
          // INVARIANT (shutdown/key custody): no await may separate this abort
          // check from the synchronous signing operation it gates.
          TransparencySchedulerAbortState.assertNotAborted(state, "test signing");
          signCalls += 1;
          writes += 1;
        },
        onError: (error) => errors.push(error),
      });
      await vi.advanceTimersByTimeAsync(1_000);
      expect(releaseEmission).toBeDefined();

      const stopped = scheduler.stop();
      await vi.advanceTimersByTimeAsync(TRANSPARENCY_STOP_DRAIN_DEADLINE_MS);
      await stopped;
      masterKey.fill(0);
      releaseEmission!();
      await Promise.resolve();
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(0);

      expect(deriveCalls).toBe(0);
      expect(macCalls).toBe(0);
      expect(signCalls).toBe(0);
      expect(writes).toBe(0);
      expect(errors[0]).toMatchObject({
        name: "TransparencySchedulerAbortedError",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
    ["primitive", 1],
  ] as const)("refuses a %s abort-state value with the typed abort error", (_label, value) => {
    expect(() =>
      TransparencySchedulerAbortState.assertNotAborted(
        value as unknown as TransparencySchedulerAbortState,
        "abort state authentication",
      ),
    ).toThrow(TransparencySchedulerAbortedError);
  });

  it("refuses constructor access without the module mint", () => {
    expect(() =>
      Reflect.construct(TransparencySchedulerAbortState, [() => false]),
    ).toThrow(TransparencySchedulerAbortedError);

    const Ctor = TransparencySchedulerAbortState as unknown as new (
      isAborted: () => boolean
    ) => TransparencySchedulerAbortState;
    expect(() => new Ctor(() => false)).toThrow(TransparencySchedulerAbortedError);

    class Subclass extends (TransparencySchedulerAbortState as unknown as new (
      ...args: unknown[]
    ) => TransparencySchedulerAbortState) {}
    expect(() => new Subclass()).toThrow(TransparencySchedulerAbortedError);
  });
});
