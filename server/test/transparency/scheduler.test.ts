import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_TRANSPARENCY_INTERVAL_MS,
  parseTransparencyInterval,
  startTransparencyScheduler,
} from "../../src/transparency/scheduler.js";

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
      await vi.advanceTimersByTimeAsync(1_000);
      expect(maxInFlight).toBe(1);
      expect(completed).toBe(1);
      scheduler.stop();
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
      scheduler.stop();
      await vi.advanceTimersByTimeAsync(3_000);
      expect(attempts).toBe(3);
    } finally {
      vi.useRealTimers();
    }
  });
});
