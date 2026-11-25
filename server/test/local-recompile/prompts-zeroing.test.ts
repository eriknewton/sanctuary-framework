// Record and model text held in a buffer is zeroed once the job is done with it.
import { afterEach, describe, expect, it, vi } from "vitest";
import { frameAndChunk, truncateUtf8 } from "../../src/local-recompile/prompts.js";

const SENTINEL = "PLAINTEXT-SENTINEL-4c1e";

afterEach(() => {
  vi.restoreAllMocks();
});

/** Every buffer allocated while `run` executes, for inspection after it returns. */
function allocations(run: () => unknown): Buffer[] {
  const seen: Buffer[] = [];
  const alloc = Buffer.alloc.bind(Buffer);
  vi.spyOn(Buffer, "alloc").mockImplementation(((size: number, ...rest: unknown[]) => {
    const buffer = (alloc as (...input: unknown[]) => Buffer)(size, ...rest);
    seen.push(buffer);
    return buffer;
  }) as typeof Buffer.alloc);
  run();
  vi.restoreAllMocks();
  return seen;
}

describe("plaintext buffers", () => {
  it("framing records leaves every plaintext buffer zeroed", () => {
    let chunks: ReturnType<typeof frameAndChunk> = null;
    const seen = allocations(() => {
      chunks = frameAndChunk([`one ${SENTINEL}`, `two ${SENTINEL}`]);
    });
    expect(chunks).not.toBeNull();
    expect(seen.length).toBeGreaterThan(0);
    for (const buffer of seen) expect(buffer.every((byte) => byte === 0)).toBe(true);
  });

  it("cutting model output leaves its buffer zeroed", () => {
    let cut: ReturnType<typeof truncateUtf8> | undefined;
    const seen = allocations(() => {
      cut = truncateUtf8(`${SENTINEL} ${"x".repeat(64)}`, 16);
    });
    expect(cut).toEqual({ text: SENTINEL.slice(0, 16), truncated: true });
    expect(seen.length).toBeGreaterThan(0);
    for (const buffer of seen) expect(buffer.every((byte) => byte === 0)).toBe(true);
  });
});
