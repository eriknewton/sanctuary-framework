/** Capability: exact-byte echo screening bounds work and retained response state. */
import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { SurrogateEchoScanner, MAX_PLACEHOLDERS_PER_REQUEST, MAX_SURROGATE_ECHO_SCAN_BYTES, MAX_SURROGATE_VALUE_BYTES } from "../../src/credential-surrogate/index.js";

const value = () => randomBytes(16).toString("hex"); // 16 random bytes produce a 32-byte ASCII value.
const output = (result: ReturnType<SurrogateEchoScanner["scan"]>) => result.blocked ? Buffer.alloc(0) : result.output;

describe("surrogate echo scanner", () => {
  it("blocks every split offset without releasing any bytes of the value", () => {
    const secret = value();
    for (let split = 1; split < secret.length; split++) {
      const scanner = new SurrogateEchoScanner([secret]);
      const first = scanner.scan(Buffer.from(secret.slice(0, split)));
      expect(output(first).length).toBe(0);
      expect(scanner.scan(Buffer.from(secret.slice(split))).blocked).toBe(true);
      expect(scanner.finish().length).toBe(0);
      expect(scanner.metrics.carryBytes).toBe(0);
    }
  });
  it("blocks at the start and end and across one-byte chunks", () => {
    const secret = value();
    for (const body of [secret, `${secret}!`, `!${secret}`]) {
      const scanner = new SurrogateEchoScanner([secret]);
      const released: Buffer[] = [];
      let blocked = false;
      for (const byte of Buffer.from(body)) {
        const result = scanner.scan(Buffer.from([byte]));
        released.push(output(result));
        blocked ||= result.blocked;
      }
      expect(blocked).toBe(true);
      expect(Buffer.concat(released).includes(Buffer.from(secret.slice(0, 1)))).toBe(false);
    }
  });
  it("flushes empty and non-echo bodies byte for byte at normal end", () => {
    for (const body of [Buffer.alloc(0), randomBytes(MAX_PLACEHOLDERS_PER_REQUEST * value().length + 1)]) {
      const scanner = new SurrogateEchoScanner([value()]);
      const released = [...body].map(byte => output(scanner.scan(Buffer.from([byte]))));
      released.push(scanner.finish());
      expect(Buffer.concat(released).equals(body)).toBe(true);
      expect(scanner.finish().length).toBe(0);
    }
  });
  it("covers every value with one carry sized to the longest", () => {
    const values = Array.from({ length: MAX_PLACEHOLDERS_PER_REQUEST }, (_, i) => value().repeat(i + 1));
    for (const secret of values) {
      const scanner = new SurrogateEchoScanner(values);
      expect(scanner.metrics.carryCapacity).toBe(Math.max(...values.map(v => v.length)) - 1);
      expect(output(scanner.scan(Buffer.from(secret.slice(0, -1)))).length).toBe(0);
      expect(scanner.scan(Buffer.from(secret.slice(-1))).blocked).toBe(true);
    }
  });
  it("checks every raw header value including duplicate fields and the last binding", () => {
    const values = Array.from({ length: MAX_PLACEHOLDERS_PER_REQUEST }, value);
    const scanner = new SurrogateEchoScanner(values);
    expect(scanner.headersEcho(["X-Test", "safe", "X-Test", values.at(-1)!])).toBe(true);
    expect(scanner.headersEcho([values[0]!, "safe"])).toBe(false);
  });
  it("flushes at the exact ceiling and reports it once while later echoes pass", () => {
    const secret = value();
    const scanner = new SurrogateEchoScanner([secret]);
    const prefix = Buffer.alloc(MAX_SURROGATE_ECHO_SCAN_BYTES, "!");
    const first = scanner.scan(prefix.subarray(0, -1));
    const last = scanner.scan(prefix.subarray(-1));
    expect(!first.blocked && first.ceiling).toBe(false);
    expect(!last.blocked && last.ceiling).toBe(true);
    expect(Buffer.concat([output(first), output(last)]).equals(prefix)).toBe(true);
    const past = scanner.scan(Buffer.from(secret));
    expect(!past.blocked && past.ceiling).toBe(false);
    expect(output(past).equals(Buffer.from(secret))).toBe(true);
    expect(scanner.metrics.scannedBytes).toBe(MAX_SURROGATE_ECHO_SCAN_BYTES);
    expect(scanner.metrics.carryBytes).toBe(0);
  });
  it("scans only the prefix of a chunk crossing the ceiling", () => {
    // A one-byte value allows the requested ceiling-plus-one body to contain a whole later echo.
    const secret = randomBytes(1).toString("hex").slice(0, 1);
    const scanner = new SurrogateEchoScanner([secret]);
    const body = Buffer.concat([Buffer.alloc(MAX_SURROGATE_ECHO_SCAN_BYTES, "!"), Buffer.from(secret)]);
    const result = scanner.scan(body);
    expect(body.length).toBe(MAX_SURROGATE_ECHO_SCAN_BYTES + 1);
    expect(!result.blocked && result.ceiling).toBe(true);
    expect(output(result).equals(body)).toBe(true);
    expect(scanner.metrics.scannedBytes).toBe(MAX_SURROGATE_ECHO_SCAN_BYTES);
  });
  it("blocks a match ending at the ceiling and passes one crossing it", () => {
    const secret = value();
    for (const extra of [0, 1]) {
      const scanner = new SurrogateEchoScanner([secret]);
      const prefix = Buffer.alloc(MAX_SURROGATE_ECHO_SCAN_BYTES - secret.length + extra, "!");
      const first = scanner.scan(prefix);
      const last = scanner.scan(Buffer.from(secret));
      expect(last.blocked).toBe(extra === 0);
      if (extra) expect(Buffer.concat([output(first), output(last)]).equals(Buffer.concat([prefix, Buffer.from(secret)]))).toBe(true);
    }
  });
  it("bounds carry allocations and comparisons under concurrent adversarial chunking", () => {
    const concurrent = MAX_PLACEHOLDERS_PER_REQUEST ** 2;
    const secret = value().padEnd(MAX_SURROGATE_VALUE_BYTES, "!");
    const alloc = vi.spyOn(Buffer, "alloc");
    try {
      const scanners = Array.from({ length: concurrent }, () => new SurrogateEchoScanner([secret]));
      const chunk = Buffer.from(secret.slice(0, 1));
      for (let wave = 0; wave < MAX_SURROGATE_VALUE_BYTES; wave++) {
        for (const scanner of scanners) {
          expect(scanner.scan(chunk).blocked).toBe(false);
          expect(scanner.metrics.carryBytes).toBeLessThanOrEqual(MAX_SURROGATE_VALUE_BYTES - 1);
        }
      }
      expect(alloc.mock.calls.filter(([size]) => size === MAX_SURROGATE_VALUE_BYTES - 1).length).toBe(concurrent);
      for (const scanner of scanners) {
        expect(scanner.metrics.carryBuffers).toBe(1);
        // KMP makes at most two comparisons per new byte, independent of chunk boundaries.
        expect(scanner.metrics.comparisons).toBeLessThanOrEqual(2 * scanner.metrics.scannedBytes);
        scanner.abort();
        expect(scanner.finish().length).toBe(0);
      }
    } finally { alloc.mockRestore(); }
  });
  it("makes delayed chunks and finish inert after abort", () => {
    const secret = value();
    const scanner = new SurrogateEchoScanner([secret]);
    scanner.scan(Buffer.from(secret.slice(0, -1)));
    scanner.abort();
    expect(scanner.scan(Buffer.from(secret.slice(-1))).blocked).toBe(true);
    expect(scanner.finish().length).toBe(0);
    expect(scanner.metrics.carryBytes).toBe(0);
  });
  it("rejects empty, oversized and over-count values with a fixed error", () => {
    for (const values of [[], [""], [value().repeat(MAX_SURROGATE_VALUE_BYTES)], Array.from({ length: MAX_PLACEHOLDERS_PER_REQUEST + 1 }, value)]) {
      expect(() => new SurrogateEchoScanner(values)).toThrow("invalid echo scan bounds");
    }
  });
});
