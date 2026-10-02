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
      const scanner = new SurrogateEchoScanner([secret], false);
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
      const scanner = new SurrogateEchoScanner([secret], false);
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
      const scanner = new SurrogateEchoScanner([value()], false);
      const released = [...body].map(byte => output(scanner.scan(Buffer.from([byte]))));
      released.push(scanner.finish());
      expect(Buffer.concat(released).equals(body)).toBe(true);
      expect(scanner.finish().length).toBe(0);
    }
  });
  it("covers every value with one carry sized to the longest", () => {
    const values = Array.from({ length: MAX_PLACEHOLDERS_PER_REQUEST }, (_, i) => value().repeat(i + 1));
    for (const secret of values) {
      const scanner = new SurrogateEchoScanner(values, false);
      expect(scanner.metrics.carryCapacity).toBe(Math.max(...values.map(v => v.length)) - 1);
      expect(output(scanner.scan(Buffer.from(secret.slice(0, -1)))).length).toBe(0);
      expect(scanner.scan(Buffer.from(secret.slice(-1))).blocked).toBe(true);
    }
  });
  it("checks every header name and value including duplicates and the last binding", () => {
    const values = Array.from({ length: MAX_PLACEHOLDERS_PER_REQUEST }, value);
    const scanner = new SurrogateEchoScanner(values, false);
    expect(scanner.headersEcho(["X-Test", "safe", "X-Test", values.at(-1)!])).toBe(true);
    expect(scanner.headersEcho([values[0]!, "safe"])).toBe(true);
    expect(scanner.headersEcho([values[0]!.toUpperCase(), "safe"])).toBe(true);
  });
  it("discards carry at the exact ceiling and never releases later bytes", () => {
    const secret = value();
    const scanner = new SurrogateEchoScanner([secret], false);
    const prefix = Buffer.alloc(MAX_SURROGATE_ECHO_SCAN_BYTES, "!");
    const first = scanner.scan(prefix.subarray(0, -1));
    const last = scanner.scan(prefix.subarray(-1));
    expect(!first.blocked && first.ceiling).toBe(false);
    expect(!last.blocked && last.ceiling).toBe(true);
    expect(output(last).length).toBe(0);
    expect(output(first).length).toBe(prefix.length - secret.length);
    const past = scanner.scan(Buffer.from(secret));
    expect(!past.blocked && past.ceiling).toBe(true);
    expect(output(past).length).toBe(0);
    expect(scanner.finish().length).toBe(0);
    expect(scanner.metrics.scannedBytes).toBe(MAX_SURROGATE_ECHO_SCAN_BYTES);
    expect(scanner.metrics.carryBytes).toBe(0);
  });
  it("releases nothing from a chunk crossing the ceiling", () => {
    // A one-byte value allows the requested ceiling-plus-one body to contain a whole later echo.
    const secret = randomBytes(1).toString("hex").slice(0, 1);
    const scanner = new SurrogateEchoScanner([secret], false);
    const body = Buffer.concat([Buffer.alloc(MAX_SURROGATE_ECHO_SCAN_BYTES, "!"), Buffer.from(secret)]);
    const result = scanner.scan(body);
    expect(body.length).toBe(MAX_SURROGATE_ECHO_SCAN_BYTES + 1);
    expect(!result.blocked && result.ceiling).toBe(true);
    expect(output(result).length).toBe(0);
    expect(scanner.metrics.scannedBytes).toBe(MAX_SURROGATE_ECHO_SCAN_BYTES);
  });
  it("blocks a match ending at the ceiling and refuses one crossing it", () => {
    const secret = value();
    for (const extra of [0, 1]) {
      const scanner = new SurrogateEchoScanner([secret], false);
      const prefix = Buffer.alloc(MAX_SURROGATE_ECHO_SCAN_BYTES - secret.length + extra, "!");
      const first = scanner.scan(prefix);
      const last = scanner.scan(Buffer.from(secret));
      expect(last.blocked).toBe(extra === 0);
      expect(output(last).length).toBe(0);
      expect(Buffer.concat([output(first), output(last)]).includes(Buffer.from(secret))).toBe(false);
    }
  });
  it("bounds carry allocations and comparisons under concurrent adversarial chunking", () => {
    const concurrent = MAX_PLACEHOLDERS_PER_REQUEST ** 2;
    const secret = value().padEnd(MAX_SURROGATE_VALUE_BYTES, "!");
    const alloc = vi.spyOn(Buffer, "alloc");
    try {
      const scanners = Array.from({ length: concurrent }, () => new SurrogateEchoScanner([secret], false));
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
    const scanner = new SurrogateEchoScanner([secret], false);
    scanner.scan(Buffer.from(secret.slice(0, -1)));
    scanner.abort();
    expect(scanner.scan(Buffer.from(secret.slice(-1))).blocked).toBe(true);
    expect(scanner.finish().length).toBe(0);
    expect(scanner.metrics.carryBytes).toBe(0);
  });
  it("screens the stripped view across every data-event split", () => {
    const secret = value();
    const middle = Math.floor(secret.length / 2);
    const framed = Buffer.from([secret.slice(0, middle), secret.slice(middle)]
      .map(part => `${part.length.toString(16)};test=yes\r\n${part}\r\n`).join("") + "0\r\n\r\n");
    const whole = new SurrogateEchoScanner([secret], true).scan(framed);
    expect(whole.blocked).toBe(true);
    if (whole.blocked) expect(whole.cause).toBeUndefined();
    const framingPrefix = framed.indexOf("\r\n") + Buffer.byteLength("\r\n");
    for (let split = 1; split < framed.length; split++) {
      const scanner = new SurrogateEchoScanner([secret], true);
      const first = scanner.scan(framed.subarray(0, split));
      const last = scanner.scan(framed.subarray(split));
      expect(first.blocked || last.blocked).toBe(true);
      expect(output(first).length + output(last).length).toBeLessThanOrEqual(framingPrefix);
      expect(scanner.finish().length).toBe(0);
    }
  });
  it("bounds both screening views under adversarial tiny frames", () => {
    const secret = value().padEnd(MAX_SURROGATE_VALUE_BYTES, "!");
    const scanner = new SurrogateEchoScanner([secret], true);
    const framed = Buffer.from("1;x=y\r\n!\r\n".repeat(MAX_SURROGATE_VALUE_BYTES) + "0\r\n\r\n");
    const released: Buffer[] = [];
    for (const byte of framed) {
      const result = scanner.scan(Buffer.from([byte]));
      expect(result.blocked).toBe(false);
      released.push(output(result));
      expect(scanner.metrics.carryBuffers).toBe(1);
      expect(scanner.metrics.carryBytes).toBeLessThanOrEqual(MAX_SURROGATE_VALUE_BYTES - 1);
    }
    released.push(scanner.finish());
    expect(Buffer.concat(released).equals(framed)).toBe(true);
    // Each KMP view needs at most two comparisons per delivered byte and value.
    expect(scanner.metrics.comparisons).toBeLessThanOrEqual(4 * scanner.metrics.scannedBytes);
    expect(scanner.metrics.comparisons).toBeGreaterThan(scanner.metrics.scannedBytes);
  });
  it("refuses framing that would release a retained stripped prefix", () => {
    const secret = value();
    const scanner = new SurrogateEchoScanner([secret], true);
    const framed = Buffer.from([...secret].map(byte => `1\r\n${byte}\r\n`).join("") + "0\r\n\r\n");
    let refused = false;
    let released = 0;
    for (const byte of framed) {
      const result = scanner.scan(Buffer.from([byte]));
      if (result.blocked) {
        expect(result.cause).toBe("encoding");
        refused = true;
        break;
      }
      released += result.output.length;
    }
    expect(refused).toBe(true);
    expect(released).toBeLessThanOrEqual(Buffer.byteLength("1\r\n"));
    expect(scanner.metrics.carryBytes).toBe(0);
    expect(scanner.finish().length).toBe(0);
  });
  it("rejects empty, oversized and over-count values with a fixed error", () => {
    for (const values of [[], [""], [value().repeat(MAX_SURROGATE_VALUE_BYTES)], Array.from({ length: MAX_PLACEHOLDERS_PER_REQUEST + 1 }, value)]) {
      expect(() => new SurrogateEchoScanner(values, false)).toThrow("invalid echo scan bounds");
    }
  });
});
