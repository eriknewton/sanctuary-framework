/** Exact-byte response screening with bounded retained state and scan work. */
import {
  MAX_PLACEHOLDERS_PER_REQUEST, MAX_SURROGATE_ECHO_SCAN_BYTES, MAX_SURROGATE_VALUE_BYTES,
} from "./constants.js";

/** Fixed response outcomes; must match SurrogateEchoEvent in egress-gate/gate-server.ts. */
export type SurrogateEchoCause = "ceiling" | "encoding" | "scan_error" | "upstream_reset" | "client_abort";
export type SurrogateEchoCode = "echo_blocked" | "echo_unscanned";
export const SURROGATE_ECHO_BLOCKED = [502, "surrogate-echo-blocked"] as const;

type ScanState = "SCANNING" | "PAST_CEILING" | "ABORTED" | "FINISHED";
/** A blocked chunk releases nothing; ceiling requires terminal refusal with no output. */
export type SurrogateEchoScanResult =
  | { blocked: true }
  | { blocked: false; output: Buffer; ceiling: boolean };

/** One instance per swapped identity response; discard it when that response ends. */
export class SurrogateEchoScanner {
  private state: ScanState = "SCANNING";
  private readonly values: Buffer[];
  private readonly prefixes: Uint32Array[];
  private readonly matched: number[];
  private readonly carry: Buffer;
  private held = 0;
  private start = 0;
  private scanned = 0;
  private comparisons = 0;

  constructor(values: readonly string[]) {
    // The helper owns value validation; this local cap also makes standalone use bounded.
    if (!values.length || values.length > MAX_PLACEHOLDERS_PER_REQUEST ||
        values.some(value => !value.length || Buffer.byteLength(value) > MAX_SURROGATE_VALUE_BYTES)) {
      throw new Error("invalid echo scan bounds");
    }
    this.values = values.map(value => Buffer.from(value));
    this.matched = values.map(() => 0);
    this.prefixes = this.values.map(value => {
      const prefix = new Uint32Array(value.length);
      for (let i = 1, j = 0; i < value.length; i++) {
        while (j > 0 && value[i] !== value[j]) j = prefix[j - 1]!;
        if (value[i] === value[j]) j++;
        prefix[i] = j;
      }
      return prefix;
    });
    // One reusable carry, sized to the longest value, covers every shorter value too.
    this.carry = Buffer.alloc(Math.max(...this.values.map(value => value.length)) - 1);
  }

  /** Inspect field names and values independently, including duplicate header fields. */
  headersEcho(rawHeaders: readonly string[]): boolean {
    for (let i = 0; i < rawHeaders.length; i++) {
      const value = Buffer.from(rawHeaders[i]!, "latin1");
      if (this.values.some(secret => value.includes(secret))) return true;
      // Node forwards lowercase names, so that representation must be screened too.
      if (i % 2 === 0 && this.values.some(secret => Buffer.from(rawHeaders[i]!.toLowerCase(), "latin1").includes(secret))) return true;
    }
    return false;
  }

  /** Counts only, so diagnostics cannot disclose retained response or credential bytes. */
  get metrics(): Readonly<{ state: ScanState; carryBuffers: number; carryBytes: number; carryCapacity: number; scannedBytes: number; comparisons: number }> {
    return { state: this.state, carryBuffers: 1, carryBytes: this.held, carryCapacity: this.carry.length,
      scannedBytes: this.scanned, comparisons: this.comparisons };
  }

  /** Screen before returning any bytes from a chunk; a match discards the whole pending chunk. */
  scan(chunk: Buffer): SurrogateEchoScanResult {
    if (this.state === "ABORTED" || this.state === "FINISHED") return { blocked: true };
    if (this.state === "PAST_CEILING") return { blocked: false, output: Buffer.alloc(0), ceiling: true };
    const count = Math.min(chunk.length, MAX_SURROGATE_ECHO_SCAN_BYTES - this.scanned);
    // Prefix matching processes each new byte once per value, even for one-byte chunks.
    for (let i = 0; i < count; i++) {
      this.scanned++;
      for (let v = 0; v < this.values.length; v++) {
        const value = this.values[v]!;
        const prefix = this.prefixes[v]!;
        let j = this.matched[v]!;
        while (true) {
          this.comparisons++;
          if (chunk[i] === value[j]) { j++; break; }
          if (j === 0) break;
          j = prefix[j - 1]!;
        }
        this.matched[v] = j;
        if (j === value.length) { this.abort(); return { blocked: true }; }
      }
    }
    if (this.scanned === MAX_SURROGATE_ECHO_SCAN_BYTES) {
      // Design section 1 bounds detection here. The fail-closed response contract refuses
      // at that bound: neither the carry nor any unscanned suffix may leave the scanner.
      this.abort();
      this.state = "PAST_CEILING";
      return { blocked: false, output: Buffer.alloc(0), ceiling: true };
    }
    return { blocked: false, output: this.release(chunk, false), ceiling: false };
  }

  private release(chunk: Buffer, flush: boolean): Buffer {
    const safeLength = flush ? this.held + chunk.length : Math.max(0, this.held + chunk.length - this.carry.length);
    const output = Buffer.allocUnsafe(safeLength);
    const fromCarry = Math.min(this.held, safeLength);
    if (fromCarry) {
      const contiguous = Math.min(fromCarry, this.carry.length - this.start);
      this.carry.copy(output, 0, this.start, this.start + contiguous);
      this.carry.copy(output, contiguous, 0, fromCarry - contiguous);
      this.start = (this.start + fromCarry) % this.carry.length;
      this.held -= fromCarry;
    }
    const fromChunk = safeLength - fromCarry;
    chunk.copy(output, fromCarry, 0, fromChunk);
    const remaining = chunk.length - fromChunk;
    if (remaining) {
      // A ring copies each retained byte once: one-byte chunks cannot repeatedly copy
      // the whole carry, and a short suffix never retains a large upstream backing buffer.
      const end = (this.start + this.held) % this.carry.length;
      const contiguous = Math.min(remaining, this.carry.length - end);
      chunk.copy(this.carry, end, fromChunk, fromChunk + contiguous);
      chunk.copy(this.carry, 0, fromChunk + contiguous);
      this.held += remaining;
    }
    return output;
  }

  /** Flush only a normally completed stream; an aborted stream can never release its carry. */
  finish(): Buffer {
    if (this.state === "ABORTED" || this.state === "FINISHED") return Buffer.alloc(0);
    const tail = this.release(Buffer.alloc(0), true);
    this.abort();
    this.state = "FINISHED";
    return tail;
  }

  /** Erase retained bytes and make all late scan/finish callbacks inert. */
  abort(): void {
    this.state = "ABORTED";
    this.held = 0;
    this.start = 0;
    this.carry.fill(0);
    this.matched.fill(0);
  }
}
