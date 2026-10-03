/** Exact-byte response screening with bounded retained state and scan work. */
import {
  MAX_PLACEHOLDERS_PER_REQUEST, MAX_SURROGATE_ECHO_SCAN_BYTES, MAX_SURROGATE_VALUE_BYTES,
} from "./constants.js";

/** Fixed response outcomes; must match SurrogateEchoEvent in egress-gate/gate-server.ts. */
export type SurrogateEchoCause = "ceiling" | "encoding" | "scan_error" | "upstream_reset" | "client_abort";
export type SurrogateEchoCode = "echo_blocked" | "echo_unscanned";
export const SURROGATE_ECHO_BLOCKED = [502, "surrogate-echo-blocked"] as const;

type FrameState = "PROBE" | "SIZE" | "EXTENSION" | "SIZE_LF" | "DATA" |
  "DATA_CR" | "DATA_LF" | "FINAL_CR" | "FINAL_LF" | "DONE" | "PASSTHROUGH";
const CR = 0x0d;
const LF = 0x0a;
const SEMICOLON = 0x3b;
const SP = 0x20; // ASCII space.
const HTAB = 0x09; // ASCII horizontal tab.
// Bytes a lenient client chunk parser skips or accepts before the first size digit
// (for example Python's int(line, 16) strips ASCII whitespace and takes a sign).
const LENIENT_SIZE_PREFIX = new Set([0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x2b, 0x2d]); // SP HT LF VT FF CR + -
const HEX_RADIX = 16;
const HEX_DIGITS = "0123456789abcdef";

type ScanState = "SCANNING" | "PAST_CEILING" | "ABORTED" | "FINISHED";
/** A blocked chunk releases nothing; ceiling requires terminal refusal with no output. */
export type SurrogateEchoScanResult =
  | { blocked: true; cause?: "encoding" }
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
  private readonly strippedMatched: number[];
  private frameState: FrameState = "PROBE";
  private frameSize = 0;
  private frameDigits = false;
  private frameCommitted = false;
  private strippedPrefixStart: number | undefined;
  private framingFailure = false;

  constructor(values: readonly string[], private readonly screenChunkFrames: boolean) {
    // The helper owns value validation; this local cap also makes standalone use bounded.
    if (!values.length || values.length > MAX_PLACEHOLDERS_PER_REQUEST ||
        values.some(value => !value.length || Buffer.byteLength(value) > MAX_SURROGATE_VALUE_BYTES)) {
      throw new Error("invalid echo scan bounds");
    }
    this.values = values.map(value => Buffer.from(value));
    this.matched = values.map(() => 0);
    this.strippedMatched = values.map(() => 0);
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
      if (this.matchByte(chunk[i]!, this.matched)) { this.abort(); return { blocked: true }; }
      if (this.screenChunkFrames) {
        const view = this.stripByte(chunk[i]!);
        if (view === "FAIL") return this.failEncoding();
        if (view === "DATA") {
          if (this.matchByte(chunk[i]!, this.strippedMatched)) { this.abort(); return { blocked: true }; }
          if (this.strippedMatched.some(length => length > 0)) this.strippedPrefixStart ??= this.scanned - 1;
          else this.strippedPrefixStart = undefined;
        }
      }
    }
    if (this.scanned === MAX_SURROGATE_ECHO_SCAN_BYTES) {
      // Design section 1 bounds detection here. The fail-closed response contract refuses
      // at that bound: neither the carry nor any unscanned suffix may leave the scanner.
      this.abort();
      this.state = "PAST_CEILING";
      return { blocked: false, output: Buffer.alloc(0), ceiling: true };
    }
    // Framing can separate a candidate's bytes by more than the raw carry holds.
    // Refuse before releasing any candidate prefix rather than allocating another buffer.
    if (this.strippedPrefixStart !== undefined && this.scanned - this.strippedPrefixStart > this.carry.length) {
      return this.failEncoding();
    }
    return { blocked: false, output: this.release(chunk, false), ceiling: false };
  }

  private matchByte(byte: number, matched: number[]): boolean {
    for (let v = 0; v < this.values.length; v++) {
      const value = this.values[v]!;
      const prefix = this.prefixes[v]!;
      let j = matched[v]!;
      while (true) {
        this.comparisons++;
        if (byte === value[j]) { j++; break; }
        if (j === 0) break;
        j = prefix[j - 1]!;
      }
      matched[v] = j;
      if (j === value.length) return true;
    }
    return false;
  }

  /** Screening-only view: delivered bytes are never decoded or rewritten for output. */
  private stripByte(byte: number): "DATA" | "SKIP" | "FAIL" {
    switch (this.frameState) {
      case "PASSTHROUGH": return "SKIP"; // The delivered view already covers this identical view.
      case "PROBE":
      case "SIZE": {
        const digit = HEX_DIGITS.indexOf(String.fromCharCode(byte).toLowerCase());
        if (digit >= 0) {
          this.frameDigits = true;
          // A begun size line can never become an ordinary body: framing deviations
          // must refuse, since unparsed framing in a non-dechunked body splits a secret across views.
          // Cost, accepted: a dechunked body that opens with a hex digit is refused too (availability, never a leak).
          this.frameCommitted = true;
          // Saturation prevents attacker-selected size digits from overflowing numeric state.
          this.frameSize = Math.min(MAX_SURROGATE_ECHO_SCAN_BYTES + 1, this.frameSize * HEX_RADIX + digit);
          return "SKIP";
        }
        if (this.frameDigits && (byte === SEMICOLON || byte === CR)) {
          this.frameState = byte === SEMICOLON ? "EXTENSION" : "SIZE_LF";
          return "SKIP";
        }
        // A first line a lenient downstream parser would still read as a chunk size must
        // refuse: passing it through would let that client reassemble a value split by framing.
        // Cost, accepted: a swapped chunked body opening with whitespace or a sign is refused.
        if (!this.frameCommitted && LENIENT_SIZE_PREFIX.has(byte)) return "FAIL";
        // Ordinary decoded bodies have no opening chunk-size line. Both views then
        // coincide; never use normalized or raw header whitespace to choose a view.
        if (!this.frameCommitted) { this.frameState = "PASSTHROUGH"; return "SKIP"; }
        return "FAIL";
      }
      case "EXTENSION":
        // The strict size-line view refuses whitespace even after the extension delimiter.
        if (byte === LF || byte === SP || byte === HTAB) return "FAIL";
        if (byte === CR) this.frameState = "SIZE_LF";
        return "SKIP";
      case "SIZE_LF":
        if (byte !== LF || this.frameSize > MAX_SURROGATE_ECHO_SCAN_BYTES) return "FAIL";
        this.frameState = this.frameSize === 0 ? "FINAL_CR" : "DATA";
        return "SKIP";
      case "DATA":
        if (--this.frameSize === 0) this.frameState = "DATA_CR";
        return "DATA";
      case "DATA_CR":
        if (byte !== CR) return "FAIL";
        this.frameState = "DATA_LF";
        return "SKIP";
      case "DATA_LF":
        if (byte !== LF) return "FAIL";
        this.frameDigits = false;
        this.frameState = "SIZE";
        return "SKIP";
      case "FINAL_CR":
        if (byte !== CR) return "FAIL";
        this.frameState = "FINAL_LF";
        return "SKIP";
      case "FINAL_LF":
        if (byte !== LF) return "FAIL";
        this.frameState = "DONE";
        return "SKIP";
      case "DONE": return "FAIL";
    }
  }

  private failEncoding(): SurrogateEchoScanResult {
    this.framingFailure = true;
    this.abort();
    return { blocked: true, cause: "encoding" };
  }

  /** Must match the end-of-stream encoding refusal in egress-gate/gate-server.ts. */
  get encodingFailed(): boolean { return this.framingFailure; }

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
    // Once a size-line prefix commits the stripped parser, incomplete framing is
    // an encoding failure; flushing its carry would expose an unscreened response.
    if (this.screenChunkFrames && this.frameCommitted && this.frameState !== "DONE") {
      this.failEncoding();
      return Buffer.alloc(0);
    }
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
    this.strippedMatched.fill(0);
    this.strippedPrefixStart = undefined;
  }
}
