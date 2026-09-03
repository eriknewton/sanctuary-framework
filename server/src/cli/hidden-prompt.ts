import { StringDecoder } from "node:string_decoder";

/**
 * Sanctuary MCP Server — shared no-echo (hidden) terminal prompt.
 *
 * ONE implementation of "read a secret line from a TTY with echo suppressed",
 * so the custody verbs that must never echo a passphrase or recovery key to the
 * screen or a scrollback buffer (`secrets`, `reset-passphrase --mode
 * recovery-key`, `restore-attest --recovery-key-prompt`) share the same raw-mode
 * reader instead of hand-copying it (the copy-drift the parity rules warn about).
 *
 * TTY-only by contract: callers gate on `stdin.isTTY`, and this shared reader
 * independently enforces both a true TTY marker and a callable raw-mode
 * capability before displaying anything. A recovery secret therefore cannot
 * be scraped from piped stdin or echoed by a TTY-like stream that cannot
 * actually suppress terminal echo.
 *
 * Cleanup contract (why this file is more than a `readline` wrapper):
 *  - The durable accumulator is a mutable Buffer and is zeroed when the prompt
 *    settles. Node's StringDecoder necessarily creates transient immutable JS
 *    strings while decoding and the final value returned to the caller is also
 *    immutable; JavaScript cannot promise zeroization of those copies. Each
 *    incoming chunk is copied into a private mutable decode buffer which is
 *    scrubbed without mutating stream-owned state. The guarantee is best-effort
 *    clearing of owned mutable bytes, not erasure of every runtime or terminal-
 *    driver copy.
 *  - The prompt settles EXACTLY ONCE. Every terminating path (Enter, Ctrl-D,
 *    Ctrl-C, stdin end/close/error, an output-stream error, or an exception
 *    thrown inside the data listener) routes through one `settle()` that
 *    restores raw mode, removes every listener, and zeroes the byte buffer —
 *    all idempotent — so the terminal is never left in raw mode and the promise
 *    can never hang or double-resolve.
 */

// Control bytes read in raw mode, built from code points so no literal control
// byte ever appears in source. Named so the reader below reads as a diagram.
const ETX = String.fromCharCode(0x03); // Ctrl-C (end-of-text)
const EOT = String.fromCharCode(0x04); // Ctrl-D (end-of-transmission)
const DEL = String.fromCharCode(0x7f); // Delete
const BACKSPACE = String.fromCharCode(0x08); // Backspace

/** The stdin shape a raw-mode read needs. `process.stdin` satisfies it. */
export interface RawModeStdin extends NodeJS.ReadableStream {
  isTTY?: boolean;
  setRawMode?(mode: boolean): this;
  resume(): this;
  pause(): this;
}

export interface HiddenPromptOptions {
  /**
   * Where the prompt label is written. Defaults to `process.stderr`. Typed as
   * the minimal `NodeJS.WritableStream` (write + EventEmitter on/off), which is
   * all this reader uses, so every custody verb's `NodeJS.WritableStream` err
   * channel flows in with no cast.
   */
  err?: NodeJS.WritableStream;
  /**
   * What to do on Ctrl-C (ETX). Defaults to `process.exit(130)` — the
   * conventional 128+SIGINT shell code. Tests override this to avoid killing
   * the runner; production leaves it default so an operator abort is honored.
   */
  onSigint?: () => void;
  /** Test seam; production bounds the terminating newline callback to 2s. */
  completionTimeoutMs?: number;
}

/**
 * Prompt on `err` and read one line from `stdin` with echo suppressed. Returns
 * the typed value WITHOUT the terminating newline. Backspace/DEL edit the
 * buffer; Enter/Return and Ctrl-D (EOT) terminate the line. Raw mode is always
 * restored (and stdin paused) and the owned mutable secret buffers are zeroed
 * before settling, including on the Ctrl-C / end / close / error paths. Immutable
 * decoder/result strings cannot be scrubbed and are not covered by that claim.
 *
 * Rejects if the input stream emits `error`, the output stream emits/throws an
 * error, or the data listener throws; a premature `end`/`close` (EOF with no
 * newline) resolves with whatever was typed so far, so a caller that trims and
 * checks for empty treats it as an abort.
 *
 * The prompt label is written as `${prompt}: ` to match the existing secrets
 * flow byte-for-byte.
 */
export async function promptHiddenLine(
  stdin: RawModeStdin,
  prompt: string,
  opts: HiddenPromptOptions = {},
): Promise<string> {
  if (stdin.isTTY !== true) {
    throw new Error("hidden prompt requires an interactive TTY input stream");
  }
  if (typeof stdin.setRawMode !== "function") {
    throw new Error(
      "hidden prompt cannot suppress terminal echo because raw mode is unavailable",
    );
  }
  const setRawMode = stdin.setRawMode.bind(stdin);
  const err = opts.err ?? process.stderr;
  const onSigint = opts.onSigint ?? ((): void => void process.exit(130));
  const completionTimeoutMs = opts.completionTimeoutMs ?? 2_000;

  return await new Promise<string>((resolve, reject) => {
    // Growable byte accumulator: this is the mutable copy we own and can scrub.
    // StringDecoder and the final API result also create unavoidable immutable
    // strings; see the module threat-model note. `charLens` records the byte-width
    // of each accepted character so backspace/DEL rewinds whole characters.
    let buf = Buffer.alloc(256);
    let len = 0;
    const charLens: number[] = [];
    // Stateful UTF-8 decoding is required for terminal paste/input where a
    // multibyte code point can be split across adjacent `data` chunks.
    const decoder = new StringDecoder("utf8");
    let settled = false;
    // A terminating control byte has been accepted and its display-only newline
    // is still being flushed. Keep listeners/raw cleanup live until that write's
    // callback settles; ignore further input while this boundary is pending.
    let finalizing = false;
    let completionTimer: NodeJS.Timeout | undefined;

    const ensure = (extra: number): void => {
      if (len + extra <= buf.length) return;
      let cap = buf.length * 2;
      while (cap < len + extra) cap *= 2;
      const bigger = Buffer.alloc(cap);
      buf.copy(bigger, 0, 0, len);
      buf.fill(0); // zero the old backing store before dropping it
      buf = bigger;
    };

    // Runs EXACTLY ONCE: restore the terminal, drop every listener, zero the
    // secret bytes, then settle the promise. Idempotent via `settled`.
    const settle = (value: string | null, error?: Error): void => {
      if (settled) return;
      settled = true;
      if (completionTimer !== undefined) clearTimeout(completionTimer);
      try {
        setRawMode(false);
        stdin.pause();
      } catch {
        // A tty that refuses to leave raw mode must not mask the original
        // outcome; the process is exiting the prompt regardless.
      }
      stdin.off("data", onData);
      stdin.off("error", onInputError);
      stdin.off("end", onEnd);
      stdin.off("close", onEnd);
      err.off("error", onOutputError);
      buf.fill(0); // zero the raw secret bytes before returning
      if (error) reject(error);
      else resolve(value ?? "");
    };

    // Decode only the accepted bytes to a string at settle time; this is the one
    // unavoidable immutable copy handed to the caller.
    const decode = (): string => buf.toString("utf8", 0, len);

    const onInputError = (error: Error): void => settle(null, error);
    const onOutputError = (error: Error): void => settle(null, error);
    const writeTerminatingNewline = (afterWrite: () => void): void => {
      if (settled || finalizing) return;
      finalizing = true;
      completionTimer = setTimeout(() => {
        settle(null, new Error("hidden prompt output did not complete within the bounded timeout"));
      }, completionTimeoutMs);
      completionTimer.unref?.();
      try {
        err.write("\n", (error?: Error | null) => {
          // Node invokes a failed write callback before its queued `error`
          // event. Defer settling one microtask so the still-attached error
          // listener consumes that event; a minimal custom writable that only
          // reports through the callback still rejects here.
          queueMicrotask(() => {
            if (settled) return;
            if (error) settle(null, error);
            else afterWrite();
          });
        });
      } catch (error) {
        settle(null, error instanceof Error ? error : new Error(String(error)));
      }
    };
    const acceptDecoded = (s: string): boolean => {
      try {
        for (const ch of s) {
          if (ch === "\r" || ch === "\n" || ch === EOT) {
            // Enter/Return and Ctrl-D (EOT) both terminate the line.
            writeTerminatingNewline(() => settle(decode()));
            return true;
          }
          if (ch === ETX) {
            // Restore + zero happen inside settle() before onSigint fires, so a
            // killed prompt never strands the tty in raw mode or leaks bytes.
            writeTerminatingNewline(() => {
              // Ctrl-C is cancellation, not a successful secret read. Do not
              // construct or return an immutable JS string containing bytes
              // the operator explicitly aborted.
              settle("");
              onSigint();
            });
            return true;
          }
          if (ch === DEL || ch === BACKSPACE) {
            const n = charLens.pop();
            if (n !== undefined) {
              len -= n;
              buf.fill(0, len, len + n); // scrub the removed character's bytes
            }
            continue;
          }
          const bytes = Buffer.from(ch, "utf8");
          ensure(bytes.length);
          bytes.copy(buf, len);
          len += bytes.length;
          charLens.push(bytes.length);
          bytes.fill(0);
        }
      } catch (error) {
        // Any throw inside the listener (e.g. an EPIPE from err.write) routes
        // through the single settle path so the promise never hangs.
        settle(null, error instanceof Error ? error : new Error(String(error)));
        return true;
      }
      return false;
    };

    // EOF with no newline: flush any pending decoder state, then resolve with
    // what was typed so the caller's empty-check treats an empty read as abort.
    const onEnd = (): void => {
      if (settled || finalizing) return;
      if (!acceptDecoded(decoder.end())) settle(decode());
    };

    const onData = (chunk: Buffer): void => {
      if (settled || finalizing) return;
      // A Readable may share its emitted Buffer with other listeners; copy it
      // before decoding so cleanup never mutates caller-owned stream state.
      const owned = Buffer.from(chunk);
      let decoded: string;
      try {
        decoded = decoder.write(owned);
      } finally {
        owned.fill(0);
      }
      acceptDecoded(decoded);
    };

    // Attach every listener and enter raw mode BEFORE writing the label. If the
    // operator types as soon as the prompt appears, there is no echo-enabled
    // window between display and terminal suppression.
    stdin.on("data", onData);
    stdin.on("error", onInputError);
    stdin.on("end", onEnd);
    stdin.on("close", onEnd);
    err.on("error", onOutputError);

    try {
      setRawMode(true);
      err.write(`${prompt}: `);
      stdin.resume();
    } catch (error) {
      settle(null, error instanceof Error ? error : new Error(String(error)));
    }
  });
}
