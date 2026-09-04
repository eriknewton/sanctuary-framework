/**
 * `promptHiddenLine` shared no-echo terminal reader.
 *
 * Verifies raw mode is entered/exited, the prompt is written to the provided
 * stream, the typed line is returned without its newline, backspace/DEL edit the
 * buffer, and Ctrl-C routes to the injected sigint handler (so the test process
 * is never killed). Also verifies the cleanup contract: input error/end/close,
 * output-stream error, Ctrl-D (EOT), and an exception thrown inside the data
 * listener all settle the promise exactly once with raw mode restored, so no
 * path can hang or strand the tty in raw mode.
 */

import { describe, it, expect, vi } from "vitest";
import { EventEmitter } from "node:events";
import { Writable } from "node:stream";

import { promptHiddenLine, type RawModeStdin } from "../../src/cli/hidden-prompt.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

/** A writable whose every write throws synchronously (models EPIPE on stderr). */
class ThrowingWritable extends Writable {
  override _write(): void {
    throw new Error("EPIPE");
  }
  override write(): boolean {
    throw new Error("EPIPE");
  }
}

/** Accepts the label, then reports the terminating newline failure later. */
class AsyncNewlineErrorWritable extends Writable {
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error | null) => void,
  ): void {
    const value = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (value === "\n") {
      setImmediate(() => cb(new Error("async EPIPE")));
    } else {
      cb();
    }
  }
}

class NeverCompletesNewlineWritable extends Writable {
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error | null) => void,
  ): void {
    const value = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (value !== "\n") cb();
  }
}

class FakeTty extends EventEmitter {
  isTTY = true;
  rawMode: boolean | null = null;
  rawModeSets: boolean[] = [];
  resumes = 0;
  pauses = 0;
  setRawMode(mode: boolean): this {
    this.rawMode = mode;
    this.rawModeSets.push(mode);
    return this;
  }
  resume(): this {
    this.resumes += 1;
    return this;
  }
  pause(): this {
    this.pauses += 1;
    return this;
  }
}

function asStdin(t: FakeTty): RawModeStdin {
  return t as unknown as RawModeStdin;
}

describe("promptHiddenLine", () => {
  it("fails closed before displaying a prompt when a claimed TTY lacks raw mode", async () => {
    const tty = new FakeTty() as unknown as RawModeStdin;
    // Class methods live on the prototype, so shadow it explicitly.
    (tty as unknown as { setRawMode?: unknown }).setRawMode = undefined;
    const err = new StringWritable();
    await expect(promptHiddenLine(tty, "Recovery key", { err })).rejects.toThrow(
      "cannot suppress terminal echo",
    );
    expect(err.text).toBe("");
    expect(tty.listenerCount("data")).toBe(0);
  });

  it("returns the typed line without the newline and restores raw mode", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "Recovery key", { err });
    // Listener is attached synchronously before the pending promise is returned.
    tty.emit("data", Buffer.from("s3cret\n"));
    const value = await p;
    expect(value).toBe("s3cret");
    expect(err.text).toContain("Recovery key: ");
    // Raw mode was turned on and then off again.
    expect(tty.rawMode).toBe(false);
  });

  it("does not echo the typed characters to the prompt stream", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "Recovery key", { err });
    tty.emit("data", Buffer.from("hunter2\n"));
    await p;
    expect(err.text).not.toContain("hunter2");
  });

  it("does not mutate stream-owned chunks while consuming a private copy", async () => {
    const tty = new FakeTty();
    const chunk = Buffer.from("owned-secret\n");
    const p = promptHiddenLine(asStdin(tty), "k", { err: new StringWritable() });
    tty.emit("data", chunk);
    expect(await p).toBe("owned-secret");
    expect(chunk.toString("utf8")).toBe("owned-secret\n");
  });

  it("honors backspace and DEL, including across multi-byte characters", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    // 'a','b', DEL (0x7f) removes 'b', 'c', BACKSPACE (0x08) removes 'c', 'd'
    tty.emit(
      "data",
      Buffer.from("ab" + String.fromCharCode(0x7f) + "c" + String.fromCharCode(0x08) + "d\n"),
    );
    expect(await p).toBe("ad");
  });

  it("rewinds a whole multi-byte character on backspace", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    // 'x', 'é' (2 UTF-8 bytes), BACKSPACE removes the whole 'é', 'y'
    tty.emit("data", Buffer.from("xé" + String.fromCharCode(0x08) + "y\n"));
    expect(await p).toBe("xy");
  });

  it("preserves a UTF-8 code point split across adjacent data chunks", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    const encoded = Buffer.from("é", "utf8");
    tty.emit("data", encoded.subarray(0, 1));
    tty.emit("data", Buffer.concat([encoded.subarray(1), Buffer.from("\n")]));
    expect(await p).toBe("é");
  });

  it("backspace removes one whole code point even when its UTF-8 bytes were split", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    const encoded = Buffer.from("é", "utf8");
    tty.emit("data", encoded.subarray(0, 1));
    tty.emit("data", encoded.subarray(1));
    tty.emit("data", Buffer.from(String.fromCharCode(0x08) + "x\n"));
    expect(await p).toBe("x");
  });

  it("routes Ctrl-C to the injected sigint handler instead of exiting", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const onSigint = vi.fn();
    const p = promptHiddenLine(asStdin(tty), "k", { err, onSigint });
    tty.emit("data", Buffer.from(String.fromCharCode(0x03)));
    expect(await p).toBe("");
    expect(onSigint).toHaveBeenCalledOnce();
    expect(tty.rawMode).toBe(false);
    expect(tty.resumes).toBe(1);
    expect(tty.pauses).toBe(1);
    expect(tty.listenerCount("data")).toBe(0);
  });

  it("terminates the line on Ctrl-D (EOT) and does not append the control byte", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    tty.emit("data", Buffer.from("abc" + String.fromCharCode(0x04)));
    const value = await p;
    expect(value).toBe("abc");
    expect(value).not.toContain(String.fromCharCode(0x04));
    expect(tty.rawMode).toBe(false);
  });

  it("resolves with what was typed on a premature stdin end (EOF)", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    tty.emit("data", Buffer.from("partial"));
    tty.emit("end");
    expect(await p).toBe("partial");
    expect(tty.rawMode).toBe(false);
  });

  it("resolves on stdin close", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    tty.emit("close");
    expect(await p).toBe("");
    expect(tty.rawMode).toBe(false);
  });

  it("rejects and restores raw mode when the input stream errors", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    tty.emit("error", new Error("input boom"));
    await expect(p).rejects.toThrow("input boom");
    expect(tty.rawMode).toBe(false);
  });

  it("rejects and restores raw mode when the output stream throws on write", async () => {
    const tty = new FakeTty();
    const err = new ThrowingWritable();
    // The label write throws synchronously; it must route through settle, not
    // escape as an uncaught throw, and raw mode must still be restored.
    await expect(promptHiddenLine(asStdin(tty), "k", { err })).rejects.toThrow("EPIPE");
    expect(tty.rawMode).toBe(false);
  });

  it("catches an exception thrown inside the data listener and settles once", async () => {
    const tty = new FakeTty();
    // An err whose write throws synchronously on the terminating newline write
    // (chunk === "\n") but accepts the label write, so the exception is raised
    // from inside onData rather than from the label write above the loop.
    class NewlineThrows extends Writable {
      chunks: string[] = [];
      override write(chunk: Buffer | string): boolean {
        const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
        if (s === "\n") throw new Error("write during data");
        this.chunks.push(s);
        return true;
      }
    }
    const err = new NewlineThrows();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    tty.emit("data", Buffer.from("abc\n"));
    await expect(p).rejects.toThrow("write during data");
    expect(tty.rawMode).toBe(false);
  });

  it("keeps output error handling through an async terminating-newline failure", async () => {
    const tty = new FakeTty();
    const err = new AsyncNewlineErrorWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    tty.emit("data", Buffer.from("abc\n"));

    await expect(p).rejects.toThrow("async EPIPE");
    // Let Writable's queued `error` emission run too: it must be consumed by
    // the prompt listener, not surface as an unhandled post-settle event.
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(tty.rawMode).toBe(false);
    expect(tty.rawModeSets.filter((mode) => mode === false)).toHaveLength(1);
    expect(err.listenerCount("error")).toBe(0);
  });

  it("fails closed and restores raw mode when newline completion never arrives", async () => {
    const tty = new FakeTty();
    const err = new NeverCompletesNewlineWritable();
    const p = promptHiddenLine(asStdin(tty), "k", {
      err,
      completionTimeoutMs: 20,
    });
    tty.emit("data", Buffer.from("abc\n"));
    await expect(p).rejects.toThrow("bounded timeout");
    expect(tty.rawMode).toBe(false);
    expect(tty.listenerCount("data")).toBe(0);
  });

  it("settles exactly once when two terminating events arrive", async () => {
    const tty = new FakeTty();
    const err = new StringWritable();
    const p = promptHiddenLine(asStdin(tty), "k", { err });
    tty.emit("data", Buffer.from("done\n"));
    // A late close after the line already resolved must be a no-op.
    tty.emit("close");
    expect(await p).toBe("done");
    // Raw mode was set true once and false exactly once (no double restore).
    expect(tty.rawModeSets.filter((m) => m === false)).toHaveLength(1);
  });
});
