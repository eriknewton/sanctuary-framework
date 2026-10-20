import { write } from "node:fs";
import { Socket } from "node:net";
import { performance } from "node:perf_hooks";
import { HermesMemoryClient, type ByteSink } from "./client.js";
import { FIXED_SOCKET_PATH, SHIM_DELIVERY_MARGIN_MS } from "./protocol.js";

export { HermesMemoryClient } from "./client.js";

/** Run the isolated stdio facade; every result is a process exit disposition. */
export async function hermesMemoryClientMain(argv: readonly string[], version: string): Promise<number> {
  if (argv.length !== 0 || process.platform !== "darwin") return 64; // EX_USAGE, no ordinary boot.
  const socket = new Socket();
  let closed = false;
  let outputStopped = false;
  // Sample pipe readiness every hundredth of the delivery reserve; the client owns the total deadline.
  const outputRetryMs = SHIM_DELIVERY_MARGIN_MS / 100;
  let retry: ReturnType<typeof setTimeout> | undefined;
  const output: ByteSink = { write(bytes, done) {
    const attempt = () => {
      if (closed || outputStopped) return;
      write(process.stdout.fd, bytes, (error, written) => {
        if (closed || outputStopped) return;
        if (error && (error.code === "EAGAIN" || error.code === "EWOULDBLOCK")) {
          // One outstanding write and one retry timer keep the loop live during pipe backpressure.
          retry = setTimeout(attempt, outputRetryMs);
        } else done(error, written);
      });
    };
    attempt();
  } };
  const relayOutput: ByteSink = { write(bytes, done) {
    const handle = (socket as unknown as { _handle?: { fd?: number } })._handle;
    if (!Number.isInteger(handle?.fd)) { done(new Error("unavailable"), 0); return; }
    let offset = 0;
    const attempt = () => {
      if (closed) return;
      write(handle!.fd!, bytes.subarray(offset), (error, written) => {
        if (closed) return;
        if (error && (error.code === "EAGAIN" || error.code === "EWOULDBLOCK")) {
          // libuv resumes the remaining suffix on writability; it never replays accepted bytes.
          socket.write(bytes.subarray(offset), error => done(error ?? null, error ? offset : bytes.length));
          return;
        }
        offset += written;
        if (error || written <= 0) { done(error ?? new Error("unavailable"), offset); return; }
        if (offset === bytes.length) done(null, offset); else attempt();
      });
    };
    attempt();
  } };
  const client = new HermesMemoryClient({
    input: process.stdin, relayInput: socket, output, relayOutput,
    connect(ready, failed) { socket.once("error", failed); socket.connect(FIXED_SOCKET_PATH, ready); },
    stopOutput() { outputStopped = true; if (retry) clearTimeout(retry); },
    close() { closed = true; if (retry) clearTimeout(retry); socket.destroy(); process.stdin.pause(); },
    now: () => performance.now(), schedule: run => { setImmediate(run); },
    timer: (run, delay) => setTimeout(run, delay), clearTimer: clearTimeout,
  }, version);
  const failed = () => client.internalFailure();
  process.on("SIGINT", client.signal); process.on("SIGTERM", client.signal);
  process.on("uncaughtException", failed); process.on("unhandledRejection", failed);
  try { return await client.run(); }
  finally {
    process.off("SIGINT", client.signal); process.off("SIGTERM", client.signal);
    process.off("uncaughtException", failed); process.off("unhandledRejection", failed);
  }
}
