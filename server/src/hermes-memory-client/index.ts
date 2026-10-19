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
  let retry: ReturnType<typeof setTimeout> | undefined;
  const output: ByteSink = { write(bytes, done) {
    const attempt = () => {
      if (closed) return;
      write(process.stdout.fd, bytes, (error, written) => {
        if (error && (error.code === "EAGAIN" || error.code === "EWOULDBLOCK")) {
          // One outstanding write and one retry timer keep the loop live during pipe backpressure.
          retry = setTimeout(attempt, SHIM_DELIVERY_MARGIN_MS / 200); // 200 opportunities in the delivery reserve.
        } else done(error, written);
      });
    };
    attempt();
  } };
  const relayOutput: ByteSink = { write(bytes, done) {
    // Node's stream write hides short native writes; the socket's owned fd preserves their disposition.
    const handle = (socket as unknown as { _handle?: { fd?: number } })._handle;
    if (!Number.isInteger(handle?.fd)) { done(new Error("unavailable"), 0); return; }
    write(handle!.fd!, bytes, (error, written) => done(error, written));
  } };
  const client = new HermesMemoryClient({
    input: process.stdin, relayInput: socket, output, relayOutput,
    connect(ready, failed) { socket.once("error", failed); socket.connect(FIXED_SOCKET_PATH, ready); },
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
