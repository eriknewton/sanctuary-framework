import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { withCrossProcessLock } from "../../src/storage/cross-process-lock.js";
import { appendFile } from "node:fs/promises";

const root = process.argv[2];
if (!root) throw new Error("missing temp root");
const mode = process.argv[3];
const id = process.argv[4] ?? "unknown";
const trace = process.argv[5];
const storage = new FilesystemStorage(`${root}/state`);
let socketPath = "";

await withCrossProcessLock(
  storage,
  "_fatal_holder_loss",
  ".fatal.lock",
  async () => {
    if (mode === "holder") {
      process.stdout.write("ACQUIRED\n");
      process.stdout.write(`SOCKET:${socketPath}\n`);
      await new Promise<never>(() => setInterval(() => undefined, 1_000));
    }
    if (mode !== "contender" || !trace) throw new Error("invalid fixture mode");
    await appendFile(trace, `start:${id}\n`);
    await new Promise((resolve) => setTimeout(resolve, 75));
    await appendFile(trace, `end:${id}\n`);
  },
  {
    kernelBacked: true,
    __testAfterKernelSocketAcquired: (path) => {
      socketPath = path;
    },
    timeoutMs: 3_000,
    retryMs: 10,
    onContended: (attempt) => {
      if (attempt === 1) process.stdout.write(`CONTENDED:${id}\n`);
    },
  },
);
