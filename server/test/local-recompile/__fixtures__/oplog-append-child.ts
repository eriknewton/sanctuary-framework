/**
 * Child process for the two-writer operator-log case: receives the store key
 * over IPC, appends `count` rows to the filesystem log, reports and exits.
 */
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { LocalOplog } from "../../../src/local-recompile/oplog.js";

const [root, runtimeRoot, countText, timeoutText] = process.argv.slice(2);

async function appendRows(encodedKey: string): Promise<void> {
  const key = Buffer.from(encodedKey, "base64");
  let log: LocalOplog | undefined;
  try {
    // Both writers receive the same acquire budget from the parent case.
    log = new LocalOplog(new FilesystemStorage(root!), key, { runtimeRoot, timeoutMs: Number(timeoutText) });
    key.fill(0);
    for (let index = 0; index < Number(countText); index += 1) {
      await log.append("worker_spawned", { pid: process.pid });
    }
  } finally {
    key.fill(0);
    log?.close();
  }
}

function report(reply: { done: true } | { done: false; kind: string; error: string }): void {
  // Flush the IPC reply before disconnecting, so the parent sees the append error before exit.
  process.send?.(reply, () => { if (process.connected) process.disconnect?.(); });
}

process.once("message", (message: { key: string }) => {
  // Handle rejection at launch, including construction and cleanup failures.
  void appendRows(message.key).then(
    () => report({ done: true }),
    error => report({
      done: false,
      kind: (error as { kind?: string }).kind ?? "unknown",
      error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    }),
  );
});
process.on("disconnect", () => process.exit());
