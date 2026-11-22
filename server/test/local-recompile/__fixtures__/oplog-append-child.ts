/**
 * Child process for the two-writer operator-log case: receives the store key
 * over IPC, appends `count` rows to the filesystem log, reports and exits.
 */
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { LocalOplog } from "../../../src/local-recompile/oplog.js";

const [root, runtimeRoot, countText] = process.argv.slice(2);
process.once("message", (message: { key: string }) => {
  void (async () => {
    const key = Buffer.from(message.key, "base64");
    let log: LocalOplog | undefined;
    try {
      // Constructed inside the try, so a refused construction still reports and disconnects.
      log = new LocalOplog(new FilesystemStorage(root!), key, { runtimeRoot });
      key.fill(0);
      for (let index = 0; index < Number(countText); index += 1) {
        await log.append("worker_spawned", { pid: process.pid });
      }
      process.send?.({ done: true });
    } catch (error) {
      process.send?.({ done: false, kind: (error as { kind?: string }).kind ?? "unknown" });
    } finally {
      key.fill(0);
      log?.close();
      process.disconnect?.();
    }
  })();
});
process.on("disconnect", () => process.exit());
