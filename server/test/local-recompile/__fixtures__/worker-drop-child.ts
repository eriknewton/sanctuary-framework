/**
 * Child process that runs the real local job worker with every offered job
 * refused as queue_full, and with its job_dropped append controlled, so the
 * order of a drop's row and its terminal state can be driven:
 *
 * - "hold": the append never settles;
 * - "fail": the append rejects;
 * - "plain": the append runs normally.
 *
 * In every mode a marker file is written when the drop's append starts.
 *
 * argv: mode markerFile
 */
import { writeFileSync } from "node:fs";
import { LocalJobQueue } from "../../../src/local-recompile/job-queue.js";
import { LocalOplog } from "../../../src/local-recompile/oplog.js";

const [mode, markerFile] = process.argv.slice(2) as [string, string];

LocalJobQueue.prototype.offer = function () {
  return { queued: false, cause: "queue_full" } as const;
};

const realAppend = LocalOplog.prototype.append;
LocalOplog.prototype.append = function (this: LocalOplog, ...args: Parameters<typeof realAppend>) {
  if (args[0] === "job_dropped") {
    writeFileSync(markerFile, "started");
    if (mode === "hold") return new Promise(() => undefined);
    if (mode === "fail") return Promise.reject(new Error("fixture append failure"));
  }
  return realAppend.apply(this, args);
} as typeof realAppend;

await import("../../../src/local-recompile/worker-entry.js");
