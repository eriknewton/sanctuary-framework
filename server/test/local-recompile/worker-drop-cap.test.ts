// Jobs a worker holds and drop rows not yet durable share the seat cap, across worker generations.
// Runs the real composition (tool, worker client, drop log) in process, with a scripted child for the
// worker and a gate that holds every operator-log write.
import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { composeLocalTask, type ComposedLocalTask } from "../../src/local-recompile/compose.js";
import { WORKER_QUEUE_MAX } from "../../src/local-recompile/limits.js";
import { LocalOplog } from "../../src/local-recompile/oplog.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { LOCAL_OPLOG_NAMESPACE } from "../../src/local-recompile/store-record.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { StrictMemoryStorage, fixtureRequestId } from "./__fixtures__/strict-memory-storage.js";

// At least three generations, each admitted past the cap and then killed with its jobs unended.
const WAVES = 3;
// One call past the cap in every wave, so each wave asks for more than the cap allows.
const CALLS_PER_WAVE = WORKER_QUEUE_MAX + 1;
// Long enough for the capped respawn backoff of every wave (one, two, then four seconds) on a loaded machine.
const RESPAWN_WAIT_MS = 30_000;
const POLL_MS = 20;
const TEST_TIMEOUT_MS = 120_000;
// Far above any real pid, so a scripted child's pid can never name a live process.
const FAKE_PID_BASE = 4_000_000;
const VALID = { kind: "summarize", sources: { refs: [{ namespace: "notes", key: "one" }] }, instruction: "Summarize." };

/** A worker child scripted in process: ready on init, holds every job it is sent, exits on shutdown or kill. */
class ScriptedWorker extends EventEmitter {
  static spawned = 0;
  readonly pid = FAKE_PID_BASE + (ScriptedWorker.spawned += 1);
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  connected = true;
  readonly jobs: string[] = [];

  send(message: { type: string; request_id?: string }, callback?: (error: Error | null) => void): boolean {
    if (!this.connected) return false;
    if (message.type === "job") this.jobs.push(message.request_id!);
    setImmediate(() => {
      callback?.(null);
      if (message.type === "init") this.emit("message", { type: "ready" });
      if (message.type === "shutdown") this.exit(null);
    });
    return true;
  }

  kill(signal: NodeJS.Signals = "SIGTERM"): boolean {
    this.exit(signal);
    return true;
  }

  unref(): void {}

  private exit(signal: NodeJS.Signals | null): void {
    if (!this.connected) return;
    this.connected = false;
    this.signalCode = signal;
    this.exitCode = signal === null ? 0 : null;
    setImmediate(() => this.emit("exit", this.exitCode, signal));
  }
}

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const step of cleanups.splice(0).reverse()) await step();
});

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + RESPAWN_WAIT_MS;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}

describe("pending drop writes share the seat cap", () => {
  it("repeated waves of lost jobs with every drop write held never leave more than the cap pending", async () => {
    const storage = new StrictMemoryStorage();
    // A held write keeps the log's lock; the appends queued behind it wait for it, never time out.
    storage.acquireWait = () => new Promise(() => undefined);
    let releaseGate: () => void = () => undefined;
    let gated = false;
    const gate = new Promise<void>((resolve) => { releaseGate = resolve; });
    storage.beforeMutation = async (call) => {
      if (gated && call.namespace === LOCAL_OPLOG_NAMESPACE) await gate;
    };
    const masterKey = generateRandomKey();
    const children: ScriptedWorker[] = [];
    let ids = 0;
    const descriptor = Object.freeze({ runtime_tag: "qwen2.5:1.5b", manifest_digest: "1".repeat(64), endpoint: Object.freeze({ address: "127.0.0.1", port: 9 }) });
    const composed: ComposedLocalTask = await composeLocalTask({
      bootOwnsStorage: true,
      storage,
      storageRoot: "/fixture-drop-cap",
      masterKey,
      auditLog: { appendCritical: async () => undefined },
      binding: { describeVerifiedLocalBinding: () => ({ ok: true, epoch: 1, descriptor }) },
      policy: DEFAULT_POLICY,
      identities: () => [],
      underVitest: true,
      test: {
        spawnWorker: () => {
          const child = new ScriptedWorker();
          children.push(child);
          return child as unknown as ChildProcess;
        },
        idSource: () => fixtureRequestId((ids += 1)),
      },
    });
    cleanups.push(async () => {
      releaseGate();
      await composed.close();
    });
    expect(composed.status.armed).toBe(true);
    gated = true;

    let pendingDrops = 0;
    for (let wave = 0; wave < WAVES; wave += 1) {
      await until(() => children.length === wave + 1 && composed.status.workerState() === "state_READY", `worker ${wave + 1} ready`);
      const child = children.at(-1)!;
      for (let call = 0; call < CALLS_PER_WAVE; call += 1) {
        const answer = await composed.tool.handler(VALID, `agent:wave-${wave}-${call}`);
        // The agent's answer is the same acknowledgement whether the job was sent or refused as full.
        expect(JSON.parse(answer.content[0]!.text).status).toBe("submitted");
      }
      // Every job this worker holds becomes a pending drop write when it dies, and every write is held.
      pendingDrops += child.jobs.length;
      expect(pendingDrops, `pending drop writes after wave ${wave + 1}`).toBeLessThanOrEqual(WORKER_QUEUE_MAX);
      child.kill("SIGKILL");
    }
    await until(() => children.length === WAVES + 1 && composed.status.workerState() === "state_READY", "the last respawn");
    // The first generation filled the cap; while its drop rows were held, no later one was sent a job.
    expect(children.slice(0, WAVES).map((child) => child.jobs.length)).toEqual([WORKER_QUEUE_MAX, ...Array<number>(WAVES - 1).fill(0)]);

    // Once the held writes land, the cap frees and the next submission is sent again.
    gated = false;
    releaseGate();
    const keys = deriveLocalStoreKeys(masterKey);
    const reader = new LocalOplog(storage, keys.oplogKey);
    cleanups.push(async () => {
      reader.close();
      keys.oplogKey.fill(0);
      keys.resultsKey.fill(0);
    });
    const drops = async () => {
      const status = await reader.status();
      return (await reader.readRows(status.base_seq, status.rows)).filter((row) => row.kind === "job_dropped");
    };
    const refusedAsFull = WAVES * CALLS_PER_WAVE - WORKER_QUEUE_MAX;
    const deadline = Date.now() + RESPAWN_WAIT_MS;
    while ((await drops()).length < WAVES * CALLS_PER_WAVE && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    }
    const causes = (await drops()).map((row) => (row.body as { cause: string }).cause);
    // Every submission past the cap was refused as full, and every lost job's drop row was written once.
    expect(causes.filter((cause) => cause === "queue_full")).toHaveLength(refusedAsFull);
    expect(causes.filter((cause) => cause === "worker_unavailable")).toHaveLength(WORKER_QUEUE_MAX);
    await composed.tool.handler(VALID, "agent:after-release");
    expect(children.at(-1)!.jobs).toHaveLength(1);
  }, TEST_TIMEOUT_MS);
});
