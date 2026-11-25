// fail-before-exempt: the arm exists on base; this is the direct test LR-1a left for it, and it passes there.
import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { LocalWorkerClient, type WorkerClientEvent, type WorkerTimers } from "../../src/local-recompile/worker-client.js";
import { WORKER_RESPAWN_INITIAL_MS } from "../../src/local-recompile/worker-protocol.js";
import { resolveCustodyLockRoot } from "../../src/storage/cross-process-lock.js";

const KEY_BYTES = 32; // One AES-256 store key.
const LOCK_ROOT = resolveCustodyLockRoot(process.getuid!(), { env: process.env, platform: process.platform });

/** A child whose spawn failed: no pid, never connected, and it emits error without ever emitting exit. */
class UnspawnedChild extends EventEmitter {
  pid: number | undefined = undefined;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  connected = false;
  kills: string[] = [];
  send(): boolean { return false; }
  kill(signal: string): boolean { this.kills.push(signal); return true; }
  unref(): void {}
}

function manualTimers(): { timers: WorkerTimers; pending: Array<{ callback: () => void; ms: number; cleared: boolean }> } {
  const pending: Array<{ callback: () => void; ms: number; cleared: boolean }> = [];
  return {
    pending,
    timers: {
      setTimeout: (callback, ms) => { const entry = { callback, ms, cleared: false }; pending.push(entry); return entry; },
      clearTimeout: (handle) => { (handle as { cleared: boolean }).cleared = true; },
    },
  };
}

describe("local worker client: a spawn error with no exit", () => {
  it("is treated as a death: the child is killed, backoff is scheduled, and a new spawn follows", async () => {
    const clock = manualTimers();
    const children: UnspawnedChild[] = [];
    const events: WorkerClientEvent[] = [];
    const client = new LocalWorkerClient({
      storageRoot: "/fixture",
      custodyLockRoot: LOCK_ROOT,
      oplogKey: new Uint8Array(KEY_BYTES).fill(1),
      resultsKey: new Uint8Array(KEY_BYTES).fill(2),
      timers: clock.timers,
      spawn: () => { const child = new UnspawnedChild(); children.push(child); return child as unknown as ChildProcess; },
      onEvent: (event) => events.push(event),
    });
    client.start();
    expect(children).toHaveLength(1);
    children[0]!.emit("error", new Error("spawn failed"));
    expect(children[0]!.kills).toEqual(["SIGKILL"]);
    expect(events.filter((event) => event.type === "state").map((event) => (event as { state: string }).state))
      .toEqual(["state_SPAWNING", "state_DEAD", "state_BACKOFF"]);
    expect(events.find((event) => event.type === "respawn_scheduled")).toEqual({ type: "respawn_scheduled", delay_ms: WORKER_RESPAWN_INITIAL_MS });
    // Nothing is sent to a dead child.
    expect(client.send({ type: "shutdown" })).toBe(false);
    const respawn = clock.pending.find((entry) => entry.ms === WORKER_RESPAWN_INITIAL_MS && !entry.cleared)!;
    respawn.callback();
    expect(children).toHaveLength(2);
    expect(client.state).toBe("state_SPAWNING");
    await client.close();
    expect(client.state).toBe("state_CLOSED");
  });
});
