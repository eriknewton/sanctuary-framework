/** Bounded, durable full-daemon restart admission. Job 996. */
import * as fs from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const modulePath = "../../src/cli/castle-wall-full-agent-state.js";
const loaded = await import(modulePath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent-state.js") | null;
const roots: string[] = [];
beforeEach(() => expect(loaded, "restart admission module is shipped").not.toBeNull());
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const api = loaded!;
  const root = fs.mkdtempSync("/tmp/j996-counter-"); roots.push(root);
  let now = 1_000_000; // Stable nonzero fixture epoch, milliseconds.
  const stderr = vi.fn(() => 0);
  const io = { ...fs, writeSync: stderr as typeof fs.writeSync };
  const store = new api.FullAgentStateStore(root, { now: () => now, fs: io });
  return { api, root, store, io, stderr, advance: (ms: number) => { now += ms; } };
}
const SECOND_MS = 1000;

describe("full agent restart state", () => {
  it("latches the fifth charged start with a durable record and exact stop line and exit zero", () => {
    const { api, store, stderr, advance } = fixture();
    expect(store.admit().admitted).toBe(true);
    for (let charge = 1; charge < api.FULL_AGENT_CRASH_BUDGET; charge++) {
      advance(SECOND_MS);
      expect(store.admit().admitted).toBe(true);
    }
    advance(SECOND_MS);
    expect(store.admit()).toMatchObject({ admitted: false, exitCode: 0, charges: api.FULL_AGENT_CRASH_BUDGET });
    expect(store.read()?.state).toBe("state_LATCHED");
    expect(store.admit()).toMatchObject({ admitted: false, exitCode: 0 });
    expect(stderr).toHaveBeenLastCalledWith(2, `[castle-wall] FULL-AGENT-CRASH-LOOP-STOP reason=crash_budget charges=5 window_s=1800 - automatic restart stopped; run 'sanctuary castle-wall reset-full --yes'\n`);
    expect(fs.statSync(store.directory).mode & 0o777).toBe(0o700);
    expect(fs.statSync(store.path).mode & 0o777).toBe(0o600);
  });

  it("never charges a clean stop", () => {
    const { store, advance } = fixture();
    expect(store.admit().admitted).toBe(true);
    store.stoppedClean();
    advance(SECOND_MS);
    expect(store.admit()).toMatchObject({ admitted: true, record: { charges_ms: [] } });
  });

  it("drops charges older than the window", () => {
    const { api, store, advance } = fixture();
    store.admit(); advance(SECOND_MS); store.admit();
    expect(store.read()?.charges_ms).toHaveLength(1);
    store.stoppedClean();
    advance(api.FULL_AGENT_CRASH_WINDOW_S * SECOND_MS + 1);
    expect(store.admit()).toMatchObject({ admitted: true, record: { charges_ms: [] } });
  });

  it.each(["corrupt", "oversized", "symlink", "unsafe-directory", "unwritable"])("terminal stop on %s state never replenishes admission", kind => {
    const { api, store, io, root } = fixture();
    expect(store.admit().admitted).toBe(true);
    const original = fs.readFileSync(store.path);
    let subject = store;
    if (kind === "corrupt") fs.writeFileSync(store.path, "{");
    if (kind === "oversized") fs.writeFileSync(store.path, "x".repeat(api.FULL_AGENT_STATE_READ_CAP_BYTES + 1));
    if (kind === "symlink") {
      const target = join(root, "unrelated"); fs.writeFileSync(target, original);
      fs.unlinkSync(store.path); fs.symlinkSync(target, store.path);
    }
    if (kind === "unsafe-directory") fs.chmodSync(store.directory, 0o777);
    if (kind === "unwritable") subject = new api.FullAgentStateStore(root, {
      fs: { ...io, openSync: (() => { throw Object.assign(new Error("fixture denied"), { code: "EACCES" }); }) as typeof fs.openSync },
    });
    const before = fs.readFileSync(store.path);
    expect(subject.admit()).toMatchObject({ admitted: false, exitCode: 0 });
    expect(fs.readFileSync(store.path)).toEqual(before);
  });

  it("directory symlinks and unsafe file modes stop rather than start", () => {
    const { api, root, store } = fixture();
    store.admit(); fs.chmodSync(store.path, 0o666);
    expect(store.admit()).toMatchObject({ admitted: false, exitCode: 0 });
    fs.chmodSync(store.path, 0o600);
    const other = fs.mkdtempSync("/tmp/j996-symlink-"); roots.push(other);
    fs.symlinkSync(store.directory, join(other, "supervision"));
    expect(new api.FullAgentStateStore(other).admit()).toMatchObject({ admitted: false, exitCode: 0 });
    expect(root).not.toBe(other);
  });

  it("one thousand clean cycles stay within the schema-derived read cap", () => {
    const { api, store, advance } = fixture();
    const CYCLES = 1000; // Rule 8 repeated-admission workload.
    for (let i = 0; i < CYCLES; i++) {
      expect(store.admit().admitted).toBe(true);
      store.stoppedClean(); advance(SECOND_MS);
      expect(fs.statSync(store.path).size).toBeLessThanOrEqual(api.FULL_AGENT_STATE_READ_CAP_BYTES);
    }
    expect(fs.readdirSync(store.directory)).toEqual(["full-agent.json"]);
  });

  it("an orphan publication slot stops admission without accumulating files and reset clears it", () => {
    const { store } = fixture();
    store.admit();
    const temporary = join(store.directory, ".full-agent.tmp");
    fs.writeFileSync(temporary, "unfinished", { mode: 0o600 });
    expect(store.admit()).toMatchObject({ admitted: false, exitCode: 0 });
    expect(store.admit()).toMatchObject({ admitted: false, exitCode: 0 });
    expect(fs.readFileSync(temporary, "utf8")).toBe("unfinished");
    expect(fs.readdirSync(store.directory).sort()).toEqual([".full-agent.tmp", "full-agent.json"]);
    expect(() => store.reset()).toThrow("Only a latched full daemon can be reset.");
    fs.unlinkSync(temporary);
    for (let i = 0; i < loaded!.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    fs.writeFileSync(temporary, "unfinished", { mode: 0o600 });
    store.reset();
    expect(fs.existsSync(temporary)).toBe(false);
    expect(store.admit().admitted).toBe(true);
  });

  it("reset explicitly replaces a latch and a failed clean write retains running state", () => {
    const { api, root, store, io } = fixture();
    for (let i = 0; i <= api.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    store.reset(); expect(store.read()?.state).toBe("state_STOPPED_CLEAN");
    store.admit();
    const failing = new api.FullAgentStateStore(root, { fs: { ...io, writeFileSync: () => { throw new Error("fixture write failed"); } } });
    expect(() => failing.stoppedClean()).toThrow();
    expect(store.read()?.state).toBe("state_RUNNING");
  });

  it.each(["state_RUNNING", "state_STOPPED_CLEAN", "state_ABSENT"])("reset refuses %s without changing accounting", state => {
    const { store } = fixture();
    if (state !== "state_ABSENT") store.admit();
    if (state === "state_STOPPED_CLEAN") store.stoppedClean();
    const before = store.read();
    expect(() => store.reset()).toThrow("Only a latched full daemon can be reset.");
    expect(store.read()).toEqual(before);
  });

  it("reset waits and re-reads an admission published while it contends", () => {
    const { api, root, store, io } = fixture();
    for (let i = 0; i <= api.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    const lock = join(store.directory, "full-agent.lock");
    fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, started_ms: 0 }), { mode: 0o600 });
    const running = { ...store.read()!, state: "state_RUNNING", latched_reason: null, charges_ms: [] };
    const wait = vi.fn(() => {
      // Inject the lock owner's publication and release before the reset can acquire.
      expect(fs.existsSync(lock)).toBe(true);
      fs.writeFileSync(store.path, JSON.stringify(running));
      fs.unlinkSync(lock);
    });
    const resetting = new api.FullAgentStateStore(root, { fs: io, wait });
    expect(() => resetting.reset()).toThrow("Only a latched full daemon can be reset.");
    expect(wait).toHaveBeenCalledOnce();
    expect(store.read()).toEqual(running);
  });

  it("reset cannot read or remove the publication slot while admission holds the lock", () => {
    const { api, root, store, io } = fixture();
    store.admit(); store.stoppedClean();
    const wait = vi.fn();
    const resetting = new api.FullAgentStateStore(root, { fs: io, wait });
    let contention: unknown;
    const admitting = new api.FullAgentStateStore(root, { fs: {
      ...io,
      renameSync: (from, to) => {
        try { resetting.reset(); } catch (error) { contention = error; }
        expect(fs.existsSync(from)).toBe(true);
        fs.renameSync(from, to);
      },
    } });
    expect(admitting.admit().admitted).toBe(true);
    expect(contention).toMatchObject({ message: "state_io" });
    expect(wait).toHaveBeenCalled();
    expect(store.read()?.state).toBe("state_RUNNING");
  });

  it.each(["admit", "stoppedClean", "reset"] as const)("live-pid lock times out and %s fails closed", operation => {
    const { api, root, store, io } = fixture();
    store.admit();
    if (operation === "reset") for (let i = 0; i < api.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    const before = store.read();
    const lock = join(store.directory, "full-agent.lock");
    const metadata = JSON.stringify({ pid: process.pid, started_ms: 0 });
    fs.writeFileSync(lock, metadata, { mode: 0o600 });
    const wait = vi.fn();
    const contender = new api.FullAgentStateStore(root, { fs: io, wait });
    if (operation === "admit") expect(contender.admit()).toMatchObject({ admitted: false, exitCode: 0, reason: "state_io" });
    else expect(() => contender[operation]()).toThrow("state_io");
    expect(store.read()).toEqual(before);
    expect(fs.readFileSync(lock, "utf8")).toBe(metadata);
    expect(wait.mock.calls.reduce((sum, [ms]) => sum + ms, 0)).toBe(api.FULL_AGENT_LOCK_WAIT_MS);
  });

  it("reclaims a proven dead-pid lock before admission", () => {
    const { api, root, store, io } = fixture();
    store.admit();
    const lock = join(store.directory, "full-agent.lock");
    const deadPid = 12345; // Injected identity, never sent to the OS.
    fs.writeFileSync(lock, JSON.stringify({ pid: deadPid, started_ms: 0 }), { mode: 0o600 });
    const probePid = vi.fn(() => { throw Object.assign(new Error("fixture dead"), { code: "ESRCH" }); });
    const successor = new api.FullAgentStateStore(root, { fs: io, wait: () => {}, probePid });
    expect(successor.admit().admitted).toBe(true);
    expect(probePid).toHaveBeenCalledWith(deadPid);
    expect(fs.existsSync(lock)).toBe(false);
    expect(store.read()?.charges_ms).toHaveLength(1);
  });

  it("post-rename directory fsync failure succeeds with a visible clean stop and diagnostic", () => {
    const { api, root, store, io, stderr } = fixture();
    store.admit();
    const failing = new api.FullAgentStateStore(root, { fs: {
      ...io,
      fsyncSync: fd => {
        if (fs.fstatSync(fd).isDirectory()) throw new Error("fixture directory fsync failed");
        fs.fsyncSync(fd);
      },
    } });
    expect(() => failing.stoppedClean()).not.toThrow();
    expect(store.read()?.state).toBe("state_STOPPED_CLEAN");
    expect(stderr).toHaveBeenCalledWith(2, "[castle-wall] Clean stop published; supervision directory sync failed.\n");
  });
});
