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
});
